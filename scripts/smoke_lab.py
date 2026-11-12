"""End-to-end assessment of the bundled, operator-owned Docker lab only."""

import argparse
import getpass
import json
import os
import subprocess
import time

import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default="http://127.0.0.1:8080")
    parser.add_argument("--username", default=os.getenv("SMOKE_USERNAME", "operator"))
    parser.add_argument("--screenshots", action="store_true")
    parser.add_argument("--credentials", action="store_true")
    args = parser.parse_args()
    container = subprocess.check_output(
        [
            "docker",
            "compose",
            "-f",
            "compose.yaml",
            "-f",
            "compose.lab.yaml",
            "ps",
            "-q",
            "lab",
        ],
        text=True,
    ).strip()
    if not container:
        parser.error("Start the bundled Docker lab first")
    info = json.loads(
        subprocess.check_output(["docker", "inspect", container], text=True)
    )[0]
    networks = info["NetworkSettings"]["Networks"]
    address = next(
        v["IPAddress"] for k, v in networks.items() if k.endswith("_scanner")
    )
    password = os.getenv("SMOKE_PASSWORD") or getpass.getpass("Platform password: ")
    url = f"http://{address}:8000/"
    with httpx.Client(
        base_url=args.origin + "/api/v1", headers={"Origin": args.origin}, timeout=20
    ) as client:
        response = client.post(
            "/auth/login", json={"username": args.username, "password": password}
        )
        response.raise_for_status()
        client.headers["X-CSRF-Token"] = client.cookies["hb_csrf"]
        credential_ids = []
        if args.credentials:
            response = client.post(
                "/credentials",
                json={
                    "label": "Owned lab fixture",
                    "username": "lab",
                    "password": "local-fixture-only",
                },
            )
            response.raise_for_status()
            credential_ids = [response.json()["id"]]
        config = {
            "name": f"Owned lab smoke {int(time.time())}",
            "targets": [address],
            "ports": "8000",
            "urls": [url, url + "protected"],
            "screenshots": args.screenshots,
            "password_spray": args.credentials,
            "credential_ids": credential_ids,
            "credential_endpoints": [url + "protected"] if args.credentials else [],
        }
        response = client.post("/scans", json=config)
        response.raise_for_status()
        scan = response.json()
        response = client.post(
            f"/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True}
        )
        response.raise_for_status()
        run_id = response.json()["id"]
        print(f"Started owned lab run {run_id}; target {address}:8000", flush=True)
        for _ in range(180):
            response = client.get(f"/runs/{run_id}")
            response.raise_for_status()
            run = response.json()
            if run["status"] in ["completed", "failed", "stopped"]:
                break
            time.sleep(2)
        else:
            raise SystemExit("Run did not finish within six minutes")
        print(
            json.dumps(
                {
                    "status": run["status"],
                    "counts": run["counts"],
                    "results": f"{args.origin}/scans/{scan['id']}/runs/{run_id}",
                },
                indent=2,
            )
        )
        if run["status"] != "completed" or run["counts"].get("services", 0) < 1:
            print(client.get(f"/runs/{run_id}/events").text)
            raise SystemExit("Discovery smoke failed")
        if args.credentials and run["counts"].get("credentials", 0) < 1:
            raise SystemExit("Credential validation smoke failed")
        if args.screenshots and run["counts"].get("screenshots", 0) < 1:
            print(client.get(f"/runs/{run_id}/events").text)
            raise SystemExit("Screenshot smoke failed")
        if args.screenshots:
            shot = client.get(f"/runs/{run_id}/screenshots").json()["items"][0]
            media = client.get(args.origin + shot["content_url"])
            media.raise_for_status()
            assert media.headers["content-type"].startswith("image/png")
            assert httpx.get(args.origin + shot["content_url"]).status_code == 401
        client.post("/auth/logout").raise_for_status()


if __name__ == "__main__":
    main()
