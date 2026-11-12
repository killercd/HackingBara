"""Regression test: the built frontend must recover when Docker API DNS changes."""

import argparse
import json
import subprocess
import time
import uuid

BACKEND = """import json,os
from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200)
  self.send_header('Content-Type','application/json')
  self.end_headers()
  self.wfile.write(json.dumps({'instance':os.environ['INSTANCE'],'path':self.path}).encode())
 def log_message(self,*args):pass
HTTPServer(('0.0.0.0',8000),Handler).serve_forever()
"""


def docker(*args, check=True):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check
    )
    return result.stdout.strip()


def wait_for_instance(proxy, instance):
    until = time.monotonic() + 30
    while time.monotonic() < until:
        raw = docker(
            "exec",
            proxy,
            "wget",
            "-q",
            "-T",
            "2",
            "-O",
            "-",
            "http://127.0.0.1:8080/api/probe?page=2",
            check=False,
        )
        try:
            value = json.loads(raw)
            if value == {"instance": instance, "path": "/api/probe?page=2"}:
                return
        except ValueError:
            pass
        time.sleep(0.5)
    raise AssertionError(
        f"Proxy did not recover to {instance} with the original API path and query"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image", required=True, help="Built HackingBara frontend image ID"
    )
    args = parser.parse_args()
    suffix = uuid.uuid4().hex[:10]
    network, first, second, proxy = [
        f"hb-dns-{name}-{suffix}" for name in ("network", "first", "second", "proxy")
    ]
    try:
        docker("network", "create", network)
        for container, instance in ((first, "first"), (second, "second")):
            docker(
                "run",
                "-d",
                "--name",
                container,
                "--network",
                network,
                "--network-alias",
                "api",
                "--cap-drop=ALL",
                "--user",
                "10001:10001",
                "-e",
                f"INSTANCE={instance}",
                "python:3.12-alpine",
                "python",
                "-c",
                BACKEND,
            )
            if instance == "first":
                docker(
                    "run",
                    "-d",
                    "--name",
                    proxy,
                    "--network",
                    network,
                    "--cap-drop=ALL",
                    "--label",
                    "com.docker.compose.project=hackingbara-dns-test",
                    "--label",
                    "com.docker.compose.service=proxy",
                    args.image,
                )
                docker("exec", proxy, "nginx", "-t")
                wait_for_instance(proxy, "first")
        # Both backends are alive together, guaranteeing distinct IP addresses.
        addresses = []
        for container in (first, second):
            info = json.loads(docker("inspect", container))[0]
            addresses.append(info["NetworkSettings"]["Networks"][network]["IPAddress"])
        assert addresses[0] != addresses[1]
        before = docker("inspect", "--format", "{{.State.StartedAt}}", proxy)
        docker("container", "stop", "--time", "1", first)
        wait_for_instance(proxy, "second")
        assert docker("inspect", "--format", "{{.State.StartedAt}}", proxy) == before
        print(
            "PASS: API DNS changed between distinct IPs; proxy recovered without restart; URI/query preserved"
        )
    finally:
        for container in (proxy, first, second):
            docker("container", "rm", "--force", container, check=False)
        docker("network", "rm", network, check=False)


if __name__ == "__main__":
    main()
