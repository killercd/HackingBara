"""Create local configuration without overwriting existing encryption keys or passwords."""

import argparse
import base64
import json
import os
import re
import secrets
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_values(content):
    return {
        key.strip(): value.strip().strip("\"'")
        for line in content.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
        for key, value in [line.split("=", 1)]
    }


def replace_value(content, key, value):
    pattern = rf"(?m)^{re.escape(key)}=.*$"
    line = f"{key}={value}"
    if re.search(pattern, content):
        return re.sub(pattern, lambda _: line, content)
    return content.rstrip() + "\n" + line + "\n"


def existing_database_password(root, values):
    project = os.getenv("COMPOSE_PROJECT_NAME") or values.get("COMPOSE_PROJECT_NAME")
    project = project or re.sub(r"[^a-z0-9_-]", "", root.name.lower())
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            "label=com.docker.compose.service=postgres",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    identities = result.stdout.split()
    if identities:
        result = subprocess.run(
            ["docker", "inspect", *identities],
            capture_output=True,
            text=True,
            check=True,
        )
        for container in json.loads(result.stdout):
            for item in container["Config"].get("Env", []):
                if item.startswith("POSTGRES_PASSWORD="):
                    return item.split("=", 1)[1]
        raise ValueError(
            "Existing PostgreSQL container has no recoverable password; restore .env from backup"
        )
    volume = subprocess.run(
        [
            "docker",
            "volume",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            "label=com.docker.compose.volume=postgres_data",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    if volume.stdout.strip():
        raise ValueError(
            "An existing database volume was found. Restore its POSTGRES_PASSWORD from backup"
        )
    return None


def configure(root, local_http=False, recover_password=existing_database_password):
    env = root / ".env"
    content = env.read_text() if env.exists() else (root / ".env.example").read_text()
    values = read_values(content)
    if not values.get("POSTGRES_PASSWORD"):
        password = recover_password(root, values) or secrets.token_hex(32)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", password):
            raise ValueError(
                "Database password must be URL-safe; restore the original .env configuration"
            )
        content = replace_value(content, "POSTGRES_PASSWORD", password)
    if local_http:
        port = values.get("HTTP_PORT") or "8080"
        content = replace_value(content, "PUBLIC_ORIGIN", f"http://127.0.0.1:{port}")
        content = replace_value(content, "SECURE_COOKIES", "false")
    directory = root / "secrets"
    key = directory / "credential_key"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    if key.exists():
        raw = key.read_bytes().strip()
        try:
            valid = (
                len(raw) == 44
                and len(base64.b64decode(raw, altchars=b"-_", validate=True)) == 32
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError(
                "Existing credential key is invalid. Restore the original key; it was not replaced"
            )
    else:
        with key.open("xb") as stream:
            stream.write(base64.urlsafe_b64encode(secrets.token_bytes(32)) + b"\n")
    key.chmod(0o644)
    # Restrict access before writing any secrets, including on first creation.
    descriptor = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--local-http",
        action="store_true",
        help="Configure loopback HTTP instead of HTTPS",
    )
    args = parser.parse_args()
    try:
        configure(ROOT, local_http=args.local_http)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        # Never echo subprocess output, which may contain container secrets.
        parser.exit(
            1,
            f"Setup failed: {exc if isinstance(exc, ValueError) else type(exc).__name__}\n",
        )
    print(
        "Configuration ready. Existing keys and passwords were preserved; secret values were not printed."
    )


if __name__ == "__main__":
    main()
