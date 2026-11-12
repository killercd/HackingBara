import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("project_setup", Path(__file__).parents[2] / "scripts/setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


@pytest.fixture
def root(tmp_path):
    (tmp_path / ".env.example").write_text(
        "POSTGRES_PASSWORD=\nPUBLIC_ORIGIN=https://localhost\nSECURE_COOKIES=true\n"
    )
    return tmp_path


def test_setup_is_idempotent_and_preserves_key_and_password(root):
    setup.configure(root, recover_password=lambda *_: None)
    original_env = (root / ".env").read_bytes()
    original_key = (root / "secrets/credential_key").read_bytes()
    setup.configure(root, recover_password=lambda *_: pytest.fail("Existing password must not be replaced"))
    assert (root / ".env").read_bytes() == original_env
    assert (root / "secrets/credential_key").read_bytes() == original_key
    assert (root / ".env").stat().st_mode & 0o777 == 0o600
    assert (root / "secrets").stat().st_mode & 0o777 == 0o700


def test_setup_recovers_database_password_and_local_origin(root):
    setup.configure(root, local_http=True, recover_password=lambda *_: "existing-container-password")
    values = setup.read_values((root / ".env").read_text())
    assert values["POSTGRES_PASSWORD"] == "existing-container-password"
    assert values["PUBLIC_ORIGIN"] == "http://127.0.0.1:8080"
    assert values["SECURE_COOKIES"] == "false"


def test_setup_refuses_to_replace_invalid_existing_key(root):
    (root / "secrets").mkdir()
    (root / "secrets/credential_key").write_bytes(b"invalid-key")
    with pytest.raises(ValueError, match="not replaced"):
        setup.configure(root, recover_password=lambda *_: None)
    assert (root / "secrets/credential_key").read_bytes() == b"invalid-key"
    assert not (root / ".env").exists()
