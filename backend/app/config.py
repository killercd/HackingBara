from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://hackingbara@postgres/hackingbara"
    redis_url: str = "redis://redis:6379/0"
    secret_key_file: str = "/run/secrets/credential_key"
    evidence_dir: Path = Path("/evidence")
    public_origin: str = "https://localhost"
    secure_cookies: bool = True
    session_hours: int = 12
    max_targets: int = 256
    max_ports: int = 10000
    max_queue: int = 32
    max_concurrent_runs: int = 2
    scanner_timeout: int = 180
    lease_seconds: int = 60
    max_output_bytes: int = 8 * 1024 * 1024
    max_artifact_bytes: int = 10 * 1024 * 1024
    spray_delay_seconds: float = 30
    spray_account_budget: int = 2
    spray_service_budget: int = 10
    max_credentials: int = 10
    eyewitness_enabled: bool = False


settings = Settings()
