import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Two DB identities: the owner runs migrations and the demo lab's DDL; the
    # API serves every request as wallet_app, which row-level security binds.
    app_dsn: str = os.getenv("APP_DATABASE_URL", "postgresql://wallet_app:app@localhost:5432/securewallet")
    owner_dsn: str = os.getenv("OWNER_DATABASE_URL", "postgresql://wallet_owner:owner@localhost:5432/securewallet")

    keys_dir: str = os.getenv("KEYS_DIR", "/keys")
    jwt_issuer: str = "securewallet-auth"
    jwt_audience: str = "wallet-api"
    access_ttl_seconds: int = int(os.getenv("ACCESS_TTL_SECONDS", "900"))
    refresh_ttl_seconds: int = int(os.getenv("REFRESH_TTL_SECONDS", str(7 * 24 * 3600)))
    cookie_secure: bool = _bool("COOKIE_SECURE", False)

    rp_id: str = os.getenv("RP_ID", "localhost")
    rp_name: str = "SecureWallet"
    expected_origins: list[str] = field(
        default_factory=lambda: [o.strip() for o in os.getenv(
            "EXPECTED_ORIGINS", "http://localhost:8080,http://localhost:5173").split(",") if o.strip()])

    # Risk thresholds (paisa). Above these a transfer needs a passkey step-up.
    stepup_amount: int = 5_000_000          # Rs 50,000
    new_payee_amount: int = 1_000_000       # Rs 10,000 to someone you've never paid
    max_transfer: int = 50_000_000          # Rs 500,000

    login_ip_limit_per_min: int = 20

    # W11 transaction PIN: 6 digits, lock after this many wrong entries.
    tpin_max_failures: int = 3
    tpin_lock_seconds: int = 900

    # W13 sessions: ended after this much inactivity, and after this long regardless.
    session_idle_seconds: int = int(os.getenv("SESSION_IDLE_SECONDS", "300"))
    session_absolute_seconds: int = int(os.getenv("SESSION_ABSOLUTE_SECONDS", str(8 * 3600)))
    lockout_threshold: int = 5

    # Secure default: the trace panel and the vulnerability lab do not exist
    # unless DEMO_MODE is explicitly switched on.
    demo_mode: bool = _bool("DEMO_MODE", False)
    seed: bool = _bool("SEED", True)


settings = Settings()
