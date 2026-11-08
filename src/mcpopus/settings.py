"""Host settings, read from environment variables (prefix MCPOPUS_)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .crypto import SecretBox

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Default redirect URI policy for dynamically registered clients. "loopback"
# means http://localhost, http://127.0.0.1 or http://[::1] on any port (Claude
# Code, the MCP Inspector, test clients). Verified source for the claude.ai URL:
# https://claude.com/docs/connectors/building/authentication.md (see BUILD_LOG).
DEFAULT_REDIRECT_URIS = ("https://claude.ai/api/mcp/auth_callback", "loopback")


class SettingsError(ValueError):
    pass


def _positive(raw: str | None, default: float, low: float, high: float, name: str) -> float:
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        raise SettingsError(f"{name} must be a number") from None
    if not low <= value <= high:
        raise SettingsError(f"{name} must be between {low:g} and {high:g}")
    return value


def parse_bool(value: str | None, name: str, default: bool = False) -> bool:
    if value is None or value.strip() == "":
        return default
    v = value.strip().lower()
    if v in ("true", "1", "yes", "on"):
        return True
    if v in ("false", "0", "no", "off"):
        return False
    raise SettingsError(f"{name} must be true or false")


@dataclass(frozen=True)
class Settings:
    public_url: str
    data_dir: Path
    config_dir: Path
    plugins_dir: Path
    secret_box: SecretBox = field(repr=False)
    routing: str = "path"  # "path" or "subdomain"
    public_bind: str = "0.0.0.0"
    public_port: int = 8080
    admin_bind: str = "127.0.0.1"
    admin_port: int = 8081
    allowed_redirect_uris: tuple[str, ...] = DEFAULT_REDIRECT_URIS
    trust_proxy_headers: bool = False
    access_token_ttl: int = 900
    refresh_token_ttl: int = 30 * 24 * 3600
    code_ttl: int = 120
    max_dcr_clients: int = 200
    admin_allowed_hosts: tuple[str, ...] = ()
    admin_secure_cookie: bool = False
    stats_record_ip: bool = True  # keep the source address of each requesting agent in the statistics
    admin_session_idle_hours: float = 168.0  # a session ends after this long without use (7 days)
    admin_session_max_days: float = 30.0  # and never lasts longer than this in total
    log_level: str = "INFO"
    access_log: bool = False
    default_source_url: str = "https://github.com/Poag/mcpopus-plugins"
    # Optional declarative credentials (compose). When set they are the source of truth at every start.
    admin_password: str | None = field(default=None, repr=False)
    admin_totp_secret: str | None = field(default=None, repr=False)
    oauth_password: str | None = field(default=None, repr=False)
    oauth_totp_secret: str | None = field(default=None, repr=False)

    @property
    def issuer(self) -> str:
        return self.public_url

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mcpopus.db"

    @property
    def audit_path(self) -> Path:
        return self.data_dir / "audit" / "audit.jsonl"

    @property
    def control_socket(self) -> Path:
        return self.data_dir / "run" / "control.sock"

    @property
    def public_host(self) -> str:
        return urlsplit(self.public_url).netloc.lower()

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env

        def get(name: str, default: str | None = None) -> str | None:
            return e.get("MCPOPUS_" + name, default)

        public_url = (get("PUBLIC_URL") or "").rstrip("/")
        validate_public_url(public_url)
        routing = get("ROUTING", "path")
        if routing not in ("path", "subdomain"):
            raise SettingsError("MCPOPUS_ROUTING must be 'path' or 'subdomain'")
        uris = get("ALLOWED_REDIRECT_URIS")
        return cls(
            public_url=public_url,
            data_dir=Path(get("DATA_DIR", "/data") or "/data"),
            config_dir=Path(get("CONFIG_DIR", "/config") or "/config"),
            plugins_dir=Path(get("PLUGINS_DIR", "/plugins") or "/plugins"),
            secret_box=load_secret_box(e),
            routing=routing,
            public_bind=get("PUBLIC_BIND", "0.0.0.0") or "0.0.0.0",
            public_port=int(get("PUBLIC_PORT", "8080") or 8080),
            admin_bind=get("ADMIN_BIND", "127.0.0.1") or "127.0.0.1",
            admin_port=int(get("ADMIN_PORT", "8081") or 8081),
            allowed_redirect_uris=tuple(u.strip() for u in uris.split(",") if u.strip())
            if uris
            else DEFAULT_REDIRECT_URIS,
            trust_proxy_headers=parse_bool(get("TRUST_PROXY_HEADERS"), "MCPOPUS_TRUST_PROXY_HEADERS"),
            access_token_ttl=int(get("ACCESS_TOKEN_TTL", "900") or 900),
            admin_allowed_hosts=tuple(h.strip().lower() for h in (get("ADMIN_ALLOWED_HOSTS", "") or "").split(",") if h.strip()),
            admin_secure_cookie=parse_bool(get("ADMIN_SECURE_COOKIE"), "MCPOPUS_ADMIN_SECURE_COOKIE"),
            stats_record_ip=parse_bool(get("STATS_RECORD_IP"), "MCPOPUS_STATS_RECORD_IP", default=True),
            admin_session_idle_hours=_positive(get("ADMIN_SESSION_IDLE_HOURS"), 168.0, 1.0, 24 * 90, "MCPOPUS_ADMIN_SESSION_IDLE_HOURS"),
            admin_session_max_days=_positive(get("ADMIN_SESSION_MAX_DAYS"), 30.0, 1.0, 365.0, "MCPOPUS_ADMIN_SESSION_MAX_DAYS"),
            log_level=_log_level(get("LOG_LEVEL")),
            access_log=parse_bool(get("ACCESS_LOG"), "MCPOPUS_ACCESS_LOG"),
            default_source_url=(get("DEFAULT_SOURCE_URL", "https://github.com/Poag/mcpopus-plugins") or "").strip(),
            admin_password=get("ADMIN_PASSWORD") or None,
            admin_totp_secret=(get("ADMIN_TOTP_SECRET") or "").strip().replace(" ", "").upper() or None,
            oauth_password=get("OAUTH_PASSWORD") or None,
            oauth_totp_secret=(get("OAUTH_TOTP_SECRET") or "").strip().replace(" ", "").upper() or None,
            refresh_token_ttl=int(get("REFRESH_TOKEN_TTL", str(30 * 24 * 3600)) or 0),
        )


def _log_level(value: str | None) -> str:
    v = (value or "INFO").strip().upper()
    if v not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise SettingsError("MCPOPUS_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR")
    return v


def validate_public_url(url: str) -> None:
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise SettingsError("MCPOPUS_PUBLIC_URL is required, e.g. https://mcp.example.com")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise SettingsError("MCPOPUS_PUBLIC_URL must be an origin with no path")
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS):
        raise SettingsError("MCPOPUS_PUBLIC_URL must be https (http is allowed for loopback only)")


def load_secret_box(e: dict[str, str]) -> SecretBox:
    """Key comes from MCPOPUS_SECRET_KEY or the file named by MCPOPUS_SECRET_KEY_FILE.

    It must not live inside the data directory (the check is advisory but is
    enforced for the file form).
    """
    inline = e.get("MCPOPUS_SECRET_KEY")
    key_file = e.get("MCPOPUS_SECRET_KEY_FILE")
    if inline and key_file:
        raise SettingsError("set only one of MCPOPUS_SECRET_KEY and MCPOPUS_SECRET_KEY_FILE")
    if key_file:
        data_dir = Path(e.get("MCPOPUS_DATA_DIR", "/data")).resolve()
        path = Path(key_file).resolve()
        if path == data_dir or data_dir in path.parents:
            raise SettingsError("the secret key file must not be inside the data directory")
        try:
            inline = path.read_text().strip()
        except OSError as exc:
            raise SettingsError(f"cannot read secret key file: {exc.strerror}") from None
    if not inline:
        raise SettingsError(
            "no secret key: set MCPOPUS_SECRET_KEY or MCPOPUS_SECRET_KEY_FILE (generate one with 'mcpopus genkey')"
        )
    try:
        return SecretBox.from_text(inline)
    except ValueError as exc:
        raise SettingsError(str(exc)) from None
