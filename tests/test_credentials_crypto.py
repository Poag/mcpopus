import base64

import pytest

from mcpopus import credentials
from mcpopus.crypto import SecretBox, SecretError, generate_key, hash_token
from mcpopus.pluginconfig import ConfigStore, Policy
from mcpopus.routing import PathRouting, SubdomainRouting, valid_plugin_name


def test_totp_rfc6238_sha1_vectors():
    # RFC 6238 appendix B (SHA-1 secret "12345678901234567890"); 8-digit values reduced to 6 digits.
    # Recalled from the RFC, not re-fetched in this build (see BUILD_LOG).
    secret = base64.b32encode(b"12345678901234567890").decode()
    for t, code in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924")):
        assert credentials.totp_at(secret, t) == code


def test_totp_window_and_replay():
    s = credentials.new_totp_secret()
    now = 1_700_000_000
    step = now // 30
    assert credentials.verify_totp(s, credentials.totp_at(s, now), 0, now) == step
    assert credentials.verify_totp(s, credentials.totp_at(s, now - 30), 0, now) == step - 1
    assert credentials.verify_totp(s, credentials.totp_at(s, now - 120), 0, now) is None
    assert credentials.verify_totp(s, credentials.totp_at(s, now), step, now) is None  # replay
    assert credentials.verify_totp(s, "abcdef", 0, now) is None


def test_password_policy_and_hashing():
    assert credentials.check_password_policy("short")
    assert credentials.check_password_policy("aaaaaaaaaaaaaaaaaaaa")
    assert credentials.check_password_policy("a long enough passphrase") is None
    h = credentials.hash_password("a long enough passphrase")
    assert h.startswith("$argon2id$")
    assert credentials.verify_password(h, "a long enough passphrase")
    assert not credentials.verify_password(h, "wrong")
    assert not credentials.verify_password(None, "anything")


def test_secretbox_roundtrip_context_binding_and_tamper():
    box = SecretBox.from_text(generate_key())
    token = box.encrypt("value", "plugin:a:f")
    assert box.decrypt(token, "plugin:a:f") == "value"
    assert box.encrypt("value", "plugin:a:f") != token  # random nonce
    with pytest.raises(SecretError):
        box.decrypt(token, "plugin:b:f")
    with pytest.raises(SecretError):
        box.decrypt(token[:-2] + "AA", "plugin:a:f")
    with pytest.raises(SecretError):
        SecretBox.from_text(generate_key()).decrypt(token, "plugin:a:f")
    with pytest.raises(ValueError):
        SecretBox.from_text("tooshort")


def test_settings_key_must_not_live_in_data_dir(tmp_path):
    from mcpopus.settings import Settings, SettingsError

    key = tmp_path / "data" / "key"
    key.parent.mkdir()
    key.write_text(generate_key())
    env = {"MCPOPUS_PUBLIC_URL": "https://mcp.example.com", "MCPOPUS_DATA_DIR": str(tmp_path / "data"), "MCPOPUS_SECRET_KEY_FILE": str(key)}
    with pytest.raises(SettingsError, match="inside the data directory"):
        Settings.from_env(env)
    outside = tmp_path / "key"
    outside.write_text(generate_key())
    assert Settings.from_env({**env, "MCPOPUS_SECRET_KEY_FILE": str(outside)}).secret_box
    with pytest.raises(SettingsError):
        Settings.from_env({**env, "MCPOPUS_SECRET_KEY_FILE": ""})
    with pytest.raises(SettingsError, match="https"):
        Settings.from_env({"MCPOPUS_PUBLIC_URL": "http://mcp.example.com", "MCPOPUS_SECRET_KEY": generate_key()})


def test_config_store_encrypts_and_policy_defaults(tmp_path):
    box = SecretBox.from_text(generate_key())
    store = ConfigStore(tmp_path, box)
    assert store.get("x").policy.read_only is True and store.get("x").enabled is True
    store.save("x", values={"a": 1}, new_secrets={"pw": "plain-text-value"})
    raw = (tmp_path / "plugins.json").read_text()
    assert "plain-text-value" not in raw and "v1:" in raw
    assert store.decrypted_secrets("x") == {"pw": "plain-text-value"}
    assert oct((tmp_path / "plugins.json").stat().st_mode & 0o777) == "0o600"
    p = Policy()
    assert p.allows("r", "read") and not p.allows("w", "write")
    assert not Policy(read_only=False).allows("w", "write")
    assert Policy(read_only=False, enable_tools=["w"]).allows("w", "write")
    assert not Policy(read_only=False, enable_tools=["w"], deny_tools=["w"]).allows("w", "write")


@pytest.mark.parametrize("name,ok", [("hello", True), ("a-b", True), ("A", False), ("-a", False), ("a" * 33, False), ("oauth", False), ("..", False), ("a/b", False), ("", False)])
def test_plugin_name_rules(name, ok):
    assert valid_plugin_name(name) is ok


def test_path_routing_resource_binding():
    r = PathRouting("https://mcp.example.com")
    assert r.resource_url("hello") == "https://mcp.example.com/hello"
    assert r.metadata_url("hello") == "https://mcp.example.com/.well-known/oauth-protected-resource/hello"
    for good in ("https://mcp.example.com/hello", "https://MCP.example.com/hello/", "https://mcp.example.com/hello"):
        assert r.plugin_for_resource(good) == "hello"
    for bad in ("https://mcp.example.com", "https://mcp.example.com/hello/x", "http://mcp.example.com/hello", "https://evil.example/hello",
                "https://mcp.example.com/hello?x=1", "https://mcp.example.com/Hello", "https://mcp.example.com/oauth"):
        assert r.plugin_for_resource(bad) is None, bad
    assert r.resolve("mcp.example.com", "/hello/x").subpath == "/x" and r.resolve("mcp.example.com", "/hello").subpath == "/"
    assert r.metadata_plugin("mcp.example.com", "/.well-known/oauth-protected-resource/hello") == "hello"
    assert r.metadata_plugin("mcp.example.com", "/.well-known/oauth-protected-resource/..") is None


def test_subdomain_routing_is_a_drop_in_replacement():
    r = SubdomainRouting("https://mcp.example.com")
    assert r.resource_url("hello") == "https://hello.mcp.example.com"
    assert r.metadata_url("hello") == "https://hello.mcp.example.com/.well-known/oauth-protected-resource"
    assert r.plugin_for_resource("https://hello.mcp.example.com") == "hello"
    assert r.plugin_for_resource("https://hello.mcp.example.com/") == "hello"
    assert r.plugin_for_resource("https://a.b.mcp.example.com") is None
    assert r.plugin_for_resource("https://mcp.example.com") is None
    assert r.resolve("hello.mcp.example.com", "/").plugin == "hello"
    assert r.metadata_plugin("hello.mcp.example.com", "/.well-known/oauth-protected-resource") == "hello"
    assert r.host_allowed("mcp.example.com") and r.host_allowed("x.mcp.example.com") and not r.host_allowed("evil.com")


def test_token_hash_is_stable_and_hex():
    assert hash_token("abc") == hash_token("abc") and len(hash_token("abc")) == 64


def test_purge_removes_expired_rows(tmp_path):
    import time

    from mcpopus.store import Store

    st = Store(tmp_path / "t.db")
    st.add_grant("g", "c", "r", "mcp")
    st.add_token("old", "access", "g", time.time() - 5)
    st.add_token("new", "access", "g", time.time() + 500)
    st.add_code("oldc", "g", "c", "u", "x", time.time() - 5)
    st.purge_expired()
    assert st.get_token("old") is None and st.get_token("new") is not None
    assert st.consume_code("oldc") == (None, False)


def test_env_credentials_are_applied_and_follow_changes(tmp_path):
    from mcpopus import credentials
    from mcpopus.app import apply_env_credentials
    from mcpopus.settings import Settings, SettingsError
    from mcpopus.store import Store

    key = generate_key()
    base = {"MCPOPUS_PUBLIC_URL": "https://mcp.example.com", "MCPOPUS_SECRET_KEY": key, "MCPOPUS_DATA_DIR": str(tmp_path)}
    secret = credentials.new_totp_secret()
    env = {**base, "MCPOPUS_ADMIN_PASSWORD": "an admin password 123", "MCPOPUS_ADMIN_TOTP_SECRET": secret.lower()}
    s = Settings.from_env(env)
    assert "an admin password" not in repr(s)
    st = Store(tmp_path / "t.db")
    apply_env_credentials(s, st)
    row = st.get_credential("admin")
    assert credentials.verify_password(row["password_hash"], "an admin password 123") and st.get_credential("oauth") is None
    assert s.secret_box.decrypt(row["totp_secret_enc"], "credential:admin:totp") == secret
    st.advance_totp_step("admin", 5)
    apply_env_credentials(s, st)  # unchanged: the used-code marker is kept
    assert st.get_credential("admin")["totp_last_step"] == 5
    apply_env_credentials(Settings.from_env({**env, "MCPOPUS_ADMIN_PASSWORD": "a different password 456"}), st)
    assert credentials.verify_password(st.get_credential("admin")["password_hash"], "a different password 456")
    # password only: created without an authenticator (set up in the admin UI); a later password change keeps an enrolled one
    only = Settings.from_env({**base, "MCPOPUS_OAUTH_PASSWORD": "an oauth password 123"})
    apply_env_credentials(only, st)
    assert st.get_credential("oauth")["totp_secret_enc"] == ""
    st.set_totp("oauth", only.secret_box.encrypt(secret, "credential:oauth:totp"))
    apply_env_credentials(Settings.from_env({**base, "MCPOPUS_OAUTH_PASSWORD": "changed oauth password 9"}), st)
    assert st.get_credential("oauth")["totp_secret_enc"] != ""
    for bad in ({"MCPOPUS_ADMIN_PASSWORD": "short", "MCPOPUS_ADMIN_TOTP_SECRET": secret}, {"MCPOPUS_ADMIN_TOTP_SECRET": secret},
                {"MCPOPUS_ADMIN_PASSWORD": "long enough password 1", "MCPOPUS_ADMIN_TOTP_SECRET": "not base32!!"}):
        with pytest.raises(SettingsError):
            apply_env_credentials(Settings.from_env({**base, **bad}), st)


def test_bool_settings_accept_true_false():
    from mcpopus.settings import Settings, SettingsError

    base = {"MCPOPUS_PUBLIC_URL": "https://mcp.example.com", "MCPOPUS_SECRET_KEY": generate_key()}
    for v, want in (("true", True), ("TRUE", True), ("false", False), ("", False), ("1", True), ("0", False)):
        assert Settings.from_env({**base, "MCPOPUS_TRUST_PROXY_HEADERS": v}).trust_proxy_headers is want
    assert Settings.from_env(base).trust_proxy_headers is False
    with pytest.raises(SettingsError):
        Settings.from_env({**base, "MCPOPUS_TRUST_PROXY_HEADERS": "maybe"})


def test_routine_library_logging_is_quiet_unless_debug():
    import logging

    from mcpopus.cli import QUIET_LIBRARIES, configure_logging

    configure_logging()
    for name in QUIET_LIBRARIES:
        assert logging.getLogger(name).level == logging.WARNING, name
    configure_logging("DEBUG")
    assert all(logging.getLogger(n).level == logging.DEBUG for n in QUIET_LIBRARIES)
    configure_logging()


def test_log_settings():
    from mcpopus.settings import Settings, SettingsError

    base = {"MCPOPUS_PUBLIC_URL": "https://mcp.example.com", "MCPOPUS_SECRET_KEY": generate_key()}
    s = Settings.from_env(base)
    assert s.log_level == "INFO" and s.access_log is False
    assert Settings.from_env({**base, "MCPOPUS_LOG_LEVEL": "debug", "MCPOPUS_ACCESS_LOG": "true"}).access_log is True
    with pytest.raises(SettingsError):
        Settings.from_env({**base, "MCPOPUS_LOG_LEVEL": "chatty"})
