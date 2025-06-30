import pytest
from pathlib import Path
from smtp2slack4qnap import Config, ConfigError, ChecksumType


def test_config_minimal(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/xxx")
    config = Config()
    assert config.slack_webhook_url == "https://hooks.slack.com/services/xxx"
    assert config.smtp_host == "0.0.0.0"
    assert config.smtp_port == 1025
    assert config.auth_password_checksum_type == ChecksumType.SHA256
    assert config.tls_cert_path == Path("cert.pem")
    assert config.tls_key_path == Path("key.pem")


def test_config_all_args():
    config = Config(
        slack_webhook_url="https://hooks.slack.com/services/yyy",
        smtp_host="127.0.0.1",
        smtp_port=2525,
        auth_username="user",
        auth_password_checksum="abc123",
        auth_password_checksum_type=ChecksumType.SHA512,
        tls_cert_path=Path("/tmp/cert.pem"),
        tls_key_path=Path("/tmp/key.pem"),
    )
    assert config.slack_webhook_url == "https://hooks.slack.com/services/yyy"
    assert config.smtp_host == "127.0.0.1"
    assert config.smtp_port == 2525
    assert config.auth_username == "user"
    assert config.auth_password_checksum == "abc123"
    assert config.auth_password_checksum_type == ChecksumType.SHA512
    assert config.tls_cert_path == Path("/tmp/cert.pem")
    assert config.tls_key_path == Path("/tmp/key.pem")


def test_config_missing_webhook(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    with pytest.raises(ConfigError):
        Config()
