#!/usr/bin/env python3
#
# Compact SMTP to HTTP Gateway
#  -> targeting Slack for QNAP-NAS notifications
#

# generate self-signed cert (better than nothing):
# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes -subj '/CN=localhost'

import asyncio
import email
from enum import Enum
import hashlib
import logging
import os
from pathlib import Path
import re
import signal
from smtplib import SMTP
import ssl
from typing import Optional
from requests.adapters import HTTPAdapter


import html2text
import requests
from aiosmtpd.controller import UnthreadedController
from aiosmtpd.smtp import AuthResult, LoginPassword, Session, Envelope
from urllib3 import Retry

LOGGER = logging.getLogger(__name__)


class ChecksumType(str, Enum):
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class ConfigError(Exception):
    """Custom exception for configuration errors."""


class Config:
    """Configuration class to hold SMTP and Slack settings."""

    def __init__(
        self,
        *,
        slack_webhook_url: Optional[str] = None,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        auth_username: Optional[str] = None,
        auth_password_checksum: Optional[str] = None,
        auth_password_checksum_type: Optional[ChecksumType] = None,
        tls_cert_path: Optional[Path] = None,
        tls_key_path: Optional[Path] = None,
    ):
        _slack_webhook_url = slack_webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        if not _slack_webhook_url:
            raise ConfigError("SLACK_WEBHOOK_URL is required.")
        self.slack_webhook_url = _slack_webhook_url.strip()

        self.smtp_host = smtp_host or os.environ.get("SMTP_HOST", "0.0.0.0")
        self.smtp_port = smtp_port or int(os.environ.get("SMTP_PORT", 1025))
        self.auth_password_checksum_type = auth_password_checksum_type or ChecksumType(
            os.environ.get("AUTH_PASSWORD_CHECKSUM_TYPE", ChecksumType.SHA256.value)
        )

        self.auth_username = auth_username or os.environ.get("SMTP_AUTH_USERNAME")
        self.auth_password_checksum = auth_password_checksum or os.environ.get("SMTP_AUTH_PASSWORD_CHECKSUM")

        env_tls_cert_path = os.environ.get("TLS_CERT_PATH")
        self.tls_cert_path = tls_cert_path or (Path(env_tls_cert_path) if env_tls_cert_path else None)
        self.tls_key_path = tls_key_path or Path(os.environ.get("TLS_KEY_PATH", "key.pem"))

        if (
            self.auth_username
            and self.auth_password_checksum
            and (self.tls_cert_path is not None or self.tls_key_path is not None)
        ):
            raise ConfigError("SMTP_AUTH_PASSWORD_CHECKSUM is required when SMTP_AUTH_USERNAME is set.")


class BasicAuthenticator:
    def __init__(self, username: str, password_checksum: str, checksum_type: ChecksumType = ChecksumType.SHA256):
        self.username = username
        self.password_checksum = password_checksum
        self.checksum_type = checksum_type

    def __call__(
        self, server: SMTP, session: Session, envelope: Envelope, mechanism: str, auth_data: LoginPassword
    ) -> AuthResult:
        fail_nothandled = AuthResult(success=False, handled=False)
        if mechanism not in {"LOGIN", "PLAIN"}:
            LOGGER.error(f"Unsupported authentication mechanism: {mechanism}")
            return fail_nothandled

        if not isinstance(auth_data, LoginPassword):
            LOGGER.error(f"Unsupported authentication data: {auth_data}")
            return fail_nothandled

        hashpass = self._get_checksum(auth_data.password)
        username = auth_data.login.decode("utf-8")
        if username == self.username and hashpass == self.password_checksum:
            LOGGER.info(f"Authenticated: {username}")
            return AuthResult(success=True)

        LOGGER.error(f"Authentication failed: {username}")
        return AuthResult(success=False, handled=True)

    def _get_checksum(self, password: bytes) -> str:
        return hashlib.new(self.checksum_type, password, usedforsecurity=True).hexdigest()


class SlackWebhookSenderHandler:
    def __init__(self, webhook_url: str):
        self.sender_bot_icon_url = "https://i.ibb.co/6R9TBVg7/letter.png"
        self.sender_bot_name = "Mail Relay"
        self._requests_session: Optional[requests.Session] = None

        self.webhook_url = webhook_url

    async def handle_DATA(self, _server: SMTP, _session: Session, envelope: Envelope) -> str:
        self._send_slack_message(self.email2text(envelope.content), envelope.mail_from)
        return "250 OK"

    @property
    def _http_client(self) -> requests.Session:
        if self._requests_session is None:
            self._requests_session = requests.Session()
            retry_policy = Retry(
                total=3,
                backoff_factor=0.1,
                status_forcelist=[502, 503, 504],
                allowed_methods={"POST"},
            )
            self._requests_session.mount("https://", HTTPAdapter(max_retries=retry_policy))
            self._requests_session.headers.update({"Content-Type": "application/json"})

        return self._requests_session

    def _send_slack_message(self, text: str, from_name: Optional[str]) -> None:
        # tuned for slack, but can be anything else
        payload = {
            "icon_url": self.sender_bot_icon_url,
            "username": f"{self.sender_bot_name} ({from_name})" if from_name else self.sender_bot_name,
            "text": text,
        }
        try:
            response = self._http_client.post(self.webhook_url, json=payload, timeout=5)
            response.raise_for_status()
        except requests.RequestException as e:
            LOGGER.error(f"Failed to send Slack message: {e}")
        else:
            LOGGER.info("Slack message sent: %s", payload["text"])

    @staticmethod
    def email2text(data) -> str:
        body = email.message_from_bytes(data).get_payload()
        h = html2text.HTML2Text()
        h.ignore_tables = True
        return re.sub(r"\n\s*\n", "\n\n", h.handle(body))


class Smtp2SlackServer:
    def __init__(self, config: Optional[Config] = None, *, loop: Optional[asyncio.AbstractEventLoop] = None):
        self.config = config or Config()

        tls_context = None
        if all(p is not None and p.exists() for p in [self.config.tls_cert_path, self.config.tls_key_path]):
            LOGGER.info("Using TLS with cert: %s and key: %s", self.config.tls_cert_path, self.config.tls_key_path)
            tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            tls_context.load_cert_chain(str(self.config.tls_cert_path), str(self.config.tls_key_path))

        authenticator = None
        if self.config.auth_username and self.config.auth_password_checksum:
            LOGGER.info("Using SMTP authentication")
            authenticator = BasicAuthenticator(
                username=self.config.auth_username,
                password_checksum=self.config.auth_password_checksum,
                checksum_type=self.config.auth_password_checksum_type,
            )

        self.loop = loop or asyncio.new_event_loop()
        handler = SlackWebhookSenderHandler(self.config.slack_webhook_url)
        self.controller = UnthreadedController(
            handler=handler,
            hostname=self.config.smtp_host,
            port=self.config.smtp_port,
            auth_required=authenticator is not None,
            authenticator=authenticator,
            require_starttls=tls_context is not None,
            tls_context=tls_context,
            loop=self.loop,
        )

    def start(self) -> None:
        LOGGER.info(
            "Starting SMTP server (%s:%d) is running. Press Ctrl+c to stop server and exit.",
            self.config.smtp_host,
            self.config.smtp_port,
        )
        self.controller.begin()

        for sig in (signal.SIGINT, signal.SIGTERM):
            self.loop.add_signal_handler(sig, lambda: self.stop())

        self.loop.run_forever()

    def stop(self) -> None:
        LOGGER.info("Stopping SMTP server...")
        try:
            self.controller.end()
        finally:
            raise SystemExit

def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    try:
        Smtp2SlackServer().start()
    except KeyboardInterrupt:
        LOGGER.info("Server stopped by user.")
        return 0
    except Exception as e:
        LOGGER.error(f"An error occurred: {e}")
        return 1
    return 0

if __name__ == "__main__":
    main()
