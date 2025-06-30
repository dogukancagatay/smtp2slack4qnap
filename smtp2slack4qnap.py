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
import json
import logging
import os
import re
import signal
from smtplib import SMTP
import ssl

import html2text
import requests
from aiosmtpd.controller import UnthreadedController
from aiosmtpd.smtp import AuthResult, LoginPassword, Session, Envelope

LOGGER = logging.getLogger(__name__)


class ChecksumType(str, Enum):
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


### CONFIG DATA

# SMTP AUTH LOGIN (optional, but recommended for remote access)
AUTH_USERNAME = os.environ.get("SMTP_AUTH_USERNAME")
AUTH_PASSWORD_CHECKSUM = os.environ.get("SMTP_AUTH_PASSWORD_CHECKSUM")
AUTH_PASSWORD_CHECKSUM_TYPE = os.environ.get("AUTH_PASSWORD_CHECKSUM_TYPE", ChecksumType.SHA256.value)

# SMTP listener (set to localhost if running on QNAP device)
LHOST, LPORT = os.environ.get("SMTP_HOST", "0.0.0.0"), int(os.environ.get("SMTP_PORT", 1025))

# target slack authenticated webhook url (keep confidential!)
WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

# TLS settings (optional, but recommended for remote access)
TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "cert.pem")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "key.pem")

### END OF CONFIG DATA


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


def email2text(data) -> str:
    body = email.message_from_bytes(data).get_payload()
    h = html2text.HTML2Text()
    h.ignore_tables = True
    return re.sub(r"\n\s*\n", "\n\n", h.handle(body))


class SlackWebhookSenderHandler:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def handle_DATA(self, _server: SMTP, _session: Session, envelope: Envelope) -> str:
        mail_from = envelope.mail_from
        data = envelope.content
        text = email2text(data)
        # tuned for slack, but can be anything else
        requests.post(
            self.webhook_url,
            data={
                "payload": json.dumps(
                    {
                        "icon_url": "https://i.ibb.co/6R9TBVg7/letter.png",
                        "username": f"Mail Relay ({mail_from})",
                        "text": text,
                    }
                )
            },
        )
        LOGGER.info("[+] Alert sent: %s", text.encode())
        return "250 OK"


class Smtp2SlackServer:
    def __init__(self):
        if not WEBHOOK_URL:
            LOGGER.error("SLACK_WEBHOOK_URL is not set")
            LOGGER.info(os.environ)
            exit(1)

        tls_context = None
        if os.path.exists(TLS_CERT_PATH) and os.path.exists(TLS_KEY_PATH):
            LOGGER.info(f"Using TLS with cert: {TLS_CERT_PATH} and key: {TLS_KEY_PATH}")
            tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            tls_context.load_cert_chain(TLS_CERT_PATH, TLS_KEY_PATH)

        authenticator = None
        if AUTH_USERNAME and AUTH_PASSWORD_CHECKSUM:
            LOGGER.info("Using SMTP authentication")
            authenticator = BasicAuthenticator(
                username=AUTH_USERNAME,
                password_checksum=AUTH_PASSWORD_CHECKSUM,
                checksum_type=ChecksumType(AUTH_PASSWORD_CHECKSUM_TYPE),
            )

        self.loop = asyncio.new_event_loop()
        handler = SlackWebhookSenderHandler(WEBHOOK_URL)
        self.controller = UnthreadedController(
            handler=handler,
            hostname=LHOST,
            port=LPORT,
            auth_required=authenticator is not None,
            authenticator=authenticator,
            require_starttls=tls_context is not None,
            tls_context=tls_context,
            loop=self.loop,
        )

    def start(self) -> None:
        LOGGER.info(f"Starting SMTP server ({LHOST}:{LPORT}) is running. Press Return to stop server and exit.")
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    Smtp2SlackServer().start()
