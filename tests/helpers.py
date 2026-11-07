import json
import time

from app.services.webhook_service import SIGNATURE_HEADER, TIMESTAMP_HEADER, WebhookService

TEST_SECRET = "test-webhook-secret"  # set in conftest.py


def signed_headers(body: bytes, secret: str = TEST_SECRET, timestamp: int | None = None) -> dict:
    timestamp = int(time.time()) if timestamp is None else timestamp
    return {
        "Content-Type": "application/json",
        TIMESTAMP_HEADER: str(timestamp),
        SIGNATURE_HEADER: WebhookService.sign(body, secret, timestamp),
    }


def post_webhook(client, path: str, payload, **sign_options):
    """POST a correctly signed webhook, the way a real sender must."""
    body = json.dumps(payload).encode()
    return client.post(path, content=body, headers=signed_headers(body, **sign_options))
