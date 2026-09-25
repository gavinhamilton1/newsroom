"""Object storage (R2 or a local directory), digest upload and index regeneration."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Protocol

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from . import config

log = logging.getLogger(__name__)


class Storage(Protocol):
    def get_text(self, key: str) -> str | None: ...
    def put_text(self, key: str, body: str, content_type: str) -> None: ...
    def list_keys(self, prefix: str) -> list[str]: ...
    def url_for(self, key: str) -> str: ...


class R2Storage:
    """Cloudflare R2 via its S3-compatible API."""

    def __init__(self, settings: config.Settings, client=None) -> None:
        self.bucket = settings.r2_bucket
        self.public_base_url = settings.r2_public_base_url
        self.client = client or boto3.client(
            "s3",
            endpoint_url=settings.r2_endpoint_url,
            aws_access_key_id=settings.r2_access_key_id,
            aws_secret_access_key=settings.r2_secret_access_key,
            region_name="auto",
            config=BotoConfig(retries={"max_attempts": 3, "mode": "standard"}),
        )

    def get_text(self, key: str) -> str | None:
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise
        return obj["Body"].read().decode("utf-8")

    def put_text(self, key: str, body: str, content_type: str) -> None:
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=body.encode("utf-8"),
            ContentType=content_type,
            CacheControl="no-cache" if not key.startswith("digests/") else "max-age=300",
        )

    def list_keys(self, prefix: str) -> list[str]:
        keys: list[str] = []
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            keys.extend(item["Key"] for item in page.get("Contents", []))
        return keys

    def url_for(self, key: str) -> str:
        return f"{self.public_base_url}/{key}" if self.public_base_url else key


class LocalStorage:
    """A directory standing in for the bucket (used by --no-upload)."""

    def __init__(self, root: Path = config.OUT_DIR) -> None:
        self.root = root

    def get_text(self, key: str) -> str | None:
        path = self.root / key
        return path.read_text(encoding="utf-8") if path.exists() else None

    def put_text(self, key: str, body: str, content_type: str) -> None:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    def list_keys(self, prefix: str) -> list[str]:
        base = self.root / prefix
        if not base.exists():
            return []
        return sorted(str(p.relative_to(self.root)) for p in base.rglob("*") if p.is_file())

    def url_for(self, key: str) -> str:
        return (self.root / key).resolve().as_uri()


def make_storage(settings: config.Settings, local: bool) -> Storage:
    if local:
        return LocalStorage()
    if not settings.r2_configured:
        raise SystemExit(
            "R2 is not configured (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, "
            "R2_BUCKET). Set them, or run with --no-upload."
        )
    return R2Storage(settings)
