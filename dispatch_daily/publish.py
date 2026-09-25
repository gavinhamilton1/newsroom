"""Object storage (R2 or a local directory), digest upload and index regeneration."""

from __future__ import annotations

import json
import logging
import re
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
    """Cloudflare R2 via its S3-compatible API.

    Keys are relative to R2_PREFIX (a folder in the bucket, e.g. "newsroom"), so the app
    never reads or writes anything outside that folder.
    """

    def __init__(self, settings: config.Settings, client=None) -> None:
        self.bucket = settings.r2_bucket
        self.public_base_url = settings.r2_public_base_url
        self.prefix = f"{settings.r2_prefix}/" if settings.r2_prefix else ""
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
            obj = self.client.get_object(Bucket=self.bucket, Key=self.prefix + key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise
        return obj["Body"].read().decode("utf-8")

    def put_text(self, key: str, body: str, content_type: str) -> None:
        self.client.put_object(
            Bucket=self.bucket,
            Key=self.prefix + key,
            Body=body.encode("utf-8"),
            ContentType=content_type,
            CacheControl="no-cache" if not key.startswith("digests/") else "max-age=300",
        )

    def list_keys(self, prefix: str) -> list[str]:
        keys: list[str] = []
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix + prefix):
            keys.extend(item["Key"].removeprefix(self.prefix) for item in page.get("Contents", []))
        return keys

    def url_for(self, key: str) -> str:
        path = self.prefix + key
        return f"{self.public_base_url}/{path}" if self.public_base_url else path


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


class ReadOnlyStorage:
    """Wraps a Storage so a dry run can read real state without writing anything."""

    def __init__(self, inner: Storage) -> None:
        self.inner = inner

    def get_text(self, key: str) -> str | None:
        return self.inner.get_text(key)

    def put_text(self, key: str, body: str, content_type: str) -> None:
        log.debug("Dry run: not writing %s", key)

    def list_keys(self, prefix: str) -> list[str]:
        return self.inner.list_keys(prefix)

    def url_for(self, key: str) -> str:
        return self.inner.url_for(key)


# --- Publishing ---------------------------------------------------------------

ISSUES_KEY = "state/issues.json"
HTML = "text/html; charset=utf-8"
JSON = "application/json"


def digest_key(date_str: str) -> str:
    return f"digests/{date_str}.html"


def record_key(date_str: str) -> str:
    return f"records/{date_str}.json"


def load_issues(storage: Storage) -> list[dict]:
    """The list of published issues. Rebuilt from records/ if the manifest is missing."""
    raw = storage.get_text(ISSUES_KEY)
    if raw:
        try:
            return json.loads(raw)["issues"]
        except (json.JSONDecodeError, KeyError, TypeError):
            log.warning("issues.json unreadable; rebuilding from records/")
    issues = []
    for key in storage.list_keys("records/"):
        m = re.search(r"(\d{4}-\d{2}-\d{2})\.json$", key)
        if not m:
            continue
        try:
            record = json.loads(storage.get_text(key) or "{}")
            count = len(record.get("digest", {}).get("items", []))
        except json.JSONDecodeError:
            count = 0
        issues.append({"date": m.group(1), "items": count})
    return issues


def publish(storage: Storage, date_str: str, html: str, record: dict, index_html_fn) -> str:
    """Upload the digest and its extraction record, then regenerate the index.

    `index_html_fn(issues)` renders the index page; passed in to keep this module free of
    template code. Returns the digest's public URL.
    """
    storage.put_text(digest_key(date_str), html, HTML)
    storage.put_text(record_key(date_str), json.dumps(record, indent=1, default=str), JSON)

    issues = [i for i in load_issues(storage) if i.get("date") != date_str]
    issues.append({"date": date_str, "items": len(record.get("digest", {}).get("items", []))})
    issues.sort(key=lambda i: i["date"], reverse=True)
    storage.put_text(ISSUES_KEY, json.dumps({"issues": issues}, indent=1), JSON)
    storage.put_text("index.html", index_html_fn(issues), HTML)
    return storage.url_for(digest_key(date_str))
