"""Seen-URL index (state/seen.json in the bucket) and in-run deduplication."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import unicodedata
from datetime import date, timedelta
from difflib import SequenceMatcher

from . import config
from .publish import Storage
from .sources import Candidate

log = logging.getLogger(__name__)

SEEN_KEY = "state/seen.json"


def url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]


class SeenIndex:
    """Map of URL hash to first-seen date (YYYY-MM-DD), pruned to SEEN_RETENTION_DAYS."""

    def __init__(self, entries: dict[str, str] | None = None) -> None:
        self.entries: dict[str, str] = dict(entries or {})

    @classmethod
    def load(cls, storage: Storage) -> SeenIndex:
        raw = storage.get_text(SEEN_KEY)
        if not raw:
            log.info("No seen index yet; starting empty")
            return cls()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("seen.json is not valid JSON; starting empty")
            return cls()
        return cls(data.get("seen", {}) if isinstance(data, dict) else {})

    def save(self, storage: Storage) -> None:
        body = json.dumps({"seen": dict(sorted(self.entries.items()))}, indent=0)
        storage.put_text(SEEN_KEY, body, "application/json")

    def __contains__(self, url: str) -> bool:
        return url_hash(url) in self.entries

    def add(self, url: str, today: date) -> None:
        self.entries.setdefault(url_hash(url), today.isoformat())

    def prune(self, today: date, days: int = config.SEEN_RETENTION_DAYS) -> int:
        cutoff = (today - timedelta(days=days)).isoformat()
        before = len(self.entries)
        self.entries = {h: d for h, d in self.entries.items() if d >= cutoff}
        return before - len(self.entries)


def normalise_title(title: str) -> str:
    title = unicodedata.normalize("NFKC", title).lower()
    title = re.sub(r"[^\w\s]", " ", title)
    return " ".join(title.split())


def title_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, normalise_title(a), normalise_title(b)).ratio()


def dedupe(candidates: list[Candidate], seen: SeenIndex) -> list[Candidate]:
    """Drop candidates already seen in earlier runs, repeated URLs, and near-duplicate
    titles within this run (keeping the first occurrence)."""
    kept: list[Candidate] = []
    urls: set[str] = set()
    dropped_seen = dropped_dup = 0
    for c in candidates:
        if c.url in seen:
            dropped_seen += 1
            continue
        if c.url in urls or any(
            title_similarity(c.title, k.title) > config.TITLE_SIMILARITY_THRESHOLD for k in kept
        ):
            dropped_dup += 1
            continue
        urls.add(c.url)
        kept.append(c)
    log.info(
        "Dedupe: %d in, %d already seen, %d duplicate(s), %d kept",
        len(candidates),
        dropped_seen,
        dropped_dup,
        len(kept),
    )
    return kept
