"""Relevance scoring, filtering, grouping, and CVE verification against NVD and CISA KEV."""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import anthropic
import httpx

from . import config
from .cost import CostTracker, call_structured
from .extract import Extraction
from .fetch import http_retry
from .publish import Storage

log = logging.getLogger(__name__)

# Real CVE IDs have a four-digit year and a sequence number of at least four digits.
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
CVE_FULL_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

SECTION_KEYS = [key for key, _ in config.DIGEST_SECTIONS]


@dataclass
class Score:
    url: str
    score: int
    category: str
    reason: str


@dataclass
class CveInfo:
    cve_id: str
    verified: bool
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    nvd_published: str | None = None
    kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    patch: str = "Not confirmed"

    @property
    def label(self) -> str:
        return self.cve_id if self.verified else f"{self.cve_id} (unverified)"


@dataclass
class SelectedItem:
    extraction: Extraction
    score: Score
    cves: list[CveInfo] = field(default_factory=list)


# --- Filtering ----------------------------------------------------------------


def is_valid_cve(identifier: str) -> bool:
    return bool(CVE_FULL_RE.match(identifier.strip()))


def find_cves(text: str) -> list[str]:
    return sorted(set(CVE_RE.findall(text)))


def prefilter(extractions: list[Extraction]) -> list[Extraction]:
    """Drop what can be dropped without a model: vendor marketing and 'other'-only topics."""
    kept = []
    for e in extractions:
        if e.is_vendor_marketing:
            log.info("Dropped (vendor marketing): %s", e.headline)
        elif set(e.topics) <= {"other"}:
            log.info("Dropped (topic 'other' only): %s", e.headline)
        else:
            kept.append(e)
    return kept


def apply_scores(
    extractions: list[Extraction], scores: list[Score], max_items: int, min_items: int = 0
) -> list[tuple[Extraction, Score]]:
    """Rank by score and keep up to `max_items`.

    Items scoring under MIN_RELEVANCE_SCORE, vendor marketing and 'other'-only items are
    left out first. If that leaves fewer than `min_items`, the best of what was left out
    fills the gap (non-marketing before marketing, then by score), so a day with any
    readable news always produces a digest.
    """
    by_url = {s.url: s for s in scores}
    preferred: list[tuple[Extraction, Score]] = []
    reserve: list[tuple[Extraction, Score]] = []
    for e in extractions:
        s = by_url.get(e.url)
        if s is None:
            # Not scored (marketing and other-only items are filtered before the call).
            s = Score(e.url, 0, _fallback_category(e), "not scored")
        if e.is_vendor_marketing:
            reason = "vendor marketing"
        elif set(e.topics) <= {"other"}:
            reason = "topic 'other' only"
        elif s.score < config.MIN_RELEVANCE_SCORE:
            reason = f"score {s.score}"
        else:
            preferred.append((e, s))
            continue
        log.info("Held back (%s): %s", reason, e.headline)
        reserve.append((e, s))

    preferred.sort(key=lambda pair: pair[1].score, reverse=True)
    chosen = preferred[:max_items]
    shortfall = min(min_items, max_items) - len(chosen)
    if shortfall > 0 and reserve:
        reserve.sort(
            key=lambda pair: (not pair[0].is_vendor_marketing, pair[1].score), reverse=True
        )
        topup = reserve[:shortfall]
        for e, _ in topup:
            log.info("Added to reach the minimum of %d items: %s", min_items, e.headline)
        chosen.extend(topup)
    return chosen


_SOURCE_TO_SECTION = {
    "fin": "fintech",
    "cyber": "cyber",
    "vuln": "vulnerabilities",
    "ai": "ai",
    "std": "standards",
    "pqc": "standards",
    "arch": "engineering",
}


def _fallback_category(e: Extraction) -> str:
    return _SOURCE_TO_SECTION.get(e.source_category, "engineering")


def group_by_section(items: list[SelectedItem]) -> list[tuple[str, str, list[SelectedItem]]]:
    """[(key, title, items)] in digest order, omitting empty sections."""
    out = []
    for key, title in config.DIGEST_SECTIONS:
        section = [i for i in items if i.score.category == key]
        if section:
            out.append((key, title, section))
    return out


# --- Scoring call -------------------------------------------------------------

SCORE_SCHEMA = {
    "type": "object",
    "properties": {
        "scores": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "score": {"type": "integer"},
                    "category": {"type": "string", "enum": SECTION_KEYS},
                    "reason": {"type": "string"},
                },
                "required": ["url", "score", "category", "reason"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["scores"],
    "additionalProperties": False,
}

SCORE_SYSTEM = (
    "You rank news items for a daily engineering digest.\n\n"
    f"Reader: {config.READER_BRIEF}\n\n"
    "Score every item from 0 to 10 for relevance to this reader. 8 to 10: directly affects "
    "their identity, ingress, CDN/edge or digital experience stack, their AI and agent "
    "infrastructure, or their regulatory obligations, or is a vulnerability in software they "
    "are likely to run. 4 to 7: useful context for engineering practice, standards or the "
    "financial services sector. 0 to 3: general business news, funding rounds, awards, "
    "consumer technology, or items with no architectural lesson. Judge only from the records "
    "given; do not add facts. Assign each item one category: engineering (engineering and "
    "architecture practice, platforms), ai, cyber (attacks, incidents, identity threats), "
    "vulnerabilities (specific flaws and advisories), standards (standards bodies, specs, "
    "post-quantum cryptography), or fintech (financial services, payments, regulation). "
    "Give a one-line reason. Return one entry per input item, using its url exactly."
)


def score_extractions(
    client: anthropic.Anthropic, tracker: CostTracker, extractions: list[Extraction]
) -> list[Score]:
    if not extractions:
        return []
    records = [e.compact() for e in extractions]
    user = "Score these items:\n\n" + json.dumps(records, ensure_ascii=False, indent=1)
    data = call_structured(
        client,
        tracker,
        system=SCORE_SYSTEM,
        user=user,
        schema=SCORE_SCHEMA,
        max_tokens=config.RANK_MAX_TOKENS,
    )
    known = {e.url for e in extractions}
    scores = []
    for row in data.get("scores", []):
        if row.get("url") not in known or row.get("category") not in SECTION_KEYS:
            log.warning("Ignoring score row for unknown url/category: %s", row)
            continue
        score = max(0, min(10, int(row.get("score", 0))))
        scores.append(Score(row["url"], score, row["category"], str(row.get("reason", ""))))
    return scores


# --- NVD and KEV --------------------------------------------------------------


def _cache_fresh(payload: dict, now: datetime) -> bool:
    try:
        fetched = datetime.fromisoformat(payload["fetched_at"])
    except (KeyError, ValueError):
        return False
    return now - fetched < timedelta(hours=config.LOOKUP_CACHE_HOURS)


class VulnLookup:
    """NVD and CISA KEV lookups, cached for 24 hours in the state store."""

    def __init__(self, storage: Storage, client: httpx.Client, nvd_api_key: str = "") -> None:
        self.storage = storage
        self.client = client
        self.nvd_api_key = nvd_api_key
        self._kev: dict[str, dict] | None = None
        self._last_nvd_call = 0.0

    @http_retry
    def _get_json(self, url: str, **kwargs) -> dict:
        resp = self.client.get(url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def _cached(self, key: str, fetch) -> dict | None:
        now = datetime.now(UTC)
        raw = self.storage.get_text(key)
        if raw:
            try:
                payload = json.loads(raw)
                if _cache_fresh(payload, now):
                    return payload["data"]
            except json.JSONDecodeError:
                pass
        data = fetch()
        if data is not None:
            body = json.dumps({"fetched_at": now.isoformat(), "data": data})
            self.storage.put_text(key, body, "application/json")
        return data

    def kev_catalog(self) -> dict[str, dict]:
        if self._kev is None:

            def fetch() -> dict:
                feed = self._get_json(config.KEV_FEED_URL)
                return {v["cveID"]: v for v in feed.get("vulnerabilities", [])}

            try:
                self._kev = self._cached("state/lookups/kev.json", fetch) or {}
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("KEV feed unavailable (%s); KEV status unknown this run", exc)
                self._kev = {}
        return self._kev

    def nvd_record(self, cve_id: str) -> dict | None:
        def fetch() -> dict:
            # Without an API key NVD allows about 5 requests per 30 seconds.
            if not self.nvd_api_key:
                wait = 6.5 - (time.monotonic() - self._last_nvd_call)
                if wait > 0:
                    time.sleep(wait)
            headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
            self._last_nvd_call = time.monotonic()
            data = self._get_json(config.NVD_API_URL, params={"cveId": cve_id}, headers=headers)
            vulns = data.get("vulnerabilities") or []
            return {"cve": vulns[0]["cve"]} if vulns else {"cve": None}

        try:
            data = self._cached(f"state/lookups/nvd/{cve_id}.json", fetch)
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("NVD lookup failed for %s (%s)", cve_id, exc)
            return None
        return (data or {}).get("cve")

    def lookup(self, cve_id: str) -> CveInfo:
        record = self.nvd_record(cve_id)
        info = parse_nvd(cve_id, record) if record else CveInfo(cve_id, verified=False)
        kev = self.kev_catalog().get(cve_id)
        if kev:
            info.kev = True
            info.kev_date_added = kev.get("dateAdded")
            info.kev_due_date = kev.get("dueDate")
        return info


def parse_nvd(cve_id: str, cve: dict) -> CveInfo:
    info = CveInfo(cve_id, verified=True, nvd_published=(cve.get("published") or "")[:10] or None)
    metrics = cve.get("metrics") or {}
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        if entries:
            primary = next((m for m in entries if m.get("type") == "Primary"), entries[0])
            data = primary.get("cvssData", {})
            info.cvss_score = data.get("baseScore")
            info.cvss_severity = data.get("baseSeverity") or primary.get("baseSeverity")
            info.cvss_version = version
            break
    tags = {t for ref in cve.get("references") or [] for t in ref.get("tags") or []}
    if "Patch" in tags:
        info.patch = "Yes (NVD patch reference)"
    elif "Mitigation" in tags:
        info.patch = "Mitigation listed (NVD)"
    return info


def attach_cves(items: list[SelectedItem], lookup: VulnLookup) -> None:
    """Look up every CVE identifier an item's validated extraction mentions."""
    for item in items:
        ids = {i for i in item.extraction.entities.get("identifiers", []) if is_valid_cve(i)}
        for claim in item.extraction.claims:
            ids.update(find_cves(claim.quote))
        item.cves = [lookup.lookup(cve_id) for cve_id in sorted(ids)]
        for info in item.cves:
            log.info(
                "%s: verified=%s cvss=%s kev=%s",
                info.cve_id,
                info.verified,
                info.cvss_score,
                info.kev,
            )


def select(
    client: anthropic.Anthropic,
    tracker: CostTracker,
    extractions: list[Extraction],
    lookup: VulnLookup,
    max_items: int,
    min_items: int = 0,
) -> tuple[list[SelectedItem], list[Score]]:
    # Only items that can make the digest on merit are sent for scoring; the rest are
    # held in reserve in case the day is thin.
    scores = score_extractions(client, tracker, prefilter(extractions))
    chosen = apply_scores(extractions, scores, max_items, min_items)
    items = [SelectedItem(e, s) for e, s in chosen]
    attach_cves(items, lookup)
    return items, scores
