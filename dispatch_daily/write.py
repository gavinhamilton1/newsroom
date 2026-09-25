"""Digest prose from Opus, built only from validated claims and verified CVE data.

The writing call never sees article text. Its output is checked again in code: any
sentence that states a number, version, date or identifier not present in that item's
quotes (or its NVD/KEV record) is removed, and unverified CVE IDs are always labelled.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import date

import anthropic

from . import config
from .cost import CostTracker, call_structured
from .extract import fact_tokens
from .select import CVE_RE, CveInfo, SelectedItem, group_by_section

log = logging.getLogger(__name__)

NOTHING_FOUND_INTRO = (
    "Nothing significant was found in today's sources. The pipeline ran normally and this "
    "short issue is published so that a quiet day can be told apart from a failed run."
)


@dataclass
class DigestItem:
    section: str
    headline: str
    url: str
    publication: str
    published_date: str | None
    summary: str
    so_what: str
    confidence: str  # "high" or "check"
    cves: list[CveInfo] = field(default_factory=list)
    claims: list[dict] = field(default_factory=list)  # kept for the extraction record


@dataclass
class Digest:
    date: date
    intro: str
    items: list[DigestItem]
    stats: dict = field(default_factory=dict)

    @property
    def sections(self) -> list[tuple[str, list[DigestItem]]]:
        """[(title, items)] in the fixed section order, omitting empty sections."""
        out = []
        for key, title in config.DIGEST_SECTIONS:
            section = [i for i in self.items if i.section == key]
            if section:
                out.append((title, section))
        return out

    def to_dict(self) -> dict:
        data = asdict(self)
        data["date"] = self.date.isoformat()
        return data


WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "intro": {"type": "string"},
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "headline": {"type": "string"},
                    "summary": {"type": "string"},
                    "so_what": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "check"]},
                },
                "required": ["id", "headline", "summary", "so_what", "confidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["intro", "items"],
    "additionalProperties": False,
}

WRITE_SYSTEM = f"""You write the daily edition of Architecture Dispatch, an internal engineering
digest.

Reader: {config.READER_BRIEF}

House style: {config.HOUSE_STYLE}

You are given a set of news items. Each item carries only validated claims, each with the
verbatim quote from the source article that supports it, and for vulnerabilities the record
confirmed from NVD and the CISA KEV catalogue. These are the only facts you may use. Every
number, date, version, CVE ID, product, vendor and person you mention must appear in that
item's claims, quotes or vulnerability record, and write numbers and dates in the form the
quotes use (for example, do not add a year that the quote does not state). Do not add
background from your own knowledge, do not speculate about impact beyond what the claims
support, and do not combine facts from different items unless they are clearly the same story.

For each item return:
- headline: rewritten to be specific and informative, with no clickbait or questions.
- summary: 3 to 5 sentences with the concrete details (numbers, versions, dates, who reported
  it), attributing claims to the publication or the named source where appropriate.
- so_what: 2 to 3 sentences on why this matters to the reader and what, if anything, they
  should do about it. Where no action is needed, say so plainly.
- confidence: "high", or "check" when the underlying reporting is thin, single-sourced, based
  on one vendor's statement, or marked as partial.

If a CVE is marked unverified, write its ID followed by "(unverified)". Also return intro: two
sentences on the theme of the day across the items. Return every item id exactly once."""


def _item_payload(item_id: str, item: SelectedItem) -> dict:
    e = item.extraction
    payload = {
        "id": item_id,
        "section": item.score.category,
        "original_headline": e.headline,
        "publication": e.publication,
        "published_date": e.published_date,
        "partial_text": e.paywalled_or_partial,
        "claims": [{"claim": c.text, "quote": c.quote} for c in e.claims],
    }
    if item.cves:
        payload["vulnerability_records"] = [_cve_payload(c) for c in item.cves]
    return payload


def _cve_payload(cve: CveInfo) -> dict:
    if not cve.verified:
        return {"cve": cve.cve_id, "status": "unverified: NVD has no record"}
    return {
        "cve": cve.cve_id,
        "status": "verified in NVD",
        "cvss": cve.cvss_score,
        "cvss_version": cve.cvss_version,
        "severity": cve.cvss_severity,
        "nvd_published": cve.nvd_published,
        "cisa_kev": cve.kev,
        "kev_date_added": cve.kev_date_added,
        "kev_due_date": cve.kev_due_date,
    }


# --- Post-checks --------------------------------------------------------------

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'(])")


def _variants(token: str) -> set[str]:
    """Equivalent spellings: 'v3.1' and '3.1', '07' and '7', and the parts of an ISO
    date, so that 2026-10-14 in a KEV record supports '14 October 2026'."""
    out = {token, token.removeprefix("v")}
    for part in re.split(r"[-/:]", token):
        if part:
            out.add(part)
    return out | {t.lstrip("0") or "0" for t in out if t.isdigit()}


def allowed_tokens(item: SelectedItem) -> set[str]:
    tokens: set[str] = set()
    for claim in item.extraction.claims:
        tokens |= fact_tokens(claim.quote)
    for cve in item.cves:
        tokens |= fact_tokens(json.dumps(_cve_payload(cve)))
    return set().union(*(_variants(t) for t in tokens)) if tokens else set()


def unsupported_tokens(text: str, allowed: set[str]) -> set[str]:
    return {t for t in fact_tokens(text) if not _supported(t, allowed)}


def _supported(token: str, allowed: set[str]) -> bool:
    if token in allowed or token.removeprefix("v") in allowed:
        return True
    if token.isdigit() and (token.lstrip("0") or "0") in allowed:
        return True
    # A date or range written differently: every part must be supported.
    parts = [p for p in re.split(r"[-/:]", token) if p]
    return len(parts) > 1 and all(_supported(p, allowed) for p in parts)


def strip_unsupported(text: str, allowed: set[str]) -> tuple[str, list[str]]:
    """Remove sentences that state a fact token not in `allowed`."""
    kept, removed = [], []
    for sentence in _SENTENCE_SPLIT.split(text.strip()):
        if unsupported_tokens(sentence, allowed):
            removed.append(sentence)
        else:
            kept.append(sentence)
    return " ".join(kept), removed


def mark_unverified(text: str, cves: list[CveInfo]) -> str:
    """Ensure every CVE ID that is not NVD-verified is followed by '(unverified)'."""
    verified = {c.cve_id for c in cves if c.verified}

    def repl(m: re.Match) -> str:
        cve_id = m.group(0)
        following = text[m.end() : m.end() + 14]
        if cve_id in verified or following.startswith(" (unverified)"):
            return cve_id
        return f"{cve_id} (unverified)"

    return CVE_RE.sub(repl, text)


def house_style(text: str) -> str:
    """Backstop for the style rules the prompt already states."""
    text = re.sub(r"\s*[—―]\s*", ", ", text)  # em-dash / horizontal bar
    text = re.sub(r"\s+–\s+", ", ", text)  # spaced en-dash used as a dash
    text = re.sub("[\U0001f300-\U0001faff\U00002600-\U000027bf\U0001f000-\U0001f2ff️]", "", text)
    return " ".join(text.split())


def finalise_item(item: SelectedItem, written: dict) -> DigestItem | None:
    e = item.extraction
    allowed = allowed_tokens(item)
    confidence = (
        written.get("confidence") if written.get("confidence") in ("high", "check") else "check"
    )

    fields = {}
    for key in ("headline", "summary", "so_what"):
        text = house_style(str(written.get(key, "")))
        text, removed = strip_unsupported(text, allowed)
        for sentence in removed:
            log.warning("%s: removed unsupported sentence from %s: %s", e.url, key, sentence)
        if removed:
            confidence = "check"
        fields[key] = mark_unverified(text, item.cves)

    if not fields["summary"]:
        log.warning("%s: nothing left of the summary after checks; item dropped", e.url)
        return None
    return DigestItem(
        section=item.score.category,
        headline=fields["headline"] or e.headline,
        url=e.final_url or e.url,
        publication=e.publication,
        published_date=e.published_date,
        summary=fields["summary"],
        so_what=fields["so_what"],
        confidence=confidence,
        cves=item.cves,
        claims=[{"text": c.text, "quote": c.quote} for c in e.claims],
    )


# --- The call -----------------------------------------------------------------


def write_digest(
    client: anthropic.Anthropic,
    tracker: CostTracker,
    items: list[SelectedItem],
    today: date,
) -> Digest:
    if not items:
        return Digest(date=today, intro=NOTHING_FOUND_INTRO, items=[])

    # Present items in section order so the model sees the digest as the reader will.
    ordered = [i for _, _, section in group_by_section(items) for i in section]
    ids = {f"item{n}": item for n, item in enumerate(ordered, 1)}
    user = f"Today's date: {today.isoformat()}\n\nItems:\n" + json.dumps(
        [_item_payload(k, v) for k, v in ids.items()], ensure_ascii=False, indent=1
    )
    data = call_structured(
        client,
        tracker,
        system=WRITE_SYSTEM,
        user=user,
        schema=WRITE_SCHEMA,
        max_tokens=config.WRITE_MAX_TOKENS,
    )

    written = {row.get("id"): row for row in data.get("items", [])}
    out: list[DigestItem] = []
    for item_id, item in ids.items():
        row = written.get(item_id)
        if row is None:
            log.warning("Writer omitted %s (%s); dropped", item_id, item.extraction.url)
            continue
        final = finalise_item(item, row)
        if final:
            out.append(final)

    # The intro may only use facts from the items it introduces.
    all_allowed = set().union(*(allowed_tokens(i) for i in ordered))
    intro, removed = strip_unsupported(house_style(str(data.get("intro", ""))), all_allowed)
    for sentence in removed:
        log.warning("Removed unsupported sentence from intro: %s", sentence)
    all_cves = [c for i in ordered for c in i.cves]
    intro = mark_unverified(intro, all_cves)
    if not out:
        intro = NOTHING_FOUND_INTRO
    return Digest(date=today, intro=intro, items=out)
