"""Per-article fact extraction with Haiku, and code-side validation of every quote.

The model is asked for claims with verbatim supporting quotes. Nothing it says is
trusted: each quote must appear in the fetched text, each number or identifier in a
claim must appear in that claim's quote, and entity names must appear in the article.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import asdict, dataclass, field

import anthropic

from . import config
from .cost import BudgetExceeded, CostTracker, api_retry
from .fetch import Article, Fetcher, FetchError
from .sources import Candidate

log = logging.getLogger(__name__)

TOOL_NAME = "record_extraction"

EXTRACTION_TOOL = {
    "name": TOOL_NAME,
    "description": "Record the verifiable facts extracted from one news article.",
    "input_schema": {
        "type": "object",
        "properties": {
            "headline": {"type": "string", "description": "The article's headline."},
            "publication": {"type": "string", "description": "Name of the publication."},
            "published_date": {
                "type": ["string", "null"],
                "description": "ISO 8601 date if the page states one, otherwise null.",
            },
            "summary": {
                "type": "string",
                "description": "2-3 factual sentences, no interpretation.",
            },
            "claims": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "The claim in plain words."},
                        "quote": {
                            "type": "string",
                            "description": "Verbatim span copied from the article text that "
                            "supports the claim.",
                        },
                    },
                    "required": ["text", "quote"],
                },
            },
            "entities": {
                "type": "object",
                "properties": {
                    "vendors": {"type": "array", "items": {"type": "string"}},
                    "products": {"type": "array", "items": {"type": "string"}},
                    "researchers": {"type": "array", "items": {"type": "string"}},
                    "identifiers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "CVE IDs, RFC numbers, standard names, spec revisions.",
                    },
                },
                "required": ["vendors", "products", "researchers", "identifiers"],
            },
            "topics": {
                "type": "array",
                "items": {"type": "string", "enum": config.TOPICS},
            },
            "is_vendor_marketing": {"type": "boolean"},
            "paywalled_or_partial": {"type": "boolean"},
        },
        "required": [
            "headline",
            "publication",
            "published_date",
            "summary",
            "claims",
            "entities",
            "topics",
            "is_vendor_marketing",
            "paywalled_or_partial",
        ],
    },
}

SYSTEM_PROMPT = (
    "You extract verifiable facts from a news article for an engineering newsletter at a "
    "bank. Use only the article text provided. Every claim must be supported by a verbatim "
    "quote from that text: copy the quote character for character, as one continuous span "
    "of at most two sentences, without ellipses or edits. Include in each claim's quote "
    "every number, date, version, CVE ID and organisation name that the claim mentions, and "
    "write those numbers and dates in the claim exactly as the quote writes them. Do "
    "not infer, interpret or add context from your own knowledge. If the article does not "
    "state a publication date, return null. Mark the article as vendor marketing if it "
    "exists mainly to promote a product. Mark it paywalled_or_partial if the text looks "
    "truncated or ends at a subscription prompt. Record your answer with the "
    f"{TOOL_NAME} tool."
)

MIN_QUOTE_CHARS = 12


class ExtractionAborted(RuntimeError):
    """Extraction is failing for every article (bad key, unknown model, a code error);
    carrying on would only produce an empty digest."""


# Errors that will not go away on the next article.
FATAL_API_ERRORS = (
    anthropic.AuthenticationError,
    anthropic.PermissionDeniedError,
    anthropic.NotFoundError,
)
# Abort if this many extraction calls in a row fail before any has succeeded.
MAX_INITIAL_FAILURES = 5


@dataclass
class Claim:
    text: str
    quote: str


@dataclass
class Extraction:
    url: str
    final_url: str
    source: str
    source_category: str
    http_status: int
    fetched_at: str
    metadata_published: str | None
    headline: str
    publication: str
    published_date: str | None
    summary: str
    claims: list[Claim]
    entities: dict[str, list[str]]
    topics: list[str]
    is_vendor_marketing: bool
    paywalled_or_partial: bool
    dropped_claims: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def compact(self) -> dict:
        """What the ranking call sees."""
        return {
            "url": self.url,
            "headline": self.headline,
            "publication": self.publication,
            "summary": self.summary,
            "entities": self.entities,
            "topics": self.topics,
        }


# --- Normalisation and validation -------------------------------------------

_QUOTE_MAP = str.maketrans(
    {
        "‘": "'",
        "’": "'",
        "‚": "'",
        "‛": "'",
        "“": '"',
        "”": '"',
        "„": '"',
        " ": " ",
    }
)


def normalise(text: str) -> str:
    """Whitespace-insensitive form used for verbatim matching. Also folds Unicode
    compatibility forms and typographic quotes, which models routinely straighten;
    words, numbers and punctuation otherwise have to match exactly."""
    text = unicodedata.normalize("NFKC", text).translate(_QUOTE_MAP)
    return " ".join(text.split())


# Tokens that must be carried by the quote if a claim states them: anything with a
# digit (numbers, versions, dates, CVSS scores, CVE IDs) and CVE/GHSA identifiers.
_FACT_TOKEN = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[\w]{4}){3}|[\w.]*\d[\w.,%/:-]*)")


def fact_tokens(text: str) -> set[str]:
    return {t.strip(".,:;-/").lower() for t in _FACT_TOKEN.findall(normalise(text))} - {""}


def validate_claims(raw_claims: list[dict], article_text: str) -> tuple[list[Claim], list[dict]]:
    """Keep claims whose quote is verbatim in the article and carries the claim's facts."""
    haystack = normalise(article_text)
    kept: list[Claim] = []
    dropped: list[dict] = []
    for item in raw_claims:
        text = str(item.get("text", "")).strip()
        quote = str(item.get("quote", "")).strip()
        norm_quote = normalise(quote)
        reason = None
        if not text or len(norm_quote) < MIN_QUOTE_CHARS:
            reason = "empty or too-short quote"
        elif norm_quote not in haystack:
            reason = "quote not found in article text"
        else:
            missing = fact_tokens(text) - fact_tokens(quote)
            if missing:
                reason = f"claim states {sorted(missing)} not present in its quote"
        if reason:
            dropped.append({"text": text, "quote": quote, "reason": reason})
        else:
            kept.append(Claim(text=text, quote=quote))
    return kept, dropped


def filter_entities(entities: dict, article_text: str) -> dict[str, list[str]]:
    """Keep only entity strings that literally occur in the article (case-insensitive)."""
    haystack = normalise(article_text).lower()
    out: dict[str, list[str]] = {}
    for key in ("vendors", "products", "researchers", "identifiers"):
        values = [str(v).strip() for v in entities.get(key) or []]
        out[key] = sorted({v for v in values if v and normalise(v).lower() in haystack})
    return out


# --- The call ---------------------------------------------------------------


def build_user_message(article: Article, candidate: Candidate) -> str:
    return (
        f"Source: {candidate.source}\n"
        f"URL: {article.final_url}\n"
        f"Feed title: {candidate.title}\n"
        f"Page metadata date: {article.published or 'not given'}\n\n"
        f"<article>\n{article.text}\n</article>"
    )


@api_retry
def _call(client: anthropic.Anthropic, user_message: str) -> anthropic.types.Message:
    return client.messages.create(
        model=config.EXTRACT_MODEL,
        max_tokens=config.EXTRACT_MAX_TOKENS,
        # anthropic 1.x removed sampling parameters from the method signature; Haiku 4.5
        # still honours temperature, so it goes in the request body directly.
        extra_body={"temperature": config.EXTRACT_TEMPERATURE},
        system=SYSTEM_PROMPT,
        tools=[EXTRACTION_TOOL],
        tool_choice={"type": "tool", "name": TOOL_NAME},
        messages=[{"role": "user", "content": user_message}],
    )


def tool_input(message: anthropic.types.Message) -> dict | None:
    for block in message.content:
        if block.type == "tool_use" and block.name == TOOL_NAME:
            return dict(block.input)
    return None


def parse_extraction(
    message: anthropic.types.Message, article: Article, candidate: Candidate
) -> Extraction | None:
    """Turn a model response into a validated Extraction, or None if nothing survives."""
    if message.stop_reason == "max_tokens":
        log.warning("%s: extraction hit max_tokens; discarded", candidate.url)
        return None
    data = tool_input(message)
    if data is None:
        log.warning("%s: no %s tool call in response", candidate.url, TOOL_NAME)
        return None

    claims, dropped = validate_claims(data.get("claims") or [], article.text)
    for d in dropped:
        log.info("%s: dropped claim (%s): %s", candidate.url, d["reason"], d["text"][:100])
    if not claims:
        log.warning("%s: no claims survived quote validation; article dropped", candidate.url)
        return None

    topics = [t for t in (data.get("topics") or []) if t in config.TOPICS] or ["other"]
    published = data.get("published_date") or None
    return Extraction(
        url=candidate.url,
        final_url=article.final_url,
        source=candidate.source,
        source_category=candidate.source_category,
        http_status=article.status,
        fetched_at=article.fetched_at,
        metadata_published=article.published,
        headline=str(data.get("headline") or candidate.title).strip(),
        publication=str(data.get("publication") or candidate.source).strip(),
        published_date=str(published) if published else None,
        summary=str(data.get("summary") or "").strip(),
        claims=claims,
        entities=filter_entities(data.get("entities") or {}, article.text),
        topics=topics,
        is_vendor_marketing=bool(data.get("is_vendor_marketing")),
        paywalled_or_partial=bool(data.get("paywalled_or_partial")),
        dropped_claims=dropped,
    )


def extract_article(
    client: anthropic.Anthropic, tracker: CostTracker, article: Article, candidate: Candidate
) -> Extraction | None:
    message = _call(client, build_user_message(article, candidate))
    tracker.record(config.EXTRACT_MODEL, message.usage)
    return parse_extraction(message, article, candidate)


def extract_all(
    client: anthropic.Anthropic,
    tracker: CostTracker,
    fetcher: Fetcher,
    candidates: list[Candidate],
) -> list[Extraction]:
    """Fetch and extract each candidate. One article failing never stops the run, but
    failures that affect every article (credentials, model, code) abort it."""
    results: list[Extraction] = []
    attempts = failures = 0
    for i, candidate in enumerate(candidates, 1):
        try:
            article = fetcher.fetch_article(candidate.url)
        except FetchError as exc:
            log.info("[%d/%d] fetch skipped: %s", i, len(candidates), exc)
            continue
        except Exception:
            log.exception("[%d/%d] unexpected fetch error: %s", i, len(candidates), candidate.url)
            continue
        attempts += 1
        try:
            extraction = extract_article(client, tracker, article, candidate)
        except BudgetExceeded:
            raise
        except FATAL_API_ERRORS as exc:
            raise ExtractionAborted(f"Anthropic API rejected the request: {exc}") from exc
        except (anthropic.APIError, Exception) as exc:
            failures += 1
            log.warning(
                "[%d/%d] extraction failed for %s: %s: %s",
                i,
                len(candidates),
                candidate.url,
                type(exc).__name__,
                exc,
            )
            if failures == attempts and failures >= MAX_INITIAL_FAILURES:
                raise ExtractionAborted(
                    f"the first {failures} extraction calls all failed; last error: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            continue
        if extraction:
            log.info(
                "[%d/%d] %d claim(s) kept, %d dropped: %s",
                i,
                len(candidates),
                len(extraction.claims),
                len(extraction.dropped_claims),
                extraction.headline,
            )
            results.append(extraction)
    return results
