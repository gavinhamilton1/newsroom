"""Load sources.yaml and collect candidate article links published in the lookback window."""

from __future__ import annotations

import calendar
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import feedparser
import lxml.html
import yaml

from . import config
from .fetch import Fetcher, FetchError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    category: str
    type: str
    feed: str | None = None
    note: str | None = None


@dataclass
class Candidate:
    source: str
    source_category: str
    url: str
    title: str
    published: datetime | None


def load_sources(path: Path = config.SOURCES_FILE) -> list[Source]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [
        Source(
            name=s["name"],
            url=s["url"],
            category=s.get("category", ""),
            type=s.get("type", ""),
            feed=s.get("feed") or None,
            note=s.get("note"),
        )
        for s in data.get("sources", [])
    ]


def lookback_hours(now: datetime, override: int | None, default: int) -> int:
    """24 hours normally; 72 on Mondays so the weekend is covered. --since wins."""
    if override is not None:
        return override
    if now.weekday() == 0:
        return max(default, 72)
    return default


def canonical_url(url: str) -> str:
    """Strip fragments and common tracking parameters so the same story dedupes."""
    parts = urlsplit(url)
    query = "&".join(
        p
        for p in parts.query.split("&")
        if p and not p.lower().startswith(("utm_", "fbclid", "gclid", "mc_cid", "mc_eid"))
    )
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path, query, ""))


# --- Feeds ------------------------------------------------------------------


def _entry_datetime(entry: feedparser.FeedParserDict) -> datetime | None:
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if parsed:
            return datetime.fromtimestamp(calendar.timegm(parsed), tz=UTC)
    return None


def parse_feed_entries(
    source: Source, content: bytes, since: datetime, now: datetime
) -> list[Candidate]:
    parsed = feedparser.parse(content)
    if parsed.bozo and not parsed.entries:
        raise FetchError(f"{source.name}: feed did not parse ({parsed.bozo_exception})")
    out: list[Candidate] = []
    undated = 0
    for entry in parsed.entries:
        link = entry.get("link")
        if not link:
            continue
        published = _entry_datetime(entry)
        if published is None:
            undated += 1
            continue
        # Allow a little clock skew into the future, but no further.
        if since <= published <= now + timedelta(hours=1):
            out.append(
                Candidate(
                    source=source.name,
                    source_category=source.category,
                    url=canonical_url(link),
                    title=(entry.get("title") or "").strip(),
                    published=published,
                )
            )
    if undated:
        log.info("%s: skipped %d feed entries with no date", source.name, undated)
    out.sort(key=lambda c: c.published or since, reverse=True)
    return out


# --- Listing pages (sources without a feed) ---------------------------------

# /2026/09/24/ or /2026-09-24/ (or -slug). The slash form must end the segment, so
# /2026/09/25-years-after-... is not read as 25 September.
_URL_DATE = re.compile(
    r"/(20\d{2})(?:/(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/"
    r"|-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?:[/-]|$))"
)


def _parse_iso(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_listing_links(
    source: Source, html: str, base_url: str, since: datetime, now: datetime
) -> list[Candidate]:
    """Find article links on a listing page whose publication date we can actually see.

    Two signals are trusted: a <time datetime="..."> inside the same <article> (or list
    item) as the link, and a full yyyy/mm/dd date in the URL path. Anything else is
    ignored, because guessing dates is how old stories end up in a daily digest.
    """
    doc = lxml.html.fromstring(html)
    for bad in doc.xpath("//script | //style | //noscript"):
        bad.drop_tree()
    doc.make_links_absolute(base_url)
    host = urlsplit(base_url).netloc.lower().removeprefix("www.")
    found: dict[str, Candidate] = {}

    def consider(href: str, title: str, published: datetime | None) -> None:
        if published is None or not (since <= published <= now + timedelta(hours=1)):
            return
        link_host = urlsplit(href).netloc.lower().removeprefix("www.")
        if link_host != host:
            return
        url = canonical_url(href)
        if url not in found and title:
            found[url] = Candidate(source.name, source.category, url, title, published)

    # Signal 1: <time datetime> within the same article/list item block.
    for block in doc.xpath("//article | //li | //div[contains(@class,'post')]"):
        times = block.xpath(".//time[@datetime]")
        links = block.xpath(".//a[@href]")
        if len(times) != 1 or not links:
            continue
        published = _parse_iso(times[0].get("datetime", ""))
        # Prefer the link that wraps a heading, then the longest link text.
        heading_links = block.xpath(".//h1//a[@href] | .//h2//a[@href] | .//h3//a[@href]")
        by_text_length = sorted(links, key=lambda a: len(a.text_content()), reverse=True)
        link = (heading_links or by_text_length)[0]
        consider(link.get("href"), " ".join(link.text_content().split()), published)

    # Signal 2: date in the URL path.
    for a in doc.xpath("//a[@href]"):
        href = a.get("href")
        m = _URL_DATE.search(urlsplit(href).path)
        if not m:
            continue
        y = int(m.group(1))
        mo = int(m.group(2) or m.group(4))
        d = int(m.group(3) or m.group(5))
        try:
            # A path date has day resolution; treat it as the end of that day (UTC),
            # capped at now, so a story from today is not excluded by the hour.
            published = datetime(y, mo, d, 23, 59, tzinfo=UTC)
        except ValueError:
            continue
        if published.date() > now.date():
            continue  # a future date in a URL is not a publication date
        published = min(published, now)
        consider(href, " ".join(a.text_content().split()), published)

    return sorted(found.values(), key=lambda c: c.published or since, reverse=True)


# --- Per-source collection --------------------------------------------------


def collect_source(
    fetcher: Fetcher, source: Source, since: datetime, now: datetime
) -> list[Candidate]:
    if source.feed:
        resp = fetcher.get(source.feed)
        items = parse_feed_entries(source, resp.content, since, now)
    else:
        resp = fetcher.get(source.url)
        items = parse_listing_links(source, resp.text, str(resp.url), since, now)
        if not items:
            log.info("%s: no feed and no dated links found on listing page; skipped", source.name)
    return items[: config.MAX_PER_SOURCE]


def collect(
    fetcher: Fetcher,
    sources: list[Source],
    since: datetime,
    now: datetime,
    max_total: int = config.MAX_CANDIDATES,
) -> list[Candidate]:
    """Collect candidates from every source. One source failing never stops the run."""
    per_source: list[list[Candidate]] = []
    for source in sources:
        try:
            items = collect_source(fetcher, source, since, now)
            if items:
                log.info("%s: %d candidate(s)", source.name, len(items))
            per_source.append(items)
        except FetchError as exc:
            log.warning("%s: skipped (%s)", source.name, exc)
        except Exception:
            log.exception("%s: unexpected error, skipped", source.name)
    return round_robin(per_source, max_total)


def round_robin(per_source: list[list[Candidate]], max_total: int) -> list[Candidate]:
    """Take each source's newest item, then each source's second, and so on, so the
    cap does not hand the whole run to the highest-volume sources."""
    total = sum(len(items) for items in per_source)
    out: list[Candidate] = []
    rank = 0
    while len(out) < max_total and any(rank < len(items) for items in per_source):
        for items in per_source:
            if rank < len(items) and len(out) < max_total:
                out.append(items[rank])
        rank += 1
    if total > max_total:
        log.info("Capped %d candidates to %d", total, max_total)
    return out


def discover_feed_links(html: str, base_url: str) -> list[str]:
    """Return RSS/Atom feed URLs advertised with <link rel="alternate">."""
    doc = lxml.html.fromstring(html)
    urls = []
    for link in doc.xpath("//link[@href]"):
        rel = (link.get("rel") or "").lower().split()
        typ = (link.get("type") or "").lower()
        if "alternate" in rel and typ in ("application/rss+xml", "application/atom+xml"):
            urls.append(urljoin(base_url, link.get("href")))
    # Prefer a section feed that matches the page's path (a category page usually
    # advertises both the site-wide feed and its own), and never a comments feed.
    page_segments = [s for s in urlsplit(base_url).path.split("/") if s]

    def rank(u: str) -> tuple[bool, int]:
        segments = [s for s in urlsplit(u).path.split("/") if s]
        shared = 0
        for a, b in zip(page_segments, segments, strict=False):
            if a != b:
                break
            shared += 1
        return ("comment" in u.lower(), -shared)

    urls.sort(key=rank)
    return urls
