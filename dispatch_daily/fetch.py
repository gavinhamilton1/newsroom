"""HTTP client, robots.txt checks and article text extraction.

Every outbound request to a news site goes through `Fetcher`, which sets a descriptive
User-Agent, honours robots.txt and retries only transient failures.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib import robotparser
from urllib.parse import urlsplit

import httpx
import trafilatura
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from . import config

log = logging.getLogger(__name__)


class FetchError(Exception):
    """A page could not be fetched; the caller should skip it and move on."""


class RobotsDisallowed(FetchError):
    """robots.txt disallows fetching this URL for our User-Agent."""


def is_retryable(exc: BaseException) -> bool:
    """Retry only timeouts, connection errors and HTTP 429/5xx."""
    if isinstance(exc, httpx.TimeoutException | httpx.ConnectError | httpx.RemoteProtocolError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code == 429 or code >= 500
    return False


http_retry = retry(
    retry=retry_if_exception(is_retryable),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)


@dataclass
class Article:
    url: str  # the URL we were given (from the feed or listing page)
    final_url: str  # after redirects
    status: int
    fetched_at: str  # ISO 8601 UTC
    published: str | None  # from page metadata, if any
    title: str | None
    text: str  # main text, truncated to MAX_ARTICLE_CHARS


class Fetcher:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self.client = client or httpx.Client(
            headers={"User-Agent": config.USER_AGENT, "Accept-Language": "en"},
            timeout=config.HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
        )
        self._robots: dict[str, robotparser.RobotFileParser] = {}

    def close(self) -> None:
        self.client.close()

    # --- robots.txt ---------------------------------------------------------

    def _robots_for(self, url: str) -> robotparser.RobotFileParser:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in self._robots:
            return self._robots[origin]
        rp = robotparser.RobotFileParser()
        robots_url = f"{origin}/robots.txt"
        try:
            resp = self._raw_get(robots_url)
            if resp.status_code in (401, 403):
                # Same convention as urllib.robotparser: access-restricted robots.txt
                # means the site does not want to be crawled.
                rp.disallow_all = True
            elif resp.status_code >= 400:
                rp.allow_all = True
            else:
                rp.parse(resp.text.splitlines())
        except httpx.HTTPError as exc:
            # Could not read robots.txt at all. Be conservative and treat the site
            # as unavailable for this run rather than assuming permission.
            log.warning("robots.txt unreachable for %s (%s); skipping host", origin, exc)
            rp.disallow_all = True
        self._robots[origin] = rp
        return rp

    def allowed(self, url: str) -> bool:
        return self._robots_for(url).can_fetch(config.USER_AGENT, url)

    # --- GET ----------------------------------------------------------------

    @http_retry
    def _raw_get(self, url: str) -> httpx.Response:
        resp = self.client.get(url)
        if resp.status_code == 429 or resp.status_code >= 500:
            resp.raise_for_status()
        return resp

    def get(self, url: str) -> httpx.Response:
        """Fetch a URL after checking robots.txt. Raises FetchError on any failure."""
        if not self.allowed(url):
            raise RobotsDisallowed(f"robots.txt disallows {url}")
        try:
            resp = self._raw_get(url)
        except httpx.HTTPError as exc:
            raise FetchError(f"{url}: {exc}") from exc
        if resp.status_code >= 400:
            raise FetchError(f"{url}: HTTP {resp.status_code}")
        return resp

    # --- Articles -----------------------------------------------------------

    def fetch_article(self, url: str) -> Article:
        resp = self.get(url)
        fetched_at = datetime.now(UTC).isoformat(timespec="seconds")
        extracted = extract_main_text(resp.text, str(resp.url))
        if extracted is None:
            raise FetchError(f"{url}: text extraction failed")
        text, published, title = extracted
        if len(text) < config.MIN_ARTICLE_CHARS:
            raise FetchError(f"{url}: extracted text too short ({len(text)} chars)")
        return Article(
            url=url,
            final_url=str(resp.url),
            status=resp.status_code,
            fetched_at=fetched_at,
            published=published,
            title=title,
            text=text[: config.MAX_ARTICLE_CHARS],
        )


def extract_main_text(html: str, url: str) -> tuple[str, str | None, str | None] | None:
    """Return (text, published_date, title) using trafilatura, or None on failure."""
    raw = trafilatura.extract(
        html,
        url=url,
        output_format="json",
        with_metadata=True,
        include_comments=False,
        include_tables=True,
        favor_precision=True,
    )
    if not raw:
        return None
    data = json.loads(raw)
    text = (data.get("text") or "").strip()
    if not text:
        return None
    return text, data.get("date") or None, data.get("title") or None
