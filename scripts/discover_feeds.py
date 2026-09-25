"""One-off: find RSS/Atom feeds for sources in sources.yaml and write them back.

For each source with `feed: null`, fetch its URL (honouring robots.txt), look for
<link rel="alternate" type="application/rss+xml|atom+xml">, and if none is advertised
try a few conventional feed paths. A candidate is only accepted if it parses as a feed
with at least one entry. The file is edited line by line so comments and notes survive.

    python scripts/discover_feeds.py            # fill in missing feeds
    python scripts/discover_feeds.py --dry-run  # report only
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

import feedparser

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dispatch_daily import config  # noqa: E402
from dispatch_daily.fetch import Fetcher, FetchError  # noqa: E402
from dispatch_daily.sources import Source, discover_feed_links, load_sources  # noqa: E402

log = logging.getLogger("discover_feeds")

COMMON_PATHS = ["feed/", "rss/", "feed.xml", "rss.xml", "atom.xml", "index.xml"]


def is_feed(fetcher: Fetcher, url: str) -> bool:
    try:
        resp = fetcher.get(url)
    except FetchError:
        return False
    parsed = feedparser.parse(resp.content)
    return bool(parsed.entries) and bool(parsed.get("version"))


def find_feed(fetcher: Fetcher, source: Source) -> str | None:
    resp = fetcher.get(source.url)
    base = str(resp.url)
    for candidate in discover_feed_links(resp.text, base):
        if is_feed(fetcher, candidate):
            return candidate
    page = base if base.endswith("/") else base + "/"
    for path in COMMON_PATHS:
        candidate = urljoin(page, path)
        if is_feed(fetcher, candidate):
            return candidate
    return None


def write_feeds(path: Path, feeds: dict[str, str]) -> int:
    """Replace `feed: null` under each named source. Returns the number of edits."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    current: str | None = None
    edits = 0
    name_re = re.compile(r'^\s*-\s*name:\s*"?(.*?)"?\s*$')
    feed_re = re.compile(r"^(\s*)feed:\s*null\s*$")
    for i, line in enumerate(lines):
        m = name_re.match(line)
        if m:
            current = m.group(1)
            continue
        m = feed_re.match(line)
        if m and current in feeds:
            lines[i] = f'{m.group(1)}feed: "{feeds[current]}"\n'
            edits += 1
    path.write_text("".join(lines), encoding="utf-8")
    return edits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="report only; do not edit")
    parser.add_argument("--file", type=Path, default=config.SOURCES_FILE)
    args = parser.parse_args()
    config.setup_logging("INFO")

    fetcher = Fetcher()
    found: dict[str, str] = {}
    try:
        for source in load_sources(args.file):
            if source.feed:
                continue
            try:
                feed = find_feed(fetcher, source)
            except FetchError as exc:
                log.warning("%-45s skipped (%s)", source.name, exc)
                continue
            except Exception:
                log.exception("%-45s unexpected error", source.name)
                continue
            if feed:
                log.info("%-45s %s", source.name, feed)
                found[source.name] = feed
            else:
                log.info("%-45s no feed found", source.name)
    finally:
        fetcher.close()

    if args.dry_run:
        log.info("Dry run: %d feed(s) found, file not changed", len(found))
    else:
        log.info("Wrote %d feed(s) to %s", write_feeds(args.file, found), args.file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
