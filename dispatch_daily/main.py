"""Pipeline entry point: python -m dispatch_daily.main [flags]."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime, timedelta

from . import config
from .fetch import Fetcher
from .sources import Candidate, collect, load_sources, lookback_hours

log = logging.getLogger("dispatch_daily")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="dispatch_daily", description="Build the daily digest.")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="collect and extract, print the selection table; no writing call, no upload",
    )
    p.add_argument("--limit", type=int, help="cap the number of candidates (cheap local runs)")
    p.add_argument("--no-upload", action="store_true", help="write HTML to ./out/ instead of R2")
    p.add_argument("--since", type=int, metavar="HOURS", help="override the lookback window")
    p.add_argument("--source", metavar="NAME", help="run a single source (for debugging)")
    return p.parse_args(argv)


def print_candidates(candidates: list[Candidate]) -> None:
    print(f"\n{'PUBLISHED (UTC)':<17} {'SOURCE':<28} TITLE")
    for c in candidates:
        when = c.published.strftime("%Y-%m-%d %H:%M") if c.published else "?"
        print(f"{when:<17} {c.source[:28]:<28} {c.title[:90]}")
    print(f"\n{len(candidates)} candidate(s)\n")


def run(args: argparse.Namespace) -> int:
    settings = config.load_settings()
    config.setup_logging(settings.log_level)
    now = datetime.now(UTC)
    hours = lookback_hours(now, args.since, settings.lookback_hours)
    since = now - timedelta(hours=hours)
    log.info("Lookback window: %d hours (since %s)", hours, since.isoformat(timespec="minutes"))

    sources = load_sources()
    if args.source:
        sources = [s for s in sources if s.name.lower() == args.source.lower()]
        if not sources:
            log.error("No source named %r in sources.yaml", args.source)
            return 2

    max_total = min(config.MAX_CANDIDATES, args.limit) if args.limit else config.MAX_CANDIDATES
    fetcher = Fetcher()
    try:
        candidates = collect(fetcher, sources, since, now, max_total=max_total)
    finally:
        fetcher.close()

    print_candidates(candidates)
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
