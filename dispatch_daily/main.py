"""Pipeline entry point: python -m dispatch_daily.main [flags]."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime, timedelta

from . import config
from .fetch import Fetcher
from .publish import LocalStorage, Storage, make_storage
from .sources import Candidate, collect, load_sources, lookback_hours
from .state import SeenIndex, dedupe

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

    # Where state and output live. --no-upload keeps everything under ./out/. A dry run
    # reads the real seen index when R2 is configured but never writes anything.
    storage: Storage
    if args.no_upload or (args.dry_run and not settings.r2_configured):
        storage = LocalStorage()
    else:
        storage = make_storage(settings, local=False)
    seen = SeenIndex.load(storage)

    fetcher = Fetcher()
    try:
        candidates = collect(fetcher, sources, since, now)
        candidates = dedupe(candidates, seen)
        if args.limit:
            candidates = candidates[: args.limit]
    finally:
        fetcher.close()

    print_candidates(candidates)

    if args.dry_run:
        return 0

    today = now.date()
    for c in candidates:
        seen.add(c.url, today)
    pruned = seen.prune(today)
    seen.save(storage)
    log.info("Seen index saved (%d entries, %d pruned)", len(seen.entries), pruned)
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
