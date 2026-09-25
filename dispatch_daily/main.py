"""Pipeline entry point: python -m dispatch_daily.main [flags]."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime, timedelta

from . import config
from .cost import BudgetExceeded, CostTracker, make_client
from .extract import Extraction, extract_all
from .fetch import Fetcher
from .publish import LocalStorage, ReadOnlyStorage, Storage, make_storage
from .select import Score, SelectedItem, VulnLookup, select
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


def print_extractions(extractions: list[Extraction]) -> None:
    print(f"\n{'CLAIMS':>6} {'DROP':>4} {'MKT':<3} {'TOPICS':<32} HEADLINE")
    for e in extractions:
        mkt = "yes" if e.is_vendor_marketing else ""
        topics = ",".join(e.topics)[:32]
        print(
            f"{len(e.claims):>6} {len(e.dropped_claims):>4} {mkt:<3} {topics:<32} {e.headline[:70]}"
        )
    print(f"\n{len(extractions)} article(s) extracted\n")


def print_selection(
    extractions: list[Extraction], scores: list[Score], items: list[SelectedItem]
) -> None:
    by_url = {s.url: s for s in scores}
    chosen = {i.extraction.url for i in items}
    print(f"\n{'SEL':<3} {'SCORE':>5} {'CATEGORY':<15} {'HEADLINE':<60} REASON")
    rows = sorted(extractions, key=lambda e: -(by_url[e.url].score if e.url in by_url else -1))
    for e in rows:
        s = by_url.get(e.url)
        mark = "*" if e.url in chosen else ""
        score = str(s.score) if s else "-"
        category = s.category if s else "(filtered)"
        reason = s.reason if s else ("vendor marketing" if e.is_vendor_marketing else "topic")
        print(f"{mark:<3} {score:>5} {category:<15} {e.headline[:60]:<60} {reason[:80]}")
    for item in items:
        for cve in item.cves:
            print(
                f"    {cve.label}: CVSS {cve.cvss_score or '-'} "
                f"KEV {'yes' if cve.kev else 'no'}, patch {cve.patch}"
            )
    print(f"\n{len(items)} item(s) selected\n")


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
    if args.dry_run:
        storage = ReadOnlyStorage(storage)
    seen = SeenIndex.load(storage)

    client = make_client(settings)
    tracker = CostTracker(ceiling_usd=settings.max_cost_usd)
    fetcher = Fetcher()
    try:
        candidates = collect(fetcher, sources, since, now)
        candidates = dedupe(candidates, seen)
        if args.limit:
            candidates = candidates[: args.limit]
        print_candidates(candidates)
        extractions = extract_all(client, tracker, fetcher, candidates)
        print_extractions(extractions)
        lookup = VulnLookup(storage, fetcher.client, settings.nvd_api_key)
        items, scores = select(
            client, tracker, extractions, lookup, max_items=settings.digest_max_items
        )
        print_selection(extractions, scores, items)
    except BudgetExceeded as exc:
        log.error("Run aborted: %s. %s", exc, tracker.summary())
        return 1
    finally:
        fetcher.close()

    log.info(tracker.summary())
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
