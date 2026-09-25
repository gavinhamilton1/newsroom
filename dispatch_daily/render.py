"""Jinja2 rendering of the digest and the index of past issues."""

from __future__ import annotations

from datetime import UTC, date, datetime
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from . import config
from .write import Digest


def safe_url(value: str) -> str:
    """Allow http(s) and relative links only; anything else (javascript:, data:) becomes '#'."""
    value = (value or "").strip()
    scheme = urlsplit(value).scheme.lower()
    if scheme in ("http", "https", "") and not value.startswith("//"):
        return value
    return "#"


def long_date(d: date) -> str:
    return f"{d:%A} {d.day} {d:%B %Y}"


def make_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(config.TEMPLATES_DIR),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    env.filters["safe_url"] = safe_url
    return env


def render_digest(
    digest: Digest, index_url: str | None = "../index.html", now: datetime | None = None
) -> str:
    now = now or datetime.now(UTC)
    return (
        make_env()
        .get_template("digest.html.j2")
        .render(
            digest=digest,
            sections=digest.sections,
            stats=digest.stats,
            long_date=long_date(digest.date),
            generated_at=now.strftime("%Y-%m-%d %H:%M UTC"),
            index_url=index_url,
        )
    )


def render_index(issues: list[dict]) -> str:
    """`issues` are {"date": "YYYY-MM-DD", "items": int}; rendered newest first."""
    rows = []
    for issue in sorted(issues, key=lambda i: i["date"], reverse=True):
        d = date.fromisoformat(issue["date"])
        rows.append(
            {
                "href": f"digests/{issue['date']}.html",
                "long_date": long_date(d),
                "count": issue["items"],
            }
        )
    return make_env().get_template("index.html.j2").render(issues=rows)
