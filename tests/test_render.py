import json
from datetime import UTC, date, datetime
from html.parser import HTMLParser

import pytest

from dispatch_daily import render
from dispatch_daily.publish import LocalStorage, publish
from dispatch_daily.select import CveInfo
from dispatch_daily.write import NOTHING_FOUND_INTRO, Digest, DigestItem

VOID = {"meta", "link", "br", "hr", "img", "input", "source", "wbr", "col", "area", "base"}
NOW = datetime(2026, 9, 24, 10, 45, tzinfo=UTC)


class BalanceChecker(HTMLParser):
    """Fails on mismatched or unclosed tags; a stand-in for an HTML validator."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.doctype = False

    def handle_decl(self, decl):
        self.doctype = decl.lower() == "doctype html"

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}>, open: {self.stack[-3:]}")
        else:
            self.stack.pop()


def assert_valid_html(html: str) -> None:
    checker = BalanceChecker()
    checker.feed(html)
    checker.close()
    assert checker.doctype, "missing <!DOCTYPE html>"
    assert not checker.errors, checker.errors
    assert not checker.stack, f"unclosed tags: {checker.stack}"


def item(section="cyber", **overrides) -> DigestItem:
    base = dict(
        section=section,
        headline="Examplar fixes an OIDC bypass in Edge Gateway 5.2.8",
        url="https://news.example.com/examplar",
        publication="Fixture Media",
        published_date="2026-09-23",
        summary="Examplar said version 5.2.8 fixes the flaw.",
        so_what="Teams running Edge Gateway in front of payment APIs should upgrade.",
        confidence="high",
        cves=[],
        claims=[{"text": "t", "quote": "Examplar said version 5.2.8"}],
    )
    base.update(overrides)
    return DigestItem(**base)


@pytest.fixture
def digest() -> Digest:
    return Digest(
        date=date(2026, 9, 24),
        intro="Identity gateways dominate today.",
        items=[
            item(
                "vulnerabilities",
                cves=[
                    CveInfo(
                        "CVE-2026-41234",
                        True,
                        9.8,
                        "CRITICAL",
                        "3.1",
                        "2026-09-22",
                        True,
                        "2026-09-23",
                        "2026-10-14",
                        "Yes (NVD patch reference)",
                    ),
                    CveInfo("CVE-2026-99999", False),
                ],
            ),
            item("engineering", headline="Platform teams adopt golden paths", confidence="check"),
            item("fintech", headline="Regulator publishes guidance"),
        ],
        stats={"candidates": 40, "extracted": 12, "cost_usd": 0.4321},
    )


def test_digest_renders_valid_html(digest):
    html = render.render_digest(digest, now=NOW)
    assert_valid_html(html)
    assert "max-width: 720px" in html
    assert 'name="viewport"' in html
    assert '<link rel="stylesheet"' not in html and "<script" not in html  # self-contained
    assert "Thursday 24 September 2026" in html
    assert "$0.43" in html


def test_sections_in_order_and_empty_sections_omitted(digest):
    html = render.render_digest(digest, now=NOW)
    order = [
        html.index(f'class="section" id="s{i}">{t}')
        for i, t in enumerate(
            ["Engineering &amp; Architecture", "Vulnerabilities", "Fintech &amp; Regulation"], 1
        )
    ]
    assert order == sorted(order)
    for absent in (">AI<", ">Cyber<", ">Standards<"):
        assert absent not in html


def test_item_parts_rendered(digest):
    html = render.render_digest(digest, now=NOW)
    assert '<a href="https://news.example.com/examplar"' in html
    assert "Fixture Media · 2026-09-23" in html
    assert 'class="sowhat"' in html and "So what" in html
    assert "CVE-2026-41234</a>" in html and "9.8 Critical (v3.1)" in html
    assert "Yes, due <span class=\"nowrap\">2026-10-14</span>" in html
    assert 'CVE-2026-99999 <span class="unverified">(unverified)</span>' in html
    assert html.count('class="badge"') == 1  # the one "check" item


def test_content_is_escaped():
    evil = Digest(
        date=date(2026, 9, 24),
        intro="Intro with <b>markup</b> & ampersand",
        items=[
            item(
                headline='<script>alert("x")</script> headline',
                summary="Tags like <img src=x onerror=alert(1)> must not render.",
                url="javascript:alert(1)",
                publication='Pub "quoted" & co',
                claims=[{"text": "t", "quote": "</q><script>bad()</script>"}],
            )
        ],
    )
    html = render.render_digest(evil, now=NOW)
    assert_valid_html(html)
    assert "<script>" not in html
    assert "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;b&gt;markup&lt;/b&gt; &amp; ampersand" in html
    assert 'href="javascript:' not in html
    assert 'href="#"' in html


def test_empty_digest_says_nothing_found():
    html = render.render_digest(Digest(date(2026, 9, 24), NOTHING_FOUND_INTRO, []), now=NOW)
    assert_valid_html(html)
    assert "Nothing significant was found" in html
    assert 'class="section"' not in html


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://a.example/x", "https://a.example/x"),
        ("../index.html", "../index.html"),
        ("javascript:alert(1)", "#"),
        ("JaVaScRiPt:alert(1)", "#"),
        ("data:text/html,hi", "#"),
        ("//evil.example/x", "#"),
    ],
)
def test_safe_url(value, expected):
    assert render.safe_url(value) == expected


def test_index_is_reverse_chronological_and_valid():
    html = render.render_index(
        [
            {"date": "2026-09-22", "items": 7},
            {"date": "2026-09-24", "items": 1},
            {"date": "2026-09-23", "items": 0},
        ]
    )
    assert_valid_html(html)
    positions = [html.index(f"digests/2026-09-{d}.html") for d in ("24", "23", "22")]
    assert positions == sorted(positions)
    assert "1 item<" in html and "0 items" in html and "7 items" in html


def test_publish_writes_digest_record_state_and_index(tmp_path, digest):
    storage = LocalStorage(tmp_path)
    record = {"digest": digest.to_dict(), "extractions": []}
    url = publish(
        storage, "2026-09-24", render.render_digest(digest, now=NOW), record, render.render_index
    )
    assert url.endswith("digests/2026-09-24.html")
    assert (tmp_path / "digests/2026-09-24.html").exists()
    saved = json.loads((tmp_path / "records/2026-09-24.json").read_text())
    assert saved["digest"]["items"][0]["claims"][0]["quote"] == "Examplar said version 5.2.8"
    # Re-publishing the same date replaces, not duplicates, the index entry.
    publish(storage, "2026-09-24", "<!DOCTYPE html><html></html>", record, render.render_index)
    issues = json.loads((tmp_path / "state/issues.json").read_text())["issues"]
    assert issues == [{"date": "2026-09-24", "items": 3}]
    assert "digests/2026-09-24.html" in (tmp_path / "index.html").read_text()
