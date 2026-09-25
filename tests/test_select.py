import json
from pathlib import Path

import httpx
import pytest

from dispatch_daily import select
from dispatch_daily.extract import Claim, Extraction
from dispatch_daily.publish import LocalStorage

FIXTURES = Path(__file__).parent / "fixtures"


def make_extraction(
    url: str, *, topics=None, marketing=False, identifiers=None, quote=""
) -> Extraction:
    return Extraction(
        url=url,
        final_url=url,
        source="Test Source",
        source_category="cyber",
        http_status=200,
        fetched_at="2026-09-24T10:00:00+00:00",
        metadata_published="2026-09-24",
        headline=f"Headline for {url}",
        publication="Test Source",
        published_date="2026-09-24",
        summary="A summary.",
        claims=[Claim(text="A claim.", quote=quote or "A quote long enough to count.")],
        entities={
            "vendors": [],
            "products": [],
            "researchers": [],
            "identifiers": identifiers or [],
        },
        topics=topics or ["identity"],
        is_vendor_marketing=marketing,
        paywalled_or_partial=False,
    )


# --- Score filter ------------------------------------------------------------


def test_apply_scores_drops_low_scores_marketing_and_other_only():
    extractions = [
        make_extraction("https://a/1"),
        make_extraction("https://a/2"),
        make_extraction("https://a/3", marketing=True),
        make_extraction("https://a/4", topics=["other"]),
        make_extraction("https://a/5", topics=["other", "identity"]),
        make_extraction("https://a/6"),
    ]
    scores = [
        select.Score("https://a/1", 9, "cyber", "r"),
        select.Score("https://a/2", 3, "cyber", "r"),  # below 4
        select.Score("https://a/3", 10, "cyber", "r"),  # marketing
        select.Score("https://a/4", 10, "cyber", "r"),  # other only
        select.Score("https://a/5", 4, "ai", "r"),  # other plus a real topic: kept
        # https://a/6 has no score at all: dropped
    ]
    kept = select.apply_scores(extractions, scores, max_items=10)
    assert [e.url for e, _ in kept] == ["https://a/1", "https://a/5"]


def test_apply_scores_caps_and_orders_by_score():
    extractions = [make_extraction(f"https://a/{i}") for i in range(15)]
    scores = [select.Score(f"https://a/{i}", 4 + (i % 7), "cyber", "r") for i in range(15)]
    kept = select.apply_scores(extractions, scores, max_items=10)
    assert len(kept) == 10
    values = [s.score for _, s in kept]
    assert values == sorted(values, reverse=True)


def test_prefilter_runs_before_scoring_call():
    kept = select.prefilter(
        [
            make_extraction("u1", marketing=True),
            make_extraction("u2", topics=["other"]),
            make_extraction("u3"),
        ]
    )
    assert [e.url for e in kept] == ["u3"]


def test_group_by_section_orders_and_omits_empty():
    items = [
        select.SelectedItem(make_extraction("u1"), select.Score("u1", 8, "fintech", "")),
        select.SelectedItem(make_extraction("u2"), select.Score("u2", 8, "engineering", "")),
        select.SelectedItem(make_extraction("u3"), select.Score("u3", 8, "fintech", "")),
    ]
    groups = select.group_by_section(items)
    assert [key for key, _, _ in groups] == ["engineering", "fintech"]
    assert [i.extraction.url for i in groups[1][2]] == ["u1", "u3"]


# --- CVE regex ---------------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["CVE-2021-44228", "CVE-2026-41234", "CVE-2024-123456", "CVE-1999-0001"]
)
def test_cve_regex_accepts_real_ids(value):
    assert select.is_valid_cve(value)
    assert select.find_cves(f"patched {value} today") == [value]


@pytest.mark.parametrize(
    "value",
    [
        "CVE-2024-1",
        "CVE-2024-123",
        "CVE-24-12345",
        "cve-2024-12345",
        "CVE_2024_12345",
        "CVE-2024-",
        "CVE-20245-1234",
        "XCVE-2024-12345",
    ],
)
def test_cve_regex_rejects_malformed(value):
    assert not select.is_valid_cve(value)
    assert select.find_cves(f"patched {value} today") == []


# --- NVD / KEV ---------------------------------------------------------------


def mock_http(nvd_body: dict, kev_body: dict, calls: list[str]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "nvd.nist.gov" in request.url.host:
            return httpx.Response(200, json=nvd_body)
        if "cisa.gov" in request.url.host:
            return httpx.Response(200, json=kev_body)
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


KEV = {
    "vulnerabilities": [
        {"cveID": "CVE-2026-41234", "dateAdded": "2026-09-23", "dueDate": "2026-10-14"}
    ]
}


def test_lookup_verified_cve_with_kev(tmp_path):
    nvd = json.loads((FIXTURES / "nvd_cve_response.json").read_text())
    calls: list[str] = []
    lookup = select.VulnLookup(LocalStorage(tmp_path), mock_http(nvd, KEV, calls), nvd_api_key="k")
    info = lookup.lookup("CVE-2026-41234")
    assert info.verified
    assert info.cvss_score == 9.8  # the Primary (NVD) score, not the vendor's
    assert info.cvss_version == "3.1"
    assert info.nvd_published == "2026-09-22"
    assert info.kev and info.kev_due_date == "2026-10-14"
    assert info.patch.startswith("Yes")
    assert info.label == "CVE-2026-41234"

    # Second lookup is served from the 24-hour cache.
    before = len(calls)
    lookup2 = select.VulnLookup(LocalStorage(tmp_path), mock_http(nvd, KEV, calls), "k")
    assert lookup2.lookup("CVE-2026-41234").cvss_score == 9.8
    assert len(calls) == before


def test_lookup_unknown_cve_is_marked_unverified(tmp_path):
    empty = {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    lookup = select.VulnLookup(LocalStorage(tmp_path), mock_http(empty, KEV, []), nvd_api_key="k")
    info = lookup.lookup("CVE-2026-99999")
    assert not info.verified
    assert info.label == "CVE-2026-99999 (unverified)"
    assert info.cvss_score is None and not info.kev


def test_attach_cves_uses_identifiers_and_quotes(tmp_path):
    nvd = json.loads((FIXTURES / "nvd_cve_response.json").read_text())
    lookup = select.VulnLookup(LocalStorage(tmp_path), mock_http(nvd, KEV, []), nvd_api_key="k")
    e = make_extraction(
        "u",
        identifiers=["CVE-2026-41234", "RFC 8725", "CVE-26-1"],
        quote="tracked as CVE-2026-41234 by the vendor",
    )
    item = select.SelectedItem(e, select.Score("u", 9, "vulnerabilities", ""))
    select.attach_cves([item], lookup)
    assert [c.cve_id for c in item.cves] == ["CVE-2026-41234"]


def test_score_extractions_parses_and_clamps(monkeypatch):
    extractions = [make_extraction("https://a/1"), make_extraction("https://a/2")]

    def fake_call(client, tracker, **kwargs):
        assert "https://a/1" in kwargs["user"]
        return {
            "scores": [
                {"url": "https://a/1", "score": 14, "category": "cyber", "reason": "r"},
                {"url": "https://a/2", "score": 5, "category": "ai", "reason": "r"},
                {"url": "https://invented/3", "score": 9, "category": "ai", "reason": "r"},
            ]
        }

    monkeypatch.setattr(select, "call_structured", fake_call)
    scores = select.score_extractions(None, None, extractions)
    assert [(s.url, s.score) for s in scores] == [("https://a/1", 10), ("https://a/2", 5)]


def test_thin_day_is_topped_up_to_minimum():
    extractions = [
        make_extraction("https://a/good"),
        make_extraction("https://a/low1"),
        make_extraction("https://a/low2"),
        make_extraction("https://a/other", topics=["other"]),
        make_extraction("https://a/mkt", marketing=True),
    ]
    scores = [
        select.Score("https://a/good", 8, "cyber", "r"),
        select.Score("https://a/low1", 3, "ai", "r"),
        select.Score("https://a/low2", 1, "fintech", "r"),
    ]
    kept = select.apply_scores(extractions, scores, max_items=10, min_items=4)
    urls = [e.url for e, _ in kept]
    assert urls[0] == "https://a/good"
    assert urls[1:] == ["https://a/low1", "https://a/low2", "https://a/other"]
    assert "https://a/mkt" not in urls  # marketing only if nothing else is left


def test_minimum_never_exceeds_available_or_maximum():
    extractions = [make_extraction("u1", marketing=True)]
    kept = select.apply_scores(extractions, [], max_items=10, min_items=5)
    assert [e.url for e, _ in kept] == ["u1"]  # even marketing beats an empty digest
    many = [make_extraction(f"u{i}") for i in range(8)]
    kept = select.apply_scores(many, [], max_items=3, min_items=5)
    assert len(kept) == 3
