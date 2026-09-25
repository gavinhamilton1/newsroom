from datetime import date

from dispatch_daily import write
from dispatch_daily.extract import Claim, Extraction
from dispatch_daily.select import CveInfo, Score, SelectedItem


def make_item(url="https://news.example.com/a", category="vulnerabilities", cves=None):
    e = Extraction(
        url=url,
        final_url=url,
        source="Fixture",
        source_category="vuln",
        http_status=200,
        fetched_at="2026-09-24T10:00:00+00:00",
        metadata_published=None,
        headline="Critical flaw in Examplar Edge Gateway",
        publication="Fixture Media",
        published_date="2026-09-23",
        summary="s",
        claims=[
            Claim(
                "Tracked as CVE-2026-41234, rated 9.8.",
                "tracked as CVE-2026-41234 and rated 9.8 on the CVSS v3.1 scale",
            ),
            Claim(
                "Version 5.2.8 fixes it.", "Examplar said version 5.2.8, published on 22 September"
            ),
        ],
        entities={
            "vendors": ["Examplar Networks"],
            "products": [],
            "researchers": [],
            "identifiers": ["CVE-2026-41234"],
        },
        topics=["vulnerability"],
        is_vendor_marketing=False,
        paywalled_or_partial=False,
    )
    return SelectedItem(e, Score(url, 9, category, "r"), cves or [])


def test_writer_sees_only_claims_and_quotes(monkeypatch):
    seen = {}

    def fake_call(client, tracker, **kwargs):
        seen.update(kwargs)
        return {
            "intro": "One flaw today.",
            "items": [
                {
                    "id": "item1",
                    "headline": "Examplar fixes gateway flaw",
                    "confidence": "high",
                    "summary": "Examplar said version 5.2.8 fixes CVE-2026-41234. It is rated 9.8.",
                    "so_what": "Upgrade to 5.2.8 soon.",
                }
            ],
        }

    monkeypatch.setattr(write, "call_structured", fake_call)
    digest = write.write_digest(None, None, [make_item()], date(2026, 9, 24))
    assert "<article>" not in seen["user"]
    assert "tracked as CVE-2026-41234" in seen["user"]
    assert "Use only the article" not in seen["system"]
    assert "British English" in seen["system"]
    assert len(digest.items) == 1
    item = digest.items[0]
    assert item.confidence == "high"
    # Not verified in NVD, so the ID must carry the mark.
    assert "CVE-2026-41234 (unverified)" in item.summary


def test_unsupported_sentence_removed_and_confidence_downgraded(monkeypatch):
    cve = CveInfo(
        "CVE-2026-41234", verified=True, cvss_score=9.8, kev=True, kev_due_date="2026-10-14"
    )

    def fake_call(client, tracker, **kwargs):
        return {
            "intro": "Intro.",
            "items": [
                {
                    "id": "item1",
                    "headline": "Examplar fixes gateway flaw",
                    "confidence": "high",
                    "summary": "Version 5.2.8 fixes CVE-2026-41234. "
                    "About 40,000 devices are exposed. "
                    "CISA set a deadline of 14 October.",
                    "so_what": "Patch now — it is in KEV.",
                }
            ],
        }

    monkeypatch.setattr(write, "call_structured", fake_call)
    digest = write.write_digest(None, None, [make_item(cves=[cve])], date(2026, 9, 24))
    item = digest.items[0]
    assert "40,000" not in item.summary
    assert "14 October" in item.summary  # supported by the KEV record
    assert "CVE-2026-41234 (unverified)" not in item.summary
    assert item.confidence == "check"
    assert "—" not in item.so_what


def test_no_items_skips_call_and_says_so(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("no writing call expected")

    monkeypatch.setattr(write, "call_structured", fail)
    digest = write.write_digest(None, None, [], date(2026, 9, 24))
    assert digest.items == []
    assert "Nothing significant" in digest.intro
