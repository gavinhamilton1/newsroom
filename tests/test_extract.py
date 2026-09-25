import json
from pathlib import Path

import anthropic
import pytest

from dispatch_daily import extract
from dispatch_daily.cost import BudgetExceeded, CostTracker
from dispatch_daily.fetch import Article, extract_main_text
from dispatch_daily.sources import Candidate
from tests.conftest import assert_sdk_accepts

FIXTURES = Path(__file__).parent / "fixtures"
URL = "https://news.example.com/2026/09/23/examplar-gateway"


@pytest.fixture
def article() -> Article:
    html = (FIXTURES / "article_gateway_cve.html").read_text()
    text, published, title = extract_main_text(html, URL)
    return Article(URL, URL, 200, "2026-09-23T15:00:00+00:00", published, title, text)


@pytest.fixture
def candidate() -> Candidate:
    return Candidate("Fixture Media", "vuln", URL, "Critical flaw in Examplar Edge Gateway", None)


@pytest.fixture
def recorded() -> anthropic.types.Message:
    data = json.loads((FIXTURES / "article_gateway_cve.response.json").read_text())
    return anthropic.types.Message.model_validate(data)


@pytest.fixture
def expected() -> dict:
    return json.loads((FIXTURES / "article_gateway_cve.expected.json").read_text())


def test_fixture_text_extracts(article):
    assert len(article.text) >= 400
    assert "CVE-2026-41234" in article.text
    assert article.published == "2026-09-23"


def test_quote_validation_keeps_supported_and_drops_unsupported(
    article, candidate, recorded, expected
):
    result = extract.parse_extraction(recorded, article, candidate)
    assert result is not None
    assert [c.text for c in result.claims] == expected["kept_claims"]
    assert {d["text"]: d["reason"] for d in result.dropped_claims} == expected["dropped_reasons"]
    for claim in result.claims:
        assert extract.normalise(claim.quote) in extract.normalise(article.text)


def test_entities_filtered_to_article_text(article, candidate, recorded, expected):
    result = extract.parse_extraction(recorded, article, candidate)
    assert result.entities == expected["entities"]
    assert result.topics == expected["topics"]


def test_corrupted_quote_is_dropped(article):
    good = {"text": "Version 5.2.8 fixes the flaw.", "quote": "Examplar said version 5.2.8"}
    kept, dropped = extract.validate_claims([good], article.text)
    assert len(kept) == 1 and not dropped

    corrupted = {"text": "Version 5.2.9 fixes the flaw.", "quote": "Examplar said version 5.2.9"}
    kept, dropped = extract.validate_claims([corrupted], article.text)
    assert not kept
    assert dropped[0]["reason"] == "quote not found in article text"


def test_whitespace_and_typographic_quotes_are_normalised():
    text = "He said “the  token\nwas  unsigned” on Monday, at version 2.1."
    claims = [{"text": "He said the token was unsigned.", "quote": 'said "the token was unsigned"'}]
    kept, dropped = extract.validate_claims(claims, text)
    assert len(kept) == 1, dropped


def test_article_dropped_when_no_claims_survive(article, candidate, recorded):
    data = recorded.model_dump()
    data["content"][0]["input"]["claims"] = [
        {"text": "Invented claim.", "quote": "this sentence is not in the article at all"}
    ]
    message = anthropic.types.Message.model_validate(data)
    assert extract.parse_extraction(message, article, candidate) is None


def test_missing_tool_call_is_dropped(article, candidate, recorded):
    data = recorded.model_dump()
    data["content"] = [{"type": "text", "text": "I cannot help with that."}]
    data["stop_reason"] = "end_turn"
    message = anthropic.types.Message.model_validate(data)
    assert extract.parse_extraction(message, article, candidate) is None


def test_extract_article_uses_haiku_at_temperature_zero(article, candidate, recorded):
    calls = []

    class FakeMessages:
        def create(self, **kwargs):
            assert_sdk_accepts("create", kwargs)
            calls.append(kwargs)
            return recorded

    class FakeClient:
        messages = FakeMessages()

    tracker = CostTracker(ceiling_usd=2.0)
    result = extract.extract_article(FakeClient(), tracker, article, candidate)
    assert result is not None
    assert calls[0]["model"] == "claude-haiku-4-5-20251001"
    assert calls[0]["extra_body"] == {"temperature": 0}
    assert calls[0]["tool_choice"] == {"type": "tool", "name": "record_extraction"}
    assert "<article>" in calls[0]["messages"][0]["content"]
    assert tracker.total_usd == pytest.approx((1450 * 1.0 + 820 * 5.0) / 1_000_000)


def test_budget_cap_aborts(recorded):
    tracker = CostTracker(ceiling_usd=0.001)
    with pytest.raises(BudgetExceeded):
        tracker.record("claude-haiku-4-5-20251001", recorded.usage)


def test_sdk_signature_guard_rejects_removed_parameters():
    with pytest.raises(TypeError):
        assert_sdk_accepts(
            "create", {"model": "m", "max_tokens": 1, "messages": [], "temperature": 0}
        )
