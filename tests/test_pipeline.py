"""End-to-end run of main.run() on fixtures, with every network call mocked."""

import json
from pathlib import Path

import anthropic
import pytest

from dispatch_daily import main
from dispatch_daily.fetch import Article, extract_main_text
from dispatch_daily.publish import LocalStorage
from dispatch_daily.select import CveInfo
from dispatch_daily.sources import Candidate

FIXTURES = Path(__file__).parent / "fixtures"
SUMMARY = (
    "Examplar said version 5.2.8, published on 22 September, corrects the validation logic "
    "behind CVE-2026-41234. Northwind Security found 1,200 internet-facing instances. "
    "Exploitation began on 3 March."
)
URL = "https://news.example.com/2026/09/23/examplar-gateway"


def opus_message(payload: dict) -> anthropic.types.Message:
    return anthropic.types.Message.model_validate(
        {
            "id": "msg_opus",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-5-5",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 3000, "output_tokens": 1500},
            "content": [{"type": "text", "text": json.dumps(payload)}],
        }
    )


class FakeStream:
    def __init__(self, message):
        self.message = message

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self.message


class FakeMessages:
    def __init__(self):
        self.create_calls, self.stream_calls = [], []

    def create(self, **kwargs):  # Haiku extraction
        self.create_calls.append(kwargs)
        data = json.loads((FIXTURES / "article_gateway_cve.response.json").read_text())
        return anthropic.types.Message.model_validate(data)

    def stream(self, **kwargs):  # Opus ranking, then writing
        self.stream_calls.append(kwargs)
        if len(self.stream_calls) == 1:
            return FakeStream(
                opus_message(
                    {
                        "scores": [
                            {
                                "url": URL,
                                "score": 9,
                                "category": "vulnerabilities",
                                "reason": "Ingress auth",
                            }
                        ]
                    }
                )
            )
        return FakeStream(
            opus_message(
                {
                    "intro": "Token validation at the gateway is today's theme. One fix is urgent.",
                    "items": [
                        {
                            "id": "item1",
                            "headline": "Examplar Edge Gateway 5.2.8 fixes a critical token bypass",
                            "summary": SUMMARY,
                            "so_what": "Upgrade gateways in front of payment APIs to 5.2.8.",
                            "confidence": "high",
                        }
                    ],
                }
            )
        )


class FakeClient:
    def __init__(self):
        self.messages = FakeMessages()


class FakeLookup:
    def __init__(self, *args, **kwargs):
        pass

    def lookup(self, cve_id):
        return CveInfo(cve_id, True, 9.8, "CRITICAL", "3.1", "2026-09-22", False)


@pytest.fixture
def pipeline(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    html = (FIXTURES / "article_gateway_cve.html").read_text()
    text, published, title = extract_main_text(html, URL)
    article = Article(URL, URL, 200, "2026-09-24T10:00:00+00:00", published, title, text)
    candidate = Candidate("Fixture Media", "vuln", URL, title, None)
    client = FakeClient()

    monkeypatch.setattr(main, "collect", lambda *a, **k: [candidate])
    monkeypatch.setattr(main.Fetcher, "fetch_article", lambda self, url: article)
    monkeypatch.setattr(main, "make_client", lambda settings: client)
    monkeypatch.setattr(main, "VulnLookup", FakeLookup)
    monkeypatch.setattr(main, "LocalStorage", lambda: LocalStorage(tmp_path))
    return client, tmp_path


def test_full_run_no_upload(pipeline, capsys):
    client, out = pipeline
    assert main.main(["--no-upload"]) == 0

    # One Haiku call at temperature 0; two Opus calls without temperature.
    assert len(client.messages.create_calls) == 1
    assert client.messages.create_calls[0]["temperature"] == 0
    assert len(client.messages.stream_calls) == 2
    assert all("temperature" not in c for c in client.messages.stream_calls)
    # The writing call never sees the article text.
    writing_prompt = client.messages.stream_calls[1]["messages"][0]["content"]
    assert "<article>" not in writing_prompt
    assert "Raman said organisations using the gateway" not in writing_prompt

    digest_files = list((out / "digests").glob("*.html"))
    assert len(digest_files) == 1
    html = digest_files[0].read_text()
    assert "Examplar Edge Gateway 5.2.8 fixes a critical token bypass" in html
    assert "1,200" in html
    assert "3 March" not in html  # unsupported sentence removed
    assert "CVE-2026-41234</a>" in html

    record = json.loads(next((out / "records").glob("*.json")).read_text())
    item = record["digest"]["items"][0]
    assert item["confidence"] == "check"  # downgraded because a sentence was removed
    extraction = record["extractions"][0]
    recorded_quotes = {c["quote"] for c in extraction["claims"]}
    assert item["claims"] and all(c["quote"] in recorded_quotes for c in item["claims"])
    assert len(extraction["dropped_claims"]) == 4
    assert (out / "index.html").exists()
    assert json.loads((out / "state/seen.json").read_text())["seen"]
    assert "Digest: file://" in capsys.readouterr().out


def test_dry_run_makes_no_writing_call_and_writes_nothing(pipeline):
    client, out = pipeline
    assert main.main(["--dry-run"]) == 0
    assert len(client.messages.stream_calls) == 1  # ranking only
    assert not any(out.rglob("*"))


def test_missing_api_key_exits_early(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    assert main.main(["--dry-run"]) == 2
