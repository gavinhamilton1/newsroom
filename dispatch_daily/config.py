"""Environment variables, model IDs and tunables. Change things here, not in the modules."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

try:  # python-dotenv is for local runs only; Render sets real environment variables.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = REPO_ROOT / "sources.yaml"
TEMPLATES_DIR = REPO_ROOT / "templates"
OUT_DIR = REPO_ROOT / "out"
CACHE_DIR = REPO_ROOT / ".cache"

# --- Models -----------------------------------------------------------------

EXTRACT_MODEL = "claude-haiku-4-5-20251001"
EXTRACT_TEMPERATURE = 0.0
EXTRACT_MAX_TOKENS = 4096

WRITE_MODEL = "claude-opus-5-5"
# Opus 5.5 rejects sampling parameters (temperature/top_p/top_k return a 400), so the
# spec's temperature 0.3 cannot be sent. Thinking is always on for this model and
# `effort` is the control for depth and cost. WRITE_TEMPERATURE is kept so that it is
# applied automatically if WRITE_MODEL is ever switched to a model that accepts it.
WRITE_TEMPERATURE = 0.3
WRITE_MODEL_ACCEPTS_TEMPERATURE = False
WRITE_EFFORT = "medium"
RANK_MAX_TOKENS = 16000
WRITE_MAX_TOKENS = 32000

# USD per million tokens (input, output). Used for the per-run spend cap.
MODEL_PRICES: dict[str, tuple[float, float]] = {
    EXTRACT_MODEL: (1.00, 5.00),
    WRITE_MODEL: (4.00, 20.00),
}

# --- Pipeline tunables ------------------------------------------------------

MAX_PER_SOURCE = 8
MAX_CANDIDATES = 80
MIN_ARTICLE_CHARS = 400
MAX_ARTICLE_CHARS = 12_000
TITLE_SIMILARITY_THRESHOLD = 0.9
SEEN_RETENTION_DAYS = 90
MIN_RELEVANCE_SCORE = 4
LOOKUP_CACHE_HOURS = 24

TOPICS = [
    "identity",
    "ingress",
    "cdn",
    "ai-agents",
    "appsec",
    "vulnerability",
    "standards",
    "regulation",
    "platform-engineering",
    "data",
    "other",
]

# Digest sections, in display order. Keys are what the ranking call returns.
DIGEST_SECTIONS: list[tuple[str, str]] = [
    ("engineering", "Engineering & Architecture"),
    ("ai", "AI"),
    ("cyber", "Cyber"),
    ("vulnerabilities", "Vulnerabilities"),
    ("standards", "Standards"),
    ("fintech", "Fintech & Regulation"),
]

# --- HTTP -------------------------------------------------------------------

USER_AGENT = (
    "ArchitectureDispatchDaily/0.1 (+personal news digest; fetches public pages only; "
    "honours robots.txt)"
)
HTTP_TIMEOUT_SECONDS = 20.0
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --- Prompts ----------------------------------------------------------------

READER_BRIEF = (
    "The reader is a senior architecture group at a bank, covering identity and access "
    "management, API gateways and ingress, CDN and edge, and digital experience platforms. "
    "The audience includes engineers, SRE, product management and project management. They "
    "care about vulnerabilities in that stack, AI and agent infrastructure (agent identity, "
    "MCP, prompt injection), engineering and platform practice, standards that affect "
    "authentication and API security, post-quantum cryptography, and financial services "
    "regulation that changes what they must build or evidence."
)

HOUSE_STYLE = (
    "Write in British English. No em-dashes; use commas, semicolons or parentheses. No "
    'emoji. Avoid the "this is X, not Y" construction: say what something is. Avoid '
    "trailing fragments tacked on after a comma; finish the sentence properly. Prefer longer "
    "connected sentences over short punchy ones. State facts plainly, and where the "
    "reporting is uncertain, say so."
)


# --- Runtime settings from the environment ----------------------------------


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    return float(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str
    r2_account_id: str
    r2_access_key_id: str
    r2_secret_access_key: str
    r2_bucket: str
    r2_public_base_url: str
    r2_prefix: str
    digest_max_items: int
    digest_min_items: int
    lookback_hours: int
    log_level: str
    max_cost_usd: float
    nvd_api_key: str

    @property
    def r2_configured(self) -> bool:
        return all(
            [self.r2_account_id, self.r2_access_key_id, self.r2_secret_access_key, self.r2_bucket]
        )

    @property
    def r2_endpoint_url(self) -> str:
        return f"https://{self.r2_account_id}.r2.cloudflarestorage.com"


def load_settings() -> Settings:
    env = os.environ.get
    return Settings(
        anthropic_api_key=env("ANTHROPIC_API_KEY", ""),
        r2_account_id=env("R2_ACCOUNT_ID", ""),
        r2_access_key_id=env("R2_ACCESS_KEY_ID", ""),
        r2_secret_access_key=env("R2_SECRET_ACCESS_KEY", ""),
        r2_bucket=env("R2_BUCKET", ""),
        r2_public_base_url=env("R2_PUBLIC_BASE_URL", "").rstrip("/"),
        r2_prefix=env("R2_PREFIX", "").strip().strip("/"),
        digest_max_items=_int_env("DIGEST_MAX_ITEMS", 10),
        digest_min_items=_int_env("DIGEST_MIN_ITEMS", 5),
        lookback_hours=_int_env("LOOKBACK_HOURS", 24),
        log_level=env("LOG_LEVEL", "INFO").upper(),
        max_cost_usd=_float_env("MAX_COST_USD", 2.0),
        nvd_api_key=env("NVD_API_KEY", ""),
    )


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Third-party libraries are noisy at INFO.
    for noisy in ("httpx", "httpcore", "botocore", "boto3", "urllib3", "trafilatura"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
