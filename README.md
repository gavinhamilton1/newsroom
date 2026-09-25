# Architecture Dispatch Daily

A batch job that runs on weekday mornings. It collects articles from a curated source list (`sources.yaml`), uses the Anthropic API to extract verifiable facts and write short summaries, renders an HTML digest, and publishes it to Cloudflare R2 with an index of past issues. You read it by opening the link printed at the end of the run.

The digest follows the format of the monthly Architecture Dispatch newsletter, with more detail per story: a specific headline linked to the source, a summary with the concrete details, a "So what" block for this group, and, for vulnerabilities, a table of CVE, CVSS, CISA KEV status and patch availability.

## Ground rules the code enforces

- **Every fact is traceable to a quote.** The extraction step returns claims with verbatim quotes. Code then checks each quote against the fetched text and drops any claim whose quote is missing, or whose numbers, versions, dates or IDs are not in the quote. The writing step sees only the surviving claims and quotes. Its output is checked again, and any sentence stating a number or identifier that isn't in that item's quotes or NVD/KEV record is removed.
- **Models never find the news.** The app fetches from `sources.yaml`; models only process fetched text.
- **No paywall circumvention.** Public pages only, `robots.txt` is honoured, the User-Agent describes the app, and a source that blocks or errors is skipped.
- **One failure never sinks the run.** Every source and article is processed inside its own try/except. Only the spend cap or a failed model call stops a run.

## Local setup

Requires Python 3.12 or later.

```bash
python3.12 -m venv .venv
```

```bash
.venv/bin/pip install -r requirements-dev.txt
```

```bash
cp .env.example .env
```

Fill in `.env` (loaded automatically by `python-dotenv` for local runs only; Render uses real environment variables):

| Variable | Purpose |
| --- | --- |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET` | R2 access (see below) |
| `R2_PUBLIC_BASE_URL` | Public URL of the bucket (r2.dev subdomain or custom domain), no trailing slash |
| `DIGEST_MAX_ITEMS` | Maximum items in a digest (default 10) |
| `LOOKBACK_HOURS` | Normal lookback window (default 24; Mondays use 72) |
| `LOG_LEVEL` | Default `INFO` |
| `MAX_COST_USD` | Optional. Per-run Anthropic spend ceiling (default 2.0) |
| `NVD_API_KEY` | Optional. Raises the NVD rate limit; lookups work without it |

Run the checks:

```bash
.venv/bin/pytest
```

```bash
.venv/bin/ruff check .
```

The tests never touch the network: a fixture blocks socket connections, and the Anthropic API, news sites, NVD and R2 are all mocked.

## Getting R2 credentials

1. In the Cloudflare dashboard, open **R2 Object Storage** and create a bucket (for example `dispatch-daily`). That name is `R2_BUCKET`.
2. Your **Account ID** is shown on the R2 overview page. That is `R2_ACCOUNT_ID`.
3. Under **Manage R2 API Tokens**, create an API token with **Object Read & Write** permission, scoped to that bucket only. Cloudflare shows an **Access Key ID** and a **Secret Access Key** once; they are `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY`.
4. To read the digest in a browser, open the bucket's **Settings** and either enable the public **r2.dev** subdomain or connect a custom domain. That URL is `R2_PUBLIC_BASE_URL`.

The app talks to R2 through its S3-compatible API at `https://<R2_ACCOUNT_ID>.r2.cloudflarestorage.com` with region `auto`.

With a public bucket, anyone who has or guesses a URL can read everything in it. That includes `records/` (the claims and quotes behind each issue) and `state/`. Pages carry `noindex`, but that is not access control. If that matters, put the custom domain behind Cloudflare Access.

## Running it

A dry run collects candidates and runs extraction and ranking, then prints three tables (candidates, extractions, selection). It makes no writing call and writes nothing. If R2 is configured it reads the real seen-URL index; otherwise it uses `./out/`.

```bash
.venv/bin/python -m dispatch_daily.main --dry-run --limit 10
```

A full local run that writes to `./out/` instead of R2 (the seen index for local runs also lives in `./out/state/`):

```bash
.venv/bin/python -m dispatch_daily.main --no-upload
```

Other flags: `--since HOURS` overrides the lookback window, `--source "The Hacker News"` runs a single source, and `--limit N` caps candidates after deduplication.

A production run (what Render executes) publishes to R2 and prints `Digest: <url>` as its last line:

```bash
.venv/bin/python -m dispatch_daily.main
```

Exit codes: `0` success, `1` the run was aborted (spend cap reached, or a model call failed or refused), `2` configuration problem.

## Deploying on Render

`render.yaml` defines a cron job (`dispatch-daily`) that installs `requirements.txt` and runs `python -m dispatch_daily.main`. Create it from the blueprint, then set the secret environment variables in the Render dashboard (they are `sync: false`, so Render prompts for them).

### Daylight saving

Render cron schedules are in UTC and do not follow daylight saving. The schedule `"0 9 * * 1-5"` is 05:00 in New York while EDT is in effect (from the second Sunday in March to the first Sunday in November). **When EST starts in November, change the schedule to `"0 10 * * 1-5"`** to keep the 05:00 run, and change it back to `"0 9 * * 1-5"` in March. If you don't, the digest arrives at 04:00 in winter; nothing else changes.

## Adding a source

Add an entry to `sources.yaml`:

```yaml
  - name: "Example Security Blog"
    url: "https://blog.example.com/security"
    category: cyber          # one of the category ids at the top of the file
    type: news               # news, primary, curated or analyst
    feed: null
    note: "Why this source is on the list."
```

Then fill in the feed and commit the result:

```bash
.venv/bin/python scripts/discover_feeds.py
```

The script looks for `<link rel="alternate">` RSS or Atom links (preferring one that matches the page's section, such as a category feed), falls back to common paths like `/feed/`, and only accepts a URL that parses as a feed with entries. It edits `feed: null` lines in place, so comments and notes survive. Use `--dry-run` to preview.

Sources without a feed are still tried: the listing page is fetched and only links with a visible publication date are used, either a `<time datetime>` in the same block or a full `yyyy/mm/dd` date in the URL. If neither is present the source is skipped and logged rather than guessed. Test a new source on its own:

```bash
.venv/bin/python -m dispatch_daily.main --dry-run --source "Example Security Blog"
```

## How a story gets from a feed to the digest

1. **Collect** (`sources.py`). Each feed is fetched after a `robots.txt` check and parsed with `feedparser`. Entries dated inside the window (24 hours, or 72 on Mondays) become candidates, capped at 8 per source and 80 per run, taken round-robin across sources.
2. **Dedupe** (`state.py`). Candidates whose URL hash is in `state/seen.json` (kept for 90 days) are dropped, as are near-duplicate titles within the run (similarity above 0.9).
3. **Fetch** (`fetch.py`). `trafilatura` extracts the main text. Anything under 400 characters counts as a failed extraction; text is truncated to 12,000 characters. The final URL, HTTP status, fetch time and metadata date are recorded.
4. **Extract** (`extract.py`). One Haiku call per article at temperature 0, with a forced tool schema, returns a headline, summary, claims with quotes, entities, topics and flags. Code then validates every claim: the quote must appear verbatim in the fetched text (whitespace and curly quotes normalised), and every number, version, date or ID in the claim must appear in its quote. Entity names must occur in the article. Articles with no surviving claims are dropped.
5. **Select** (`select.py`). Vendor marketing and `other`-only items are dropped. One Opus call scores the rest from 0 to 10, with a category and a one-line reason, using only the compact records (headline, summary, entities, topics). Scores under 4 are dropped and the top 10 kept. Any CVE ID in the validated identifiers or quotes is looked up in NVD and the CISA KEV feed (cached for 24 hours in `state/lookups/`). IDs that NVD doesn't know are labelled `(unverified)` wherever they appear.
6. **Write** (`write.py`). One Opus call receives only the validated claims, quotes and NVD/KEV records, never article text. It returns a headline, summary, "So what" and confidence per item, plus a two-sentence intro, in British English house style. Code removes any sentence with an unsupported fact and marks that item `check`.
7. **Render and publish** (`render.py`, `publish.py`). Jinja2 renders a self-contained page. The job uploads `digests/YYYY-MM-DD.html` and `records/YYYY-MM-DD.json` (every claim, quote, score and dropped claim), regenerates `index.html`, updates `state/seen.json`, and prints the digest URL. If nothing survives selection, a short "nothing significant was found" issue is still published, so a quiet day can be told apart from a failed run.

To trace a fact in a digest, expand "Evidence" under the item to see its quotes, or open that day's `records/*.json`.

## Models and cost

Model IDs and tunables live in `dispatch_daily/config.py`:

- Extraction: `claude-haiku-4-5-20251001`, temperature 0, one call per article.
- Ranking and writing: `claude-opus-5-5`, one call each. **Opus 5.5 does not accept a `temperature` parameter** (the API returns 400 for sampling parameters on this model), so the specified 0.3 cannot be sent. Thinking is always on for this model, and depth is controlled with `WRITE_EFFORT` (`medium`). `WRITE_TEMPERATURE` is kept in config and is applied automatically if `WRITE_MODEL` is switched to a model that accepts it (set `WRITE_MODEL_ACCEPTS_TEMPERATURE = True`). Opus 5.5 also rejects forced tool choice, so these two calls use structured JSON output instead of a tool.

Every response's token usage is added to a running estimate (prices in `MODEL_PRICES`). The run aborts if the estimate passes `MAX_COST_USD` (default $2), and the actual figure is logged at the end of each run. A full day of about 80 candidates is expected to cost well under $1: most of it is the Haiku extraction calls, plus two Opus calls. Check the logged figure after the first few runs and adjust `MAX_COST_USD` if needed.

## Layout

```
dispatch_daily/
  config.py    env vars, model IDs, prompts' reader brief and house style, tunables
  sources.py   sources.yaml, feed and listing-page collection
  fetch.py     HTTP client, robots.txt, trafilatura extraction, retries
  state.py     seen-URL index and deduplication
  extract.py   Haiku extraction, tool schema, quote validation
  select.py    filtering, Opus scoring, NVD/KEV lookups
  write.py     Opus digest prose and post-write fact checks
  render.py    Jinja2 rendering
  publish.py   R2/local storage, upload, index regeneration
  cost.py      Anthropic client, retries, spend cap
  main.py      pipeline and CLI
templates/     digest.html.j2, index.html.j2
scripts/       discover_feeds.py
tests/         fixtures and tests (no network)
```
