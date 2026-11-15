# Decisions

Choices made while building PkgWatch where the brief was open or where reality differed
from it. Newest context first within each section.

## Data sources (probed 2026-11-15 with `scripts/probe_sources.py`)

| Source | Status | What PkgWatch does |
|---|---|---|
| `https://replicate.npmjs.com/_changes` | Works, but only as a legacy alias; documented path is now `/registry/_changes` | Uses `https://replicate.npmjs.com/registry/_changes?since=<seq>&limit=<n>` |
| npm `_changes` parameters | `since=<int>`, `limit` and `descending=true` work. `since=now` and `include_docs=true` return `400 Bad Request` | Reads the current sequence from `GET https://replicate.npmjs.com/` (`update_seq`); cold start uses `descending=true&limit=N`; packuments are fetched separately |
| `https://registry.npmjs.org/<name>` | Works. Full packument carries `time`, per-version `maintainers`, `_npmUser`, `dist.tarball`, `dist.unpackedSize` | Used as-is. Documents above 25 MB are skipped (`metadata-too-large`) |
| `https://registry.npmjs.org/-/v1/search?text=maintainer:<user>` | Works, returns `total` | Used to estimate publisher history (see "New publisher") |
| `https://pypi.org/rss/packages.xml` | Works, 40 newest projects, sends an `ETag` | Cold start and fallback only |
| `https://pypi.org/rss/updates.xml` | Works, but holds only the newest 100 releases, which covered about 19 minutes when probed | Cold start and fallback only: on its own it would miss releases between 20-minute runs |
| PyPI XML-RPC `changelog_since_serial` / `changelog_last_serial` (`POST https://pypi.org/pypi`) | Works. This is the mirroring API and is still supported | **Primary PyPI feed.** Gives gap-free coverage with a serial cursor |
| `https://pypi.org/pypi/<name>/json` | Works, includes `releases`, `ownership.roles`. CDN-cached: a release published seconds ago is often missing | Fetched first; if the wanted version is missing, `https://pypi.org/pypi/<name>/<version>/json` is fetched and merged |
| `https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json` | 301 redirect to `https://hugovk.dev/top-pypi-packages/...`; content unchanged (`rows[].project`) | Requests follow redirects; the original URL is kept so it survives another move |
| npm popularity list | No official "top N" endpoint. The search API ranks by a text query, not global popularity | Uses the published `npm-high-impact` list (`lib/top-download.js`) via jsDelivr, falling back to the GitHub raw file |

### Differences from the brief

1. **npm changes URL** is `/registry/_changes`, and `since=now` is rejected.
2. **PyPI primary feed is the changelog API, not RSS.** The brief lists the RSS feeds; they
   are still used for the first run and whenever XML-RPC fails, but relying on them alone
   would silently drop releases whenever more than 100 land between runs.
3. **PyPI project JSON lags.** The per-version endpoint from the brief is used as the fix.
4. **The PyPI baseline URL redirects** to `hugovk.dev`.

## Detection

- **Finding ids.** Fifteen ids, one per detector function (`typosquat`,
  `name-manipulation`, `combosquat`, `dependency-confusion`,
  `new-publisher-similar-name`, `sparse-metadata`, `repo-impersonation`,
  `popular-package-change`, `npm-install-hook`, `python-install-code`, `obfuscation`,
  `exfiltration`, `suspicious-endpoint`, `binary-dropper`, `unsafe-archive`). Sub-cases
  (for example the five kinds of obfuscation) share an id and differ by message and weight.
- **Name signals alone rarely list a package.** Distance-2 typos, affixes and combosquats
  weigh 12, below the listing threshold of 15, because they are common among legitimate
  packages. They list a package only together with another signal. Distance-1 typos (25),
  homoglyphs (30), separator swaps (20) and scope confusion (25) list on their own.
- **Short names.** The brief's rule is kept (names of 5 characters or fewer match only at
  distance 1), but such a match weighs 12: one substituted letter in a five-letter name
  is weak evidence.
- **Scoped npm packages** are not compared against unscoped popular names
  (`@myorg/lodash` is the normal way to publish a fork). Scopes themselves are checked
  against popular scopes (`@babe1/core`).
- **Established packages.** Name weights are halved for packages first published more than
  180 days ago.
- **New publisher (detector 5).** Neither registry exposes account creation dates. The
  approximation: on npm, the package was created within 30 days *and* the publishing
  account maintains at most two packages (one search request, made only when the name
  already resembles a popular one). On PyPI, where no per-user API exists, it is "project
  created within 30 days".
- **Repository impersonation (detector 6).** Comparing against the popular package's real
  repository would need an extra fetch per candidate, so the check is: the repository URL's
  last path segment equals the imitated package's name and differs from this package's.
- **Popular-package changes (detector 7).** Maintainer comparison is npm-only (per-version
  `maintainers`); PyPI's JSON API has no per-release owner history. Size and version jumps
  work on both.
- **Credential access needs a read.** A sensitive path (`~/.ssh`, `.npmrc`, browser
  profiles, wallet files) only counts when a file-read call sits within 400 characters and
  the same file makes network calls. The first live run flagged security tools that merely
  *list* such paths in deny-lists.
- **Environment exfiltration** means serialising the whole environment
  (`JSON.stringify(process.env)`, `str(dict(os.environ))`, passing it as a request body).
  `os.environ.copy()` for a subprocess is not matched.
- **Download-and-execute** needs a download call, a run or chmod within 1,200 characters
  after it, and an executable file name or a pipe-to-shell in between. File-level
  co-occurrence alone flagged about 10% of ordinary CLI packages in live testing.
- **Binaries.** `.node` addons, platform wheels, npm packages declaring `os`/`cpu`, and the
  setuptools/distlib launcher stubs are expected and not flagged.
- **Raw IP URLs.** Loopback, private, link-local and unspecified addresses are ignored.
  The RFC 5737 documentation ranges are *not* ignored, so the fixtures can use them.
- **Endpoint patterns allow a trailing host suffix** (`discord.com.example.invalid/api/webhooks/...`)
  so fixtures can obey the "only `example.invalid`" rule while exercising the same
  expressions that match real webhook URLs.
- **Scan budget.** Pattern detectors read at most 4 MB of code per package and 256 KB per
  file, shallowest and smallest files first. Without it one 13 MB package took 15 seconds.
- **`setup.py` scope.** Only a `setup.py` at an sdist root is treated as install-time code.
  A `pkg/setup.py` module inside a wheel never runs at install time.

## Fixtures and evaluation

- Fixtures are **JSON documents**, not directories of runnable files
  (`tests/fixtures/{malicious,clean}/*.json`, generated by `scripts/build_fixtures.py`).
  File contents are strings, so nothing in the corpus can be imported, executed, or
  picked up by an antivirus scanner as a live sample.
- Fixtures use a small fixed baseline (`tests/fixtures/baselines/`) so results do not
  drift when the real baselines refresh weekly.
- `pkgwatch.eval` gates: recall is the share of malicious fixtures scoring 40 or more
  (gate 90%), and no clean fixture may score 40 or more. Per-detector precision and recall
  compare the ids that fired with each fixture's `expected` list.
- Clean fixtures include look-alikes of real false positives found in live runs.

## Data, outputs and repository growth

- **Daily shards are keyed by publish date**, falling back to scan date. A version
  rescanned later replaces its record in place instead of appearing twice.
- **De-duplication across runs** uses `state/cursors.json` → `recent`: up to 6,000
  ten-character hashes of `ecosystem/name/version`.
- **Data files are compact JSON** with sorted keys, so an unchanged run produces no diff.
- `docs/data/findings/index.json` lists the available days so the dashboard can load
  history beyond `latest.json`.
- `docs/data/stats.json` keeps all-time totals, a 90-day daily window and a 48-hour hourly
  window (the dashboard's "24 h" figure needs sub-day resolution).
- **Reports** live in `reports/<ecosystem>/<name>-<version>.md`; scoped names become
  `scope__name`, long names are truncated with a hash. Reports are pruned when their
  finding ages out of the 365-day window.
- **Git history still grows** with every bot commit, which no file layout can prevent.
  Each run rewrites a handful of small files; if the repository ever becomes large, squash
  the history of `docs/data` and `state` (nothing depends on it).

## Runtime behaviour

- **Per-run cap** is 2,000 packages split evenly between ecosystems, plus a 12-minute
  deadline. Unprocessed packages stay behind the cursor and are picked up next run.
- **Backlog guard.** If the scanner falls more than 400,000 npm sequences or 60,000 PyPI
  serials behind (several days of downtime), it skips ahead and records a warning in
  `health.json` rather than never catching up.
- **Failure policy.** A source that cannot be read, or more than 30% of packages failing,
  makes the run exit non-zero. Outputs and cursors for the healthy part are still written,
  `health.json` is not, so the dashboard badge turns red after two hours.
- **npm recency.** A change-feed entry is scanned only if the package's newest version was
  published within 48 hours; older entries are metadata edits (deprecations, tag moves).
- **Issues.** At most 15 triage issues per run; the rest wait in `issue_backlog`. Scoped
  names in issue bodies are written so they never @-mention a GitHub account.
- **`--dry-run`** ignores and does not save cursors, opens no issues, and writes to
  `./dry-run-out` unless `--output-dir` is given.

## Project setup

- **GitHub Pages** is served from `main` / `docs` ("Deploy from a branch"). It needs no
  extra workflow and the bot's data commits publish themselves.
- **Dependencies.** Runtime: `httpx`, `rapidfuzz`. Development: `pytest`, `pytest-cov`,
  `respx`, `ruff`. Workflow YAML is checked with a small stdlib script, so PyYAML is not
  a dependency.
- **Work happens directly on `main`**, as the brief asks.

## Sample data

- `docs/data`, the feeds and `reports/` were first populated by a local live dry run on
  2026-11-15 (`--dry-run --limit 600 --output-dir docs --reports-dir reports`), so the
  dashboard has real data before the first scheduled scan. `state/cursors.json` is
  deliberately absent: the first scheduled scan cold-starts from the newest changes.
