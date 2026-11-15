# Contributing to PkgWatch

Thanks for helping. Bug reports, false-positive reports and new detectors are all welcome.

## Ground rules

- **Never commit real malware.** Fixtures are synthetic stand-ins that reproduce the
  *pattern* of an attack. URLs must point at `example.invalid`, IP addresses must come from
  the documentation range `203.0.113.0/24`, "payloads" must decode to something harmless,
  and nothing may be functional. A test enforces the host rule.
- **Never execute scanned code.** No `pip install`, `npm install`, `import`, `eval`, `exec`
  or `subprocess` on package content. Detectors read bytes and text only.
- **Keep the language neutral.** Public output says "suspicious", with reasons. It never
  calls a package malware.
- **Stay within the dependency budget:** `httpx` and `rapidfuzz` at runtime; `pytest`,
  `pytest-cov`, `respx` and `ruff` for development. Standard library first.

## Setup

```bash
python -m venv .venv
```

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
```

Before opening a pull request, run what CI runs:

```bash
ruff check . && ruff format --check .
```

```bash
pytest --cov=pkgwatch --cov-fail-under=85
```

```bash
python -m pkgwatch.eval && python scripts/check_site.py
```

## Adding a detector

1. **Write the function.** Add it to the fitting module in `pkgwatch/detectors/` (or a new
   module). The signature is `(PackageContext) -> list[Finding]`. It must be pure: no
   network, no disk, no mutation of the context. Useful context fields:
   - `name`, `version`, `ecosystem`, `baseline`, `config`
   - `description`, `readme`, `repository_url`, `maintainers`, `publisher_is_new`
   - `files` (bytes), `texts` (decoded text files), `code` (source files),
     `scan_code` (source files within the per-package scan budget; use this for regular
     expressions), `package_json`
2. **Give it a weight.** Add a key under `[weights]` in `pkgwatch/config.toml` and read it
   with `ctx.config.weight("your_key")`. Do not hard-code numbers.
3. **Register it.** Add the function to the module's `DETECTORS` tuple, and add the
   finding id with a one-line description to `FINDING_IDS` in
   `pkgwatch/detectors/__init__.py`. If the module is new, add it to that file too.
4. **Add fixtures** in `scripts/build_fixtures.py`, then regenerate:

   ```bash
   python scripts/build_fixtures.py
   ```

   You need at least one malicious fixture that lists your id under `expected`, and one
   clean fixture showing a legitimate package that comes close and must not fire.
5. **Add unit tests** with a true positive, a true negative and a tricky near miss. The
   `make_ctx` fixture in `tests/conftest.py` builds a context from a dict of files.
6. **Run the evaluation.** `python -m pkgwatch.eval` must still pass: at least 90% of
   malicious fixtures at 40 or more, and no clean fixture at 40 or more.
7. **Try it on live data** and look at what it flags:

   ```bash
   python -m pkgwatch.scan --dry-run --limit 200
   ```

   A detector that fires on more than a few percent of ordinary packages needs a tighter
   rule or a lower weight. Add the false positives you find as clean fixtures.
8. **Document it:** the detector table in `README.md`, the "About" section of
   `docs/index.html`, and `DECISIONS.md` if you made a judgement call.

## Tuning weights

Change `pkgwatch/config.toml`, rerun the evaluation and a live dry run, and say in the
pull request what the change did to both.

## Reporting a false positive

Use the "Report a false positive" link next to the listing, or the issue template. Say
which finding is wrong and why the behaviour is legitimate; a link to the relevant source
file helps most.
