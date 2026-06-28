# Changelog

## v3.2.1 — Review pass: cleanup + small efficiency wins

### Changed
- **`--query` now uses the binary length probe** (`_bin_length`) instead of the old linear
  `1..maxlen` scan — ~7 requests instead of ~64, and no silent truncation of long results.
- **`--maxlen` repurposed** as the binary length cap (default raised `64 → 4096`); removed the
  hard-coded internal cap.
- **Removed dead `--cmin` / `--cmax`** flags (the Unicode-aware extractor no longer uses them;
  also dropped from the resume signature).
- **`char()` raises the search floor to 128** once a byte is known to be non-ASCII (saves ~1
  request per non-ASCII char).
- **Threaded extraction uses `submit` + `as_completed`** with per-position retry, so one bad
  worker can't abort the whole batch.
- Removed leftover dead `thresh` in `find_time`; renamed resume file to `.blindfold-<id>.json`.

### Added
- **`--ascii`**: skip the Unicode probe on ASCII-only targets (1 fewer request/char).

### Peer-review hardening
- **`requests.Session()`** for all traffic — connection keep-alive, cookie persistence,
  and a real speedup over per-request connections.
- **TLS verification on by default**; `--insecure` opts out and scopes the urllib3 warning
  suppression to that case only (was suppressed globally before).
- **MySQL error-based now HEX-encodes** the leaked value — values containing quotes, `<`, `>`,
  `&` (and multibyte UTF-8) are recovered intact instead of being truncated by the old regex.
- **Oracle identifiers are whitelisted** (`^[A-Za-z0-9_$#]+$`) before use as bare identifiers.
- **Fail loud on inconclusive DBMS fingerprint** — abort with guidance to pass `--dbms`
  instead of silently assuming PostgreSQL.
- **Time oracle uses a majority vote** over `retries+1` samples (robust to jitter both ways).
- **`_bin_length` warns** when a value hits the `--maxlen` cap instead of silently truncating.
- Friendly errors on malformed request lines / `-H` headers; SOCKS proxy dependency check.

### Resilience
- **Transport failures are now catchable and resumable.** `Target.send()` retries connection
  errors with backoff (`--net-retries`, default 2) and then raises a catchable `RequestError`
  instead of calling `SystemExit`.
- **Threaded extraction checkpoints incrementally** — it commits the contiguous prefix as
  workers finish, so a crash mid-run resumes from the last saved character (re-run the same
  command). A failing worker no longer aborts the whole batch silently.
- Clean top-level handling of `RequestError` / `KeyboardInterrupt` with proper exit codes.

## v3.2 — Reliability hardening

### Added
- **Adaptive time threshold**: samples baseline response latency (`--cal-samples`) and sets the
  delay cutoff to `median + margin`, instead of a fixed `sleep*0.6` — far more robust to network
  jitter and server load. `--threshold` still forces an absolute value.
- **Unicode / full code-point extraction**: per-character search now auto-extends beyond ASCII
  (PostgreSQL/Oracle `ascii`, MSSQL `unicode`), so UTF-8 data (accents, symbols, CJK) is no longer
  silently corrupted. `--max-codepoint` caps the range.
- **Per-character confirmation** in threaded boolean mode: each char is verified with an equality
  check and re-extracted on disagreement, guarding against a single flipped response.

### Changed / Fixed
- **Safe identifier & literal quoting** for all schema/dump queries (per-dialect: `"..."`, `` `...` ``,
  `[...]`; doubled quotes in string literals) — handles table/column names with quotes or specials.
- MSSQL row dump casts columns to `nvarchar` for clean concatenation.

## v3.1 — Default DB mapping + table dump

### Added
- **Map mode is now the default** (no `--query` needed): after detection it prints the
  **DBMS, current database, and table list** — quiet by design (no columns/rows).
- **`--dump TABLE`**: auto-discovers the table's columns and dumps its rows, capped by
  **`--max-rows`** (default 50), rendered as an aligned table.
- Per-DBMS schema queries for PostgreSQL/MySQL/MSSQL/Oracle (`information_schema`,
  `group_concat`/`string_agg`/`listagg`, dialect-correct `LIMIT/OFFSET/FETCH`).

### Changed
- `--query` is now **optional** (power mode). `--query` and `--dump` are mutually exclusive.
- Long values use a binary-search length probe (handles big aggregates like table lists).

## v3.0 — Multi-DBMS + automatic technique selection

> Renamed: `pg-time-blind` → **blindfold** (script `pg_time_blind.py` → `blindfold.py`).

### Added
- **Automatic DBMS detection** (fingerprinting) for **PostgreSQL, MySQL, MSSQL, Oracle**;
  pin manually with `--dbms`.
- **Error-based extraction** — forces a reflected DB error and dumps the value in a single
  request (PostgreSQL `CAST`, MySQL `extractvalue` with automatic chunking, MSSQL `CAST/convert`).
  Tried first because it's the fastest path; `--no-error` to skip.
- **Technique auto-selection**: error-based → boolean-based → time-based.
- **Safe mode (default)**: risky `OR` contexts that can change app state are skipped unless
  `--allow-or` is given.
- **Threaded boolean extraction** via `--threads N` (time-based stays serial for clean timing).
- **Robust calibration**: 3 samples per side and digit-stripped token matching to survive
  dynamic content (CSRF tokens, timestamps).
- Resume checkpoint now also caches the detected DBMS/technique/context.

### Changed
- Detection reorganised into explicit **DBMS / TECHNIQUE / CONTEXT** reporting.
- Per-character primitives are now DBMS-aware (`substr` vs `substring`, `length` vs `len`).

### Notes
- Oracle uses boolean extraction (inline time/error primitives omitted for reliability).
- Existing PostgreSQL commands keep working; output now reports the detected backend + technique.

## v2.0 — Structured detection (boolean + time-based)

- Two-phase workflow: detect injection (boolean preferred, time fallback) then extract.
- Auto-calibrated TRUE/FALSE signal; automatic context discovery; resume support.
