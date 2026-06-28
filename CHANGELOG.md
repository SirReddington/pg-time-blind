# Changelog

## v3.5.1 — stronger boolean calibration + verbose diagnostics

### Added
- **`-v` / `--verbose`** — prints detection internals (per-context true/false probe status &
  length, and which discriminator fired) so a failed detection is diagnosable instead of opaque.

### Changed / Fixed
- **Boolean calibration is far more robust** to dynamic pages (CSRF tokens, timestamps):
  - length now uses **range separation** instead of strict stability — small jitter no longer
    defeats it;
  - added a **line/phrase discriminator** that catches multi-word markers like "Welcome back"
    when no single word is uniquely true/false;
  - added a **response-similarity** last resort for content-only differences.
- **`--true-match` / `--false-match` are verified** before claiming detection (they used to be
  trusted blindly, reporting a signal with 0 requests sent and then extracting nothing).

> Tip: cookie/header injection still needs `--no-encode --tamper space2comment` (a cookie value
> isn't URL-decoded server-side). Run with `-v` if detection fails — flat true/false lengths
> mean the payload isn't landing (wrong page, encoding, or a fake base value), not a tool bug.

## v3.5.0 — UNION extraction + WAF tamper

### Added
- **UNION-based extraction** (`union-based` technique). When the injection reflects output,
  blindfold discovers the column count and the reflecting column, then reads each value in a
  **single request** (`UNION SELECT ... wrap(value) ...`) instead of per-character blind work.
  It's now the **preferred** technique (union → error → boolean → time). Per-DBMS concat
  handled (PG/Oracle `||`, MySQL `concat`, MSSQL `+CAST`; Oracle adds `FROM dual`).
  - `--no-union` to skip it, `--union-cols N` to bound the column probe (default 12).
  - Reflection-only targets with no blind signal: pass `--dbms` so it can run.
- **`--tamper`** WAF evasion (comma-separated): `space2comment`, `randomcase`, `charencode`.
  The string tampers are **quote-aware** — they never alter text inside `'...'` literals, so
  markers, identifiers, and webshell payloads stay intact. `charencode` emits full `%XX`.

## v3.4.0 — review pass: fail-loud fingerprint, charset, decoupled timeout

### Added
- **`--charset`** — restrict extraction to a known alphabet (preset `hex`/`HEX`/`digits`/`alnum`
  or a literal set). Binary-searches within the alphabet, so e.g. a hex hash drops from
  ~7 to ~4 requests/char (≈47% fewer in testing).
- **`--timeout`** — HTTP timeout is now its own setting (auto-raised above `--sleep` so
  time-based payloads still complete). Previously hard-coupled to `sleep + 20`.

### Changed / Fixed
- **No more PostgreSQL fallback.** If DBMS fingerprinting is inconclusive the tool now
  stops and asks for `--dbms` instead of guessing (a wrong guess = wrong syntax = false negatives).
- **Gentler Unicode growth** (`hi *= 2`) — less overshoot before the binary search.
- **Threaded extraction checkpoints on *any* error**, not just transport ones — a logic
  error can't lose the contiguous prefix (it's persisted, then re-raised).
- File handles use `with` context managers (request file, state file).

## v3.3.0 — `--rce` (command exec) and `--webshell` (file drop)

Two distinct, DBMS-aware RCE actions. Both run after auto-detection (DBMS + technique +
context) and skip data extraction. **Authorized testing only.**

### Added
- **`--rce [CMD]`** — direct OS command execution; output read back through the detected oracle.
  Bare `--rce` opens an interactive pseudo-shell; `--rce "cmd"` runs once.
  - **PostgreSQL**: `COPY ... FROM PROGRAM` (superuser).
  - **MSSQL**: enables + runs `xp_cmdshell` (sysadmin).
  - MySQL/Oracle: no direct exec → points you to `--webshell`.
- **`--webshell`** — drops a webshell file, **verifies the write through the oracle**
  (`LOAD_FILE` / `pg_read_file`), and prints the confirmed path. No blind guessing.
  - **MySQL**: `INTO DUMPFILE` with a hex-encoded payload (raw, survives quotes/specials).
  - **PostgreSQL**: `COPY (...) TO`.
  - When `--os-path` is omitted, it tries common web roots; for MySQL it also tries
    `../`-traversal candidates relative to the datadir, verifying each.
- **`--os-path`** (target file or web-root dir), `--shell-name`, `--shell-payload`.

> Needs high DB privileges (superuser / sysadmin / `FILE` + permissive `secure_file_priv`).
> Command exec requires stacked-query support; the webshell **verify** step works over any
> detected blind channel (boolean / error / time).

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
