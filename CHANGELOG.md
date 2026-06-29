# Changelog

## v3.7.0 — fewer requests, visible progress

### Added
- **Automatic per-column charset (data-driven).** For boolean/time `--dump` (when `--charset`
  isn't pinned), blindfold asks the database which character class *every* value of a column
  fits — `bool_and(col ~ '^[class]*$')`, narrowest first — and then binary-searches each
  character within only that alphabet. Because the class is confirmed against the real data, it
  provably covers every character: no guessing from column names, and no "widen and retry". A
  numeric column drops from ~7 to ~3.5 requests/char, lowercase to ~5 — typically 25–50% fewer
  requests on boolean/time dumps, for ~1–6 cheap probes per column. PostgreSQL today (uses the
  `~` regex operator); other engines fall back to the full search automatically.
- **Live progressive output during `--dump`.** Columns are printed as soon as they're
  discovered, and each value streams to the screen as it's recovered — so a slow boolean/time
  extraction shows visible progress instead of a long silence. (No `-v` needed.)

### Changed
- **Detection tries error-based before the slow time probe.** error-based is one request and
  self-identifying, so on a visible-error target blindfold no longer pays for (or prints) a
  time-based probe first. Order is now UNION → error → time (last resort).

## v3.6.8 — per-cell dump fallback for the tightest caps

### Added
- **Per-cell extraction fallback in `--dump`.** When even the column-at-a-time `string_agg`
  query is too long for the injection point's cap, blindfold drops to the smallest possible
  read: one column / one row via `SELECT <col> FROM <table> LIMIT 1 OFFSET <n>`, iterating rows
  until the first empty one. This is the exact short shape that already worked for `--query`, so
  it succeeds on caps that defeat every wider query. One request per cell — used only as a last
  resort, after the gentler per-column path. (PostgreSQL / MySQL.)
- **`ident_lean()`** — emits a bare identifier for plainly-safe lower-case names (saving the two
  quote characters that can decide whether a read fits the cap) and falls back to full quoting
  for anything else, so it never weakens identifier safety.

## v3.6.7 — column-at-a-time dumping that fits length caps

### Changed
- **`--dump` now extracts one column per request instead of one row.** The old approach asked
  for a row count (a numeric value needing the longer `~`-forced payload) and then concatenated
  *every column* into a single per-row query — both overflow a tight length cap, so dumps came
  back `rows: 0`. blindfold now runs a short `string_agg(col)` per column: every value of that
  column rides back in one error (the result isn't length-capped — only the injected query is),
  and the rows are reassembled client-side. New per-DBMS `q_col` (PG `::text`, MySQL
  `group_concat`, MSSQL `string_agg`, Oracle `listagg`). The row count is derived from the data,
  so the separate (and often un-castable) count query is gone.
- Gentle and honest under pressure: it's one request per column, and any column whose query is
  still too long for the cap is reported by name so you can pull it with a targeted `--query`.

## v3.6.6 — precise time-based detection (no phantom fires)

### Fixed
- **Time-based detection no longer false-positives under network load.** It previously accepted
  a hit when the TRUE payload crossed an *absolute* threshold derived from an early latency
  baseline — so if the server slowed down after baselining, ordinary jitter could push the TRUE
  samples over the line with no real conditional sleep (e.g. the phantom `time-based fires:
  postgresql/stacked` on a non-stacked target). Detection now confirms **relatively**: the TRUE
  payload must take ~`--sleep` longer than the FALSE payload *of the same shape*, and the gap
  must repeat (both TRUE samples beat both FALSE samples by ≥60% of `--sleep`). Overall slowdown
  cancels out, and a one-off spike can't fake a hit. Same request budget — and it rejects
  non-matches in 2 requests instead of 4.

## v3.6.5 — gentle schema enumeration under tight length caps

### Changed
- **Shorter PostgreSQL schema queries.** The table list now uses `pg_stat_user_tables`
  (user tables only, no `information_schema` bulk) and error-based casting uses PG's compact
  `(…)::int` instead of `CAST(… AS int)`. The table-list probe drops from ~124 to ~74
  characters, so map mode now works in a **single request** on moderate length caps where it
  previously truncated — no probing, no extra noise.

### Added
- **Gentle fallback enumeration for very tight caps.** When even the shortened schema query
  can't fit the injection point, blindfold falls back to checking a **small, curated list** of
  common table/column names by existence (`' AND EXISTS(SELECT … )-- -`, a ~36-char payload
  that fits any cap). This is deliberately *not* a sqlmap-style wordlist — it stays quiet and
  only runs when the proper query is physically too long, and it announces itself. Extend the
  list with `--wordlist FILE`. Found names are clearly marked "probed — not exhaustive".

## v3.6.4 — error-based payloads short enough to fit tight length caps

### Fixed
- **Targeted error-based extraction now fits length-capped points.** v3.6.3 wrapped every leak in
  `'~'||(…)` to force the cast to fail, which added ~7 characters — enough to overflow a tight
  cap (a ~61-char point would leak `current_database()` but truncate `SELECT password FROM users
  LIMIT 1`). The cast is now **direct** — `1=CAST((<query>) AS int)`, exactly like a hand-written
  payload — so a non-numeric value fails the cast and the error quotes it, with no wrapper
  overhead. The redundant extra parentheses around the query were also dropped.
- The `~`-forced variant is now a **fallback** used only when the direct cast returns nothing
  (i.e. a purely numeric value cast cleanly with no error), so numeric leaks (counts, ids) still
  work without costing every text leak the extra length.

### Changed
- Clearer guidance when error-based returns nothing on a capped point: both `--query` and map
  mode now explain the value may be too long and suggest a shorter targeted query (large
  schema/map queries can't fit a very tight cap — extract directly instead).

## v3.6.3 — error-based that actually leaks on visible-error + length-capped targets

### Fixed
- **Error-based extraction returned the payload instead of the value on query-echoing pages.**
  Targets that print the offending SQL in their error (the classic PortSwigger visible-error
  lab) echoed our `QxZx…QxZx` delimiters back, so `error_value` matched the **echoed query**
  and "leaked" the payload text (`'||((SELECT current_database()))||'`) instead of the real
  value. PostgreSQL and MSSQL now drop the delimiter wrapper entirely and read the value
  **straight from the cast/conversion error message**, anchored to that message — an echoed
  query can no longer fool it. A leading `~` marker forces the cast to fail even for numeric
  values (counts, ids).
- **Payloads are much shorter, so they survive length-capped injection points.** Removing the
  `'QxZx'||(…)||'QxZx'` wrapper makes the error payload roughly match a hand-written one
  (`' AND 1=CAST((…) AS int)--`), so targeted queries (e.g. `SELECT password FROM users
  LIMIT 1`) now fit caps that previously truncated them.

### Added
- **Automatic injection-prefix trimming on length-capped points.** When the marker has a
  deletable value prefix (e.g. `TrackingId=abc123INJECT`) and a payload is being truncated,
  blindfold drops that prefix automatically (it isn't needed for the injection) and retries —
  at both detection and extraction — freeing the field's full length budget. Announced once.
- Length-cap aware hinting: very long map/schema queries that can't fit a tight cap now point
  you to a shorter targeted `--query` instead of silently returning nothing.

## v3.6.2 — fix UNION false positive on visible-error targets

### Fixed
- **UNION detection no longer false-positives when the page reflects errors.** The column
  probe injected a plain literal (`'bfUc1z'`) and matched if it appeared anywhere in the
  response — but a visible-error target echoes the payload inside its error text, so the
  marker "reflected" without any UNION actually running. blindfold then locked onto
  `union-based`, extracted nothing (`Database: None, Tables: 0`), and never reached the
  error-based probe. The probe now emits each value as a **split concatenation**
  (`'bf'||'Uc1z'`, dialect-aware), which only appears contiguously if the database truly
  evaluated it — so error-reflecting targets correctly fall through to error-based.

## v3.6.1 — error-based detection that actually triggers, https auto-probe, failure diagnostic

### Fixed
- **Error-based injection is now detected on its own.** Previously `find_error` could only run
  *after* boolean or time had already fingerprinted the DBMS, so a classic visible-error target
  (no boolean/time signal) bailed at "no blind injection detected" without ever probing for an
  error. Detection now tries each candidate DBMS's forced-error syntax directly — the one whose
  error reflects the probe **both confirms error-based and identifies the backend** — so
  error-based works with zero blind signal. It also announces `[*] error probe : <dbms>/<ctx>`
  alongside the boolean/time probes.
- **`--request` now reaches HTTPS targets.** A raw request file carries no scheme and `--proto`
  defaulted to `http`, so HTTPS-only targets (e.g. PortSwigger labs) silently 400'd every payload
  and looked like "no injection". `--proto` now **auto-probes HTTPS first and falls back to HTTP**
  only if the TLS endpoint is unreachable; pass `--proto http` to force plaintext.

### Added
- **`--force-error`** — only use error-based, skipping boolean/time probing (mutually exclusive
  with `--force-boolean` / `--force-time`).
- **Failure diagnostic.** When detection fails, blindfold sends a clean baseline and a
  representative injected request and reports `status`/`len` for each, flagging the failure mode:
  the injected request being rejected (WAF / encoding), the base request being rejected
  (scheme / host / session), or identical responses (payload not landing).

### Removed
- Dead code: the unused `_stable()` helper and the unread `--len-jitter` flag.

## v3.6.0 — dump count fix + bigger banner

### Fixed
- **`--dump` no longer reports `rows: 0` on PostgreSQL/Oracle when the table has data.**
  The row count was extracted as a raw `count(*)` (an integer); the per-character extractor
  wraps the value in `length()` / `substr()`, which **error on a non-text argument** in
  strict engines (PostgreSQL `length(<bigint>)`, Oracle), so the count read back as 0 and
  nothing was dumped. `q_count` now casts to text per dialect (`as text` / `as char` /
  `as varchar` / `to_char`). MySQL auto-casts, so it was never affected.

### Added
- **`--delay` / `--jitter`** — fixed + random inter-request pacing (rate-limit / WAF friendly).

### Changed
- Bigger ASCII banner in **bold red**, with "created by Hassan Almatar" centered directly
  beneath it.

## v3.5.2 — request hygiene: marker check + header sanitization

### Fixed
- **Errors loudly if the injection marker is missing** from the URL/body/headers (a saved
  request with no marker used to be replayed unchanged, producing a confusing "no signal").
- **Replayed requests are sanitized**: `Accept-Encoding` is forced to `identity` (Brotli/gzip
  bodies broke length/content matching) and hop-by-hop headers (`Connection`, `TE`,
  `Content-Length`) are dropped — these caused some servers to return HTTP 400 on a replayed
  browser request, which looked like a detection failure but wasn't.

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
