#!/usr/bin/env python3
"""End-to-end test of every module over the real HTTP API."""
import json, sys, time, urllib.request, urllib.parse, concurrent.futures as cf

BASE = "http://127.0.0.1:8000"

CASES = [
    ("dns", "/api/dns?q=example.com"),
    ("rdap", "/api/rdap?q=example.com"),
    ("rdap_ip", "/api/rdap?q=8.8.8.8"),
    ("subdomains", "/api/subdomains?q=example.com"),
    ("ip", "/api/ip?q=8.8.8.8"),
    ("tls", "/api/tls?q=github.com"),
    ("http", "/api/http?q=https://example.com"),
    ("robots", "/api/robots?q=https://example.com"),
    ("wayback", "/api/wayback?q=example.com"),
    ("ports", "/api/ports?q=scanme.nmap.org"),
    ("urlscan", "/api/urlscan?q=domain:example.com"),
    ("flight", "/api/flight?q=50.11,8.68&dist=40"),
    ("geoip", "/api/geoip"),
    ("username", "/api/username?q=torvalds"),
    ("email", "/api/email?q=test@gmail.com"),
    ("phone", "/api/phone?q=%2B4915112345678"),
    ("hash", "/api/hash?q=5f4dcc3b5aa765d61d8327deb882cf99"),
    ("github", "/api/github?q=torvalds"),
    ("dorks", "/api/dorks?q=example.com&kind=domain"),
    ("cve", "/api/cve?q=CVE-2021-44228"),
    ("crypto", "/api/crypto?q=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    ("geo", "/api/geo?q=Frankfurt"),
    ("revgeo", "/api/revgeo?q=50.1109,8.6821"),
    ("distance", "/api/distance?q=50.11,8.68,48.85,2.35"),
    ("weather", "/api/weather?q=50.11,8.68"),
    ("earthquakes", "/api/earthquakes?q=2.5/day"),
    ("company", "/api/company?q=Apple"),
    ("catalog", "/api/catalog?q=shodan"),
    ("investigate_domain", "/api/investigate?q=example.com"),
    ("investigate_user", "/api/investigate?q=torvalds"),
]

POST_CASES = [
    ("password", "/api/password", {"q": "P@ssw0rd123"}),
    ("ioc", "/api/ioc?enrich=0", {"q": "contact bad@evil.com from 45.33.32.156 via http://evil.com/x.php hash 5f4dcc3b5aa765d61d8327deb882cf99 CVE-2021-44228"}),
]

def call(name, path, payload=None, timeout=180):
    t0 = time.time()
    try:
        if payload is not None:
            req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        else:
            req = urllib.request.Request(BASE + path)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode())
            ms = int((time.time() - t0) * 1000)
            if not body.get("ok"):
                return name, False, ms, "ERROR: " + str(body.get("error"))[:160]
            d = body.get("data")
            keys = list(d.keys())[:6] if isinstance(d, dict) else type(d).__name__
            return name, True, ms, f"keys={keys}"
    except Exception as e:
        return name, False, int((time.time() - t0) * 1000), f"{type(e).__name__}: {str(e)[:160]}"

def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    cases = [c for c in CASES if not only or only in c[0]]
    posts = [c for c in POST_CASES if not only or only in c[0]]
    results = []
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(call, n, p) for n, p in cases] + [ex.submit(call, n, p, d) for n, p, d in posts]
        for f in cf.as_completed(futs):
            results.append(f.result())
    order = {n: i for i, (n, *_) in enumerate(cases + posts)}
    results.sort(key=lambda r: order.get(r[0], 99))
    ok = sum(1 for r in results if r[1])
    print(f"\n{'الوحدة':<20}{'النتيجة':<10}{'الزمن':>8}   تفاصيل")
    print("-" * 100)
    for n, good, ms, info in results:
        print(f"{n:<20}{'✓ نجح' if good else '✗ فشل':<10}{ms:>7}ms   {info[:70]}")
    print("-" * 100)
    print(f"نجح {ok}/{len(results)}")
    fails = [r for r in results if not r[1]]
    if fails:
        print("\nفشل:")
        for n, _, _, info in fails:
            print(" -", n, "→", info)
        sys.exit(1)

if __name__ == "__main__":
    main()
