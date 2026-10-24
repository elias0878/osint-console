#!/usr/bin/env python3
"""OSINT Console — self-hosted, no API keys, stdlib only.
Run: python3 server.py [--port 8000]
"""
import json, os, sys, re, time, threading, traceback, mimetypes, urllib.parse, io
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import concurrent.futures as cf

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core
import modules_net as net
import modules_identity as ident
import modules_intel as intel
import modules_extra as extra
import sweep as sweep_engine
import routes as shared_routes
from core import FetchError

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(ROOT, "web")
STARTED = time.time()
JOBS = {}
JOBS_LOCK = threading.Lock()
JOB_TTL = 3600

def _job_gc():
    now = time.time()
    with JOBS_LOCK:
        for k in [k for k, v in JOBS.items() if now - v["created"] > JOB_TTL]:
            JOBS.pop(k, None)

def start_sweep_job(q, kind="auto"):
    import uuid
    jid = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[jid] = {"events": [], "done": False, "created": time.time(), "target": q}
        job = JOBS[jid]

    def emit(ev):
        with JOBS_LOCK:
            job["events"].append(ev)
            if ev.get("type") in ("done", "fatal"):
                job["done"] = True

    def work():
        try:
            sweep_engine.run(q, kind, on_event=emit)
        except FetchError as e:
            emit({"type": "fatal", "error": str(e)})
        except Exception as e:
            traceback.print_exc()
            emit({"type": "fatal", "error": f"{type(e).__name__}: {str(e)[:200]}"})
        finally:
            with JOBS_LOCK:
                job["done"] = True

    threading.Thread(target=work, daemon=True).start()
    _job_gc()
    return jid
LOG = []          # recent calls: (time, path, ms, status)
LOG_LOCK = threading.Lock()
STATS = {"calls": 0, "errors": 0}
STATS_LOCK = threading.Lock()

MODULES = [
    {"id": "dns", "name": "DNS", "icon": "🌐", "group": "الشبكة", "q": "example.com", "ph": "example.com",
     "desc": "سجلات A/AAAA/MX/TXT/NS/CNAME/SOA/CAA + PTR عكسي + مزوّد البريد"},
    {"id": "rdap", "name": "RDAP / WHOIS", "icon": "📇", "group": "الشبكة", "q": "example.com",
     "ph": "example.com أو 8.8.8.8 أو AS15169", "desc": "بيانات تسجيل النطاق/الـIP (بديل WHOIS الحديث، بلا مفاتيح)"},
    {"id": "subdomains", "name": "النطاقات الفرعية", "icon": "🧭", "group": "الشبكة", "q": "example.com",
     "ph": "example.com", "desc": "crt.sh (سجلات الشهادات) + hackertarget"},
    {"id": "ip", "name": "تحليل IP", "icon": "📍", "group": "الشبكة", "q": "8.8.8.8", "ph": "8.8.8.8",
     "desc": "جغرافيا + ISP/ASN + منافذ Shodan InternetDB + Tor + Spamhaus + سمعة"},
    {"id": "tls", "name": "شهادة TLS", "icon": "🔒", "group": "الشبكة", "q": "example.com", "ph": "example.com",
     "desc": "سلسلة الشهادة، SANs، المُصدر، البصمة، صلاحية التحقق"},
    {"id": "http", "name": "فحص HTTP", "icon": "🧾", "group": "الشبكة", "q": "https://example.com",
     "ph": "https://example.com", "desc": "الرؤوس، التقنيات، ترويسات الأمان، إعادة التوجيه"},
    {"id": "robots", "name": "robots/sitemap", "icon": "🤖", "group": "الشبكة", "q": "https://example.com",
     "ph": "https://example.com", "desc": "robots.txt + sitemaps + security.txt + humans.txt"},
    {"id": "wayback", "name": "أرشيف الويب", "icon": "🗄️", "group": "الشبكة", "q": "example.com",
     "ph": "example.com", "desc": "Wayback Machine: أقرب نسخة + لقطات محفوظة"},
    {"id": "ports", "name": "فحص المنافذ", "icon": "🚪", "group": "الشبكة", "q": "scanme.nmap.org",
     "ph": "host (استخدم أهدافاً تملكها)", "desc": "TCP connect لـ24 منفذاً شائعاً — استخدمه على أهداف مصرّح بها فقط"},
    {"id": "urlscan", "name": "urlscan.io", "icon": "🕵️", "group": "الشبكة", "q": "domain:example.com",
     "ph": "domain:example.com أو ip:1.2.3.4", "desc": "فحوصات عامة محفوظة بلا مفتاح"},
    {"id": "flight", "name": "الطيران المباشر", "icon": "✈️", "group": "الشبكة", "q": "50.11,8.68,60",
     "ph": "lat,lon,radius_km", "desc": "طائرات ADS-B حول نقطة (adsb.fi المجاني)"},

    {"id": "username", "name": "اسم المستخدم", "icon": "👤", "group": "الهوية", "q": "torvalds",
     "ph": "username", "desc": "تحقق من ~34 منصة + روابط فحص يدوي للباقي"},
    {"id": "email", "name": "البريد الإلكتروني", "icon": "✉️", "group": "الهوية", "q": "test@gmail.com",
     "ph": "name@example.com", "desc": "MX/SPF/DMARC + Gravatar + مؤشرات + روابط فحص"},
    {"id": "phone", "name": "رقم الهاتف", "icon": "📱", "group": "الهوية", "q": "+4915112345678",
     "ph": "+4915112345678", "desc": "تحليل E.164 محلي، الدولة، الصيغ، روابط"},
    {"id": "github", "name": "GitHub", "icon": "🐙", "group": "الهوية", "q": "torvalds", "ph": "username",
     "desc": "الملف الشخصي + المستودعات + اللغات (بلا مفتاح)"},
    {"id": "dorks", "name": "مولّد Dorks", "icon": "🔍", "group": "الهوية", "q": "example.com",
     "ph": "كلمة/بريد/نطاق", "desc": "dorks جاهزة عبر Google/Bing/DuckDuckGo + Yandex"},
    {"id": "password", "name": "كلمة المرور", "icon": "🔑", "group": "الهوية", "q": "P@ssw0rd123",
     "ph": "كلمة المرور (لا تُخزَّن)", "desc": "قوة + كشف التسريب عبر k-anonymity (HIBP)"},
    {"id": "hash", "name": "تحديد Hash", "icon": "#️⃣", "group": "الهوية", "q": "5f4dcc3b5aa765d61d8327deb882cf99",
     "ph": "قيمة الهاش", "desc": "تحديد النوع والطول والخصائص"},

    {"id": "cve", "name": "CVE / ثغرات", "icon": "🛡️", "group": "الاستخبارات", "q": "CVE-2021-44228",
     "ph": "CVE-2021-44228 أو كلمة", "desc": "NVD + CIRCL بلا مفتاح"},
    {"id": "crypto", "name": "عملات رقمية", "icon": "₿", "group": "الاستخبارات", "q": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
     "ph": "BTC / ETH / TRX / SOL", "desc": "رصيد + معاملات + روابط مستكشفات"},
    {"id": "geo", "name": "ترميز جغرافي", "icon": "🗺️", "group": "الاستخبارات", "q": "Frankfurt",
     "ph": "اسم مكان", "desc": "بحث أمامي (open-meteo + Photon/OSM)"},
    {"id": "revgeo", "name": "عكس الإحداثيات", "icon": "📌", "group": "الاستخبارات", "q": "50.1109,8.6821",
     "ph": "lat,lon", "desc": "عنوان تقريبي + روابط خرائط + SunCalc"},
    {"id": "distance", "name": "مسافة/اتجاه", "icon": "📐", "group": "الاستخبارات", "q": "50.11,8.68,48.85,2.35",
     "ph": "lat1,lon1,lat2,lon2", "desc": "Haversine + الاتجاه + زمن طيران"},
    {"id": "weather", "name": "الطقس", "icon": "🌦️", "group": "الاستخبارات", "q": "50.11,8.68",
     "ph": "lat,lon", "desc": "الحالي + 3 أيام + شروق/غروب"},
    {"id": "earthquakes", "name": "زلازل", "icon": "🌋", "group": "الاستخبارات", "q": "2.5/day",
     "ph": "magnitude/window مثل 2.5/day", "desc": "USGS — أحدث الزلازل"},
    {"id": "company", "name": "الشركات", "icon": "🏢", "group": "الاستخبارات", "q": "Apple",
     "ph": "اسم شركة أو رمز", "desc": "GLEIF LEI + SEC EDGAR + روابط سجلات"},
    {"id": "ioc", "name": "استخراج IOC", "icon": "🧩", "group": "الاستخبارات", "q": "",
     "ph": "الصق نصاً/تقريراً لاستخراج المؤشرات", "desc": "IPs/نطاقات/روابط/بريد/هاشات/عناوين + إثراء"},
    {"id": "catalog", "name": "دليل الأدوات", "icon": "📚", "group": "الاستخبارات", "q": "",
     "ph": "ابحث في 867 أداة مجانية", "desc": "من تدقيق قائمة Awesome-OSINT (المجاني فقط)"},
    {"id": "file", "name": "تحليل ملف", "icon": "📄", "group": "الاستخبارات", "q": "",
     "ph": "ارفع صورة/PDF/أي ملف", "desc": "هاشات + نوع حقيقي + EXIF/GPS + PDF + سلاسل + IOC"},

    {"id": "whois", "name": "WHOIS خام", "icon": "📜", "group": "مصادر إضافية", "q": "example.com",
     "ph": "example.com أو 8.8.8.8", "desc": "استعلام WHOIS المباشر عبر المنفذ 43 مع تتبّع الإحالة بين الخوادم"},
    {"id": "certs", "name": "مُصدرو الشهادات", "icon": "🏷️", "group": "مصادر إضافية", "q": "example.com",
     "ph": "example.com", "desc": "تجميع شهادات crt.sh حسب جهة الإصدار + أسماء فريدة"},
    {"id": "reverseip", "name": "عكس IP (نطاقات)", "icon": "🔁", "group": "مصادر إضافية", "q": "45.33.32.156",
     "ph": "IP", "desc": "النطاقات المستضافة على نفس العنوان (Hackertarget)"},
    {"id": "threat", "name": "فحص السمعة", "icon": "🚨", "group": "مصادر إضافية", "q": "8.8.8.8",
     "ph": "IP أو نطاق", "desc": "Tor + Spamhaus DROP + Feodo + blocklist.de + StopForumSpam"},
    {"id": "oui", "name": "مورّد MAC/OUI", "icon": "🖧", "group": "مصادر إضافية", "q": "00:1A:2B:3C:4D:5E",
     "ph": "00:1A:2B:3C:4D:5E", "desc": "معرّف الشركة المصنّعة من عنوان MAC"},
    {"id": "wikipedia", "name": "ويكيبيديا", "icon": "📖", "group": "مصادر إضافية", "q": "Frankfurt",
     "ph": "اسم شخص/شركة/مكان", "desc": "ملخص موسوعي عربي مع بحث احتياطي + روابط Wikidata"},
    {"id": "news", "name": "أخبار GDELT", "icon": "📰", "group": "مصادر إضافية", "q": "cyberattack",
     "ph": "كلمة أو عبارة", "desc": "أحدث المقالات من GDELT (مجاني، بلا مفتاح) — قد يحدّ الطلبات"},
]

def ja(x):
    return json.dumps(core.clean(x), ensure_ascii=False).encode("utf-8")

def guard(fn, *a, **kw):
    t0 = time.time()
    try:
        return {"ok": True, "data": core.clean(fn(*a, **kw)), "ms": int((time.time() - t0) * 1000)}
    except FetchError as e:
        # validation / upstream rejection: expected, not a server fault
        return {"ok": False, "soft": True, "error": str(e), "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        traceback.print_exc()
        return {"ok": False, "soft": False, "error": f"{type(e).__name__}: {str(e)[:200]}",
                "ms": int((time.time() - t0) * 1000)}

def _floats(s, n):
    parts = [p.strip() for p in s.replace(";", ",").split(",")]
    if len(parts) < n:
        raise FetchError("أدخل القيم مفصولة بفواصل")
    try:
        return [float(x) for x in parts[:n]]
    except ValueError:
        raise FetchError("قيم رقمية غير صالحة")

def investigate(q, kind="auto"):
    """Run every applicable module concurrently and aggregate results."""
    q = q.strip()
    if not q:
        raise FetchError("أدخل هدفاً")
    if kind == "auto":
        if re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", q, re.I):
            kind = "email"
        elif re.match(r"^(\d{1,3}\.){3}\d{1,3}$", q):
            kind = "ip"
        elif re.match(r"^\+?\d{7,15}$", q.replace(" ", "")):
            kind = "phone"
        elif re.match(r"^(bc1|[13])[a-zA-Z0-9]{25,60}$", q) or re.match(r"^0x[a-fA-F0-9]{40}$", q):
            kind = "crypto"
        elif re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", q, re.I):
            kind = "domain"
        else:
            kind = "username"
    jobs = {}
    if kind == "domain":
        jobs = {"dns": lambda: net.dns_lookup(q), "rdap": lambda: net.rdap_lookup(q),
                "subdomains": lambda: net.subdomains(q), "tls": lambda: net.tls_info(q),
                "http": lambda: net.http_probe("https://" + q), "robots": lambda: net.robots("https://" + q),
                "wayback": lambda: net.wayback(q), "urlscan": lambda: net.urlscan_search("domain:" + q),
                "certs": lambda: extra.cert_issuers(q), "whois": lambda: extra.whois_lookup(q)}
    elif kind == "ip":
        jobs = {"ip": lambda: net.ip_intel(q), "rdap": lambda: net.rdap_lookup(q),
                "dns": lambda: net.dns_lookup(q, ["PTR"]), "ports": lambda: net.port_check(q, list(net.COMMON_PORTS)[:16]),
                "threat": lambda: extra.threat_check(q), "reverseip": lambda: extra.reverse_ip(q)}
    elif kind == "email":
        jobs = {"email": lambda: ident.email_intel(q), "dns": lambda: net.dns_lookup(q.split("@")[1], ["MX", "TXT", "A"]),
                "dorks": lambda: ident.dork_builder(q, "email")}
    elif kind == "username":
        jobs = {"username": lambda: ident.username_scan(q), "github": lambda: ident.github_user(q),
                "dorks": lambda: ident.dork_builder(q, "person")}
    elif kind == "phone":
        jobs = {"phone": lambda: ident.phone_intel(q), "dorks": lambda: ident.dork_builder(q, "general")}
    elif kind == "crypto":
        jobs = {"crypto": lambda: intel.crypto_lookup(q)}
    else:
        jobs = {"username": lambda: ident.username_scan(q)}
    res = {"target": q, "kind": kind, "modules": {}, "errors": {}}
    with cf.ThreadPoolExecutor(max_workers=len(jobs) or 1) as ex:
        futs = {ex.submit(guard, fn): name for name, fn in jobs.items()}
        for f in cf.as_completed(futs, timeout=110):
            name = futs[f]
            try:
                r = f.result()
            except Exception as e:
                r = {"ok": False, "error": str(e)[:200]}
            if r.get("ok"):
                res["modules"][name] = r["data"]
            else:
                res["errors"][name] = r.get("error")
    return res

SELFCHECK = [
    ("DNS", lambda: net.dns_lookup("example.com")),
    ("RDAP", lambda: net.rdap_lookup("example.com")),
    ("نطاقات فرعية", lambda: net.subdomains("example.com")),
    ("IP", lambda: net.ip_intel("8.8.8.8")),
    ("TLS", lambda: net.tls_info("example.com")),
    ("HTTP", lambda: net.http_probe("https://example.com")),
    ("robots", lambda: net.robots("https://github.com")),
    ("أرشيف", lambda: net.wayback("example.com")),
    ("المنافذ", lambda: net.port_check("scanme.nmap.org")),
    ("urlscan", lambda: net.urlscan_search("domain:example.com")),
    ("الطيران", lambda: net.flight_nearby(50.11, 8.68, 40)),
    ("WHOIS", lambda: extra.whois_lookup("example.com")),
    ("الشهادات", lambda: extra.cert_issuers("example.com")),
    ("عكس IP", lambda: extra.reverse_ip("45.33.32.156")),
    ("السمعة", lambda: extra.threat_check("8.8.8.8")),
    ("OUI", lambda: extra.oui_lookup("00:1A:2B:3C:4D:5E")),
    ("ويكيبيديا", lambda: extra.wikipedia_lookup("Berlin")),
    ("اسم مستخدم", lambda: ident.username_scan("torvalds")),
    ("بريد", lambda: ident.email_intel("test@gmail.com")),
    ("هاتف", lambda: ident.phone_intel("+4915112345678")),
    ("GitHub", lambda: ident.github_user("torvalds")),
    ("Hash", lambda: ident.hash_identify("5f4dcc3b5aa765d61d8327deb882cf99")),
    ("كلمة المرور", lambda: ident.password_check("P@ssw0rd123")),
    ("CVE", lambda: intel.cve_lookup("CVE-2021-44228")),
    ("العملات", lambda: intel.crypto_lookup("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")),
    ("جغرافيا", lambda: intel.geocode("Berlin")),
    ("عكس الإحداثيات", lambda: intel.reverse_geocode(50.11, 8.68)),
    ("الطقس", lambda: intel.weather(50.11, 8.68)),
    ("الزلازل", lambda: intel.earthquakes("2.5", "day")),
    ("الشركات", lambda: intel.company_lookup("Apple Inc")),
    ("دليل الأدوات", lambda: intel.catalog_search("dns")),
    ("IOC", lambda: intel.ioc_extract("a@b.com 8.8.8.8 CVE-2021-44228")),
]

def selfcheck():
    """Run every module once and report pass/fail with timing (used by the UI button)."""
    t0 = time.time()
    results = []
    def one(name, fn):
        s = time.time()
        try:
            d = fn()
            ok = d is not None and (not isinstance(d, dict) or len(d) > 0)
            return {"module": name, "ok": ok, "ms": int((time.time() - s) * 1000),
                    "error": None if ok else "نتيجة فارغة"}
        except FetchError as e:
            return {"module": name, "ok": False, "ms": int((time.time() - s) * 1000), "error": str(e)[:140]}
        except Exception as e:
            return {"module": name, "ok": False, "ms": int((time.time() - s) * 1000),
                    "error": f"{type(e).__name__}: {str(e)[:120]}"}
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(lambda p: one(*p), SELFCHECK):
            results.append(r)
    passed = sum(1 for r in results if r["ok"])
    return {"ok": passed == len(results), "passed": passed, "total": len(results),
            "total_ms": int((time.time() - t0) * 1000), "results": results}


class Handler(BaseHTTPRequestHandler):
    server_version = "OSINTConsole/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body, ctype="application/json; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Access-Control-Allow-Origin", "*")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _record(self, path, ms, ok, status=200):
        with LOG_LOCK:
            LOG.append({"t": int(time.time()), "p": path, "ms": ms, "ok": ok, "s": status})
            del LOG[:-400]
        with STATS_LOCK:
            STATS["calls"] += 1
            if status >= 500:
                STATS["errors"] += 1
            elif status == 400:
                STATS["rejected"] = STATS.get("rejected", 0) + 1

    def do_OPTIONS(self):
        self._send(204, b"", extra={"Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                                    "Access-Control-Allow-Headers": "Content-Type"})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    # ------------------------------------------------------------------ static
    def _static(self, path):
        rel = path.split("?")[0].lstrip("/") or "index.html"
        full = os.path.normpath(os.path.join(WEB, rel))
        if not os.path.isfile(full):                      # fall back to repo root (Vercel layout)
            full = os.path.normpath(os.path.join(ROOT, rel))
            if not os.path.isfile(full):
                full = os.path.join(WEB, rel)
        if not full.startswith(WEB):
            return self._send(403, b'{"error":"forbidden"}')
        if not os.path.isfile(full):
            return self._send(404, b'{"error":"not found"}')
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if full.endswith((".html", ".css", ".js")):
            ctype += "; charset=utf-8"
        with open(full, "rb") as f:
            data = f.read()
        self._send(200, data, ctype)

    # ------------------------------------------------------------------ routing
    def _route(self, method):
        t0 = time.time()
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        args = {k: v[0] for k, v in qs.items()}
        body = b""
        if method == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
        try:
            if not path.startswith("/api/"):
                return self._static(path)

            if path == "/api/health":
                out = {"ok": True, "uptime_s": int(time.time() - STARTED), "modules": len(MODULES),
                       "python": sys.version.split()[0], "stats": STATS}
                self._record(path, int((time.time() - t0) * 1000), True)
                return self._send(200, ja(out))
            if path == "/api/modules":
                return self._send(200, ja({"modules": MODULES, "groups": sorted({m["group"] for m in MODULES})}))
            if path == "/api/selfcheck":
                return self._send(200, ja(selfcheck()))
            if path == "/api/stats":
                return self._send(200, ja({"stats": STATS, "log": LOG[-100:],
                                           "cache_entries": len(core._cache)}))

            # dispatch table -------------------------------------------------
            def need(name):
                v = args.get(name) or (json.loads(body).get(name) if body[:1] in (b"{",) else None)
                if v is None or not str(v).strip():
                    raise FetchError(f"المعامل «{name}» مطلوب")
                return str(v).strip()

            def qtext():
                if body[:1] == b"{":
                    try:
                        return str(json.loads(body).get("q", "")).strip()
                    except Exception:
                        return ""
                return args.get("q", "").strip()

            table = {
                "/api/dns": lambda: net.dns_lookup(need("q")),
                "/api/rdap": lambda: net.rdap_lookup(need("q")),
                "/api/subdomains": lambda: net.subdomains(need("q")),
                "/api/ip": lambda: net.ip_intel(need("q")),
                "/api/tls": lambda: net.tls_info(need("q")),
                "/api/http": lambda: net.http_probe(need("q")),
                "/api/robots": lambda: net.robots(need("q")),
                "/api/wayback": lambda: net.wayback(need("q")),
                "/api/ports": lambda: net.port_check(need("q"),
                                                     [int(x) for x in args["ports"].split(",") if x.strip().isdigit()] or None
                                                     if args.get("ports") else None),
                "/api/urlscan": lambda: net.urlscan_search(need("q")),
                "/api/flight": lambda: net.flight_nearby(*_floats(need("q"), 2), *(_floats(args["dist"], 1) if args.get("dist") else [40])),
                "/api/geoip": lambda: net.geoip_self(),
                "/api/username": lambda: ident.username_scan(need("q")),
                "/api/email": lambda: ident.email_intel(need("q")),
                "/api/phone": lambda: ident.phone_intel(need("q"), int(args.get("cc", 49))),
                "/api/password": lambda: ident.password_check(qtext() or need("q")),
                "/api/hash": lambda: ident.hash_identify(need("q")),
                "/api/github": lambda: ident.github_user(need("q")),
                "/api/dorks": lambda: ident.dork_builder(need("q"), args.get("kind", "general")),
                "/api/cve": lambda: intel.cve_lookup(need("q")),
                "/api/crypto": lambda: intel.crypto_lookup(need("q")),
                "/api/geo": lambda: intel.geocode(need("q")),
                "/api/revgeo": lambda: intel.reverse_geocode(*_floats(need("q"), 2)),
                "/api/distance": lambda: intel.distance(*_floats(need("q"), 4)),
                "/api/weather": lambda: intel.weather(*_floats(need("q"), 2)),
                "/api/earthquakes": lambda: intel.earthquakes(*(need("q").split("/") + ["day"])[:2]),
                "/api/company": lambda: intel.company_lookup(need("q")),
                "/api/catalog": lambda: intel.catalog_search(args.get("q", ""), args.get("cat", ""),
                                                             int(args.get("limit", 200))),
                "/api/investigate": lambda: investigate(need("q"), args.get("kind", "auto")),
                "/api/whois": lambda: extra.whois_lookup(need("q")),
                "/api/certs": lambda: extra.cert_issuers(need("q")),
                "/api/reverseip": lambda: extra.reverse_ip(need("q")),
                "/api/threat": lambda: extra.threat_check(need("q")),
                "/api/oui": lambda: extra.oui_lookup(need("q")),
                "/api/wikipedia": lambda: extra.wikipedia_lookup(need("q"), args.get("lang", "ar")),
                "/api/news": lambda: extra.news_search(need("q"), args.get("timespan", "7d")),
            }
            if path == "/api/plan":
                out = guard(shared_routes.plan, need("q"), args.get("kind", "auto"))
                self._record(path, out["ms"], out["ok"])
                return self._send(200, ja(out))
            if path == "/api/sweep":
                out = guard(sweep_engine.run, need("q"), args.get("kind", "auto"))
                self._record(path, out["ms"], out["ok"], 200 if out["ok"] else 500)
                return self._send(200, ja(out))
            if path == "/api/sweep/start":
                return self._send(200, ja({"ok": True, "job": start_sweep_job(need("q"), args.get("kind", "auto"))}))
            if path == "/api/sweep/poll":
                jid = need("id")
                frm = int(args.get("from", 0) or 0)
                with JOBS_LOCK:
                    job = JOBS.get(jid)
                    if not job:
                        return self._send(404, ja({"ok": False, "error": "مهمة غير موجودة أو منتهية الصلاحية"}))
                    evs = job["events"][frm:]
                    total = len(job["events"])
                    done = job["done"]
                return self._send(200, ja({"ok": True, "events": evs, "next": total, "done": done}))
            if path == "/api/sweep/stream":
                return self._sweep_stream(need("q"), args.get("kind", "auto"))
            if path == "/api/ioc":
                txt = qtext() or need("q")
                iocs = intel.ioc_extract(txt)
                if args.get("enrich") == "1":
                    iocs["enrichment"] = intel.ioc_enrich(iocs)
                out = {"ok": True, "data": iocs, "ms": int((time.time() - t0) * 1000)}
                self._record(path, out["ms"], True)
                return self._send(200, ja(out))
            if path == "/api/file":
                return self._handle_file(body)
            fn = table.get(path)
            if not fn:
                return self._send(404, ja({"ok": False, "error": "مسار غير معروف"}))
            out = guard(fn)
            self._record(path, out["ms"], out["ok"],
                         200 if out["ok"] else (400 if out.get("soft") else 500))
            return self._send(200, ja(out))
        except FetchError as e:
            self._record(path, int((time.time() - t0) * 1000), False)
            return self._send(400, ja({"ok": False, "error": str(e)}))
        except Exception as e:
            traceback.print_exc()
            self._record(path, int((time.time() - t0) * 1000), False)
            return self._send(500, ja({"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}))

    # ------------------------------------------------------------------ SSE sweep
    def _sweep_stream(self, q, kind):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        alive = {"v": True}

        def emit(obj):
            if not alive["v"]:
                return
            try:
                self.wfile.write(b"data: " + json.dumps(core.clean(obj), ensure_ascii=False).encode() + b"\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                alive["v"] = False

        try:
            sweep_engine.run(q, kind, on_event=emit)
            emit({"type": "end"})
        except FetchError as e:
            emit({"type": "fatal", "error": str(e)})
        except Exception as e:
            traceback.print_exc()
            emit({"type": "fatal", "error": f"{type(e).__name__}: {str(e)[:200]}"})
        self._record("/api/sweep/stream", 0, True)

    # ------------------------------------------------------------------ upload
    def _handle_file(self, body):
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            return self._send(400, ja({"ok": False, "error": "أرسل الملف عبر multipart/form-data"}))
        boundary = ctype.split("boundary=", 1)[1].strip().strip('"').encode()
        parts = body.split(b"--" + boundary)
        fname, data = None, b""
        for part in parts:
            if b"Content-Disposition" not in part:
                continue
            head, _, payload = part.partition(b"\r\n\r\n")
            m = re.search(rb'filename="([^"]*)"', head)
            if m:
                fname = m.group(1).decode("utf-8", "replace")
                data = payload[:-2] if payload.endswith(b"\r\n") else payload
                break
        if not data:
            return self._send(400, ja({"ok": False, "error": "لم يصل ملف"}))
        out = guard(intel.file_analyze, fname or "upload.bin", data)
        self._record("/api/file", out["ms"], out["ok"])
        return self._send(200, ja(out), extra={"Connection": "close"})


def main():
    port = 8000
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    print(f"OSINT Console → http://0.0.0.0:{port}  ({len(MODULES)} modules)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")

if __name__ == "__main__":
    main()
