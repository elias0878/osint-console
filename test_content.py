#!/usr/bin/env python3
"""Content-level assertions for every module: validates real data, not just HTTP 200."""
import json, sys, time, io, os, urllib.request, urllib.parse, concurrent.futures as cf

BASE = "http://127.0.0.1:8000"
PASS, FAIL = [], []

def api(path, payload=None, method=None, raw_body=None, ctype=None, timeout=180, expect_fail=False):
    t0 = time.time()
    try:
        if payload is not None:
            req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        elif raw_body is not None:
            req = urllib.request.Request(BASE + path, data=raw_body, headers={"Content-Type": ctype}, method="POST")
        else:
            req = urllib.request.Request(BASE + path)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
    except Exception as e:
        return None, f"اتصال فاشل: {type(e).__name__}", int((time.time() - t0) * 1000)
    return body, None, int((time.time() - t0) * 1000)

def check(name, path_or_none, assertions, payload=None, raw=None, ctype=None, expect_fail=False):
    body, err, ms = api(path_or_none, payload=payload, raw_body=raw, ctype=ctype)
    if err:
        FAIL.append((name, err)); return
    if expect_fail:
        if body.get("ok") is False and body.get("error"):
            PASS.append((name, f"رفض صحيح: {body['error'][:60]}", ms))
        else:
            FAIL.append((name, f"كان يجب الرفض لكنه نجح: {str(body)[:100]}"))
        return
    if not body.get("ok"):
        FAIL.append((name, f"خطأ: {str(body.get('error'))[:140]}")); return
    data = body["data"]
    for label, fn in assertions:
        try:
            ok = fn(data)
        except Exception as e:
            ok = False
            label += f" ({type(e).__name__})"
        if not ok:
            FAIL.append((name, f"فشل التحقق: {label}")); return
    PASS.append((name, f"{len(assertions)} تحقق", ms))

def g(d, *keys, default=None):
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d

# ---------------------------------------------------------------- cases
C = [
 ("DNS", "/api/dns?q=example.com", [
    ("سجلات A موجودة", lambda d: len(g(d,"records","A","answers") or []) > 0),
    ("PTR عكسي", lambda d: len(d.get("reverse_dns") or {}) > 0),
 ]),
 ("RDAP (نطاق)", "/api/rdap?q=example.com", [
    ("تم العثور", lambda d: d.get("found") is True),
    ("أحداث التسجيل", lambda d: len(d.get("events") or []) > 0),
    ("خوادم الأسماء", lambda d: len(d.get("nameservers") or []) > 0),
 ]),
 ("RDAP (IP)", "/api/rdap?q=8.8.8.8", [("تم العثور", lambda d: d.get("found") is True)]),
 ("نطاقات فرعية", "/api/subdomains?q=example.com", [
    ("عدد > 0", lambda d: d.get("count", 0) > 0),
    ("مصدر واحد على الأقل", lambda d: len(d.get("sources") or {}) >= 1),
 ]),
 ("تحليل IP", "/api/ip?q=8.8.8.8", [
    ("دولة", lambda d: bool(g(d,"geo","country"))),
    ("ASN", lambda d: bool(g(d,"asn_info","org") or g(d,"geo","as"))),
    ("فحص Tor", lambda d: isinstance(d.get("tor_exit"), bool)),
    ("Spamhaus", lambda d: d.get("spamhaus_drop") is not None),
    ("منافذ InternetDB", lambda d: "ports" in (d.get("shodan_internetdb") or {})),
 ]),
 ("TLS", "/api/tls?q=github.com", [
    ("CN", lambda d: bool(g(d,"subject","commonName"))),
    ("المُصدر", lambda d: bool(g(d,"issuer","organizationName") or g(d,"issuer","commonName"))),
    ("SANs", lambda d: len(d.get("sans") or []) > 0),
    ("تاريخ الانتهاء", lambda d: bool(d.get("not_after"))),
    ("سلسلة صالحة", lambda d: d.get("valid_chain") is True),
 ]),
 ("TLS (شهادة تالفة)", "/api/tls?q=expired.badssl.com", [
    ("يكشف عدم الصلاحية", lambda d: d.get("valid_chain") is False),
    ("يستخرج البيانات", lambda d: bool(g(d,"subject","commonName"))),
 ]),
 ("HTTP", "/api/http?q=https://example.com", [
    ("الحالة 200", lambda d: d.get("status") == 200),
    ("عنوان الصفحة", lambda d: bool(d.get("title"))),
    ("تقييم الأمان", lambda d: "/" in str(d.get("security_score"))),
 ]),
 ("robots", "/api/robots?q=https://github.com", [
    ("robots.txt موجود", lambda d: g(d,"robots","status") == 200),
    ("sitemaps", lambda d: len(d.get("sitemaps") or []) > 0),
 ]),
 ("أرشيف الويب", "/api/wayback?q=example.com", [
    ("لقطات", lambda d: len(d.get("snapshots") or []) > 0),
    ("أقرب نسخة", lambda d: bool(g(d,"closest","url"))),
 ]),
 ("المنافذ", "/api/ports?q=scanme.nmap.org", [
    ("كشف وسيط الشبكة", lambda d: d.get("proxy_intercepted") is True and bool(d.get("warning"))),
 ]),
 ("urlscan", "/api/urlscan?q=domain:example.com", [
    ("نتائج", lambda d: len(d.get("results") or []) > 0),
 ]),
 ("الطيران", "/api/flight?q=50.11,8.68&dist=40", [
    ("طائرات", lambda d: d.get("count", 0) > 0),
    ("إحداثيات", lambda d: d["aircraft"][0].get("lat") is not None),
 ]),
 ("IP الخاص بي", "/api/geoip", [("IP", lambda d: bool(d.get("ip")))]),

 ("WHOIS نطاق", "/api/whois?q=example.com", [
    ("تم العثور", lambda d: d.get("found") is True),
    ("المسجّل", lambda d: bool(g(d,"parsed","registrar"))),
    ("خادم WHOIS", lambda d: bool(d.get("whois_server"))),
 ]),
 ("WHOIS IP", "/api/whois?q=8.8.8.8", [
    ("تم العثور", lambda d: d.get("found") is True),
    ("المنظمة", lambda d: bool(g(d,"parsed","org") or g(d,"parsed","netname"))),
 ]),
 ("مُصدرو الشهادات", "/api/certs?q=example.com", [
    ("شهادات", lambda d: d.get("total_certs", 0) > 0),
    ("مُصدرون", lambda d: len(d.get("issuers") or {}) > 0),
 ]),
 ("عكس IP", "/api/reverseip?q=45.33.32.156", [
    ("نطاقات أو ملاحظة حدّ", lambda d: d.get("count", 0) > 0 or bool(d.get("note"))),
 ]),
 ("السمعة", "/api/threat?q=8.8.8.8", [
    ("مصادر مفحوصة", lambda d: d.get("sources_checked", 0) >= 4),
    ("حكم", lambda d: bool(d.get("verdict"))),
 ]),
 ("MAC/OUI", "/api/oui?q=00:1A:2B:3C:4D:5E", [
    ("مورّد", lambda d: bool(d.get("vendor"))),
 ]),
 ("ويكيبيديا", "/api/wikipedia?q=Frankfurt", [
    ("ملخص", lambda d: len(d.get("extract") or "") > 50),
 ]),
 ("أخبار", "/api/news?q=cyberattack", [
    ("استجابة (مقالات أو ملاحظة حدّ)", lambda d: "articles" in d and ("count" in d or "note" in d)),
 ]),

 ("اسم المستخدم", "/api/username?q=torvalds", [
    ("موجود في > 3 مواقع", lambda d: d.get("found_count", 0) > 3),
    ("GitHub محسوب أو محجوب بحد مجاني", lambda d: any(r["site"]=="GitHub" and r["state"] in ("found","blocked") for r in d.get("all") or [])),
    ("روابط الفحص اليدوي", lambda d: len(d.get("manual_checks") or []) > 0),
 ]),
 ("البريد", "/api/email?q=test@gmail.com", [
    ("MX", lambda d: len(d.get("mx") or []) > 0),
    ("يستقبل بريداً", lambda d: d.get("accepts_mail") is True),
    ("SPF", lambda d: len(d.get("spf") or []) > 0),
    ("Gravatar مفحوص", lambda d: isinstance(d.get("gravatar_exists"), bool)),
 ]),
 ("الهاتف", "/api/phone?q=%2B4915112345678", [
    ("دولة معروفة", lambda d: d.get("country_ar") != "غير معروف"),
    ("E.164", lambda d: d.get("e164","").startswith("+49")),
 ]),
 ("GitHub", "/api/github?q=torvalds", [
    ("اسم الدخول", lambda d: d.get("login") == "torvalds"),
    ("مستودعات", lambda d: d.get("public_repos", 0) > 0),
    ("أهم المستودعات", lambda d: len(d.get("top_repos") or []) > 0),
 ]),
 ("Dorks", "/api/dorks?q=example.com&kind=domain", [
    ("dorks", lambda d: len(d.get("dorks") or []) >= 5),
    ("روابط", lambda d: len(d.get("links") or []) > 0),
 ]),
 ("Hash", "/api/hash?q=5f4dcc3b5aa765d61d8327deb882cf99", [
    ("نوع محدد", lambda d: d["candidates"][0]["type"] != "غير معروف"),
 ]),
 ("CVE", "/api/cve?q=CVE-2021-44228", [
    ("وصف", lambda d: bool(d.get("title") or d.get("results"))),
 ]),
 ("العملات", "/api/crypto?q=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", [
    ("صيغة صحيحة", lambda d: d.get("valid_format") is True),
    ("رصيد", lambda d: "balances" in d),
    ("معاملات", lambda d: len(g(d,"blockchain_info","txs") or []) > 0),
 ]),
 ("العملات (ETH)", "/api/crypto?q=0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", [
    ("شبكة ETH", lambda d: "Ethereum" in d.get("chain","")),
    ("بيانات بلوكسكوت", lambda d: "ethereum" in d),
 ]),
 ("ترميز جغرافي", "/api/geo?q=Frankfurt", [
    ("نتائج", lambda d: len(d.get("results") or []) > 0),
 ]),
 ("عكس الإحداثيات", "/api/revgeo?q=50.1109,8.6821", [
    ("مدينة", lambda d: bool(g(d,"bigdatacloud","city"))),
    ("روابط خرائط", lambda d: len(d.get("links") or {}) > 0),
 ]),
 ("مسافة", "/api/distance?q=50.11,8.68,48.85,2.35", [
    ("مسافة منطقية", lambda d: 400 < d.get("distance_km", 0) < 600),
    ("اتجاه", lambda d: bool(d.get("bearing_compass"))),
 ]),
 ("الطقس", "/api/weather?q=50.11,8.68", [
    ("حالة حالية", lambda d: d.get("current") is not None),
    ("توقعات", lambda d: d.get("daily") is not None),
 ]),
 ("الزلازل", "/api/earthquakes?q=2.5/day", [("عدد", lambda d: d.get("count", 0) > 0)]),
 ("الشركات", "/api/company?q=Apple%20Inc", [
    ("LEI", lambda d: len(d.get("lei") or []) > 0),
    ("SEC", lambda d: len(d.get("sec") or []) > 0),
 ]),
 ("دليل الأدوات", "/api/catalog?q=shodan", [
    ("نتائج", lambda d: d.get("count", 0) > 0),
    ("إجمالي 867", lambda d: d.get("total_in_catalog") == 867),
 ]),
 ("كلمة المرور", "/api/password", [
    ("قوة", lambda d: bool(d.get("strength"))),
    ("كشف تسريب", lambda d: isinstance(d.get("pwned"), bool)),
    ("تسريبة معروفة", lambda d: d.get("pwned") is True),
 ], {"payload": {"q": "password"}}),
 ("IOC", "/api/ioc?enrich=0", [
    ("IPs", lambda d: len(d.get("ipv4") or []) > 0),
    ("بريد", lambda d: len(d.get("emails") or []) > 0),
    ("هاش", lambda d: len(d.get("md5") or []) > 0),
    ("CVE", lambda d: len(d.get("cve") or []) > 0),
 ], {"payload": {"q": "bad@evil.com 45.33.32.156 http://evil.com/x.php 5f4dcc3b5aa765d61d8327deb882cf99 CVE-2021-44228"}}),
]

INVEST = [
 ("تحقيق: نطاق", "/api/investigate?q=example.com", [
    ("نوع صحيح", lambda d: d.get("kind") == "domain"),
    ("≥9 وحدات", lambda d: len(d.get("modules") or {}) >= 9),
    ("بلا أخطاء", lambda d: len(d.get("errors") or {}) == 0),
 ]),
 ("تحقيق: IP", "/api/investigate?q=8.8.8.8", [
    ("نوع صحيح", lambda d: d.get("kind") == "ip"),
    ("وحدة IP", lambda d: "ip" in (d.get("modules") or {})),
 ]),
 ("تحقيق: بريد", "/api/investigate?q=test@gmail.com", [
    ("نوع صحيح", lambda d: d.get("kind") == "email"),
    ("وحدة البريد", lambda d: "email" in (d.get("modules") or {})),
 ]),
 ("تحقيق: مستخدم", "/api/investigate?q=torvalds", [
    ("نوع صحيح", lambda d: d.get("kind") == "username"),
    ("GitHub", lambda d: "github" in (d.get("modules") or {})),
 ]),
 ("تحقيق: هاتف", "/api/investigate?q=%2B4915112345678", [
    ("نوع صحيح", lambda d: d.get("kind") == "phone"),
 ]),
 ("تحقيق: عملة", "/api/investigate?q=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", [
    ("نوع صحيح", lambda d: d.get("kind") == "crypto"),
 ]),
]

ERRORS = [
 ("خطأ: نطاق غير صالح", "/api/dns?q=not%20a%20domain!!", []),
 ("خطأ: IP غير صالح", "/api/ip?q=999.1.1.1", []),
 ("خطأ: بريد غير صالح", "/api/email?q=abc", []),
 ("خطأ: معامل ناقص", "/api/tls", []),
 ("خطأ: مسار غير معروف", "/api/nope", []),
]

def multipart(fname, content, field="file"):
    b = "----OSINTBOUNDARY7f3a"
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{fname}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{b}--\r\n".encode()
    return body, f"multipart/form-data; boundary={b}"

def main():
    for item in C:
        name, path, asserts = item[0], item[1], item[2]
        kw = item[3] if len(item) > 3 else {}
        check(name, path, asserts, **kw)
    for name, path, asserts in INVEST:
        check(name, path, asserts)
    for name, path, _ in ERRORS:
        check(name, path, [], expect_fail=True)
    # file uploads
    png = (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 40)
    check("ملف: PNG", "/api/file", [
        ("نوع حقيقي PNG", lambda d: "PNG" in d.get("magic", "")),
        ("هاش SHA256", lambda d: len(d.get("hashes", {}).get("sha256", "")) == 64),
        ("إنتروبيا", lambda d: d.get("entropy") is not None),
    ], raw=multipart("test.png", png)[0], ctype=multipart("", b"")[1])
    pdf = (b"%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\n2 0 obj<</Type/Pages/Count 3/Kids[3 0 R 4 0 R 5 0 R]>>endobj\n"
           b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\n4 0 obj<</Type/Page/Parent 2 0 R>>endobj\n"
           b"5 0 obj<</Type/Page/Parent 2 0 R>>endobj\n/Title (Secret Doc) /Author (Ali) /Producer (LibreOffice)\ntrailer<</Encrypt>>")
    check("ملف: PDF", "/api/file", [
        ("نوع PDF", lambda d: "PDF" in d.get("magic", "")),
        ("بيانات PDF", lambda d: d.get("pdf", {}).get("pages") == 3),
        ("كشف التشفير", lambda d: d.get("pdf", {}).get("encrypted") is True),
        ("استخراج العنوان", lambda d: "Secret Doc" in str(d.get("pdf", {}).get("meta"))),
    ], raw=multipart("doc.pdf", pdf)[0], ctype=multipart("", b"")[1])
    txt = b"report contact admin@corp.com from 91.198.174.192 see https://evil.example/x 5f4dcc3b5aa765d61d8327deb882cf99"
    check("ملف: نص + IOC", "/api/file", [
        ("استخراج بريد", lambda d: "admin@corp.com" in d.get("iocs", {}).get("emails", [])),
        ("استخراج IP", lambda d: "91.198.174.192" in d.get("iocs", {}).get("ipv4", [])),
        ("استخراج هاش", lambda d: len(d.get("iocs", {}).get("md5", [])) > 0),
    ], raw=multipart("log.txt", txt)[0], ctype=multipart("", b"")[1])

    print(f"\n{'الاختبار':<26}{'النتيجة':<8}{'الزمن':>7}  تفاصيل")
    print("=" * 96)
    for n, info, ms in PASS:
        print(f"{n:<26}{'✓':<8}{ms:>6}ms  {info}")
    for n, info in FAIL:
        print(f"{n:<26}{'✗':<8}{'-':>7}  {info}")
    print("=" * 96)
    print(f"نجح {len(PASS)} / {len(PASS)+len(FAIL)}")
    if FAIL:
        print("\nإخفاقات:")
        for n, i in FAIL:
            print("  -", n, "→", i)
        sys.exit(1)

if __name__ == "__main__":
    main()
