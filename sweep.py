"""Full sweep engine: runs EVERY module against a target, with retries and per-module status.
Nothing is silently skipped — inapplicable modules are reported with a reason."""
import time, re, ipaddress, concurrent.futures as cf
import modules_net as net
import modules_identity as ident
import modules_intel as intel
import modules_extra as extra
from core import FetchError

MODULE_TIMEOUT = 80          # seconds per module (hard cap)
RETRIES = 1                  # extra attempts on network/upstream failures

RETRYABLE = (FetchError, TimeoutError, ConnectionError, OSError)

def normalize(q):
    """Accept URLs, bare hosts, @handles and spaced numbers; return a clean target."""
    q = (q or "").strip()
    if re.match(r"^https?://", q, re.I):
        from urllib.parse import urlsplit
        q = urlsplit(q).netloc
    q = q.rstrip("/").split("/")[0] if not re.match(r"^@", q) else q
    if re.match(r"^www\.[a-z0-9-]+\.[a-z]{2,}$", q, re.I):
        q = q[4:]
    return q

def detect(q):
    q = q.strip().lstrip("@")
    if re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", q):
        return "email"
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", q):
        return "ip"
    if re.match(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", q):
        return "mac"
    if re.match(r"^\+?[\d\s\-()]{7,18}$", q) and len(re.sub(r"\D", "", q)) >= 7:
        return "phone"
    if re.match(r"^(bc1|[13])[A-Za-z0-9]{25,60}$", q) or re.match(r"^0x[a-fA-F0-9]{40}$", q):
        return "crypto"
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", q):
        return "hash"
    if re.match(r"^CVE-\d{4}-\d{4,7}$", q, re.I):
        return "cve"
    if re.match(r"^-?\d{1,3}(\.\d+)?\s*,\s*-?\d{1,3}(\.\d+)?$", q):
        return "coords"
    if re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", q, re.I) or re.match(r"^https?://", q, re.I):
        return "domain"
    return "username"

def _resolve(q):
    try:
        import socket
        return socket.gethostbyname(q.replace("https://", "").replace("http://", "").split("/")[0])
    except Exception:
        return None

def build_plan(q, kind):
    """Return every module with (id, label, callable-or-None, reason-if-skipped)."""
    items = []
    def add(mid, label, fn=None, skip=None, qval=None):
        # a module that CAN run must never be reported as skipped
        if fn is not None:
            skip = None
        items.append({"id": mid, "name": label, "fn": fn, "skip": skip, "q": qval or q})

    host = q.split("/")[0] if kind == "domain" else q

    # --- always meaningful for any target ---
    add("dorks", "مولّد Dorks", lambda: ident.dork_builder(q, "person" if kind == "username" else
                                                          "email" if kind == "email" else
                                                          "domain" if kind == "domain" else "general"))
    add("catalog", "دليل الأدوات (بحث مطابق)", lambda: intel.catalog_search(q, limit=40))

    if kind == "domain":
        dq = host
        add("dns", "سجلات DNS", lambda: net.dns_lookup(dq))
        add("rdap", "RDAP", lambda: net.rdap_lookup(dq))
        add("whois", "WHOIS خام", lambda: extra.whois_lookup(dq))
        add("subdomains", "النطاقات الفرعية", lambda: net.subdomains(dq))
        add("certs", "مُصدرو الشهادات", lambda: extra.cert_issuers(dq))
        add("tls", "شهادة TLS", lambda: net.tls_info(host))
        add("http", "فحص HTTP", lambda: net.http_probe("https://" + host))
        add("robots", "robots/sitemap", lambda: net.robots("https://" + host))
        add("wayback", "أرشيف الويب", lambda: net.wayback(dq))
        add("urlscan", "urlscan.io", lambda: net.urlscan_search("domain:" + host))
        rip = _resolve(host)
        add("ip", "IP المستضيف", (lambda ip=rip: net.ip_intel(ip)) if rip else None,
            "تعذّر تحويل النطاق إلى عنوان IP", qval=rip)
        add("threat", "فحص السمعة", (lambda ip=rip: extra.threat_check(ip)) if rip else None,
            "لا يوجد IP لفحصه", qval=rip)
        add("reverseip", "نطاقات على نفس IP", (lambda ip=rip: extra.reverse_ip(ip)) if rip else None,
            "لا يوجد IP لفحصه", qval=rip)
        add("wikipedia", "ويكيبيديا", lambda: extra.wikipedia_lookup(dq))
        add("news", "أخبار GDELT", lambda: extra.news_search(dq))
        add("geo", "ترميز جغرافي", lambda: intel.geocode(dq))
        add("ports", "فحص المنافذ", lambda: net.port_check(host, [22, 80, 443, 8080, 8443]))
    elif kind == "ip":
        add("ip", "تحليل IP", lambda: net.ip_intel(q))
        add("rdap", "RDAP", lambda: net.rdap_lookup(q))
        add("whois", "WHOIS خام", lambda: extra.whois_lookup(q))
        add("dns", "PTR عكسي", lambda: net.dns_lookup(q, ["PTR"]))
        add("threat", "فحص السمعة", lambda: extra.threat_check(q))
        add("reverseip", "نطاقات على نفس IP", lambda: extra.reverse_ip(q))
        add("urlscan", "urlscan.io", lambda: net.urlscan_search("ip:" + q))
        add("ports", "فحص المنافذ", lambda: net.port_check(q, [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]))
        add("wikipedia", "ويكيبيديا", lambda: extra.wikipedia_lookup(q))
        add("news", "أخبار GDELT", lambda: extra.news_search(q))
    elif kind == "email":
        dom = q.split("@")[1]
        add("email", "تحليل البريد", lambda: ident.email_intel(q))
        add("dns", "DNS النطاق", lambda: net.dns_lookup(dom, ["MX", "TXT", "A", "NS"]), qval=dom)
        add("rdap", "RDAP النطاق", lambda: net.rdap_lookup(dom), qval=dom)
        add("whois", "WHOIS النطاق", lambda: extra.whois_lookup(dom), qval=dom)
        add("threat", "سمعة النطاق", lambda: extra.threat_check(dom), qval=dom)
        add("subdomains", "نطاقات فرعية للنطاق", lambda: net.subdomains(dom), qval=dom)
        add("company", "الشركات", lambda: intel.company_lookup(dom.split(".")[0]), qval=dom.split(".")[0])
        add("wikipedia", "ويكيبيديا", lambda: extra.wikipedia_lookup(dom.split(".")[0]))
        add("news", "أخبار GDELT", lambda: extra.news_search(dom))
    elif kind == "username":
        add("username", "تعداد أسماء المستخدمين", lambda: ident.username_scan(q))
        add("github", "GitHub", lambda: ident.github_user(q))
        add("wikipedia", "ويكيبيديا", lambda: extra.wikipedia_lookup(q))
        add("news", "أخبار GDELT", lambda: extra.news_search(q))
    elif kind == "phone":
        add("phone", "تحليل الهاتف", lambda: ident.phone_intel(q))
        add("wikipedia", "ويكيبيديا", lambda: extra.wikipedia_lookup(q))
        add("news", "أخبار GDELT", lambda: extra.news_search(q))
    elif kind == "crypto":
        add("crypto", "تحليل العملة", lambda: intel.crypto_lookup(q))
        add("threat", "فحص السمعة", lambda: extra.threat_check(q))
    elif kind == "hash":
        add("hash", "تحديد Hash", lambda: ident.hash_identify(q))
    elif kind == "mac":
        add("oui", "مورّد MAC", lambda: extra.oui_lookup(q))
    elif kind == "cve":
        add("cve", "تفاصيل CVE", lambda: intel.cve_lookup(q))
        add("news", "أخبار GDELT", lambda: extra.news_search(q))
        add("wikipedia", "ويكيبيديا", lambda: extra.wikipedia_lookup(q))
    elif kind == "coords":
        lat, lon = [float(x) for x in q.split(",")]
        add("revgeo", "عكس الإحداثيات", lambda: intel.reverse_geocode(lat, lon))
        add("weather", "الطقس", lambda: intel.weather(lat, lon))
        add("flight", "طيران ADS-B", lambda: net.flight_nearby(lat, lon, 40))
        add("earthquakes", "زلازل", lambda: intel.earthquakes("2.5", "day"), qval="2.5/day")
        add("geo", "ترميز جغرافي", lambda: intel.geocode(f"{lat},{lon}"), qval=f"{lat},{lon}")
    else:
        add("username", "تعداد أسماء المستخدمين", lambda: ident.username_scan(q))

    # modules that need dedicated input — reported, never hidden
    for mid, nm, why in [
        ("password", "كلمة المرور", "يتطلب إدخال كلمة مرور في وحدتها"),
        ("file", "تحليل ملف", "يتطلب رفع ملف"),
        ("ioc", "استخراج IOC", "يتطلب لصق نص"),
        ("distance", "مسافة/اتجاه", "يتطلب إحداثيات هدفين"),
        ("phone", "الهاتف", "غير منطبق على هذا النوع") if kind != "phone" else ("phone_h", "", ""),
        ("github", "GitHub", "غير منطبق — الهدف ليس اسم مستخدم") if kind != "username" else ("gh", "", ""),
        ("crypto", "العملات", "غير منطبق — الهدف ليس عنوان عملة") if kind != "crypto" else ("cr", "", ""),
        ("hash", "Hash", "غير منطبق — الهدف ليس هاشاً") if kind != "hash" else ("hs", "", ""),
        ("oui", "MAC/OUI", "غير منطبق — الهدف ليس عنوان MAC") if kind != "mac" else ("ou", "", ""),
        ("cve", "CVE", "غير منطبق — الهدف ليس رقم ثغرة") if kind != "cve" else ("cv", "", ""),
    ]:
        if not mid or not nm:
            continue
        if any(i["id"] == mid for i in items):
            continue
        add(mid, nm, None, why)
    return items

def _call(item, deadline_ok=True):
    t0 = time.time()
    last = None
    for attempt in range(RETRIES + 1):
        try:
            data = item["fn"]()
            return {"status": "ok", "data": data, "ms": int((time.time() - t0) * 1000), "attempts": attempt + 1}
        except RETRYABLE as e:
            last = e
            if attempt < RETRIES:
                time.sleep(1.2 * (attempt + 1))
                continue
        except Exception as e:
            return {"status": "error", "error": f"{type(e).__name__}: {str(e)[:180]}",
                    "ms": int((time.time() - t0) * 1000), "attempts": attempt + 1}
    return {"status": "error", "error": str(last)[:180], "ms": int((time.time() - t0) * 1000),
            "attempts": RETRIES + 1}

def run(q, kind=None, on_event=None):
    """Execute the full plan. on_event(dict) is called for 'start', 'result' and 'done'."""
    q = normalize(q)
    if not q:
        raise FetchError("أدخل هدفاً للمسح")
    kind = kind if kind and kind != "auto" else detect(q)
    plan = build_plan(q, kind)
    t0 = time.time()
    if on_event:
        on_event({"type": "start", "target": q, "kind": kind, "total": len(plan),
                  "modules": [{"id": i["id"], "name": i["name"], "skipped": bool(i["skip"])} for i in plan]})
    results, errors, skipped = {}, {}, {}
    runnable = [i for i in plan if i["fn"]]
    for i in plan:
        if i["skip"] and not i["fn"]:
            skipped[i["id"]] = i["skip"]
            if on_event:
                on_event({"type": "result", "id": i["id"], "name": i["name"], "status": "skipped",
                          "reason": i["skip"], "ms": 0})
    done_ids = set(skipped)
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        futs = {}
        for i in runnable:
            futs[ex.submit(_call, i)] = i
        t_start = {f: time.time() for f in futs}
        pending = set(futs)
        while pending:
            finished, pending = cf.wait(pending, timeout=1.0,
                                        return_when=cf.FIRST_COMPLETED)
            for f in finished:
                item = futs[f]
                try:
                    r = f.result(timeout=1)
                except Exception as e:
                    r = {"status": "error", "error": str(e)[:160], "ms": 0, "attempts": 1}
                results[item["id"]] = r
                done_ids.add(item["id"])
                if r["status"] == "ok":
                    if on_event:
                        on_event({"type": "result", "id": item["id"], "name": item["name"], "status": "ok",
                                  "ms": r["ms"], "attempts": r.get("attempts", 1), "data": r["data"]})
                else:
                    errors[item["id"]] = r["error"]
                    if on_event:
                        on_event({"type": "result", "id": item["id"], "name": item["name"], "status": "error",
                                  "ms": r["ms"], "error": r["error"]})
            # hard cap for modules that hang
            for f in list(pending):
                if time.time() - t_start.get(f, t0) > MODULE_TIMEOUT:
                    item = futs[f]
                    results[item["id"]] = {"status": "timeout", "ms": MODULE_TIMEOUT * 1000,
                                           "error": "تجاوز الحد الزمني"}
                    errors[item["id"]] = "تجاوز الحد الزمني"
                    done_ids.add(item["id"])
                    pending.discard(f)
                    if on_event:
                        on_event({"type": "result", "id": item["id"], "name": item["name"],
                                  "status": "error", "ms": MODULE_TIMEOUT * 1000, "error": "تجاوز الحد الزمني"})
    # ---- automatic repair pass: retry anything that failed, once ----
    if errors:
        retry_items = [i for i in runnable if i["id"] in errors]
        for item in retry_items:
            r = _call(item)
            if r["status"] == "ok":
                errors.pop(item["id"], None)
                results[item["id"]] = r
                if on_event:
                    on_event({"type": "result", "id": item["id"], "name": item["name"], "status": "ok",
                              "ms": r["ms"], "attempts": r.get("attempts", 1) + 1, "data": r["data"],
                              "retried": True})
    summary = {"target": q, "kind": kind, "total_modules": len(plan), "ran": len(runnable),
               "ok": sum(1 for i in runnable if results.get(i["id"], {}).get("status") == "ok"),
               "failed": len(errors), "skipped": len(skipped), "ms": int((time.time() - t0) * 1000)}
    out = {"summary": summary, "results": {k: v.get("data") for k, v in results.items() if v.get("status") == "ok"},
           "errors": errors, "skipped": skipped}
    if on_event:
        on_event({"type": "done", **summary, "errors": errors, "skipped": skipped})
    return out
