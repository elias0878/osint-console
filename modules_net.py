"""Network / infrastructure modules: DNS, RDAP, subdomains, IP intel, TLS, HTTP, robots, archive, ports, urlscan, ADS-B."""
import json, re, socket, ssl, time, threading, ipaddress, concurrent.futures as cf
import urllib.parse
from urllib.parse import urlsplit, quote
from core import get_json, get_text, safe_fetch, FetchError, cache_get, cache_set, polite, UA, UA_BOT, NoRedirect

DOH = "https://dns.google/resolve"
RT = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA"}

def _doh(name, rtype, timeout=12):
    u = f"{DOH}?name={quote(name)}&type={rtype}"
    try:
        return get_json(u, timeout=timeout, ttl=180)
    except Exception:
        # fallback resolver (Cloudflare needs the JSON accept header)
        j = get_json(f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type={rtype}",
                     timeout=timeout, ttl=180, headers={"Accept": "application/dns-json"})
        for a in j.get("Answer", []) or []:
            if "type" in a and isinstance(a["type"], int):
                a["type"] = RT.get(a["type"], a["type"])
        return j

def dns_lookup(domain, types=None):
    domain = domain.strip().rstrip(".")
    if not re.match(r"^[a-zA-Z0-9._-]{1,253}$", domain):
        raise FetchError("اسم نطاق غير صالح")
    types = types or ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]
    out = {"domain": domain, "records": {}, "errors": {}}
    def one(t):
        try:
            j = _doh(domain, t)
            ans = []
            for a in j.get("Answer", []) or []:
                ans.append({"type": RT.get(a.get("type"), str(a.get("type"))), "ttl": a.get("TTL"),
                            "data": str(a.get("data", "")).strip('"')})
            return t, {"status": j.get("Status"), "answers": ans}
        except Exception as e:
            return t, {"error": str(e)[:120]}
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for t, res in ex.map(one, types):
            if "error" in res:
                out["errors"][t] = res["error"]
            else:
                out["records"][t] = res
    # reverse DNS for first A record
    ips = [a["data"] for a in out["records"].get("A", {}).get("answers", [])][:4]
    if ips:
        out["reverse_dns"] = {}
        def rev(ip):
            try:
                q = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
                j = _doh(q, "PTR")
                return ip, [a["data"] for a in j.get("Answer", []) or []]
            except Exception:
                return ip, []
        with cf.ThreadPoolExecutor(max_workers=4) as ex:
            for ip, names in ex.map(rev, ips):
                out["reverse_dns"][ip] = names
    # mail provider summary
    mx = [a["data"] for a in out["records"].get("MX", {}).get("answers", [])]
    if mx:
        out["mail_providers"] = sorted({_provider(m) for m in mx})
    return out

def _provider(mx):
    m = mx.lower()
    for k, v in [("google", "Google Workspace"), ("outlook", "Microsoft 365"), ("protection.outlook", "Microsoft 365"),
                 ("zoho", "Zoho"), ("yandex", "Yandex"), ("mail.ru", "Mail.ru"), ("proton", "Proton"),
                 ("cloudflare", "Cloudflare Email"), ("amazonses", "Amazon SES"), ("mimecast", "Mimecast"),
                 ("proofpoint", "Proofpoint"), ("barracuda", "Barracuda"), ("qq.com", "Tencent")]:
        if k in m:
            return v
    return "مزوّد آخر / خاص"

def rdap_lookup(target):
    target = target.strip()
    kind = "domain"
    try:
        ipaddress.ip_address(target)
        kind = "ip"
    except ValueError:
        if target.upper().startswith("AS") and target[2:].isdigit():
            kind = "autnum"
    url = f"https://rdap.org/{kind}/{quote(target)}"
    st, hd, raw, final = safe_fetch(url, timeout=20, headers={"Accept": "application/rdap+json"})
    if st == 404:
        return {"query": target, "found": False, "note": "لا يوجد سجل RDAP (نطاق غير مسجل أو TLD لا يدعم RDAP)"}
    if st >= 400 or not raw.strip():
        # fallback for .com/.net
        alt = f"https://rdap.verisign.com/com/v1/domain/{quote(target)}"
        st, hd, raw, final = safe_fetch(alt, timeout=20)
        if st >= 400:
            raise FetchError(f"RDAP غير متاح لهذا الهدف (HTTP {st})")
    j = json.loads(raw.decode("utf-8", "replace"))
    out = {"query": target, "found": True, "server": final, "handle": j.get("handle"),
           "ldhName": j.get("ldhName") or j.get("name"),
           "status": j.get("status") or [], "events": [], "nameservers": [], "entities": []}
    for e in j.get("events", []) or []:
        out["events"].append({"event": e.get("eventAction"), "date": e.get("eventDate")})
    for n in j.get("nameservers", []) or []:
        out["nameservers"].append(n.get("ldhName"))
    for ent in j.get("entities", []) or []:
        roles = ent.get("roles", [])
        name = None
        for v in ent.get("vcardArray", [[], []])[1] if ent.get("vcardArray") else []:
            if v and v[0] == "fn":
                name = v[3]
        emails = []
        for v in (ent.get("vcardArray", [[], []])[1] if ent.get("vcardArray") else []):
            if v and v[0] == "email":
                emails.append(v[3])
        out["entities"].append({"roles": roles, "handle": ent.get("handle"), "name": name, "email": emails})
    return out

def _ct_rows(domain, timeout=50):
    """Certificate-transparency rows. crt.sh first, certspotter as fallback (cached, shared)."""
    key = "ct:" + domain
    c = cache_get(key, 1800)
    if c is not None:
        return c
    last = None
    for attempt in range(2):
        try:
            rows = get_json(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", timeout=timeout)
            if isinstance(rows, list) and rows:
                cache_set(key, rows, 1800)
                return rows
        except Exception as e:
            last = e
            time.sleep(1.2 * (attempt + 1))
    # fallback: certspotter (independent CT source)
    try:
        j = get_json(f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}"
                     f"&include_subdomains=true&expand=dns_names", timeout=timeout)
        rows = []
        for r in j if isinstance(j, list) else []:
            rows.append({"issuer_name": r.get("issuer", {}).get("name", "") if isinstance(r.get("issuer"), dict) else "",
                         "name_value": "\n".join(r.get("dns_names", []) or []),
                         "not_before": r.get("not_before"), "not_after": r.get("not_after")})
        if rows:
            cache_set(key, rows, 1800)
            return rows
    except Exception as e:
        last = last or e
    if last:
        raise FetchError(f"مصدرا الشهادات غير متاحين الآن ({str(last)[:80]})")
    return []

def _ct_names(rows, domain):
    names = set()
    for row in rows:
        for n in str(row.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith("." + domain) or n == domain:
                names.add(n)
    return names

def subdomains(domain, limit=500):
    domain = domain.strip().lower().lstrip("*.")
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        raise FetchError("نطاق غير صالح")
    found, sources, errors = set(), {}, {}

    def crt():
        return _ct_names(_ct_rows(domain), domain)

    def htr():
        t = get_text(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}", timeout=25, ttl=1800)
        low = t.lower()
        if any(k in low for k in ("quota", "api count", "membership", "increase quota")):
            raise FetchError("حد مجاني مؤقت (Hackertarget)")
        if low.startswith("error") or "no records" in low:
            return set()
        return {ln.split(",")[0].strip().lower() for ln in t.splitlines()
                if "," in ln and ln.split(",")[0].strip().lower().endswith("." + domain)}

    def rapid():
        html = get_text(f"https://rapiddns.io/subdomain/{quote(domain)}?full=1", timeout=30, ttl=1800)
        names = set()
        for m in re.findall(r"<td>([a-zA-Z0-9_.\-]+\." + re.escape(domain) + r")</td>", html):
            names.add(m.strip().lower())
        if not names:
            raise FetchError("لا نتائج قابلة للقراءة من RapidDNS")
        return names

    def cspot():
        j = get_json(f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}&include_subdomains=true&expand=dns_names", timeout=30, ttl=1800)
        names = set()
        for row in j:
            for n in row.get("dns_names", []) or []:
                n = str(n).lower().lstrip("*.")
                if n.endswith("." + domain):
                    names.add(n)
        return names

    jobs = {"crt.sh": crt, "hackertarget": htr, "rapiddns": rapid, "certspotter": cspot}
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(fn): name for name, fn in jobs.items()}
        for f in cf.as_completed(futs, timeout=60):
            name = futs[f]
            try:
                r = f.result()
                sources[name] = len(r)
                found |= r
            except Exception as e:
                errors[name] = str(e)[:120]
    sub = sorted(found)[:limit]
    if not sub and errors and len(errors) == len(jobs):
        raise FetchError("كل مصادر النطاقات الفرعية غير متاحة الآن: " + "; ".join(sorted(errors))[:150])
    return {"domain": domain, "count": len(found), "returned": len(sub), "subdomains": sub,
            "sources": sources, "errors": errors}

_inflight = {}
_inflight_lock = threading.Lock()

def _feed_text(url, timeout=25, retries=2):
    """Fetch a plain-text feed with retries; transient failures shouldn't break a module."""
    last = None
    for i in range(retries + 1):
        try:
            return get_text(url, timeout=timeout)
        except Exception as e:
            last = e
            if i < retries:
                time.sleep(0.8 * (i + 1))
    raise last

def _single_flight(key, fn):
    """Concurrent callers share one fetch instead of hammering the provider."""
    with _inflight_lock:
        ev = _inflight.get(key)
        owner = ev is None
        if owner:
            ev = threading.Event()
            _inflight[key] = ev
    if not owner:
        ev.wait(timeout=45)
        return cache_get(key, 3600)
    try:
        val = fn()
        cache_set(key, val, 3600)
        return val
    finally:
        with _inflight_lock:
            _inflight.pop(key, None)
        ev.set()

TOR_SOURCES = ["https://check.torproject.org/torbulkexitlist",
               "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"]

def _tor_exits():
    c = cache_get("torexit", 3600)
    if c:
        return c
    def fetch_all():
        for url in TOR_SOURCES:
            try:
                t = _feed_text(url, timeout=25, retries=1)
                ips = {l.strip() for l in t.splitlines() if re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())}
                if len(ips) > 100:
                    return ips
            except Exception:
                continue
        return set()
    return _single_flight("torexit", fetch_all) or set()

def _spamhaus_drop():
    c = cache_get("drop", 3600)
    if c:
        return c
    def build():
        t = _feed_text("https://www.spamhaus.org/drop/drop.txt", timeout=30)
        out = []
        for line in t.splitlines():
            part = line.split(";")[0].strip()
            if "/" in part:
                try:
                    out.append(ipaddress.ip_network(part, strict=False))
                except ValueError:
                    pass
        return out
    return _single_flight("spamhaus_drop", build) or []
    t = ""
    nets = []
    for line in t.splitlines():
        line = line.split(";")[0].strip()
        if "/" in line:
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    cache_set("drop", nets, 3600)
    return nets

def ip_intel(ip):
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise FetchError("عنوان IP غير صالح")
    out = {"ip": ip, "version": addr.version, "private": addr.is_private, "reserved": addr.is_reserved}
    if addr.is_private:
        return out

    def geo():
        try:
            return "geo", get_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query", timeout=12, ttl=900)
        except Exception:
            try:
                j = get_json(f"https://ipapi.co/{ip}/json/", timeout=15, ttl=900)
                return "geo", {"status": "success", "country": j.get("country_name"), "countryCode": j.get("country_code"),
                               "regionName": j.get("region"), "city": j.get("city"), "lat": j.get("latitude"),
                               "lon": j.get("longitude"), "timezone": j.get("timezone"), "isp": j.get("org"),
                               "org": j.get("org"), "as": j.get("asn"), "reverse": j.get("hostname"),
                               "proxy": None, "hosting": None, "source": "ipapi.co (احتياطي)"}
            except Exception as e:
                return "geo_error", str(e)[:120]

    def asn():
        try:
            return "asn_info", get_json(f"https://ipinfo.io/{ip}/json", timeout=12, ttl=900)
        except Exception as e:
            return "asn_error", str(e)[:120]

    def idb():
        try:
            return "shodan_internetdb", get_json(f"https://internetdb.shodan.io/{ip}", timeout=12, ttl=1800)
        except Exception as e:
            return "internetdb_error", str(e)[:120]

    def rep():
        try:
            return "reputation", get_json(f"http://api.stopforumspam.com/api?ip={ip}&json", timeout=12, ttl=1800)
        except Exception as e:
            return "reputation_error", str(e)[:120]

    def tor():
        try:
            return "tor_exit", ip in _tor_exits()
        except Exception:
            return "tor_exit", None

    def drop():
        try:
            nets = _spamhaus_drop()
            return "spamhaus_drop", any(addr in n for n in nets if n.version == addr.version)
        except Exception:
            return "spamhaus_drop", None

    def ptr():
        try:
            return "ptr", socket.gethostbyaddr(ip)[0]
        except Exception:
            return "ptr", None

    with cf.ThreadPoolExecutor(max_workers=7) as ex:
        for k, v in ex.map(lambda f: f(), [geo, asn, idb, rep, tor, drop, ptr]):
            out[k] = v
    return out

def _asn1(b, i=0):
    """Minimal DER reader -> (tag, value_start, value_len, next_index)."""
    tag = b[i]; i += 1
    ln = b[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big"); i += n
    return tag, i, ln, i + ln

def _asn1_children(b, i, end):
    out = []
    while i < end:
        tag, vs, ln, nx = _asn1(b, i)
        out.append((tag, b[vs:vs + ln]))
        i = nx
    return out

def _parse_name(seq):
    """X.509 Name -> dict. Name=SEQ of RDN; RDN=SET of ATV; ATV=SEQ{OID,value}."""
    out = {}
    oidmap = {"2.5.4.3": "commonName", "2.5.4.6": "countryName", "2.5.4.7": "locality",
              "2.5.4.8": "state", "2.5.4.10": "organizationName", "2.5.4.11": "organizationalUnit",
              "1.2.840.113549.1.9.1": "emailAddress", "2.5.4.5": "serialNumber"}
    try:
        for _set_tag, set_val in _asn1_children(seq, 0, len(seq)):        # SET
            for _seq_tag, atv in _asn1_children(set_val, 0, len(set_val)):  # SEQUENCE
                parts = _asn1_children(atv, 0, len(atv))
                if len(parts) < 2:
                    continue
                key = oidmap.get(_oid_str(parts[0][1]), _oid_str(parts[0][1]))
                out[key] = parts[1][1].decode("utf-8", "replace")
    except Exception:
        pass
    return out

def _oid_str(b):
    if not b:
        return ""
    first = b[0]
    parts = [first // 40, first % 40]
    n = 0
    for x in b[1:]:
        n = (n << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(n); n = 0
    return ".".join(str(p) for p in parts)

def _parse_cert_der(der):
    """Extract subject, issuer, validity, serial and SANs from a DER certificate."""
    out = {}
    try:
        _, vs, ln, _ = _asn1(der, 0)
        top = _asn1_children(der, vs, vs + ln)
        tbs = top[0][1]
        f = _asn1_children(tbs, 0, len(tbs))
        idx = 0
        if f and f[0][0] == 0xA0:
            out["version"] = (f[0][1][0] & 0x07) + 1 if f[0][1] else None
            idx = 1
        out["serial"] = f[idx][1].hex() if idx < len(f) else None
        idx += 2
        if idx < len(f):
            out["issuer"] = _parse_name(f[idx][1]); idx += 1
        if idx < len(f):
            times = _asn1_children(f[idx][1], 0, len(f[idx][1]))
            def t(raw):
                st = raw.decode("ascii", "replace")
                if len(st) == 13:
                    y = int(st[:2]); y += 2000 if y < 50 else 1900
                    st = f"{y}{st[2:]}"
                return f"{st[0:4]}-{st[4:6]}-{st[6:8]}T{st[8:10]}:{st[10:12]}:{st[12:14]}Z" if len(st) >= 14 else st
            out["not_before"] = t(times[0][1]) if times else None
            out["not_after"] = t(times[1][1]) if len(times) > 1 else None
            idx += 1
        if idx < len(f):
            out["subject"] = _parse_name(f[idx][1]); idx += 1
        sans = []
        for tag, val in f:
            if tag != 0xA3:
                continue
            _t, evs, eln, _n = _asn1(val, 0)          # unwrap the inner SEQUENCE
            ext_list = val[evs:evs + eln]
            for _et, ext in _asn1_children(ext_list, 0, len(ext_list)):
                e = _asn1_children(ext, 0, len(ext))
                if len(e) < 2:
                    continue
                if _oid_str(e[0][1]) == "2.5.29.17":
                    inner = e[-1][1]                   # OCTET STRING payload
                    _it, ivs, iln, _in = _asn1(inner, 0)
                    for gtag, gval in _asn1_children(inner, ivs, ivs + iln):
                        if gtag == 0x82:               # dNSName
                            sans.append(gval.decode("ascii", "replace"))
                        elif gtag == 0x87:             # iPAddress
                            sans.append(".".join(str(b) for b in gval))
        if sans:
            out["sans"] = sans[:100]
    except Exception as e:
        out["parse_error"] = str(e)[:120]
    return out

def tls_info(host, port=443):
    host = host.strip().lower().replace("https://", "").split("/")[0]
    if ":" in host:
        host, p = host.split(":", 1)
        if p.isdigit():
            port = int(p)
    out = {"host": host, "port": port}
    t0 = time.time()
    der = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["tls_version"] = ss.version()
                out["cipher"] = ss.cipher()[0] if ss.cipher() else None
                out["handshake_ms"] = int((time.time() - t0) * 1000)
                der = ss.getpeercert(binary_form=True)
                cert = ss.getpeercert() or {}
                out["valid_chain"] = True
    except ssl.SSLCertVerificationError as e:
        out["valid_chain"] = False
        out["valid_error"] = (e.verify_message or str(e))[:150]
    except Exception as e:
        # last resort: insecure handshake to still show metadata
        if "CERTIFICATE" not in str(e).upper() and "SSL" not in str(e).upper():
            raise FetchError(f"فشل اتصال TLS: {str(e)[:150]}")
        out["valid_chain"] = False
        out["valid_error"] = str(e)[:150]
    if der is None:
        ictx = ssl.create_default_context(); ictx.check_hostname = False; ictx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=12) as sock:
                with ictx.wrap_socket(sock, server_hostname=host) as ss:
                    out.setdefault("tls_version", ss.version())
                    out.setdefault("cipher", ss.cipher()[0] if ss.cipher() else None)
                    out.setdefault("handshake_ms", int((time.time() - t0) * 1000))
                    der = ss.getpeercert(binary_form=True)
        except Exception as e:
            raise FetchError(f"فشل اتصال TLS: {str(e)[:150]}")
    parsed = _parse_cert_der(der) if der else {}
    out["subject"] = parsed.get("subject", {})
    out["issuer"] = parsed.get("issuer", {})
    out["not_before"] = parsed.get("not_before")
    out["not_after"] = parsed.get("not_after")
    out["sans"] = parsed.get("sans", [])
    out["serial"] = parsed.get("serial")
    out["sha256_fingerprint"] = __import__("hashlib").sha256(der).hexdigest() if der else None
    if parsed.get("not_after"):
        try:
            import datetime as _dt
            exp = _dt.datetime.strptime(parsed["not_after"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
            out["days_until_expiry"] = (exp - _dt.datetime.now(_dt.timezone.utc)).days
        except Exception:
            pass
    return out

SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
               "x-content-type-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy"]
TECH = [("cloudflare", "Cloudflare"), ("nginx", "Nginx"), ("apache", "Apache"), ("wordpress", "WordPress"),
        ("wp-content", "WordPress"), ("shopify", "Shopify"), ("react", "React"), ("next.js", "_next", ),
        ("__next", "Next.js"), ("vue", "Vue.js"), ("jquery", "jQuery"), ("bootstrap", "Bootstrap"),
        ("google-analytics", "Google Analytics"), ("gtag(", "Google Tag"), ("googletagmanager", "GTM"),
        ("cloudfront", "AWS CloudFront"), ("amazonaws", "AWS"), ("vercel", "Vercel"), ("netlify", "Netlify"),
        ("drupal", "Drupal"), ("joomla", "Joomla"), ("laravel", "Laravel"), ("django", "Django"),
        ("asp.net", "ASP.NET"), ("php", "PHP"), ("magento", "Magento"), ("wix.com", "Wix"),
        ("squarespace", "Squarespace"), ("hubspot", "HubSpot"), ("intercom", "Intercom"), ("sentry", "Sentry"),
        ("recaptcha", "reCAPTCHA"), ("hcaptcha", "hCaptcha"), ("stripe", "Stripe"), ("facebook pixel", "Meta Pixel")]

def http_probe(url):
    if not re.match(r"^https?://", url):
        url = "https://" + url
    # walk the redirect chain manually so it can be reported
    chain, cur = [], url
    for _ in range(8):
        try:
            st0, hd0, raw0, _f = safe_fetch(cur, timeout=15, max_bytes=2000, allow_redirects=False)
        except Exception:
            break
        loc = hd0.get("Location")
        chain.append({"url": cur, "status": st0})
        if st0 in (301, 302, 303, 307, 308) and loc:
            cur = urllib.parse.urljoin(cur, loc)
            continue
        break
    st, hd, raw, final = safe_fetch(url, timeout=20, max_bytes=800000)
    html = raw.decode("utf-8", "replace")
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    low = html.lower()
    tech = sorted({name for key, name in TECH if key in low or key in (json.dumps(hd).lower())})
    return {"url": url, "final_url": final, "status": st, "server": hd.get("Server"),
            "powered_by": hd.get("X-Powered-By"), "content_type": hd.get("Content-Type"),
            "size_bytes": len(raw), "title": re.sub(r"\s+", " ", title.group(1)).strip()[:200] if title else None,
            "headers": {k: v for k, v in hd.items() if k.lower() not in ("set-cookie",)},
            "cookies": hd.get("Set-Cookie"),
            "security_headers": {h: (hd.get(h) is not None) for h in SEC_HEADERS},
            "security_score": f"{sum(1 for h in SEC_HEADERS if hd.get(h))}/{len(SEC_HEADERS)}",
            "technologies": tech,
            "redirected": final.rstrip("/") != url.rstrip("/"),
            "redirect_chain": chain if len(chain) > 1 else [],
            "redirect_count": max(0, len(chain) - 1)}

def robots(url):
    if not re.match(r"^https?://", url):
        url = "https://" + url
    base = "{0.scheme}://{0.netloc}".format(urlsplit(url))
    out = {"base": base, "robots": None, "sitemaps": [], "security_txt": None, "humans": None}
    try:
        st, hd, raw, _ = safe_fetch(base + "/robots.txt", timeout=12, max_bytes=300000)
        if st == 200:
            txt = raw.decode("utf-8", "replace")
            out["robots"] = {"status": 200, "length": len(txt), "disallow": [l.strip() for l in txt.splitlines() if re.match(r"(?i)^disallow", l.strip())][:80],
                             "allow": [l.strip() for l in txt.splitlines() if re.match(r"(?i)^allow", l.strip())][:80],
                             "raw_preview": txt[:1500]}
            out["sitemaps"] = re.findall(r"(?i)sitemap:\s*(\S+)", txt)
        else:
            out["robots"] = {"status": st}
    except Exception as e:
        out["robots_error"] = str(e)[:120]
    for name, path in (("security_txt", "/.well-known/security.txt"), ("humans", "/humans.txt")):
        try:
            st, hd, raw, _ = safe_fetch(base + path, timeout=10, max_bytes=60000)
            if st == 200:
                out[name] = raw.decode("utf-8", "replace")[:1200]
        except Exception:
            pass
    return out

def wayback(url, limit=30):
    if not re.match(r"^https?://", url):
        url = "https://" + url
    out = {"url": url}
    try:
        j = get_json("https://archive.org/wayback/available?url=" + quote(url, safe=""), timeout=20, ttl=600)
        out["closest"] = (j.get("archived_snapshots") or {}).get("closest")
    except Exception as e:
        out["available_error"] = str(e)[:120]
    try:
        t = get_text(f"http://web.archive.org/cdx/search/cdx?url={quote(url, safe='')}&output=json&limit={limit}&collapse=digest&fl=timestamp,original,statuscode,mimetype,digest", timeout=35, ttl=600)
        rows = json.loads(t) if t.strip().startswith("[") else []
        out["snapshots"] = [dict(zip(rows[0], r)) for r in rows[1:]] if rows else []
        out["snapshot_count_returned"] = max(0, len(rows) - 1)
    except Exception as e:
        out["cdx_error"] = str(e)[:120]
    return out

COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
                143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-sub", 993: "IMAPS",
                995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB"}

def port_check(host, ports=None, timeout=2.0):
    host = host.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    ports = ports or list(COMMON_PORTS)
    ports = [p for p in ports if 0 < p < 65536][:60]
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        raise FetchError(f"تعذر تحويل الاسم إلى IP: {e}")

    def probe(p):
        s = socket.socket()
        s.settimeout(timeout)
        t0 = time.time()
        try:
            return p, s.connect_ex((ip, p)) == 0, (time.time() - t0) * 1000
        except Exception:
            return p, False, None
        finally:
            s.close()

    # sanity check: these ports must be closed on a normal host. If they "open",
    # egress passes through an intercepting proxy and results would be false.
    control = [probe(1), probe(65534)]
    if all(ok for _, ok, _ in control):
        return {"host": host, "ip": ip, "checked": 0, "open_count": 0, "open_ports": [],
                "proxy_intercepted": True, "all_results": [],
                "warning": "شبكة هذه البيئة تمر عبر وسيط (proxy) يفتح كل اتصالات TCP — لذلك فحص المنافذ غير موثوق هنا وأُوقف لتجنّب نتائج كاذبة. شغّل المنصة على جهازك/خادمك ليعمل الفحص بشكل صحيح."}

    with cf.ThreadPoolExecutor(max_workers=25) as ex:
        res = list(ex.map(probe, ports))
    results = [{"port": p, "service": COMMON_PORTS.get(p, ""), "open": ok,
                "latency_ms": int(ms) if (ok and ms is not None) else None} for p, ok, ms in res]
    opened = [r for r in results if r["open"]]
    return {"host": host, "ip": ip, "checked": len(ports), "open_count": len(opened),
            "open_ports": opened, "all_results": results, "proxy_intercepted": False,
            "note": "فحص TCP connect لغرض التحقق التشغيلي فقط — استخدمه على أهداف تملكها أو تملك إذناً بها."}

def urlscan_search(q):
    q = q.strip()
    if not re.match(r"^[\w:\.\-\*/ ]{1,120}$", q):
        raise FetchError("استعلام غير صالح")
    j = get_json(f"https://urlscan.io/api/v1/search/?q={quote(q)}&size=20", timeout=20, ttl=300)
    res = []
    for r in j.get("results", [])[:20]:
        res.append({"url": r.get("page", {}).get("url"), "domain": r.get("page", {}).get("domain"),
                    "ip": r.get("page", {}).get("ip"), "asn": r.get("page", {}).get("asnname"),
                    "country": r.get("page", {}).get("country"), "server": r.get("page", {}).get("server"),
                    "scan_date": r.get("task", {}).get("time"), "result": r.get("result"),
                    "screenshot": r.get("screenshot")})
    return {"query": q, "total": j.get("total"), "results": res}

def flight_nearby(lat, lon, dist_km=40):
    try:
        lat, lon, dist_km = float(lat), float(lon), min(float(dist_km), 250)
    except ValueError:
        raise FetchError("إحداثيات غير صالحة")
    j = get_json(f"https://opendata.adsb.fi/api/v2/lat/{lat}/lon/{lon}/dist/{int(dist_km)}", timeout=20, ttl=30)
    ac = []
    for a in (j.get("aircraft") or [])[:120]:
        ac.append({"callsign": (a.get("flight") or "").strip(), "icao24": a.get("hex"),
                   "registration": a.get("r"), "type": a.get("t"), "alt_baro": a.get("alt_baro"),
                   "gs": a.get("gs"), "track": a.get("track"), "lat": a.get("lat"), "lon": a.get("lon"),
                   "squawk": a.get("squawk"), "category": a.get("category")})
    return {"center": {"lat": lat, "lon": lon}, "radius_km": dist_km, "count": len(ac), "aircraft": ac}

def geoip_self():
    try:
        return get_json("https://ipinfo.io/json", timeout=12, ttl=300)
    except Exception as e:
        raise FetchError(str(e))
