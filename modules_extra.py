"""Extra free, key-less sources: raw WHOIS (port 43), Wikipedia, reverse-IP, MAC/OUI,
threat-feed checks, news (GDELT) and certificate issuers."""
import re, socket, json, time, ipaddress, concurrent.futures as cf
from urllib.parse import quote
from core import get_json, get_text, safe_fetch, FetchError, cache_get, cache_set

TLD_WHOIS = {"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com", "org": "whois.pir.org",
             "io": "whois.nic.io", "co": "whois.nic.co", "ai": "whois.nic.ai", "dev": "whois.nic.google",
             "app": "whois.nic.google", "info": "whois.afilias.net", "biz": "whois.biz",
             "me": "whois.nic.me", "xyz": "whois.nic.xyz", "de": "whois.denic.de", "uk": "whois.nic.uk",
             "fr": "whois.nic.fr", "nl": "whois.sidn.nl", "ru": "whois.tcinet.ru", "tr": "whois.nic.tr",
             "sa": "whois.nic.net.sa", "ae": "whois.aeda.net.ae", "eg": "whois.ripe.net",
             "ir": "whois.nic.ir", "cn": "whois.cnnic.cn", "jp": "whois.jprs.jp", "in": "whois.registry.in",
             "br": "whois.registro.br", "au": "whois.auda.org.au", "ca": "whois.cira.ca"}

def _whois_raw(server, query, timeout=15, max_bytes=400000):
    s = socket.create_connection((server, 43), timeout=timeout)
    try:
        s.sendall((query + "\r\n").encode())
        buf = b""
        while len(buf) < max_bytes:
            try:
                d = s.recv(8192)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
        return buf.decode("utf-8", "replace")
    finally:
        s.close()

def _refer(text):
    m = re.findall(r"(?im)^(?:refer|whois|referralserver|Registry WHOIS):\s*(\S+)", text)
    return m[0].strip().lower() if m else None

def whois_lookup(q):
    q = q.strip().lower()
    out = {"query": q, "chain": []}
    try:
        ipaddress.ip_address(q)
        is_ip = True
    except ValueError:
        is_ip = False
    # step 1: IANA for the TLD (domains) or the address space (IPs)
    target = None
    if is_ip:
        try:
            iana = _whois_raw("whois.iana.org", q)
            out["chain"].append({"server": "whois.iana.org", "bytes": len(iana)})
            target = _refer(iana)
        except Exception as e:
            out["iana_error"] = str(e)[:120]
    else:
        tld = q.rsplit(".", 1)[-1]
        if not re.match(r"^[a-z]{2,12}$", tld):
            raise FetchError("نطاق غير صالح")
        try:
            iana = _whois_raw("whois.iana.org", tld)
            out["chain"].append({"server": "whois.iana.org", "bytes": len(iana)})
            target = _refer(iana)
        except Exception as e:
            out["iana_error"] = str(e)[:120]
        target = target or TLD_WHOIS.get(tld)
    if not target:
        raise FetchError("لم يُعرف خادم WHOIS لهذا الهدف — جرّب RDAP")
    out["whois_server"] = target
    try:
        raw = _whois_raw(target, q)
    except Exception as e:
        raise FetchError(f"تعذر الاتصال بخادم WHOIS ({target}): {str(e)[:100]}")
    out["chain"].append({"server": target, "bytes": len(raw)})
    if re.search(r"(?i)no match|not found|no entries found|no data found|NOT FOUND", raw):
        out["found"] = False
        out["raw_excerpt"] = raw[:600]
        out["note"] = "لا يوجد سجل WHOIS لهذا الهدف"
        return out
    out["found"] = True
    out["raw"] = raw[:20000]
    fields = {}
    for key, pats in {
        "registrar": [r"(?im)^\s*registrar:\s*(.+)$", r"(?im)^\s*Registrar Name:\s*(.+)$"],
        "created": [r"(?im)^\s*(?:creation date|created|created on|registered on|domain registration date):\s*(.+)$"],
        "expires": [r"(?im)^\s*(?:registry expiry date|expiry date|expiration date|registrar registration expiration date|paid-till):\s*(.+)$"],
        "updated": [r"(?im)^\s*(?:updated date|last updated|last-modified|changed):\s*(.+)$"],
        "status": [r"(?im)^\s*(?:domain status|status):\s*(.+)$"],
        "nameservers": [r"(?im)^\s*(?:name server|nserver|nameserver):\s*(.+)$"],
        "org": [r"(?im)^\s*(?:registrant organization|org-name|orgname|organisation):\s*(.+)$"],
        "country": [r"(?im)^\s*(?:registrant country|country):\s*(.+)$"],
        "netname": [r"(?im)^\s*netname:\s*(.+)$"],
        "abuse": [r"(?im)^\s*(?:abuse-mailbox|orgabuseemail|abuse-mailbox):\s*(\S+@\S+)$"],
    }.items():
        vals = []
        for p in pats:
            vals += [v.strip() for v in re.findall(p, raw)]
        if vals:
            fields[key] = vals[:8] if key in ("status", "nameservers") else vals[0]
    out["parsed"] = fields
    return out

def wikipedia_lookup(q, lang="ar"):
    q = q.strip()
    out = {"query": q, "lang": lang}
    try:
        j = get_json(f"https://{lang}.wikipedia.org/api/rest_v1/page/summary/{quote(q)}", timeout=15, ttl=3600)
        out["title"] = j.get("title")
        out["extract"] = (j.get("extract") or "")[:1500]
        out["url"] = (j.get("content_urls", {}).get("desktop", {}) or {}).get("page")
        out["thumbnail"] = (j.get("thumbnail") or {}).get("source")
        out["type"] = j.get("type")
    except Exception:
        j = get_json(f"https://{lang}.wikipedia.org/w/api.php?action=query&list=search&srsearch={quote(q)}&format=json&srlimit=8", timeout=15, ttl=1800)
        hits = j.get("query", {}).get("search", [])
        out["search_results"] = [{"title": h.get("title"), "snippet": re.sub(r"<[^>]+>", "", h.get("snippet", ""))[:200],
                                  "url": f"https://{lang}.wikipedia.org/wiki/{quote(h.get('title','').replace(' ','_'))}"} for h in hits]
        if not hits:
            out["note"] = "لا نتائج"
    try:
        j2 = get_json(f"https://{lang}.wikipedia.org/w/api.php?action=query&prop=extracts&exintro&explaintext&titles={quote(q)}&format=json&redirects=1", timeout=15, ttl=3600)
        pages = (j2.get("query", {}).get("pages") or {})
        for pid, p in pages.items():
            if pid != "-1" and p.get("extract"):
                out.setdefault("extract", p["extract"][:1500])
                out.setdefault("title", p.get("title"))
    except Exception:
        pass
    out["links"] = {"ar": f"https://ar.wikipedia.org/wiki/{quote(q)}",
                    "en": f"https://en.wikipedia.org/wiki/{quote(q)}",
                    "wikidata": f"https://www.wikidata.org/w/index.php?search={quote(q)}"}
    return out

def reverse_ip(ip):
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise FetchError("عنوان IP غير صالح")
    t = get_text(f"https://api.hackertarget.com/reverseiplookup/?q={quote(ip)}", timeout=30, ttl=3600)
    low = t.lower()
    if "quota" in low or "api count exceeded" in low or "increase quota" in low or "membership" in low:
        return {"ip": ip, "count": 0, "domains": [], "rate_limited": True,
                "note": "تجاوز الحد المجاني للمزوّد (Hackertarget) مؤقتاً — أعد المحاولة بعد قليل أو استخدم المصادر الأخرى."}
    if low.startswith("error") or ("error" in low and "no dns" not in low):
        raise FetchError(t.strip()[:130])
    if "no dns" in low or "no record" in low or "no results" in low:
        return {"ip": ip, "count": 0, "domains": [], "note": "لا نطاقات مسجّلة على هذا العنوان (حسب Hackertarget)"}
    doms = sorted({d.strip().lower() for d in re.split(r"[\r\n]+", t) if d.strip() and "." in d})
    return {"ip": ip, "count": len(doms), "domains": doms[:300],
            "source": "hackertarget.com (مجاني، بلا مفتاح)"}

def oui_lookup(mac):
    m = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(m) < 6:
        raise FetchError("أدخل عنوان MAC مثل 00:1A:2B:3C:4D:5E")
    oui = m[:6]
    out = {"mac": mac, "oui": ":".join(oui[i:i + 2] for i in range(0, 6, 2)),
           "locally_administered": bool(int(oui[:2], 16) & 0x02),
           "multicast": bool(int(oui[:2], 16) & 0x01)}
    out["vendor"] = None
    try:
        t = get_text(f"https://api.macvendors.com/{out['oui']}", timeout=12, ttl=86400)
        out["vendor"] = t.strip()[:200]
        out["vendor_source"] = "macvendors.com"
    except Exception:
        pass
    if not out.get("vendor"):
        try:
            j = get_json(f"https://api.maclookup.app/v2/macs/{out['oui']}", timeout=12, ttl=86400)
            if j.get("found"):
                out["vendor"] = j.get("company")
                out["vendor_source"] = "maclookup.app"
                out["address"] = j.get("address")
                out["country"] = j.get("country")
        except Exception as e:
            out["error"] = str(e)[:100]
    if not out.get("vendor"):
        out["note"] = "المورّد غير مسجّل في قواعد OUI المتاحة"
    out["links"] = {"Wireshark OUI": f"https://www.wireshark.org/tools/oui-lookup.html",
                    "maclookup": f"https://maclookup.app/search/result?q={out['oui']}"}
    return out

def _feed(url, ttl=3600):
    c = cache_get("feed:" + url, ttl)
    if c:
        return c
    t = get_text(url, timeout=30)
    lines = [l.strip() for l in t.splitlines() if l.strip() and not l.startswith("#") and not l.startswith(";")]
    cache_set("feed:" + url, lines, ttl)
    return lines

def threat_check(target):
    target = target.strip()
    out = {"target": target, "hits": {}, "sources_checked": 0, "note": "فحص مقابل قوائم سمعة مجانية محدودة (ليست حكماً نهائياً)."}
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        addr = ipaddress.ip_address(target)

        def c_tor():
            return "Tor exit node", target in set(_feed("https://check.torproject.org/torbulkexitlist"))

        def c_drop():
            nets = []
            for l in _feed("https://www.spamhaus.org/drop/drop.txt"):
                part = l.split(";")[0].strip()
                try:
                    nets.append(ipaddress.ip_network(part, strict=False))
                except Exception:
                    pass
            return "Spamhaus DROP", any(addr in n for n in nets if n.version == addr.version)

        def c_feodo():
            ips = {l.split(",")[0].strip() for l in _feed("https://feodotracker.abuse.ch/downloads/ipblocklist.txt") if l.count(".") == 3}
            return "Feodo (C2 botnets)", target in ips

        def c_bl():
            return "blocklist.de", target in set(_feed("https://lists.blocklist.de/lists/all.txt"))

        def c_sfs():
            r = get_json(f"http://api.stopforumspam.com/api?ip={target}&json", timeout=15, ttl=1800)
            return "StopForumSpam (spam)", bool((r.get("ip") or {}).get("appears"))

        checks = {"Tor exit node": c_tor, "Spamhaus DROP": c_drop, "Feodo (C2 botnets)": c_feodo,
                  "blocklist.de": c_bl, "StopForumSpam (spam)": c_sfs}
        import concurrent.futures as _cf
        with _cf.ThreadPoolExecutor(max_workers=5) as ex:
            futs = {ex.submit(fn): k for k, fn in checks.items()}
            for f in _cf.as_completed(futs, timeout=45):
                k = futs[f]
                try:
                    name, val = f.result()
                    out["hits"][name] = val
                    out["sources_checked"] += 1
                except Exception as e:
                    out.setdefault("errors", {})[k] = str(e)[:80]
    else:
        try:
            r = get_json(f"http://api.stopforumspam.com/api?domain={quote(target)}&json", timeout=15, ttl=1800)
            out["hits"]["StopForumSpam (spam)"] = bool((r.get("domain") or {}).get("appears"))
            out["sources_checked"] += 1
        except Exception:
            pass
    out["listed_count"] = sum(1 for v in out["hits"].values() if v)
    out["verdict"] = ("مُدرج في قوائم سمعة" if out["listed_count"] else
                      "غير مُدرج في المصادر المفحوصة" if out["sources_checked"] else "تعذر الفحص")
    return out

def _gnews_rss(q, limit=25):
    """Google News RSS — free, key-less fallback when GDELT throttles or is unreachable."""
    rss = "https://news.google.com/rss/search?q=" + quote(q) + "&hl=ar&gl=SA&ceid=SA:ar"
    st, hd, raw, _ = safe_fetch(rss, timeout=12, max_bytes=900_000)
    xml = raw.decode("utf-8", "replace")
    items = []
    for m in list(re.finditer(r"<item>(.*?)</item>", xml, re.S))[:limit]:
        block = m.group(1)
        t = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", block, re.S)
        u = re.search(r"<link>(.*?)</link>", block, re.S)
        d = re.search(r"<pubDate>(.*?)</pubDate>", block, re.S)
        title = (t.group(1) if t else "").strip()
        link = (u.group(1) if u else "").strip()
        if title:
            items.append({"title": title, "url": link, "source": "Google News RSS",
                          "seendate": (d.group(1) if d else None)})
    return items


def news_search(q, timespan="7d"):
    q = q.strip()
    if not q:
        raise FetchError("أدخل كلمة بحث")
    out = {"query": q, "timespan": timespan, "articles": []}
    url = ("https://api.gdeltproject.org/api/v2/doc/doc?query=" + quote(q) +
           f"&mode=artlist&maxrecords=25&timespan={timespan}&format=json&sort=datedesc")
    ck = "news2:" + url
    cached = cache_get(ck, 600)
    if cached is not None:
        cached["cached"] = True
        return cached

    last_err = None
    throttled = False
    try:                                            # single short attempt: fail fast to the fallback
        st, hd, raw, _ = safe_fetch(url, timeout=7, max_bytes=1_500_000)
        if st == 429:
            throttled = True
        else:
            j = json.loads(raw.decode("utf-8", "replace"))
            if j.get("status") == "error":          # GDELT reports throttling in the body too
                throttled = True
            else:
                for a in (j.get("articles") or [])[:25]:
                    out["articles"].append({"title": a.get("title"), "url": a.get("url"),
                                            "domain": a.get("domain"), "language": a.get("language"),
                                            "country": a.get("sourcecountry"), "seendate": a.get("seendate")})
                out["count"] = len(out["articles"])
                if not out["articles"]:
                    out["note"] = "لا مقالات مطابقة في المدة المحددة (جرّب كلمة أعم أو timespan=30d)."
                cache_set(ck, out, 600)
    except Exception as e:
        last_err = e

    if "count" not in out:                       # GDELT unavailable -> independent fallback
        try:
            items = _gnews_rss(q)
            if items:
                out["articles"] = items
                out["count"] = len(items)
                why = "يتجاوز حدّ الطلبات" if throttled else f"غير متاح ({str(last_err)[:50]})"
                out["note"] = f"GDELT {why} — النتائج أدناه من Google News RSS (مصدر بديل مستقل)."
            else:
                out["note"] = "تعذر جلب الأخبار من GDELT ومن Google News الآن — جرّب لاحقاً."
        except Exception as e2:
            out["note"] = f"تعذر جلب الأخبار: {str(last_err or e2)[:100]}"
        cache_set(ck, out, 120)

    out["links"] = {"Google News": f"https://news.google.com/search?q={quote(q)}",
                    "GDELT TV": f"https://tv.gdeltproject.org/?query={quote(q)}"}
    return out


def cert_issuers(domain):
    domain = domain.strip().lower()
    from modules_net import _ct_rows, _ct_names
    rows = _ct_rows(domain)
    by_issuer, names = {}, set()
    for row in rows:
        iss = row.get("issuer_name") or ""
        cn = re.search(r"CN=([^,]+)", iss)
        key = (cn.group(1) if cn else iss)[:80]
        by_issuer[key] = by_issuer.get(key, 0) + 1
        names.add(row.get("name_value", ""))
    uniq = _ct_names(rows, domain)
    return {"domain": domain, "total_certs": len(rows),
            "issuers": {k: v for k, v in sorted(by_issuer.items(), key=lambda x: -x[1])[:15]},
            "unique_names": len(uniq), "sample_names": sorted(uniq)[:80],
            "source": "crt.sh (مخزّن مؤقتاً ومشترك مع وحدة النطاقات الفرعية)"}
