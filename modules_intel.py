"""Intel modules: CVE, crypto, geo, company, file analysis, IOC extraction, catalog."""
import json, re, math, hashlib, base64, struct, time, concurrent.futures as cf
from urllib.parse import quote
from core import get_json, get_text, safe_fetch, FetchError, cache_get, cache_set

# ---------------------------------------------------------------- CVE
def cve_lookup(q):
    q = q.strip()
    out = {"query": q, "results": []}
    if re.match(r"(?i)^CVE-\d{4}-\d{4,7}$", q):
        try:
            j = get_json(f"https://cve.circl.lu/api/cve/{q.upper()}", timeout=20, ttl=900)
            if j and j.get("cveMetadata"):
                c = j["cveMetadata"]; a = (j.get("containers") or {}).get("cna", {})
                return {"query": q.upper(), "source": "CIRCL", "id": c.get("cveId"), "state": c.get("state"),
                        "published": c.get("datePublished"), "updated": c.get("dateUpdated"),
                        "title": (a.get("title") or "")[:300],
                        "descriptions": [d.get("value") for d in a.get("descriptions", [])][:2],
                        "metrics": a.get("metrics", [])[:3], "affected": a.get("affected", [])[:5],
                        "references": [r.get("url") for r in a.get("references", [])][:12],
                        "results": []}
        except Exception:
            pass
        j = get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={q.upper()}", timeout=30, ttl=900)
    else:
        j = get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(q)}&resultsPerPage=20", timeout=35, ttl=600)
    for v in j.get("vulnerabilities", [])[:20]:
        c = v.get("cve", {})
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        sev, score = None, None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(k):
                m = c["metrics"][k][0]
                score = m.get("cvssData", {}).get("baseScore")
                sev = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity")
                break
        out["results"].append({"id": c.get("id"), "published": c.get("published"), "severity": sev,
                               "score": score, "description": desc[:400],
                               "references": [r.get("url") for r in c.get("references", [])][:5]})
    out["count"] = len(out["results"])
    out["source"] = "NVD"
    return out

# ---------------------------------------------------------------- crypto
def _b58check(addr):
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in addr:
        if ch not in A:
            return False
        n = n * 58 + A.index(ch)
    raw = n.to_bytes(25, "big") if n else b""
    if len(raw) != 25:
        return False
    chk = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    return chk == raw[21:]

def crypto_lookup(addr):
    addr = addr.strip()
    out = {"address": addr}
    if re.match(r"^(bc1|tb1)[a-z0-9]{20,70}$", addr.lower()):
        out["chain"] = "Bitcoin (bech32)"; out["valid_format"] = True
    elif re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", addr):
        out["chain"] = "Bitcoin (legacy/P2SH)"; out["valid_format"] = _b58check(addr)
    elif re.match(r"^0x[a-fA-F0-9]{40}$", addr):
        out["chain"] = "Ethereum/EVM"; out["valid_format"] = True
    elif re.match(r"^T[1-9A-HJ-NP-Za-km-z]{33}$", addr):
        out["chain"] = "Tron"; out["valid_format"] = True
    elif re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", addr):
        out["chain"] = "Solana (محتمل)"; out["valid_format"] = True
    else:
        out["chain"] = "غير معروف"; out["valid_format"] = False
    if not out["valid_format"]:
        out["note"] = "الصيغة غير صحيحة — تحقق من العنوان."
        return out
    if out["chain"].startswith("Bitcoin"):
        try:
            j = get_json(f"https://mempool.space/api/address/{quote(addr)}", timeout=20, ttl=120)
            cs = j.get("chain_stats", {})
            out["balances"] = {"confirmed_sats": cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0),
                               "total_received_sats": cs.get("funded_txo_sum", 0),
                               "tx_count": cs.get("tx_count", 0)}
            out["balances"]["confirmed_btc"] = out["balances"]["confirmed_sats"] / 1e8
            out["balances"]["source"] = "mempool.space (مجموعة UTXO الحالية)"
        except Exception as e:
            out["mempool_error"] = str(e)[:120]
        try:
            j2 = get_json(f"https://blockchain.info/rawaddr/{quote(addr)}?limit=15", timeout=20, ttl=120)
            out["blockchain_info"] = {"final_balance_btc": j2.get("final_balance", 0) / 1e8,
                                      "n_tx": j2.get("n_tx"), "total_received_btc": j2.get("total_received", 0) / 1e8,
                                      "txs": [{"hash": t.get("hash"), "time": t.get("time"),
                                               "result_btc": t.get("result", 0) / 1e8} for t in (j2.get("txs") or [])[:10]]}
        except Exception as e:
            out["blockchain_info_error"] = str(e)[:120]
        if "blockchain_info" in out and "balances" in out:
            a = out["balances"]["confirmed_btc"]; b = out["blockchain_info"]["final_balance_btc"]
            if abs(a - b) > 0.01:
                out["balance_note"] = ("الفرق بين المصدرين طبيعي: mempool يحسب من مجموعة UTXO الحالية، "
                                       "بينما blockchain.info يشمل مخرجات غير قابلة للصرف مثل مكافأة الكتلة الأولى (50 BTC).")
    elif out["chain"].startswith("Ethereum"):
        try:
            j = get_json(f"https://eth.blockscout.com/api/v2/addresses/{quote(addr)}", timeout=20, ttl=120)
            out["ethereum"] = {"balance_wei": j.get("coin_balance"),
                               "balance_eth": int(j.get("coin_balance") or 0) / 1e18,
                               "tx_count": (j.get("transaction_count") or j.get("transactions_count")),
                               "is_contract": j.get("is_contract"), "creator": j.get("creator_address_hash")}
        except Exception as e:
            out["blockscout_error"] = str(e)[:120]
        try:
            j2 = get_json(f"https://api.etherscan.io/api?module=account&action=balance&address={quote(addr)}&tag=latest", timeout=15, ttl=120)
            out["etherscan_note"] = j2.get("result") if j2.get("status") == "1" else "يتطلب مفتاح API (متجاوز)"
        except Exception:
            pass
    out["explorer_links"] = {
        "mempool.space": f"https://mempool.space/address/{addr}",
        "blockchain.com": f"https://www.blockchain.com/explorer/addresses/btc/{addr}",
        "etherscan": f"https://etherscan.io/address/{addr}",
        "blockscout": f"https://eth.blockscout.com/address/{addr}",
        "tronscan": f"https://tronscan.org/#/address/{addr}",
        "solscan": f"https://solscan.io/account/{addr}",
    }
    return out

# ---------------------------------------------------------------- geo
def geocode(q):
    q = q.strip()
    out = {"query": q, "results": [], "sources": {}}
    try:
        j = get_json("https://geocoding-api.open-meteo.com/v1/search?name=" + quote(q) + "&count=8&language=ar", timeout=15, ttl=3600)
        for r in j.get("results", []) or []:
            out["results"].append({"name": r.get("name"), "country": r.get("country"), "cc": r.get("country_code"),
                                   "admin": r.get("admin1"), "lat": r.get("latitude"), "lon": r.get("longitude"),
                                   "tz": r.get("timezone"), "pop": r.get("population"), "src": "open-meteo"})
        out["sources"]["open-meteo"] = len(out["results"])
    except Exception as e:
        out["sources"]["open-meteo_error"] = str(e)[:100]
    try:
        j = get_json("https://photon.komoot.io/api/?q=" + quote(q) + "&limit=8", timeout=15, ttl=3600)
        n = 0
        for f in j.get("features", []) or []:
            p = f.get("properties", {}); c = f.get("geometry", {}).get("coordinates", [None, None])
            out["results"].append({"name": p.get("name"), "country": p.get("country"), "cc": p.get("countrycode"),
                                   "admin": p.get("state"), "city": p.get("city"), "street": p.get("street"),
                                   "housenumber": p.get("housenumber"), "postcode": p.get("postcode"),
                                   "lat": c[1], "lon": c[0], "osm_type": p.get("osm_type"), "osm_id": p.get("osm_id"),
                                   "src": "photon/OSM"})
            n += 1
        out["sources"]["photon"] = n
    except Exception as e:
        out["sources"]["photon_error"] = str(e)[:100]
    return out

def reverse_geocode(lat, lon):
    try:
        lat, lon = float(lat), float(lon)
    except ValueError:
        raise FetchError("إحداثيات غير صالحة")
    out = {"lat": lat, "lon": lon}
    try:
        out["bigdatacloud"] = get_json(f"https://api.bigdatacloud.net/data/reverse-geocode-client?latitude={lat}&longitude={lon}&localityLanguage=ar", timeout=15, ttl=1800)
    except Exception as e:
        out["error"] = str(e)[:120]
    try:
        j = get_json(f"https://photon.komoot.io/reverse?lat={lat}&lon={lon}", timeout=15, ttl=1800)
        out["photon"] = (j.get("features") or [{}])[0].get("properties") if j.get("features") else None
    except Exception:
        pass
    out["links"] = {"OpenStreetMap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
                    "Google Maps": f"https://www.google.com/maps/@{lat},{lon},15z",
                    "Bing": f"https://www.bing.com/maps?cp={lat}~{lon}&lvl=16",
                    "Yandex": f"https://yandex.com/maps/?ll={lon},{lat}&z=16",
                    "SunCalc (شمس/ظل)": f"https://www.suncalc.org/#/{lat},{lon},15"}
    return out

def distance(a_lat, a_lon, b_lat, b_lon):
    try:
        p1, p2 = math.radians(float(a_lat)), math.radians(float(b_lat))
        dp = p2 - p1; dl = math.radians(float(b_lon) - float(a_lon))
        h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        d = 2 * 6371.0088 * math.asin(math.sqrt(h))
        br = math.degrees(math.atan2(math.sin(dl) * math.cos(p2),
                                     math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl))) % 360
        return {"distance_km": round(d, 3), "distance_m": round(d * 1000, 1),
                "bearing_deg": round(br, 1), "bearing_compass": _compass(br),
                "flight_time_min_900kmh": round(d / 900 * 60, 1)}
    except ValueError:
        raise FetchError("إحداثيات غير صالحة")

def _compass(d):
    dirs = ["شمال", "شمال شرق", "شرق", "جنوب شرق", "جنوب", "جنوب غرب", "غرب", "شمال غرب"]
    return dirs[int((d + 22.5) % 360 // 45)]

def weather(lat, lon):
    j = get_json(f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,apparent_temperature,is_day,precipitation,weather_code,wind_speed_10m,wind_direction_10m,pressure_msl&daily=temperature_2m_max,temperature_2m_min,sunrise,sunset&timezone=auto&forecast_days=3", timeout=15, ttl=900)
    return {"location": {"lat": lat, "lon": lon}, "current": j.get("current"), "daily": j.get("daily"),
            "units": j.get("current_units"), "timezone": j.get("timezone")}

def earthquakes(min_mag=2.5, hours="day"):
    j = get_json(f"https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/{min_mag}_{hours}.geojson", timeout=20, ttl=300)
    qs = []
    for f in (j.get("features") or [])[:100]:
        p = f.get("properties", {}); c = f.get("geometry", {}).get("coordinates", [None, None, None])
        qs.append({"mag": p.get("mag"), "place": p.get("place"), "time": p.get("time"),
                   "lon": c[0], "lat": c[1], "depth_km": c[2], "url": p.get("url"),
                   "tsunami": p.get("tsunami")})
    qs.sort(key=lambda x: -(x["mag"] or 0))
    return {"min_magnitude": min_mag, "window": hours, "count": len(qs), "largest": qs[:40]}

# ---------------------------------------------------------------- company
def company_lookup(q):
    q = q.strip()
    out = {"query": q, "lei": [], "sec": []}
    try:
        j = get_json("https://api.gleif.org/api/v1/lei-records?filter%5Bentity.legalName%5D=" + quote(q) + "&page%5Bsize%5D=10", timeout=20, ttl=1800)
        for r in j.get("data", []) or []:
            a = r.get("attributes", {}); e = a.get("entity", {})
            out["lei"].append({"lei": a.get("lei"), "name": e.get("legalName", {}).get("name"),
                               "country": e.get("legalAddress", {}).get("country"),
                               "city": e.get("legalAddress", {}).get("city"),
                               "status": e.get("status"), "legal_form": e.get("legalForm", {}).get("id"),
                               "registration": e.get("registeredAt", {}).get("id"),
                               "address": " ".join(filter(None, [e.get("legalAddress", {}).get("addressLines", [None])[0] if e.get("legalAddress", {}).get("addressLines") else None]))})
        ql = q.lower().strip()
        def rank(r):
            n = (r.get("name") or "").lower()
            return (0 if n == ql else 1 if n.startswith(ql) else 2 if ql in n else 3)
        out["lei"].sort(key=rank)
        out["lei_note"] = "GLEIF يطابق الاسم القانوني؛ النتائج مرتّبة حسب قرب الاسم من استعلامك."
    except Exception as e:
        out["lei_error"] = str(e)[:120]
    try:
        cached = cache_get("sec_tickers", 86400)
        if not cached:
            cached = get_json("https://www.sec.gov/files/company_tickers.json", timeout=30, ua="OSINT-Console research contact@example.com")
            cache_set("sec_tickers", cached, 86400)
        ql = q.lower()
        hits = [v for v in cached.values() if ql in str(v.get("title", "")).lower() or ql == str(v.get("ticker", "")).lower()][:10]
        for h in hits:
            out["sec"].append({"cik": str(h["cik_str"]).zfill(10), "ticker": h["ticker"], "title": h["title"],
                               "filings": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={str(h['cik_str']).zfill(10)}&type=&dateb=&owner=include&count=40"})
    except Exception as e:
        out["sec_error"] = str(e)[:120]
    out["manual_links"] = {"OpenCorporates": f"https://opencorporates.com/companies?q={quote(q)}",
                           "Companies House (UK)": f"https://find-and-update.company-information.service.gov.uk/search?q={quote(q)}",
                           "OCCRP Aleph": f"https://aleph.occrp.org/search?q={quote(q)}",
                           "OpenLEIs": f"https://openleis.com/entities?q={quote(q)}"}
    return out

# ---------------------------------------------------------------- file analysis
MAGIC = [(b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF87a", "GIF image"),
         (b"GIF89a", "GIF image"), (b"%PDF-", "PDF document"), (b"PK\x03\x04", "ZIP / Office / APK / JAR"),
         (b"Rar!\x1a\x07", "RAR archive"), (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"), (b"\x1f\x8b", "GZIP"),
         (b"BM", "BMP image"), (b"II*\x00", "TIFF (LE)"), (b"MM\x00*", "TIFF (BE)"),
         (b"\x7fELF", "ELF executable"), (b"MZ", "PE executable (Windows)"), (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
         (b"\x00\x00\x00\x18ftyp", "MP4 / MOV"), (b"\x00\x00\x00\x20ftyp", "MP4"), (b"OggS", "OGG"),
         (b"RIFF", "RIFF (WAV/AVI/WebP)"), (b"ID3", "MP3 (ID3)"), (b"\xff\xfb", "MP3"),
         (b"SQLite format 3", "SQLite DB"), (b"\xd0\xcf\x11\xe0", "MS Office legacy (OLE2)"),
         (b"<?xml", "XML"), (b"{\\rtf", "RTF"), (b"\x1aE\xdf\xa3", "Matroska/WebM"),
         (b"wOFF", "WOFF font"), (b"\x00\x01\x00\x00", "TrueType font")]

def file_analyze(name, data):
    if len(data) > 25 * 1024 * 1024:
        raise FetchError("الحجم الأقصى 25MB")
    h = {a: hashlib.new(a, data).hexdigest() for a in ("md5", "sha1", "sha256")}
    magic = next((n for sig, n in MAGIC if data.startswith(sig)), "غير معروف")
    ent = _entropy(data)
    out = {"filename": name, "size_bytes": len(data), "size_human": f"{len(data)/1024:.1f} KB",
           "hashes": h, "magic": magic, "entropy": round(ent, 3),
           "entropy_verdict": ("مشفّر/مضغوط جداً (احتمال تعبئة)" if ent > 7.5 else
                               "مضغوط" if ent > 6.8 else "طبيعي" if ent > 3 else "بيانات متكررة/نص"),
           "type_guess": _type_guess(name, data), "strings_preview": _strings(data)[:20],
           "iocs": ioc_extract(data.decode("utf-8", "ignore"))}
    if data[:3] == b"\xff\xd8\xff":
        out["exif"] = _exif(data)
    if data[:5] == b"%PDF-":
        txt = data.decode("latin-1", "ignore")
        pages = len(re.findall(r"/Type\s*/Page(?![s\w])", txt))
        if pages == 0:
            m = re.search(r"/Type\s*/Pages.{0,200}?/Count\s+(\d+)", txt, re.S)
            if m:
                pages = int(m.group(1))
        out["pdf"] = {"version": txt[5:8], "pages": pages,
                      "meta": {k: v for k, v in re.findall(r"/(Title|Author|Creator|Producer|CreationDate|ModDate)\s*\(([^)]{0,200})\)", txt)},
                      "has_javascript": "/JavaScript" in txt or "/JS" in txt,
                      "has_embedded": "/EmbeddedFile" in txt, "encrypted": "/Encrypt" in txt}
    if data[:2] == b"PK":
        import io, zipfile
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            out["zip"] = {"entries": len(z.namelist()), "names": z.namelist()[:30]}
        except Exception:
            pass
    out["reference"] = {"VirusTotal": "https://www.virustotal.com/gui/file/" + h["sha256"],
                        "Hybrid Analysis": "https://www.hybrid-analysis.com/search?query=" + h["sha256"],
                        "MalwareBazaar": "https://bazaar.abuse.ch/browse.php?search=sha256:" + h["sha256"]}
    return out

def _entropy(b):
    if not b:
        return 0.0
    from collections import Counter
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def _type_guess(name, data):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return {"ext": ext, "double_extension": bool(re.search(r"\.(jpg|png|pdf|docx?)\.(exe|scr|bat|js|vbs)$", name.lower())),
            "rtlo_char": "\u202e" in name, "macros": b"vbaProject" in data or b"AutoOpen" in data}

def _strings(data, minlen=6):
    found, cur = [], b""
    for ch in data[:300000]:
        if 32 <= ch < 127:
            cur += bytes([ch])
        else:
            if len(cur) >= minlen:
                found.append(cur.decode("latin-1"))
            cur = b""
    if len(cur) >= minlen:
        found.append(cur.decode("latin-1"))
    seen, out = set(), []
    for s in found:
        if s not in seen:
            seen.add(s); out.append(s)
    return out[:200]

TAGS = {271: "Make", 272: "Model", 274: "Orientation", 305: "Software", 306: "DateTime",
        315: "Artist", 33434: "ExposureTime", 33437: "FNumber", 34855: "ISO", 36867: "DateTimeOriginal",
        36868: "DateTimeDigitized", 42036: "LensModel", 1: "GPSLatitudeRef", 2: "GPSLatitude",
        3: "GPSLongitudeRef", 4: "GPSLongitude", 5: "GPSAltitudeRef", 6: "GPSAltitude", 29: "GPSDateStamp"}

def _exif(data):
    out = {}
    try:
        i = data.find(b"Exif\x00\x00")
        if i < 0:
            return {"note": "لا يوجد EXIF"}
        t = data[i + 6:]
        end = "<" if t[:2] == b"II" else ">"
        off = struct.unpack(end + "I", t[4:8])[0]
        def read_ifd(pos, depth=0):
            if pos + 2 > len(t):
                return
            n = struct.unpack(end + "H", t[pos:pos + 2])[0]
            for k in range(n):
                e = pos + 2 + k * 12
                if e + 12 > len(t):
                    return
                tag, typ, cnt = struct.unpack(end + "HHI", t[e:e + 8])
                val_off = e + 8
                fmt = {1: ("B", 1), 2: ("s", 1), 3: ("H", 2), 4: ("I", 4), 5: ("II", 8), 7: ("B", 1), 9: ("i", 4)}.get(typ)
                if not fmt:
                    continue
                f, sz = fmt
                raw = t[val_off:val_off + 4]
                if sz * cnt > 4:
                    vo = struct.unpack(end + "I", raw)[0]
                    raw = t[vo:vo + sz * cnt]
                try:
                    if typ == 2:
                        v = raw.split(b"\x00")[0].decode("latin-1", "ignore").strip()
                    elif typ == 5:
                        vals = struct.unpack(end + "I" * (2 * cnt), raw[:8 * cnt])
                        v = tuple(round(a / b, 6) if b else a for a, b in zip(vals[::2], vals[1::2]))
                    else:
                        v = struct.unpack(end + f * cnt, raw[:sz * cnt])
                        v = v[0] if cnt == 1 else v
                except Exception:
                    continue
                name = TAGS.get(tag)
                if name:
                    out[name] = v
                if depth == 0 and tag == 34853:
                    val = struct.unpack(end + "I", raw)[0]
                    read_ifd(val, depth + 1)
            nxt = pos + 2 + n * 12
            if depth == 0 and nxt + 4 <= len(t):
                npos = struct.unpack(end + "I", t[nxt:nxt + 4])[0]
                if 0 < npos < len(t):
                    read_ifd(npos, 1)
        read_ifd(off)
    except Exception as e:
        return {"error": str(e)[:120]}
    lat = out.get("GPSLatitude"); lon = out.get("GPSLongitude")
    if lat and lon:
        def dms(v, ref):
            try:
                d = float(v[0]) + float(v[1]) / 60 + float(v[2]) / 3600
                return -d if str(ref) in ("S", "W") else d
            except Exception:
                return None
        la = dms(lat, out.get("GPSLatitudeRef", "N")); lo = dms(lon, out.get("GPSLongitudeRef", "E"))
        if la and lo:
            out["_coordinates"] = {"lat": round(la, 6), "lon": round(lo, 6),
                                   "maps": f"https://www.google.com/maps/@{la:.6f},{lo:.6f},17z",
                                   "osm": f"https://www.openstreetmap.org/?mlat={la}&mlon={lo}#map=17/{la}/{lo}"}
    return out or {"note": "لا يوجد EXIF مقروء"}

# ---------------------------------------------------------------- IOC
RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_DOM = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|tk|ml|ga|cf|gq|onion|de|uk|fr|sa|ae|eg|ye|tr|ir|in|br|jp|kr|app|dev|me|co|site|online|shop|club|live|pro|link|click|space|website|store|tech|cloud|ai)\b")
RE_URL = re.compile(r"https?://[^\s<>\"'\]\)]{4,200}")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_BTC = re.compile(r"\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def ioc_extract(text):
    if not text:
        return {}
    def uniq(rx, s, flags=0):
        return sorted(set(m.group(0) for m in re.finditer(rx.pattern, s, flags or rx.flags)))[:200]
    ips = uniq(RE_IP, text)
    domains = [d for d in uniq(RE_DOM, text) if d not in ips][:200]
    return {
        "ipv4": ips,
        "domains": domains,
        "urls": uniq(RE_URL, text)[:100],
        "emails": uniq(RE_EMAIL, text)[:100],
        "md5": uniq(RE_MD5, text)[:50], "sha1": uniq(RE_SHA1, text)[:50], "sha256": uniq(RE_SHA256, text)[:50],
        "bitcoin": uniq(RE_BTC, text)[:30], "ethereum": uniq(RE_ETH, text)[:30],
        "cve": sorted({c.upper() for c in re.findall(RE_CVE.pattern, text, re.I)})[:50],
        "counts": {},
    }

def ioc_enrich(iocs):
    res = {"dns": {}, "ip": {}, "errors": {}}
    for d in iocs.get("domains", [])[:12]:
        try:
            from modules_net import dns_lookup
            r = dns_lookup(d, ["A", "MX", "NS"])
            res["dns"][d] = {"A": [a["data"] for a in r["records"].get("A", {}).get("answers", [])],
                             "MX": [a["data"] for a in r["records"].get("MX", {}).get("answers", [])][:3],
                             "NS": [a["data"] for a in r["records"].get("NS", {}).get("answers", [])][:3]}
        except Exception as e:
            res["errors"][d] = str(e)[:80]
    for ip in iocs.get("ipv4", [])[:12]:
        try:
            from modules_net import ip_intel
            r = ip_intel(ip)
            g = r.get("geo", {})
            res["ip"][ip] = {"country": g.get("country"), "org": g.get("org") or g.get("isp"),
                             "asn": g.get("as"), "hosting": g.get("hosting"), "proxy": g.get("proxy"),
                             "tor": r.get("tor_exit"), "ports": (r.get("shodan_internetdb") or {}).get("ports")}
        except Exception as e:
            res["errors"][ip] = str(e)[:80]
    return res

# ---------------------------------------------------------------- catalog
def catalog_search(q="", cat="", limit=200):
    data = json.load(open("data/catalog.json", encoding="utf-8"))
    ql = q.strip().lower()
    out = []
    for t in data:
        if cat and t["c"] != cat:
            continue
        if ql and ql not in (t["n"] + " " + t["u"] + " " + t.get("d", "") + " " + t["c"]).lower():
            continue
        out.append(t)
        if len(out) >= limit:
            break
    cats = sorted({t["c"] for t in data})
    return {"count": len(out), "total_in_catalog": len(data), "categories": cats, "tools": out}
