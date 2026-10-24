"""Identity modules: username enumeration, email, phone, password, hash, github, dorks."""
import re, json, hashlib, math, concurrent.futures as cf
from urllib.parse import quote
from core import get_json, get_text, safe_fetch, FetchError, cache_get, cache_set, polite

# ---------------------------------------------------------------- username
# mode: status (200=exists,404=no) | json | marker
SITES = [
    {"n": "GitHub", "u": "https://api.github.com/users/{}", "mode": "status"},
    {"n": "GitLab", "u": "https://gitlab.com/api/v4/users?username={}", "mode": "json_empty"},
    {"n": "Reddit", "u": "https://www.reddit.com/user/{}/about.json", "mode": "status"},
    {"n": "Hacker News", "u": "https://hn.algolia.com/api/v1/users/{}", "mode": "status"},
    {"n": "Keybase", "u": "https://keybase.io/_/api/1.0/user/lookup.json?username={}", "mode": "json_empty", "key": "them"},
    {"n": "PyPI", "u": "https://pypi.org/pypi/{}/json", "mode": "status"},
    {"n": "npm", "u": "https://registry.npmjs.org/{}", "mode": "status"},
    {"n": "Docker Hub", "u": "https://hub.docker.com/v2/users/{}/", "mode": "status"},
    {"n": "Bitbucket", "u": "https://api.bitbucket.org/2.0/users/{}", "mode": "status"},
    {"n": "Dev.to", "u": "https://dev.to/api/users/by_username?url={}", "mode": "status"},
    {"n": "Codeforces", "u": "https://codeforces.com/api/user.info?handles={}", "mode": "cf"},
    {"n": "LeetCode", "u": "https://leetcode.com/{}/", "mode": "status"},
    {"n": "HackerRank", "u": "https://www.hackerrank.com/{}", "mode": "status"},
    {"n": "Chess.com", "u": "https://api.chess.com/pub/player/{}", "mode": "status"},
    {"n": "Lichess", "u": "https://lichess.org/api/user/{}", "mode": "status"},
    {"n": "SoundCloud", "u": "https://soundcloud.com/{}", "mode": "status"},
    {"n": "Medium", "u": "https://medium.com/@{}", "mode": "status"},
    {"n": "Dribbble", "u": "https://dribbble.com/{}", "mode": "status"},
    {"n": "Behance", "u": "https://www.behance.net/{}", "mode": "status"},
    {"n": "Vimeo", "u": "https://vimeo.com/{}", "mode": "status"},
    {"n": "Flickr", "u": "https://www.flickr.com/people/{}", "mode": "status"},
    {"n": "About.me", "u": "https://about.me/{}", "mode": "status"},
    {"n": "Linktree", "u": "https://linktr.ee/{}", "mode": "status"},
    {"n": "Patreon", "u": "https://www.patreon.com/{}", "mode": "status"},
    {"n": "Tumblr", "u": "https://{}.tumblr.com", "mode": "status"},
    {"n": "Mastodon.social", "u": "https://mastodon.social/@{}", "mode": "status"},
    {"n": "Bluesky", "u": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social", "mode": "status"},
    {"n": "YouTube", "u": "https://www.youtube.com/@{}", "mode": "status"},
    {"n": "Steam", "u": "https://steamcommunity.com/id/{}", "mode": "marker",
     "notfound": ["the specified profile could not be found"]},
    {"n": "Telegram", "u": "https://t.me/{}", "mode": "marker",
     "found": ["tgme_page_extra"], "notfound": ["telegram: contact"]},
    {"n": "Pinterest", "u": "https://www.pinterest.com/{}/", "mode": "status"},
    {"n": "Last.fm", "u": "https://www.last.fm/user/{}", "mode": "status"},
    {"n": "Duolingo", "u": "https://www.duolingo.com/2017-06-30/users?username={}", "mode": "json_empty", "key": "users"},
    {"n": "TikTok", "u": "https://www.tiktok.com/@{}", "mode": "marker",
     "notfound": ["couldn't find this account", "page not available", "unavailable"]},
    {"n": "Codeberg", "u": "https://codeberg.org/api/v1/users/{}", "mode": "status"},
    {"n": "Hugging Face", "u": "https://huggingface.co/api/users/{}/overview", "mode": "status"},
    {"n": "Stack Overflow", "u": "https://api.stackexchange.com/2.3/users?inname={}&site=stackoverflow", "mode": "json_empty", "key": "items"},
    {"n": "Quay.io", "u": "https://quay.io/api/v1/users/{}", "mode": "status"},
]
MANUAL = [("Instagram", "https://www.instagram.com/{}/"), ("X (Twitter)", "https://x.com/{}"),
          ("Facebook", "https://www.facebook.com/{}"), ("Twitch", "https://www.twitch.tv/{}"),
          ("TikTok", "https://www.tiktok.com/@{}"), ("Snapchat", "https://www.snapchat.com/add/{}"),
          ("Threads", "https://www.threads.net/@{}"), ("VK", "https://vk.com/{}"),
          ("WhatsApp", "https://wa.me/{}"), ("Weibo", "https://weibo.com/{}")]

def username_scan(username):
    u = username.strip().lstrip("@")
    ck = "uname:" + u.lower()
    cached = cache_get(ck, 900)
    if cached is not None:
        cached = dict(cached); cached["cached"] = True
        return cached
    if not re.match(r"^[A-Za-z0-9._\-]{2,40}$", u):
        raise FetchError("اسم مستخدم غير صالح (حروف/أرقام/نقطة/شرطة، 2-40)")
    def probe(site):
        url = site["u"].format(quote(u, safe=""))
        rec = {"site": site["n"], "url": url, "state": "unknown", "detail": ""}
        try:
            st, hd, raw, _ = safe_fetch(url, timeout=10, max_bytes=200000,
                                        headers={"Accept": "application/json,text/html,*/*"})
            body = raw.decode("utf-8", "replace")
            low = body.lower()
            if site["mode"] == "status":
                if st == 200:
                    rec["state"] = "found"
                elif st == 404:
                    rec["state"] = "not_found"
                elif st in (403, 429, 401):
                    rec["state"] = "blocked"; rec["detail"] = f"HTTP {st}"
                else:
                    rec["state"] = "unknown"; rec["detail"] = f"HTTP {st}"
            elif site["mode"] == "json_empty":
                try:
                    j = json.loads(body)
                except Exception:
                    rec["state"] = "unknown"; rec["detail"] = "رد غير JSON"
                    return rec
                if site["key"]:
                    v = j.get(site["key"]) if isinstance(j, dict) else None
                    rec["state"] = "found" if v else "not_found"
                else:
                    rec["state"] = "found" if j else "not_found"
            elif site["mode"] == "cf":
                j = json.loads(body)
                rec["state"] = "found" if j.get("status") == "OK" else "not_found"
                if j.get("status") == "FAILED":
                    rec["detail"] = j.get("comment", "")[:80]
            elif site["mode"] == "marker":
                # a site can be judged by: explicit "not found" text, an explicit
                # "found" marker, or a fallback status code.
                if any(m in low for m in site.get("notfound", [])):
                    rec["state"] = "not_found"
                elif site.get("found") and any(m in low for m in site["found"]):
                    rec["state"] = "found"
                elif st == 404:
                    rec["state"] = "not_found"
                elif st == 200:
                    rec["state"] = "unknown"
                    rec["detail"] = "لا توجد علامة حاسمة — تحقق يدوياً"
            if rec["state"] == "not_found":
                rec["detail"] = rec["detail"] or "لا يوجد حساب بهذا الاسم"
        except Exception as e:
            rec["state"] = "unknown"; rec["detail"] = str(e)[:80]
        return rec
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(probe, SITES))
    found = [r for r in results if r["state"] == "found"]
    out = {"username": u, "checked": len(results), "found_count": len(found),
            "found": found, "all": results,
            "manual_checks": [{"site": n, "url": t.format(quote(u))} for n, t in MANUAL],
            "note": "الحالات «unknown/blocked» تحتاج تحققاً يدوياً (المواقع تحجب الطلبات الآلية)."}
    blocked = [r["site"] for r in results if r["state"] == "blocked"]
    if blocked:
        out["blocked_sites"] = blocked
        out["rate_limit_note"] = ("مواقع أعادت 403/429 (حد مجاني أو حجب آلي): " + ", ".join(blocked) +
                                  " — تُعاد المحاولة تلقائياً بعد قليل، والنتيجة مخزّنة 15 دقيقة.")
    cache_set(ck, out, 900)
    return out

# ---------------------------------------------------------------- email
DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
              "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com",
              "maildrop.cc", "throwawaymail.com", "mytemp.email", "emailondeck.com", "spam4.me",
              "fakeinbox.com", "mailnesia.com", "tempinbox.com", "moakt.com", "33mail.com"}
ROLE = {"admin", "info", "support", "sales", "contact", "hello", "noreply", "no-reply", "postmaster",
        "webmaster", "abuse", "security", "billing", "jobs", "hr", "press", "marketing"}

def email_intel(email):
    e = email.strip()
    if not re.match(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", e):
        raise FetchError("صيغة بريد غير صالحة")
    local, domain = e.rsplit("@", 1)
    out = {"email": e, "local": local, "domain": domain.lower(),
           "valid_syntax": True, "disposable": domain.lower() in DISPOSABLE,
           "role_account": local.lower() in ROLE,
           "local_length": len(local), "has_plus_tag": "+" in local, "dots_in_local": "." in local}
    try:
        from modules_net import dns_lookup
        d = dns_lookup(domain, ["MX", "A", "TXT"])
        mx = [a["data"] for a in d["records"].get("MX", {}).get("answers", [])]
        out["mx"] = mx
        out["accepts_mail"] = bool(mx) or bool(d["records"].get("A", {}).get("answers"))
        out["mail_providers"] = d.get("mail_providers", [])
        spf = [a["data"] for a in d["records"].get("TXT", {}).get("answers", []) if a["data"].startswith("v=spf1")]
        out["spf"] = spf[:2]
        out["dmarc_present"] = any("v=DMARC1" in a["data"] for a in d["records"].get("TXT", {}).get("answers", []))
    except Exception as ex:
        out["dns_error"] = str(ex)[:120]
    try:
        d2 = get_json(f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT", timeout=10, ttl=600)
        out["dmarc_present"] = any("v=DMARC1" in a.get("data", "") for a in d2.get("Answer", []) or [])
    except Exception:
        pass
    md5 = hashlib.md5(e.lower().encode()).hexdigest()
    out["gravatar_hash"] = md5
    out["gravatar_url"] = f"https://www.gravatar.com/avatar/{md5}?d=404"
    try:
        st, _, _, _ = safe_fetch(out["gravatar_url"], timeout=8)
        out["gravatar_exists"] = st == 200
    except Exception:
        out["gravatar_exists"] = None
    try:
        gp = get_json(f"https://gravatar.com/{md5}.json", timeout=10, ttl=3600)
        ent = (gp.get("entry") or [{}])[0]
        out["gravatar_profile"] = {k: ent.get(k) for k in
            ("displayName", "preferredUsername", "aboutMe", "currentLocation", "urls", "accounts")
            if ent.get(k)}
    except Exception:
        pass
    out["check_links"] = {
        "HaveIBeenPwned": f"https://haveibeenpwned.com/account/{quote(e)}",
        "Epieos": f"https://epieos.com/?q={quote(e)}&t=email",
        "Google dork (paste)": f"https://www.google.com/search?q=%22{quote(e)}%22",
        "GitHub code search": f"https://github.com/search?q=%22{quote(e)}%22&type=code",
    }
    return out

# ---------------------------------------------------------------- phone
CC = {1: ("US/CA", "الولايات المتحدة/كندا"), 7: ("RU/KZ", "روسيا/كازاخستان"), 20: ("EG", "مصر"),
      27: ("ZA", "جنوب أفريقيا"), 30: ("GR", "اليونان"), 31: ("NL", "هولندا"), 32: ("BE", "بلجيكا"),
      33: ("FR", "فرنسا"), 34: ("ES", "إسبانيا"), 36: ("HU", "هنغاريا"), 39: ("IT", "إيطاليا"),
      40: ("RO", "رومانيا"), 41: ("CH", "سويسرا"), 43: ("AT", "النمسا"), 44: ("GB", "المملكة المتحدة"),
      45: ("DK", "الدنمارك"), 46: ("SE", "السويد"), 47: ("NO", "النرويج"), 48: ("PL", "بولندا"),
      49: ("DE", "ألمانيا"), 51: ("PE", "بيرو"), 52: ("MX", "المكسيك"), 53: ("CU", "كوبا"),
      54: ("AR", "الأرجنتين"), 55: ("BR", "البرازيل"), 56: ("CL", "تشيلي"), 57: ("CO", "كولومبيا"),
      58: ("VE", "فنزويلا"), 60: ("MY", "ماليزيا"), 61: ("AU", "أستراليا"), 62: ("ID", "إندونيسيا"),
      63: ("PH", "الفلبين"), 64: ("NZ", "نيوزيلندا"), 65: ("SG", "سنغافورة"), 66: ("TH", "تايلاند"),
      81: ("JP", "اليابان"), 82: ("KR", "كوريا الجنوبية"), 84: ("VN", "فيتنام"), 86: ("CN", "الصين"),
      90: ("TR", "تركيا"), 91: ("IN", "الهند"), 92: ("PK", "باكستان"), 93: ("AF", "أفغانستان"),
      94: ("LK", "سريلانكا"), 95: ("MM", "ميانمار"), 98: ("IR", "إيران"), 212: ("MA", "المغرب"),
      213: ("DZ", "الجزائر"), 216: ("TN", "تونس"), 218: ("LY", "ليبيا"), 220: ("GM", "غامبيا"),
      221: ("SN", "السنغال"), 233: ("GH", "غانا"), 234: ("NG", "نيجيريا"), 249: ("SD", "السودان"),
      251: ("ET", "إثيوبيا"), 252: ("SO", "الصومال"), 254: ("KE", "كينيا"), 255: ("TZ", "تنزانيا"),
      256: ("UG", "أوغندا"), 260: ("ZM", "زامبيا"), 263: ("ZW", "زيمبابوي"), 351: ("PT", "البرتغال"),
      352: ("LU", "لوكسمبورغ"), 353: ("IE", "أيرلندا"), 355: ("AL", "ألبانيا"), 357: ("CY", "قبرص"),
      358: ("FI", "فنلندا"), 359: ("BG", "بلغاريا"), 370: ("LT", "ليتوانيا"), 371: ("LV", "لاتفيا"),
      372: ("EE", "إستونيا"), 373: ("MD", "مولدوفا"), 375: ("BY", "روسيا البيضاء"), 380: ("UA", "أوكرانيا"),
      381: ("RS", "صربيا"), 385: ("HR", "كرواتيا"), 386: ("SI", "سلوفينيا"), 387: ("BA", "البوسنة"),
      389: ("MK", "مقدونيا"), 420: ("CZ", "التشيك"), 421: ("SK", "سلوفاكيا"), 961: ("LB", "لبنان"),
      962: ("JO", "الأردن"), 963: ("SY", "سوريا"), 964: ("IQ", "العراق"), 965: ("KW", "الكويت"),
      966: ("SA", "السعودية"), 967: ("YE", "اليمن"), 968: ("OM", "عُمان"), 970: ("PS", "فلسطين"),
      971: ("AE", "الإمارات"), 972: ("IL", "إسرائيل"), 973: ("BH", "البحرين"), 974: ("QA", "قطر"),
      975: ("BT", "بوتان"), 976: ("MN", "منغوليا"), 977: ("NP", "نيبال"), 992: ("TJ", "طاجيكستان"),
      993: ("TM", "تركمانستان"), 994: ("AZ", "أذربيجان"), 995: ("GE", "جورجيا"), 996: ("KG", "قيرغيزستان"),
      998: ("UZ", "أوزبكستان")}

def phone_intel(number, default_cc=49):
    raw = number.strip()
    digits = re.sub(r"[^\d+]", "", raw)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    if not digits.startswith("+"):
        if digits.startswith("0"):
            digits = f"+{default_cc}{digits[1:]}"
        else:
            digits = f"+{default_cc}{digits}"
    if not re.match(r"^\+\d{7,15}$", digits):
        raise FetchError("رقم غير صالح: استخدم صيغة دولية مثل +4915112345678")
    nat = digits[1:]
    cc = None
    for n in (3, 2, 1):
        if int(nat[:n]) in CC:
            cc = int(nat[:n]); break
    iso, country = CC.get(cc, ("??", "غير معروف"))
    national = nat[len(str(cc)):] if cc else nat
    return {"input": raw, "e164": digits, "country_code": cc, "iso": iso, "country_ar": country,
            "national_number": national, "national_digits": len(national),
            "plausible_length": 6 <= len(national) <= 13,
            "links": {"WhatsApp": f"https://wa.me/{nat}", "Telegram": f"https://t.me/+{nat}",
                      "Truecaller": f"https://www.truecaller.com/search/{iso.lower()}/{nat}",
                      "Sync.me": f"https://sync.me/search/?number={nat}",
                      "Google": f"https://www.google.com/search?q=%22{digits}%22"},
            "note": "تحليل صيغة محلي بدون مفاتيح — لا يتحقق من الملكية أو النشاط."}

# ---------------------------------------------------------------- password
COMMON = {"123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567", "111111", "1234567890",
          "123123", "abc123", "1234", "password1", "iloveyou", "000000", "zaq1zaq1", "dragon", "monkey",
          "letmein", "welcome", "admin", "login", "passw0rd", "master", "hello", "freedom", "whatever",
          "qazwsx", "trustno1", "football", "baseball", "sunshine", "princess", "shadow", "superman"}

def password_check(pw):
    if not pw:
        raise FetchError("كلمة مرور فارغة")
    charsets = [(r"[a-z]", 26), (r"[A-Z]", 26), (r"[0-9]", 10), (r"[^A-Za-z0-9]", 33)]
    pool = sum(sz for pat, sz in charsets if re.search(pat, pw))
    pool = max(pool, 1)
    entropy = round(len(pw) * math.log2(pool), 2)
    out = {"length": len(pw), "entropy_bits": entropy,
           "charsets": {"lower": bool(re.search(r"[a-z]", pw)), "upper": bool(re.search(r"[A-Z]", pw)),
                        "digits": bool(re.search(r"[0-9]", pw)), "symbols": bool(re.search(r"[^A-Za-z0-9]", pw))},
           "is_common": pw.lower() in COMMON,
           "repeated": bool(re.match(r"^(.)\1+$", pw)),
           "sequential": any(s in pw.lower() for s in ("123456", "abcdef", "qwerty", "111111"))}
    out["strength"] = ("ضعيفة جداً" if (out["is_common"] or entropy < 28) else "ضعيفة" if entropy < 40
                       else "متوسطة" if entropy < 60 else "قوية" if entropy < 80 else "قوية جداً")
    try:
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        pre, suf = sha1[:5], sha1[5:]
        txt = get_text(f"https://api.pwnedpasswords.com/range/{pre}", timeout=15, ttl=3600)
        hits = 0
        for line in txt.splitlines():
            if ":" in line and line.split(":")[0].strip() == suf:
                hits = int(line.split(":")[1].strip()); break
        out["pwned_count"] = hits
        out["pwned"] = hits > 0
    except Exception as e:
        out["pwned_error"] = str(e)[:100]
    out["note"] = "يُرسل أول 5 أحرف من SHA-1 فقط (k-anonymity) — كلمة المرور نفسها لا تُرسل أبداً."
    return out

# ---------------------------------------------------------------- hash
HASH_TYPES = [
    (r"^[a-f0-9]{32}$", "MD5 / NTLM / MD4", 32),
    (r"^[a-f0-9]{40}$", "SHA-1", 40),
    (r"^[a-f0-9]{56}$", "SHA-224", 56),
    (r"^[a-f0-9]{64}$", "SHA-256", 64),
    (r"^[a-f0-9]{96}$", "SHA-384", 96),
    (r"^[a-f0-9]{128}$", "SHA-512", 128),
    (r"^\$2[aby]?\$\d{2}\$.{53}$", "bcrypt", 60),
    (r"^\$argon2(id|i|d)\$", "Argon2", 0),
    (r"^\$6\$", "sha512crypt", 0), (r"^\$5\$", "sha256crypt", 0),
    (r"^\$1\$", "md5crypt", 0), (r"^\$y\$", "yescrypt", 0),
    (r"^[a-f0-9]{16}$", "MySQL323 / CRC-64", 16),
    (r"^[A-Za-z0-9+/]{27}=$", "MySQL4.1 (base64)", 28),
]

def hash_identify(h):
    h = h.strip()
    if not h:
        raise FetchError("أدخل قيمة hash")
    cands = [{"type": name, "confidence": "عالية" if h.lower() != h or name in ("MD5 / NTLM / MD4",) else "متوسطة"}
             for pat, name, ln in HASH_TYPES if re.match(pat, h, re.I)]
    if not cands:
        cands = [{"type": "غير معروف", "confidence": "-"}]
    out = {"value": h, "length": len(h), "candidates": cands,
           "looks_hex": bool(re.match(r"^[a-fA-F0-9]+$", h)),
           "reference_links": {"CrackStation": "https://crackstation.net/",
                               "Hashes.com": "https://hashes.com/en/decrypt/hash",
                               "CMD5": "https://www.cmd5.org/"}}
    if len(h) == 32:
        out["note"] = "32 حرفاً سادس عشري = MD5 أو NTLM (شائع جداً في تسريبات Windows)."
    return out

# ---------------------------------------------------------------- github
def _num(txt):
    """'329k' / '1,234' / '12' -> int"""
    if txt is None:
        return None
    t = str(txt).strip().replace(",", "").lower()
    m = re.match(r"([\d.]+)\s*([kmb])?", t)
    if not m:
        return None
    n = float(m.group(1))
    mult = {"k": 1e3, "m": 1e6, "b": 1e9}.get(m.group(2) or "", 1)
    return int(n * mult)

def _gh_html(u):
    """Fallback when the GitHub API quota (60/h per IP) is exhausted: parse the public HTML."""
    from core import get_text as _gt
    html = _gt(f"https://github.com/{quote(u)}", timeout=20)
    if "Not Found" in html[:3000] and "p-name" not in html:
        raise FetchError("GitHub: لا يوجد مستخدم بهذا الاسم")

    def grab(pat):
        m = re.search(pat, html, re.S)
        return m.group(1).strip() if m else None

    name = grab(r'<span class="p-name[^"]*"[^>]*>\s*<span[^>]*>\s*([^<]+)') or \
           grab(r'<span class="p-name[^"]*"[^>]*>\s*([^<]+)')
    bio = grab(r'<div class="p-note[^"]*"[^>]*>\s*([^<]+)')
    loc = grab(r'itemprop="homeLocation"[^>]*>.*?<span[^>]*>\s*([^<]+)')
    followers = _num(grab(r'<span class="text-bold[^"]*">([\d,\.]+[kmb]?)</span>\s*followers'))
    following = _num(grab(r'<span class="text-bold[^"]*">([\d,\.]+[kmb]?)</span>\s*following'))
    # repositories counter (tab link)
    repos_n = _num(grab(r'tab=repositories[^>]*>.*?<span[^>]*class="Counter[^"]*"[^>]*>\s*([\d,\.]+[kmb]?)'))
    if repos_n is None:
        repos_n = _num(grab(r'Repositories\s*<span[^>]*>\s*([\d,\.]+[kmb]?)'))

    repos = re.findall(r'href="/' + re.escape(u) + r'/([A-Za-z0-9._-]+)"', html)
    seen, lst = set(), []
    for r in repos:
        if r in seen or r in ("followers", "following"):
            continue
        seen.add(r)
        lst.append({"name": r, "url": f"https://github.com/{u}/{r}", "stars": None, "lang": None, "desc": ""})
    out = {"login": u, "name": name or u, "bio": bio, "location": loc,
           "followers": followers, "following": following, "public_repos": repos_n,
           "html_url": f"https://github.com/{u}", "avatar": f"https://github.com/{u}.png",
           "source": "HTML العام (بديل عند تجاوز حد GitHub API المجاني)",
           "languages": {}, "top_repos": lst[:15]}
    return out

def github_user(username):
    u = username.strip().lstrip("@")
    if not re.match(r"^[A-Za-z0-9\-]{2,39}$", u):
        raise FetchError("اسم مستخدم GitHub غير صالح")
    ck = "gh:" + u.lower()
    cached = cache_get(ck, 1800)
    if cached is not None:
        cached = dict(cached)
        cached["cached"] = True
        return cached
    try:
        prof = get_json(f"https://api.github.com/users/{quote(u)}", timeout=15, ttl=1800,
                        headers={"Accept": "application/vnd.github+json"})
    except FetchError as e:
        msg = str(e)
        if "HTTP 403" in msg or "429" in msg or "HTTP 401" in msg:
            out = _gh_html(u)
            cache_set(ck, out, 1800)
            return out
        if "404" in msg:
            raise FetchError("GitHub: لا يوجد مستخدم بهذا الاسم")
        raise FetchError("GitHub: " + msg)
    repos_err = None
    try:
        repos = get_json(f"https://api.github.com/users/{quote(u)}/repos?per_page=100&sort=updated",
                         timeout=15, ttl=1800, headers={"Accept": "application/vnd.github+json"})
    except Exception as e:
        repos = []
        repos_err = str(e)[:120]
    langs = {}
    for r in repos:
        if r.get("language"):
            langs[r["language"]] = langs.get(r["language"], 0) + 1
    out = {"login": prof.get("login"), "name": prof.get("name"), "bio": prof.get("bio"),
           "company": prof.get("company"), "location": prof.get("location"), "blog": prof.get("blog"),
           "twitter": prof.get("twitter_username"), "email": prof.get("email"),
           "public_repos": prof.get("public_repos"), "public_gists": prof.get("public_gists"),
           "followers": prof.get("followers"), "following": prof.get("following"),
           "created_at": prof.get("created_at"), "updated_at": prof.get("updated_at"),
           "avatar": prof.get("avatar_url"), "html_url": prof.get("html_url"),
           "source": "GitHub API",
           "languages": dict(sorted(langs.items(), key=lambda x: -x[1])[:10]),
           "top_repos": [{"name": r["name"], "stars": r["stargazers_count"], "lang": r.get("language"),
                          "desc": (r.get("description") or "")[:120], "url": r["html_url"]}
                         for r in sorted(repos, key=lambda r: -r.get("stargazers_count", 0))[:15]]}
    if not out["top_repos"]:
        # API gave the profile but no repos (quota on the second call) → read them from HTML
        try:
            html_side = _gh_html(u)
            if html_side.get("top_repos"):
                out["top_repos"] = html_side["top_repos"]
                out["repos_source"] = "HTML العام (بديل)"
        except Exception:
            pass
    if repos_err:
        out["repos_warning"] = "تعذر جلب تفاصيل المستودعات من الـAPI: " + repos_err
    cache_set(ck, out, 1800)
    return out

# ---------------------------------------------------------------- dorks
def dork_builder(term, kind="general"):
    term = term.strip()
    if not term:
        raise FetchError("أدخل كلمة أو بريداً أو نطاقاً")
    t = quote(term, safe="")
    q = {
        "general": [f'"{term}"', f'"{term}" filetype:pdf', f'"{term}" -site:facebook.com',
                    f'"{term}" (site:pastebin.com OR site:ghostbin.com)', f'intitle:"{term}"'],
        "email": [f'"{term}"', f'"{term}" site:pastebin.com', f'"{term}" filetype:xlsx OR filetype:csv',
                  f'"{term}" "password"'],
        "domain": [f'site:{term}', f'site:{term} -www', f'site:{term} ext:env OR ext:log OR ext:sql',
                   f'site:{term} inurl:admin', f'link:{term}'],
        "person": [f'"{term}" (site:linkedin.com OR site:facebook.com)', f'"{term}" filetype:pdf',
                   f'"{term}" resume OR CV', f'"{term}" email OR phone'],
        "docs": [f'"{term}" filetype:docx', f'"{term}" filetype:xlsx', f'"{term}" filetype:csv', f'"{term}" filetype:env'],
        "code": [f'"{term}" site:github.com', f'"{term}" site:gitlab.com', f'"{term}" "api_key"'],
    }.get(kind, [f'"{term}"'])
    engines = {"Google": "https://www.google.com/search?q=", "Bing": "https://www.bing.com/search?q=",
               "DuckDuckGo": "https://duckduckgo.com/?q=", "Yandex": "https://yandex.com/search/?text=",
               "Brave": "https://search.brave.com/search?q="}
    return {"term": term, "kind": kind, "dorks": q,
            "links": [{"engine": e, "url": b + quote(d)} for d in q for e, b in list(engines.items())[:3]]}
