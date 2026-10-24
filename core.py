"""Core helpers: HTTP client, cache, rate limit, json handling. Stdlib only."""
import json, time, threading, gzip, zlib, io, socket, ssl, urllib.request, urllib.error, urllib.parse, http.client, random

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
UA_BOT = "OSINT-Console/1.0 (self-hosted research tool)"
MAX_BYTES = 2_500_000

_cache = {}
_lock = threading.Lock()

def cache_get(k, ttl):
    with _lock:
        v = _cache.get(k)
        if v and time.time() - v[1] < ttl:
            return v[0]
    return None

def cache_set(k, v, ttl=300):
    with _lock:
        if len(_cache) > 800:
            for kk in list(_cache)[:300]:
                _cache.pop(kk, None)
        _cache[k] = (v, time.time())

class FetchError(Exception):
    pass

def safe_fetch(url, timeout=15, max_bytes=MAX_BYTES, headers=None, method="GET", data=None,
               ua=UA, allow_redirects=True):
    """GET/POST returning (status, headers_dict, body_bytes, final_url). Never raises on HTTP status."""
    h = {"User-Agent": ua, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9",
         "Accept-Encoding": "gzip, deflate"}
    if headers:
        h.update(headers)
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPRedirectHandler() if allow_redirects else NoRedirect())
    try:
        r = opener.open(req, timeout=timeout)
        status, hdrs, raw, final = r.status, dict(r.headers), r.read(max_bytes), r.geturl()
    except urllib.error.HTTPError as e:
        status, hdrs, final = e.code, dict(e.headers or {}), url
        try:
            raw = e.read(max_bytes)
        except Exception:
            raw = b""
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, http.client.HTTPException, OSError) as e:
        raise FetchError(f"{type(e).__name__}: {str(e)[:160]}")
    raw = _decompress(raw, (hdrs.get("Content-Encoding") or "").lower())
    return status, hdrs, raw, final

def _decompress(raw, enc=""):
    """Handle gzip/deflate by header OR by magic bytes (some CDNs omit the header)."""
    if not raw:
        return raw
    def try_gzip(b):
        try:
            return gzip.decompress(b)
        except Exception:
            try:
                import zlib as _z
                return _z.decompress(b, 16 + _z.MAX_WBITS)
            except Exception:
                return None
    def try_zlib(b):
        for wbits in (-_zlib().MAX_WBITS, _zlib().MAX_WBITS):
            try:
                return _zlib().decompress(b, wbits)
            except Exception:
                continue
        return None
    if raw[:2] == b"\x1f\x8b":
        return try_gzip(raw) or raw
    if raw[:2] in (b"x\x9c", b"x\x01", b"x\xda", b"x^"):
        return try_zlib(raw) or raw
    if "gzip" in enc:
        return try_gzip(raw) or raw
    if "deflate" in enc:
        return try_zlib(raw) or raw
    return raw

def _zlib():
    import zlib as z
    return z

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def get_json(url, timeout=15, ttl=0, **kw):
    if ttl:
        c = cache_get("json:" + url, ttl)
        if c is not None:
            return c
    st, hd, raw, _ = safe_fetch(url, timeout=timeout, **kw)
    if st >= 400:
        raise FetchError(f"HTTP {st} from {urllib.parse.urlsplit(url).netloc}")
    try:
        v = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        raise FetchError(f"رد غير صالح من {urllib.parse.urlsplit(url).netloc}")
    if ttl:
        cache_set("json:" + url, v, ttl)
    return v

def get_text(url, timeout=15, ttl=0, **kw):
    if ttl:
        c = cache_get("text:" + url, ttl)
        if c is not None:
            return c
    st, hd, raw, _ = safe_fetch(url, timeout=timeout, **kw)
    if st >= 400:
        raise FetchError(f"HTTP {st} from {urllib.parse.urlsplit(url).netloc}")
    t = raw.decode("utf-8", "replace")
    if ttl:
        cache_set("text:" + url, t, ttl)
    return t

# ---- simple token bucket per host (politeness) ----
_buckets = {}
def polite(host, per_sec=4.0):
    with _lock:
        b = _buckets.setdefault(host, [0.0, 0])
        now = time.time()
        b[0] = max(0.0, b[0] + (now - b[1]) * per_sec)
        b[1] = now
        if b[0] < 1:
            wait = (1 - b[0]) / per_sec
            b[0] = 0
        else:
            b[0] -= 1
            wait = 0
    if wait > 0:
        time.sleep(min(wait, 1.0))

def clean(d):
    """JSON-safe conversion."""
    if isinstance(d, dict):
        return {str(k): clean(v) for k, v in d.items()}
    if isinstance(d, (list, tuple, set)):
        return [clean(x) for x in d]
    if isinstance(d, bytes):
        return d.decode("utf-8", "replace")
    if isinstance(d, (str, int, float, bool)) or d is None:
        return d
    return str(d)
