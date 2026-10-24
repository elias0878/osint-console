"""Shared route table used by both the local server and the Vercel serverless function.
`dispatch(path, args)` is stateless and returns (http_status, payload_dict).
"""
import json, os, time

import core
import modules_net as net
import modules_identity as ident
import modules_intel as intel
import modules_extra as extra
import sweep as sweep_engine
from core import FetchError

SERVERLESS = os.environ.get("SERVERLESS") == "1"


def ja(x):
    return json.dumps(core.clean(x), ensure_ascii=False).encode("utf-8")


def guard(fn, *a, **kw):
    t0 = time.time()
    try:
        return {"ok": True, "data": core.clean(fn(*a, **kw)), "ms": int((time.time() - t0) * 1000)}
    except FetchError as e:
        return {"ok": False, "soft": True, "error": str(e), "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"ok": False, "soft": False, "error": f"{type(e).__name__}: {str(e)[:200]}",
                "ms": int((time.time() - t0) * 1000)}


def _floats(s, n):
    parts = [p.strip() for p in str(s).replace(";", ",").split(",")]
    if len(parts) < n:
        raise FetchError("أدخل القيم مفصولة بفواصل")
    try:
        return [float(x) for x in parts[:n]]
    except ValueError:
        raise FetchError("قيم رقمية غير صالحة")


def _need(args, name):
    v = args.get(name)
    if v is None or not str(v).strip():
        raise FetchError(f"المعامل «{name}» مطلوب")
    return str(v).strip()


def plan(q, kind="auto"):
    """Which modules apply to this target (used by the browser-side orchestrator)."""
    q2 = sweep_engine.normalize(q)
    k = kind if kind and kind != "auto" else sweep_engine.detect(q2)
    items = sweep_engine.build_plan(q2, k)
    return {"target": q2, "kind": k, "total": len(items),
            "modules": [{"id": i["id"], "name": i["name"], "skip": i["skip"],
                         "runnable": bool(i["fn"]), "q": i.get("q") or q2} for i in items]}


def module_dispatch(mid, args):
    """Run one module by id with the same shapes the UI already understands."""
    def need(n):
        return _need(args, n)

    q = args.get("q", "").strip()
    table = {
        "dns": lambda: net.dns_lookup(need("q")),
        "rdap": lambda: net.rdap_lookup(need("q")),
        "subdomains": lambda: net.subdomains(need("q")),
        "ip": lambda: net.ip_intel(need("q")),
        "tls": lambda: net.tls_info(need("q")),
        "http": lambda: net.http_probe(need("q")),
        "robots": lambda: net.robots(need("q")),
        "wayback": lambda: net.wayback(need("q")),
        "ports": lambda: net.port_check(need("q"),
                                        [int(x) for x in args["ports"].split(",") if x.strip().isdigit()]
                                        if args.get("ports") else None),
        "urlscan": lambda: net.urlscan_search(need("q")),
        "flight": lambda: net.flight_nearby(*_floats(need("q"), 2),
                                            *(_floats(args["dist"], 1) if args.get("dist") else [40])),
        "geoip": lambda: net.geoip_self(),
        "username": lambda: ident.username_scan(need("q")),
        "email": lambda: ident.email_intel(need("q")),
        "phone": lambda: ident.phone_intel(need("q"), int(args.get("cc", 49))),
        "password": lambda: ident.password_check(args.get("q", "")),
        "hash": lambda: ident.hash_identify(need("q")),
        "github": lambda: ident.github_user(need("q")),
        "dorks": lambda: ident.dork_builder(need("q"), args.get("kind_q") or args.get("kind", "general")),
        "cve": lambda: intel.cve_lookup(need("q")),
        "crypto": lambda: intel.crypto_lookup(need("q")),
        "geo": lambda: intel.geocode(need("q")),
        "revgeo": lambda: intel.reverse_geocode(*_floats(need("q"), 2)),
        "distance": lambda: intel.distance(*_floats(need("q"), 4)),
        "weather": lambda: intel.weather(*_floats(need("q"), 2)),
        "earthquakes": lambda: intel.earthquakes(*(need("q").split("/") + ["day"])[:2]),
        "company": lambda: intel.company_lookup(need("q")),
        "catalog": lambda: intel.catalog_search(args.get("q", ""), args.get("cat", ""),
                                                int(args.get("limit", 200))),
        "whois": lambda: extra.whois_lookup(need("q")),
        "certs": lambda: extra.cert_issuers(need("q")),
        "reverseip": lambda: extra.reverse_ip(need("q")),
        "threat": lambda: extra.threat_check(need("q")),
        "oui": lambda: extra.oui_lookup(need("q")),
        "wikipedia": lambda: extra.wikipedia_lookup(need("q"), args.get("lang", "ar")),
        "news": lambda: extra.news_search(need("q"), args.get("timespan", "7d")),
        "investigate": lambda: sweep_engine.run(need("q"), args.get("kind", "auto")),
        "sweep": lambda: sweep_engine.run(need("q"), args.get("kind", "auto")),
    }
    if mid == "ioc":
        txt = args.get("q", "")
        if not txt.strip():
            raise FetchError("الصق نصاً لاستخراج المؤشرات")
        iocs = intel.ioc_extract(txt)
        if args.get("enrich") == "1":
            iocs["enrichment"] = intel.ioc_enrich(iocs)
        return iocs
    fn = table.get(mid)
    if not fn:
        raise FetchError(f"وحدة غير معروفة: {mid}")
    return fn()


def dispatch(path, args):
    """path like '/api/dns' or '/api/health'."""
    name = path[len("/api/"):] if path.startswith("/api/") else path.lstrip("/")
    if name in ("health", ""):
        return 200, {"ok": True, "mode": "serverless" if SERVERLESS else "server",
                     "modules": 36, "version": "1.1.0"}
    if name == "modules":
        from catalog_meta import MODULES, GROUPS
        return 200, {"ok": True, "modules": MODULES, "groups": GROUPS}
    if name == "plan":
        return 200, guard(plan, _need(args, "q"), args.get("kind", "auto"))
    if name == "ioc":
        return 200, guard(lambda: module_dispatch("ioc", args))
    return 200, guard(module_dispatch, name, args)
