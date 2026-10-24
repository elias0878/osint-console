"""Vercel Python serverless entrypoint (WSGI).

Routing:
  /api/<module>?q=...        -> handled here
  /api/plan?q=...            -> list of modules that apply to a target
  /api/health                -> status
The same code powers the local server (server.py) so behaviour is identical.
"""
import json, os, sys, urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SERVERLESS", "1")

import routes  # noqa: E402


def app(environ, start_response):
    try:
        path = environ.get("PATH_INFO") or "/"
        # vercel.json rewrites /api/(.*) -> /api/index?__p=(.*)
        args = {k: v[0] for k, v in urllib.parse.parse_qs(environ.get("QUERY_STRING", "")).items()}
        method = (environ.get("REQUEST_METHOD") or "GET").upper()
        original = args.pop("__p", None)
        if original:
            path = "/api/" + original.strip("/")
        if path.rstrip("/") == "/api/file" and method == "POST":
            try:
                n = int(environ.get("CONTENT_LENGTH") or 0)
                body = environ["wsgi.input"].read(n) if n else b""
                payload = routes.dispatch_file(body, environ.get("CONTENT_TYPE", ""))
                status = 200
            except Exception as e:
                payload = {"ok": False, "error": str(e), "soft": True}
                status = 200
        else:
            status, payload = routes.dispatch(path, args)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        start_response(f"{status} OK" if status == 200 else f"{status} Error", [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("Access-Control-Allow-Origin", "*"),
        ])
        return [body]
    except Exception as e:  # never leak a traceback to the client
        import traceback
        traceback.print_exc()
        body = json.dumps({"ok": False, "error": f"{type(e).__name__}: {str(e)[:180]}"},
                          ensure_ascii=False).encode()
        start_response("500 Internal Server Error", [("Content-Type", "application/json; charset=utf-8"),
                                                     ("Content-Length", str(len(body)))])
        return [body]
