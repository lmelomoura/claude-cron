#!/usr/bin/env python3
"""A throwaway Jira stand-in, just enough to exercise round-cap.sh end to end.

Scenario per issue key, set in SCEN:
  rounds        how many "Change Requested" entries the changelog holds
  noise         extra non-matching changelog entries (to force pagination)
  routes        transitions offered from the *current* status
  changelog_500 serve an error instead of the changelog
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

SCEN = {
    # fresh ticket, no rounds spent
    "T-0": dict(rounds=0, noise=0, routes=["In Progress", "Blocked"]),
    # one round spent, still under a cap of 2
    "T-1": dict(rounds=1, noise=0, routes=["In Progress", "Blocked"]),
    # at the cap -> must be refused and parked
    "T-2": dict(rounds=2, noise=0, routes=["In Progress", "Blocked"]),
    # at the cap, but the rounds sit past the first changelog page
    "T-PAGE": dict(rounds=2, noise=250, routes=["In Progress", "Blocked"]),
    # changelog unreadable -> must fail OPEN
    "T-ERR": dict(rounds=9, noise=0, routes=["In Progress", "Blocked"], changelog_500=True),
    # no direct route to Blocked -> must go via In Progress
    "T-INDIRECT": dict(rounds=2, noise=0, routes=["In Progress"], blocked_after_ip=True),
    # nowhere to park -> must refuse without wedging
    "T-NOPARK": dict(rounds=2, noise=0, routes=[]),
    # capped, used only to prove a dry run refuses without writing
    "T-DRY": dict(rounds=2, noise=0, routes=["In Progress", "Blocked"]),
}

STATE = {k: {"status": "Change Requested", "comments": [], "moves": []} for k in SCEN}


def changelog(key):
    s = SCEN[key]
    vals = []
    for i in range(s["noise"]):
        vals.append({"items": [{"field": "assignee", "toString": f"n{i}"}]})
    for i in range(s["rounds"]):
        vals.append({"items": [{"field": "status", "fromString": "In Review - DEV",
                                "toString": "Change Requested"}]})
        vals.append({"items": [{"field": "status", "fromString": "Change Requested",
                                "toString": "In Progress"}]})
    return vals


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _key(self, path):
        # /rest/api/3/issue/<KEY>/... -> index 4
        parts = path.strip("/").split("/")
        return parts[4] if len(parts) > 4 else None

    def do_GET(self):
        u = urlparse(self.path)
        key = self._key(u.path)
        if u.path.endswith("/myself"):
            return self._send(200, {"accountId": "test"})
        if key not in SCEN:
            return self._send(404, {"err": "no such key"})
        if u.path.endswith("/changelog"):
            if SCEN[key].get("changelog_500"):
                return self._send(500, {"err": "boom"})
            q = parse_qs(u.query)
            start = int(q.get("startAt", ["0"])[0])
            mx = int(q.get("maxResults", ["100"])[0])
            vals = changelog(key)
            return self._send(200, {"total": len(vals), "startAt": start,
                                    "maxResults": mx, "values": vals[start:start + mx]})
        if u.path.endswith("/transitions"):
            st = STATE[key]
            routes = list(SCEN[key]["routes"])
            if SCEN[key].get("blocked_after_ip") and st["status"] == "In Progress":
                routes = ["Blocked"]
            return self._send(200, {"transitions": [
                {"id": str(100 + i), "to": {"name": r}} for i, r in enumerate(routes)]})
        if u.path.endswith("/comment"):
            return self._send(200, {"comments": STATE[key]["comments"]})
        if u.path.rstrip("/").endswith(key):          # GET issue?fields=status
            return self._send(200, {"fields": {"status": {"name": STATE[key]["status"]}}})
        return self._send(404, {})

    def do_POST(self):
        u = urlparse(self.path)
        key = self._key(u.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else "{}"
        if key not in SCEN:
            return self._send(404, {})
        if u.path.endswith("/comment"):
            try:
                doc = json.loads(raw)["body"]
            except Exception:
                return self._send(400, {"err": "bad ADF"})
            # Reject the shapes real Jira rejects, so a malformed comment fails here too.
            if doc.get("type") != "doc" or not doc.get("content"):
                return self._send(400, {"err": "bad ADF"})
            for para in doc["content"]:
                if para.get("type") != "paragraph" or not para.get("content"):
                    return self._send(400, {"err": "empty paragraph"})
            STATE[key]["comments"].append(doc)
            return self._send(201, {"id": "1"})
        if u.path.endswith("/transitions"):
            tid = json.loads(raw)["transition"]["id"]
            st = STATE[key]
            routes = list(SCEN[key]["routes"])
            if SCEN[key].get("blocked_after_ip") and st["status"] == "In Progress":
                routes = ["Blocked"]
            idx = int(tid) - 100
            if idx < 0 or idx >= len(routes):
                return self._send(400, {"err": "illegal transition"})
            st["status"] = routes[idx]
            st["moves"].append(routes[idx])
            return self._send(204)
        return self._send(404, {})


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1])
    srv = HTTPServer(("127.0.0.1", port), H)
    import threading

    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # Dump state on demand so the shell test can assert on it.
    import signal

    def dump(*a):
        out = {k: {"status": v["status"], "comments": len(v["comments"]),
                   "moves": v["moves"],
                   "comment_text": (v["comments"][0]["content"][0]["content"][0]["text"][:60]
                                    if v["comments"] else "")}
               for k, v in STATE.items()}
        open(sys.argv[2], "w").write(json.dumps(out, indent=2))

    signal.signal(signal.SIGUSR1, dump)
    signal.pause()
