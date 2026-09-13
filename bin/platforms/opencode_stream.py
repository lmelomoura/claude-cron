#!/usr/bin/env python3
"""OpenCode `run --format json` events -> Claude Code stream-json, one line at
a time.

`opencode run --format json` prints one event per line: step_start, text,
tool_use (already completed), step_finish (tokens and cost per step), error.
Every reader in this scheduler -- the watchdog, turn_is_over, bind_session,
the classifier, the dashboard's Timeline and Terminal -- reads the stream-json
shape Claude Code emits. This filter turns the one into the other at the
boundary, so none of those readers learns a third dialect. It is the sibling
of openai_stream.py and solves the same problems the same way.

Pure and unbuffered: stdin in, stdout out, one canonical line per OpenCode
event that has a translation, flushed at once. Two readers depend on that
flush: the Terminal follows the file live, and the watchdog measures it --
including its new rule that a stream still EMPTY after the stall window is a
dead run. The first OpenCode event (step_start) arrives only when the model
starts answering, so the init line it becomes must reach the file the moment
it arrives, never after a completed tool or a closed step. Every raw line is
copied to --raw-out BEFORE anything is done with it, so a line that is not
JSON, or an event this filter has never seen, is copied and skipped.

The other two things it knows: the catalog (--catalog, config/models.json:
whether the model has a price, in which case the CLI's own per-step `cost`
is reported) and the price table (--pricing, config/pricing.json: the
operator's row, from which an unpriced model is estimated with the CLI's own
formula). Zero in the catalog is UNKNOWN, never free: measured, a provider
with no price configured lists the same zeros as a free model -- and so is
a priced model whose steps carried no numeric `cost` at all, which falls
through to the estimate, then to none, instead of reporting a silent zero.

At EOF, only a turn that ended on an auto-rejected ask (measured 04, 18)
becomes an error result naming the tool. A rule denial (measured 23) does
not end the turn, so an EOF after one is a killed run left to the salvage
path, the same as any other EOF with no result.
"""
import argparse
import json
import sys

OUTPUT_CAP = 8192               # bytes of a tool's output kept in a tool_result

# The tool names Claude Code uses, so the Timeline draws an OpenCode run the
# way it draws the other two (measured roster: 06, 22).
CANONICAL = {"bash": "Bash", "edit": "Edit", "write": "Write", "read": "Read", "glob": "Glob",
             "grep": "Grep", "list": "LS", "webfetch": "WebFetch", "websearch": "WebSearch",
             "task": "Task", "todowrite": "TodoWrite", "skill": "Skill"}

# The two denial phrases the CLI puts in `state.error` (measured 04/18 and 23).
REJECTED = "The user rejected permission"
RULED_OUT = "The user has specified a rule which prevents"


def canonical_name(tool):
    return CANONICAL.get(tool or "", tool or "tool")


def denial_of(state):
    """True when a tool's terminal state is one of the two measured denials."""
    if not isinstance(state, dict) or state.get("status") != "error":
        return False
    err = state.get("error")
    return isinstance(err, str) and (err.startswith(REJECTED) or err.startswith(RULED_OUT))


def rejection_of(state):
    """True when a tool's terminal state is specifically the auto-rejected-ask
    denial (measured 04, 18) -- narrower than denial_of, which also matches
    the rule denial (measured 23) that does NOT end the turn at EOF."""
    if not isinstance(state, dict) or state.get("status") != "error":
        return False
    err = state.get("error")
    return isinstance(err, str) and err.startswith(REJECTED)


def load_price(path, model):
    """The per-1M row for `model` in the table's `opencode` block, or None: no
    file, no row, or a null in any of the three billed fields. `cache_write`
    may be absent (0). A row of ZEROS is a price (the operator declaring a
    free model), unlike a zero in the catalog."""
    try:
        with open(path, encoding="utf-8") as fh:
            table = json.load(fh)
    except Exception:  # noqa: BLE001 -- a missing or broken table is "no price"
        return None
    row = (table.get("opencode") or {}).get(model) if isinstance(table, dict) else None
    if not isinstance(row, dict):
        return None
    prices = {}
    for key in ("input", "cached_input", "output"):
        v = row.get(key)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None
        prices[key] = float(v)
    cw = row.get("cache_write", 0)
    prices["cache_write"] = float(cw) if isinstance(cw, (int, float)) and not isinstance(cw, bool) else 0.0
    return prices


def catalog_priced(path, model):
    """True when config/models.json's `opencode` catalog prices the model
    (`priced: true`, written by resolve_models_opencode when any of the four
    catalog prices is above zero)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:  # noqa: BLE001
        return False
    block = data.get("opencode") if isinstance(data, dict) else None
    for m in (block or {}).get("models") or []:
        if isinstance(m, dict) and m.get("id") == model:
            return m.get("priced") is True
    return False


def _n(v):
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


def tokens_of(part):
    """The five counters of a step_finish part, as ints, missing = 0."""
    t = part.get("tokens") if isinstance(part, dict) else None
    t = t if isinstance(t, dict) else {}
    cache = t.get("cache") if isinstance(t.get("cache"), dict) else {}
    return {"input": _n(t.get("input")), "cached": _n(cache.get("read")),
            "cache_write": _n(cache.get("write")), "output": _n(t.get("output")),
            "reasoning": _n(t.get("reasoning"))}


def estimate(tokens, price):
    """USD for the run at `price` (USD per 1,000,000 tokens), with the CLI's
    own formula (measured 24b, 24c, 34): `input` already excludes the cache,
    reasoning is billed at the output price, cached input at the cache price.
    None without a price."""
    if price is None:
        return None
    usd = (tokens["input"] * price["input"] + (tokens["output"] + tokens["reasoning"]) * price["output"]
           + tokens["cached"] * price["cached_input"] + tokens["cache_write"] * price["cache_write"])
    return round(usd / 1_000_000, 6)


class Normalizer:
    """One OpenCode event in, zero or more canonical events out."""

    def __init__(self, model, permission, cwd, priced, price):
        self.model, self.permission, self.cwd = model, permission, cwd
        self.priced, self.price = bool(priced), price
        self.session = ""
        self.inited = False
        self.assistant_events = 0   # what `result.num_turns` reports
        self.last_text = ""         # the last text part: `result.result`
        self.tokens = {"input": 0, "cached": 0, "cache_write": 0, "output": 0, "reasoning": 0}
        self.cost = 0.0             # the CLI's own per-step cost, summed
        self.costed_steps = 0       # step_finish events that carried a numeric cost
        self.steps = 0              # step_finish events seen
        self.last_reason = ""       # the last step_finish reason
        self.last_rejected = False  # the LAST tool event was an auto-rejected ask, not a rule denial
        self.denials = []           # permission_denials on the final event
        self.done = False           # a result has been emitted

    # -- envelopes ---------------------------------------------------------
    def _msg(self, role, blocks):
        return {"type": "assistant" if role == "assistant" else "user",
                "message": {"role": role, "content": blocks},
                "session_id": self.session}

    def _assistant(self, blocks):
        self.assistant_events += 1
        return self._msg("assistant", blocks)

    def _init(self, ev):
        """The FIRST line, from the first event that names the session,
        whatever its type: session_from_stream reads five lines and stops,
        and the watchdog wants a byte the moment the CLI starts talking."""
        self.session = ev.get("sessionID") or ""
        self.inited = True
        return {"type": "system", "subtype": "init", "session_id": self.session,
                "model": self.model, "platform": "opencode",
                "permissionMode": self.permission, "cwd": self.cwd, "tools": []}

    # -- tools -------------------------------------------------------------
    def _tool(self, part):
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        name = canonical_name(part.get("tool"))
        call = part.get("callID") or part.get("id") or ""
        inp = state.get("input") if isinstance(state.get("input"), dict) else {}
        is_error = state.get("status") == "error"
        out = state.get("error") if is_error else state.get("output")
        out = out if isinstance(out, str) else ""
        if len(out.encode("utf-8")) > OUTPUT_CAP:
            out = out.encode("utf-8")[:OUTPUT_CAP].decode("utf-8", errors="ignore") + "\n...[truncated]"
        if denial_of(state):
            self.denials.append({"tool_name": name, "tool_use_id": call, "tool_input": inp})
        self.last_rejected = rejection_of(state)   # only an auto-rejected ask can end the turn at EOF
        return [self._assistant([{"type": "tool_use", "id": call, "name": name, "input": inp}]),
                self._msg("user", [{"type": "tool_result", "tool_use_id": call,
                                    "content": out, "is_error": is_error}])]

    # -- the final event ---------------------------------------------------
    def _result(self, error=None):
        self.done = True
        base = {"type": "result", "session_id": self.session, "platform": "opencode",
                "num_turns": self.assistant_events, "permission_denials": list(self.denials),
                "usage": {"input_tokens": self.tokens["input"],
                          "cache_read_input_tokens": self.tokens["cached"],
                          "cache_creation_input_tokens": self.tokens["cache_write"],
                          "output_tokens": self.tokens["output"] + self.tokens["reasoning"]}}
        cost, basis = self._cost()          # a failed run keeps the cost the CLI already reported
        if error is None:
            base.update({"subtype": "success", "is_error": False, "result": self.last_text,
                         "total_cost_usd": cost, "cost_basis": basis,
                         "tokens": dict(self.tokens), "api_error_status": None})
        else:
            msg, status = error
            base.update({"subtype": "error_during_execution", "is_error": True, "result": msg,
                         "total_cost_usd": cost, "cost_basis": basis,
                         "tokens": dict(self.tokens) if self.steps else None,
                         "api_error_status": status})
        return base

    def _cost(self):
        """(total_cost_usd, cost_basis). The CLI's number when the catalog
        prices the model AND at least one step_finish actually carried a
        numeric `cost` (self.costed_steps); the operator's table when it
        does not; unknown otherwise. A priced model whose steps never
        carried a numeric cost falls through to the estimate instead of
        reporting a silent zero. A run with no step_finish at all has no
        tokens to price."""
        if not self.steps:
            return None, "none"
        if self.priced and self.costed_steps:
            # the sum of the CLI's per-step numbers at their own precision,
            # twelve decimals (the estimate below stays at six)
            return round(self.cost, 12), "reported"
        est = estimate(self.tokens, self.price)
        return (est, "estimated") if est is not None else (None, "none")

    # -- the feed ----------------------------------------------------------
    def feed(self, ev):
        out = []
        if not self.inited and ev.get("sessionID"):
            out.append(self._init(ev))
        kind = ev.get("type")
        # A rejection only ends the turn at EOF if nothing followed it: any
        # event that is not another tool_use, step_finish, or error (a new
        # step_start, more text, ...) means the run kept going past it, so
        # finish() must not read the stale rejection as how the run ended.
        if kind not in ("tool_use", "step_finish", "error"):
            self.last_rejected = False
        part = ev.get("part") if isinstance(ev.get("part"), dict) else {}
        if kind == "text":
            text = part.get("text") or ""
            self.last_text = text
            out.append(self._assistant([{"type": "text", "text": text}]))
        elif kind == "tool_use":
            out.extend(self._tool(part))
        elif kind == "step_finish":
            self.steps += 1
            t = tokens_of(part)
            for k in self.tokens:
                self.tokens[k] += t[k]
            c = part.get("cost")
            if isinstance(c, (int, float)) and not isinstance(c, bool):
                self.cost += float(c)
                self.costed_steps += 1
            # A missing/empty reason (malformed) is treated like "tool-calls":
            # more of the turn may still be coming, so accumulate and emit
            # nothing, rather than ending the run as "the model stopped: unknown".
            reason = part.get("reason") or "tool-calls"
            self.last_reason = reason
            if reason == "stop" and not self.done:
                out.append(self._result())
            elif reason != "tool-calls" and not self.done:
                # Not measured (length, error, content-filter, ...): the model
                # stopped for a reason that is not "I am done".
                out.append(self._result(error=("the model stopped: " + reason, None)))
        elif kind == "error" and not self.done:
            err = ev.get("error") if isinstance(ev.get("error"), dict) else {}
            data = err.get("data") if isinstance(err.get("data"), dict) else {}
            msg = data.get("message") if isinstance(data.get("message"), str) else (err.get("name") or "error")
            ref = data.get("ref")
            if isinstance(ref, str) and ref:
                msg += " (ref " + ref + ")"
            status = data.get("statusCode")
            status = status if isinstance(status, int) and not isinstance(status, bool) else None
            out.append(self._result(error=(msg, status)))
        # step_start and anything not seen yet: nothing beyond the init line
        return out

    def finish(self):
        """EOF. A turn that ended on an auto-rejected ask (measured 04, 18:
        the LAST tool event was rejected, and the step closed on
        `tool-calls`) is an error that names the tool -- never a silent,
        result-less run the salvage would read as merely killed. A rule
        denial (measured 23) does NOT end the turn -- the model keeps
        going -- so an EOF after one, like any other EOF without a result,
        is left to the salvage path."""
        if self.done or not self.last_rejected or self.last_reason != "tool-calls":
            return []
        d = self.denials[-1]
        msg = "the turn ended on a rejected permission: " + d["tool_name"]
        detail = d.get("tool_input") or {}
        if isinstance(detail, dict) and detail.get("command"):
            msg += " (" + str(detail["command"]) + ")"
        return [self._result(error=(msg, None))]


def main(argv=None):
    ap = argparse.ArgumentParser(description="OpenCode JSON on stdin -> stream-json on stdout")
    ap.add_argument("--model", required=True, help="the provider/model the run asked for")
    ap.add_argument("--permission", required=True, help="the run's permission_mode")
    ap.add_argument("--cwd", required=True, help="the run's working directory")
    ap.add_argument("--catalog", default="", help="config/models.json (whether the model is priced)")
    ap.add_argument("--pricing", default="", help="config/pricing.json (the operator's opencode rows)")
    ap.add_argument("--raw-out", default="", help="where every raw line is copied")
    args = ap.parse_args(argv)
    priced = catalog_priced(args.catalog, args.model) if args.catalog else False
    price = load_price(args.pricing, args.model) if args.pricing else None
    norm = Normalizer(args.model, args.permission, args.cwd, priced, price)
    raw = open(args.raw_out, "ab") if args.raw_out else None
    out = sys.stdout

    def emit(events):
        for e in events:
            out.write(json.dumps(e) + "\n")     # ASCII-safe whatever the locale
        out.flush()                             # the watchdog and the Terminal read the file live

    try:
        # Bytes in, so a locale with no UTF-8 (launchd's default) can neither
        # refuse a curly quote on the way in nor mangle the raw copy.
        for bline in sys.stdin.buffer:
            if raw is not None:
                raw.write(bline if bline.endswith(b"\n") else bline + b"\n")
                raw.flush()
            line = bline.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:  # noqa: BLE001 -- copied above, skipped here
                continue
            if isinstance(ev, dict):
                emit(norm.feed(ev))
        emit(norm.finish())
    finally:
        if raw is not None:
            raw.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
