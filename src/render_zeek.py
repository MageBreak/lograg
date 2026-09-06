"""Render Zeek records into sentences and APPEND to documents.jsonl.

Runs after render.py. Same document schema, same file, so index.py sees
host and network events as one corpus.

Note the Zeek UID in every sentence. Zeek assigns one UID per connection
and repeats it across dns.log, ssl.log, http.log for that same flow. Putting
it in the text means a question containing a UID pulls every protocol record
for that connection via exact BM25 match - free cross-log correlation.
"""
from __future__ import annotations
import json
from collections import Counter

IN  = "data/parsed/zeek_events.jsonl"
OUT = "data/parsed/documents.jsonl"      # appended, not overwritten

MAX_PER_SHAPE = 6


def g(d, *names, default=""):
    for n in names:
        v = d.get(n)
        if v not in (None, ""):
            return v
    return default


def nbytes(v):
    """Human-readable byte counts. '142208' is harder to reason about
    than '142.2 KB', both for a reader and for a language model."""
    try:
        v = int(v)
    except (TypeError, ValueError):
        return "unknown"
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024:
            return f"{v:,.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB"


def _conn(d):
    svc = g(d, "service", default="no service identified").replace(",", ", ")
    dur = g(d, "duration")
    dur_s = f" over {float(dur):.1f}s" if dur else ""
    return (f"Connection {g(d,'id_orig_h')}:{g(d,'id_orig_p')} -> "
            f"{g(d,'id_resp_h')}:{g(d,'id_resp_p')} over "
            f"{g(d,'proto',default='?')} (service: {svc}), "
            f"state {g(d,'conn_state',default='?')}, "
            f"{nbytes(g(d,'orig_bytes',default=0))} sent / "
            f"{nbytes(g(d,'resp_bytes',default=0))} received{dur_s}. "
            f"UID {g(d,'uid')}.")


def _dns(d):
    ans = g(d, "answers", default=[])
    ans = ", ".join(map(str, ans)) if isinstance(ans, list) else str(ans)
    return (f"DNS query for {g(d,'query',default='?')} "
            f"(type {g(d,'qtype_name',default='?')}) from {g(d,'id_orig_h')} "
            f"to {g(d,'id_resp_h')}; response "
            f"{g(d,'rcode_name',default='?')}, answers: {ans or 'none'}. "
            f"UID {g(d,'uid')}.")


def _http(d):
    return (f"HTTP {g(d,'method',default='?')} from {g(d,'id_orig_h')} to "
            f"{g(d,'host', 'id_resp_h', default='?')}"
            f"{g(d,'uri',default='')} — status "
            f"{g(d,'status_code',default='?')} "
            f"{g(d,'status_msg',default='')}, user-agent "
            f"\"{g(d,'user_agent',default='none')}\", response "
            f"{nbytes(g(d,'response_body_len',default=0))}. "
            f"UID {g(d,'uid')}.")


def _ssl(d):
    return (f"TLS session {g(d,'id_orig_h')} -> {g(d,'id_resp_h')}:"
            f"{g(d,'id_resp_p')} to server name "
            f"{g(d,'server_name',default='none presented')}, "
            f"{g(d,'version',default='?')} cipher "
            f"{g(d,'cipher',default='?')}, "
            f"established: {g(d,'established',default='?')}, "
            f"JA3 {g(d,'ja3',default='none')}. UID {g(d,'uid')}.")


def _dce_rpc(d):
    return (f"DCE/RPC call {g(d,'id_orig_h')} -> {g(d,'id_resp_h')}:"
            f"{g(d,'id_resp_p')} — endpoint "
            f"{g(d,'endpoint',default='?')}, operation "
            f"{g(d,'operation',default='?')}. UID {g(d,'uid')}.")


def _kerberos(d):
    # ~10 of 35 kerberos records in this dataset carry only the connection
    # tuple - no client, service or request_type. Rendering those produces
    # "Kerberos ? from X for client ?" which is pure noise in a retrieval
    # slot. Return None and let main() drop them.
    if not (g(d, "client") or g(d, "service") or g(d, "request_type")):
        return None
    return (f"Kerberos {g(d,'request_type',default='?')} request from "
            f"{g(d,'id_orig_h')} to {g(d,'id_resp_h')} — client "
            f"{g(d,'client',default='?')} requesting service "
            f"{g(d,'service',default='?')}, success "
            f"{g(d,'success',default='?')}"
            + (f", error: {g(d,'error_msg')}" if g(d, "error_msg") else "")
            + f". UID {g(d,'uid')}.")

def _smb_files(d):
    return (f"SMB file {g(d,'action',default='access')} by "
            f"{g(d,'id_orig_h')} on {g(d,'id_resp_h')}: path "
            f"{g(d,'path',default='?')}\\{g(d,'name',default='?')}, "
            f"size {nbytes(g(d,'size',default=0))}. UID {g(d,'uid')}.")


def _smb_mapping(d):
    return (f"SMB share mapped by {g(d,'id_orig_h')} on {g(d,'id_resp_h')}: "
            f"{g(d,'path',default='?')} "
            f"(type {g(d,'share_type',default='?')}). UID {g(d,'uid')}.")


def _notice(d):
    return (f"Zeek notice: {g(d,'note',default='?')} — "
            f"{g(d,'msg',default='')} "
            f"[{g(d,'sub',default='')}] src {g(d,'src',default='?')}, "
            f"dst {g(d,'dst',default='?')}.")


RENDERERS = {
    "conn": _conn, "dns": _dns, "http": _http, "ssl": _ssl,
    "dce_rpc": _dce_rpc, "kerberos": _kerberos,
    "smb_files": _smb_files, "smb_mapping": _smb_mapping,
    "notice": _notice,
}


def render(rec):
    d = rec["data"]
    fn = RENDERERS.get(rec["event_name"])
    body = fn(d) if fn else json.dumps(d)
    if body is None:
        return None
    head = f"[{rec['ts']}] sensor={rec['host']} zeek {rec['event_name']}"
    return f"{head} - {body}"

def shape(rec):
    """Dedupe key: same endpoints and stream say the same thing."""
    d = rec["data"]
    return (rec["host"], rec["event_name"], d.get("id_orig_h"),
            d.get("id_resp_h"), d.get("id_resp_p"),
            d.get("query"), d.get("server_name"), d.get("endpoint"))


def main():
    seen, n_out, n_dedup, n_empty = Counter(), 0, 0, 0

    with open(IN) as fin, open(OUT, "a") as fout:     # APPEND
        for line in fin:
            rec = json.loads(line)

            s = shape(rec)
            seen[s] += 1
            if seen[s] > MAX_PER_SHAPE:
                n_dedup += 1
                continue

            text = render(rec)
            if text is None:          # renderer refused this record
                n_empty += 1
                continue

            fout.write(json.dumps({
                "chunk_id": f"{rec['file']}#{rec['record_id']}",
                "text":     text,
                "ts":       rec["ts"],
                "host":     rec["host"],
                "event_id": rec["event_id"],
                "source":   "zeek",
                "tactic":   rec["tactic"],
                "file":     rec["file"],
            }) + "\n")
            n_out += 1

    print(f"appended {n_out} zeek documents to {OUT} "
          f"({n_dedup} deduped, {n_empty} empty)")


if __name__ == "__main__":
    main()
