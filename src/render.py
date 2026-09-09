"""Stage 2: normalised records -> natural-language sentences.

Embedding models were trained on prose. They have no idea what
{"EventID":1,"Image":"C:\\...\\powershell.exe"} means, but they have a very
good idea what "powershell.exe was launched by winword.exe" means. This file
is the translation layer, and it does three jobs:

  1. FILTER  - drop infrastructure chatter that carries no security signal
  2. DEDUPE  - collapse repeated identical events so they can't flood top-k
  3. RENDER  - turn each survivor into one readable sentence
"""
from __future__ import annotations
import json
from collections import Counter

IN  = "data/parsed/events.jsonl"
OUT = "data/parsed/documents.jsonl"

# --------------------------------------------------------------------------
# Curation policy
# --------------------------------------------------------------------------
# Event types worth indexing. Everything else (RPC calls 5/6, WFP filter
# events 5158, BITS transfers 59) is infrastructure noise: thousands of
# near-identical records that would crowd out the events that matter.
# Nothing is lost - events.jsonl still holds every record.
KEEP_SYSMON = {1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
               17, 18, 19, 20, 21, 22, 23, 25}
KEEP_SECURITY = {4624, 4625, 4634, 4648, 4657, 4663, 4672, 4688, 4697,
                 4698, 4720, 4728, 4732, 4738, 4768, 4769, 4776,
                 5140, 5145, 7045, 1102, 4719, 4739}

MAX_PER_SHAPE = 5     # keep the first N of any repeated event shape


def keep(rec) -> bool:
    allowed = KEEP_SYSMON if rec["source"] == "sysmon" else KEEP_SECURITY
    return rec["event_id"] in allowed


def shape(rec):
    """Identity of an event ignoring timestamp and PID.

    Two events with the same shape say the same thing. Keeping five of them
    preserves 'this happened repeatedly' while freeing retrieval slots for
    events that happened once - usually the interesting ones.
    """
    d = rec["data"]
    return (rec["host"], rec["source"], rec["event_id"],
            d.get("Image"), d.get("TargetObject"),
            d.get("DestinationIp"), d.get("TargetFilename"),
            d.get("TargetUserName"), d.get("PipeName"))


# --------------------------------------------------------------------------
# Field access
# --------------------------------------------------------------------------
def g(d, *names, default=""):
    """First present key wins. Field names drift between log versions."""
    for n in names:
        v = d.get(n)
        if v not in (None, ""):
            return v
    return default


# --------------------------------------------------------------------------
# Per-event-type templates
# --------------------------------------------------------------------------
def _process(rec, d):
    img    = g(d, "Image", "NewProcessName", default="unknown image")
    pid    = g(d, "ProcessId", "NewProcessId", default="?")
    parent = g(d, "ParentImage", "ParentProcessName", default="unknown parent")
    user   = g(d, "User", "SubjectUserName", default="unknown user")
    cmd    = g(d, "CommandLine")
    s = f"Process {img} (PID {pid}) was created by {parent}, running as {user}."
    if cmd:
        s += f" Command line: {cmd}"
    if g(d, "IntegrityLevel"):
        s += f" Integrity level: {g(d,'IntegrityLevel')}."
    if rec["hashes"].get("sha256"):
        s += f" SHA256: {rec['hashes']['sha256']}"
    return s


def _network(d):
    return (f"Network connection from {g(d,'Image',default='unknown image')} "
            f"(PID {g(d,'ProcessId',default='?')}) as "
            f"{g(d,'User',default='unknown user')}: "
            f"{g(d,'SourceIp')}:{g(d,'SourcePort')} -> "
            f"{g(d,'DestinationIp')}:{g(d,'DestinationPort')} "
            f"over {g(d,'Protocol',default='unknown protocol')}, "
            f"destination host "
            f"{g(d,'DestinationHostname',default='not resolved')}.")


def _dns(d):
    return (f"DNS query for {g(d,'QueryName',default='unknown name')} by "
            f"{g(d,'Image',default='unknown image')} "
            f"(PID {g(d,'ProcessId',default='?')}); answer: "
            f"{g(d,'QueryResults',default='none')}.")


def _file(d, eid):
    verb = {11: "created",
            23: "deleted",
            2:  "changed the creation timestamp of",
            15: "created an alternate data stream on"}[eid]
    s = (f"{g(d,'Image',default='unknown image')} "
         f"(PID {g(d,'ProcessId',default='?')}) {verb} file "
         f"{g(d,'TargetFilename',default='unknown path')}.")
    if eid == 15 and g(d, "Hash"):
        s += f" Stream hash: {g(d,'Hash')}"
    return s


def _registry(d, eid):
    action = {12: "created or deleted key",
              13: "set value",
              14: "renamed key"}[eid]
    s = (f"Registry {action} by {g(d,'Image',default='unknown image')} "
         f"(PID {g(d,'ProcessId',default='?')}) on target "
         f"{g(d,'TargetObject',default='unknown key')}")
    if eid == 13 and g(d, "Details"):
        s += f", value set to {g(d,'Details')}"
    if eid == 14 and g(d, "NewName"):
        s += f", renamed to {g(d,'NewName')}"
    return s + "."


def _imageload(d):
    return (f"{g(d,'Image',default='unknown image')} loaded module "
            f"{g(d,'ImageLoaded',default='unknown module')} "
            f"(signed: {g(d,'Signed',default='unknown')}, signer: "
            f"{g(d,'Signature',default='none')}).")


def _remotethread(d):
    return (f"{g(d,'SourceImage',default='unknown')} "
            f"(PID {g(d,'SourceProcessId',default='?')}) created a remote "
            f"thread in {g(d,'TargetImage',default='unknown')} "
            f"(PID {g(d,'TargetProcessId',default='?')}) at start address "
            f"{g(d,'StartAddress',default='unknown')} "
            f"({g(d,'StartFunction',default='no symbol')}).")


def _procaccess(d):
    return (f"{g(d,'SourceImage',default='unknown')} "
            f"(PID {g(d,'SourceProcessId',default='?')}) opened a handle to "
            f"{g(d,'TargetImage',default='unknown')} "
            f"(PID {g(d,'TargetProcessId',default='?')}) with granted access "
            f"{g(d,'GrantedAccess',default='unknown')}.")


def _pipe(d, eid):
    verb = "created" if eid == 17 else "connected to"
    return (f"{g(d,'Image',default='unknown image')} "
            f"(PID {g(d,'ProcessId',default='?')}) {verb} named pipe "
            f"{g(d,'PipeName',default='unknown pipe')}.")


def _logon(d, eid):
    ok = "succeeded" if eid == 4624 else "FAILED"
    s = (f"Logon {ok} for "
         f"{g(d,'TargetDomainName',default='?')}\\"
         f"{g(d,'TargetUserName',default='?')} "
         f"(logon type {g(d,'LogonType',default='?')}) from "
         f"{g(d,'IpAddress',default='local')} via "
         f"{g(d,'LogonProcessName',default='unknown process')}.")
    if eid == 4625 and g(d, "Status"):
        s += f" Failure status: {g(d,'Status')}."
    return s


def _fallback(rec, d):
    """Unknown event type: emit key=value. Ugly, but never silently drops data."""
    skip = {"RuleName", "UtcTime", "ProcessGuid", "ParentProcessGuid", "LogonGuid"}
    fields = ", ".join(f"{k}={v}" for k, v in d.items()
                       if v not in (None, "") and k not in skip)
    return f"{rec['event_name']} event. {fields}"


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------
def render_body(rec):
    """One sentence describing this event.

    Dispatch is scoped by SOURCE first, then event ID. Event IDs are only
    unique within a provider - Sysmon 14 is a registry key rename, but
    Microsoft-Windows-RPC 14 is something else entirely. Dispatching on the
    ID alone sent RPC events into the registry template and produced
    'Registry event by  on .' with empty fields.
    """
    d, eid, src = rec["data"], rec["event_id"], rec["source"]

    if src == "sysmon":
        if eid == 1:              return _process(rec, d)
        if eid == 3:              return _network(d)
        if eid == 22:             return _dns(d)
        if eid in (2, 11, 15, 23): return _file(d, eid)
        if eid in (12, 13, 14):   return _registry(d, eid)
        if eid == 7:              return _imageload(d)
        if eid == 8:              return _remotethread(d)
        if eid == 10:             return _procaccess(d)
        if eid in (17, 18):       return _pipe(d, eid)
    else:
        if eid == 4688:           return _process(rec, d)
        if eid in (4624, 4625):   return _logon(d, eid)

    return _fallback(rec, d)


def render(rec):
    """Prefix every sentence with when/where/what.

    Dense embeddings are poor at time and identity - two adjacent dates give
    near-identical vectors. Putting host and timestamp in the text lets BM25
    match them exactly. This is why hybrid retrieval works.
    """
    # The source filename is often the most semantically loaded string
    # available - it names the technique, the tool, the CVE. Excluding it
    # made CVE-2020-1472 unretrievable despite the file being indexed.
    scenario = rec["file"].rsplit("/", 1)[-1].replace(".evtx", "").replace("_", " ")
    head = (f"[{rec['ts']}] host={rec['host']} "
            f"{rec['source']} EventID {rec['event_id']} ({rec['event_name']}) "
            f"[scenario: {rec['tactic']} / {scenario}]")
    return f"{head} - {render_body(rec)}"


def main():
    seen = Counter()
    n_in = n_filtered = n_deduped = n_out = 0

    with open(IN) as fin, open(OUT, "w") as fout:
        for line in fin:
            n_in += 1
            rec = json.loads(line)

            if not keep(rec):
                n_filtered += 1
                continue

            s = shape(rec)
            seen[s] += 1
            if seen[s] > MAX_PER_SHAPE:
                n_deduped += 1
                continue

            doc = {
                "chunk_id": f"{rec['file']}#{rec['record_id']}",
                "text":     render(rec),
                "ts":       rec["ts"],
                "host":     rec["host"],
                "event_id": rec["event_id"],
                "source":   rec["source"],
                "tactic":   rec["tactic"],
                "file":     rec["file"],
            }
            fout.write(json.dumps(doc) + "\n")
            n_out += 1

    print(f"read     {n_in}")
    print(f"filtered {n_filtered}  (noisy event types)")
    print(f"deduped  {n_deduped}  (repeats beyond {MAX_PER_SHAPE} per shape)")
    print(f"wrote    {n_out} -> {OUT}")


if __name__ == "__main__":
    main()
