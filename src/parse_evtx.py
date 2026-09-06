"""Stage 1: EVTX binary logs -> normalised JSONL records."""
from __future__ import annotations
import glob, json, os
from evtx import PyEvtxParser

SAMPLES = "data/raw/evtx-attack-samples"
OUT     = "data/parsed/events.jsonl"

# Sysmon event IDs -> human names. Without this every event is just "3".
SYSMON = {
    1: "ProcessCreate",   2: "FileCreateTime",  3: "NetworkConnect",
    5: "ProcessTerminate", 6: "DriverLoad",     7: "ImageLoad",
    8: "CreateRemoteThread", 9: "RawAccessRead", 10: "ProcessAccess",
    11: "FileCreate",     12: "RegistryKeyEvent", 13: "RegistrySetValue",
    14: "RegistryKeyRename", 15: "FileCreateStreamHash",
    17: "PipeCreated",    18: "PipeConnected",  19: "WmiFilter",
    20: "WmiConsumer",    21: "WmiBinding",     22: "DnsQuery",
    23: "FileDelete",     25: "ProcessTampering",
}

# Windows Security log events. Different channel, same idea.
SECURITY = {
    4624: "LogonSuccess",   4625: "LogonFailure", 4634: "Logoff",
    4648: "ExplicitCredentialLogon", 4672: "SpecialPrivilegesAssigned",
    4688: "ProcessCreate",  4697: "ServiceInstalled",
    4698: "ScheduledTaskCreated", 4720: "UserAccountCreated",
    4728: "MemberAddedToGroup",   5140: "NetworkShareAccessed",
    5145: "NetworkShareChecked",
}


def dig(d, *keys, default=None):
    """Walk a nested dict safely. dig(e,'System','Computer') -> value or None."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
        if d is None:
            return default
    return d


def split_hashes(s):
    """'SHA1=99...,MD5=20...' -> {'sha1':'99...','md5':'20...'}

    Sysmon packs several hashes into one string. Splitting them out means
    a user can search for a bare SHA256 and BM25 will match it exactly.
    """
    out = {}
    if not s:
        return out
    for part in str(s).split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def normalise(evt, source_file, tactic):
    """One raw EVTX record -> one flat dict with a stable shape."""
    e = evt.get("Event", {})
    sysblk = e.get("System", {}) or {}
    data = e.get("EventData") or e.get("UserData") or {}
    if not isinstance(data, dict):
        data = {"raw": data}

    eid = sysblk.get("EventID")
    if isinstance(eid, dict):            # some logs wrap it: {"#text": 4624}
        eid = eid.get("#text")
    try:
        eid = int(eid)
    except (TypeError, ValueError):
        eid = -1

    provider = dig(sysblk, "Provider", "#attributes", "Name", default="") or ""
    is_sysmon = "Sysmon" in provider
    name = (SYSMON if is_sysmon else SECURITY).get(eid, f"EventID{eid}")

    return {
        "record_id":  sysblk.get("EventRecordID"),
        "ts":         dig(sysblk, "TimeCreated", "#attributes", "SystemTime"),
        "host":       sysblk.get("Computer"),
        "channel":    sysblk.get("Channel"),
        "provider":   provider,
        "event_id":   eid,
        "event_name": name,
        "source":     "sysmon" if is_sysmon else "windows",
        "tactic":     tactic,          # MITRE tactic, free from the folder name
        "file":       source_file,
        "data":       data,            # everything else, kept as-is
        "hashes":     split_hashes(data.get("Hashes")),
    }


def main():
    files = sorted(glob.glob(f"{SAMPLES}/**/*.evtx", recursive=True))
    print(f"found {len(files)} evtx files")

    n_ok = n_bad = 0
    with open(OUT, "w") as fh:
        for path in files:
            rel = os.path.relpath(path, SAMPLES)
            tactic = rel.split(os.sep)[0] if os.sep in rel else "Uncategorised"
            try:
                parser = PyEvtxParser(path)
                for rec in parser.records_json():
                    try:
                        evt = json.loads(rec["data"])
                        fh.write(json.dumps(normalise(evt, rel, tactic)) + "\n")
                        n_ok += 1
                    except Exception:
                        n_bad += 1
            except Exception as exc:
                print(f"  skipped {rel}: {exc}")

    print(f"wrote {n_ok} records to {OUT} ({n_bad} unparseable)")


if __name__ == "__main__":
    main()
