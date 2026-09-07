"""Verify a citation by pulling the original record from its source.

An answer cites chunk_id 'Execution/foo.evtx#12345'. This walks back to that
exact record in the original log and prints it in full alongside the rendered
sentence, so you can see whether any stage lost or distorted something.

Two chunk_id shapes, because the two sources identify records differently:

  EVTX  Privilege Escalation/foo.evtx#2362765
        int EventRecordID, assigned by Windows, unique within the file

  Zeek  apt29/day1/NASHUA_dce_rpc.log#CzUc9syGEsRry0zWl:11
        connection uid + 0-based line offset. The uid alone is NOT unique -
        several records in one session share it - hence the offset.
"""
from __future__ import annotations
import json, sys, os

EVTX_ROOT = "data/raw/evtx-attack-samples"
ZEEK_ROOT = ("data/raw/security-datasets/datasets/compound/apt29/"
             "day1/zeek/individual_zeek_logs")
DOCS      = "data/parsed/documents.jsonl"
EVENTS    = "data/parsed/events.jsonl"
ZEEK_EV   = "data/parsed/zeek_events.jsonl"


def rendered(chunk_id):
    """The sentence that was embedded and shown to the model."""
    for line in open(DOCS):
        d = json.loads(line)
        if d["chunk_id"] == chunk_id:
            return d["text"]
    return None


def normalised(path, rel_file, record_id):
    """The parsed record, after stage 1."""
    for line in open(path):
        e = json.loads(line)
        if e["file"] == rel_file and str(e["record_id"]) == str(record_id):
            return e
    return None


def raw_evtx(rel_file, record_id):
    from evtx import PyEvtxParser
    parser = PyEvtxParser(f"{EVTX_ROOT}/{rel_file}")
    for rec in parser.records_json():
        evt = json.loads(rec["data"])
        if evt.get("Event", {}).get("System", {}).get("EventRecordID") == record_id:
            return evt
    return None


def raw_zeek(rel_file, uid, line_no):
    """Read the NDJSON line at the recorded offset, and verify the uid matches.

    Reading by offset alone would silently return the wrong record if the file
    changed since indexing. Checking the uid catches that.
    """
    base = os.path.basename(rel_file)           # apt29/day1/X.log -> X.log
    path = f"{ZEEK_ROOT}/{base}"
    with open(path) as fh:
        for i, line in enumerate(fh):
            if i == line_no:
                r = json.loads(line)
                if r.get("uid") and r["uid"] != uid:
                    print(f"  WARNING: uid mismatch — file has {r.get('uid')}, "
                          f"chunk_id says {uid}. Source file changed since indexing?")
                return r
    return None


def show(chunk_id: str):
    chunk_id = chunk_id.strip()
    rel_file, record_id = chunk_id.rsplit("#", 1)
    is_zeek = rel_file.endswith(".log")

    print("=" * 70)
    print(f"CHUNK ID : {chunk_id}")
    print(f"SOURCE   : {'zeek NDJSON' if is_zeek else 'EVTX binary'}")
    print(f"FILE     : {rel_file}")
    print(f"RECORD   : {record_id}")
    print("=" * 70)

    text = rendered(chunk_id)
    print("\n[RENDERED - what the retriever searched]\n")
    print(text if text else "(not in documents.jsonl - filtered or deduped)")

    if is_zeek:
        uid, _, line_no = record_id.rpartition(":")
        norm = normalised(ZEEK_EV, rel_file, record_id)
        print("\n[NORMALISED - after parsing]\n")
        print(json.dumps(norm, indent=2)[:1500] if norm else "(not found)")

        print("\n[RAW ZEEK - ground truth]\n")
        raw = raw_zeek(rel_file, uid, int(line_no))
        print(json.dumps(raw, indent=2) if raw else "(record not found)")
    else:
        record_id = int(record_id)
        norm = normalised(EVENTS, rel_file, record_id)
        print("\n[NORMALISED - after parsing]\n")
        print(json.dumps(norm, indent=2)[:2000] if norm else "(not found)")

        print("\n[RAW EVTX - ground truth]\n")
        raw = raw_evtx(rel_file, record_id)
        print(json.dumps(raw, indent=2) if raw else "(record not found)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python src/verify.py '<chunk_id>'")
    show(sys.argv[1])
