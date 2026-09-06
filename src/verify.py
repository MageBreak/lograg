"""Verify a citation by pulling the original record from the raw EVTX.

The point: an answer cites chunk_id 'Execution/foo.evtx#12345'. This walks
back to that exact record in the original binary log and prints it in full.
If the rendered sentence dropped or distorted something, you see it here.

    python src/verify.py "Privilege Escalation/sysmon_uacbypass_....evtx#2362764"
"""
from __future__ import annotations
import json, sys
from evtx import PyEvtxParser

SAMPLES = "data/raw/evtx-attack-samples"
DOCS    = "data/parsed/documents.jsonl"
EVENTS  = "data/parsed/events.jsonl"


def show(chunk_id: str):
    rel_file, record_id = chunk_id.rsplit("#", 1)
    record_id = int(record_id)

    print("=" * 70)
    print(f"CHUNK ID : {chunk_id}")
    print(f"FILE     : {SAMPLES}/{rel_file}")
    print(f"RECORD   : {record_id}")
    print("=" * 70)

    # 1. the sentence that was indexed and embedded
    for line in open(DOCS):
        d = json.loads(line)
        if d["chunk_id"] == chunk_id:
            print("\n[RENDERED - what the retriever searched]\n")
            print(d["text"])
            break
    else:
        print("\n(not in documents.jsonl - filtered or deduped)")

    # 2. the normalised record
    for line in open(EVENTS):
        e = json.loads(line)
        if e["file"] == rel_file and e["record_id"] == record_id:
            print("\n[NORMALISED - after parsing]\n")
            print(json.dumps(e, indent=2)[:2000])
            break

    # 3. the original event, straight from the binary log
    print("\n[RAW EVTX - ground truth]\n")
    parser = PyEvtxParser(f"{SAMPLES}/{rel_file}")
    for rec in parser.records_json():
        evt = json.loads(rec["data"])
        if evt.get("Event", {}).get("System", {}).get("EventRecordID") == record_id:
            print(json.dumps(evt, indent=2))
            return
    print("record not found in source file")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python src/verify.py '<chunk_id>'")
    show(sys.argv[1])
