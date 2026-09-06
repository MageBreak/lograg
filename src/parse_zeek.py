"""Parse Zeek NDJSON logs into the same schema as parse_evtx.py.

Zeek writes one JSON object per line with a "@stream" field naming the log
type (conn, dns, http, ssl, ...). Because the output schema matches the EVTX
parser exactly, everything downstream — index.py, ask.py, verify.py — needs
no changes at all. Network events sit in the same index as host events.
"""
from __future__ import annotations
import glob, json, os
from datetime import datetime, timezone

ZEEK = ("data/raw/security-datasets/datasets/compound/apt29/"
        "day1/zeek/individual_zeek_logs")
OUT  = "data/parsed/zeek_events.jsonl"

# Zeek log types worth indexing. Excluded: dpd, weird, x509, files —
# high volume, low analytic value for the questions we care about.
KEEP = {"conn", "dns", "http", "ssl", "smb_files", "smb_mapping",
        "kerberos", "dce_rpc", "notice", "ntlm"}


def iso(ts):
    """Zeek writes epoch floats. Convert to the same ISO format as EVTX."""
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)\
                       .isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None


def main():
    files = sorted(glob.glob(f"{ZEEK}/*.log"))
    print(f"found {len(files)} zeek logs")

    n_ok = n_skip = 0
    with open(OUT, "w") as fh:
        for path in files:
            base = os.path.basename(path)          # NASHUA_conn.log
            sensor = base.split("_")[0]            # NASHUA

            with open(path) as fin:
                for i, line in enumerate(fin):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    stream = r.get("@stream", "unknown")
                    if stream not in KEEP:
                        n_skip += 1
                        continue

                    # Zeek's "uid" ties related records together across logs;
                    # fall back to line number where absent.
                    uid = r.get("uid") or f"line{i}"

                    fh.write(json.dumps({
                        "record_id":  f"{uid}:{i}",
                        "ts":         iso(r.get("ts")),
                        "host":       sensor,
                        "sensor_fqdn": r.get("@system"),
                        "channel":    f"zeek/{stream}",
                        "provider":   "zeek",
                        "event_id":   stream,        # string, not int, for zeek
                        "event_name": stream,
                        "source":     "zeek",
                        "tactic":     "APT29 Day1",
                        "file":       f"apt29/day1/{base}",
                        "data":       r,
                        "hashes":     {},
                    }) + "\n")
                    n_ok += 1

    print(f"wrote {n_ok} records to {OUT} ({n_skip} skipped stream types)")


if __name__ == "__main__":
    main()
