# Security Log RAG

Ask natural-language questions about Windows event logs and network session
logs. Get answers grounded in the actual records, with citations back to the
source events and a tool to verify any citation against the raw binary.

INT450 course project.

## What it does

```
$ python src/ask.py "was there any evidence of UAC bypass?"

Evidence of an attempted UAC bypass:

* byeintegrity5-uac.exe (PID 11644) executed from cmd.exe at Medium
  integrity [3]
* Created C:\Users\Public\tools\privesc\uac\system32\npmproxy.dll [5]
* Set HKU\...\Environment\systemroot to C:\Users\Public\tools\privesc\uac [1]

[Inference] Environment-variable hijacking to make an auto-elevating binary
load a malicious DLL.
[Limitation] The logs show the tool's actions but not the outcome.

--- evidence ---
[1] Privilege Escalation/sysmon_uacbypass_...byeintegrity5.evtx#2362767
    text : [2020-11-26T17:38:11Z] host=LAPTOP-JU4M3I0E sysmon EventID 13
           (RegistrySetValue) - Registry set value by ...
```

## Pipeline

```
HOST                                  NETWORK
*.evtx (binary Windows event logs)    Zeek NDJSON session logs
      |                                     |
      | parse_evtx.py                       | parse_zeek.py
      v                                     v
events.jsonl      37,364 records      zeek_events.jsonl   1,289 records
      |                                     |
      | render.py (overwrites)              | render_zeek.py (appends)
      v                                     v
      +--------------+----------------------+
                     v
        documents.jsonl    2,074 documents (1,771 host + 303 network)
                     |
                     | index.py
                     v
        FAISS (dense) + BM25 (sparse) + metadata
                     |
   question ---------+ ask.py: hybrid retrieve -> RRF fuse -> top-8 -> LLM
                     v
         grounded answer with [n] citations
                     |
                     | verify.py
                     v
         citation -> raw source record
```

Everything downstream of `documents.jsonl` is source-agnostic. Adding a third
telemetry source means one parser and one renderer, and no changes elsewhere.

## Design notes

Security logs are not prose, and naive chunk-and-embed fails on them.

**Near-duplicate flooding.** Around 20,000 of the 37,364 raw events are RPC
calls saying essentially the same thing. Indexed as-is, every top-k result is
infrastructure noise. Curation drops 88% of event types and caps repeated event
shapes at five, taking 37,364 records down to 1,771 documents.

**Identifiers need exact matching.** Queries contain IPs, SHA256 hashes, PIDs
and filenames. Dense embeddings place `192.168.0.4` and `192.168.0.5` in nearly
the same position -- they encode *kind*, not *identity*. Hence BM25 alongside,
fused with Reciprocal Rank Fusion (scores from the two retrievers live on
incomparable scales; ranks do not).

**Event IDs are only unique within a provider.** Sysmon 14 is a registry key
rename; Microsoft-Windows-RPC 14 is unrelated. Dispatch is scoped by source
first, then event ID.

**Zeek sessions, not packets.** One TCP conversation can be 4,000 packets but
is one `conn.log` record. Session granularity is already the right document
size. The Zeek connection UID appears in every rendered sentence, so a query
containing a UID retrieves every protocol-level view of that flow via exact
match.

## Setup

```bash
uv venv --python 3.12
source .venv/bin/activate
uv pip install -r requirements.txt

cd data/raw
git clone --depth 1 \
  https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git evtx-attack-samples
git clone --depth 1 \
  https://github.com/OTRF/Security-Datasets.git security-datasets
cd ../..

printf 'GEMINI_API_KEY=your-key\n' > .env
```

## Build

Order matters -- `render.py` overwrites `documents.jsonl`, `render_zeek.py`
appends to it.

```bash
python src/parse_evtx.py    # 278 evtx     -> 37,364 records
python src/parse_zeek.py    # 26 zeek logs ->  1,289 records
python src/render.py        # OVERWRITES   ->  1,771 documents
python src/render_zeek.py   # APPENDS      ->    303 documents
python src/index.py         # 2,074 docs   -> FAISS + BM25
```

## Query

```bash
# host
python src/ask.py "was there any evidence of UAC bypass?"
python src/ask.py "show me signs of credential dumping from lsass"

# network
python src/ask.py "which accounts requested Kerberos service tickets?"
python src/ask.py "was there evidence of AD replication abuse?"

# interactive -- embedding model loads once
python src/ask.py

# audit a citation: rendered sentence, parsed record, raw EVTX side by side
python src/verify.py "<chunk_id from the evidence list>"

# compare retrievers on one query
python src/compare.py "192.168.0.4"

```

## Files

| File | Job |
|---|---|
| `src/parse_evtx.py` | EVTX binary to normalised JSONL |
| `src/parse_zeek.py` | Zeek NDJSON to the same schema |
| `src/render.py` | Filter, dedupe, render host events to English |
| `src/render_zeek.py` | Per-protocol templates; append network documents |
| `src/index.py` | Build dense (FAISS) and sparse (BM25) indexes |
| `src/ask.py` | Hybrid retrieval, RRF fusion, LLM generation |
| `src/verify.py` | Trace a citation back to the raw EVTX record |
| `src/compare.py` | Show BM25 vs dense vs hybrid for one query |
| `src/gemini.py` | Cloud LLM backend |
| `src/llm.py` | Local LLM backend, same interface |
| `eval/run_eval.py` | Recall@8, MRR, Precision@8 against gold labels |


## Known limitations

**Causal chains are not retrieved.** The ByeIntegrity5 scenario has eight
events; retrieval returned five and the model correctly reported the outcome as
unproven. The three it missed showed the bypass completing 16ms later --
`taskhostw.exe` loading the planted DLL at High integrity and spawning an
elevated shell. They were missed because none of them names the attacker's
binary. Retrievers score documents independently; log evidence is a causal
chain.

**Analyst vocabulary is not log vocabulary.** Same corpus, same retriever:

| Query | Kerberos events in top-8 |
|---|---|
| "which user account was used for lateral movement between hosts?" | 0 |
| "which accounts requested Kerberos service tickets?" | 8 |

One account pulling service tickets for SMB, LDAP and HTTP on two remote hosts
*is* lateral movement -- but that phrase appears in no log line, and the
embedding model has no link between a protocol transaction and the security
abstraction.

**Aggregate questions.** "How many failed logons?" cannot be answered from
top-k, because the answer depends on all the data. Needs a SQL path alongside
retrieval.

**Dedupe discards rather than summarising.** 976 of 1,289 Zeek records were
dropped. A roll-up document ("147 connections to X between 04:22 and 04:31")
would preserve the count.

**verify.py handles EVTX only.** Zeek chunk_ids use a string UID and line
offset against NDJSON, which it does not parse.

**No reranking.** A cross-encoder second stage over the top ~100 would improve
precision and is a natural next step.

## Data sources

Not committed -- clone and rebuild.

- Host: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  -- 278 `.evtx` files foldered by MITRE ATT&CK tactic
- Network: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
  -- APT29 evaluation, PCAPs and pre-extracted Zeek logs
