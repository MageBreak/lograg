# Security Log RAG

Retrieval-augmented generation over Windows Sysmon and Security event logs.
Ask questions in natural language, get answers grounded in actual log records
with citations back to the source events.

INT450 course project.

## Pipeline

    .evtx binaries → parse → render → index (FAISS + BM25) → retrieve → LLM

37,364 raw events are curated to 1,771 indexed documents (95% reduction)
by filtering noisy event types and capping repeated event shapes.

## Setup

    uv venv --python 3.12
    source .venv/bin/activate
    uv pip install -r requirements.txt

    # corpus
    cd data/raw
    git clone --depth 1 \
      https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git evtx-attack-samples
    cd ../..

    # API key
    printf 'GEMINI_API_KEY=your-key\n' > .env

## Build and query

    python src/parse_evtx.py   # evtx → events.jsonl
    python src/render.py       # events.jsonl → documents.jsonl
    python src/index.py        # → faiss.idx + store.pkl

    python src/ask.py "was there any evidence of UAC bypass?"
    python src/verify.py "<chunk_id from the evidence list>"
    python eval/run_eval.py

## Files

| File | Job |
|---|---|
| `src/parse_evtx.py` | EVTX binary → normalised JSONL |
| `src/render.py` | Filter, dedupe, render to English sentences |
| `src/index.py` | Build dense (FAISS) and sparse (BM25) indexes |
| `src/ask.py` | Hybrid retrieval with RRF fusion, LLM generation |
| `src/gemini.py` | Cloud LLM backend |
| `src/llm.py` | Local LLM backend, same interface |
| `src/verify.py` | Trace a citation back to the raw EVTX record |

## Notes

Data is not committed — clone the corpus and rebuild. Full technical
reference in `docs/`.
