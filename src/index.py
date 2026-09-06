"""Stage 3: documents -> two indexes (dense + sparse).

Why two? Lecture 14, slide 54: BM25 matches exact tokens but is blind to
synonyms; dense retrieval matches meaning but is blind to identifiers. A
question like "did anything touch 172.16.66.254?" needs exact matching.
"was there evidence of credential theft?" needs semantic matching. Security
logs contain both kinds of query, so we build both indexes.
"""
from __future__ import annotations
import json, pickle, re
import numpy as np
import faiss
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer

DOCS  = "data/parsed/documents.jsonl"
OUT   = "data/index"
MODEL = "BAAI/bge-small-en-v1.5"


def tokenize(text: str) -> list[str]:
    """Tokenizer tuned for security logs.

    Default whitespace splitting would keep 'C:\\Windows\\System32\\cmd.exe'
    as ONE token, so a query for 'cmd.exe' would never match it. We split on
    path separators and punctuation so every component is searchable, while
    keeping dotted forms (IPs, filenames) intact.
    """
    text = text.lower()
    parts = re.split(r"[\s\\/,;:()\[\]{}=\"'<>|]+", text)
    out = []
    for p in parts:
        p = p.strip(".-")
        if p:
            out.append(p)
            # also index the bare filename: cmd.exe -> cmd
            if "." in p and not p.replace(".", "").isdigit():
                out.extend(x for x in p.split(".") if x)
    return out


def main():
    docs = [json.loads(l) for l in open(DOCS)]
    texts = [d["text"] for d in docs]
    print(f"{len(docs)} documents")

    # ---- dense index -----------------------------------------------------
    model = SentenceTransformer(MODEL, device="cuda")
    emb = model.encode(texts, batch_size=64, show_progress_bar=True,
                       normalize_embeddings=True)   # unit vectors
    emb = np.asarray(emb, dtype="float32")

    # With normalised vectors, inner product == cosine similarity.
    # IndexFlatIP is exact brute-force search. Slide 55 says exact search is
    # fine up to ~10^6 vectors; we have ~10^3, so ANN would be pointless
    # complexity.
    index = faiss.IndexFlatIP(emb.shape[1])
    index.add(emb)
    faiss.write_index(index, f"{OUT}/faiss.idx")
    print(f"dense index: {index.ntotal} vectors, dim {emb.shape[1]}")

    # ---- sparse index ----------------------------------------------------
    bm25 = BM25Okapi([tokenize(t) for t in texts])

    with open(f"{OUT}/store.pkl", "wb") as fh:
        pickle.dump({"docs": docs, "bm25": bm25}, fh)
    print(f"sparse index + metadata -> {OUT}/store.pkl")


if __name__ == "__main__":
    main()
