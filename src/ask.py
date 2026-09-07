"""Stage 4: question -> hybrid retrieve -> Claude -> grounded answer."""
from __future__ import annotations
import json, pickle, sys
import numpy as np, faiss
from sentence_transformers import SentenceTransformer

from index import tokenize   # same tokenizer as indexing time
from gemini import GeminiLLM

IDX, MODEL = "data/index", "BAAI/bge-small-en-v1.5"
LOCAL_MODEL = "/home/magebreak/Projects/SLM/models/qwen3.5-4b"

SYSTEM = """You are a security analyst reviewing Windows event logs.

Answer ONLY from the numbered log events provided. Rules:
- Cite the event number(s) supporting each claim, like [3] or [1][7].
- If the logs do not contain the answer, say so plainly. Do not speculate.
- Note the specific artefacts: process names, command lines, IPs, registry keys.
- Distinguish what the logs SHOW from what it might MEAN. Flag inferences.

A hallucinated intrusion is worse than an honest 'the logs don't show this'."""


class Retriever:
    def __init__(self):
        self.index = faiss.read_index(f"{IDX}/faiss.idx")
        store = pickle.load(open(f"{IDX}/store.pkl", "rb"))
        self.docs, self.bm25 = store["docs"], store["bm25"]
        self.model = SentenceTransformer(MODEL, device="cuda")

    def search(self, query, k=8, pool=60, mode="hybrid"):
        """Hybrid retrieval fused with Reciprocal Rank Fusion.

        mode lets the eval harness disable one retriever at a time, so the
        contribution of each can be measured rather than assumed.
        """
        fused = {}

        if mode in ("dense", "hybrid"):
            qv = self.model.encode([query], normalize_embeddings=True)
            _, dense_ids = self.index.search(np.asarray(qv, "float32"), pool)
            for rank, i in enumerate(dense_ids[0]):
                fused[i] = fused.get(i, 0) + 1 / (60 + rank)

        if mode in ("sparse", "hybrid"):
            scores = self.bm25.get_scores(tokenize(query))
            for rank, i in enumerate(np.argsort(scores)[::-1][:pool]):
                fused[i] = fused.get(i, 0) + 1 / (60 + rank)

        best = sorted(fused, key=fused.get, reverse=True)[:k]
        return [self.docs[i] for i in best]


def ask(question, retriever, client, k=8):
    hits = retriever.search(question, k=k)

    context = "\n".join(f"[{n}] {h['text']}" for n, h in enumerate(hits, 1))
    prompt = f"LOG EVENTS:\n{context}\n\nQUESTION: {question}"

    answer = client.generate(SYSTEM, prompt)
    return answer, hits


def main():
    r, client = Retriever(), GeminiLLM()

    if len(sys.argv) > 1:                      # one-shot mode
        answer, hits = ask(" ".join(sys.argv[1:]), r, client)
        print(answer)
        print("\n--- evidence ---")
        for n, h in enumerate(hits, 1):
            print(f"[{n}] {h['chunk_id']}")
            print(f"    tactic : {h['tactic']}")
            print(f"    file   : {h['file']}")
            print(f"    record : {h['chunk_id'].split('#')[1]}")
            print(f"    text   : {h['text']}")
            print()
        return

    print("Ask about the logs. Ctrl-D to quit.\n")     # interactive mode
    while True:
        try:
            q = input("> ").strip()
        except EOFError:
            break
        if not q:
            continue
        answer, hits = ask(q, r, client)
        print(f"\n{answer}\n")
        print("--- evidence ---")
        for n, h in enumerate(hits, 1):
            print(f"[{n}] {h['chunk_id']}")
            print(f"    tactic : {h['tactic']}")
            print(f"    file   : {h['file']}")
            print(f"    record : {h['chunk_id'].split('#')[1]}")
            print(f"    text   : {h['text']}")
            print()


if __name__ == "__main__":
    main()
