"""Measure retrieval quality against gold-labelled questions.

Retrieval quality caps answer quality, so we measure it separately from
generation. Three metrics because a question can fail three different ways:

  recall@k    - was the right evidence retrieved at all?
  MRR         - how highly was the first correct hit ranked?
  precision@k - how much of the retrieved context was wasted?

These come apart in practice. A query can score recall=1.0, MRR=1.0 and
precision=0.125: the right document ranked first, seven of eight slots noise.
"""
from __future__ import annotations
import json, sys, pathlib, argparse

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))
from ask import Retriever

K = 8


def evaluate(retriever, questions, mode="hybrid"):
    rows = []
    for q in questions:
        hits = retriever.search(q["question"], k=K, mode=mode)
        gold = set(q["gold_files"])

        # positions (0-based) of retrieved docs that came from a gold file
        rel = [i for i, h in enumerate(hits) if h["file"] in gold]

        rows.append({
            "id":        q["id"],
            "question":  q["question"],
            "kind":      q.get("kind", ""),
            "recall":    1.0 if rel else 0.0,
            "mrr":       1.0 / (rel[0] + 1) if rel else 0.0,
            "precision": len(rel) / K,
            "rank":      rel[0] + 1 if rel else None,
            "top_file":  hits[0]["file"] if hits else None,
        })
    return rows


def summarise(rows, label):
    n = len(rows)
    r = sum(x["recall"] for x in rows) / n
    m = sum(x["mrr"] for x in rows) / n
    p = sum(x["precision"] for x in rows) / n
    return {"config": label, "recall": r, "mrr": m, "precision": p, "n": n}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ablation", action="store_true",
                    help="run bm25 / dense / hybrid and compare")
    args = ap.parse_args()

    qs = [json.loads(l) for l in open("eval/questions.jsonl")]
    r = Retriever()

    modes = ["sparse", "dense", "hybrid"] if args.ablation else ["hybrid"]
    summaries, all_rows = [], {}

    for mode in modes:
        rows = evaluate(r, qs, mode=mode)
        all_rows[mode] = rows
        summaries.append(summarise(rows, mode))

        if not args.ablation:
            print(f"{'id':<5} {'rank':>5} {'P@8':>6}  {'kind':<10} question")
            print("-" * 78)
            for x in rows:
                rank = x["rank"] if x["rank"] else "MISS"
                print(f"{x['id']:<5} {str(rank):>5} {x['precision']:>6.2f}  "
                      f"{x['kind']:<10} {x['question'][:40]}")
            print()

    print(f"{'config':<10} {'recall@8':>9} {'MRR':>7} {'P@8':>7}")
    print("-" * 36)
    for s in summaries:
        print(f"{s['config']:<10} {s['recall']:>9.3f} "
              f"{s['mrr']:>7.3f} {s['precision']:>7.3f}")

    json.dump({"summaries": summaries, "rows": all_rows},
              open("eval/results.json", "w"), indent=2)
    print("\nwrote eval/results.json")


if __name__ == "__main__":
    main()
