"""Answer a fixed question set with the local model. Loads the model ONCE."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))
from ask import Retriever, ask
from local_llm import LocalLLM

QUESTIONS = [
 "was there any evidence of UAC bypass?",
 "was there evidence of credential dumping from lsass memory?",
 "which accounts requested Kerberos service tickets and for which services?",
 "was there evidence of AD replication abuse via drsuapi?",
 "was any data exfiltrated, and how much?",
 "did anyone clear the security event log?",
 "was there a zerologon attack?",
 "which user account was used for lateral movement between hosts?",
 "was there any cryptomining activity?",
 "were there failed SSH login attempts?",
]

r, client = Retriever(), LocalLLM()
for i, q in enumerate(QUESTIONS, 1):
    print(f"\n{'#'*70}\n# Q{i}: {q}\n{'#'*70}", flush=True)
    try:
        answer, hits = ask(q, r, client)
        print(answer, flush=True)
        print("\n--- evidence ---", flush=True)
        for n, h in enumerate(hits, 1):
            print(f"[{n}] {h['chunk_id']}", flush=True)
    except Exception as e:
        print("ERROR:", e, flush=True)
print("\nDONE", flush=True)
