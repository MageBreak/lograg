"""Local LLM backend. Same interface as the Anthropic client path.

Loading a 4B model in bfloat16 needs ~8GB VRAM. Your 3060 laptop has 6GB,
so device_map="auto" spills the overflow layers to system RAM. It works,
just slower - expect 10-25 seconds per answer rather than 2-3.
"""
from __future__ import annotations
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_PATH = "/home/magebreak/Projects/SLM/models/qwen3.5-4b"


class LocalLLM:
    def __init__(self, path: str = MODEL_PATH):
        print(f"loading {path} ...")
        self.tok = AutoTokenizer.from_pretrained(path, trust_remote_code=True)
        self.model = AutoModelForCausalLM.from_pretrained(
            path,
            dtype=torch.bfloat16,     # half the memory of fp32, no real quality loss
            device_map="auto",        # fit what we can on GPU, rest to CPU
            trust_remote_code=True,
        )
        self.model.eval()
        print("loaded.")

    def generate(self, system: str, user: str, max_new_tokens: int = 800) -> str:
        # Chat template inserts the model's expected role markers. Skipping it
        # and concatenating raw strings is a common cause of rambling output.
        msgs = [{"role": "system", "content": system},
                {"role": "user",   "content": user}]
        prompt = self.tok.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True)

        inputs = self.tok(prompt, return_tensors="pt").to(self.model.device)

        with torch.no_grad():
            out = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=0.2,      # low: we want faithful reading, not creativity
                do_sample=True,
                top_p=0.9,
                pad_token_id=self.tok.eos_token_id,
            )

        # Slice off the prompt tokens so we return only what was generated.
        return self.tok.decode(out[0][inputs["input_ids"].shape[1]:],
                               skip_special_tokens=True).strip()
