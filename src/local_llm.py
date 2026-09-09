"""Local generation backend. Same generate(system, user) interface as
GeminiLLM, so ask.py doesn't care which is behind it.

Motivation is privacy, not capability: security telemetry contains hostnames,
internal addressing, usernames and command lines. Sending that to a third-party
API is unacceptable in most SOC environments, so the whole pipeline - embedding,
retrieval, generation - runs on hardware the operator controls.
"""
from __future__ import annotations
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL = "Qwen/Qwen3-8B"


class LocalLLM:
    def __init__(self, model: str = MODEL):
        print(f"loading {model} ...", flush=True)
        self.tok = AutoTokenizer.from_pretrained(model)
        self.model = AutoModelForCausalLM.from_pretrained(
            model,
            dtype=torch.bfloat16,   # H200 has native bf16; ~16GB for 8B
            device_map="cuda:0",    # single pinned GPU, not "auto"
        )
        self.model.eval()
        print("loaded.", flush=True)

    def generate(self, system: str, user: str, max_new_tokens: int = 2000) -> str:
        msgs = [{"role": "system", "content": system},
                {"role": "user",   "content": user}]
        prompt = self.tok.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True,
            enable_thinking=False)     # Qwen3 emits <think> blocks by default

        inputs = self.tok(prompt, return_tensors="pt").to(self.model.device)

        with torch.no_grad():
            out = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=0.2,       # faithful reading, not creativity
                do_sample=True,
                top_p=0.9,
                pad_token_id=self.tok.eos_token_id,
            )

        text = self.tok.decode(out[0][inputs["input_ids"].shape[1]:],
                               skip_special_tokens=True).strip()

        # belt and braces: strip a thinking block if one appears anyway
        if "</think>" in text:
            text = text.split("</think>", 1)[1].strip()
        return text
