"""Gemini backend. Same generate(system, user) interface as LocalLLM,
so ask.py doesn't care which one it's talking to."""
from __future__ import annotations
import os, time
from dotenv import load_dotenv
load_dotenv()
from google import genai
from google.genai import types, errors

MODEL = "gemini-3.6-flash"   # fast, generous free tier


class GeminiLLM:
    def __init__(self, model: str = MODEL):
        self.client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        self.model = model

    def generate(self, system: str, user: str, max_new_tokens: int = 2500) -> str:
        # 503s are common under load. An eval run of 20 questions will hit one
        # eventually, and losing the whole batch to a transient error is worse
        # than waiting seven seconds.
        for attempt in range(4):
            try:
                resp = self.client.models.generate_content(
                    model=self.model,
                    contents=user,
                    config=types.GenerateContentConfig(
                        system_instruction=system,   # separate from the user turn
                        temperature=0.2,             # faithful reading, not creativity
                        max_output_tokens=max_new_tokens,
                    ),
                )
                return resp.text.strip()
            except errors.ServerError:
                if attempt == 3:
                    raise
                wait = 2 ** attempt          # 1s, 2s, 4s
                print(f"  server busy, retrying in {wait}s")
                time.sleep(wait)
