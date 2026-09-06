"""Gemini backend. Same generate(system, user) interface as LocalLLM,
so ask.py doesn't care which one it's talking to."""
from __future__ import annotations
import os
from dotenv import load_dotenv
load_dotenv()
from google import genai
from google.genai import types

MODEL = "gemini-3.6-flash"   # fast, generous free tier


class GeminiLLM:
    def __init__(self, model: str = MODEL):
        self.client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        self.model = model

    def generate(self, system: str, user: str, max_new_tokens: int = 2500) -> str:
        resp = self.client.models.generate_content(
            model=self.model,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=system,   # kept separate from the user turn
                temperature=0.2,             # low: faithful reading, not creativity
                max_output_tokens=max_new_tokens,
            ),
        )
        return resp.text.strip()
