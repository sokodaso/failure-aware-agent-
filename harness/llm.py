import os
from typing import Protocol

DEFAULT_MODEL = "gpt-4o-mini"  # cheap default; override with OPENAI_MODEL


class LLM(Protocol):
    def chat(self, system: str, user: str) -> str: ...


class OpenAILLM:
    def __init__(self, model: str | None = None):
        from openai import OpenAI  # reads OPENAI_API_KEY from the environment

        self.model = model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
        self._client = OpenAI()

    def chat(self, system: str, user: str) -> str:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        return resp.choices[0].message.content or ""
