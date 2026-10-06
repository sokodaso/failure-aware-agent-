import os
import time
from typing import Protocol

DEFAULT_MODEL = "gpt-4o-mini"  # cheap default; override with OPENAI_MODEL


class LLM(Protocol):
    def chat(self, system: str, user: str) -> str: ...


class OpenAILLM:
    def __init__(self, model: str | None = None):
        from openai import OpenAI  # reads OPENAI_API_KEY from the environment

        self.model = model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
        self._client = OpenAI()
        self.usage: list[dict] = []  # one entry per call, for cost and latency logging

    def chat(self, system: str, user: str) -> str:
        start = time.monotonic()
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        u = resp.usage
        self.usage.append({"model": resp.model, "prompt_tokens": u.prompt_tokens if u else None,
                           "completion_tokens": u.completion_tokens if u else None,
                           "seconds": round(time.monotonic() - start, 3)})
        return resp.choices[0].message.content or ""
