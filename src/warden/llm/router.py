"""Build a ChatModel from a model spec string.

Spec format: ``<provider>:<model>``, for example ``groq:openai/gpt-oss-120b`` or
``ollama:llama3.2:3b-instruct-q4_K_M``. A bare model id defaults to Groq.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from warden.config import Settings
from warden.llm.base import ChatModel, ProviderUnavailable
from warden.llm.cache import CachingChatModel
from warden.llm.openai_compat import OpenAICompatChat
from warden.llm.ratelimit import LimiterRegistry

# Groq free-tier per-model limits, checked 2026-09-11 (verify on build day).
GROQ_FREE_RPM = 30
GROQ_FREE_TPM = 8_000


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.model}"

    @staticmethod
    def parse(spec: str) -> ModelSpec:
        provider, sep, model = spec.partition(":")
        if not sep or provider not in {"groq", "ollama", "fake"}:
            return ModelSpec("groq", spec)
        return ModelSpec(provider, model)


def build_chat_model(
    spec: str,
    settings: Settings,
    limiters: LimiterRegistry,
    client: httpx.AsyncClient | None = None,
) -> ChatModel:
    ms = ModelSpec.parse(spec)
    inner: ChatModel
    if ms.provider == "groq":
        if settings.groq_api_key is None:
            raise ProviderUnavailable("GROQ_API_KEY is not set; add it to .env")
        inner = OpenAICompatChat(
            model=ms.model,
            base_url=settings.groq_base_url,
            api_key=settings.groq_api_key.get_secret_value(),
            provider="groq",
            limiter=limiters.get(ms.key, rpm=GROQ_FREE_RPM, tpm=GROQ_FREE_TPM),
            client=client,
            timeout_s=settings.llm_timeout_s,
        )
    elif ms.provider == "ollama":
        inner = OpenAICompatChat(
            model=ms.model,
            base_url=settings.ollama_base_url,
            provider="ollama",
            limiter=limiters.get(ms.key, rpm=10_000, tpm=10_000_000),
            client=client,
            timeout_s=max(settings.llm_timeout_s, 180.0),
        )
    else:
        raise ProviderUnavailable(f"provider {ms.provider!r} cannot be built from settings")
    if settings.llm_cache:
        return CachingChatModel(inner, settings.llm_cache_dir)
    return inner
