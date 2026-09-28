"""Versioned prompt registry.

Every prompt has an ``id`` and an integer ``version``; run manifests record ``id@version`` for every
prompt used, and the pre-registration freezes them. Changing a prompt's text without bumping its
version is caught by ``tests/unit/test_prompts.py`` through the recorded text hashes.
"""

from __future__ import annotations

import string
from dataclasses import dataclass

from warden.canonical import sha256_hex


@dataclass(frozen=True)
class Prompt:
    id: str
    version: int
    template: str

    @property
    def ref(self) -> str:
        return f"{self.id}@{self.version}"

    @property
    def sha256(self) -> str:
        return sha256_hex(self.template)

    def fields(self) -> set[str]:
        return {f for _, f, _, _ in string.Formatter().parse(self.template) if f}

    def render(self, **values: str) -> str:
        missing = self.fields() - values.keys()
        if missing:
            raise KeyError(f"prompt {self.ref} missing fields: {sorted(missing)}")
        return self.template.format(**values)


class PromptRegistry:
    def __init__(self) -> None:
        self._prompts: dict[str, Prompt] = {}

    def register(self, prompt: Prompt) -> Prompt:
        existing = self._prompts.get(prompt.id)
        if existing is not None and existing.version >= prompt.version:
            raise ValueError(f"prompt {prompt.id} already registered at v{existing.version}")
        self._prompts[prompt.id] = prompt
        return prompt

    def get(self, prompt_id: str) -> Prompt:
        return self._prompts[prompt_id]

    def versions(self) -> dict[str, int]:
        return {p.id: p.version for p in self._prompts.values()}

    def hashes(self) -> dict[str, str]:
        return {p.ref: p.sha256 for p in self._prompts.values()}


REGISTRY = PromptRegistry()


def prompt(prompt_id: str, version: int, template: str) -> Prompt:
    """Declare and register a prompt at import time."""
    return REGISTRY.register(Prompt(prompt_id, version, template))
