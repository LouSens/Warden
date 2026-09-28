"""The mandate extractor: the trusted prompt → a draft (model) → a Mandate (resolver, code).

Runs once, on the trusted prompt only, before any tool call (docs/agents.md §2). The signature
takes a ``TrustedPrompt``, a distinct type, so tool output cannot be passed by accident.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from warden.canonical import sha256_hex
from warden.chain.registry import Registries
from warden.checks.context import BookEntry
from warden.llm.base import ChatModel, Message
from warden.llm.prompts import prompt
from warden.llm.structured import complete_json
from warden.mandate.resolver import MandateDraft, MandateResolver
from warden.mandate.schema import Mandate

EXTRACT_PROMPT = prompt(
    "mandate.extract",
    1,
    """You turn a user's instruction to their wallet assistant into a structured mandate: the
limits of what the assistant may do. Extract only what the user explicitly allows. Never invent
recipients, amounts or permissions. If something is ambiguous ("the usual amount", "the vendor"),
put the phrase in "unresolved" instead of guessing.

Known assets: {assets}
Known contracts the user may approve or trade through: {spenders}
Known paid services (x402): {services}
Saved contacts: {contacts}

Fields:
- recipients: [{{"label": name as the user wrote it, "address": 0x... only if the user typed it}}]
- assets: asset symbols the user mentions
- caps: [{{"asset": symbol, "per_tx": max per payment as a decimal string, "session": max total}}]
- allowed_actions: subset of ["transfer", "approve", "permit", "swap", "x402"]
- spenders: contract names from the known list the user allows approving or trading through
- approvals: [{{"spender": name, "asset": symbol, "cap": decimal string}}] only if stated
- services: [{{"service": name, "per_request_cap": decimal string}}]
- max_slippage_bps: integer or null
- expires_in_s: integer seconds or null
- constraints: other conditions in the user's words that do not fit a field
- unresolved: phrases you could not resolve

User instruction:
{instruction}

Return only the JSON object.""",
)


@dataclass(frozen=True)
class TrustedPrompt:
    """Text that came from the user's own channel (web app, CLI, benchmark task prompt)."""

    text: str


@dataclass(frozen=True)
class Extraction:
    mandate: Mandate
    draft: MandateDraft
    prompt_sha256: str
    model: str
    prompt_version: str
    tokens_in: int
    tokens_out: int


class MandateExtractor:
    def __init__(self, model: ChatModel, registries: Registries) -> None:
        self.model = model
        self.registries = registries

    async def extract(
        self,
        user_prompt: TrustedPrompt,
        *,
        book: list[BookEntry],
        chain_id: int,
        now: datetime,
        ttl_s: int = 3600,
    ) -> Extraction:
        reg = self.registries
        text = EXTRACT_PROMPT.render(
            assets=", ".join(["ETH", *sorted(t.symbol for t in reg.tokens.values())]),
            spenders=", ".join(sorted(set(reg.spenders.values()))) or "(none)",
            services=", ".join(sorted(reg.services)) or "(none)",
            contacts=", ".join(sorted(e.label for e in book if e.trusted)) or "(none)",
            instruction=user_prompt.text,
        )
        draft, tin, tout = await complete_json(self.model, [Message.user(text)], MandateDraft)
        mandate = MandateResolver(reg, book, chain_id).resolve(draft, user_prompt.text, now, ttl_s)
        return Extraction(
            mandate,
            draft,
            sha256_hex(user_prompt.text),
            self.model.model,
            EXTRACT_PROMPT.ref,
            tin,
            tout,
        )
