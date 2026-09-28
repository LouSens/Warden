"""Registries the firewall trusts: known tokens (with reference prices), spenders and x402 services.

Built from a deployment record. Tokens without a reference price (the honeypot and the tax token) are
deliberately absent: touching them raises ``token_not_in_registry``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from warden.chain.world import NATIVE_REFERENCE_PRICE, World
from warden.firewall.models import NATIVE


@dataclass(frozen=True)
class RegisteredToken:
    symbol: str
    address: str
    decimals: int
    reference_price: Decimal


@dataclass(frozen=True)
class RegisteredService:
    service: str
    pay_to: str
    asset: str


@dataclass
class Registries:
    tokens: dict[str, RegisteredToken] = field(default_factory=dict)  # lower address -> token
    spenders: dict[str, str] = field(default_factory=dict)  # lower address -> label
    services: dict[str, RegisteredService] = field(default_factory=dict)  # name -> service
    all_token_meta: dict[str, tuple[str, int]] = field(default_factory=dict)  # incl. unregistered

    def token(self, address: str) -> RegisteredToken | None:
        return self.tokens.get(address.lower())

    def is_registered(self, address: str) -> bool:
        return address == NATIVE or address.lower() in self.tokens

    def symbol(self, address: str) -> str:
        if address == NATIVE:
            return "ETH"
        meta = self.all_token_meta.get(address.lower())
        return meta[0] if meta else address[:10]

    def decimals(self, address: str) -> int:
        if address == NATIVE:
            return 18
        meta = self.all_token_meta.get(address.lower())
        return meta[1] if meta else 18

    def usd_value(self, address: str, amount: int) -> Decimal | None:
        """Reference value; None for unregistered tokens (no price to trust)."""
        if address == NATIVE:
            return Decimal(amount) / Decimal(10**18) * NATIVE_REFERENCE_PRICE
        t = self.token(address)
        if t is None:
            return None
        return Decimal(amount) / Decimal(10**t.decimals) * t.reference_price

    def human(self, address: str, amount: int) -> str:
        value = Decimal(amount) / Decimal(10 ** self.decimals(address))
        text = f"{value:,.6f}".rstrip("0").rstrip(".")
        return f"{text} {self.symbol(address)}"

    @staticmethod
    def from_world(world: World) -> Registries:
        reg = Registries()
        for t in world.tokens.values():
            reg.all_token_meta[t.address.lower()] = (t.symbol, t.decimals)
            if t.reference_price is not None:
                reg.tokens[t.address.lower()] = RegisteredToken(
                    t.symbol, t.address, t.decimals, t.reference_price
                )
        reg.spenders[world.amm.lower()] = "MiniAMM"
        reg.services["weather-api"] = RegisteredService(
            "weather-api", world.accounts["weather_api"], world.token("tUSD").address
        )
        return reg
