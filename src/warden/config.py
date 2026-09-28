"""Typed settings, read from the environment and `.env` (prefix ``WARDEN_``)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from warden.chains import ANVIL, require_allowed


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="WARDEN_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- paths
    data_dir: Path = Path("data")

    # --- chain
    rpc_url: str = "http://127.0.0.1:8545"
    chain_id: int = ANVIL

    # --- processes
    api_host: str = "127.0.0.1"
    api_port: int = 8200
    signer_url: str = "http://127.0.0.1:8201"
    signer_port: int = 8201
    signer_max_native_wei: int = 10**18  # hard ceiling enforced inside the signer
    signer_max_token_amount: int = 10**24  # base units, any token

    # --- LLM providers
    groq_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("GROQ_API_KEY", "WARDEN_GROQ_API_KEY")
    )
    groq_base_url: str = "https://api.groq.com/openai/v1"
    ollama_base_url: str = "http://127.0.0.1:11434/v1"
    llm_cache: bool = True
    llm_timeout_s: float = 60.0

    # --- observability
    log_level: str = "INFO"
    log_json: bool = True
    trace_content: bool = False
    trace_retention_days: int = 30
    otlp_endpoint: str | None = None

    # --- MCP
    mcp_session_id: str | None = None

    @field_validator("chain_id")
    @classmethod
    def _chain_allowed(cls, v: int) -> int:
        return require_allowed(v)

    # --- derived paths
    @property
    def db_path(self) -> Path:
        return self.data_dir / "warden.db"

    @property
    def signer_db_path(self) -> Path:
        return self.data_dir / "signer" / "signer.db"

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @property
    def traces_dir(self) -> Path:
        return self.data_dir / "traces"

    @property
    def bench_runs_dir(self) -> Path:
        return self.data_dir / "bench" / "runs"

    @property
    def llm_cache_dir(self) -> Path:
        return self.data_dir / "llm_cache"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
