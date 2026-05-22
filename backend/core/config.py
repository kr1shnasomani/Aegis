"""
Aegis Application Settings.

Loads configuration from environment variables and .env file.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # ── Application ─────────────────────────────────────
    PROJECT_NAME: str = "Aegis"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "change-me-in-production"
    SKIP_ENUMERATION: bool = False

    # ── Database ────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://aegis:aegis@postgres:5432/aegis"

    # ── Qdrant ──────────────────────────────────────────
    QDRANT_URL: str = "http://qdrant:6333"
    QDRANT_COLLECTION_NAME: str = "aegis_nist_docs"
    DOCS_SOURCE_DIR: str = "corpus/nist"

    # ── LLM / RAG ──────────────────────────────────────
    EMBEDDING_PROVIDER_MODE: str = "local"

    GROQ_BASE_URL: str = "https://api.groq.com/openai/v1"
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"

    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "google/gemma-3-27b-it"
    OPENROUTER_EMBEDDING_MODEL: str = "text-embedding-3-small"

    JINA_BASE_URL: str = "https://api.jina.ai/v1"
    JINA_API_KEY: str = ""
    JINA_EMBEDDING_MODEL: str = "jina-embeddings-v3"

    COHERE_BASE_URL: str = "https://api.cohere.com/v2"
    COHERE_API_KEY: str = ""
    COHERE_EMBEDDING_MODEL: str = "embed-english-v3.0"

    LLM_PROVIDER_MODE: str = "local"
    RAG_TOP_K: int = 5
    LLM_TIMEOUT_SECONDS: float = 15.0
    EMBEDDING_TIMEOUT_SECONDS: float = 15.0
    RAG_AUTO_REBUILD_ON_VECTOR_MISMATCH: bool = True

    # Certificate issuer
    CERT_ISSUER_COMMON_NAME: str = "Aegis Compliance CA"
    CERT_ISSUER_ORGANIZATION: str = "Aegis"
    CERT_ISSUER_ORG_UNIT: str = "Quantum Compliance"
    CERT_RUNTIME_DIR: str = ".aegis-runtime/certs"


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
