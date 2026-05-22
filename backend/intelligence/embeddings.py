"""
Embedding provider implementations for the Aegis intelligence layer.

Each provider exposes an `embed(texts)` method returning `list[list[float]]`.
The `create_embedding_provider` factory selects the appropriate provider
based on the application settings.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from typing import Any

from backend.core.config import Settings, get_settings
from .cloud_utils import call_cloud_api


class RetrievalError(RuntimeError):
    """Raised when Qdrant retrieval or embedding generation fails."""


class OpenRouterEmbeddingProvider:
    """OpenAI-compatible embedding client pointed at an OpenRouter-style endpoint."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        url = f"{self.base_url}/embeddings"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {"model": self.model, "input": list(texts)}

        response_json = call_cloud_api(url, headers, payload)
        embeddings = [item["embedding"] for item in response_json["data"]]
        if not embeddings:
            raise RetrievalError("Embedding provider returned no vectors.")
        return embeddings


class JinaEmbeddingProvider:
    """Jina AI embedding client."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        url = f"{self.base_url}/embeddings"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {"model": self.model, "input": list(texts), "task": "retrieval.passage"}

        response_json = call_cloud_api(url, headers, payload)
        embeddings = [item["embedding"] for item in response_json["data"]]
        if not embeddings:
            raise RetrievalError("Jina AI returned no vectors.")
        return embeddings


class CohereEmbeddingProvider:
    """Cohere embedding client (v2 API)."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        url = f"{self.base_url}/embed"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "texts": list(texts),
            "input_type": "search_document",
            "embedding_types": ["float"],
        }

        response_json = call_cloud_api(url, headers, payload)
        embeddings = response_json["embeddings"]["float"]
        if not embeddings:
            raise RetrievalError("Cohere returned no vectors.")
        return embeddings


class FallbackEmbeddingProvider:
    """A wrapper that tries multiple embedding providers in order."""

    def __init__(
        self,
        providers: Sequence[Any],
    ) -> None:
        self.providers = tuple(providers)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        last_error: Exception | None = None
        for provider in self.providers:
            try:
                return provider.embed(texts)
            except Exception as e:
                last_error = e
                continue
        raise RetrievalError(f"All embedding providers failed. Last error: {last_error}")


class LocalDeterministicEmbeddingProvider:
    """Offline deterministic embedding provider for local/test environments.

    This avoids hard failure during app startup when cloud embedding credentials are absent.
    The vectors are stable and suitable for deterministic retrieval tests, but not for
    production-grade semantic quality.
    """

    def __init__(self, *, vector_size: int = 128) -> None:
        self.vector_size = vector_size

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            vector = [0.0] * self.vector_size
            for token in _tokenize(text):
                digest = hashlib.sha256(token.encode("utf-8")).digest()
                index = int.from_bytes(digest[:4], "big") % self.vector_size
                sign = 1.0 if (digest[4] & 1) else -1.0
                vector[index] += sign

            norm = sum(value * value for value in vector) ** 0.5
            if norm > 0:
                vector = [value / norm for value in vector]
            vectors.append(vector)
        return vectors


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9][A-Za-z0-9+._/-]*", text.lower())


def create_embedding_provider(
    settings: Settings | None = None,
) -> Any:
    """Return the configured cloud embedding provider with fallbacks."""
    configured = settings or get_settings()
    providers = []

    if getattr(configured, "JINA_API_KEY", None):
        providers.append(
            JinaEmbeddingProvider(
                base_url=configured.JINA_BASE_URL,
                api_key=configured.JINA_API_KEY,
                model=configured.JINA_EMBEDDING_MODEL,
                timeout_seconds=configured.EMBEDDING_TIMEOUT_SECONDS,
            )
        )

    if getattr(configured, "COHERE_API_KEY", None):
        providers.append(
            CohereEmbeddingProvider(
                base_url=configured.COHERE_BASE_URL,
                api_key=configured.COHERE_API_KEY,
                model=configured.COHERE_EMBEDDING_MODEL,
                timeout_seconds=configured.EMBEDDING_TIMEOUT_SECONDS,
            )
        )

    if getattr(configured, "OPENROUTER_API_KEY", None):
        providers.append(
            OpenRouterEmbeddingProvider(
                base_url=configured.OPENROUTER_BASE_URL,
                api_key=configured.OPENROUTER_API_KEY,
                model=configured.OPENROUTER_EMBEDDING_MODEL,
                timeout_seconds=configured.EMBEDDING_TIMEOUT_SECONDS,
            )
        )

    if not providers:
        return LocalDeterministicEmbeddingProvider(
            vector_size=getattr(configured, "LOCAL_EMBEDDING_VECTOR_SIZE", 128),
        )

    return FallbackEmbeddingProvider(providers)
