"""
Unit tests for Phase 6 retrieval and corpus ingestion helpers.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qdrant_client import QdrantClient

from backend.core.config import Settings
from backend.intelligence.retrieval import (
    CorpusSetupError,
    RetrievalService,
    create_embedding_provider,
)
from tests.unit._phase6_helpers import write_sample_corpus


def test_local_embedding_fallback_retrieval_works_without_cloud_credentials(
    tmp_path: Path,
) -> None:
    corpus_dir = write_sample_corpus(tmp_path)
    settings = Settings()
    service = RetrievalService(
        client=QdrantClient(":memory:"),
        collection_name="phase6_unit_docs",
        embedding_provider=create_embedding_provider(settings),
        default_top_k=5,
    )

    summary = service.ingest_source_directory(corpus_dir)
    results = service.search("hybrid deployment guidance for x25519mlkem768")

    assert summary.documents_ingested >= 2
    assert summary.chunks_ingested >= 2
    assert results
    assert results[0].metadata["title"] == "Fips203"
    assert results[0].metadata["path"].endswith("fips203.md")


def test_default_and_overridden_top_k_are_honored(tmp_path: Path) -> None:
    corpus_dir = write_sample_corpus(tmp_path)
    service = RetrievalService(
        client=QdrantClient(":memory:"),
        collection_name="phase6_topk_docs",
        embedding_provider=create_embedding_provider(Settings()),
        default_top_k=1,
    )
    service.ingest_source_directory(corpus_dir)

    assert len(service.search("quantum guidance")) == 1
    assert len(service.search("quantum guidance", top_k=2)) == 2


def test_missing_corpus_raises_explicit_setup_error(tmp_path: Path) -> None:
    service = RetrievalService(
        client=QdrantClient(":memory:"),
        collection_name="phase6_missing_docs",
        embedding_provider=create_embedding_provider(Settings()),
        default_top_k=5,
    )

    with pytest.raises(CorpusSetupError, match="Local corpus directory does not exist"):
        service.load_documents(tmp_path / "missing")


def test_chunk_metadata_preserves_sections_when_available(tmp_path: Path) -> None:
    corpus_dir = write_sample_corpus(tmp_path)
    service = RetrievalService(
        client=QdrantClient(":memory:"),
        collection_name="phase6_section_docs",
        embedding_provider=create_embedding_provider(Settings()),
        default_top_k=5,
    )

    service.ingest_source_directory(corpus_dir)
    results = service.search("hybrid deployment")

    assert any(result.metadata.get("section") == "Hybrid Deployment" for result in results)
