"""
Qdrant ingestion and retrieval helpers for the Phase 6 intelligence layer.
"""

from __future__ import annotations

import re
import unicodedata
import uuid
import contextlib
import os
import logging
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qdrant_client import QdrantClient, models

from .types import CorpusChunk, IngestionSummary, RetrievedChunk
from .embeddings import (
    RetrievalError,
    create_embedding_provider,  # noqa: F401
    LocalDeterministicEmbeddingProvider,  # noqa: F401
    JinaEmbeddingProvider,  # noqa: F401
    CohereEmbeddingProvider,  # noqa: F401
    OpenRouterEmbeddingProvider,  # noqa: F401
)

try:
    from langchain_core.documents import Document as LangChainDocument
except ImportError:  # pragma: no cover
    LangChainDocument = None

try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover
    PdfReader = None


class CorpusSetupError(RuntimeError):
    """Raised when the local intelligence corpus is missing or malformed."""


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _LoadedDocument:
    title: str
    path: str
    source_type: str
    text: str
    page: int | None = None
    section: str | None = None


@contextlib.contextmanager
def _clean_openssl_env():
    """Temporarily remove PQC OpenSSL environment variables."""
    old_conf = os.environ.get("OPENSSL_CONF")
    old_ld = os.environ.get("LD_LIBRARY_PATH")
    try:
        if "OPENSSL_CONF" in os.environ:
            del os.environ["OPENSSL_CONF"]
        if "LD_LIBRARY_PATH" in os.environ:
            del os.environ["LD_LIBRARY_PATH"]
        yield
    finally:
        if old_conf is not None:
            os.environ["OPENSSL_CONF"] = old_conf
        if old_ld is not None:
            os.environ["LD_LIBRARY_PATH"] = old_ld


class RetrievalService:
    """Coordinate corpus ingestion and grounded retrieval against Qdrant."""

    _SUPPORTED_EXTENSIONS = {".txt", ".md", ".pdf"}
    _IGNORED_FILENAMES = {"readme.md", ".gitkeep", ".ds_store"}

    def __init__(
        self,
        *,
        client: QdrantClient,
        collection_name: str,
        embedding_provider: Any,
        default_top_k: int = 5,
    ) -> None:
        self.client = client
        self.collection_name = collection_name
        self.embedding_provider = embedding_provider
        self.default_top_k = default_top_k

    def ingest_source_directory(
        self,
        source_dir: Path,
        *,
        recreate_collection: bool = True,
        chunk_size: int = 650,
        chunk_overlap: int = 100,
    ) -> IngestionSummary:
        """Load, chunk, embed, and store the local corpus in Qdrant."""
        documents = self.load_documents(source_dir)
        chunks = self.chunk_documents(
            documents,
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
        )
        return self.upsert_chunks(
            chunks,
            documents_ingested=len(documents),
            recreate_collection=recreate_collection,
        )

    def upsert_chunks(
        self,
        chunks: Sequence[CorpusChunk],
        *,
        documents_ingested: int,
        recreate_collection: bool = False,
    ) -> IngestionSummary:
        """Embed prepared chunks and write them to Qdrant."""
        if not chunks:
            raise CorpusSetupError("No corpus chunks were generated for ingestion.")

        vectors = self.embedding_provider.embed([chunk.text for chunk in chunks])
        vector_size = len(vectors[0])
        self._ensure_collection(vector_size=vector_size, recreate_collection=recreate_collection)

        points = [
            models.PointStruct(
                id=chunk.chunk_id,
                vector=vector,
                payload={"text": chunk.text, **chunk.metadata},
            )
            for chunk, vector in zip(chunks, vectors, strict=True)
        ]
        self.client.upsert(collection_name=self.collection_name, points=points, wait=True)
        return IngestionSummary(
            collection_name=self.collection_name,
            documents_ingested=documents_ingested,
            chunks_ingested=len(chunks),
            vector_size=vector_size,
        )

    def search(self, query: str, *, top_k: int | None = None) -> tuple[RetrievedChunk, ...]:
        """Retrieve top-k grounded chunks from Qdrant."""
        limit = top_k or self.default_top_k
        query_vector = self.embedding_provider.embed([query])[0]
        if hasattr(self.client, "query_points"):
            response = self.client.query_points(
                collection_name=self.collection_name,
                query=query_vector,
                limit=limit,
                with_payload=True,
            )
            hits = response.points
        else:
            hits = self.client.search(
                collection_name=self.collection_name,
                query_vector=query_vector,
                limit=limit,
                with_payload=True,
            )
        results: list[RetrievedChunk] = []
        for hit in hits:
            payload = dict(hit.payload or {})
            results.append(
                RetrievedChunk(
                    chunk_id=str(hit.id),
                    text=str(payload.pop("text", "")),
                    score=float(hit.score) if hit.score is not None else None,
                    metadata=payload,
                )
            )
        return tuple(results)

    def ensure_runtime_collection_compatibility(
        self,
        *,
        source_dir: Path,
        auto_recreate_on_mismatch: bool,
    ) -> None:
        """Ensure Qdrant collection dimensions match the active embedding provider.

        If the collection is missing or incompatible, this can rebuild the corpus so
        remediation retrieval does not fail at runtime.
        """
        try:
            vector_size = len(self.embedding_provider.embed(["aegis-collection-healthcheck"])[0])
        except Exception as exc:
            logger.warning(
                "Unable to compute embedding vector size for runtime compatibility check: %s", exc
            )
            return

        existing_size = self._get_collection_vector_size()
        if existing_size == vector_size:
            return

        if existing_size is None:
            logger.warning(
                "Qdrant collection '%s' not found; ingesting corpus from %s.",
                self.collection_name,
                source_dir,
            )
            self.ingest_source_directory(source_dir, recreate_collection=True)
            return

        message = (
            f"Qdrant collection '{self.collection_name}' vector size mismatch "
            f"(collection={existing_size}, provider={vector_size})."
        )
        if not auto_recreate_on_mismatch:
            raise RetrievalError(message)

        logger.warning(
            "%s Rebuilding collection from %s to restore compatibility.",
            message,
            source_dir,
        )
        self.ingest_source_directory(source_dir, recreate_collection=True)

    def load_documents(self, source_dir: Path) -> list[_LoadedDocument]:
        """Load supported local documents from the configured corpus directory."""
        if not source_dir.exists():
            raise CorpusSetupError(f"Local corpus directory does not exist: {source_dir}")

        files = sorted(
            path
            for path in source_dir.rglob("*")
            if path.is_file()
            and path.suffix.lower() in self._SUPPORTED_EXTENSIONS
            and path.name.lower() not in self._IGNORED_FILENAMES
        )
        if not files:
            raise CorpusSetupError(f"No supported corpus documents were found under {source_dir}")

        loaded_documents: list[_LoadedDocument] = []
        for path in files:
            loaded_documents.extend(self._load_single_document(path))
        return loaded_documents

    def chunk_documents(
        self,
        documents: Sequence[_LoadedDocument],
        *,
        chunk_size: int = 650,
        chunk_overlap: int = 100,
    ) -> list[CorpusChunk]:
        """Chunk preprocessed documents into retrieval-friendly windows."""
        chunks: list[CorpusChunk] = []
        for document in documents:
            lines = [line.strip() for line in document.text.splitlines() if line.strip()]
            current_section = document.section
            words: list[str] = []
            chunk_index = 0

            for line in lines:
                if line.startswith("#"):
                    current_section = line.lstrip("# ").strip() or current_section
                    continue

                line_words = line.split()
                if not line_words:
                    continue

                if len(words) + len(line_words) > chunk_size and words:
                    chunks.append(
                        self._build_chunk(
                            document=document,
                            chunk_words=words,
                            section=current_section,
                            chunk_index=chunk_index,
                        )
                    )
                    chunk_index += 1
                    words = words[-chunk_overlap:] if chunk_overlap < len(words) else list(words)

                words.extend(line_words)

            if words:
                chunks.append(
                    self._build_chunk(
                        document=document,
                        chunk_words=words,
                        section=current_section,
                        chunk_index=chunk_index,
                    )
                )
        return chunks

    def _ensure_collection(self, *, vector_size: int, recreate_collection: bool) -> None:
        if recreate_collection:
            try:
                self.client.delete_collection(collection_name=self.collection_name)
            except Exception:
                pass

        if self.client.collection_exists(self.collection_name):
            existing_size = self._get_collection_vector_size()
            if existing_size is not None and existing_size != vector_size:
                raise RetrievalError(
                    f"Qdrant collection '{self.collection_name}' vector size mismatch: "
                    f"expected {vector_size}, found {existing_size}."
                )

        if not self.client.collection_exists(self.collection_name):
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=models.VectorParams(
                    size=vector_size,
                    distance=models.Distance.COSINE,
                ),
            )

    def _get_collection_vector_size(self) -> int | None:
        """Return the configured vector size for the active collection when available."""
        try:
            collection_info = self.client.get_collection(self.collection_name)
        except Exception:
            return None

        vectors = getattr(getattr(collection_info.config, "params", None), "vectors", None)
        if isinstance(vectors, models.VectorParams):
            return int(vectors.size)
        if isinstance(vectors, dict):
            first_vector = next(iter(vectors.values()), None)
            if first_vector is not None and getattr(first_vector, "size", None) is not None:
                return int(first_vector.size)
        if getattr(vectors, "size", None) is not None:
            return int(vectors.size)
        return None

    def _load_single_document(self, path: Path) -> list[_LoadedDocument]:
        title = path.stem.replace("_", " ").replace("-", " ").strip().title()
        title = _normalize_reference_label(title) or title
        suffix = path.suffix.lower()
        if suffix == ".pdf":
            if PdfReader is None:
                raise CorpusSetupError(
                    "PDF ingestion requires the 'pypdf' dependency to be installed."
                )
            return self._load_pdf_document(path, title)

        text = normalize_text(path.read_text(encoding="utf-8", errors="replace"))
        cleaned = strip_headers_and_footers(text)
        return [
            _LoadedDocument(
                title=title,
                path=str(path),
                source_type="text",
                text=cleaned,
            )
        ]

    def _load_pdf_document(self, path: Path, title: str) -> list[_LoadedDocument]:
        reader = PdfReader(str(path))
        documents: list[_LoadedDocument] = []
        for page_number, page in enumerate(reader.pages, start=1):
            page_text = normalize_text(page.extract_text() or "")
            cleaned = strip_headers_and_footers(page_text)
            if not cleaned.strip():
                continue
            documents.append(
                _LoadedDocument(
                    title=title,
                    path=str(path),
                    source_type="pdf",
                    text=cleaned,
                    page=page_number,
                )
            )
        return documents

    @staticmethod
    def _build_chunk(
        *,
        document: _LoadedDocument,
        chunk_words: Sequence[str],
        section: str | None,
        chunk_index: int,
    ) -> CorpusChunk:
        chunk_text = " ".join(chunk_words).strip()
        chunk_hash = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{document.path}:{document.page}:{chunk_index}:{chunk_text}",
            )
        )
        metadata: dict[str, Any] = {
            "title": document.title,
            "source_type": document.source_type,
            "path": document.path,
            "chunk_index": chunk_index,
        }
        if document.page is not None:
            metadata["page"] = document.page
        if section:
            metadata["section"] = section
        return CorpusChunk(chunk_id=chunk_hash, text=chunk_text, metadata=metadata)


def build_citation_payload(chunks: Sequence[RetrievedChunk]) -> dict[str, Any]:
    """Return structured citations derived from retrieved chunks."""
    documents: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for chunk in chunks:
        key = (
            chunk.metadata.get("title"),
            chunk.metadata.get("section"),
            chunk.metadata.get("page"),
            chunk.metadata.get("path"),
            chunk.chunk_id,
        )
        if key in seen:
            continue
        seen.add(key)
        documents.append(
            {
                "title": _normalize_reference_label(chunk.metadata.get("title")),
                "section": chunk.metadata.get("section"),
                "page": chunk.metadata.get("page"),
                "path": chunk.metadata.get("path"),
                "chunk_id": chunk.chunk_id,
                "excerpt": chunk.text[:240],
            }
        )
    return {"documents": documents}


def build_langchain_documents(chunks: Sequence[RetrievedChunk]) -> tuple[Any, ...]:
    """Convert retrieved chunks into LangChain Documents when the dependency is available."""
    if LangChainDocument is None:
        return ()
    return tuple(
        LangChainDocument(page_content=chunk.text, metadata=dict(chunk.metadata))
        for chunk in chunks
    )


def normalize_text(text: str) -> str:
    """Normalize text to a retrieval-stable UTF-8-compatible representation."""
    normalized = unicodedata.normalize("NFKC", text).replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"[ \t]+", " ", normalized)


def strip_headers_and_footers(text: str) -> str:
    """Remove common repeated header/footer lines from extracted corpus text."""
    lines = [line.strip() for line in text.splitlines()]
    counts = Counter(line for line in lines if line)
    cleaned = [line for line in lines if line and not (counts[line] > 2 and len(line.split()) <= 8)]
    return "\n".join(cleaned)


def _normalize_reference_label(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if re.search(r"(?i)\bnist\s*ir\s*8547\b", text):
        return "NIST IR 8547"
    if re.search(r"(?i)\bir\s*[-_ ]?8547(?:\.pdf)?\b", text):
        return "NIST IR 8547"
    if re.search(r"(?i)\bir8547(?:\.pdf)?\b", text):
        return "NIST IR 8547"
    return text
