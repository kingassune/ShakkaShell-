"""Persistent Vector Memory for ShakkaShell.

This module provides semantic memory storage and retrieval using vector embeddings.
Supports ChromaDB for vector storage with fallback to simple JSON storage.
"""

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class MemoryType(str, Enum):
    """Types of memories that can be stored."""
    
    SESSION = "session"      # Current engagement context
    TARGET = "target"        # Per-target findings
    TECHNIQUE = "technique"  # General attack patterns
    FAILURE = "failure"      # Approaches to avoid


@dataclass
class MemoryEntry:
    """A single memory entry."""
    
    id: str
    content: str
    memory_type: MemoryType
    target: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict = field(default_factory=dict)
    embedding: Optional[list[float]] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "content": self.content,
            "memory_type": self.memory_type.value,
            "target": self.target,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "MemoryEntry":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            content=data["content"],
            memory_type=MemoryType(data["memory_type"]),
            target=data.get("target"),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            metadata=data.get("metadata", {}),
        )


@dataclass
class RecallResult:
    """Result from a memory recall operation."""
    
    entries: list[MemoryEntry]
    query: str
    similarity_threshold: float
    
    @property
    def found(self) -> bool:
        """Whether any memories were found."""
        return len(self.entries) > 0
    
    def format(self) -> str:
        """Format results for display."""
        if not self.entries:
            return "No relevant memories found."
        
        lines = [f"Found {len(self.entries)} relevant memories:\n"]
        for i, entry in enumerate(self.entries, 1):
            lines.append(f"{i}. [{entry.memory_type.value}] {entry.content}")
            if entry.target:
                lines.append(f"   Target: {entry.target}")
            lines.append(f"   Recorded: {entry.timestamp}")
        
        return "\n".join(lines)


@dataclass
class MemoryConfig:
    """Configuration for memory storage."""
    
    # Storage location
    storage_path: Path = field(default_factory=lambda: Path.home() / ".shakkashell" / "memory")
    
    # Memory limits
    max_memories: int = 10000
    max_per_target: int = 1000
    
    # Recall settings
    default_similarity_threshold: float = 0.7
    default_recall_limit: int = 10
    
    # Embedding settings
    embedding_provider: str = "none"  # "openai", "ollama", "none"
    embedding_model: str = "text-embedding-3-small"
    
    # Privacy mode
    privacy_mode: bool = False  # No persistent storage when enabled
    
    def __post_init__(self):
        """Ensure storage_path is a Path object."""
        if isinstance(self.storage_path, str):
            self.storage_path = Path(self.storage_path)


class MemoryBackend(ABC):
    """Abstract base class for memory storage backends."""
    
    @abstractmethod
    def store(self, entry: MemoryEntry) -> str:
        """Store a memory entry. Returns the entry ID."""
        pass
    
    @abstractmethod
    def recall(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        target: Optional[str] = None,
        limit: int = 10,
        similarity_threshold: float = 0.7,
    ) -> list[MemoryEntry]:
        """Recall memories matching the query."""
        pass
    
    @abstractmethod
    def forget(
        self,
        target: Optional[str] = None,
        memory_type: Optional[MemoryType] = None,
        memory_id: Optional[str] = None,
    ) -> int:
        """Delete memories. Returns count of deleted entries."""
        pass
    
    @abstractmethod
    def get_stats(self) -> dict:
        """Get storage statistics."""
        pass
    
    @abstractmethod
    def export(self, path: Path) -> None:
        """Export memories to a file."""
        pass
    
    @abstractmethod
    def import_memories(self, path: Path) -> int:
        """Import memories from a file. Returns count of imported entries."""
        pass


class JSONMemoryBackend(MemoryBackend):
    """Simple JSON-based memory storage with keyword matching.
    
    This backend doesn't use vector embeddings but provides basic functionality
    when ChromaDB is not available.
    """
    
    def __init__(self, config: MemoryConfig):
        """Initialize the JSON backend.
        
        Args:
            config: Memory configuration.
        """
        self.config = config
        self._memories: dict[str, MemoryEntry] = {}
        self._storage_file = config.storage_path / "memories.json"
        self._counter = 0
        
        if not config.privacy_mode:
            self._load()
    
    def _load(self) -> None:
        """Load memories from disk."""
        if self._storage_file.exists():
            try:
                with open(self._storage_file) as f:
                    data = json.load(f)
                    for entry_data in data.get("memories", []):
                        entry = MemoryEntry.from_dict(entry_data)
                        self._memories[entry.id] = entry
                    self._counter = data.get("counter", len(self._memories))
            except (json.JSONDecodeError, KeyError):
                # Corrupted file, start fresh
                self._memories = {}
                self._counter = 0
    
    def _save(self) -> None:
        """Save memories to disk."""
        if self.config.privacy_mode:
            return
        
        self.config.storage_path.mkdir(parents=True, exist_ok=True)
        
        data = {
            "counter": self._counter,
            "memories": [entry.to_dict() for entry in self._memories.values()],
        }
        
        with open(self._storage_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _generate_id(self) -> str:
        """Generate a unique memory ID."""
        self._counter += 1
        return f"mem_{self._counter:06d}"
    
    def _keyword_match(self, query: str, content: str) -> float:
        """Simple keyword matching score (0.0 to 1.0)."""
        query_words = set(query.lower().split())
        content_words = set(content.lower().split())
        
        if not query_words:
            return 0.0
        
        # Calculate Jaccard-like similarity
        intersection = query_words & content_words
        union = query_words | content_words
        
        if not union:
            return 0.0
        
        return len(intersection) / len(union)
    
    def store(self, entry: MemoryEntry) -> str:
        """Store a memory entry."""
        if not entry.id:
            entry.id = self._generate_id()
        
        # Enforce limits with LRU eviction
        if len(self._memories) >= self.config.max_memories:
            # Remove oldest entry
            oldest = min(self._memories.values(), key=lambda e: e.timestamp)
            del self._memories[oldest.id]
        
        self._memories[entry.id] = entry
        self._save()
        return entry.id
    
    def recall(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        target: Optional[str] = None,
        limit: int = 10,
        similarity_threshold: float = 0.7,
    ) -> list[MemoryEntry]:
        """Recall memories matching the query using keyword matching."""
        results: list[tuple[float, MemoryEntry]] = []
        
        for entry in self._memories.values():
            # Filter by type if specified
            if memory_type and entry.memory_type != memory_type:
                continue
            
            # Filter by target if specified
            if target and entry.target != target:
                continue
            
            # Calculate similarity score
            score = self._keyword_match(query, entry.content)
            
            if score >= similarity_threshold:
                results.append((score, entry))
        
        # Sort by score descending
        results.sort(key=lambda x: x[0], reverse=True)
        
        return [entry for _, entry in results[:limit]]
    
    def forget(
        self,
        target: Optional[str] = None,
        memory_type: Optional[MemoryType] = None,
        memory_id: Optional[str] = None,
    ) -> int:
        """Delete memories matching criteria."""
        to_delete = []
        
        for entry_id, entry in self._memories.items():
            if memory_id and entry_id == memory_id:
                to_delete.append(entry_id)
            elif target and entry.target == target:
                if memory_type is None or entry.memory_type == memory_type:
                    to_delete.append(entry_id)
            elif memory_type and entry.memory_type == memory_type and target is None:
                to_delete.append(entry_id)
        
        for entry_id in to_delete:
            del self._memories[entry_id]
        
        if to_delete:
            self._save()
        
        return len(to_delete)
    
    def get_stats(self) -> dict:
        """Get storage statistics."""
        type_counts = {}
        target_counts = {}
        
        for entry in self._memories.values():
            type_counts[entry.memory_type.value] = type_counts.get(entry.memory_type.value, 0) + 1
            if entry.target:
                target_counts[entry.target] = target_counts.get(entry.target, 0) + 1
        
        return {
            "total_memories": len(self._memories),
            "by_type": type_counts,
            "by_target": target_counts,
            "backend": "json",
            "storage_path": str(self.config.storage_path),
        }
    
    def export(self, path: Path) -> None:
        """Export memories to a file."""
        data = {
            "exported_at": datetime.now().isoformat(),
            "total_memories": len(self._memories),
            "memories": [entry.to_dict() for entry in self._memories.values()],
        }
        
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    
    def import_memories(self, path: Path) -> int:
        """Import memories from a file."""
        with open(path) as f:
            data = json.load(f)
        
        imported = 0
        for entry_data in data.get("memories", []):
            entry = MemoryEntry.from_dict(entry_data)
            # Generate new ID to avoid conflicts
            entry.id = self._generate_id()
            self._memories[entry.id] = entry
            imported += 1
        
        self._save()
        return imported
    
    def clear(self) -> int:
        """Clear all memories. Returns count of deleted entries."""
        count = len(self._memories)
        self._memories.clear()
        self._save()
        return count


class VectorMemoryBackend(MemoryBackend):
    """ChromaDB-based vector memory storage with semantic search.
    
    Falls back to JSONMemoryBackend if ChromaDB is not available.
    """
    
    def __init__(self, config: MemoryConfig):
        """Initialize the vector backend.
        
        Args:
            config: Memory configuration.
        """
        self.config = config
        self._chroma_client = None
        self._collection = None
        self._available = False
        
        try:
            import chromadb
            from chromadb.config import Settings
            
            if not config.privacy_mode:
                config.storage_path.mkdir(parents=True, exist_ok=True)
                self._chroma_client = chromadb.PersistentClient(
                    path=str(config.storage_path / "chroma"),
                    settings=Settings(anonymized_telemetry=False),
                )
            else:
                self._chroma_client = chromadb.Client(
                    settings=Settings(anonymized_telemetry=False),
                )
            
            self._collection = self._chroma_client.get_or_create_collection(
                name="shakka_memories",
                metadata={"hnsw:space": "cosine"},
            )
            self._available = True
            
        except ImportError:
            # ChromaDB not installed, mark as unavailable
            self._available = False
    
    @property
    def is_available(self) -> bool:
        """Check if the vector backend is available."""
        return self._available
    
    def store(self, entry: MemoryEntry) -> str:
        """Store a memory entry with vector embedding."""
        if not self._available:
            raise RuntimeError("ChromaDB is not available")
        
        if not entry.id:
            entry.id = f"mem_{datetime.now().timestamp()}"
        
        # Store in ChromaDB
        self._collection.add(
            ids=[entry.id],
            documents=[entry.content],
            metadatas=[{
                "memory_type": entry.memory_type.value,
                "target": entry.target or "",
                "timestamp": entry.timestamp,
                **entry.metadata,
            }],
        )
        
        return entry.id
    
    def recall(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        target: Optional[str] = None,
        limit: int = 10,
        similarity_threshold: float = 0.7,
    ) -> list[MemoryEntry]:
        """Recall memories using semantic search."""
        if not self._available:
            raise RuntimeError("ChromaDB is not available")
        
        # Build where clause
        where = {}
        if memory_type:
            where["memory_type"] = memory_type.value
        if target:
            where["target"] = target
        
        # Query ChromaDB
        results = self._collection.query(
            query_texts=[query],
            n_results=limit,
            where=where if where else None,
        )
        
        entries = []
        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                # Check distance/similarity threshold
                distance = results["distances"][0][i] if results.get("distances") else 0
                # ChromaDB returns distance, convert to similarity (1 - distance for cosine)
                similarity = 1 - distance
                
                if similarity >= similarity_threshold:
                    metadata = results["metadatas"][0][i]
                    entries.append(MemoryEntry(
                        id=doc_id,
                        content=results["documents"][0][i],
                        memory_type=MemoryType(metadata.get("memory_type", "technique")),
                        target=metadata.get("target") or None,
                        timestamp=metadata.get("timestamp", ""),
                        metadata={k: v for k, v in metadata.items() 
                                 if k not in ("memory_type", "target", "timestamp")},
                    ))
        
        return entries
    
    def forget(
        self,
        target: Optional[str] = None,
        memory_type: Optional[MemoryType] = None,
        memory_id: Optional[str] = None,
    ) -> int:
        """Delete memories matching criteria."""
        if not self._available:
            raise RuntimeError("ChromaDB is not available")
        
        if memory_id:
            self._collection.delete(ids=[memory_id])
            return 1
        
        # Build where clause
        where = {}
        if memory_type:
            where["memory_type"] = memory_type.value
        if target:
            where["target"] = target
        
        if where:
            # Get matching IDs first
            results = self._collection.get(where=where)
            if results["ids"]:
                self._collection.delete(ids=results["ids"])
                return len(results["ids"])
        
        return 0
    
    def get_stats(self) -> dict:
        """Get storage statistics."""
        if not self._available:
            return {"error": "ChromaDB not available"}
        
        count = self._collection.count()
        
        return {
            "total_memories": count,
            "backend": "chromadb",
            "storage_path": str(self.config.storage_path),
        }
    
    def export(self, path: Path) -> None:
        """Export memories to a file."""
        if not self._available:
            raise RuntimeError("ChromaDB is not available")
        
        # Get all memories
        results = self._collection.get()
        
        memories = []
        for i, doc_id in enumerate(results["ids"]):
            metadata = results["metadatas"][i]
            memories.append({
                "id": doc_id,
                "content": results["documents"][i],
                "memory_type": metadata.get("memory_type", "technique"),
                "target": metadata.get("target"),
                "timestamp": metadata.get("timestamp", ""),
                "metadata": {k: v for k, v in metadata.items()
                           if k not in ("memory_type", "target", "timestamp")},
            })
        
        data = {
            "exported_at": datetime.now().isoformat(),
            "total_memories": len(memories),
            "memories": memories,
        }
        
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    
    def import_memories(self, path: Path) -> int:
        """Import memories from a file."""
        if not self._available:
            raise RuntimeError("ChromaDB is not available")
        
        with open(path) as f:
            data = json.load(f)
        
        imported = 0
        for entry_data in data.get("memories", []):
            entry = MemoryEntry.from_dict(entry_data)
            # Generate new ID to avoid conflicts
            entry.id = f"imported_{datetime.now().timestamp()}_{imported}"
            self.store(entry)
            imported += 1
        
        return imported
    
    def clear(self) -> int:
        """Clear all memories."""
        if not self._available:
            raise RuntimeError("ChromaDB is not available")
        
        count = self._collection.count()
        # Recreate collection to clear it
        self._chroma_client.delete_collection("shakka_memories")
        self._collection = self._chroma_client.create_collection(
            name="shakka_memories",
            metadata={"hnsw:space": "cosine"},
        )
        return count


class MemoryStore:
    """High-level memory store interface.
    
    Automatically selects the best available backend and provides
    a simple interface for memory operations.
    
    Example:
        store = MemoryStore()
        store.remember("SQLi worked on port 8080", target="192.168.1.1")
        results = store.recall("What SQL attacks worked?")
    """
    
    def __init__(self, config: Optional[MemoryConfig] = None):
        """Initialize the memory store.
        
        Args:
            config: Memory configuration. Uses defaults if not provided.
        """
        self.config = config or MemoryConfig()
        
        # Try vector backend first, fall back to JSON
        self._vector_backend = VectorMemoryBackend(self.config)
        
        if self._vector_backend.is_available:
            self._backend: MemoryBackend = self._vector_backend
            self._backend_type = "vector"
        else:
            self._backend = JSONMemoryBackend(self.config)
            self._backend_type = "json"
    
    @property
    def backend_type(self) -> str:
        """Get the current backend type."""
        return self._backend_type
    
    def remember(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.TECHNIQUE,
        target: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """Store a memory.
        
        Args:
            content: The memory content to store.
            memory_type: Type of memory (session, target, technique, failure).
            target: Optional target IP/hostname this memory relates to.
            metadata: Additional metadata to store.
            
        Returns:
            Memory ID.
        """
        entry = MemoryEntry(
            id="",
            content=content,
            memory_type=memory_type,
            target=target,
            metadata=metadata or {},
        )
        
        return self._backend.store(entry)
    
    def recall(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        target: Optional[str] = None,
        limit: Optional[int] = None,
        similarity_threshold: Optional[float] = None,
    ) -> RecallResult:
        """Recall memories matching a query.
        
        Args:
            query: Natural language query.
            memory_type: Filter by memory type.
            target: Filter by target.
            limit: Maximum results to return.
            similarity_threshold: Minimum similarity score.
            
        Returns:
            RecallResult with matching memories.
        """
        limit = limit or self.config.default_recall_limit
        threshold = similarity_threshold or self.config.default_similarity_threshold
        
        entries = self._backend.recall(
            query=query,
            memory_type=memory_type,
            target=target,
            limit=limit,
            similarity_threshold=threshold,
        )
        
        return RecallResult(
            entries=entries,
            query=query,
            similarity_threshold=threshold,
        )
    
    def forget(
        self,
        target: Optional[str] = None,
        memory_type: Optional[MemoryType] = None,
        memory_id: Optional[str] = None,
    ) -> int:
        """Delete memories.
        
        Args:
            target: Delete all memories for this target.
            memory_type: Delete all memories of this type.
            memory_id: Delete a specific memory by ID.
            
        Returns:
            Number of deleted memories.
        """
        return self._backend.forget(
            target=target,
            memory_type=memory_type,
            memory_id=memory_id,
        )
    
    def get_stats(self) -> dict:
        """Get memory storage statistics."""
        return self._backend.get_stats()
    
    def export(self, path: Path) -> None:
        """Export memories to a JSON file for sharing."""
        self._backend.export(path)
    
    def import_memories(self, path: Path) -> int:
        """Import memories from a JSON file.
        
        Args:
            path: Path to the JSON file.
            
        Returns:
            Number of imported memories.
        """
        return self._backend.import_memories(path)
    
    def clear(self) -> int:
        """Clear all memories.
        
        Returns:
            Number of cleared memories.
        """
        if isinstance(self._backend, JSONMemoryBackend):
            return self._backend.clear()
        elif isinstance(self._backend, VectorMemoryBackend):
            return self._backend.clear()
        return 0
