"""Tests for the persistent vector memory module."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from shakka.storage.memory import (
    JSONMemoryBackend,
    MemoryConfig,
    MemoryEntry,
    MemoryStore,
    MemoryType,
    RecallResult,
    VectorMemoryBackend,
)


class TestMemoryType:
    """Tests for MemoryType enum."""
    
    def test_session_type(self):
        """Test SESSION memory type."""
        assert MemoryType.SESSION.value == "session"
    
    def test_target_type(self):
        """Test TARGET memory type."""
        assert MemoryType.TARGET.value == "target"
    
    def test_technique_type(self):
        """Test TECHNIQUE memory type."""
        assert MemoryType.TECHNIQUE.value == "technique"
    
    def test_failure_type(self):
        """Test FAILURE memory type."""
        assert MemoryType.FAILURE.value == "failure"


class TestMemoryEntry:
    """Tests for MemoryEntry dataclass."""
    
    def test_create_entry(self):
        """Test creating a memory entry."""
        entry = MemoryEntry(
            id="test_001",
            content="SQLi worked on port 8080",
            memory_type=MemoryType.TECHNIQUE,
        )
        
        assert entry.id == "test_001"
        assert entry.content == "SQLi worked on port 8080"
        assert entry.memory_type == MemoryType.TECHNIQUE
        assert entry.target is None
        assert entry.metadata == {}
    
    def test_entry_with_target(self):
        """Test entry with target."""
        entry = MemoryEntry(
            id="test_002",
            content="Port 22 open",
            memory_type=MemoryType.TARGET,
            target="192.168.1.1",
        )
        
        assert entry.target == "192.168.1.1"
    
    def test_entry_with_metadata(self):
        """Test entry with metadata."""
        entry = MemoryEntry(
            id="test_003",
            content="Test content",
            memory_type=MemoryType.SESSION,
            metadata={"tool": "nmap", "severity": "high"},
        )
        
        assert entry.metadata["tool"] == "nmap"
        assert entry.metadata["severity"] == "high"
    
    def test_to_dict(self):
        """Test converting entry to dictionary."""
        entry = MemoryEntry(
            id="test_004",
            content="Test",
            memory_type=MemoryType.FAILURE,
            target="10.0.0.1",
        )
        
        data = entry.to_dict()
        
        assert data["id"] == "test_004"
        assert data["content"] == "Test"
        assert data["memory_type"] == "failure"
        assert data["target"] == "10.0.0.1"
    
    def test_from_dict(self):
        """Test creating entry from dictionary."""
        data = {
            "id": "test_005",
            "content": "Restored memory",
            "memory_type": "technique",
            "target": "example.com",
            "timestamp": "2025-02-05T10:00:00",
            "metadata": {"key": "value"},
        }
        
        entry = MemoryEntry.from_dict(data)
        
        assert entry.id == "test_005"
        assert entry.content == "Restored memory"
        assert entry.memory_type == MemoryType.TECHNIQUE
        assert entry.target == "example.com"
        assert entry.timestamp == "2025-02-05T10:00:00"


class TestRecallResult:
    """Tests for RecallResult dataclass."""
    
    def test_empty_result(self):
        """Test empty recall result."""
        result = RecallResult(entries=[], query="test", similarity_threshold=0.7)
        
        assert result.found is False
        assert "No relevant memories found" in result.format()
    
    def test_result_with_entries(self):
        """Test recall result with entries."""
        entries = [
            MemoryEntry(id="1", content="Memory 1", memory_type=MemoryType.TECHNIQUE),
            MemoryEntry(id="2", content="Memory 2", memory_type=MemoryType.TARGET),
        ]
        
        result = RecallResult(entries=entries, query="test", similarity_threshold=0.7)
        
        assert result.found is True
        assert len(result.entries) == 2
    
    def test_format_with_entries(self):
        """Test formatting with entries."""
        entries = [
            MemoryEntry(
                id="1",
                content="SQLi on port 8080",
                memory_type=MemoryType.TECHNIQUE,
                target="192.168.1.1",
            ),
        ]
        
        result = RecallResult(entries=entries, query="SQL", similarity_threshold=0.7)
        formatted = result.format()
        
        assert "Found 1 relevant memories" in formatted
        assert "[technique]" in formatted
        assert "SQLi on port 8080" in formatted
        assert "Target: 192.168.1.1" in formatted


class TestMemoryConfig:
    """Tests for MemoryConfig."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = MemoryConfig()
        
        assert config.max_memories == 10000
        assert config.max_per_target == 1000
        assert config.default_similarity_threshold == 0.7
        assert config.default_recall_limit == 10
        assert config.embedding_provider == "none"
        assert config.privacy_mode is False
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = MemoryConfig(
            max_memories=5000,
            privacy_mode=True,
            default_similarity_threshold=0.8,
        )
        
        assert config.max_memories == 5000
        assert config.privacy_mode is True
        assert config.default_similarity_threshold == 0.8
    
    def test_storage_path_string(self):
        """Test storage path from string."""
        config = MemoryConfig(storage_path="/tmp/test_memory")
        
        assert isinstance(config.storage_path, Path)
        assert str(config.storage_path) == "/tmp/test_memory"


class TestJSONMemoryBackend:
    """Tests for JSONMemoryBackend."""
    
    @pytest.fixture
    def temp_storage(self):
        """Create a temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def backend(self, temp_storage):
        """Create a JSON backend with temporary storage."""
        config = MemoryConfig(storage_path=temp_storage)
        return JSONMemoryBackend(config)
    
    def test_store_and_recall(self, backend):
        """Test storing and recalling a memory."""
        entry = MemoryEntry(
            id="",
            content="nmap scan revealed open ports",
            memory_type=MemoryType.TECHNIQUE,
        )
        
        memory_id = backend.store(entry)
        
        assert memory_id.startswith("mem_")
        
        results = backend.recall("nmap open ports", similarity_threshold=0.3)
        
        assert len(results) > 0
        assert "nmap" in results[0].content.lower()
    
    def test_recall_by_type(self, backend):
        """Test recalling by memory type."""
        backend.store(MemoryEntry(
            id="",
            content="Technique memory",
            memory_type=MemoryType.TECHNIQUE,
        ))
        backend.store(MemoryEntry(
            id="",
            content="Failure memory",
            memory_type=MemoryType.FAILURE,
        ))
        
        results = backend.recall(
            "memory",
            memory_type=MemoryType.TECHNIQUE,
            similarity_threshold=0.2,
        )
        
        for result in results:
            assert result.memory_type == MemoryType.TECHNIQUE
    
    def test_recall_by_target(self, backend):
        """Test recalling by target."""
        backend.store(MemoryEntry(
            id="",
            content="Port 22 SSH open",
            memory_type=MemoryType.TARGET,
            target="192.168.1.1",
        ))
        backend.store(MemoryEntry(
            id="",
            content="Port 80 HTTP open",
            memory_type=MemoryType.TARGET,
            target="192.168.1.2",
        ))
        
        results = backend.recall(
            "Port open",
            target="192.168.1.1",
            similarity_threshold=0.2,
        )
        
        for result in results:
            assert result.target == "192.168.1.1"
    
    def test_forget_by_id(self, backend):
        """Test forgetting by memory ID."""
        memory_id = backend.store(MemoryEntry(
            id="",
            content="Test memory",
            memory_type=MemoryType.SESSION,
        ))
        
        deleted = backend.forget(memory_id=memory_id)
        
        assert deleted == 1
        
        results = backend.recall("Test memory", similarity_threshold=0.2)
        assert len(results) == 0
    
    def test_forget_by_target(self, backend):
        """Test forgetting by target."""
        backend.store(MemoryEntry(
            id="",
            content="Memory 1",
            memory_type=MemoryType.TARGET,
            target="10.0.0.1",
        ))
        backend.store(MemoryEntry(
            id="",
            content="Memory 2",
            memory_type=MemoryType.TARGET,
            target="10.0.0.1",
        ))
        backend.store(MemoryEntry(
            id="",
            content="Memory 3",
            memory_type=MemoryType.TARGET,
            target="10.0.0.2",
        ))
        
        deleted = backend.forget(target="10.0.0.1")
        
        assert deleted == 2
    
    def test_forget_by_type(self, backend):
        """Test forgetting by type."""
        backend.store(MemoryEntry(
            id="",
            content="Session 1",
            memory_type=MemoryType.SESSION,
        ))
        backend.store(MemoryEntry(
            id="",
            content="Technique 1",
            memory_type=MemoryType.TECHNIQUE,
        ))
        
        deleted = backend.forget(memory_type=MemoryType.SESSION)
        
        assert deleted == 1
    
    def test_get_stats(self, backend):
        """Test getting statistics."""
        backend.store(MemoryEntry(
            id="",
            content="Test 1",
            memory_type=MemoryType.TECHNIQUE,
        ))
        backend.store(MemoryEntry(
            id="",
            content="Test 2",
            memory_type=MemoryType.TARGET,
            target="192.168.1.1",
        ))
        
        stats = backend.get_stats()
        
        assert stats["total_memories"] == 2
        assert stats["backend"] == "json"
        assert "technique" in stats["by_type"]
        assert "target" in stats["by_type"]
    
    def test_export_and_import(self, backend, temp_storage):
        """Test export and import functionality."""
        backend.store(MemoryEntry(
            id="",
            content="Exportable memory",
            memory_type=MemoryType.TECHNIQUE,
        ))
        
        export_path = temp_storage / "export.json"
        backend.export(export_path)
        
        assert export_path.exists()
        
        # Create new backend and import
        new_config = MemoryConfig(storage_path=temp_storage / "new")
        new_backend = JSONMemoryBackend(new_config)
        
        imported = new_backend.import_memories(export_path)
        
        assert imported == 1
        
        results = new_backend.recall("Exportable", similarity_threshold=0.2)
        assert len(results) == 1
    
    def test_clear(self, backend):
        """Test clearing all memories."""
        backend.store(MemoryEntry(
            id="",
            content="Memory 1",
            memory_type=MemoryType.TECHNIQUE,
        ))
        backend.store(MemoryEntry(
            id="",
            content="Memory 2",
            memory_type=MemoryType.SESSION,
        ))
        
        cleared = backend.clear()
        
        assert cleared == 2
        assert backend.get_stats()["total_memories"] == 0
    
    def test_lru_eviction(self, temp_storage):
        """Test LRU eviction when limit is reached."""
        config = MemoryConfig(storage_path=temp_storage, max_memories=3)
        backend = JSONMemoryBackend(config)
        
        backend.store(MemoryEntry(
            id="",
            content="First oldest",
            memory_type=MemoryType.TECHNIQUE,
            timestamp="2025-01-01T00:00:00",
        ))
        backend.store(MemoryEntry(
            id="",
            content="Second",
            memory_type=MemoryType.TECHNIQUE,
            timestamp="2025-01-02T00:00:00",
        ))
        backend.store(MemoryEntry(
            id="",
            content="Third",
            memory_type=MemoryType.TECHNIQUE,
            timestamp="2025-01-03T00:00:00",
        ))
        backend.store(MemoryEntry(
            id="",
            content="Fourth newest",
            memory_type=MemoryType.TECHNIQUE,
            timestamp="2025-01-04T00:00:00",
        ))
        
        # Should have evicted the oldest
        stats = backend.get_stats()
        assert stats["total_memories"] == 3
        
        results = backend.recall("oldest", similarity_threshold=0.2)
        assert len(results) == 0  # "First oldest" should be evicted
    
    def test_privacy_mode(self, temp_storage):
        """Test privacy mode doesn't persist."""
        config = MemoryConfig(storage_path=temp_storage, privacy_mode=True)
        backend = JSONMemoryBackend(config)
        
        backend.store(MemoryEntry(
            id="",
            content="Private memory",
            memory_type=MemoryType.SESSION,
        ))
        
        # Memory file should not exist
        memory_file = temp_storage / "memories.json"
        assert not memory_file.exists()
    
    def test_persistence(self, temp_storage):
        """Test memories persist across backend instances."""
        config = MemoryConfig(storage_path=temp_storage)
        backend1 = JSONMemoryBackend(config)
        
        backend1.store(MemoryEntry(
            id="",
            content="Persistent memory",
            memory_type=MemoryType.TECHNIQUE,
        ))
        
        # Create new backend instance
        backend2 = JSONMemoryBackend(config)
        
        results = backend2.recall("Persistent", similarity_threshold=0.2)
        assert len(results) == 1


class TestVectorMemoryBackend:
    """Tests for VectorMemoryBackend."""
    
    @pytest.fixture
    def temp_storage(self):
        """Create a temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def test_availability_check(self, temp_storage):
        """Test availability check for ChromaDB."""
        config = MemoryConfig(storage_path=temp_storage)
        backend = VectorMemoryBackend(config)
        
        # Backend should indicate availability status
        assert isinstance(backend.is_available, bool)
    
    def test_fallback_when_unavailable(self, temp_storage):
        """Test that operations raise when ChromaDB unavailable."""
        config = MemoryConfig(storage_path=temp_storage)
        backend = VectorMemoryBackend(config)
        
        if not backend.is_available:
            with pytest.raises(RuntimeError, match="ChromaDB is not available"):
                backend.store(MemoryEntry(
                    id="",
                    content="Test",
                    memory_type=MemoryType.TECHNIQUE,
                ))


class TestMemoryStore:
    """Tests for MemoryStore high-level interface."""
    
    @pytest.fixture
    def temp_storage(self):
        """Create a temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def store(self, temp_storage):
        """Create a memory store with temporary storage."""
        config = MemoryConfig(storage_path=temp_storage)
        return MemoryStore(config)
    
    def test_remember(self, store):
        """Test remember method."""
        memory_id = store.remember(
            "SQLi worked on port 8080 with --dbs flag",
            memory_type=MemoryType.TECHNIQUE,
            target="192.168.1.1",
        )
        
        assert memory_id.startswith("mem_")
    
    def test_recall(self, store):
        """Test recall method."""
        store.remember("nmap scan found SSH on port 22", memory_type=MemoryType.TARGET)
        store.remember("gobuster found /admin directory", memory_type=MemoryType.TARGET)
        
        result = store.recall("nmap SSH port", similarity_threshold=0.2)
        
        assert isinstance(result, RecallResult)
        assert result.found is True
    
    def test_forget(self, store):
        """Test forget method."""
        store.remember("Memory to delete", target="10.0.0.1")
        
        deleted = store.forget(target="10.0.0.1")
        
        assert deleted == 1
    
    def test_get_stats(self, store):
        """Test get_stats method."""
        store.remember("Test memory", memory_type=MemoryType.TECHNIQUE)
        
        stats = store.get_stats()
        
        assert stats["total_memories"] == 1
        assert "backend" in stats
    
    def test_export_and_import(self, store, temp_storage):
        """Test export and import via store interface."""
        store.remember("Shareable knowledge", memory_type=MemoryType.TECHNIQUE)
        
        export_path = temp_storage / "share.json"
        store.export(export_path)
        
        # Create new store and import
        new_config = MemoryConfig(storage_path=temp_storage / "team")
        new_store = MemoryStore(new_config)
        
        imported = new_store.import_memories(export_path)
        
        assert imported == 1
    
    def test_clear(self, store):
        """Test clear method."""
        store.remember("Memory 1")
        store.remember("Memory 2")
        
        cleared = store.clear()
        
        assert cleared == 2
        assert store.get_stats()["total_memories"] == 0
    
    def test_backend_type(self, store):
        """Test backend type detection."""
        # Without ChromaDB, should use JSON backend
        assert store.backend_type in ["json", "vector"]
    
    def test_default_memory_type(self, store):
        """Test default memory type is TECHNIQUE."""
        memory_id = store.remember("Test default type")
        
        result = store.recall("Test default", similarity_threshold=0.2)
        
        if result.found:
            assert result.entries[0].memory_type == MemoryType.TECHNIQUE
    
    def test_metadata_storage(self, store):
        """Test storing with metadata."""
        store.remember(
            "SQLi vector",
            memory_type=MemoryType.TECHNIQUE,
            metadata={"tool": "sqlmap", "success": True},
        )
        
        result = store.recall("SQLi", similarity_threshold=0.2)
        
        if result.found:
            assert "tool" in result.entries[0].metadata
    
    def test_recall_with_limit(self, store):
        """Test recall with limit."""
        for i in range(5):
            store.remember(f"Memory entry {i} about testing")
        
        result = store.recall("Memory testing", limit=3, similarity_threshold=0.2)
        
        assert len(result.entries) <= 3
    
    def test_recall_empty_store(self, store):
        """Test recall on empty store."""
        result = store.recall("anything")
        
        assert result.found is False
        assert len(result.entries) == 0


class TestShakkaConfigMemory:
    """Tests for memory config in ShakkaConfig."""
    
    def test_default_memory_config(self):
        """Test default memory configuration."""
        from shakka.config import ShakkaConfig
        
        config = ShakkaConfig()
        
        assert config.memory_enabled is True
        assert config.memory_privacy_mode is False
        assert config.memory_max_entries == 10000
        assert config.memory_similarity_threshold == 0.7
        assert config.memory_embedding_provider == "none"
    
    def test_memory_config_from_env(self, monkeypatch):
        """Test memory config from environment variables."""
        from shakka.config import ShakkaConfig
        
        monkeypatch.setenv("SHAKKA_MEMORY_ENABLED", "false")
        monkeypatch.setenv("SHAKKA_MEMORY_PRIVACY_MODE", "true")
        monkeypatch.setenv("SHAKKA_MEMORY_MAX_ENTRIES", "5000")
        monkeypatch.setenv("SHAKKA_MEMORY_SIMILARITY_THRESHOLD", "0.8")
        
        config = ShakkaConfig()
        
        assert config.memory_enabled is False
        assert config.memory_privacy_mode is True
        assert config.memory_max_entries == 5000
        assert config.memory_similarity_threshold == 0.8
