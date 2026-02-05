# Vector Memory

ShakkaShell v2 includes persistent vector memory for storing and retrieving attack knowledge using semantic search.

## Overview

The memory system stores:
- **Session Memory**: Current engagement context
- **Target Memory**: Per-target findings and successful approaches
- **Technique Memory**: General attack patterns that worked
- **Failure Memory**: Approaches to avoid

## Storage Backends

| Backend | Description | Use Case |
|---------|-------------|----------|
| **JSON** | Simple file-based storage | Default, zero dependencies |
| **ChromaDB** | Vector database with embeddings | Semantic search, large datasets |

## CLI Usage

```bash
# Remember something
shakka remember "SQLi on port 8080 worked with --dbs flag"

# Recall relevant memories
shakka recall "What worked on this target?"

# Forget memories for a target
shakka forget --target 192.168.1.1
```

## Automatic Memory

Memory is automatically captured during command execution:

```bash
# This scan will be remembered
shakka generate "scan 192.168.1.1"

# Future commands will recall previous findings
shakka generate "exploit 192.168.1.1"
# → Recalls: "Previous scan found ports 22, 80, 443 open"
```

## Python API

```python
from shakka.memory import MemoryStore, MemoryType

# Create store
store = MemoryStore(backend="chromadb")

# Store memory
await store.remember(
    content="SQLi found on login form",
    memory_type=MemoryType.TECHNIQUE,
    target="192.168.1.1",
    metadata={"port": 80, "path": "/login"}
)

# Recall memories
memories = await store.recall(
    query="SQL injection techniques",
    limit=5,
    memory_type=MemoryType.TECHNIQUE
)

for memory in memories:
    print(f"[{memory.similarity:.2f}] {memory.content}")
```

### Memory Types

```python
from shakka.memory import MemoryType

# Session Memory - current engagement
store.remember("Target scope: 10.0.0.0/24", MemoryType.SESSION)

# Target Memory - per-target findings
store.remember("Open ports: 22, 80, 443", MemoryType.TARGET, target="10.0.0.1")

# Technique Memory - general patterns
store.remember("Kerberoasting worked on AD", MemoryType.TECHNIQUE)

# Failure Memory - approaches to avoid
store.remember("NTLM relay blocked by SMB signing", MemoryType.FAILURE)
```

### Semantic Search

```python
# Search with similarity threshold
results = await store.recall(
    query="password attacks on Active Directory",
    threshold=0.7,  # Minimum similarity score
    limit=10
)

for result in results:
    print(f"Score: {result.similarity}")
    print(f"Content: {result.content}")
    print(f"Type: {result.memory_type}")
```

## Storage Layout

```
~/.shakkashell/
├── memory/
│   ├── store.json       # JSON backend
│   ├── chroma.db/       # ChromaDB backend
│   ├── targets/         # Per-target JSON files
│   │   ├── 192.168.1.1.json
│   │   └── target.com.json
│   └── exports/         # Team sharing exports
```

## Configuration

```yaml
# config.yaml
memory:
  # Enable persistent memory
  enable: true
  
  # Backend: json or chromadb
  backend: json
  
  # Maximum entries (LRU eviction when exceeded)
  max_entries: 1000
  
  # Privacy mode (no persistent storage)
  privacy_mode: false
  
  # Embedding model
  embedding_model: text-embedding-3-small
  
  # Similarity threshold for recall
  similarity_threshold: 0.7
```

## Export/Import

Share memory between team members:

```python
from shakka.memory import MemoryStore

store = MemoryStore()

# Export memories
await store.export("engagement_findings.json")

# Import memories
await store.import_from("teammate_findings.json")
```

## Privacy Mode

Disable persistent storage:

```python
store = MemoryStore(privacy_mode=True)

# Memories only exist in-memory for this session
store.remember("Sensitive finding", MemoryType.SESSION)

# Nothing persisted to disk
```

Or via config:

```yaml
memory:
  privacy_mode: true
```

## LRU Eviction

When max_entries is exceeded, oldest memories are evicted:

```python
store = MemoryStore(max_entries=1000)

# When 1001st memory is added, oldest is removed
# Failure memories are evicted first
# Then technique, target, session
```

## See Also

- [Multi-Agent System](agents.md)
- [Configuration](configuration.md)
