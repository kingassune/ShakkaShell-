# Safety Layer

ShakkaShell includes a comprehensive safety layer to prevent accidental execution of dangerous commands.

## Overview

The safety layer:
- Detects dangerous command patterns
- Classifies risk levels
- Requires confirmation for high-risk commands
- Maintains audit logs
- Supports blocklists

## Risk Categories

| Category | Description | Examples |
|----------|-------------|----------|
| **Destructive** | Irreversible file/data deletion | `rm -rf`, `mkfs`, `dd if=` |
| **Privilege Escalation** | Gaining elevated privileges | `sudo`, `chmod 777`, `chown root` |
| **Network Exfil** | Data exfiltration risk | `curl \| bash`, `wget -O- \| sh` |
| **Credential Exposure** | Password/key disclosure | Dumping credentials, key extraction |
| **Disk Operation** | Disk-level operations | `fdisk`, `parted`, `mount` |
| **System Modification** | System configuration changes | Modifying `/etc`, registry edits |

## Risk Levels

| Level | Description | Action |
|-------|-------------|--------|
| **Low** | Safe information gathering | Execute directly |
| **Medium** | May trigger detection | Show warning |
| **High** | Potentially harmful | Require confirmation |
| **Critical** | Destructive/irreversible | Block or require explicit override |

## CLI Behavior

### Default (Confirmation Required)

```
$ shakka generate "delete all logs"

⚠️  DANGEROUS COMMAND DETECTED

Generated command:
  sudo rm -rf /var/log/*

Risks identified:
  • Irreversible file deletion (destructive)
  • Requires root privileges (privilege_escalation)
  • Affects system logging (system_modification)

Recommendations:
  • Consider backing up logs first
  • Use more targeted deletion
  • Review what will be deleted with -i flag

[E]xecute  [M]odify  [C]ancel  [?] Help
```

### YOLO Mode (Skip Confirmations)

```bash
# Warning: Skips all safety confirmations
shakka generate "delete logs" --yolo

# Or set globally
export SHAKKA_YOLO_MODE=true
```

## Python API

```python
from shakka.core.safety import SafetyChecker, RiskLevel

# Create checker
checker = SafetyChecker()

# Check command
result = checker.check("rm -rf /var/log/*")

print(f"Risk Level: {result.risk_level}")  # RiskLevel.CRITICAL
print(f"Categories: {result.categories}")   # ['destructive', 'system_modification']
print(f"Warnings: {result.warnings}")
print(f"Recommendations: {result.recommendations}")

# Check if blocked
if result.is_blocked:
    print("Command is blocked by policy")
```

### Custom Blocklist

```python
checker = SafetyChecker(
    blocklist=[
        "rm -rf /",
        "mkfs",
        ":(){ :|:& };:"  # Fork bomb
    ]
)

# Check against blocklist
result = checker.check("mkfs.ext4 /dev/sda1")
if result.is_blocked:
    print("Command matches blocklist!")
```

## Configuration

```yaml
# config.yaml
safety:
  # Require confirmation for dangerous commands
  confirm_dangerous: true
  
  # Block destructive commands entirely (vs just warn)
  block_destructive: false
  
  # YOLO mode - skip all confirmations
  yolo_mode: false
  
  # Whitelist of allowed targets (IPs/domains)
  allowed_targets:
    - 10.0.0.0/8
    - 192.168.0.0/16
    - target.local
  
  # Absolute blocklist - never allow these
  blocked_commands:
    - "rm -rf /"
    - "rm -rf /*"
    - "mkfs"
    - ":(){ :|:& };:"
  
  # Audit logging
  audit_log: ~/.config/shakka/audit.log
  audit_enabled: true
```

## Audit Logging

All executed commands are logged:

```python
from shakka.core.safety import AuditLogger

logger = AuditLogger()

# Log entry format
entry = {
    "timestamp": "2026-02-05T10:30:00Z",
    "command": "nmap -sV 10.0.0.1",
    "risk_level": "medium",
    "categories": ["network_scan"],
    "executed": True,
    "user_confirmed": True
}
logger.log(entry)

# View audit log
for entry in logger.entries():
    print(f"{entry.timestamp}: {entry.command}")
```

## Pattern Detection

The safety layer uses regex patterns for detection:

```python
# Built-in patterns
DESTRUCTIVE_PATTERNS = [
    r"rm\s+(-[rf]+\s+)*(/|/\*)",
    r"mkfs",
    r"dd\s+if=",
    r"shred",
    r"wipefs"
]

PRIV_ESC_PATTERNS = [
    r"\bsudo\b",
    r"chmod\s+[0-7]*7[0-7]*",
    r"chown\s+root",
    r"setuid"
]
```

## Formatted Warnings

```
┌─────────────────────────────────────────────────────────┐
│ ⚠️  SAFETY WARNING                                      │
├─────────────────────────────────────────────────────────┤
│ Risk Level: HIGH                                        │
│                                                         │
│ Command:                                                │
│   sudo rm -rf /var/log/*                               │
│                                                         │
│ Detected Risks:                                         │
│   • [destructive] Irreversible file deletion           │
│   • [privilege_escalation] Root access required        │
│   • [system_modification] System logs affected         │
│                                                         │
│ Recommendations:                                        │
│   1. Backup logs before deletion                       │
│   2. Use targeted deletion: rm /var/log/app.log       │
│   3. Use -i flag for interactive confirmation         │
└─────────────────────────────────────────────────────────┘
```

## See Also

- [CLI Reference](cli.md)
- [Configuration](configuration.md)
