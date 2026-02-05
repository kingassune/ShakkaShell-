# Tool Detection

ShakkaShell v2 automatically detects installed security tools and generates commands using available software.

## Overview

The tool detection system:
- Scans for installed tools on startup
- Parses version information
- Provides fallback alternatives for missing tools
- Suggests installation commands
- Supports custom tool registration

## CLI Usage

```bash
# Detect available tools
shakka --detect-tools

# Output:
# Detected Tools:
#   ✓ nmap (7.94)
#   ✓ gobuster (3.6)
#   ✓ sqlmap (1.8)
#   ✓ ffuf (2.1)
#   ✗ nuclei (not found)
#   ✗ metasploit (not found)
```

## Automatic Fallbacks

When a preferred tool isn't available, ShakkaShell uses alternatives:

```bash
# User requests:
shakka generate "scan for vulnerabilities"

# If nuclei is unavailable, uses nmap scripts instead:
# → nmap --script vuln 10.0.0.1
```

## Python API

```python
from shakka.tools import ToolRegistry, ToolDetector, FallbackManager

# Detect tools
detector = ToolDetector()
available = await detector.detect_all()

for tool in available:
    print(f"{tool.name}: {tool.version}")
    print(f"  Path: {tool.path}")
    print(f"  Category: {tool.category}")
```

### Tool Registry

```python
from shakka.tools import ToolRegistry, ToolInfo, ToolCategory

# Get tool info
registry = ToolRegistry()

nmap = registry.get("nmap")
print(f"Name: {nmap.name}")
print(f"Category: {nmap.category}")  # ToolCategory.SCANNER
print(f"Description: {nmap.description}")
```

### Fallback Manager

```python
from shakka.tools import FallbackManager

manager = FallbackManager()

# Get fallback for unavailable tool
fallback = manager.get_fallback("nuclei")
print(f"Fallback: {fallback.tool}")  # "nmap --script vuln"
print(f"Command translation: {fallback.translation}")
```

## Pre-Registered Tools

| Category | Tools |
|----------|-------|
| **Scanners** | nmap, masscan, rustscan, zmap |
| **Web Enum** | gobuster, ffuf, feroxbuster, dirb, dirsearch |
| **Vuln Scan** | nuclei, nikto, wpscan, nessus |
| **SQLi** | sqlmap, ghauri |
| **Passwords** | hydra, medusa, hashcat, john |
| **Sniffing** | tcpdump, wireshark, tshark |
| **Exploitation** | metasploit, exploitdb |
| **Recon** | subfinder, amass, theHarvester |
| **Post-Exp** | mimikatz, impacket, crackmapexec |

## Fallback Rules

```python
# Built-in fallback translations
FALLBACKS = {
    "gobuster": "ffuf",
    "ffuf": "dirb",
    "nuclei": "nmap --script vuln",
    "rustscan": "nmap -T4",
    "feroxbuster": "gobuster",
    "ghauri": "sqlmap",
    "medusa": "hydra",
}
```

## Custom Tool Registration

```python
from shakka.tools import ToolRegistry, ToolInfo, ToolCategory

registry = ToolRegistry()

# Register custom tool
registry.register(ToolInfo(
    name="mytool",
    category=ToolCategory.SCANNER,
    description="My custom scanning tool",
    check_command="mytool --version",
    version_pattern=r"mytool v(\d+\.\d+\.\d+)"
))

# Add fallback
registry.add_fallback("mytool", "nmap")
```

## Installation Suggestions

```python
from shakka.tools import ToolDetector

detector = ToolDetector()

# Get installation suggestions for missing tools
missing = await detector.get_missing()

for tool in missing:
    print(f"Missing: {tool.name}")
    print(f"Install: {tool.install_command}")
    # e.g., "apt install nmap" or "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
```

## Configuration

```yaml
# config.yaml
tools:
  # Auto-detect on startup
  auto_detect: true
  
  # Enable fallbacks
  enable_fallbacks: true
  
  # Suggest installations
  suggest_install: true
  
  # Custom tool paths
  paths:
    nmap: /usr/local/bin/nmap
    sqlmap: ~/tools/sqlmap/sqlmap.py
  
  # Custom tools
  custom:
    - name: mytool
      category: scanner
      check_command: mytool --version
      version_pattern: "v(\\d+\\.\\d+)"
```

## Tool Categories

```python
from shakka.tools import ToolCategory

categories = [
    ToolCategory.SCANNER,        # Port/network scanners
    ToolCategory.WEB_ENUM,       # Directory/file enumeration
    ToolCategory.VULN_SCAN,      # Vulnerability scanners
    ToolCategory.SQLI,           # SQL injection
    ToolCategory.PASSWORD,       # Password cracking/brute-force
    ToolCategory.SNIFFING,       # Network sniffing
    ToolCategory.EXPLOITATION,   # Exploitation frameworks
    ToolCategory.RECON,          # Reconnaissance/OSINT
    ToolCategory.POST_EXP,       # Post-exploitation
]
```

## See Also

- [CLI Reference](cli.md)
- [Command Generation](cli.md#generate)
