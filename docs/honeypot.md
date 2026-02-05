# Anti-Honeypot Detection

ShakkaShell v2 includes heuristics to detect and avoid security traps (honeypots).

## Overview

The anti-honeypot system detects common trap patterns:
- Suspiciously easy credentials
- Unicode manipulation hiding content
- Planted evidence
- Canary files
- Timing anomalies
- Banner anomalies
- Service anomalies
- Network anomalies

## CLI Usage

```bash
# Enable paranoid mode
shakka --paranoid "enumerate 10.0.0.0/24"

# Output:
# ⚠️  POTENTIAL HONEYPOT INDICATORS DETECTED
#
# [!] 10.0.0.15 - SSH banner contains unusual delay pattern
# [!] 10.0.0.22 - credentials.txt found in web root (likely canary)
# [!] 10.0.0.30 - "Admin password: hunter2" in robots.txt (too easy)
#
# Recommended: Skip flagged hosts or proceed with caution
```

## Detection Patterns

### 1. Easy Credentials

Suspiciously obvious credentials in unexpected places:

```python
# Detected patterns:
- password.txt in web root
- "password: admin123" in robots.txt
- credentials.csv with high-value names
- Private keys in public directories
```

### 2. Unicode Manipulation

Hidden content using Unicode tricks:

```python
# U+0008 (backspace) hiding content from LLMs
# Example: "rm -rf /[U+0008][U+0008][U+0008][U+0008][U+0008]safe_file"
# LLM sees: "rm -rf safe_file"
# Terminal executes: "rm -rf /"
```

### 3. Planted Evidence

Fake "patched" notifications:

```python
# "All CVEs patched as of 2024-01-01"
# "Security audit completed - no vulnerabilities"
# Fake patch notifications in logs
```

### 4. Canary Files

Trap files designed to detect intrusion:

```python
# Suspicious file names:
- passwords.txt
- credentials.xlsx
- admin_backup.sql
- private_key.pem (in unusual locations)
```

### 5. Timing Anomalies

Unusual response patterns:

```python
# Services responding too fast
# Consistent response times (lack of jitter)
# Immediate responses to slow operations
```

### 6. Banner Anomalies

Known honeypot signatures:

```python
# Kippo/Cowrie SSH banners
# Dionaea service banners
# Generic/default banners
```

## Python API

```python
from shakka.honeypot import HoneypotDetector, Sensitivity

# Create detector
detector = HoneypotDetector(sensitivity=Sensitivity.HIGH)

# Check single indicator
result = detector.check_file("passwords.txt")
print(f"Suspicious: {result.is_suspicious}")
print(f"Confidence: {result.confidence}")
print(f"Category: {result.category}")

# Check multiple indicators
summary = await detector.analyze_target("10.0.0.1")
for indicator in summary.indicators:
    print(f"[{indicator.category}] {indicator.description}")
```

### Sensitivity Levels

```python
from shakka.honeypot import Sensitivity

levels = [
    Sensitivity.LOW,      # Only obvious honeypot signatures
    Sensitivity.MEDIUM,   # Default - balanced detection
    Sensitivity.HIGH,     # More aggressive, some false positives
    Sensitivity.PARANOID, # Maximum detection, high false positive rate
]

detector = HoneypotDetector(sensitivity=Sensitivity.PARANOID)
```

### Indicator Groups

```python
from shakka.honeypot import IndicatorGroup

groups = [
    IndicatorGroup.EASY_CREDENTIALS,
    IndicatorGroup.UNICODE_MANIPULATION,
    IndicatorGroup.PLANTED_EVIDENCE,
    IndicatorGroup.CANARY_FILES,
    IndicatorGroup.TIMING_ANOMALY,
    IndicatorGroup.BANNER_ANOMALY,
    IndicatorGroup.SERVICE_ANOMALY,
    IndicatorGroup.NETWORK_ANOMALY,
]
```

### Batch Analysis

```python
from shakka.honeypot import HoneypotDetector, IndicatorSummary

detector = HoneypotDetector()

# Analyze multiple targets
targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
summary = await detector.batch_analyze(targets)

for target, result in summary.items():
    if result.has_indicators:
        print(f"\n{target}:")
        for indicator in result.indicators:
            print(f"  [{indicator.severity}] {indicator.description}")
```

### Custom Detection Functions

```python
from shakka.honeypot import HoneypotDetector

detector = HoneypotDetector()

# Add custom check
@detector.register_check("my_check")
def check_custom_pattern(content: str) -> bool:
    return "DEFINITELY_A_HONEYPOT" in content

# Check with custom function
result = detector.check("file content with DEFINITELY_A_HONEYPOT")
```

## Configuration

```yaml
# config.yaml
honeypot:
  # Enable detection
  enabled: true
  
  # Sensitivity level
  sensitivity: medium  # low, medium, high, paranoid
  
  # Action on detection
  action: warn  # warn, skip, or block
  
  # Log suspicious hosts
  log_suspicious: true
  
  # Custom patterns
  custom_patterns:
    - pattern: "admin.*password"
      category: easy_credentials
      description: "Admin password exposed"
    
  # Known honeypot IPs to skip
  known_honeypots:
    - 10.0.0.99
```

## Recommendations

When honeypot indicators are detected, ShakkaShell provides recommendations:

```python
from shakka.honeypot import HoneypotDetector

detector = HoneypotDetector()
result = detector.analyze_target("10.0.0.1")

for rec in result.recommendations:
    print(f"• {rec}")

# Example output:
# • Skip this host - multiple honeypot indicators detected
# • If proceeding, use isolated environment
# • Consider this target for deception analysis
# • Review all credentials carefully before use
```

## Detection Logging

```python
from shakka.honeypot import HoneypotDetector

detector = HoneypotDetector(log_path="~/.config/shakka/honeypot.log")

# Log entries include:
# - Timestamp
# - Target
# - Indicator category
# - Confidence score
# - Detection details
```

## See Also

- [Safety Layer](safety.md)
- [Multi-Agent System](agents.md)
