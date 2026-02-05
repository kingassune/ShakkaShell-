# Report Generation

ShakkaShell v2 can generate professional penetration testing reports in multiple formats.

## Supported Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| **Markdown** | `.md` | Default, readable text |
| **HTML** | `.html` | Styled web format |
| **DOCX** | `.docx` | Microsoft Word |
| **PDF** | `.pdf` | Print-ready |
| **JSON** | `.json` | Machine-readable |

## CLI Usage

```bash
# Generate markdown report
shakka report --format markdown --output report.md

# Generate HTML report
shakka report --format html --output report.html

# Generate Word document
shakka report --format docx --output report.docx

# Generate PDF
shakka report --format pdf --output report.pdf
```

## Report Structure

Generated reports include:

1. **Executive Summary**
   - Overall risk assessment
   - Key findings summary
   - Recommended priority actions

2. **Methodology**
   - Testing approach
   - Scope and limitations
   - Tools used

3. **Findings**
   - Sorted by severity (Critical → Info)
   - CVSS v3.1 scoring
   - Evidence and screenshots
   - Remediation recommendations

4. **Technical Details**
   - Commands executed
   - Raw output
   - Exploitation steps

5. **Appendix**
   - Full command history
   - Scan results
   - Tool versions

## Python API

```python
from shakka.reports import ReportGenerator, Report, Finding, Severity

# Create findings
findings = [
    Finding(
        title="SQL Injection in Login Form",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="Authentication bypass via SQL injection",
        evidence=["Screenshot of sqlmap output"],
        remediation="Use parameterized queries",
        affected_systems=["https://target.com/login"]
    ),
    Finding(
        title="Weak TLS Configuration",
        severity=Severity.MEDIUM,
        cvss_score=5.3,
        description="Server supports TLS 1.0/1.1",
        remediation="Disable legacy TLS versions"
    )
]

# Generate report
generator = ReportGenerator()
report = generator.generate(
    title="Penetration Test Report - Target Corp",
    findings=findings,
    format="html"
)

# Save report
report.save("report.html")
```

### From Session Memory

```python
from shakka.reports import ReportGenerator
from shakka.memory import MemoryStore

# Generate report from session memory
store = MemoryStore()
generator = ReportGenerator()

report = await generator.from_memory(
    store,
    title="Engagement Report",
    format="docx"
)

report.save("engagement_report.docx")
```

## Severity Levels

| Severity | CVSS Range | Color |
|----------|------------|-------|
| Critical | 9.0 - 10.0 | Red |
| High | 7.0 - 8.9 | Orange |
| Medium | 4.0 - 6.9 | Yellow |
| Low | 0.1 - 3.9 | Green |
| Info | 0.0 | Blue |

## Templates

### Built-in Templates

```python
from shakka.reports import TemplateRegistry

templates = TemplateRegistry()

# Available templates
print(templates.list())
# ['default', 'html', 'executive', 'technical']

# Use specific template
generator = ReportGenerator(template="executive")
```

### Custom Templates

```python
from shakka.reports import TemplateRenderer

# Custom template
template = """
# {{ title }}

## Executive Summary
{{ executive_summary }}

## Findings
{% for finding in findings %}
### {{ finding.title }} ({{ finding.severity }})
{{ finding.description }}
{% endfor %}
"""

renderer = TemplateRenderer()
output = renderer.render(template, {
    "title": "Security Assessment",
    "executive_summary": "Critical vulnerabilities found...",
    "findings": findings
})
```

## Evidence Types

```python
from shakka.reports import Evidence, EvidenceType

evidence = [
    Evidence(
        type=EvidenceType.SCREENSHOT,
        path="/path/to/screenshot.png",
        caption="SQLMap output showing database extraction"
    ),
    Evidence(
        type=EvidenceType.COMMAND_OUTPUT,
        content="root:x:0:0:root:/root:/bin/bash\n...",
        caption="Extracted /etc/passwd"
    ),
    Evidence(
        type=EvidenceType.LOG,
        path="/path/to/access.log",
        lines=(100, 150)  # Lines 100-150
    )
]

finding = Finding(
    title="Root Access Obtained",
    severity=Severity.CRITICAL,
    evidence=evidence
)
```

## Configuration

```yaml
# config.yaml
reports:
  # Default format
  default_format: markdown
  
  # Output directory
  output_dir: ./reports
  
  # Include raw command output
  include_raw_output: true
  
  # Include screenshots
  include_screenshots: true
  
  # Template
  template: default
  
  # Company branding
  branding:
    company_name: "Security Corp"
    logo_path: "/path/to/logo.png"
    contact: "security@example.com"
```

## Example Output

### Markdown

```markdown
# Penetration Test Report

**Client:** Target Corp  
**Date:** February 5, 2026  
**Tester:** Security Team  

## Executive Summary

During the assessment, 3 critical, 5 high, and 12 medium 
severity vulnerabilities were identified...

## Findings

### 1. SQL Injection in Login Form

**Severity:** Critical (CVSS 9.8)  
**Affected Systems:** https://target.com/login  

**Description:**
The login form is vulnerable to SQL injection...

**Evidence:**
![SQLMap Output](evidence/sqli-login.png)

**Remediation:**
- Use parameterized queries
- Implement input validation
- Deploy WAF rules
```

## See Also

- [CLI Reference](cli.md)
- [Vector Memory](memory.md)
