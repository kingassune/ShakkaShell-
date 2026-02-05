"""Report generation module for penetration testing reports.

This module provides functionality for generating professional penetration testing
reports in multiple formats (Markdown, HTML, DOCX, PDF) with CVSS scoring,
customizable templates, and automatic executive summary generation.
"""

from shakka.reports.models import (
    Report,
    Finding,
    Evidence,
    CVSSScore,
    Severity,
    EvidenceType,
    ReportMetadata,
)

from shakka.reports.templates import (
    ReportTemplate,
    TemplateRegistry,
    TemplateRenderer,
    DEFAULT_MARKDOWN_TEMPLATE,
    DEFAULT_FINDING_TEMPLATE,
    DEFAULT_HTML_TEMPLATE,
    DEFAULT_HTML_FINDING_TEMPLATE,
)

from shakka.reports.generator import (
    ReportGenerator,
    GeneratorConfig,
    OutputFormat,
    create_report,
    create_finding,
    quick_generate,
)

__all__ = [
    # Models
    "Report",
    "Finding",
    "Evidence",
    "CVSSScore",
    "Severity",
    "EvidenceType",
    "ReportMetadata",
    # Templates
    "ReportTemplate",
    "TemplateRegistry",
    "TemplateRenderer",
    "DEFAULT_MARKDOWN_TEMPLATE",
    "DEFAULT_FINDING_TEMPLATE",
    "DEFAULT_HTML_TEMPLATE",
    "DEFAULT_HTML_FINDING_TEMPLATE",
    # Generator
    "ReportGenerator",
    "GeneratorConfig",
    "OutputFormat",
    # Convenience functions
    "create_report",
    "create_finding",
    "quick_generate",
]
