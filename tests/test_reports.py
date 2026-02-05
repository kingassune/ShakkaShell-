"""Tests for the report generation module."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from shakka.reports import (
    Report,
    Finding,
    Evidence,
    CVSSScore,
    Severity,
    EvidenceType,
    ReportMetadata,
    ReportTemplate,
    TemplateRegistry,
    TemplateRenderer,
    ReportGenerator,
    GeneratorConfig,
    OutputFormat,
    create_report,
    create_finding,
    quick_generate,
    DEFAULT_MARKDOWN_TEMPLATE,
    DEFAULT_HTML_TEMPLATE,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_cvss():
    """Create a sample CVSS score."""
    return CVSSScore(
        score=7.5,
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="N",
        availability="N",
    )


@pytest.fixture
def sample_evidence():
    """Create sample evidence."""
    return Evidence(
        evidence_type=EvidenceType.COMMAND_OUTPUT,
        title="Nmap Scan Results",
        content="PORT    STATE SERVICE\n22/tcp  open  ssh\n80/tcp  open  http",
    )


@pytest.fixture
def sample_finding(sample_cvss, sample_evidence):
    """Create a sample finding."""
    finding = Finding(
        title="SQL Injection in Login Form",
        description="A SQL injection vulnerability was found in the login form.",
        severity=Severity.HIGH,
        cvss=sample_cvss,
        affected_asset="webapp.example.com",
        remediation="Use parameterized queries.",
        evidence=[sample_evidence],
        cve_ids=["CVE-2021-12345"],
        cwe_ids=["CWE-89"],
    )
    return finding


@pytest.fixture
def sample_metadata():
    """Create sample report metadata."""
    return ReportMetadata(
        title="Security Assessment Report",
        client="ACME Corporation",
        assessor="Security Team",
        assessment_type="Penetration Test",
        start_date=datetime(2024, 1, 15),
        end_date=datetime(2024, 1, 20),
        scope=["webapp.example.com", "api.example.com"],
        executive_summary="Test executive summary.",
        methodology="OWASP Testing Guide v4",
    )


@pytest.fixture
def sample_report(sample_metadata, sample_finding):
    """Create a sample report."""
    report = Report(
        metadata=sample_metadata,
        findings=[sample_finding],
    )
    return report


@pytest.fixture
def complex_report(sample_metadata):
    """Create a report with multiple findings of varying severity."""
    findings = [
        Finding(
            title="Critical RCE Vulnerability",
            description="Remote code execution possible.",
            severity=Severity.CRITICAL,
            cvss=CVSSScore(score=9.8),
            affected_asset="server.example.com",
            remediation="Patch immediately.",
        ),
        Finding(
            title="Sensitive Data Exposure",
            description="API exposes sensitive data.",
            severity=Severity.HIGH,
            cvss=CVSSScore(score=7.5),
            affected_asset="api.example.com",
            remediation="Implement proper access controls.",
        ),
        Finding(
            title="Missing Security Headers",
            description="Security headers not configured.",
            severity=Severity.MEDIUM,
            cvss=CVSSScore(score=5.3),
            affected_asset="webapp.example.com",
            remediation="Add security headers.",
        ),
        Finding(
            title="Verbose Error Messages",
            description="Error messages reveal internal details.",
            severity=Severity.LOW,
            cvss=CVSSScore(score=3.1),
            affected_asset="api.example.com",
            remediation="Use generic error messages.",
        ),
        Finding(
            title="Outdated TLS Configuration",
            description="TLS 1.0 still supported.",
            severity=Severity.INFO,
            affected_asset="webapp.example.com",
            remediation="Disable TLS 1.0.",
        ),
    ]
    return Report(metadata=sample_metadata, findings=findings)


# =============================================================================
# Tests - Severity
# =============================================================================

class TestSeverity:
    """Tests for Severity enum."""
    
    def test_severity_values(self):
        """Test all severity values exist."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
    
    def test_severity_score_range(self):
        """Test severity score ranges."""
        assert Severity.CRITICAL.score_range == (9.0, 10.0)
        assert Severity.HIGH.score_range == (7.0, 8.9)
        assert Severity.MEDIUM.score_range == (4.0, 6.9)
        assert Severity.LOW.score_range == (0.1, 3.9)
        assert Severity.INFO.score_range == (0.0, 0.0)
    
    def test_severity_colors(self):
        """Test severity colors."""
        assert Severity.CRITICAL.color == "#DC143C"
        assert Severity.HIGH.color == "#FF4500"
        assert Severity.MEDIUM.color == "#FFA500"
        assert Severity.LOW.color == "#FFD700"
        assert Severity.INFO.color == "#1E90FF"
    
    def test_from_cvss_score(self):
        """Test severity classification from CVSS score."""
        assert Severity.from_cvss(9.5) == Severity.CRITICAL
        assert Severity.from_cvss(7.5) == Severity.HIGH
        assert Severity.from_cvss(5.0) == Severity.MEDIUM
        assert Severity.from_cvss(2.0) == Severity.LOW
        assert Severity.from_cvss(0.0) == Severity.INFO


# =============================================================================
# Tests - CVSSScore
# =============================================================================

class TestCVSSScore:
    """Tests for CVSS score model."""
    
    def test_basic_cvss(self):
        """Test basic CVSS creation."""
        cvss = CVSSScore(score=7.5)
        assert cvss.score == 7.5
    
    def test_cvss_vector_generation(self, sample_cvss):
        """Test CVSS vector string generation."""
        vector = sample_cvss.generate_vector()
        assert "CVSS:3.1" in vector
        assert "AV:N" in vector
        assert "AC:L" in vector
        assert "PR:N" in vector
        assert "UI:N" in vector
        assert "S:U" in vector
        assert "C:H" in vector
        assert "I:N" in vector
        assert "A:N" in vector
    
    def test_cvss_to_dict(self, sample_cvss):
        """Test CVSS serialization."""
        data = sample_cvss.to_dict()
        assert data["score"] == 7.5
        assert "vector" in data
        assert "severity" in data


# =============================================================================
# Tests - Evidence
# =============================================================================

class TestEvidence:
    """Tests for Evidence model."""
    
    def test_evidence_creation(self, sample_evidence):
        """Test evidence creation."""
        assert sample_evidence.title == "Nmap Scan Results"
        assert sample_evidence.evidence_type == EvidenceType.COMMAND_OUTPUT
        assert "PORT" in sample_evidence.content
    
    def test_evidence_format_markdown(self, sample_evidence):
        """Test evidence markdown formatting."""
        md = sample_evidence.format_markdown()
        assert "**Nmap Scan Results**" in md
        assert "command_output" in md.lower() or "Command Output" in md or "```" in md
    
    def test_evidence_types(self):
        """Test all evidence types."""
        types = [
            EvidenceType.COMMAND_OUTPUT,
            EvidenceType.SCREENSHOT,
            EvidenceType.FILE,
            EvidenceType.LOG,
            EvidenceType.NETWORK_CAPTURE,
            EvidenceType.CODE_SNIPPET,
        ]
        assert len(types) == 6
    
    def test_evidence_to_dict(self, sample_evidence):
        """Test evidence serialization."""
        data = sample_evidence.to_dict()
        assert data["title"] == "Nmap Scan Results"
        assert data["type"] == "command_output"


# =============================================================================
# Tests - Finding
# =============================================================================

class TestFinding:
    """Tests for Finding model."""
    
    def test_finding_creation(self, sample_finding):
        """Test finding creation."""
        assert sample_finding.title == "SQL Injection in Login Form"
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.affected_asset == "webapp.example.com"
    
    def test_finding_id(self, sample_finding):
        """Test finding ID generation."""
        assert sample_finding.id is not None
        assert len(sample_finding.id) == 8  # SHA256 hex[:8]
    
    def test_finding_cvss_score(self, sample_finding):
        """Test CVSS score property."""
        assert sample_finding.cvss_score == 7.5
    
    def test_finding_cvss_score_default(self):
        """Test CVSS score default for no CVSS."""
        finding = Finding(
            title="Test",
            description="Test",
            severity=Severity.MEDIUM,
        )
        # Estimated from severity (MEDIUM = 5.5)
        assert finding.cvss_score == 5.5
    
    def test_finding_add_evidence(self, sample_finding):
        """Test adding evidence."""
        initial_count = len(sample_finding.evidence)
        new_evidence = Evidence(
            evidence_type=EvidenceType.LOG,
            title="Access Log",
            content="192.168.1.1 - - [GET /admin HTTP/1.1]",
        )
        sample_finding.add_evidence(new_evidence)
        assert len(sample_finding.evidence) == initial_count + 1
    
    def test_finding_add_command_output(self, sample_finding):
        """Test adding command output."""
        initial_count = len(sample_finding.evidence)
        sample_finding.add_command_output(
            "sqlmap --url http://target/login",
            "[*] Parameter 'username' is vulnerable",
        )
        assert len(sample_finding.evidence) == initial_count + 1
    
    def test_finding_to_dict(self, sample_finding):
        """Test finding serialization."""
        data = sample_finding.to_dict()
        assert data["title"] == "SQL Injection in Login Form"
        assert data["severity"] == "high"
        assert "cvss" in data
        assert "evidence" in data
        assert len(data["evidence"]) >= 1


# =============================================================================
# Tests - ReportMetadata
# =============================================================================

class TestReportMetadata:
    """Tests for ReportMetadata model."""
    
    def test_metadata_creation(self, sample_metadata):
        """Test metadata creation."""
        assert sample_metadata.title == "Security Assessment Report"
        assert sample_metadata.client == "ACME Corporation"
        assert sample_metadata.assessor == "Security Team"
    
    def test_metadata_defaults(self):
        """Test metadata defaults."""
        metadata = ReportMetadata(title="Test Report")
        # Check that defaults are set
        assert metadata.version is not None
        assert metadata.classification is not None
    
    def test_metadata_to_dict(self, sample_metadata):
        """Test metadata serialization."""
        data = sample_metadata.to_dict()
        assert data["title"] == "Security Assessment Report"
        assert data["client"] == "ACME Corporation"


# =============================================================================
# Tests - Report
# =============================================================================

class TestReport:
    """Tests for Report model."""
    
    def test_report_creation(self, sample_report):
        """Test report creation."""
        assert sample_report.metadata.title == "Security Assessment Report"
        assert len(sample_report.findings) == 1
    
    def test_report_id(self, sample_report):
        """Test report ID generation."""
        assert sample_report.id is not None
        assert len(sample_report.id) > 0  # Has an ID
    
    def test_report_counts(self, complex_report):
        """Test finding severity counts."""
        assert complex_report.critical_count == 1
        assert complex_report.high_count == 1
        assert complex_report.medium_count == 1
        assert complex_report.low_count == 1
        assert complex_report.info_count == 1
        assert complex_report.total_findings == 5
    
    def test_report_sorted_findings(self, complex_report):
        """Test findings sorted by severity."""
        sorted_findings = complex_report.sorted_findings
        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[-1].severity == Severity.INFO
    
    def test_report_risk_score(self, complex_report):
        """Test risk score calculation."""
        risk = complex_report.risk_score
        assert 0 <= risk <= 100
    
    def test_report_get_findings_by_severity(self, complex_report):
        """Test filtering findings by severity."""
        critical = complex_report.get_findings_by_severity(Severity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].severity == Severity.CRITICAL
    
    def test_report_get_findings_by_asset(self, complex_report):
        """Test filtering findings by asset."""
        api_findings = complex_report.get_findings_by_asset("api.example.com")
        assert len(api_findings) == 2
    
    def test_report_to_dict(self, sample_report):
        """Test report serialization."""
        data = sample_report.to_dict()
        assert "id" in data
        assert "metadata" in data
        assert "findings" in data


# =============================================================================
# Tests - TemplateRegistry
# =============================================================================

class TestTemplateRegistry:
    """Tests for template registry."""
    
    def test_default_templates_registered(self):
        """Test default templates are registered."""
        registry = TemplateRegistry()
        names = registry.list_names()
        assert "default" in names
        assert "html" in names
    
    def test_get_template(self):
        """Test getting template."""
        registry = TemplateRegistry()
        template = registry.get("default")
        assert template is not None
        assert template.name == "default"
    
    def test_register_custom_template(self):
        """Test registering custom template."""
        registry = TemplateRegistry()
        custom = ReportTemplate(
            name="custom",
            report_template="Custom: $title",
        )
        registry.register(custom)
        assert registry.get("custom") is not None
    
    def test_remove_template(self):
        """Test removing template."""
        registry = TemplateRegistry()
        assert registry.remove("default") is True
        assert registry.get("default") is None
    
    def test_get_nonexistent_template(self):
        """Test getting nonexistent template."""
        registry = TemplateRegistry()
        assert registry.get("nonexistent") is None


# =============================================================================
# Tests - TemplateRenderer
# =============================================================================

class TestTemplateRenderer:
    """Tests for template renderer."""
    
    def test_render_basic(self, sample_report):
        """Test basic template rendering."""
        template = ReportTemplate(
            name="basic",
            report_template="Report: $title - $client",
        )
        renderer = TemplateRenderer(template)
        result = renderer.render(sample_report)
        
        assert "Security Assessment Report" in result
        assert "ACME Corporation" in result
    
    def test_render_with_findings(self, sample_report):
        """Test rendering with findings."""
        registry = TemplateRegistry()
        template = registry.get("default")
        renderer = TemplateRenderer(template)
        result = renderer.render(sample_report)
        
        assert sample_report.metadata.title in result
        assert "SQL Injection" in result
    
    def test_render_finding_counts(self, complex_report):
        """Test rendering finding counts."""
        registry = TemplateRegistry()
        template = registry.get("default")
        renderer = TemplateRenderer(template)
        result = renderer.render(complex_report)
        
        # Should contain severity distribution
        assert "1" in result  # At least one severity count


# =============================================================================
# Tests - GeneratorConfig
# =============================================================================

class TestGeneratorConfig:
    """Tests for generator configuration."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = GeneratorConfig()
        assert config.default_format == OutputFormat.MARKDOWN
        assert config.default_template == "default"
        assert config.include_evidence is True
    
    def test_config_to_dict(self):
        """Test config serialization."""
        config = GeneratorConfig()
        data = config.to_dict()
        assert data["default_format"] == "markdown"
        assert data["include_evidence"] is True
    
    def test_config_from_dict(self):
        """Test config deserialization."""
        data = {
            "default_format": "html",
            "include_evidence": False,
        }
        config = GeneratorConfig.from_dict(data)
        assert config.default_format == OutputFormat.HTML
        assert config.include_evidence is False


# =============================================================================
# Tests - OutputFormat
# =============================================================================

class TestOutputFormat:
    """Tests for output format enum."""
    
    def test_format_values(self):
        """Test all format values."""
        assert OutputFormat.MARKDOWN.value == "markdown"
        assert OutputFormat.HTML.value == "html"
        assert OutputFormat.DOCX.value == "docx"
        assert OutputFormat.PDF.value == "pdf"
        assert OutputFormat.JSON.value == "json"
    
    def test_format_extensions(self):
        """Test file extensions."""
        assert OutputFormat.MARKDOWN.extension == ".md"
        assert OutputFormat.HTML.extension == ".html"
        assert OutputFormat.DOCX.extension == ".docx"
        assert OutputFormat.PDF.extension == ".pdf"
        assert OutputFormat.JSON.extension == ".json"


# =============================================================================
# Tests - ReportGenerator
# =============================================================================

class TestReportGenerator:
    """Tests for report generator."""
    
    def test_generator_creation(self):
        """Test generator creation."""
        generator = ReportGenerator()
        assert generator.config is not None
        assert generator.templates is not None
    
    def test_generator_with_custom_config(self):
        """Test generator with custom config."""
        config = GeneratorConfig(default_format=OutputFormat.HTML)
        generator = ReportGenerator(config=config)
        assert generator.config.default_format == OutputFormat.HTML
    
    def test_preview_markdown(self, sample_report):
        """Test markdown preview."""
        generator = ReportGenerator()
        content = generator.preview(sample_report, OutputFormat.MARKDOWN)
        
        assert "Security Assessment Report" in content
        assert "SQL Injection" in content
    
    def test_preview_html(self, sample_report):
        """Test HTML preview."""
        generator = ReportGenerator()
        content = generator.preview(sample_report, OutputFormat.HTML)
        
        assert "<html" in content.lower()
        assert "Security Assessment Report" in content
    
    def test_preview_json(self, sample_report):
        """Test JSON preview."""
        generator = ReportGenerator()
        content = generator.preview(sample_report, OutputFormat.JSON)
        
        data = json.loads(content)
        assert "metadata" in data
        assert "findings" in data
    
    def test_generate_markdown_file(self, sample_report):
        """Test markdown file generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = GeneratorConfig(output_directory=tmpdir)
            generator = ReportGenerator(config=config)
            
            path = generator.generate(sample_report, OutputFormat.MARKDOWN)
            
            assert Path(path).exists()
            assert path.endswith(".md")
            
            with open(path) as f:
                content = f.read()
            assert "Security Assessment Report" in content
    
    def test_generate_html_file(self, sample_report):
        """Test HTML file generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = GeneratorConfig(output_directory=tmpdir)
            generator = ReportGenerator(config=config)
            
            path = generator.generate(sample_report, OutputFormat.HTML)
            
            assert Path(path).exists()
            assert path.endswith(".html")
    
    def test_generate_json_file(self, sample_report):
        """Test JSON file generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = GeneratorConfig(output_directory=tmpdir)
            generator = ReportGenerator(config=config)
            
            path = generator.generate(sample_report, OutputFormat.JSON)
            
            assert Path(path).exists()
            assert path.endswith(".json")
            
            with open(path) as f:
                data = json.load(f)
            assert "metadata" in data
    
    def test_generate_custom_path(self, sample_report):
        """Test generation with custom output path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = ReportGenerator()
            custom_path = str(Path(tmpdir) / "custom_report.md")
            
            path = generator.generate(
                sample_report,
                OutputFormat.MARKDOWN,
                output_path=custom_path,
            )
            
            assert path == custom_path
            assert Path(path).exists()
    
    def test_generate_all_formats(self, sample_report):
        """Test generating all formats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = GeneratorConfig(output_directory=tmpdir)
            generator = ReportGenerator(config=config)
            
            paths = generator.generate_all_formats(sample_report)
            
            assert OutputFormat.MARKDOWN in paths
            assert OutputFormat.HTML in paths
            assert OutputFormat.JSON in paths
    
    def test_generated_reports_tracking(self, sample_report):
        """Test tracking of generated reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = GeneratorConfig(output_directory=tmpdir)
            generator = ReportGenerator(config=config)
            
            assert len(generator.generated_reports) == 0
            
            generator.generate(sample_report, OutputFormat.MARKDOWN)
            assert len(generator.generated_reports) == 1
            
            generator.generate(sample_report, OutputFormat.HTML)
            assert len(generator.generated_reports) == 2
    
    def test_auto_executive_summary(self, complex_report):
        """Test automatic executive summary generation."""
        # Remove executive summary
        complex_report.metadata.executive_summary = ""
        
        config = GeneratorConfig(auto_generate_summary=True)
        generator = ReportGenerator(config=config)
        
        content = generator.preview(complex_report, OutputFormat.MARKDOWN)
        
        # Should have auto-generated content
        assert "findings" in content.lower()


# =============================================================================
# Tests - Convenience Functions
# =============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_create_report(self):
        """Test create_report function."""
        report = create_report(
            title="Test Report",
            client="Test Client",
            assessor="Tester",
        )
        
        assert report.metadata.title == "Test Report"
        assert report.metadata.client == "Test Client"
        assert report.metadata.assessor == "Tester"
    
    def test_create_finding(self):
        """Test create_finding function."""
        finding = create_finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            cvss_score=7.5,
            affected_asset="test.example.com",
            remediation="Fix it",
        )
        
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.cvss_score == 7.5
    
    def test_quick_generate(self, sample_report):
        """Test quick_generate function."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "quick_report.md")
            result = quick_generate(sample_report, "markdown", path)
            
            assert Path(result).exists()


# =============================================================================
# Tests - Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""
    
    def test_empty_report(self):
        """Test report with no findings."""
        metadata = ReportMetadata(title="Empty Report")
        report = Report(metadata=metadata)
        
        assert report.total_findings == 0
        assert report.risk_score == 0
        
        generator = ReportGenerator()
        content = generator.preview(report)
        assert "Empty Report" in content
    
    def test_finding_without_cvss(self):
        """Test finding without CVSS score."""
        finding = Finding(
            title="No CVSS",
            description="Test",
            severity=Severity.MEDIUM,
        )
        
        # Estimated from severity (MEDIUM = 5.5)
        assert finding.cvss_score == 5.5
        assert finding.cvss is None
    
    def test_finding_without_evidence(self):
        """Test finding without evidence."""
        finding = Finding(
            title="No Evidence",
            description="Test",
            severity=Severity.LOW,
        )
        
        assert len(finding.evidence) == 0
        data = finding.to_dict()
        assert data["evidence"] == []
    
    def test_report_with_many_findings(self):
        """Test report with many findings."""
        metadata = ReportMetadata(title="Large Report")
        findings = [
            Finding(
                title=f"Finding {i}",
                description=f"Description {i}",
                severity=Severity.MEDIUM,
            )
            for i in range(50)
        ]
        report = Report(metadata=metadata, findings=findings)
        
        assert report.total_findings == 50
        
        generator = ReportGenerator()
        content = generator.preview(report)
        assert "Finding 1" in content
        assert "Finding 49" in content
    
    def test_special_characters_in_content(self):
        """Test handling of special characters."""
        finding = Finding(
            title="XSS <script>alert('xss')</script>",
            description="Input: $variable & 'quotes' \"double\"",
            severity=Severity.HIGH,
        )
        
        metadata = ReportMetadata(title="Special & <Characters>")
        report = Report(metadata=metadata, findings=[finding])
        
        generator = ReportGenerator()
        content = generator.preview(report)
        # Should not crash and should contain title
        assert "Special" in content


# =============================================================================
# Tests - Integration
# =============================================================================

class TestIntegration:
    """Integration tests for full workflow."""
    
    def test_full_report_workflow(self):
        """Test complete report generation workflow."""
        # Create report
        report = create_report(
            title="Full Integration Test",
            client="Integration Client",
            assessor="Test Team",
        )
        
        # Add findings
        report.findings.append(create_finding(
            title="Critical Vulnerability",
            description="Found a critical issue.",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            affected_asset="prod.example.com",
            remediation="Apply patch immediately.",
        ))
        
        report.findings.append(create_finding(
            title="Medium Issue",
            description="Found a medium issue.",
            severity=Severity.MEDIUM,
            cvss_score=5.0,
            affected_asset="dev.example.com",
            remediation="Schedule fix.",
        ))
        
        # Add evidence to first finding
        report.findings[0].add_command_output(
            "nmap -sV prod.example.com",
            "22/tcp open ssh OpenSSH 7.9",
        )
        
        # Set metadata
        report.metadata.start_date = datetime(2024, 1, 1)
        report.metadata.end_date = datetime(2024, 1, 5)
        report.metadata.scope = ["prod.example.com", "dev.example.com"]
        
        # Verify counts
        assert report.total_findings == 2
        assert report.critical_count == 1
        assert report.medium_count == 1
        
        # Generate reports
        with tempfile.TemporaryDirectory() as tmpdir:
            config = GeneratorConfig(output_directory=tmpdir)
            generator = ReportGenerator(config=config)
            
            # Generate all formats
            paths = generator.generate_all_formats(report)
            
            # Verify all files exist
            for fmt, path in paths.items():
                assert Path(path).exists(), f"{fmt.value} report not created"
            
            # Verify markdown content
            md_path = paths[OutputFormat.MARKDOWN]
            with open(md_path) as f:
                md_content = f.read()
            
            assert "Full Integration Test" in md_content
            assert "Critical Vulnerability" in md_content
            assert "Medium Issue" in md_content
            assert "nmap" in md_content.lower() or "evidence" in md_content.lower()
            
            # Verify JSON content
            json_path = paths[OutputFormat.JSON]
            with open(json_path) as f:
                json_data = json.load(f)
            
            assert json_data["metadata"]["title"] == "Full Integration Test"
            assert len(json_data["findings"]) == 2
    
    def test_template_customization_workflow(self, sample_report):
        """Test template customization workflow."""
        # Create custom template
        custom_template = ReportTemplate(
            name="custom",
            description="Custom test template",
            report_template="""
# Custom: $title

Client: $client
Generated: $date

## Summary
Total: $total_findings findings

## Details

$findings
""",
            finding_template="""
### $finding_title

$finding_description
""",
        )
        
        # Register and use
        registry = TemplateRegistry()
        registry.register(custom_template)
        
        generator = ReportGenerator(template_registry=registry)
        content = generator.preview(
            sample_report,
            OutputFormat.MARKDOWN,
            template_name="custom",
        )
        
        assert "Custom: Security Assessment Report" in content
        assert "Client: ACME Corporation" in content
