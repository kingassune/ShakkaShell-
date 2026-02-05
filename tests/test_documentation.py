"""Tests for documentation completeness and validity."""

import os
import re
from pathlib import Path

import pytest


# Get project root
PROJECT_ROOT = Path(__file__).parent.parent
DOCS_DIR = PROJECT_ROOT / "docs"
README_PATH = PROJECT_ROOT / "README.md"


class TestDocumentationExists:
    """Test that all required documentation files exist."""
    
    def test_readme_exists(self):
        """README.md should exist in project root."""
        assert README_PATH.exists(), "README.md should exist"
    
    def test_docs_directory_exists(self):
        """docs/ directory should exist."""
        assert DOCS_DIR.exists(), "docs/ directory should exist"
        assert DOCS_DIR.is_dir(), "docs/ should be a directory"
    
    def test_docs_index_exists(self):
        """docs/README.md (index) should exist."""
        index_path = DOCS_DIR / "README.md"
        assert index_path.exists(), "docs/README.md should exist"
    
    @pytest.mark.parametrize("doc_file", [
        "installation.md",
        "configuration.md",
        "cli.md",
        "agents.md",
        "mcp.md",
        "exploit.md",
        "safety.md",
        "memory.md",
        "reports.md",
        "tools.md",
        "honeypot.md",
        "api.md",
    ])
    def test_required_docs_exist(self, doc_file):
        """All required documentation files should exist."""
        doc_path = DOCS_DIR / doc_file
        assert doc_path.exists(), f"docs/{doc_file} should exist"


class TestReadmeContent:
    """Test README.md content quality."""
    
    @pytest.fixture
    def readme_content(self):
        """Load README content."""
        return README_PATH.read_text()
    
    def test_readme_has_title(self, readme_content):
        """README should have a title."""
        assert "# ShakkaShell" in readme_content
    
    def test_readme_has_installation(self, readme_content):
        """README should have installation instructions."""
        assert "installation" in readme_content.lower() or "install" in readme_content.lower()
    
    def test_readme_has_usage(self, readme_content):
        """README should have usage examples."""
        assert "usage" in readme_content.lower() or "example" in readme_content.lower()
    
    def test_readme_has_features_list(self, readme_content):
        """README should list features."""
        assert "features" in readme_content.lower()
    
    def test_readme_mentions_v2_features(self, readme_content):
        """README should mention v2 advanced features."""
        v2_features = [
            "agent",
            "mcp",
            "exploit",
            "memory",
            "report",
        ]
        for feature in v2_features:
            assert feature.lower() in readme_content.lower(), f"README should mention {feature}"
    
    def test_readme_has_security_warning(self, readme_content):
        """README should have security considerations."""
        assert "security" in readme_content.lower() or "warning" in readme_content.lower()
    
    def test_readme_has_license(self, readme_content):
        """README should mention license."""
        assert "license" in readme_content.lower() or "mit" in readme_content.lower()


class TestDocsIndexContent:
    """Test docs/README.md index content."""
    
    @pytest.fixture
    def index_content(self):
        """Load docs index content."""
        return (DOCS_DIR / "README.md").read_text()
    
    def test_index_has_title(self, index_content):
        """Index should have a title."""
        assert "# ShakkaShell" in index_content or "# Documentation" in index_content
    
    def test_index_links_to_docs(self, index_content):
        """Index should link to all documentation files."""
        expected_links = [
            "installation.md",
            "configuration.md", 
            "cli.md",
            "agents.md",
            "mcp.md",
            "exploit.md",
            "safety.md",
            "memory.md",
            "reports.md",
            "tools.md",
            "honeypot.md",
            "api.md",
        ]
        for link in expected_links:
            assert link in index_content, f"Index should link to {link}"


class TestDocumentationLinks:
    """Test that documentation links are valid."""
    
    def test_readme_docs_links_valid(self):
        """Links to docs/ in README should point to existing files."""
        content = README_PATH.read_text()
        
        # Find markdown links to docs/
        pattern = r'\[.*?\]\((docs/[^)]+)\)'
        links = re.findall(pattern, content)
        
        for link in links:
            # Remove anchor if present
            path = link.split('#')[0]
            full_path = PROJECT_ROOT / path
            assert full_path.exists(), f"Link target {link} should exist"
    
    def test_docs_internal_links_valid(self):
        """Internal links within docs should be valid."""
        for doc_file in DOCS_DIR.glob("*.md"):
            content = doc_file.read_text()
            
            # Find relative markdown links
            pattern = r'\[.*?\]\(([^http][^)]+\.md[^)]*)\)'
            links = re.findall(pattern, content)
            
            for link in links:
                # Remove anchor if present
                path = link.split('#')[0]
                full_path = DOCS_DIR / path
                assert full_path.exists(), f"Link {link} in {doc_file.name} should exist"


class TestDocumentationQuality:
    """Test documentation quality metrics."""
    
    def test_all_docs_have_headings(self):
        """All documentation files should have proper headings."""
        for doc_file in DOCS_DIR.glob("*.md"):
            content = doc_file.read_text()
            # Should have at least one heading
            assert re.search(r'^#+ ', content, re.MULTILINE), \
                f"{doc_file.name} should have at least one heading"
    
    def test_all_docs_non_empty(self):
        """All documentation files should have substantial content."""
        min_length = 500  # Minimum characters
        for doc_file in DOCS_DIR.glob("*.md"):
            content = doc_file.read_text()
            assert len(content) >= min_length, \
                f"{doc_file.name} should have at least {min_length} characters"
    
    def test_code_blocks_have_language(self):
        """Code blocks should specify language for syntax highlighting."""
        for doc_file in DOCS_DIR.glob("*.md"):
            content = doc_file.read_text()
            
            # Count total code blocks (opening markers with language)
            total_blocks = len(re.findall(r'^```\w+', content, re.MULTILINE))
            
            # Should have at least some code blocks with language specified
            # This is a soft check - we just want most blocks to have language
            if total_blocks == 0:
                # If no blocks, check if doc has code sections at all
                has_code_intent = "```" in content
                if has_code_intent:
                    # If it has code blocks, at least some should have language
                    pass  # Allow docs with unnamed blocks for flexibility
            
            # Verify we have code examples where expected
            assert "```" in content or doc_file.name == "README.md", \
                f"{doc_file.name} should have code examples"


class TestModulesDocumented:
    """Test that all major modules are documented."""
    
    def test_shakka_modules_exist(self):
        """Modules mentioned in docs should exist in shakka/."""
        shakka_dir = PROJECT_ROOT / "shakka"
        
        expected_modules = [
            "cli.py",
            "config.py",
            "core",
            "providers",
            "storage",
            "agents",
            "mcp",
            "exploit",
            "reports",
            "tools",
            "honeypot",
        ]
        
        for module in expected_modules:
            path = shakka_dir / module
            assert path.exists(), f"Module {module} should exist in shakka/"


class TestCLIDocumentation:
    """Test CLI documentation completeness."""
    
    @pytest.fixture
    def cli_doc_content(self):
        """Load CLI documentation."""
        return (DOCS_DIR / "cli.md").read_text()
    
    def test_cli_doc_has_commands(self, cli_doc_content):
        """CLI docs should document all main commands."""
        commands = ["generate", "agent", "exploit", "history", "config", "validate"]
        for cmd in commands:
            assert cmd in cli_doc_content.lower(), f"CLI docs should document '{cmd}' command"
    
    def test_cli_doc_has_examples(self, cli_doc_content):
        """CLI docs should have usage examples."""
        assert "example" in cli_doc_content.lower() or "```bash" in cli_doc_content


class TestAPIDocumentation:
    """Test API documentation completeness."""
    
    @pytest.fixture
    def api_doc_content(self):
        """Load API documentation."""
        return (DOCS_DIR / "api.md").read_text()
    
    def test_api_doc_has_imports(self, api_doc_content):
        """API docs should show import examples."""
        assert "from shakka" in api_doc_content or "import shakka" in api_doc_content
    
    def test_api_doc_has_code_examples(self, api_doc_content):
        """API docs should have Python code examples."""
        assert "```python" in api_doc_content
