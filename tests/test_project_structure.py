"""Test project structure and configuration."""

import tomli
from pathlib import Path


def test_pyproject_toml_exists():
    """Test that pyproject.toml exists."""
    project_root = Path(__file__).parent.parent
    pyproject_path = project_root / "pyproject.toml"
    assert pyproject_path.exists(), "pyproject.toml should exist"


def test_pyproject_toml_structure():
    """Test that pyproject.toml has the correct structure."""
    project_root = Path(__file__).parent.parent
    pyproject_path = project_root / "pyproject.toml"
    
    with open(pyproject_path, "rb") as f:
        data = tomli.load(f)
    
    # Check basic structure
    assert "tool" in data, "pyproject.toml should have [tool] section"
    assert "poetry" in data["tool"], "Should have [tool.poetry] section"
    
    poetry = data["tool"]["poetry"]
    assert poetry["name"] == "shakkashell", "Project name should be 'shakkashell'"
    assert poetry["version"] == "2.0.0", "Version should be 2.0.0"
    
    # Check required dependencies
    deps = poetry["dependencies"]
    required_deps = ["typer", "rich", "litellm", "pydantic-settings", "sqlalchemy", "httpx"]
    for dep in required_deps:
        assert dep in deps, f"Missing required dependency: {dep}"
    
    # Check dev dependencies
    dev_deps = data["tool"]["poetry"]["group"]["dev"]["dependencies"]
    assert "pytest" in dev_deps, "Should have pytest in dev dependencies"
    assert "pytest-asyncio" in dev_deps, "Should have pytest-asyncio in dev dependencies"
    assert "ruff" in dev_deps, "Should have ruff in dev dependencies"
    
    # Check scripts
    assert "scripts" in poetry, "Should have scripts section"
    assert "shakka" in poetry["scripts"], "Should have shakka entry point"
