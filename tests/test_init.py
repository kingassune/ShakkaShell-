"""Test shakka package initialization."""

import shakka


def test_version_exists():
    """Test that __version__ is defined."""
    assert hasattr(shakka, "__version__")
    assert isinstance(shakka.__version__, str)
    assert shakka.__version__ == "2.0.0"


def test_author_exists():
    """Test that __author__ is defined."""
    assert hasattr(shakka, "__author__")
    assert isinstance(shakka.__author__, str)


def test_license_exists():
    """Test that __license__ is defined."""
    assert hasattr(shakka, "__license__")
    assert isinstance(shakka.__license__, str)
