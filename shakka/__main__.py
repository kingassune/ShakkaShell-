"""Entry point for running ShakkaShell as a module.

Usage:
    python -m shakka generate "scan ports on 10.0.0.1"
    python -m shakka --help
"""

from shakka.cli import app

if __name__ == "__main__":
    app()
