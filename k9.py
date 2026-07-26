#!/usr/bin/env python3
"""Thin launcher so `python3 k9.py ...` works without installing.

Equivalent to `python3 -m k9`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from k9.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
