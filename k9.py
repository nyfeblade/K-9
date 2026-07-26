#!/usr/bin/env python3
"""Thin launcher so `python3 viperscan.py ...` works without installing.

Equivalent to `python3 -m viperscan`.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from viperscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
