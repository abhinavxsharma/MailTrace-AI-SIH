"""Backend test package."""

from __future__ import annotations

import sys
from pathlib import Path

# Repo root is 2 levels up from backend/tests/
REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = Path(__file__).resolve().parents[1]

for path in (REPO_ROOT, BACKEND_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
