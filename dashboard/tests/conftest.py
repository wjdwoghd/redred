"""Make dashboard's flat module imports work from repository root pytest runs."""

from __future__ import annotations

import sys
from pathlib import Path


dashboard_root = Path(__file__).resolve().parents[1]
if str(dashboard_root) not in sys.path:
    sys.path.insert(0, str(dashboard_root))

