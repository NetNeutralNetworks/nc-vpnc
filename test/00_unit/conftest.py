"""In-process tests: no lab. test/ holds fuzz_common, vpncmangle/src the engine."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "test", ROOT / "vpncmangle" / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
