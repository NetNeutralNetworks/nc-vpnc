"""Replay the answers a lab DNS fuzz run saved; name those vpncmangle fails on.

Usage: python3 test/00_unit/replay_dns_answers.py test/04_fuzz/.dns-answers-*.txt
"""

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import conftest  # noqa: F401 (the paths)
from test_dns_properties import check_answer


def main() -> int:
    """Check each saved answer; return how many failed."""
    failed = 0
    for path in sys.argv[1:]:
        lines = Path(path).read_text(encoding="utf-8").split()
        for number, line in enumerate(lines, 1):
            try:
                check_answer(bytes.fromhex(line))
            except Exception:  # noqa: BLE001 (each failure is reported)
                failed += 1
                print(f"{path}:{number}: {line}")
                traceback.print_exc(limit=1)
    print(f"{failed} failed")
    return min(failed, 1)


if __name__ == "__main__":
    sys.exit(main())
