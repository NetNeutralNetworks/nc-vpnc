"""Lab helpers used by this suite; see test/lab_helpers.py."""

import sys
from pathlib import Path

# test/ holds lab_helpers.py. Add it explicitly so the suite also works when
# pytest is started from inside the suite directory.
TEST_DIR = str(Path(__file__).resolve().parents[2])
if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)

from lab_helpers import (  # noqa: E402
    close_ssh_sessions,
    nft_drop,
    run_cmd,
    run_cmd_shell,
    run_cmd_vtysh,
    ssh_server_down,
    wait_until,
    write_file,
)

__all__ = [
    "close_ssh_sessions",
    "nft_drop",
    "run_cmd",
    "run_cmd_shell",
    "run_cmd_vtysh",
    "ssh_server_down",
    "wait_until",
    "write_file",
]
