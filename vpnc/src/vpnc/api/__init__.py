"""The local REST API on a Unix socket (root only), served in a thread."""

from __future__ import annotations

import logging
import pathlib
import threading

import uvicorn

logger = logging.getLogger("vpnc")

SOCKET = pathlib.Path("/run/vpnc/api.sock")


def start() -> threading.Thread:
    """Serve the API in a daemon thread and return it."""
    from vpnc.api import config_files  # noqa: PLC0415
    from vpnc.api.app import app  # noqa: PLC0415  (loads FastAPI only when served)

    config_files.remember_startup()
    config_files.resume_pending()

    # Root only: uvicorn makes the socket itself accessible to all.
    SOCKET.parent.mkdir(exist_ok=True)
    SOCKET.parent.chmod(0o700)
    SOCKET.unlink(missing_ok=True)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            uds=str(SOCKET),
            log_level="warning",
            # The daemon handles signals; the API stops with it.
            lifespan="off",
        ),
    )
    # Not in the main thread: uvicorn mustn't install signal handlers.
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]

    thread = threading.Thread(target=server.run, name="api", daemon=True)
    thread.start()
    logger.info("Serving the API on %s.", SOCKET)
    return thread
