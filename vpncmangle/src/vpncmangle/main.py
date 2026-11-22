"""Mangle/doctor DNS responses."""

import contextlib
import logging
import sys
import time
from logging.handlers import SysLogHandler

from netfilterqueue import NetfilterQueue, Packet

from . import config, dns_processing, helpers, nftables, observers, stats

logger = logging.getLogger("vpncmangle")


# Seconds between the tracebacks of an exception type; each is counted.
TRACEBACK_INTERVAL = 60
_TRACEBACKS: dict[type[BaseException], float] = {}


def _journal_handler() -> logging.Handler:
    """Return a handler to the journal (syslog), or stderr where it isn't running."""
    try:
        handler = SysLogHandler(address="/dev/log", facility=SysLogHandler.LOG_DAEMON)
    except OSError:
        return logging.StreamHandler()
    # The journal's SYSLOG_IDENTIFIER, which vpnctl reads.
    handler.ident = "vpncmangle: "
    handler.append_nul = False
    return handler


def setup_nftables(queue_number: int) -> None:
    """Queue DNS responses to vpncmangle, and drop the old ip6tables rule."""
    nftables.apply(queue_number)
    logger.info("Queueing DNS responses to netfilter queue %s.", queue_number)


def _log_error(error: BaseException) -> None:
    """Log an exception's traceback, at most once a TRACEBACK_INTERVAL per type."""
    now = time.monotonic()
    last = _TRACEBACKS.get(type(error))
    if last is None or now - last >= TRACEBACK_INTERVAL:
        _TRACEBACKS[type(error)] = now
        logger.warning(
            "Dropping a DNS response that can't be translated.", exc_info=error
        )


def mangle_dns(pkt: Packet) -> None:
    """Translate a DNS response; drop it if that fails.

    An exception here would end the queue, and with it DNS for every tenant.
    """
    try:
        # Read once: a reload replaces them.
        result = dns_processing.process(
            pkt.get_payload(), config.ACL_MATCH, config.LIMITS
        )
        if result.action == dns_processing.DROP:
            stats.dropped(result.reason or stats.ERROR, result.ni)
            pkt.drop()
            return
        if result.payload is not None:
            pkt.set_payload(result.payload)
        pkt.accept()
        if result.payload is not None and result.ni is not None:
            stats.translated(result.ni)
    except Exception as error:  # noqa: BLE001 (counted and logged)
        _log_error(error)
        stats.dropped(stats.ERROR)
        # Fails if it already got a verdict.
        with contextlib.suppress(Exception):
            pkt.drop()


def main() -> None:
    """Set up netfilter and try to keep the mangle_dns function alive."""
    logger.setLevel(level=logging.INFO)
    logger.addHandler(_journal_handler())

    nfqueue = NetfilterQueue()
    retries = 10

    helpers.load_config()

    mangle_obs = observers.observe()
    mangle_obs.start()
    stats.start()

    while True:
        for queue_number in range(retries):
            try:
                nfqueue.bind(queue_number, mangle_dns)
                setup_nftables(queue_number)
                break
            except OSError:
                logger.debug(
                    "Attaching to netfilter queue %s failed, retrying.",
                    queue_number,
                )
            if queue_number >= retries - 1:
                logger.critical("Could not find an available netfilter queue.")
                sys.exit(1)
        try:
            logger.info("Starting mangle process.")
            nfqueue.run()
        except KeyboardInterrupt:
            logger.info("Exiting mangle process.")
            sys.exit(0)
        except Exception:
            logger.critical(
                "Mangle process ended prematurely. Restarting.",
                exc_info=True,
            )
        finally:
            # The table stays: without a listener its queue drops DNS responses
            # instead of passing them untranslated. setup_nftables replaces it.
            nfqueue.unbind()

        time.sleep(0.1)


if __name__ == "__main__":
    main()
