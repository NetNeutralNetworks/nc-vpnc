"""What the peers of IPsec and WireGuard connections send, as EXTERNAL counts it.

EXTERNAL's peer sets count the packets per peer. A sample every full check notes
when each last sent something, so "the peer is silent" doesn't depend on logs.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from vpnc import config
from vpnc.models import enums
from vpnc.network import nftables

if TYPE_CHECKING:
    from vpnc.models.connections import Connection

logger = logging.getLogger("vpnc")


@dataclass
class Seen:
    """The packets a peer sent, as sampled."""

    # As counted now; restarts when EXTERNAL's firewall is replaced.
    packets: int
    # Unix time of the first sample, and of the last one with more packets.
    since: float
    last: float | None = None


# By set and element, e.g. ("ipsec_peers_ipv4", "192.0.2.7").
SEEN: dict[tuple[str, str], Seen] = {}
_LOCK = threading.Lock()


def sample() -> None:
    """Note which peers sent packets since the last sample."""
    try:
        counters = nftables.set_counters(config.EXTERNAL_NI)
    except (nftables.NftablesError, OSError, ValueError) as err:
        logger.debug("Reading EXTERNAL's peer counters failed: %s", err)
        return
    now = time.time()
    with _LOCK:
        current = {
            (name, element): packets
            for name, elements in counters.items()
            for element, packets in elements.items()
        }
        for key, packets in current.items():
            seen = SEEN.setdefault(key, Seen(packets, now))
            # Also when there are fewer: counted from zero again, then these.
            if packets != seen.packets and packets:
                seen.last = now
            seen.packets = packets
        for key in SEEN.keys() - current.keys():
            del SEEN[key]


def seen(connection: Connection) -> dict[str, Seen]:
    """Return what the peers (remote_addrs) of a connection sent, sampled now."""
    cfg = connection.config
    if cfg.type == enums.ConnectionType.IPSEC:
        keys = {
            str(address): (f"ipsec_peers_ipv{address.version}", str(address))
            for address in cfg.remote_addrs
        }
    elif cfg.type == enums.ConnectionType.WIREGUARD:
        keys = {
            str(address): (
                f"wireguard_peers_ipv{address.version}",
                f"{address} . {cfg.local_port}",
            )
            for address in cfg.remote_addrs
        }
    else:
        return {}
    sample()
    with _LOCK:
        return {
            address: Seen(**vars(SEEN[key]))
            for address, key in keys.items()
            if key in SEEN
        }
