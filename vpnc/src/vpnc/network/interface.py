import atexit
from ipaddress import IPv4Interface, IPv6Interface
from typing import Any, Literal

from pyroute2 import IPDB, NDB, NetNS
from pyroute2.ndb.objects import interface

from . import namespace


def get(
    name: str,
    kind: str | None = None,
    ns_name: str | Literal["*"] | None = None,
) -> interface.Interface | None:
    with NDB() as ndb:
        query = {"ifname": name}  # , "kind": kind}

        if ns_name == "*":
            ns_list = namespace.list_()
            ndb.sources.remove("localhost")
            for i in ns_list:
                ndb.sources.add(netns=i)
        elif ns_name is not None:
            ndb.sources.remove("localhost")
            ndb.sources.add(netns=ns_name)
            query["target"] = ns_name

        if kind:
            query["kind"] = kind

        if ns_name == "*":
            gm_query = {"ifname": name}
            if kind:
                gm_query["IFLA_INFO_KIND"] = kind

            infs: list[dict[str, Any]] = list(ndb.interfaces.getmany(gm_query))
            if len(infs) != 1:
                return None

            query["target"] = infs[0]["target"]

        inf: interface.Interface = ndb.interfaces.get(query)

        return inf


def set(
    inf: interface.Interface,
    state: Literal["up", "down"] | None = None,
    addresses: list[IPv4Interface | IPv6Interface] | None = None,
    ns_name: str | None = None,
    cleanup=False,
) -> interface.Interface:
    if addresses is None:
        addresses = []

    with NDB() as ndb:
        # ndb.sources.remove("localhost")
        try:
            ndb.sources.add(netns=inf["target"])
        except Exception:
            pass
        try:
            ndb.sources.add(netns=ns_name)
        except Exception:
            pass
        intf: interface.Interface = ndb.interfaces[
            {"ifname": inf["ifname"], "target": inf["target"]}
        ]
        with intf:
            if ns_name and ns_name != intf["target"]:
                intf.set(net_ns_fd=ns_name).commit()
            if state:
                intf.set(state=state)
            if addresses:
                intf.del_ip()
            for i in addresses:
                intf.add_ip(str(i))
            intf.commit()

    if cleanup:
        atexit.register(delete, inf=intf)

    # delete(intf)

    return intf


def delete(inf: interface.Interface) -> None:
    if inf["kind"] is None:
        netns = NetNS(inf["target"])
        with IPDB(netns) as ipdb:
            # ipdb.sources.add(netns=inf["target"])
            with ipdb.interfaces[inf["ifname"]] as intf:
                # interface.net_ns_pid = os.getpid()
                intf.net_ns_pid = 1
    else:
        with NDB() as ndb:
            ndb.sources.add(netns=inf["target"])
            with ndb.interfaces[
                {"ifname": inf["ifname"], "target": inf["target"]}
            ] as intf:
                intf.remove().commit()
