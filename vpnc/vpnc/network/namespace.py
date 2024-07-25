import atexit

from pyroute2 import netns


def list_() -> list[str]:
    return netns.listnetns()


def add(name: str, cleanup=False) -> str:
    ns_list = netns.listnetns()

    if not name in ns_list:
        netns.create(name)

    if cleanup:
        atexit.register(delete, name=name)

    return name


def delete(name: str):
    ns_list = netns.listnetns()

    if name in ns_list:
        netns.remove(name)
