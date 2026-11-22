"""Generated DNS answers from a tenant's DNS server, through hub00's vpncmangle.

A responder on cli00 answers a query from mgt00 (through hub00: NAT64, or the
identity translation of C0001-00) with a generated answer: well-formed with any
records, names and sections, or broken in a place (a lying count or length, a
pointer anywhere, truncated), or anything at all. vpncmangle must keep running
and translating, and what reaches mgt00 must hold no tenant address it didn't
translate (as a lenient parser, like a client's, reads it).

After each answer the responder sends a sentinel, an answer that vpncmangle
translates: it shows that vpncmangle still does, and that the generated answer
came before it or was dropped, without waiting for one that doesn't come.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from fuzz_common import dns_oracle, dns_strategies, dns_wire
from hypothesis import event, given, settings
from hypothesis import strategies as st

from . import conftest

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.skipif(
    not conftest.FUZZ_LAB,
    reason="runs in the fuzz lab: run test/04_fuzz on its own",
)

# An example takes about 80 ms.
FUZZ = settings(
    max_examples=10 * int(os.environ.get("FUZZ_EXAMPLES", "100")),
    deadline=None,
)
SERVER = "cli00"
NI = "C0001-00"
# The responder's addresses on cli00, and as mgt00 reaches them through hub00.
RESPONDER_4 = "172.16.31.53"
RESPONDER_6 = "2001:db8:c57:31::53"
TARGETS = {
    "NAT64": f"fdcc:0:c:1::{RESPONDER_4}",
    "DNS66": RESPONDER_6,
}
QNAME = dns_strategies.QNAME
# How long after the sentinel an answer sent before it may still come.
GRACE = float(os.environ.get("FUZZ_DNS_GRACE", "0.03"))
QTYPES = {"A": 1, "AAAA": 28}
# The sentinel's A record, and as vpncmangle translates it (NAT64).
SENTINEL_4 = "172.16.31.4"
SENTINEL_6 = "fdcc:0:c:1::ac10:1f04"
# Answers each query to the addresses with ANSWER (whether it gets the query's
# id, and the answer), then with the sentinel: an A record of the question's
# name, its id the query's inverted. It binds before the addresses exist
# (freebind): named takes any new address.
SENTINEL = f"""
def sentinel(query):
    ident = bytes(b ^ 0xFF for b in query[:2])
    header = ident + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
    record = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4)
    return header + query[12:] + record + socket.inet_aton("{SENTINEL_4}")
"""
RESPONDER = f"""
import select, socket, struct, threading
{SENTINEL}
ANSWER = None
SOCKS = []
for family, level, option, address in (
    (socket.AF_INET, socket.IPPROTO_IP, 15, "{RESPONDER_4}"),
    (socket.AF_INET6, socket.IPPROTO_IPV6, 78, "{RESPONDER_6}"),
):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.setsockopt(level, option, 1)
    s.bind((address, 53))
    SOCKS.append(s)


def serve():
    while True:
        for s in select.select(SOCKS, [], [])[0]:
            query, peer = s.recvfrom(4096)
            if ANSWER:
                keep_id, answer = ANSWER[0], bytes.fromhex(ANSWER[1])
                if keep_id and len(answer) >= 2:
                    answer = query[:2] + answer[2:]
                s.sendto(answer, peer)
            s.sendto(sentinel(query), peer)


threading.Thread(target=serve, daemon=True).start()
"""

# vpncmangle drops a network instance's answers over 50 kbytes per second (the
# sentinel too): the examples stay well under it.
RATE = 30000


def within_rate(sent: collections.deque[tuple[float, int]], size: int) -> None:
    """Wait until an answer of size (and its sentinel) is within the rate."""
    while True:
        now = time.monotonic()
        while sent and sent[0][0] < now - 1:
            sent.popleft()
        if sum(s for _, s in sent) + size <= RATE:
            break
        time.sleep(0.05)
    sent.append((now, size + 100))


def translations() -> dict:
    """Return C0001-00's translations, as vpncmangle has them."""
    text = conftest.run_cmd(
        conftest.HOST,
        "cat /opt/ncubed/config/vpncmangle/translations.json",
    )
    return json.loads(text)[NI]


def translated_prefixes() -> list[ipaddress.IPv6Network]:
    """Return the prefixes vpncmangle translates C0001-00's addresses into."""
    ni = translations()
    return [ipaddress.IPv6Network(local) for local, _ in ni["dns64"] + ni["dns66"]]


def translated_sentinel(server: str, qtype: int) -> str:
    """Return the sentinel as mgt00 gets it, without its id (hex): translated."""
    answers, _ = conftest.dns_ask(server, QNAME, qtype, "")
    assert answers, f"no answer from the responder through {server}"
    found = [
        (a.source, str(a.address))
        for a in dns_wire.addresses(answers[0], answers_only=True)
    ]
    assert found == [("AAAA", SENTINEL_6)], f"not the translated sentinel: {found}"
    return answers[0][2:].hex()


def errors() -> int:
    """Return how many answers vpncmangle failed on (an exception), once counted.

    It writes its counters every 30 s.
    """
    now = time.time()
    conftest.wait_until(
        lambda: (
            int(
                conftest.run_cmd(conftest.HOST, "stat -c %Y /run/vpncmangle/stats.json")
            )
            > now
        ),
        timeout=60,
        interval=1,
        message="vpncmangle's counters",
    )
    status = conftest.api("GET", "/v1/status")[1]
    return status["vpncmangle"]["drop_reasons"].get("ERROR", 0)


def vpncmangle_pid() -> str:
    """Return vpncmangle's process id."""
    return conftest.run_cmd(conftest.HOST, "pgrep -x vpncmangle").strip()


@dataclass
class Errors:
    """vpncmangle's ERROR counter and process when a test started."""

    count: int
    pid: str

    @classmethod
    def now(cls) -> Errors:
        """Return the counter (once written) and the process id."""
        return cls(errors(), vpncmangle_pid())

    def check(self) -> None:
        """Assert that the counter didn't rise in the same process."""
        assert vpncmangle_pid() == self.pid, "vpncmangle was restarted"
        failed = errors() - self.count
        assert not failed, f"vpncmangle failed on {failed} answers (ERROR counter)"


# The run's generated answers (hex), written out when an end check fails.
ANSWERS: list[str] = []
ANSWERS_DIR = Path(conftest.TEST_DIR) / "04_fuzz"


def save_answers() -> Path:
    """Write the run's answers, one per line, for replay_dns_answers.py."""
    path = ANSWERS_DIR / f".dns-answers-{time.strftime('%Y%m%d-%H%M%S')}.txt"
    path.write_text("".join(f"{answer}\n" for answer in ANSWERS), encoding="utf-8")
    return path


def check_late(late: list[bytes], prefixes: list[ipaddress.IPv6Network]) -> None:
    """Check datagrams of earlier examples: leaks only, they're no one's now."""
    leaked = dns_wire.untranslated(late, prefixes)
    assert not leaked, f"untranslated tenant addresses came late: {leaked}"


def check_exact(
    generated: bytes,
    received: list[bytes],
    sentinel: bool,  # noqa: FBT001
    expected: dns_oracle.Translations,
) -> str:
    """Check an answer against the oracle where it tells; return what happened."""
    if not received:
        what = "dropped"
    elif received[0][2:] == generated[2:]:
        what = "as it came"
    else:
        what = "translated"
    original = dns_wire.readable(generated)
    if original is None or not original.flags & dns_oracle.QR or not sentinel:
        return what
    expect = dns_oracle.expected(original, expected)
    if expect.drop:
        assert not received, "an answer vpncmangle must drop came"
        return what
    if not received:
        assert expect.may_drop, "vpncmangle dropped an answer it must pass"
        return what
    # Every answer that came, not only the first: a second may differ.
    for answer in received:
        if expect.unchanged:
            assert answer[2:] == generated[2:], (
                "vpncmangle changed an answer it must pass as is"
            )
        elif expect.records is not None:
            read = dns_wire.records(answer)
            assert read.flags == expect.flags, (
                f"flags {read.flags:#x}, not {expect.flags:#x}"
            )
            assert read.questions == original.questions, "other questions"
            got = dns_oracle.comparable(read.records, expect.records)
            assert got == expect.records, f"records\n{got}\nnot\n{expect.records}"
    return what


@dataclass
class Responder:
    """What the examples check against."""

    # The prefixes answers may hold.
    prefixes: list[ipaddress.IPv6Network]
    # The translations vpncmangle has, as the oracle takes them.
    translations: dns_oracle.Translations
    # The sentinel as mgt00 gets it, per path and query type.
    sentinels: dict[tuple[str, int], str]
    vitals: conftest.Vitals
    errors: Errors
    agent: conftest.Agent
    # When the last answers were sent, and their sizes.
    sent: collections.deque[tuple[float, int]]
    # Of the examples whose answer records() reads: how many, how many translated.
    readable: int = 0
    translated: int = 0


@pytest.fixture(scope="module")
def responder(deployed: conftest.Deployed) -> Iterator[Responder]:  # noqa: ARG001
    """Run the responder on cli00."""
    agent = conftest.Agent(SERVER, setup=RESPONDER)
    try:
        agent.run("")
        conftest.sh(
            SERVER,
            f"ip address add {RESPONDER_4}/32 dev lo;"
            f" ip address add {RESPONDER_6}/128 dev lo",
        )
        for target in TARGETS.values():
            conftest.wait_until(
                lambda target=target: conftest.dns_ask(target, QNAME, 1, "")[0],
                timeout=30,
                message=f"the responder's answer through {target}",
            )
        yield Responder(
            translated_prefixes(),
            dns_oracle.Translations.from_json(translations()),
            {
                (path, qtype): translated_sentinel(target, qtype)
                for path, target in TARGETS.items()
                for qtype in QTYPES.values()
            },
            conftest.vitals(),
            Errors.now(),
            agent,
            collections.deque(),
        )
    finally:
        agent.stop()
        conftest.sh(
            SERVER,
            f"ip address del {RESPONDER_4}/32 dev lo;"
            f" ip address del {RESPONDER_6}/128 dev lo; true",
        )


@FUZZ
@given(data=st.data())
def test_dns_answers(responder: Responder, data: st.DataObject) -> None:
    """Vpncmangle survives any answer, and lets no tenant address through."""
    path = data.draw(st.sampled_from(sorted(TARGETS)), label="path")
    qtype = QTYPES[data.draw(st.sampled_from(sorted(QTYPES)), label="qtype")]
    keep_id, generated = data.draw(dns_strategies.answer(qtype), label="answer")
    ANSWERS.append(generated.hex())
    responder.agent.run("ANSWER = args", [keep_id, generated.hex()])
    within_rate(responder.sent, len(generated))

    # The answer and the sentinel take the same way, in order.
    received, sentinel, late = conftest.dns_observe(
        TARGETS[path],
        QNAME,
        qtype,
        responder.sentinels[path, qtype],
        grace=GRACE,
    )
    if late:
        event("late")
    check_late(late, responder.prefixes)
    leaked = dns_wire.untranslated(received, responder.prefixes)
    assert not leaked, f"untranslated tenant addresses reached mgt00: {leaked}"
    what = check_exact(generated, received, sentinel, responder.translations)
    event(f"{path}: {what}")
    if dns_wire.readable(generated) is not None:
        responder.readable += 1
        responder.translated += what == "translated"
    responder.vitals.check()
    assert sentinel, "vpncmangle didn't translate the answer after it"


def test_dns_answers_end(responder: Responder) -> None:
    """Nothing came late, vpncmangle translated, failed on none, all still answer."""
    responder.agent.run("ANSWER = None")
    try:
        time.sleep(1)
        for target in TARGETS.values():
            check_late(conftest.dns_drain(target), responder.prefixes)
        # Evidence that the answers took vpncmangle's path.
        assert responder.translated * 10 >= responder.readable > 0, (
            f"{responder.translated} of {responder.readable} readable answers"
            " came back translated"
        )
        responder.errors.check()
    except AssertionError:
        print(f"The run's answers: {save_answers()}")
        raise
    conftest.check_answering()
    assert not conftest.bgp_down(), f"BGP went down: {conftest.bgp_down()}"
