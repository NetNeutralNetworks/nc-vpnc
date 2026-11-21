# Lab tests

The tests run against containerlab labs and check end results in the lab.

| Directory | What | Time |
|---|---|---|
| `00_setup/` | The host's prerequisites (Docker, containerlab, Jool, test tools) and the images | |
| `00_base/` | The base lab: topology, node configuration and lab scripts | |
| `00_scale/` | The scale lab | |
| `00_fuzz/` | The fuzz lab: the base lab's nodes, for tests that wreck it | |
| `01_sanity/` | The freshly deployed lab is configured and working. Read-only. | seconds |
| `02_reliability/` | Configuration changes, drift and failures (outages, restarts, lost sessions) are handled. Disrupts the lab and restores it. | ~20 min |
| `03_performance/` | 200 network instances and 300 connections, in the scale lab. | ~10 min |
| `04_fuzz/` | Generated configuration, API requests, DNS answers, IKE packets, faults and crashes (Hypothesis, Schemathesis), in the fuzz lab. May leave it broken. | ~40 min with `FUZZ_EXAMPLES=25` |

## Setup

Once per host (Ubuntu 26.04), then log in again for the docker group:

```sh
sudo test/00_setup/install.sh
```

Then build the images, after each change to vpnc:

```sh
sudo test/00_setup/build-image.sh 26.04
```

## Base lab

```sh
sudo test/00_base/deploy-base.sh 26.04
sudo test/00_base/healthcheck.sh
sudo python3 -m pytest test/01_sanity        # quick check
sudo python3 -m pytest test/02_reliability   # full check
sudo test/00_setup/diagnostics.sh            # when something fails
```

Run the sanity tests on a fresh lab, before the reliability tests.

![Base lab](docs/base-lab.svg)

hub00/hub01 run vpnc in hub mode, end00/end01 in endpoint mode. mgt00/mgt01 are
the provider side (strongSwan, FRR); cli00/cli01 are customer networks behind
end00/end01. The labels show what each tunnel uses. mgt00 sends its traffic
through hub00 and mgt01 through hub01, so the tests' traffic crosses both hubs.

The containers have tini as init (PID 1): `docker stop` stops vpnc as systemd
would, and what daemons leave behind is reaped. A container stops when its vpnc
exits.

## Scale lab

Runs next to the base lab, with its own bridge and container names.

![Scale lab](docs/scale-lab.svg)

The tests add the tenants C0100-C0124 to hub00; peer00 is the other end of all
their connections.

```sh
sudo test/00_scale/deploy-scale.sh 26.04
sudo python3 -m pytest test/03_performance
```

The run ends with its measurements: apply and recovery times, idle CPU.

## Fuzz lab

The base lab's nodes and configuration, next to the base lab, with its own bridge,
management network and container names (`clab-vpnc-fuzz-*`). Tests that leave the
lab in an unknown state run here, so other runs keep a working base lab.

```sh
sudo test/00_fuzz/deploy-fuzz.sh 26.04
sudo test/00_base/healthcheck.sh vpnc-fuzz
sudo VPNC_LAB=vpnc-fuzz python3 -m pytest test/01_sanity
sudo test/00_setup/diagnostics.sh vpnc-fuzz
```

`VPNC_LAB` selects the lab the tests run in; without it, the base lab.

```sh
python3 -m pytest test/04_fuzz                         # on its own: skipped next to other suites
FUZZ_EXAMPLES=25 python3 -m pytest test/04_fuzz        # examples per test, default 100 (hours)
python3 -m pytest test/04_fuzz --hypothesis-show-statistics
```

The fuzz tests need `python3-hypothesis`. A failure prints the smallest input that
fails; it's kept in `test/04_fuzz/.hypothesis` and tried first in the next run.

| Test | Generates |
|---|---|
| `test_config_input` | Configuration files and API requests, valid or not |
| `test_api_schema` | API requests from the OpenAPI schema (Schemathesis) |
| `test_dns_answers` | DNS answers that vpncmangle translates |
| `test_config_states` | Sequences of valid changes to a tenant; hub00 restarts after each sequence |
| `test_network_faults` | The same, with hub00's uplink down, flapping, losing or delaying packets |
| `test_restarts` | The same, with charon, vpncmangle, an FRR daemon or vpnc killed, or hub00 restarted right after a commit |
| `test_concurrency` | API calls and hand edits at the same time |
| `test_ike_packets` | IKE messages to charon from a peer's address |
| `test_tenant_traffic` | Packets from tenants through their tunnels (any range, protocol, ICMP type, options, fragments), and spoofed DNS answers |

Besides vpnc's own state, the tests check that charon, FRR and vpncmangle run,
answer and took the configuration, that the nftables tables exist, and that BGP
is up. The tenant traffic test checks, with sniffers in all of hub00's network
instances, that nothing a tenant sends leaves its network instance. The state
machines run a tenth of the examples (sequences), the concurrency test half, the
IKE test four times as many. A test that restarts hub00 links its uplink to the
bridge again: containerlab only adds links at deploy.

Without a version, the deploy scripts use the last built image (`latest`), as in CI.
