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
sudo test/00_base/diagnostics.sh            # when something fails
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
sudo test/00_base/diagnostics.sh vpnc-fuzz
```

`VPNC_LAB` selects the lab the tests run in; without it, the base lab.

Without a version, the deploy scripts use the last built image (`latest`), as in CI.
