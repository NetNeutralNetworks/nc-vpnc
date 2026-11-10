# Lab tests

The tests run against containerlab labs and check end results in the lab.

| Directory | What | Time |
|---|---|---|
| `00_setup/` | Images, the base and scale lab topologies, node configuration and lab scripts | |
| `01_sanity/` | The freshly deployed lab is configured and working. Read-only. | seconds |
| `02_reliability/` | Configuration changes, drift and failures (outages, restarts, lost sessions) are handled. Disrupts the lab and restores it. | ~15 min |
| `03_performance/` | 200 network instances and 300 connections, in the scale lab. | ~10 min |

## Base lab

```sh
sudo test/00_setup/build-image.sh 26.04
sudo test/00_setup/deploy-base.sh 26.04
sudo test/00_setup/healthcheck.sh
sudo python3 -m pytest test/01_sanity        # quick check
sudo python3 -m pytest test/02_reliability   # full check
sudo test/00_setup/diagnostics.sh            # when something fails
```

Run the sanity tests on a fresh lab, before the reliability tests.

## Scale lab

Runs next to the base lab, with its own bridge and container names.

```sh
sudo test/00_setup/deploy-scale.sh 26.04
sudo python3 -m pytest -s test/03_performance
```

Without a version, the deploy scripts use the last built image (`latest`), as in CI.
