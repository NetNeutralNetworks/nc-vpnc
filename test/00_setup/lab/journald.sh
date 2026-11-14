#! /bin/bash
# Lab only: start journald as systemd does; vpnc, vpncmangle and charon log to it.
mkdir -p /run/systemd/journal
/usr/lib/systemd/systemd-journald > /dev/null 2>&1 &
for _ in {1..50}; do
    [ -S /run/systemd/journal/dev-log ] && break
    sleep 0.1
done
ln -sf /run/systemd/journal/dev-log /dev/log
