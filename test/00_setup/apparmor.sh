#! /bin/bash
# Lab only: load the AppArmor profiles of vpnc and the daemons it starts from the
# vpnc image, with the image's includes, so they're confined as on a VM (as root).
# Usage: apparmor.sh <image>
set -euo pipefail
[[ -d /sys/kernel/security/apparmor ]] || exit 0
dir="$(mktemp -d)"
trap 'rm -rf "${dir}"' EXIT
podman run --rm --entrypoint tar "$1" -C /etc/apparmor.d -c . | tar -C "${dir}" -x
for name in ncubed-vpnc ncubed-vpncmangle usr.lib.ipsec.charon usr.sbin.swanctl bgpd bfdd staticd; do
    apparmor_parser -r -b "${dir}" "${dir}/${name}"
done
echo "Loaded the AppArmor profiles of vpnc, vpncmangle, charon, swanctl and FRR"
