#! /bin/bash
# Lab only: load the AppArmor profiles of the vpnc image that the host lacks,
# such as charon's, so its daemons are confined as on a VM (as root).
# Usage: apparmor.sh <image>
set -euo pipefail
[[ -d /sys/kernel/security/apparmor ]] || exit 0
dir="$(mktemp -d)"
trap 'rm -rf "${dir}"' EXIT
podman run --rm --entrypoint tar "$1" -C /etc/apparmor.d -c . | tar -C "${dir}" -x
for profile in "${dir}"/*; do
    name="$(basename "${profile}")"
    if [[ -f "${profile}" && ! -e "/etc/apparmor.d/${name}" ]]; then
        apparmor_parser -r -I "${dir}" "${profile}"
        echo "Loaded the AppArmor profile ${name}"
    fi
done
