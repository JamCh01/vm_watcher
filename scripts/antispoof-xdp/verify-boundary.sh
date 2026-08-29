#!/usr/bin/env bash
# verify-boundary.sh — check the pre-TCX anti-spoofing boundary on one bridge.
#
# Usage: verify-boundary.sh <bridge>
#
# Exit 0: every TAP under the bridge carries an XDP program (boundary in place).
# Exit 1: at least one TAP has no XDP program — the boundary is VIOLATED there:
#         spoofed-source frames would be counted into the victim's rate budget
#         before any netdev-ingress drop can stop them (see
#         docs/antispoof-boundary.md for the measured hook order and impact).
#
# This check is attachment-only. To prove the ORDER end-to-end, inject a frame
# with a foreign source on one TAP and confirm it never appears in the daemon's
# TRAFFIC map (bpftool map dump name TRAFFIC) — procedure in
# docs/antispoof-boundary.md.
set -u
BR="${1:?usage: verify-boundary.sh <bridge>}"
if [ ! -d "/sys/class/net/$BR" ]; then
    echo "ERROR: no such bridge: $BR" >&2
    exit 2
fi

violations=0
checked=0
for port in $(ls "/sys/class/net/$BR/brif" 2>/dev/null); do
    # Only TAP/TUN ports are VM-facing; other bridge ports (veth, phys) are out
    # of scope for this boundary.
    [ -r "/sys/class/net/$port/tun_flags" ] || continue
    checked=$((checked + 1))
    if ip -o link show dev "$port" | grep -qw xdp; then
        echo "OK       $port: XDP program attached (pre-TCX boundary present)"
    else
        echo "VIOLATED $port: NO XDP program — attach scripts/antispoof-xdp/antispoof_xdp.o"
        violations=$((violations + 1))
    fi
done

if [ "$checked" -eq 0 ]; then
    echo "WARN: bridge $BR has no TAP ports right now; nothing to check"
    exit 0
fi
echo "checked $checked TAP(s), $violations violation(s)"
[ "$violations" -eq 0 ]
