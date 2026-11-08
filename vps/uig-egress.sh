#!/usr/bin/env bash
# Block every NEW connection that starts inside the honeypot network, so an
# attacker can never use this VPS to reach other hosts or the host itself.
# Replies to inbound attacker sessions are ESTABLISHED and still flow.
# Cowrie's fake wget/curl therefore fail, but the URLs are still logged.
# Idempotent: safe to run on every boot and every deploy.
set -euo pipefail
BRIDGE=br-cowrie

add() { # add <chain> : insert the drop rule once, at the top
    local rule=(-i "$BRIDGE" -m conntrack --ctstate NEW -j DROP)
    iptables -C "$1" "${rule[@]}" 2>/dev/null || iptables -I "$1" 1 "${rule[@]}"
}

iptables -nL DOCKER-USER >/dev/null 2>&1 || iptables -N DOCKER-USER
add DOCKER-USER   # container -> internet
add INPUT         # container -> this host (real sshd and anything else)
echo "egress from $BRIDGE blocked"
