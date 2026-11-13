#!/usr/bin/env bash
# VPS setup, run as root on Debian 13 (Linux only). The Mac-side ./hp pipes
# this file over ssh, so nothing has to be copied first.
#
#   prepare <port>   install packages; real sshd listens on 22 AND <port>,
#                    key-only login. Nothing is closed yet.
#   finalize <port>  must run over a session on <port>: drops 22 from sshd
#                    so Cowrie can take it.
#   install          copy-in step for ./hp deploy (files already in place).
#
# The two-step SSH move means a closed cloud firewall or a typo can never
# lock you out: port 22 stays open until <port> is proven to work.
set -euo pipefail
umask 022
DROPIN=/etc/ssh/sshd_config.d/10-uig-honeypot.conf
APP=/opt/uig-honeypot

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root"

check_port() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -ge 1024 ] && [ "$1" -le 65535 ] \
        || die "give the new sshd port (1024-65535)"
}

write_dropin() { # write_dropin <port>...
    {
        echo "# Managed by uig-honeypot harden.sh"
        for p in "$@"; do echo "Port $p"; done
        echo "PasswordAuthentication no"
        echo "KbdInteractiveAuthentication no"
        echo "PermitRootLogin prohibit-password"
    } >"$DROPIN.new"
    mv "$DROPIN.new" "$DROPIN"
    sshd -t || die "sshd config test failed; nothing reloaded ($DROPIN)"
    systemctl reload ssh
}

prepare() {
    check_port "${1:-}"
    local port=$1
    grep -q '^ID=debian' /etc/os-release || die "expected Debian"
    systemctl is-enabled ssh.socket >/dev/null 2>&1 \
        && die "sshd is socket-activated (ssh.socket); disable it first: systemctl disable --now ssh.socket"
    [ -s /root/.ssh/authorized_keys ] \
        || die "/root/.ssh/authorized_keys is empty; add your key first (ssh-copy-id), password login is about to be disabled"

    say "Installing packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -yq --no-install-recommends \
        docker.io docker-cli docker-compose apparmor iptables python3 python3-maxminddb \
        git unattended-upgrades ca-certificates

    say "Enabling automatic security updates"
    echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' >/etc/apt/apt.conf.d/20auto-upgrades

    say "Turning off LLMNR (systemd-resolved listens on 5355 on all interfaces by default)"
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nLLMNR=no\n' >/etc/systemd/resolved.conf.d/10-uig-honeypot.conf
    systemctl try-restart systemd-resolved.service

    say "Moving Port lines out of the other sshd config files"
    local f
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] && [ "$f" != "$DROPIN" ] || continue
        if grep -qiE '^[[:space:]]*Port[[:space:]]' "$f"; then
            cp -p "$f" "$f.uig-bak"
            sed -i -E 's/^([[:space:]]*[Pp][Oo][Rr][Tt][[:space:]])/# uig-honeypot: \1/' "$f"
            echo "   commented out Port in $f (backup: $f.uig-bak)"
        fi
    done

    say "sshd now listens on 22 and $port, key-only"
    write_dropin 22 "$port"
    cat <<EOF

Next:
  1. Open TCP $port (and 22, 23 for the honeypot) in the provider's security group.
  2. On your Mac: ./hp finalize   (connects on port $port, so it proves it works)
EOF
}

finalize() {
    check_port "${1:-}"
    local port=$1 server_port
    server_port=$(awk '{print $4}' <<<"${SSH_CONNECTION:-}")
    [ "$server_port" = "$port" ] \
        || die "run this over an ssh session on port $port (this one is on '${server_port:-?}')"
    write_dropin "$port"
    sleep 1
    if ss -ltnpH 'sport = :22' | grep -q sshd; then
        die "sshd still listens on 22; check 'sshd -T | grep ^port'"
    fi
    say "Real sshd is on $port only. Port 22 is free for Cowrie."
}

install() {
    [ -d "$APP" ] || die "$APP missing; run ./hp deploy"
    if ss -ltnpH 'sport = :22' | grep -q sshd; then
        die "real sshd still owns port 22; run ./hp finalize first"
    fi
    cd "$APP"
    say "Preparing data directories (Cowrie runs as uid 999)"
    mkdir -p data/state data/geoip data/var/log/cowrie data/var/lib/cowrie/tty data/var/lib/cowrie/downloads
    chown -R 999:999 data/var
    chmod 755 uig-egress.sh aggregate.py enrich.py sentinel.py detect.py geoip-update.sh publish.sh
    dpkg -s python3-maxminddb git >/dev/null 2>&1 \
        || DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends python3-maxminddb git

    say "Installing systemd units"
    cp systemd/*.service systemd/*.timer /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now docker.service
    systemctl enable uig-egress.service
    systemctl restart uig-egress.service   # rule in place before the container starts

    local compose=(docker compose)
    docker compose version >/dev/null 2>&1 || compose=(docker-compose)
    say "Starting Cowrie"
    "${compose[@]}" up -d --remove-orphans
    systemctl enable --now uig-aggregate.timer uig-live.timer uig-geoip.timer uig-sentinel.timer uig-sentinel-suricata.timer
    [ -s data/geoip/dbip-city-lite.mmdb ] || { say "Downloading GeoIP database"; systemctl start uig-geoip.service; }
    systemctl start uig-aggregate.service || true
    "${compose[@]}" ps
}

case "${1:-}" in
    prepare)  shift; prepare "$@" ;;
    finalize) shift; finalize "$@" ;;
    install)  install ;;
    *) die "usage: harden.sh prepare <port> | finalize <port> | install" ;;
esac
