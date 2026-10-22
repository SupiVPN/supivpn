#!/bin/sh
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
test "$(cat /etc/supivpn-disposable-vm)" = 'Debian package acceptance only'
test "$(cat /proc/1/comm)" = systemd
test ! -e /.dockerenv
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends curl ca-certificates liblzo2-2 liblz4-1 libcap-ng0 openssl iproute2 iputils-ping python3 nftables
# The upstream PostgreSQL repository supports Debian 13 on both target CPUs.
# This configuration exists only inside the disposable guest.
install -d /usr/share/postgresql-common/pgdg
curl --fail --show-error --silent --proto '=https' https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
cat > /etc/apt/sources.list.d/supivpn-test-pgdg.sources <<'EOF'
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: trixie-pgdg
Components: main
Signed-By: /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
EOF
apt-get update -qq
case "${1:-local}" in
    local) apt-get install -y --no-install-recommends postgresql-18 ;;
    remote)
        apt-get install -y --no-install-recommends postgresql-client-18
        test ! -e /usr/lib/postgresql/18/bin/postgres
        printf '\n10.0.2.2 db.supivpn.test\n' >> /etc/hosts
        ;;
    *) echo 'FAIL: unknown database mode'; exit 1 ;;
esac
dpkg -i /opt/supivpn-test/openvpn-test.deb /opt/supivpn-test/supivpn*.deb
for service in supivpn-controller supivpn-node supivpn-openvpn; do
    if systemctl is-active --quiet "$service"; then
        echo "FAIL: fresh package started $service"
        exit 1
    fi
    state=$(systemctl is-enabled "$service" || true)
    # is-enabled returns success for static units too; static is not enabled.
    if test "$state" != disabled && test "$state" != static; then
        echo "FAIL: fresh package enabled $service"
        exit 1
    fi
done
echo 'PASS: fresh installation leaves SupiVPN stopped and not enabled'
systemd-analyze verify supivpn-controller.service supivpn-node.service supivpn-openvpn.service
echo 'PASS: installed units verified by real systemd'
