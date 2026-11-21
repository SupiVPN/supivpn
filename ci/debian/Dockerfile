# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS go
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
RUN apt-get update && apt-get install -y --no-install-recommends \
    debhelper build-essential python3 ca-certificates systemd systemd-sysv \
    adduser file lintian libssl-dev liblzo2-dev liblz4-dev libcap-ng-dev \
    pkg-config curl iproute2 && rm -rf /var/lib/apt/lists/*
# Real OpenVPN dependency used only in disposable package/lifecycle tests.
RUN curl --fail --show-error --proto '=https' --tlsv1.2 \
    https://build.openvpn.net/downloads/releases/openvpn-2.7.9.tar.gz -o /tmp/openvpn.tar.gz && \
    printf '%s  %s\n' c42a6ed892ddfe2d6e3317a5040f19bec5827564affb2fe3f2b3904a94daacb1 /tmp/openvpn.tar.gz | sha256sum -c - && \
    tar -xzf /tmp/openvpn.tar.gz -C /tmp && cd /tmp/openvpn-2.7.9 && \
    ./configure --prefix=/usr --sbindir=/usr/sbin --disable-dco --disable-plugin-auth-pam && \
    make -j2 && make DESTDIR=/tmp/openvpn-package install && \
    mkdir /tmp/openvpn-package/DEBIAN && \
    printf 'Package: openvpn\nVersion: 2.7.9-0supivpntest1\nArchitecture: %s\nMaintainer: SupiVPN <enot@supivpn.com>\nDescription: Disposable OpenVPN test dependency\n' "$(dpkg --print-architecture)" > /tmp/openvpn-package/DEBIAN/control && \
    dpkg-deb --build --root-owner-group /tmp/openvpn-package /opt/openvpn-test.deb && \
    rm -rf /tmp/openvpn*
ENTRYPOINT []
CMD ["/bin/sh"]
