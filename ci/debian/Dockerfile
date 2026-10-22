# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
FROM golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110 AS go
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
RUN apt-get update && apt-get install -y --no-install-recommends \
    debhelper build-essential python3 ca-certificates systemd systemd-sysv \
    adduser file lintian libssl-dev liblzo2-dev liblz4-dev libcap-ng-dev \
    pkg-config curl iproute2 && rm -rf /var/lib/apt/lists/*
# Real OpenVPN dependency used only in disposable package/lifecycle tests.
RUN curl --fail --show-error --proto '=https' --tlsv1.2 \
    https://build.openvpn.net/downloads/releases/openvpn-2.7.8.tar.gz -o /tmp/openvpn.tar.gz && \
    printf '%s  %s\n' c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36 /tmp/openvpn.tar.gz | sha256sum -c - && \
    tar -xzf /tmp/openvpn.tar.gz -C /tmp && cd /tmp/openvpn-2.7.8 && \
    ./configure --prefix=/usr --sbindir=/usr/sbin --disable-dco --disable-plugin-auth-pam && \
    make -j2 && make DESTDIR=/tmp/openvpn-package install && \
    mkdir /tmp/openvpn-package/DEBIAN && \
    printf 'Package: openvpn\nVersion: 2.7.8-0supivpntest1\nArchitecture: %s\nMaintainer: SupiVPN <enot@supivpn.com>\nDescription: Disposable OpenVPN test dependency\n' "$(dpkg --print-architecture)" > /tmp/openvpn-package/DEBIAN/control && \
    dpkg-deb --build --root-owner-group /tmp/openvpn-package /opt/openvpn-test.deb && \
    rm -rf /tmp/openvpn*
ENTRYPOINT []
CMD ["/bin/sh"]
