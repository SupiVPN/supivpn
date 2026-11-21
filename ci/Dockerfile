# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
ARG GO_IMAGE=golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea
ARG POSTGRES_IMAGE=postgres:18.7-bookworm@sha256:194e55feb2597b1465dbee81cc9fd8d204566cd2eb42c8d22fd6c931a38781b1
FROM ${GO_IMAGE} AS go
FROM ${POSTGRES_IMAGE}
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ARG OPENVPN_SHA256=c42a6ed892ddfe2d6e3317a5040f19bec5827564affb2fe3f2b3904a94daacb1
ARG OPENVPN_VERSION=2.7.9
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-yaml xmlsec1 ca-certificates curl gnupg git \
    build-essential pkg-config libssl-dev liblzo2-dev liblz4-dev libcap-ng-dev \
    iproute2 iptables && rm -rf /var/lib/apt/lists/*
RUN test "${OPENVPN_VERSION}" = "2.7.9" && \
    test "${#OPENVPN_SHA256}" = 64 && \
    curl --fail --show-error --proto '=https' --tlsv1.2 \
      "https://build.openvpn.net/downloads/releases/openvpn-${OPENVPN_VERSION}.tar.gz" -o /tmp/openvpn.tar.gz && \
    printf '%s  %s\n' "${OPENVPN_SHA256}" /tmp/openvpn.tar.gz | sha256sum -c - && \
    tar -xzf /tmp/openvpn.tar.gz -C /tmp && \
    cd "/tmp/openvpn-${OPENVPN_VERSION}" && \
    ./configure --prefix=/usr --sbindir=/usr/sbin --disable-dco --disable-plugin-auth-pam && \
    make -j2 && make install && \
    rm -rf /tmp/openvpn*
RUN useradd --create-home --uid 10001 builder
USER builder
ENTRYPOINT []
CMD ["/bin/sh"]
