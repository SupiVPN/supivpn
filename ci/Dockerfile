# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
ARG GO_IMAGE=golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61
ARG POSTGRES_IMAGE=postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c
FROM ${GO_IMAGE} AS go
FROM ${POSTGRES_IMAGE}
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ARG OPENVPN_SHA256=c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36
ARG OPENVPN_VERSION=2.7.8
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-yaml xmlsec1 ca-certificates curl gnupg git \
    build-essential pkg-config libssl-dev liblzo2-dev liblz4-dev libcap-ng-dev \
    iproute2 iptables && rm -rf /var/lib/apt/lists/*
RUN test "${OPENVPN_VERSION}" = "2.7.8" && \
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
