# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
ARG BASE_IMAGE=supivpn-openvpn-test:2.7.8-arm64
FROM ${BASE_IMAGE}
USER root
ARG CLIENT_VERSION=27.1-1+4.1
RUN install -d /etc/apt/keyrings && \
    curl --fail --silent --show-error --location --proto '=https' \
      https://packages.openvpn.net/packages-repo.gpg -o /etc/apt/keyrings/openvpn.asc && \
    printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/openvpn.asc] https://packages.openvpn.net/openvpn3/debian bookworm main' > /etc/apt/sources.list.d/openvpn3.list && \
    apt-get update && apt-get install -y --no-install-recommends \
      "openvpn3-client=${CLIENT_VERSION}" dbus dbus-x11 xdg-utils && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
CMD ["/bin/sh"]
