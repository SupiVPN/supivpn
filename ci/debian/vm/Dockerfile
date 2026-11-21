# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
# QEMU is a test tool here, not a SupiVPN deployment image.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-arm qemu-system-x86 qemu-utils qemu-efi-aarch64 \
    genisoimage && rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
