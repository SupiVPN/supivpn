# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
# QEMU is a test tool here, not a SupiVPN deployment image.
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-arm qemu-system-x86 qemu-utils qemu-efi-aarch64 \
    genisoimage && rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
