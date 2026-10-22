# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
FROM postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
    && rm -rf /var/lib/apt/lists/*
COPY check.py /test/check.py
ENTRYPOINT ["python3", "-B", "/test/check.py"]
