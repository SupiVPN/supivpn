# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
FROM postgres:18.7-bookworm@sha256:194e55feb2597b1465dbee81cc9fd8d204566cd2eb42c8d22fd6c931a38781b1
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
    && rm -rf /var/lib/apt/lists/*
COPY check.py /test/check.py
ENTRYPOINT ["python3", "-B", "/test/check.py"]
