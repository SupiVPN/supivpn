# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-yaml reprepro gnupg ca-certificates && rm -rf /var/lib/apt/lists/*
CMD ["python3", "-B", "-m", "unittest", "discover", "-s", "tools", "-p", "test_apt_repository.py", "-v"]
