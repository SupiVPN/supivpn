# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-yaml reprepro gnupg ca-certificates && rm -rf /var/lib/apt/lists/*
CMD ["python3", "-B", "-m", "unittest", "discover", "-s", "tools", "-p", "test_apt_repository.py", "-v"]
