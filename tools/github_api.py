# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded GitHub requests; credentials never follow download redirects."""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

import artifacts as a

REPOSITORY = "SupiVPN/supivpn"
API = "https://api.github.com/repos/" + REPOSITORY + "/"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download_host(url):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    return (parsed.scheme == "https" and not parsed.username and not parsed.password
            and parsed.port in {None, 443} and not parsed.fragment
            and (host in {"api.github.com", "github.com", "release-assets.githubusercontent.com"}
                 or host.endswith(".blob.core.windows.net")))


def request(url, *, method="GET", data=None, limit=8 * 1024 * 1024, accept="application/vnd.github+json"):
    parsed = urllib.parse.urlsplit(url)
    a.require(parsed.scheme == "https" and parsed.hostname in {"api.github.com", "uploads.github.com"}
              and not parsed.username and not parsed.password and parsed.port in {None, 443}
              and parsed.path.startswith("/repos/" + REPOSITORY + "/"), "GitHub endpoint refused")
    headers = {"Accept": accept, "User-Agent": "SupiVPN-release", "X-GitHub-Api-Version": "2026-03-10"}
    token = os.environ.get("GH_TOKEN", "")
    if token:
        a.require("\n" not in token and "\r" not in token, "Invalid GitHub credential")
        headers["Authorization"] = "Bearer " + token
    if isinstance(data, dict):
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    elif data is not None:
        headers["Content-Type"] = "application/octet-stream"
    opener = urllib.request.build_opener(NoRedirect())
    for _ in range(4):
        try:
            with opener.open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=60) as reply:
                content = reply.read(limit + 1)
                a.require(len(content) <= limit, "GitHub response too large")
                return reply.status, content
        except urllib.error.HTTPError as error:
            error.close()
            if error.code in {301, 302, 303, 307, 308} and method == "GET":
                target = urllib.parse.urljoin(url, error.headers.get("Location", ""))
                a.require(download_host(target), "GitHub download redirect refused")
                headers = {"Accept": accept, "User-Agent": "SupiVPN-release"}
                url = target
                continue
            # Never include response bodies, URL query strings or credentials in diagnostics.
            if error.code == 404:
                return 404, b""
            raise a.ValidationError("GitHub request failed: HTTP " + str(error.code)) from None
        except (OSError, urllib.error.URLError):
            raise a.ValidationError("GitHub request failed or timed out") from None
    raise a.ValidationError("Too many GitHub download redirects")


def api(path, *, method="GET", data=None, missing=False):
    a.require(not path.startswith("/") and ".." not in path and "://" not in path,
              "Invalid GitHub API path")
    status, raw = request(API + path, method=method, data=data)
    if missing and status == 404:
        return None
    a.require(200 <= status < 300, "GitHub object unavailable")
    return a.json_object(raw)
