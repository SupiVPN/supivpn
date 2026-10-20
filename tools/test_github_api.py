# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
import io
import os
import unittest
from email.message import Message
from unittest.mock import MagicMock, patch
import urllib.error

import artifacts as a
import github_api as gh


def response(data=b"{}", status=200):
    reply = MagicMock()
    reply.__enter__.return_value = reply
    reply.read.return_value = data
    reply.status = status
    return reply


class GitHubAPITests(unittest.TestCase):
    def test_download_redirect_strips_credentials_and_accepts_only_https_storage(self):
        headers = Message()
        headers["Location"] = "https://release-assets.githubusercontent.com/example"
        redirect = urllib.error.HTTPError(gh.API, 302, "redirect", headers, io.BytesIO())
        with patch.dict(os.environ, {"GH_TOKEN": "synthetic-test-token"}), \
                patch.object(gh.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = [redirect, response(b"asset")]
            self.assertEqual(gh.request(gh.API + "releases/assets/1"), (200, b"asset"))
            requests = [call.args[0] for call in opener.return_value.open.call_args_list]
            self.assertEqual(requests[0].get_header("Authorization"), "Bearer synthetic-test-token")
            self.assertIsNone(requests[1].get_header("Authorization"))
            self.assertIsInstance(opener.call_args.args[0], gh.NoRedirect)
        for url in ("http://github.com/x", "https://github.com.attacker.invalid/x",
                    "https://github.com@attacker.invalid/x", "https://github.com:444/x",
                    "https://127.0.0.1/x", "file:///etc/passwd"):
            self.assertFalse(gh.download_host(url))

    def test_redirected_writes_and_untrusted_gets_never_forward_token(self):
        for method, location in (("POST", "https://github.com/x"),
                                 ("GET", "https://attacker.invalid/x")):
            headers = Message()
            headers["Location"] = location
            error = urllib.error.HTTPError(gh.API, 302, "private diagnostic", headers, io.BytesIO())
            with patch.object(gh.urllib.request, "build_opener") as opener:
                opener.return_value.open.side_effect = error
                with self.assertRaises(a.ValidationError) as raised:
                    gh.request(gh.API + "releases", method=method)
                self.assertNotIn("private diagnostic", str(raised.exception))
                self.assertEqual(opener.return_value.open.call_count, 1)

    def test_oversized_response_fails_closed(self):
        with patch.object(gh.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response(b"long")
            with self.assertRaises(a.ValidationError):
                gh.request(gh.API + "releases", limit=3)

    def test_foreign_initial_endpoint_is_refused_before_io(self):
        with patch.object(gh.urllib.request, "build_opener") as opener:
            for url in ("https://api.github.com/repos/other/project/releases", "http://api.github.com/",
                        "https://attacker.invalid/repos/SupiVPN/supivpn/releases"):
                with self.assertRaises(a.ValidationError):
                    gh.request(url)
            opener.assert_not_called()
