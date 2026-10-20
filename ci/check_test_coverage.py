#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Require a combined integration run to include every ordinary Go test file."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FIELDS = ("GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles",
                 "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles", "SysoFiles", "EmbedFiles")
TEST_FIELDS = ("TestGoFiles", "XTestGoFiles", "TestEmbedFiles", "XTestEmbedFiles")


class CoverageError(ValueError):
    """A static reason, safe to report without package contents or tool output."""


def packages(data):
    if len(data) > 4 * 1024 * 1024:
        raise CoverageError("Go package metadata too large")
    decoder, result = json.JSONDecoder(), {}
    remaining = data.strip()
    while remaining:
        item, end = decoder.raw_decode(remaining)
        if not isinstance(item, dict):
            raise CoverageError("Invalid Go package metadata")
        name = item.get("ImportPath")
        if not isinstance(name, str) or not name or name in result or item.get("Error"):
            raise CoverageError("Invalid Go package metadata")
        result[name] = item
        remaining = remaining[end:].lstrip()
    if not result:
        raise CoverageError("No Go packages found")
    return result


def files(item, fields):
    result = set()
    for field in fields:
        names = item.get(field, [])
        if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
            raise CoverageError("Invalid Go file list")
        result.update((field, name) for name in names)
    return result


def verify(ordinary, combined):
    if ordinary.keys() != combined.keys():
        raise CoverageError("Integration tags change the package set")
    for name, original in ordinary.items():
        if files(original, SOURCE_FIELDS) != files(combined[name], SOURCE_FIELDS):
            raise CoverageError("Integration tags change production sources")
        if not files(original, TEST_FIELDS) <= files(combined[name], TEST_FIELDS):
            raise CoverageError("Integration tags exclude ordinary tests")


def command_failure(error):
    # Never forward Go/Git diagnostics: they can contain credential-bearing URLs.
    stderr = error.stderr if isinstance(error.stderr, str) else ""
    if "error obtaining VCS status" in stderr:
        return "Go could not inspect VCS metadata"
    if "-race requires cgo" in stderr:
        return "race-enabled selection requires CGO"
    return "go list exited with code " + str(error.returncode)


def main():
    phase = "ordinary package selection"
    try:
        snapshots = []
        for phase, flags in (("ordinary package selection", []),
                             ("integration package selection", ["-tags=integration"])):
            # Runner's helper can own the checkout. Listing source/test files does
            # not need VCS stamping; signatures are verified in the preceding job.
            result = subprocess.run(["go", "list", "-buildvcs=false", "-race", "-json", *flags, "./..."],
                                    cwd=ROOT, capture_output=True, text=True,
                                    check=True, timeout=90)
            snapshots.append(packages(result.stdout))
        phase = "coverage comparison"
        verify(*snapshots)
    except CoverageError as error:
        reason = str(error)
    except subprocess.CalledProcessError as error:
        reason = command_failure(error)
    except subprocess.TimeoutExpired:
        reason = "go list timed out after 90 seconds; check dependency availability"
    except FileNotFoundError:
        reason = "Go executable or module root is missing"
    except OSError:
        reason = "cannot execute Go or access package files"
    except (ValueError, TypeError, AttributeError):
        reason = "invalid Go package metadata"
    else:
        print("Integration tags retain all ordinary Go source and test files")
        return
    sys.exit("Combined-test coverage refused at " + phase + ": " + reason)


if __name__ == "__main__":
    main()
