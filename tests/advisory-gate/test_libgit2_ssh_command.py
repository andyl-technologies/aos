"""Checks the vendored libgit2 SSH repository-command quoting."""

from __future__ import annotations

import os
import shlex
import unittest
from pathlib import Path


VENDOR_ROOT = Path(os.environ["AOS_CARGO_VENDOR"])


def libgit2_ssh_source() -> Path:
    """Returns the SSH transport source selected by the workspace lockfile."""
    matches = list(
        VENDOR_ROOT.glob(
            "source-registry-*/libgit2-sys-0.18.8+1.9.7/"
            "libgit2/src/libgit2/transports/ssh_libssh2.c"
        )
    )
    if len(matches) != 1:
        raise AssertionError(f"expected one libgit2 SSH source, found {matches}")
    return matches[0]


def repository_command(repository_path: str) -> str:
    """Models the checked `git_str_puts_escaped` call for a repository path."""
    escaped = "".join(
        f"'\\{character}'" if character in "'!" else character
        for character in repository_path
    )
    return f"git-upload-pack '{escaped}'"


class Libgit2SshCommandTests(unittest.TestCase):
    """Checks the vendored command construction and its argument boundaries."""

    def test_vendored_transport_escapes_shell_metacharacters(self) -> None:
        source = libgit2_ssh_source().read_text(encoding="utf-8")

        self.assertIn(
            'git_str_puts_escaped(request, repo, "\'!", "\'\\\\", "\'");',
            source,
        )

    def test_repository_path_remains_one_server_argument(self) -> None:
        for repository_path in (
            "/srv/registry.git",
            "/srv/registry with spaces.git",
            "/srv/registry'quoted.git",
            "/srv/registry!history.git",
        ):
            with self.subTest(repository_path=repository_path):
                self.assertEqual(
                    shlex.split(repository_command(repository_path)),
                    ["git-upload-pack", repository_path],
                )


if __name__ == "__main__":
    unittest.main()
