"""Executes the journal sealing adapter with controlled mount interfaces."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BASH = sys.argv.pop(1)
SCRIPT = str(Path(sys.argv.pop(1)).resolve())

HARNESS = r'''
set -euo pipefail
options=$TEST_OPTIONS
function [ {
  if [[ "$#" == 3 && "$1" == -b ]]; then
    [[ "$2" == /dev/test-esp || "$2" == /dev/esp-alias || "$2" == /dev/foreign-esp ]]
  else
    builtin [ "$@"
  fi
}
mountpoint() {
  [[ "$#" == 2 && "$1" == -q && "$2" == "$TEST_TARGET" ]]
  [[ "$TEST_MOUNTED" == true ]]
}
findmnt() {
  [[ "$#" == 5 && "$1" == -rn && "$2" == --mountpoint ]]
  [[ "$3" == "$TEST_TARGET" && "$4" == -o ]]
  case "$5" in
    FSTYPE) printf '%s\n' "$TEST_FILESYSTEM";;
    SOURCE) printf '%s\n' "$TEST_SOURCE";;
    OPTIONS) printf '%s\n' "$options";;
    *) return 1;;
  esac
}
readlink() {
  [[ "$#" == 2 && "$1" == -f ]]
  case "$2" in
    /dev/esp-alias) printf '/dev/test-esp\n';;
    *) printf '%s\n' "$2";;
  esac
}
mount() {
  printf 'mount'; printf ' <%s>' "$@"; printf '\n'
  [[ "$#" == 3 && "$1" == -o && "$2" == remount,ro && "$3" == "$TEST_TARGET" ]]
  [[ "$TEST_REMOUNT_FAILURE" == false ]] || return 1
  options=$TEST_POST_OPTIONS
}
unmount() { echo 'unexpected unmount' >&2; return 1; }
umount() { echo 'unexpected umount' >&2; return 1; }
source "$1" "$TEST_TARGET" "$TEST_DEVICE" /dev/not-a-block-device
'''


class TransactionStorageSealTests(unittest.TestCase):
    def run_script(self, **overrides):
        settings = {
            "TARGET": "/run/aos-boot-transaction-storage",
            "MOUNTED": "true",
            "FILESYSTEM": "vfat",
            "SOURCE": "/dev/test-esp",
            "DEVICE": "/dev/test-esp",
            "OPTIONS": "rw,noatime,fmask=0077,dmask=0077",
            "POST_OPTIONS": "ro,noatime,fmask=0077,dmask=0077",
            "REMOUNT_FAILURE": "false",
        }
        settings.update(overrides)
        environment = dict(os.environ, LC_ALL="C")
        environment.update({"TEST_" + key: value for key, value in settings.items()})

        return subprocess.run(
            [BASH, "-c", HARNESS, "transaction-storage-seal-test", SCRIPT],
            env=environment,
            capture_output=True,
            text=True,
        )

    def test_writable_configured_esp_is_sealed_once(self):
        result = self.run_script()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "mount <-o> <remount,ro> </run/aos-boot-transaction-storage>\n",
        )

    def test_already_read_only_esp_is_unchanged(self):
        result = self.run_script(OPTIONS="ro,noatime")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_configured_device_alias_is_resolved(self):
        result = self.run_script(DEVICE="/dev/esp-alias")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("mount <"), 1)

    def test_unmounted_target_is_not_mounted_or_changed(self):
        result = self.run_script(MOUNTED="false")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_foreign_filesystem_or_device_is_not_changed(self):
        for overrides in (
            {"FILESYSTEM": "ext4"},
            {"SOURCE": "/dev/foreign-esp"},
            {"SOURCE": "/dev/not-a-block-device"},
            {"DEVICE": "/dev/not-a-block-device"},
        ):
            with self.subTest(overrides=overrides):
                result = self.run_script(**overrides)

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_missing_or_ambiguous_access_mode_is_rejected(self):
        for options in ("noatime", "rw,ro,noatime", "ro,rw,noatime"):
            with self.subTest(options=options):
                result = self.run_script(OPTIONS=options)

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_remount_failure_is_not_hidden(self):
        result = self.run_script(REMOUNT_FAILURE="true")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("mount <"), 1)

    def test_post_remount_access_mode_must_be_unambiguously_read_only(self):
        for options in ("rw,noatime", "noatime", "ro,rw,noatime"):
            with self.subTest(options=options):
                result = self.run_script(POST_OPTIONS=options)

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout.count("mount <"), 1)

    def test_only_esp_mount_changes_and_journal_roots_are_preserved(self):
        with tempfile.TemporaryDirectory(prefix="transaction-seal-test-") as directory:
            target = Path(directory)
            journal = target / "aos/initrd-stage-journal/effects.journal"
            root = journal.parent / "roots/pinned-generation"
            root.parent.mkdir(parents=True)
            journal.write_bytes(b"genuine journal sentinel")
            root.symlink_to("/nix/store/retained-test-root")
            before = journal.stat()

            result = self.run_script(TARGET=directory)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, f"mount <-o> <remount,ro> <{directory}>\n")
            self.assertEqual(journal.read_bytes(), b"genuine journal sentinel")
            self.assertEqual(journal.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(journal.stat().st_ino, before.st_ino)
            self.assertEqual(os.readlink(root), "/nix/store/retained-test-root")


unittest.main()
