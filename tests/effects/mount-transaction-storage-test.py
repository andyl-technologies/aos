"""Executes the boot adapter with controlled device and mount interfaces."""

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
esp_mounted=$TEST_ESP_MOUNTED
roots_mounted=$TEST_ROOTS_MOUNTED
function [ {
  if [[ "$#" == 3 && "$1" == -b ]]; then
    [[ "$2" == /dev/test-esp || "$2" == /dev/foreign-esp ]]
  elif [[ "$#" == 3 && "$2" == /sys/firmware/efi/efivars/* ]]; then
    return 1
  elif [[ "$#" == 3 && "$2" == "$TEST_TARGET/aos/initrd-stage-journal/roots" ]]; then
    case "$1" in
      -L) [[ "$TEST_ROOTS_KIND" == symlink ]];;
      -e) [[ "$TEST_ROOTS_KIND" != absent ]];;
      -d) [[ "$TEST_ROOTS_KIND" == directory ]];;
      *) builtin [ "$@";;
    esac
  else
    builtin [ "$@"
  fi
}
mountpoint() {
  if [[ "$2" == "$TEST_TARGET" ]]; then
    [[ "$esp_mounted" == true ]]
  else
    [[ "$roots_mounted" == true ]]
  fi
}
findmnt() {
  [[ "$1" == -rn && "$2" == --mountpoint && "$4" == -o ]]
  if [[ "$3" == "$TEST_TARGET" ]]; then
    case "$5" in
      FSTYPE) printf '%s\n' "$TEST_ESP_TYPE";;
      SOURCE) printf '%s\n' "$TEST_ESP_SOURCE";;
      *) return 1;;
    esac
  else
    case "$5" in
      FSTYPE) printf '%s\n' "$TEST_ROOTS_TYPE";;
      OPTIONS) printf '%s\n' "$TEST_ROOTS_OPTIONS";;
      *) return 1;;
    esac
  fi
}
readlink() { printf '%s\n' "$2"; }
stat() { printf '%s\n' "$TEST_ROOTS_METADATA"; }
mkdir() { printf 'mkdir <%s>\n' "$*"; }
install() { printf 'install <%s>\n' "$*"; }
mount() {
  printf 'mount'; printf ' <%s>' "$@"; printf '\n'
  if [[ "$2" == vfat ]]; then
    [[ "$TEST_ESP_FAILURE" == false ]] || return 1
    esp_mounted=true
  else
    [[ "$TEST_ROOTS_FAILURE" == false ]] || return 1
    roots_mounted=true
  fi
}
source "$1" "$TEST_TARGET" /dev/test-esp
'''


class TransactionStorageMountTests(unittest.TestCase):
    def run_script(self, **overrides):
        settings = {
            "ESP_MOUNTED": "false",
            "ESP_TYPE": "vfat",
            "ESP_SOURCE": "/dev/test-esp",
            "ESP_FAILURE": "false",
            "ROOTS_MOUNTED": "false",
            "ROOTS_TYPE": "tmpfs",
            "ROOTS_OPTIONS": "rw,nosuid,nodev,noexec,relatime,mode=700",
            "ROOTS_METADATA": "0:0:700",
            "ROOTS_FAILURE": "false",
            "ROOTS_KIND": "directory",
            "TARGET": "/run/aos-boot-transaction-storage",
        }
        settings.update(overrides)
        environment = dict(os.environ, LC_ALL="C")
        environment.update({"TEST_" + key: value for key, value in settings.items()})
        return subprocess.run(
            [BASH, "-c", HARNESS, "transaction-storage-test", SCRIPT],
            env=environment, capture_output=True, text=True,
        )

    def test_first_mount_keeps_esp_and_adds_only_private_roots_mount(self):
        result = self.run_script()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "mount <-t> <vfat> <-o> <rw,noatime,fmask=0077,dmask=0077> "
            "</dev/test-esp> </run/aos-boot-transaction-storage>", result.stdout,
        )
        self.assertIn(
            "mount <-t> <tmpfs> <-o> <mode=0700,nodev,nosuid,noexec> <tmpfs> "
            "</run/aos-boot-transaction-storage/aos/initrd-stage-journal/roots>",
            result.stdout,
        )
        self.assertEqual(result.stdout.count("mount <"), 2)

    def test_existing_esp_still_creates_roots_mount(self):
        result = self.run_script(ESP_MOUNTED="true")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("mount <"), 1)
        self.assertIn("mount <-t> <tmpfs>", result.stdout)

    def test_correct_existing_roots_mount_is_not_changed(self):
        result = self.run_script(ESP_MOUNTED="true", ROOTS_MOUNTED="true")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("mount <", result.stdout)
        self.assertNotIn("/roots>", result.stdout)

    def test_foreign_esp_is_rejected_without_changes(self):
        for overrides in ({"ESP_TYPE": "ext4"}, {"ESP_SOURCE": "/dev/foreign-esp"}):
            with self.subTest(overrides=overrides):
                result = self.run_script(ESP_MOUNTED="true", **overrides)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not a configured ESP", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_foreign_roots_filesystem_is_not_replaced(self):
        result = self.run_script(
            ESP_MOUNTED="true", ROOTS_MOUNTED="true", ROOTS_TYPE="ext4",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not private tmpfs", result.stderr)
        self.assertNotIn("mount <", result.stdout)

    def test_each_roots_mount_protection_is_required(self):
        for missing in ("rw", "nodev", "nosuid", "noexec"):
            with self.subTest(missing=missing):
                options = ",".join(
                    option for option in ("rw", "nodev", "nosuid", "noexec")
                    if option != missing
                )
                result = self.run_script(
                    ESP_MOUNTED="true", ROOTS_MOUNTED="true", ROOTS_OPTIONS=options,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("lacks " + missing, result.stderr)
                self.assertNotIn("mount <", result.stdout)

    def test_roots_ownership_and_mode_must_be_private(self):
        for metadata in ("0:0:755", "1:0:700", "0:1:700"):
            with self.subTest(metadata=metadata):
                result = self.run_script(
                    ESP_MOUNTED="true", ROOTS_MOUNTED="true", ROOTS_METADATA=metadata,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("mount <", result.stdout)

    def test_non_directory_roots_path_is_not_overwritten(self):
        for kind in ("symlink", "file"):
            with self.subTest(kind=kind):
                result = self.run_script(ESP_MOUNTED="true", ROOTS_KIND=kind)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not a real directory", result.stderr)
                self.assertNotIn("mount <", result.stdout)

    def test_roots_mount_failure_is_not_hidden(self):
        result = self.run_script(ROOTS_FAILURE="true")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("mount <"), 2)

    def test_existing_unmounted_roots_contents_are_not_hidden(self):
        with tempfile.TemporaryDirectory(prefix="transaction-roots-test-") as directory:
            roots = Path(directory) / "aos/initrd-stage-journal/roots"
            roots.mkdir(parents=True)
            foreign = roots / ".foreign"
            foreign.write_text("preserve this entry")

            result = self.run_script(ESP_MOUNTED="true", TARGET=directory)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to hide", result.stderr)
            self.assertNotIn("mount <", result.stdout)
            self.assertEqual(foreign.read_text(), "preserve this entry")

    def test_esp_mount_failure_does_not_create_roots_mount(self):
        result = self.run_script(ESP_FAILURE="true")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no configured EFI System Partition", result.stderr)
        self.assertNotIn("mount <-t> <tmpfs>", result.stdout)


unittest.main()
