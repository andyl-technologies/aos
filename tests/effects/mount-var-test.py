"""Exercises the mount script's device selection and fail-closed checks."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BASH = sys.argv[1]
SCRIPT = str(Path(sys.argv[2]).resolve())
sys.argv = sys.argv[:1]

# Source the actual shell script with command mocks. Device existence is mocked
# at the shell test boundary, so production paths and selection stay unchanged.
HARNESS = r'''
set -euo pipefail
polls=0
function [ {
  if [[ "$#" == 3 && "$1" == -e ]]; then
    [[ "$polls" -ge "$TEST_DELAY" && " $TEST_DEVICES " == *" $2 "* ]]
  else
    builtin [ "$@"
  fi
}
mountpoint() { [[ "$TEST_MOUNTED" == true ]]; }
mkdir() { :; }
chmod() { :; }
ln() { :; }
sleep() { polls=$((polls + 1)); printf 'wait\n'; }
mount() { printf 'mount'; printf ' <%s>' "$@"; printf '\n'; }
source "$1"
printf 'polls=%s\n' "$polls"
'''


class MountVarTests(unittest.TestCase):
    def run_script(self, devices="", delay=0, filesystem="ext4", mounted=False,
                   zfs=False, blkid_status=0):
        with tempfile.TemporaryDirectory(prefix="mount-var-test-") as directory:
            root = Path(directory)
            tools = root / "util-linux"
            (tools / "sbin").mkdir(parents=True)
            probe = tools / "sbin/blkid"
            probe.write_text(
                f"#!{BASH}\n"
                'printf "%s\\n" "$@" > "$TEST_PROBE_LOG"\n'
                'printf "%s\\n" "$TEST_TYPE"\n'
                'exit "$TEST_BLKID_STATUS"\n'
            )
            probe.chmod(0o555)

            # Match the recipe's installation substitution. The probe exists
            # only in sbin and PATH is empty, exposing accidental bare calls.
            rendered = root / "mount-var"
            rendered.write_text(Path(SCRIPT).read_text().replace(
                "@util_linux@", str(tools)))
            probe_log = root / "probe-arguments"
            environment = dict(
                os.environ, PATH="", LC_ALL="C",
                AOS_ZFS_STATE=str(zfs).lower(), AOS_ZFS_POOL="tank",
                TEST_DEVICES=devices, TEST_DELAY=str(delay),
                TEST_TYPE=filesystem, TEST_MOUNTED=str(mounted).lower(),
                TEST_BLKID_STATUS=str(blkid_status),
                TEST_PROBE_LOG=str(probe_log),
            )
            result = subprocess.run(
                [BASH, "-c", HARNESS, "mount-var-test", str(rendered)],
                env=environment, capture_output=True, text=True,
            )
            self.probe_arguments = (
                probe_log.read_text().splitlines() if probe_log.exists() else []
            )
            return result

    def assert_device(self, result, device):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"mount <-o> <nosuid,nodev> <{device}> </sysroot/var>",
                      result.stdout)

    def test_mapper_precedes_array_and_partition(self):
        result = self.run_script("/dev/mapper/var /dev/md/var /dev/disk/by-partlabel/var")
        self.assert_device(result, "/dev/mapper/var")

    def test_array_precedes_member_partition(self):
        result = self.run_script("/dev/md/var /dev/disk/by-partlabel/var")
        self.assert_device(result, "/dev/md/var")

    def test_raw_partition_uses_gpt_label(self):
        self.assert_device(self.run_script("/dev/disk/by-partlabel/var"),
                           "/dev/disk/by-partlabel/var")

    def test_probe_resolves_sbin_without_environment_path(self):
        result = self.run_script("/dev/disk/by-partlabel/var")
        self.assert_device(result, "/dev/disk/by-partlabel/var")
        self.assertEqual(self.probe_arguments,
                         ["-p", "-s", "TYPE", "-o", "value",
                          "/dev/disk/by-partlabel/var"])

    def test_late_device_is_waited_for(self):
        result = self.run_script("/dev/disk/by-partlabel/var", delay=3)
        self.assert_device(result, "/dev/disk/by-partlabel/var")
        self.assertIn("polls=3", result.stdout)

    def test_missing_device_fails_after_bounded_wait(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no device carries the system-state volume", result.stderr)
        self.assertEqual(result.stdout.splitlines().count("wait"), 60)
        self.assertNotIn("mount <", result.stdout)

    def test_wrong_filesystem_fails_before_mount(self):
        result = self.run_script("/dev/md/var", filesystem="linux_raid_member")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected ext4", result.stderr)
        self.assertNotIn("mount <", result.stdout)

    def test_failed_probe_fails_before_mount(self):
        result = self.run_script("/dev/md/var", filesystem="", blkid_status=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("filesystem type none", result.stderr)
        self.assertNotIn("mount <", result.stdout)

    def test_existing_mount_is_not_remounted(self):
        result = self.run_script(mounted=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("mount <", result.stdout)

    def test_zfs_branch_keeps_all_dataset_mounts(self):
        result = self.run_script(zfs=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for dataset in ("tank/var", "tank/var/log", "tank/var/lib"):
            self.assertIn(f"<{dataset}>", result.stdout)
        self.assertEqual(result.stdout.count("mount <"), 3)


unittest.main()
