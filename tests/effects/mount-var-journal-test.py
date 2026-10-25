"""Checks durable root-label visibility across actual ext4 journal recovery."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


TOOLS = Path(sys.argv[1]) / "sbin"
sys.argv = sys.argv[:1]
ROOT_LABEL = 'security.selinux (23) = "system_u:object_r:var_t"'


class RootLabelJournalTests(unittest.TestCase):
    def recover_root_label(self, committed):
        with tempfile.TemporaryDirectory(prefix="mount-var-journal-") as directory:
            root = Path(directory)
            image = root / "volume.ext4"
            with image.open("wb") as stream:
                stream.truncate(32 * 1024 * 1024)
            subprocess.run(
                [str(TOOLS / "mkfs.ext4"), "-q", "-F", "-b", "4096", str(image)],
                check=True, capture_output=True,
            )

            def debug(command):
                return subprocess.run(
                    [str(TOOLS / "debugfs"), "-w", "-R", command, str(image)],
                    check=True, capture_output=True, text=True,
                )

            mapping = debug("imap <2>").stdout
            match = re.search(r"located at block (\d+)", mapping)
            self.assertIsNotNone(match, mapping)
            block = int(match[1])
            with image.open("rb") as stream:
                stream.seek(block * 4096)
                original = stream.read(4096)

            # Capture a valid, checksummed inode block with the formatter's
            # exact label, then leave that update solely in the journal.
            debug("ea_set / security.selinux system_u:object_r:var_t")
            self.assertEqual(debug("ea_get / security.selinux").stdout.strip(), ROOT_LABEL)
            with image.open("r+b") as stream:
                stream.seek(block * 4096)
                labeled = stream.read(4096)
                stream.seek(block * 4096)
                stream.write(original)
            self.assertNotEqual(original, labeled)

            payload = root / "root-inode-block"
            payload.write_bytes(labeled)
            commands = root / "journal.commands"
            commit_flag = "" if committed else "-c "
            commands.write_text(
                "journal_open\n"
                f"journal_write {commit_flag}-b {block} {payload}\n"
                "journal_close\n"
            )
            subprocess.run(
                [str(TOOLS / "debugfs"), "-w", "-f", str(commands), str(image)],
                check=True, capture_output=True, text=True,
            )
            if not committed:
                debug("feature needs_recovery")
            self.assertIn("needs_recovery", debug("stats").stdout)
            self.assertEqual(debug("ea_get / security.selinux").stdout, "")

            recovery = subprocess.run(
                [str(TOOLS / "e2fsck"), "-p", "-E", "journal_only", str(image)],
                capture_output=True, text=True,
            )

            self.assertIn(recovery.returncode, (0, 1), recovery.stdout + recovery.stderr)
            self.assertNotIn("needs_recovery", debug("stats").stdout)
            return debug("ea_get / security.selinux").stdout.strip()

    def test_committed_label_is_visible_only_after_replay(self):
        self.assertEqual(self.recover_root_label(committed=True), ROOT_LABEL)

    def test_uncommitted_label_is_not_installed_by_replay(self):
        self.assertEqual(self.recover_root_label(committed=False), "")


unittest.main()
