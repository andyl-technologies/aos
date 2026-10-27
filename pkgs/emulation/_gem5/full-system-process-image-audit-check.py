# SPDX-License-Identifier: MIT
"""Rejects malformed asset scopes before the finite ARM mechanism audit."""

import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "crucible_arm_audit_policy", Path(__file__).with_name("full-system-process-image-audit.py"))
policy_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy_module)


class AssetPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.modeled = self.root / "resources"
        self.modeled.mkdir(mode=0o700)
        configurations = self.modeled / "configs"
        configurations.mkdir(mode=0o700)
        self.request = {
            "owned_root": str(self.root), "modeled_root": str(self.modeled), "assets": [],
            "model_scope": {
                "schema": "crucible.gem5.model-scope.v1",
                "model_id": "arm-linux-vexpress-atomic-functional-v1", "full_system": True,
                "complete_process_closure_qualified": False, "cpu_timing_qualified": False,
                "guest_readiness_qualified": False, "guest_assets": {},
                "configuration_tree": policy_module.asset_custody.configuration_tree(configurations),
            },
        }
        self.native_assets = {}
        for role, name in (("kernel", "kernel.elf"), ("initramfs", "initrd.img"),
                           ("firmware", "boot_v2.arm64")):
            path = self.modeled / name
            path.write_bytes(b"source-owned finite role")
            path.chmod(0o600)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            binding = {"bytes": str(path.stat().st_size), "sha256": digest}
            self.request["model_scope"]["guest_assets"][role] = binding
            self.request["assets"].append({"path": str(path), "sha256": digest})
            self.native_assets[str(path)] = binding

    def tearDown(self):
        self.temporary.cleanup()

    def policy(self):
        return policy_module.ArmFunctionalAssetPolicy(self.request)

    def mapping(self):
        return {"name": str(self.modeled / "kernel.elf"), "permissions": "r--s",
                "offset": 0, "start": 0, "end": os.sysconf("SC_PAGE_SIZE")}

    def test_exact_readonly_bounded_role(self):
        self.assertTrue(self.policy().accepts_map(self.mapping(), self.native_assets, str(self.root)))

    def test_qualification_cannot_be_promoted_by_input(self):
        for key in ("complete_process_closure_qualified", "cpu_timing_qualified",
                    "guest_readiness_qualified"):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.request)
                changed["model_scope"][key] = True
                with self.assertRaises(ValueError):
                    policy_module.ArmFunctionalAssetPolicy(changed)

    def test_unknown_or_incomplete_guest_roles(self):
        del self.request["model_scope"]["guest_assets"]["firmware"]
        with self.assertRaises(ValueError):
            self.policy()

    def test_duplicate_closure_asset(self):
        self.request["assets"].append(self.request["assets"][0])
        with self.assertRaises(ValueError):
            self.policy()

    def test_role_hash_cannot_differ_from_closure(self):
        self.request["assets"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.policy()

    def test_overlarge_declared_extent(self):
        self.request["model_scope"]["guest_assets"]["kernel"]["bytes"] = str(1024**3 + 1)
        with self.assertRaises(ValueError):
            self.policy()

    def test_group_readable_role_refused(self):
        (self.modeled / "kernel.elf").chmod(0o640)
        with self.assertRaises(ValueError):
            self.policy()

    def test_role_hardlink_refused(self):
        os.link(self.modeled / "kernel.elf", self.root / "alias")
        with self.assertRaises(ValueError):
            self.policy()

    def test_symbolic_role_refused(self):
        path = self.modeled / "kernel.elf"
        path.unlink()
        path.symlink_to(self.modeled / "initrd.img")
        with self.assertRaises(ValueError):
            self.policy()

    def test_configuration_change_refused(self):
        (self.modeled / "configs" / "changed.py").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.policy()

    def test_unapproved_mapping_name_refused(self):
        mapping = self.mapping()
        mapping["name"] = str(self.root / "unrelated-file")
        self.assertFalse(self.policy().accepts_map(mapping, self.native_assets, str(self.root)))

    def test_shared_writable_or_private_mapping_not_exempted(self):
        for permissions in ("rw-s", "r-xp", "r--p"):
            with self.subTest(permissions=permissions):
                mapping = self.mapping()
                mapping["permissions"] = permissions
                self.assertFalse(self.policy().accepts_map(mapping, self.native_assets, str(self.root)))

    def test_mapping_offset_and_extent_bounds(self):
        for offset, end in ((1, 4096), (-4096, 4096), (4096, 8192), (0, 8192), (0, 0)):
            with self.subTest(offset=offset, end=end):
                mapping = self.mapping()
                mapping.update(offset=offset, end=end)
                self.assertFalse(self.policy().accepts_map(mapping, self.native_assets, str(self.root)))


class PlaceholderTests(unittest.TestCase):
    def placeholder(self):
        return {"start": 0, "end": 8192, "permissions": "---p", "name": "",
                "offset": 0, "inode": 0, "device": [0, 0]}

    def file(self, start=0, end=4096):
        return {"original_map": {"start": start, "end": end, "permissions": "r--s",
                                 "name": "/private/boot_v2.arm64", "offset": 0,
                                 "inode": 17, "device": [0, 40]}}

    def test_coalesced_guard_keeps_its_anonymous_custody(self):
        original = self.placeholder()
        unchanged = copy.deepcopy(original)
        receipt = self.file()

        result = policy_module.core.retained_file_maps([original], [receipt])

        self.assertEqual(result, [receipt["original_map"], {**original, "start": 4096}])
        self.assertEqual(original, unchanged)

    def test_middle_file_preserves_both_guard_intervals(self):
        original = self.placeholder()
        receipt = self.file(4096, 6144)
        result = policy_module.core.retained_file_maps([original], [receipt])
        self.assertEqual(result, [{**original, "end": 4096}, receipt["original_map"],
                                  {**original, "start": 6144}])

    def test_overlapping_transform_receipts_refused(self):
        with self.assertRaises(ValueError):
            policy_module.core.retained_file_maps([self.placeholder()],
                                                  [self.file(), self.file(2048, 8192)])

    def test_absent_or_partial_placeholder_refused(self):
        for bounds in ((-4096, 4096), (4096, 12288), (4096, 4096)):
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                policy_module.core.retained_file_maps([self.placeholder()], [self.file(*bounds)])

    def test_external_or_writable_placeholder_refused(self):
        for key, value in (("permissions", "rw-p"), ("name", "/external"),
                           ("inode", 1), ("device", [0, 40]), ("offset", 4096)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                original = self.placeholder()
                original[key] = value
                policy_module.core.retained_file_maps([original], [self.file()])

    def test_ambiguous_placeholder_refused(self):
        with self.assertRaises(ValueError):
            policy_module.core.retained_file_maps([self.placeholder(), self.placeholder()], [self.file()])


if __name__ == "__main__":
    unittest.main()
