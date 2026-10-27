"""Checks closed initializer rendering with the real libselinux path matcher.

These checks establish selection and label precision, not linked production
policy permissions, funded Source entry, or installed MAC qualification.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from context_plan import FileContextResolver, InodeKind
from coverage import read_expected


class InitialPolicyRenderingTest(unittest.TestCase):
    """Exercises every closed selection produced by the actual Nix renderer."""

    @classmethod
    def setUpClass(cls):
        cls.inputs = json.loads(Path(os.environ["AOS_METHOD46_INITIAL_POLICY_CASES"]).read_text())
        cls.library = Path(os.environ["AOS_SELINUX_FILE_CONTEXTS_LIBRARY"])

    def resolver(self, directory, case):
        path = directory / "initial.fc"
        path.write_text(case["fileContexts"])
        return FileContextResolver(self.library, path)

    def test_selection_and_package_roots_fail_closed(self):
        self.assertTrue(all(self.inputs["rejectedSelections"]))
        self.assertTrue(all(self.inputs["rejectedPackages"]))
        empty = self.inputs["cases"][0]
        self.assertEqual(empty["purposes"], [])
        self.assertEqual(empty["roles"], [])
        self.assertEqual(empty["moduleText"], "")
        self.assertEqual(empty["fileContexts"], "")
        self.assertEqual(empty, self.inputs["defaultUnselected"])

    def test_roster_matches_the_actual_startup_consumer(self):
        source = self.inputs["credentialSource"]
        roster = re.search(r"const NAMES: \[&str; 36\] = \[(.*?)\n\];", source, re.S)
        self.assertIsNotNone(roster)
        names = re.findall(r'"([a-z0-9-]+)"', roster[1])
        self.assertEqual(len(names), 36)
        self.assertEqual(len(set(names)), 36)
        for case in self.inputs["cases"]:
            self.assertEqual(case["credentials"], names)

    def test_selected_roles_use_the_actual_unit_and_helper_contexts(self):
        for case in self.inputs["cases"][1:]:
            self.assertNotIn("@", case["moduleText"])
            self.assertEqual(case["moduleText"].count("type aos_method46_initial_profile_t;"), 1)
            self.assertEqual([role["role"] for role in case["roles"]], case["purposes"])
            for role in case["roles"]:
                with self.subTest(purposes=case["purposes"], role=role["role"]):
                    self.assertIn(f'type {role["domain"]};', case["moduleText"])
                    self.assertIn(f'type {role["helper"]};', case["moduleText"])
                    self.assertIn(f'system_u:system_r:{role["helper"]}', self.inputs["helperSource"])
                    self.assertIn(f'system_u:object_r:{role["credential"]}', self.inputs["credentialSource"])
                    self.assertIn(role["service"], self.inputs["unitSource"])

    def test_rendered_roles_compile_with_the_selected_kernel_permissions(self):
        # External types here are unresolved requirements, not a fabricated
        # linked policy. This checks actual template syntax and kernel names;
        # the normal linked-policy checker still owns permission confinement.
        classmap = read_expected(Path(os.environ["AOS_SELINUX_KERNEL_CLASSMAP"]))
        classmap["dbus"] = ["send_msg"]
        classmap["service"] = ["status"]
        classmap["system"] = [*classmap["system"], "status"]
        for case in self.inputs["cases"][1:]:
            body = re.sub(r"#[^\n]*", "", case["moduleText"])
            body = re.sub(r"require\s*\{[^}]*\}", "", body)
            declarations = set(re.findall(r"^type ([a-z0-9_]+);", body, re.M))
            external_types = set(re.findall(r"\b[a-z][a-z0-9_]*_t\b", body)) - declarations
            classes = set(re.findall(r":([a-z][a-z0-9_]*)\b", body))
            requirements = [
                "role system_r;", "attribute domain;",
                "attribute aos_no_context_translation_domain;",
                "attribute aos_private_root_custody_domain;",
                *(f"type {name};" for name in sorted(external_types)),
                *(f"class {name} {{ {' '.join(classmap[name])} }};" for name in sorted(classes)),
            ]
            module = "module initial_fixture 1.0;\nrequire {\n" + "\n".join(requirements) + "\n}\n" + body
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "initial_fixture.te"
                source.write_text(module)
                result = subprocess.run(
                    [os.environ["AOS_METHOD46_CHECKMODULE"], "-m", "-o", str(root / "initial_fixture.mod"), str(source)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, f'{case["purposes"]}: {result.stderr}')

    def test_executable_labels_bind_exact_packages_and_inode_kinds(self):
        for case in self.inputs["cases"][1:]:
            with tempfile.TemporaryDirectory() as temporary:
                with self.resolver(Path(temporary), case) as resolver:
                    for role in ("controller", "storage"):
                        initial = f'aos-sandbox-{role}-floor-initialize'
                        helper = f'aos-method46-initial-{role}-tpm-helper'
                        entries = (
                            (self.inputs["initialPackage"], f"bin/{initial}", f"aos_method46_{role}_initial_exec_t"),
                            (self.inputs["helperPackage"], f"libexec/{helper}", f"aos_method46_initial_{role}_helper_exec_t"),
                        )
                        for package, suffix, label in entries:
                            selected = role in case["purposes"]
                            context = f"system_u:object_r:{label}" if selected else None
                            basename = Path(package).name
                            for root in ("/nix", "/nix.lower", "/usr/lib/aos/nix"):
                                path = f"{root}/store/{basename}/{suffix}"
                                with self.subTest(purposes=case["purposes"], path=path):
                                    self.assertEqual(resolver.lookup(path, InodeKind.regular), context)
                                    for kind in (InodeKind.directory, InodeKind.symlink, InodeKind.socket):
                                        self.assertIsNone(resolver.lookup(path, kind))
                                    for tail in ("0", ".foreign", "/child", ".sha256", ".loader"):
                                        self.assertIsNone(resolver.lookup(path + tail, InodeKind.regular))

                            sibling = ("1" if basename[0] == "0" else "0") + basename[1:]
                            version_sibling = (
                                basename.removesuffix("0.1.0") + "0.1.1"
                                if suffix.startswith("bin/")
                                else basename.removesuffix("-1") + "-2"
                            )
                            invalid = (
                                f"/nix/store/{sibling}/{suffix}",
                                f"/nix/store/{basename}-alias/{suffix}",
                                f"/tmp/store/{basename}/{suffix}",
                                f"/nix/lower/store/{basename}/{suffix}",
                                f"/nix/store/{version_sibling}/{suffix}",
                            )
                            for path in invalid:
                                self.assertIsNone(resolver.lookup(path, InodeKind.regular))

    def test_credential_labels_and_transitions_promote_only_literal_aliases(self):
        for case in self.inputs["cases"][1:]:
            with tempfile.TemporaryDirectory() as temporary:
                with self.resolver(Path(temporary), case) as resolver:
                    for role in ("controller", "storage"):
                        credential = f"aos_method46_{role}_initial_credential_t"
                        root = f"/run/credentials/aos-sandbox-{role}-floor-initialize.service"
                        selected = role in case["purposes"]
                        context = f"system_u:object_r:{credential}" if selected else None
                        self.assertEqual(resolver.lookup(root, InodeKind.directory), context)
                        self.assertIsNone(resolver.lookup(root, InodeKind.regular))
                        for name in case["credentials"]:
                            self.assertEqual(resolver.lookup(f"{root}/{name}", InodeKind.regular), context)
                            for kind in (InodeKind.directory, InodeKind.symlink, InodeKind.socket):
                                self.assertIsNone(resolver.lookup(f"{root}/{name}", kind))
                            for suffix in (".foreign", "/child"):
                                self.assertIsNone(resolver.lookup(f"{root}/{name}{suffix}", InodeKind.regular))
                            transition = f'type_transition init_t {credential}:file {credential} "{name}";'
                            self.assertEqual(case["moduleText"].count(transition), int(selected))

                        for name in ("private-signing-key", "foreign", "storage-broker-record-key"):
                            self.assertIsNone(resolver.lookup(f"{root}/{name}", InodeKind.regular))
                        default = f"type_transition init_t {credential}:file init_tmpfs_t;"
                        self.assertEqual(case["moduleText"].count(default), int(selected))

    def test_approval_socket_is_exact_and_role_local(self):
        for case in self.inputs["cases"][1:]:
            with tempfile.TemporaryDirectory() as temporary:
                with self.resolver(Path(temporary), case) as resolver:
                    for role in ("controller", "storage"):
                        path = f"/run/aos/sandbox/method46-{role}-initial.sock"
                        self.assertIn(path, self.inputs["approvalSource"])
                        selected = role in case["purposes"]
                        context = f"system_u:object_r:aos_method46_{role}_initial_approval_t" if selected else None
                        self.assertEqual(resolver.lookup(path, InodeKind.socket), context)
                        for kind in (InodeKind.regular, InodeKind.directory, InodeKind.symlink):
                            self.assertIsNone(resolver.lookup(path, kind))
                        for suffix in ("0", ".foreign", "/child"):
                            self.assertIsNone(resolver.lookup(path + suffix, InodeKind.socket))

    def test_profile_label_is_limited_to_the_versioned_delivered_files(self):
        context = "system_u:object_r:aos_method46_initial_profile_t"
        for case in self.inputs["cases"][1:]:
            with tempfile.TemporaryDirectory() as temporary:
                with self.resolver(Path(temporary), case) as resolver:
                    for root in ("/nix", "/nix.lower", "/usr/lib/aos/nix"):
                        package = f"{root}/store/{'0' * 32}-aos-method46-initial-startup-profile-3"
                        for name in ("profile.json", "source-policy.33", "effective-policy.tsv"):
                            path = f"{package}/{name}"
                            self.assertEqual(resolver.lookup(path, InodeKind.regular), context)
                            self.assertIsNone(resolver.lookup(path, InodeKind.symlink))
                            for suffix in ("0", ".foreign", "/child"):
                                self.assertIsNone(resolver.lookup(path + suffix, InodeKind.regular))
                            self.assertIsNone(resolver.lookup(path.replace("profile-3/", "profile-4/"), InodeKind.regular))
                        self.assertIsNone(resolver.lookup(package, InodeKind.directory))
                        self.assertIsNone(resolver.lookup(f"{package}/foreign", InodeKind.regular))


if __name__ == "__main__":
    unittest.main()
