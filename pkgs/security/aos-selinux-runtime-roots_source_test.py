"""Source-contract tests for the static SELinux runtime-root provisioner."""

from pathlib import Path
import re
import unittest


SOURCE = Path(__file__).with_name("aos-selinux-runtime-roots.c").read_text(
    encoding="utf-8"
)


def function(name: str) -> str:
    """Returns one C function body using brace depth, not a broad regex."""

    match = re.search(rf"^static [^\n]+\b{re.escape(name)}\([^;]*\) \{{", SOURCE, re.M)
    if match is None:
        raise AssertionError(f"missing function {name}")
    start = match.start()
    cursor = match.end()
    depth = 1
    while cursor < len(SOURCE) and depth:
        if SOURCE[cursor] == "{":
            depth += 1
        elif SOURCE[cursor] == "}":
            depth -= 1
        cursor += 1
    if depth:
        raise AssertionError(f"unterminated function {name}")
    return SOURCE[start:cursor]


class ExistingObjectAdmissionTests(unittest.TestCase):
    def test_rejects_wrong_owner_mode_device_mount_and_label(self) -> None:
        inspect = function("inspect_directory")

        for predicate in (
            "st.st_uid != 0",
            "st.st_gid != 0",
            "(st.st_mode & 07777) != spec->mode",
            "st.st_dev != expected_device",
            "mount_id != expected_mount_id",
            "strcmp(observed_context, spec->context) != 0",
        ):
            with self.subTest(predicate=predicate):
                self.assertIn(predicate, inspect)

    def test_rejects_symlinks_magiclinks_and_submounts(self) -> None:
        opening = function("open_or_create_directory")

        for resolver in (
            "RESOLVE_BENEATH",
            "RESOLVE_NO_MAGICLINKS",
            "RESOLVE_NO_SYMLINKS",
            "RESOLVE_NO_XDEV",
        ):
            with self.subTest(resolver=resolver):
                self.assertIn(resolver, opening)

    def test_rejects_idmapped_or_other_unexpected_mount_attributes(self) -> None:
        mount = function("verify_ext4_mount")

        self.assertIn(
            "response.status.mnt_attr != (MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)",
            mount,
        )
        self.assertIn("response.status.mnt_id != mount_id", mount)
        self.assertIn("response.status.sb_magic != EXT4_SUPER_MAGIC", mount)
        self.assertIn('strcmp(filesystem_type, "ext4") != 0', mount)

    def test_final_retained_fd_boundary_rechecks_mount_attributes(self) -> None:
        provision = function("provision")

        # Initial admission and each of the two successful phase exits check
        # the exact same retained mount identity and attribute set.
        self.assertEqual(provision.count("verify_ext4_mount(var_mount_id, var_st.st_dev)"), 3)


class PartialTopologyTests(unittest.TestCase):
    def test_preflight_precedes_first_network_topology_creation(self) -> None:
        provision = function("provision")

        preflight = provision.index("preflight_network_topology(")
        first_create = provision.index("aos_fd = open_or_create_directory(")
        self.assertLess(preflight, first_create)

    def test_existing_objects_are_never_repaired_relabelled_or_removed(self) -> None:
        forbidden = (
            r"\bchmod(at)?\s*\(",
            r"\bfchmod(at)?\s*\(",
            r"\bchown(at)?\s*\(",
            r"\bfchown(at)?\s*\(",
            r"\bsetxattr\s*\(",
            r"\bfsetxattr\s*\(",
            r"\bunlink(at)?\s*\(",
            r"\brmdir\s*\(",
            r"\brename(at2?)?\s*\(",
        )

        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, SOURCE))

    def test_racing_eexist_is_failure_not_adoption(self) -> None:
        create = function("create_directory")

        self.assertIn("saved_errno == EEXIST", create)
        self.assertIn("refusing the race", create)

    def test_partial_tree_rejects_unknown_and_legacy_entries(self) -> None:
        names = function("inspect_owned_names")
        preflight = function("preflight_network_topology")

        self.assertIn("migration required: legacy state entry", names)
        self.assertIn("corrupts the protected topology", names)
        self.assertIn("inspect_owned_names(network_fd", preflight)
        self.assertIn("inspect_owned_names(inspector_fd", preflight)


if __name__ == "__main__":
    unittest.main()
