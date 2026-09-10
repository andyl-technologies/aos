"""Source-level tests for device-mapper's post-scrub RPATH sanitizer."""

from pathlib import Path
import importlib.util
import unittest


module_path = Path(__file__).with_name("aos-device-mapper-rpath-sanitize.py")
module_spec = importlib.util.spec_from_file_location(
    "aos_device_mapper_rpath_sanitize", module_path
)
assert module_spec is not None and module_spec.loader is not None
sanitizer = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(sanitizer)


class RpathSanitizerTests(unittest.TestCase):
    def test_reviewed_inventory_is_exact(self) -> None:
        expected = {
            f"{sanitizer.DUMMY_STORE_PREFIX}libselinux-3.10/lib",
            f"{sanitizer.DUMMY_STORE_PREFIX}libsepol-3.10/lib",
            f"{sanitizer.DUMMY_STORE_PREFIX}pcre2-10.47/lib",
        }

        self.assertEqual(sanitizer.REVIEWED_DUMMY_RPATHS, expected)
        sanitizer.require_exact_review(expected)

    def test_removes_reviewed_placeholders_and_preserves_order(self) -> None:
        real_a = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-a/lib"
        real_b = "/nix/store/11111111111111111111111111111111-b/lib"
        dummy = f"{sanitizer.DUMMY_STORE_PREFIX}libselinux-3.10/lib"

        self.assertEqual(
            sanitizer.sanitize_rpath(f"{real_a}:{dummy}:{real_b}"),
            f"{real_a}:{real_b}",
        )

    def test_preserves_arbitrary_real_store_path(self) -> None:
        unreviewed = "/nix/store/22222222222222222222222222222222-unreviewed/lib"

        self.assertEqual(sanitizer.sanitize_rpath(unreviewed), unreviewed)

    def test_rejects_unreviewed_scrub_placeholder(self) -> None:
        unknown = f"{sanitizer.DUMMY_STORE_PREFIX}unknown-1/lib"

        with self.assertRaises(SystemExit):
            sanitizer.sanitize_rpath(unknown)

    def test_rejects_nearby_dependency_version(self) -> None:
        future = f"{sanitizer.DUMMY_STORE_PREFIX}pcre2-10.48/lib"

        with self.assertRaises(SystemExit):
            sanitizer.sanitize_rpath(future)

    def test_rejects_stale_reviewed_inventory(self) -> None:
        incomplete = set(sanitizer.REVIEWED_DUMMY_RPATHS)
        incomplete.remove(f"{sanitizer.DUMMY_STORE_PREFIX}libsepol-3.10/lib")

        with self.assertRaises(SystemExit):
            sanitizer.require_exact_review(incomplete)

    def test_rejects_empty_search_entry(self) -> None:
        with self.assertRaises(SystemExit):
            sanitizer.sanitize_rpath("/nix/store/safe/lib::/nix/store/also-safe/lib")


if __name__ == "__main__":
    unittest.main()
