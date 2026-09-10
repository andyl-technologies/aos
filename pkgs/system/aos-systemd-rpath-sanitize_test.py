"""Source-level tests for systemd's post-scrub RPATH sanitizer."""

from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock


module_path = Path(__file__).with_name("aos-systemd-rpath-sanitize.py")
module_spec = importlib.util.spec_from_file_location("aos_systemd_rpath_sanitize", module_path)
assert module_spec is not None and module_spec.loader is not None
sanitizer = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(sanitizer)


class RpathSanitizerTests(unittest.TestCase):
    def make_roots(self, relative_rpaths: dict[str, str]):
        temporary = tempfile.TemporaryDirectory()
        base = Path(temporary.name)
        roots = {"out": base / "out", "tools": base / "tools"}
        for root in roots.values():
            root.mkdir()
        rpaths = {}
        for location, rpath in relative_rpaths.items():
            root_name, relative = location.split("/", 1)
            elf = roots[root_name] / relative
            elf.parent.mkdir(parents=True, exist_ok=True)
            elf.write_bytes(b"\x7fELFfixture")
            rpaths[elf] = rpath
        return temporary, roots, rpaths

    @staticmethod
    def fake_tool_output(rpaths):
        def output(_tool, option, elf, *_values):
            if option != "--print-rpath":
                raise AssertionError(f"unexpected option {option}")
            return rpaths[elf]

        return output

    def test_removes_only_reviewed_placeholders_and_preserves_order(self) -> None:
        real_a = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-a/lib"
        real_b = "/nix/store/11111111111111111111111111111111-b/lib"
        dummy = f"{sanitizer.DUMMY_STORE_PREFIX}json-c-0.18/lib"

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

    def test_rejects_empty_search_entry(self) -> None:
        with self.assertRaises(SystemExit):
            sanitizer.sanitize_rpath("/nix/store/safe/lib::/nix/store/also-safe/lib")

    def test_plans_both_named_roots_before_mutation(self) -> None:
        dummy = f"{sanitizer.DUMMY_STORE_PREFIX}json-c-0.18/lib"
        temporary, roots, rpaths = self.make_roots(
            {
                "out/bin/a": f"/nix/store/safe-a/lib:{dummy}",
                "tools/bin/b": f"/nix/store/safe-b/lib:{dummy}",
            }
        )
        self.addCleanup(temporary.cleanup)
        reviewed = frozenset({("out/bin/a", dummy), ("tools/bin/b", dummy)})

        with mock.patch.object(sanitizer, "REVIEWED_DUMMY_LOCATIONS", reviewed), mock.patch.object(
            sanitizer, "tool_output", side_effect=self.fake_tool_output(rpaths)
        ):
            plan = sanitizer.plan_sanitization(Path("patchelf"), roots)

        self.assertEqual([entry[0] for entry in plan], [roots["out"] / "bin/a", roots["tools"] / "bin/b"])

    def test_rejects_stale_missing_review_before_mutation(self) -> None:
        dummy = f"{sanitizer.DUMMY_STORE_PREFIX}json-c-0.18/lib"
        temporary, roots, rpaths = self.make_roots(
            {"out/bin/a": "/nix/store/safe-a/lib"}
        )
        self.addCleanup(temporary.cleanup)
        reviewed = frozenset({("out/bin/a", dummy)})

        with mock.patch.object(sanitizer, "REVIEWED_DUMMY_LOCATIONS", reviewed), mock.patch.object(
            sanitizer, "tool_output", side_effect=self.fake_tool_output(rpaths)
        ), mock.patch.object(sanitizer, "install_rpath") as install:
            with self.assertRaises(SystemExit):
                plan = sanitizer.plan_sanitization(Path("patchelf"), roots)
                sanitizer.apply_plan(Path("patchelf"), Path("readelf"), plan)

        install.assert_not_called()

    def test_rejects_placeholder_moved_to_other_output_or_elf(self) -> None:
        dummy = f"{sanitizer.DUMMY_STORE_PREFIX}json-c-0.18/lib"
        temporary, roots, rpaths = self.make_roots(
            {"tools/bin/moved": f"/nix/store/safe/lib:{dummy}"}
        )
        self.addCleanup(temporary.cleanup)
        reviewed = frozenset({("out/bin/reviewed", dummy)})

        with mock.patch.object(sanitizer, "REVIEWED_DUMMY_LOCATIONS", reviewed), mock.patch.object(
            sanitizer, "tool_output", side_effect=self.fake_tool_output(rpaths)
        ):
            with self.assertRaises(SystemExit):
                sanitizer.plan_sanitization(Path("patchelf"), roots)

    def test_rejects_incomplete_or_duplicate_root_plan(self) -> None:
        with self.assertRaises(SystemExit):
            sanitizer.plan_sanitization(Path("patchelf"), {"out": Path("out")})
        with self.assertRaises(SystemExit):
            sanitizer.parse_root("unknown=/tmp/root")

    def test_rechecks_every_planned_rpath_before_first_mutation(self) -> None:
        first = Path("/fixture/first")
        second = Path("/fixture/second")
        plan = [
            (first, "old-a", "new-a"),
            (second, "old-b", "new-b"),
        ]
        observed = {first: "old-a", second: "changed"}

        with mock.patch.object(
            sanitizer,
            "tool_output",
            side_effect=lambda _tool, _option, elf, *_values: observed[elf],
        ), mock.patch.object(sanitizer, "install_rpath") as install:
            with self.assertRaises(SystemExit):
                sanitizer.apply_plan(Path("patchelf"), Path("readelf"), plan)

        install.assert_not_called()


if __name__ == "__main__":
    unittest.main()
