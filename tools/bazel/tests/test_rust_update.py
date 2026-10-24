"""Checks dependency-update integrity and ownership without network access."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


path = Path(__file__).resolve().parents[1] / "metadata/update_rust.py"
spec = importlib.util.spec_from_file_location("update_rust", path)
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class RustUpdateTests(unittest.TestCase):
    def test_overridden_alias_retains_license_scope_without_a_compilation_rule(self):
        rendered = 'alias(\n    name = "binding",\n    actual = "//binding:lib",\n    tags = ["manual"],\n)\n'
        crate = {"override_targets": {"lib": "//binding:lib"}}

        tagged = updater.add_license_tags(rendered, crate, "apache-host", "BUILD.binding.bazel")

        self.assertIn('"aos-license:apache-host"', tagged)
        self.assertIn('actual = "//binding:lib"', tagged)
        self.assertNotIn("rust_library(", tagged)
        with self.assertRaisesRegex(ValueError, "expected tag declarations"):
            updater.add_license_tags(rendered, {}, "apache-host", "BUILD.binding.bazel")
        with self.assertRaisesRegex(ValueError, "expected tag declarations"):
            updater.add_license_tags('alias(name = "binding")\n', crate, "apache-host", "BUILD.binding.bazel")

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.staged = self.root / "staged"
        self.staged.mkdir()
        self.output = self.root / "output"
        self.output.mkdir()

    def test_publication_preserves_unmanaged_files_and_removes_owned_obsolete_files(self):
        (self.output / "notes.txt").write_text("keep this\n")
        (self.output / "obsolete.bazel").write_text("old graph\n")
        (self.output / "sources.json").write_text(json.dumps({
            "schema_version": 1, "generated_files": {"obsolete.bazel": "old digest"},
        }))
        (self.staged / "BUILD.new.bazel").write_text("new graph\n")
        (self.staged / "sources.json").write_text("{}\n")

        updater.publish(self.staged, self.output)

        self.assertEqual((self.output / "notes.txt").read_text(), "keep this\n")
        self.assertEqual((self.output / "BUILD.new.bazel").read_text(), "new graph\n")
        self.assertFalse((self.output / "obsolete.bazel").exists())
        self.assertEqual(list(self.output.glob(".update-*")), [])

    def test_unmanaged_collision_and_unsafe_obsolete_paths_fail_before_writes(self):
        (self.output / "BUILD.new.bazel").write_text("human declaration\n")
        (self.staged / "BUILD.new.bazel").write_text("generated declaration\n")
        with self.assertRaisesRegex(ValueError, "unmanaged"):
            updater.publish(self.staged, self.output)
        self.assertEqual((self.output / "BUILD.new.bazel").read_text(), "human declaration\n")

        (self.output / "sources.json").write_text(json.dumps({
            "schema_version": 1, "generated_files": {"../outside": "digest"},
        }))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            updater.publish(self.staged, self.output)

    def test_boundary_sources_require_reviewed_original_license(self):
        specification = {
            "license_domain": "permissive-protocol",
            "approved_licenses": ["MIT OR Apache-2.0"],
        }
        crate = {"name": "example", "version": "1.0.0", "license": "MIT OR Apache-2.0"}
        self.assertEqual(updater.validate_license(specification, crate), "permissive-protocol")

        for license_expression in ["Apache-2.0", "GPL-3.0-only", "MIT OR Apache-2.0 OR unknown"]:
            with self.subTest(license=license_expression):
                crate["license"] = license_expression
                with self.assertRaisesRegex(ValueError, "unreviewed protocol dependency"):
                    updater.validate_license(specification, crate)

    def test_reviewed_host_only_license_never_inherits_protocol_scope(self):
        specification = {
            "license_domain": "permissive-protocol",
            "approved_licenses": ["MIT OR Apache-2.0"],
            "host_only_licenses": ["Apache-2.0"],
        }
        crate = {"name": "ciborium", "version": "0.2.2", "license": "Apache-2.0"}
        self.assertEqual(updater.validate_license(specification, crate), "apache-host")

        # A duplicate broad approval cannot weaken the explicit restriction.
        specification["approved_licenses"].append("Apache-2.0")
        self.assertEqual(updater.validate_license(specification, crate), "apache-host")

        crate["license"] = "unreviewed"
        with self.assertRaisesRegex(ValueError, "unreviewed protocol dependency"):
            updater.validate_license(specification, crate)

    def test_host_family_preserves_only_version_pinned_reviewed_protocol_crates(self):
        specification = {"license_domain": "apache-host", "permissive_crates": ["example@1.0.0"],
                         "approved_licenses": ["MIT"], "host_only_licenses": ["Apache-2.0"]}
        crate = {"name": "example", "version": "1.0.0", "license": "MIT"}
        self.assertEqual(updater.validate_license(specification, crate), "permissive-protocol")

        crate["version"] = "1.0.1"
        self.assertEqual(updater.validate_license(specification, crate), "apache-host")

        crate.update(version="1.0.0", license="unreviewed")
        with self.assertRaisesRegex(ValueError, "unreviewed protocol dependency"):
            updater.validate_license(specification, crate)

        crate["license"] = "Apache-2.0"
        specification["approved_licenses"].append("Apache-2.0")
        self.assertEqual(updater.validate_license(specification, crate), "apache-host")

    def test_unknown_permissive_crate_version_fails_before_publication(self):
        self.prepare_example("1.0.0")
        before = {path.name: path.read_bytes() for path in self.staged.iterdir()}
        with self.assertRaisesRegex(ValueError, "present in the resolved graph"):
            updater.prepare_sources({"license_domain": "apache-host", "permissive_crates": ["example@2.0.0"]},
                                    self.root, "example", self.staged)
        self.assertEqual({path.name: path.read_bytes() for path in self.staged.iterdir()}, before)

    def test_archive_must_match_both_resolved_locks(self):
        archive = self.root / "cargo-home/registry/cache/example/example-1.0.0.crate"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"source archive")
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "spliced").mkdir()
        (self.root / "spliced/Cargo.lock").write_text(
            'version = 4\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{checksum}"\n'
        )
        (self.root / "context.json").write_text(json.dumps({"crates": {"example": {
            "name": "example", "version": "1.0.0",
            "repository": {"Http": {"url": "https://static.crates.io/example.crate", "sha256": "wrong"}},
        }}}))

        with self.assertRaisesRegex(ValueError, "checksum disagrees"):
            updater.prepare_sources({"license_domain": "apache-host"}, self.root, "example", self.staged)

        self.assertEqual(list(self.staged.iterdir()), [])

    def prepare_example(self, version):
        archive = self.root / f"cargo-home/registry/cache/example/example-{version}.crate"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"source archive")
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "spliced").mkdir()
        (self.root / "spliced/Cargo.lock").write_text(
            f'version = 4\n[[package]]\nname = "example"\nversion = "{version}"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{checksum}"\n'
        )
        (self.root / "context.json").write_text(json.dumps({
            "crates": {"example": {
                "name": "example", "version": version, "license": "Apache-2.0",
                "library_target_name": "example",
                "repository": {"Http": {"url": "https://static.crates.io/example.crate", "sha256": checksum}},
            }},
            "direct_deps": ["example"],
        }))
        (self.root / "rendered").mkdir()
        (self.root / f"rendered/BUILD.example-{version}.bazel").write_text('rust_library(\n    tags = [\n    ],\n)\n')
        (self.root / "config.json").write_text("{}\n")
        specification = {"license_domain": "permissive-protocol", "host_only_licenses": ["Apache-2.0"]}

        return updater.prepare_sources(specification, self.root, "example", self.staged)

    def test_generated_rules_and_source_inventory_retain_host_only_scope(self):
        sources = self.prepare_example("1.0.0")

        self.assertEqual(sources["example__example-1.0.0"]["license_domain"], "apache-host")
        rendered = (self.staged / "BUILD.example-1.0.0.bazel").read_text()
        self.assertIn('"aos-license:apache-host"', rendered)
        self.assertNotIn('"aos-license:permissive-protocol"', rendered)

    def test_build_metadata_uses_the_rendered_repository_name_everywhere(self):
        sources = self.prepare_example("1.0.0+vendor.1")

        label = "example__example-1.0.0-vendor.1"
        self.assertEqual(list(sources), [label])
        self.assertEqual(sources[label]["strip_prefix"], "example-1.0.0+vendor.1")
        self.assertTrue((self.staged / "BUILD.example-1.0.0+vendor.1.bazel").is_file())
        self.assertIn(f'aos_crate(name = "{label}")', (self.staged / "repositories.MODULE.bazel").read_text())
        self.assertIn(f'@{label}//:example', (self.staged / "aliases.bzl").read_text())

    def alias_context(self):
        return {
            "direct_deps": ["one", "two"],
            "workspace_members": {"root": ""},
            "crates": {
                "one": {"name": "example", "version": "1", "library_target_name": "example"},
                "two": {"name": "example", "version": "2", "library_target_name": "example"},
                "root": {"common_attrs": {
                    "deps": {"common": [{"id": "one"}], "selects": {}},
                    "proc_macro_deps": {"common": [{"id": "two", "alias": "example_v2"}], "selects": {}},
                }},
            },
        }

    def test_direct_aliases_preserve_renamed_versions_and_macro_dependencies(self):
        aliases = updater.direct_aliases(self.alias_context(), "sdk")
        self.assertEqual(aliases, {
            "example": "@sdk__example-1//:example",
            "example_v2": "@sdk__example-2//:example",
        })

    def test_direct_aliases_reject_collisions_and_missing_root_edges(self):
        context = self.alias_context()
        context["crates"]["root"]["common_attrs"]["proc_macro_deps"]["common"][0].pop("alias")
        with self.assertRaisesRegex(ValueError, "ambiguous direct dependency alias"):
            updater.direct_aliases(context, "sdk")

        context = self.alias_context()
        context["crates"]["root"]["common_attrs"].pop("proc_macro_deps")
        with self.assertRaisesRegex(ValueError, "do not cover"):
            updater.direct_aliases(context, "sdk")

    def test_direct_aliases_retain_conditional_root_edges(self):
        context = self.alias_context()
        selection = context["crates"]["root"]["common_attrs"]["deps"]
        selection["selects"]["cfg(unix)"] = selection["common"]
        selection["common"] = []
        self.assertEqual(len(updater.direct_aliases(context, "sdk")), 2)

    def feature_graph(self):
        context = {"crates": {"libc": {
            "name": "libc", "version": "0.2.186", "library_target_name": "libc",
            "common_attrs": {"crate_features": {"common": ["default", "std"], "selects": {}}},
        }}}
        builds = {
            ("libc", "0.2.186"): '''package(default_visibility = ["//visibility:public"])
cargo_toml_env_vars(name = "env", src = "Cargo.toml")
rust_library(
    name = "libc",
    crate_features = ["default", "std"],
    deps = ["@example__libc-0.2.186//:build_script_build"],
    rustc_env_files = [":env"],
)
cargo_build_script(
    name = "_bs",
    crate_name = "build_script_build",
    crate_features = ["default", "std"],
)
alias(name = "build_script_build", actual = ":_bs")
''',
            ("jobserver", "0.1.34"): 'rust_library(name = "jobserver", deps = ["@example__libc-0.2.186//:libc"])\n',
            ("getrandom", "0.4.2"): 'rust_library(name = "getrandom", deps = ["@example__libc-0.2.186//:libc"])\n',
        }
        policy = {"feature_variants": {"libc": {
            "version": "0.2.186", "resolved_features": ["default", "std"], "features": [],
            "variants": {"build": {"features": ["default", "std"], "dependents": {"jobserver": "0.1.34"}}},
        }}}
        return policy, context, builds

    def test_feature_variants_keep_script_features_constant_and_preserve_crate_identity(self):
        policy, context, builds = self.feature_graph()

        result = updater.specialize_feature_graph(policy, context, builds, "example")

        libc = result["libc", "0.2.186"]
        base, variant = libc.split("# Reviewed Cargo feature unit: build")
        self.assertEqual(base.count("crate_features = []"), 2)
        self.assertEqual(variant.count('crate_features = ["default", "std"]'), 2)
        self.assertIn('crate_name = "libc"', variant)
        self.assertIn('"@example__libc-0.2.186//:build_script_build__aos_build"', variant)
        self.assertIn('actual = ":_bs__aos_build"', variant)
        self.assertIn('rustc_env_files = [":env"]', variant)
        self.assertNotIn("cargo_toml_env_vars(", variant)
        self.assertIn('//:libc__aos_build"', result["jobserver", "0.1.34"])
        self.assertNotIn("__aos_build", result["getrandom", "0.4.2"])

    def test_execution_units_select_complete_libraries_and_constant_script_features(self):
        policy, context, builds = self.feature_graph()
        settings = policy["feature_variants"]["libc"]
        settings.pop("variants")
        settings["exec_features"] = ["default", "std"]

        result = updater.specialize_feature_graph(policy, context, builds, "example")

        rendered = result["libc", "0.2.186"]
        self.assertEqual(rendered.count('cargo_toml_env_vars(name = "env"'), 1)
        self.assertEqual(rendered.count("crate_features = []"), 2)
        self.assertEqual(rendered.count('crate_features = ["default", "std"]'), 2)
        self.assertEqual(rendered.count('crate_name = "libc"'), 2)
        self.assertIn('"@example__libc-0.2.186//:build_script_build__aos_target"', rendered)
        self.assertIn('"@example__libc-0.2.186//:build_script_build__aos_exec"', rendered)
        self.assertIn('"@//tools/bazel/rules:exec_compilation": ":libc__aos_exec"', rendered)
        self.assertIn('"//conditions:default": ":libc__aos_target"', rendered)
        self.assertNotIn("crate_features = select", rendered)
        self.assertEqual(result["jobserver", "0.1.34"], builds["jobserver", "0.1.34"])

    def test_execution_units_reject_ambiguous_consumer_redirection(self):
        policy, context, builds = self.feature_graph()
        policy["feature_variants"]["libc"]["exec_features"] = ["default", "std"]

        with self.assertRaisesRegex(ValueError, "cannot also redirect"):
            updater.specialize_feature_graph(policy, context, builds, "example")

    def test_platform_feature_resolution_is_verified_before_specializing(self):
        policy, context, builds = self.feature_graph()
        settings = policy["feature_variants"]["libc"]
        settings.pop("variants")
        settings["resolved_selects"] = {"x86_64-unknown-linux-gnu": ["extra"]}
        settings["exec_features"] = ["default", "std", "extra"]
        context["crates"]["libc"]["common_attrs"]["crate_features"]["selects"] = settings["resolved_selects"]
        expression = '["default", "std"] + select({"@rules_rust//rust/platform:x86_64-unknown-linux-gnu": ["extra"], "//conditions:default": []})'
        builds["libc", "0.2.186"] = builds["libc", "0.2.186"].replace('["default", "std"]', expression)

        result = updater.specialize_feature_graph(policy, context, builds, "example")

        self.assertEqual(result["libc", "0.2.186"].count("crate_features = []"), 2)
        self.assertEqual(result["libc", "0.2.186"].count('crate_features = ["default", "std", "extra"]'), 2)
        changed = builds["libc", "0.2.186"].replace(': ["extra"]', ': ["unexpected"]')
        with self.assertRaisesRegex(ValueError, "reviewed resolution"):
            updater.specialize_feature_graph(policy, context, {**builds, ("libc", "0.2.186"): changed}, "example")

    def test_platform_feature_expressions_fail_closed(self):
        expressions = [
            '["std"] + select({"//conditions:default": ["extra"]})',
            '["std"] + select({"//unknown:platform": [], "//conditions:default": []})',
            '["std"] + discover_features()',
        ]
        for expression in expressions:
            with self.subTest(expression=expression), self.assertRaisesRegex(ValueError, "feature"):
                updater.rendered_features(__import__("ast").parse(expression, mode="eval").body)

    def test_feature_policy_rejects_changed_versions_features_and_edges(self):
        for mutation in ["version", "features", "selects", "rendered", "consumer", "edge"]:
            with self.subTest(mutation=mutation):
                policy, context, builds = self.feature_graph()
                if mutation == "version":
                    policy["feature_variants"]["libc"]["version"] = "0.2.187"
                elif mutation == "features":
                    context["crates"]["libc"]["common_attrs"]["crate_features"]["common"].append("extra")
                elif mutation == "selects":
                    context["crates"]["libc"]["common_attrs"]["crate_features"]["selects"] = {"linux": ["std"]}
                elif mutation == "rendered":
                    builds["libc", "0.2.186"] = builds["libc", "0.2.186"].replace('["default", "std"]', '["std"]')
                elif mutation == "consumer":
                    del builds["jobserver", "0.1.34"]
                else:
                    builds["jobserver", "0.1.34"] = 'rust_library(name = "jobserver")'
                with self.assertRaisesRegex(ValueError, "reviewed"):
                    updater.specialize_feature_graph(policy, context, builds, "example")


if __name__ == "__main__":
    unittest.main()
