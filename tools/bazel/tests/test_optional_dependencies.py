"""Checks optional dependency activation and precise generated-edge removal."""

import ast
import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).resolve().parents[1] / "metadata/optional_dependencies.py"
spec = importlib.util.spec_from_file_location("optional_dependencies", path)
dependencies = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dependencies)


class OptionalDependencyTests(unittest.TestCase):
    def test_target_defaults_and_empty_execution_features_keep_distinct_edges(self):
        manifest = {
            "dependencies": {name: {"optional": True} for name in ["allocator-api2", "equivalent", "foldhash"]},
            "features": {
                "default": ["default-hasher", "allocator-api2", "equivalent"],
                "default-hasher": ["dep:foldhash"],
            },
        }

        self.assertEqual(dependencies.inactive_optional_dependencies(manifest, ["default"]), set())
        self.assertEqual(dependencies.inactive_optional_dependencies(manifest, []),
                         {"allocator-api2", "equivalent", "foldhash"})

    def test_weak_dependency_features_do_not_activate_an_optional_dependency(self):
        manifest = {
            "dependencies": {"search": {"optional": True}},
            "features": {"std": ["search?/std"], "fast": ["dep:search"], "direct": ["search/fast"]},
        }

        self.assertEqual(dependencies.inactive_optional_dependencies(manifest, ["std"]), {"search"})
        for features in [["std", "fast"], ["direct"]]:
            with self.subTest(features=features):
                self.assertEqual(dependencies.inactive_optional_dependencies(manifest, features), set())

    def test_feature_cycles_terminate_and_explicit_dependencies_suppress_implicit_features(self):
        manifest = {
            "dependencies": {"renamed": {"package": "original", "optional": True}},
            "features": {"first": ["second"], "second": ["first", "dep:renamed"]},
        }

        self.assertEqual(dependencies.inactive_optional_dependencies(manifest, ["first"]), set())
        with self.assertRaisesRegex(ValueError, "unknown Cargo feature"):
            dependencies.inactive_optional_dependencies(manifest, ["renamed"])

    def test_platform_required_alias_and_build_dependencies_are_never_pruned(self):
        manifest = {
            "dependencies": {"portable": {"optional": True}},
            "target": {
                "cfg(unix)": {"dependencies": {"portable": "1", "native": {"optional": True}}},
            },
            "build-dependencies": {"generator": {"optional": True}},
            "dev-dependencies": {"fixture": {"optional": True}},
            "features": {"native": ["dep:native"]},
        }

        self.assertEqual(dependencies.inactive_optional_dependencies(manifest, []), {"native"})
        self.assertEqual(dependencies.inactive_optional_dependencies(manifest, ["native"]), set())

    def test_unknown_feature_and_dependency_references_fail_closed(self):
        for feature in ["unknown", "dep:unknown", "unknown/std", "unknown?/std", "known/"]:
            with self.subTest(feature=feature), self.assertRaises(ValueError):
                dependencies.inactive_optional_dependencies({"dependencies": {"known": "1"}}, [feature])

    def test_features_can_enable_a_build_dependency_without_pruning_its_edge(self):
        manifest = {
            "dependencies": {"runtime": {"optional": True}},
            "build-dependencies": {"generator": {"optional": True}},
            "features": {"generate": ["dep:generator", "generator/std"]},
        }

        self.assertEqual(dependencies.inactive_optional_dependencies(manifest, ["generate"]), {"runtime"})

    def test_pruning_keeps_build_script_edges_and_unrelated_strings(self):
        rendered = '''rust_library(
    name = "library",
    deps = ["@optional//:lib", "@required//:lib"] + select({
        "//platform:unix": ["@optional//:lib", "@native//:lib"],
        "//conditions:default": [],
    }),
    proc_macro_deps = ["@optional_macro//:macro", "@required_macro//:macro"],
    aliases = {"@optional//:lib": "renamed", "@required//:lib": "required"},
    rustc_env = {"LITERAL": "@optional//:lib"},
)
cargo_build_script(name = "script", deps = ["@optional//:lib"])
'''

        result = dependencies.prune_library_dependencies(rendered, {"@optional//:lib", "@optional_macro//:macro"})

        calls = [row.value for row in ast.parse(result).body]
        library = {keyword.arg: ast.literal_eval(keyword.value) for keyword in calls[0].keywords
                   if keyword.arg in {"aliases", "proc_macro_deps", "rustc_env"}}
        self.assertEqual(library["aliases"], {"@required//:lib": "required"})
        self.assertEqual(library["proc_macro_deps"], ["@required_macro//:macro"])
        self.assertEqual(library["rustc_env"], {"LITERAL": "@optional//:lib"})
        self.assertIn('deps = ["@required//:lib"] + select', result)
        self.assertIn('"//platform:unix": ["@native//:lib"]', result)
        self.assertIn('cargo_build_script(name = "script", deps = ["@optional//:lib"])', result)

    def test_absent_and_dynamic_edges_cannot_silently_satisfy_the_requested_pruning(self):
        for rendered in [
            'cargo_build_script(name = "script", deps = ["@optional//:lib"])',
            'rust_library(name = "lib", deps = helper("@optional//:lib"))',
            'rust_library(name = "lib", deps = ["@optional//:lib", dynamic_label])',
        ]:
            with self.subTest(rendered=rendered), self.assertRaises(ValueError):
                dependencies.prune_library_dependencies(rendered, {"@optional//:lib"})

    def test_empty_pruning_preserves_the_generated_file_bytes(self):
        rendered = 'rust_library(name = "lib", deps = ["@required//:lib"])  # retained\n'

        self.assertEqual(dependencies.prune_library_dependencies(rendered, set()), rendered)


if __name__ == "__main__":
    unittest.main()
