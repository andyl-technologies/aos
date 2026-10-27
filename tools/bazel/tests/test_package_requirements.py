"""Exercises source-gate requirements against independently exported query fixtures."""

import copy
import unittest

from test_architecture_export import attribute, compilation, record, selected, source
from export_architecture import export
from verify_package_requirements import verify


class PackageRequirementsTests(unittest.TestCase):
    def graph(self):
        records = [
            source("protocol"), source("host"),
            compilation("protocol", deps=["@sdk//:lib"]),
            compilation("host", deps=["//crates/protocol:lib"]),
            compilation("host", target="test_library", deps=["@sdk//:lib"], testonly=True),
        ]
        return export(records, {"sdk": "libc"})

    def requirements(self, package="protocol", required=("libc",), forbidden=()):
        return {"schema_version": 1, "packages": {
            package: {"required": list(required), "forbidden": list(forbidden)},
        }}

    def test_checks_resolved_production_package_identity(self):
        result = verify(self.graph(), self.requirements())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["packages"]["protocol"]["production_dependencies"], ["libc"])

    def test_transitive_or_test_only_dependencies_do_not_satisfy_direct_requirement(self):
        with self.assertRaisesRegex(ValueError, "missing required production dependencies: libc"):
            verify(self.graph(), self.requirements(package="host"))

    def test_alias_and_platform_selector_branches_retain_forbidden_dependencies(self):
        records = [
            source("protocol"),
            record("//crates/protocol:platform_lib", "alias",
                   selected("actual", "LABEL", {"//conditions:default": "@sdk//:lib",
                                                "//platform:other": "@other//:lib"})),
            compilation("protocol", deps=["//crates/protocol:platform_lib"]),
        ]
        graph = export(records, {"sdk": "libc", "other": "banned"})
        with self.assertRaisesRegex(ValueError, "forbidden production dependencies: banned"):
            verify(graph, self.requirements(forbidden=("banned",)))

    def test_rejects_missing_unmodeled_and_duplicate_packages(self):
        variants = []
        missing = self.graph()
        missing["packages"] = [row for row in missing["packages"] if row["name"] != "protocol"]
        variants.append(("missing", missing))
        unmodeled = self.graph()
        next(row for row in unmodeled["packages"] if row["name"] == "protocol")["production_dependencies"] = None
        variants.append(("unmodeled", unmodeled))
        duplicate = self.graph()
        duplicate["packages"].append(copy.deepcopy(duplicate["packages"][0]))
        variants.append(("duplicate", duplicate))

        for name, graph in variants:
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify(graph, self.requirements())

    def test_rejects_inconsistent_summaries_targets_and_dependency_views(self):
        for field in ("production_dependencies", "production_targets"):
            graph = self.graph()
            next(row for row in graph["packages"] if row["name"] == "protocol")[field] = []
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify(graph, self.requirements())

        for field in ("target_dependencies", "dependency_targets", "compilation_targets"):
            graph = self.graph()
            graph[field].pop("//crates/protocol:lib")
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify(graph, self.requirements())

    def test_rejects_malformed_and_contradictory_requirements(self):
        bad = [None, {}, {"schema_version": 1, "packages": {}},
               self.requirements(required=("libc", "libc")),
               self.requirements(required=("libc",), forbidden=("libc",))]
        unknown = self.requirements()
        unknown["packages"]["protocol"]["require"] = ["libc"]
        bad.append(unknown)

        for requirements in bad:
            with self.subTest(requirements=requirements), self.assertRaises(ValueError):
                verify(self.graph(), requirements)


if __name__ == "__main__":
    unittest.main()
