"""Regression tests for distinct method-46 journal and initial-intent custody."""

import json
import os
import unittest
from dataclasses import replace
from pathlib import Path

import effective_policy as checker
import effective_policy_test as fixture
import method46_policy
import coverage as policy_coverage
from context_plan import FileContextResolver, InodeKind


class JournalCustodyPolicyTest(unittest.TestCase):
    """Uses the existing checker and its expanded native-shaped rule fixture."""

    def check(self, policy):
        return checker.check_policy(fixture.FAKE_SETOOLS, policy)

    def test_normal_composition_and_closed_matrix_are_consistent(self):
        evidence = self.check(fixture.FakePolicy())
        self.assertFalse(set(checker.POSITIVE_ACCESS) & set(checker.NEGATIVE_ACCESS))
        for _, family, object_type, _ in method46_policy.CUSTODY_OBJECTS:
            self.assertIn(f"exclusive-method46-{family}-transitions\t{object_type}", evidence)

    def test_custody_queries_cover_the_selected_kernel_file_class(self):
        classmap = Path(os.environ["AOS_SELINUX_KERNEL_CLASSMAP"])
        file_permissions = policy_coverage.read_expected(classmap)["file"]
        checked = (*method46_policy.READ, *method46_policy.WRITE, "lock", *method46_policy.FORBIDDEN)
        self.assertEqual(len(checked), len(set(checked)))
        self.assertEqual(set(checked), set(file_permissions))

    def test_each_normal_writer_and_root_read_operation_is_required(self):
        required = [
            checker.Access(actor, main, "file", permission)
            for role, main in zip(method46_policy.ROLES, method46_policy.MAIN_TYPES)
            for permission in (*method46_policy.READ, *method46_policy.WRITE, "lock")
            for actor in method46_policy.main_sources(role, permission)
        ]
        for access in required:
            with self.subTest(access=access):
                policy = fixture.FakePolicy()
                del policy.allows[access]
                with self.assertRaisesRegex(ValueError, "missing effective allow"):
                    self.check(policy)

    def test_foreign_attribute_members_and_disabled_grants_are_rejected(self):
        for role, family, main, names in method46_policy.CUSTODY_OBJECTS:
            for permission in (*method46_policy.READ, *method46_policy.WRITE, "lock", *method46_policy.FORBIDDEN):
                with self.subTest(role=role, permission=permission):
                    policy = fixture.FakePolicy()
                    access = checker.Access("foreign_main_reader_t", main, "file", permission)
                    policy.allows[access] = [fixture.FakeRule(
                        "disabled expanded foreign main grant",
                        active=False,
                        source=fixture.FakeAttribute(
                            "mixed_main_actors",
                            (f"aos_sandbox_{role}_t", "foreign_main_reader_t"),
                        ),
                    )]
                    with self.assertRaisesRegex(ValueError, f"foreign method46 {family} custody"):
                        self.check(policy)

    def test_normal_owners_and_helpers_cannot_access_initial_intents(self):
        for role, intent in zip(method46_policy.ROLES, method46_policy.INTENT_TYPES):
            for actor in (f"aos_sandbox_{role}_t", f"aos_method46_{role}_helper_t"):
                for permission in (*method46_policy.READ, *method46_policy.WRITE, "lock"):
                    with self.subTest(role=role, actor=actor, permission=permission):
                        policy = fixture.FakePolicy()
                        access = checker.Access(actor, intent, "file", permission)
                        policy.allows[access] = [fixture.FakeRule(
                            "normal owner or helper inherited intent access",
                            source=fixture.FakeAttribute("intent_actor", (actor,)),
                        )]
                        with self.assertRaisesRegex(ValueError, "foreign method46 initial-intent custody"):
                            self.check(policy)

    def test_protected_types_cannot_inherit_broad_file_membership(self):
        for main in method46_policy.PROTECTED_TYPES:
            with self.subTest(main=main):
                policy = fixture.FakePolicy()
                policy.file_types.add(main)
                with self.assertRaisesRegex(ValueError, "protected object inherited broad file_type"):
                    self.check(policy)

    def test_protected_object_types_cannot_become_domains(self):
        for main in method46_policy.PROTECTED_TYPES:
            with self.subTest(main=main):
                policy = fixture.FakePolicy()
                policy.attributes["domain"].add(main)
                with self.assertRaisesRegex(ValueError, "method46 object inherited domain"):
                    self.check(policy)

    def test_only_own_parent_and_exact_names_promote_the_label(self):
        for role, family, main, names in method46_policy.CUSTODY_OBJECTS:
            owner = f"aos_sandbox_{role}_t"
            floor = f"aos_method46_{role}_floor_t"
            original = checker.Transition(owner, floor, "file", main, filename=names[0])
            for field, value in (
                ("source", fixture.FakeAttribute("mixed_sources", (owner, "foreign_main_writer_t"))),
                ("target", fixture.FakeTypeAttribute({floor, "var_lib_t"})),
                ("filename_value", None),
                ("filename_value", "session-floor.journal"),
                ("filename_value", "session.journal.lock"),
                ("filename_value", "session.journal.foreign"),
            ):
                with self.subTest(role=role, field=field, value=value):
                    policy = fixture.FakePolicy()
                    policy.transitions[original].append(replace(
                        policy.transitions[original][0], active=False, **{field: value},
                    ))
                    with self.assertRaisesRegex(ValueError, f"foreign method46 {family} label transition"):
                        self.check(policy)

    def test_each_literal_transition_is_required(self):
        for role, family, main, names in method46_policy.CUSTODY_OBJECTS:
            for name in names:
                with self.subTest(role=role, name=name):
                    policy = fixture.FakePolicy()
                    transition = checker.Transition(
                        f"aos_sandbox_{role}_t", f"aos_method46_{role}_floor_t",
                        "file", main, filename=name,
                    )
                    del policy.transitions[transition]
                    with self.assertRaisesRegex(ValueError, "missing effective transition"):
                        self.check(policy)

    def test_real_file_context_lookup_is_exact_and_preserves_other_history(self):
        support = Path(__file__).parent
        library = Path(os.environ["AOS_SELINUX_FILE_CONTEXTS_LIBRARY"])
        expectations = json.loads((support / "method46-main-contexts.json").read_text())
        with FileContextResolver(library, support / "aos_sandbox.fc") as resolver:
            for entry in expectations["entries"]:
                with self.subTest(path=entry["path"]):
                    self.assertEqual(
                        resolver.lookup(entry["path"], InodeKind.regular), entry["context"],
                    )
                    if not any(main in entry["context"] for main in method46_policy.PROTECTED_TYPES):
                        continue
                    for suffix in (".lock", ".foreign", ".compact.tmp.foreign", ".pending.foreign", "/child"):
                        self.assertNotEqual(
                            resolver.lookup(entry["path"] + suffix, InodeKind.regular),
                            entry["context"],
                        )
                    for kind in (InodeKind.directory, InodeKind.symlink, InodeKind.socket):
                        self.assertNotEqual(resolver.lookup(entry["path"], kind), entry["context"])


if __name__ == "__main__":
    unittest.main()
