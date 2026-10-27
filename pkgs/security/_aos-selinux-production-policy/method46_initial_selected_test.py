"""Exercises immutable selected DATA and actual rendered initial TE modules.

The parent test starts a fresh interpreter beside each rendered DATA module.
The small native policy below contains the real rendered rules with unresolved
external principals declared as inert fixture types. It is not a production
policy, installed confinement proof, or provisioning authority.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import setools

import effective_policy as checker
import effective_policy_test as fixture
import method46_initial_policy as initial
import method46_policy as journal
from coverage import read_expected


class SelectedInitialPolicyTest(unittest.TestCase):
    """Uses the same effective checker for fixture and native observations."""

    @classmethod
    def setUpClass(cls):
        inputs = json.loads(Path(os.environ["AOS_METHOD46_INITIAL_POLICY_CASES"]).read_text())
        cls.case = next(case for case in inputs["cases"] if tuple(case["purposes"]) == initial.PURPOSES)

    def guarded_fixture(self):
        policy = fixture.FakePolicy()
        targets = {*initial.DOMAINS, *initial.OBJECT_TYPES}
        policy.allows = {access: rules for access, rules in policy.allows.items() if access.target in targets}
        return policy

    def test_selected_composition_passes_the_complete_existing_checker(self):
        self.assertFalse(set(checker.POSITIVE_ACCESS) & set(checker.NEGATIVE_ACCESS))
        evidence = checker.check_policy(fixture.FAKE_SETOOLS, fixture.FakePolicy())
        for domain in initial.DOMAINS:
            self.assertIn(f"enforcing\t{domain}", evidence)

    def test_object_permission_cuts_cover_the_selected_kernel_classes(self):
        classes = read_expected(Path(os.environ["AOS_SELINUX_KERNEL_CLASSMAP"]))
        for name, permissions in (
            ("file", initial.FILE), ("dir", initial.DIR),
            ("sock_file", initial.COMMON_FILE), ("unix_stream_socket", initial.STREAM),
            ("capability", initial.CAPABILITIES), ("capability2", initial.CAPABILITIES2),
            ("cap_userns", initial.CAPABILITIES), ("cap2_userns", initial.CAPABILITIES2),
        ):
            self.assertEqual(len(permissions), len(set(permissions)))
            self.assertEqual(set(permissions), set(classes[name]))

    def test_each_object_and_private_cut_rejects_disabled_foreign_attributes(self):
        for target, object_class, permission, permitted in (*initial.object_custody(), *initial.private_custody()):
            with self.subTest(target=target, object_class=object_class, permission=permission):
                policy = self.guarded_fixture()
                access = checker.Access("foreign_initial_actor_t", target, object_class, permission)
                policy.allows[access] = [fixture.FakeRule(
                    "disabled mixed initial custody grant", active=False,
                    source=fixture.FakeAttribute("mixed_initial_actors", (*sorted(permitted), "foreign_initial_actor_t")),
                )]
                with self.assertRaisesRegex(ValueError, "foreign method46 initial custody"):
                    checker._check_method46_initial_policy(fixture.FAKE_SETOOLS, policy)

    def test_unselected_principals_and_objects_are_absent(self):
        selected = {*initial.DOMAINS, *initial.OBJECT_TYPES}
        for name in (*initial.KNOWN_DOMAINS, *initial.KNOWN_OBJECT_TYPES):
            if name in selected:
                continue
            policy = fixture.FakePolicy()
            lookup = policy.lookup_type
            policy.lookup_type = lambda candidate: fixture.FakeType(name) if candidate == name else lookup(candidate)
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "unselected method46 initial type present"):
                    checker._check_method46_initial_policy(fixture.FAKE_SETOOLS, policy)

    def test_helper_and_credential_transitions_reject_foreign_expansion(self):
        for role in initial.PURPOSES:
            service = journal.initial_service(role)
            helper = journal.initial_helper(role)
            executable = f"aos_method46_initial_{role}_helper_exec_t"
            credential = initial.object_type(role, "credential")
            transitions = (
                checker.Transition(service, executable, "process", helper, filename=checker.Transition.UNNAMED),
                checker.Transition("init_t", credential, "file", credential, filename=journal.INITIAL_CREDENTIAL_NAMES[0]),
            )
            for transition in transitions:
                for field, value in (
                    ("source", fixture.FakeAttribute("mixed_initial_sources", (transition.source, "foreign_initial_actor_t"))),
                    ("target", fixture.FakeTypeAttribute({transition.target, "var_lib_t"})),
                ):
                    with self.subTest(transition=transition, field=field):
                        policy = self.guarded_fixture()
                        policy.transitions[transition].append(replace(
                            policy.transitions[transition][0], active=False, **{field: value},
                        ))
                        with self.assertRaisesRegex(ValueError, "foreign method46 initial .* transition"):
                            checker._check_method46_initial_policy(fixture.FAKE_SETOOLS, policy)
            original = transitions[1]
            for name in (None, "foreign", "broker-method46-tpm-index-auth-v1.foreign"):
                policy = self.guarded_fixture()
                policy.transitions[original].append(replace(
                    policy.transitions[original][0], active=False, filename_value=name,
                ))
                with self.assertRaisesRegex(ValueError, "foreign method46 initial credential transition"):
                    checker._check_method46_initial_policy(fixture.FAKE_SETOOLS, policy)

    def test_pidfd_cells_require_only_the_exact_get_info_selector(self):
        for source, target in initial.PIDFD_CELLS:
            access = checker.Access(source, target, "file", "ioctl")
            policy = self.guarded_fixture()
            policy.xperms[access].append(fixture.FakeXpermRule(
                "disabled additional selector", active=False, perms=frozenset({0xff0b, 0xffff}),
            ))
            with self.subTest(source=source, target=target):
                with self.assertRaisesRegex(ValueError, "forbidden method46 initial pidfs ioctl selectors"):
                    checker._check_method46_initial_policy(fixture.FAKE_SETOOLS, policy)

    def test_selected_services_cannot_inherit_other_endpoint_custody(self):
        for role in initial.PURPOSES:
            service = journal.initial_service(role)
            helper = journal.initial_helper(role)
            for endpoint in journal.ROLES:
                for family in ("main", "initial-intent"):
                    for permission in initial.FILE:
                        permitted = journal.custody_sources(endpoint, family, permission)
                        self.assertNotIn(helper, permitted)
                        if endpoint != role:
                            self.assertNotIn(service, permitted)
            for target in journal.PROTECTED_TYPES:
                for owner in (*checker.owner_policy.OWNER_DOMAINS, *checker.owner_policy.HELPER_DOMAINS):
                    if "initial_intent" in target:
                        for permission in initial.FILE:
                            self.assertIn(checker.Access(owner, target, "file", permission), checker.NEGATIVE_ACCESS)

    def test_actual_rendered_rules_obey_the_same_native_queries(self):
        if not initial.PURPOSES:
            return
        body = re.sub(r"#[^\n]*", "", self.case["moduleText"])
        body = re.sub(r"require\s*\{[^}]*\}", "", body)
        declared = set(re.findall(r"^type ([a-z0-9_]+);", body, re.M))
        actors = {*checker.DOMAINS, *checker.owner_policy.ENFORCING, "init_t", "kernel_t", "unconfined_t"}
        required = (set(re.findall(r"\b[a-z][a-z0-9_]*_t\b", body)) | actors) - declared
        classes = set(re.findall(r":([a-z][a-z0-9_]*)\b", body))
        positive, negative, transitions = initial.matrix(checker.Access, checker.Transition, checker.accesses, actors)
        classes.update(access.object_class for access in (*positive, *negative))
        classmap = read_expected(Path(os.environ["AOS_SELINUX_KERNEL_CLASSMAP"]))
        classmap.update(dbus=["send_msg"], service=["status"])
        classmap["system"] = [*classmap["system"], "status"]
        attributes = ("domain", "aos_no_context_translation_domain", "aos_private_root_custody_domain")
        source = "\n".join((
            *(f"class {name}" for name in sorted(classes)), "sid kernel",
            *(f"class {name} {{ {' '.join(classmap[name])} }}" for name in sorted(classes)),
            *(f"attribute {name};" for name in attributes),
            *(f"type {name};" for name in sorted(required)),
            "role system_r;", body,
            "role system_r types { " + " ".join(sorted(required | declared)) + " };",
            "user system_u roles system_r;", "sid kernel system_u:system_r:kernel_t",
        ))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "initial.conf"
            path.write_text(source)
            binary = root / "initial.policy"
            result = subprocess.run(
                [os.environ["AOS_METHOD46_CHECKPOLICY"], "-c", "33", "-U", "reject", "-o", str(binary), str(path)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            policy = setools.SELinuxPolicy(str(binary))
            checker._check_method46_initial_policy(setools, policy)
            for attribute in attributes:
                members = checker.attribute_members(setools, policy, attribute)
                self.assertEqual(members, set(initial.DOMAINS))
                self.assertFalse(members.intersection(initial.OBJECT_TYPES))
            for domain in initial.DOMAINS:
                self.assertFalse(policy.lookup_type(domain).ispermissive)
            main_positive, _, _ = journal.matrix(checker.Access, checker.Transition, checker.accesses, actors)
            positive.extend(access for access in main_positive if access.source in initial.DOMAINS)
            for domain, executable in initial.FIXED_ELF_ENTRIES:
                positive.extend(checker.accesses(domain, executable, "file", initial.ELF))
            for access in positive:
                self.assertTrue(checker.allow_rules(setools, policy, access), str(access))
            for access in negative:
                self.assertFalse(checker.allow_rules(setools, policy, access), str(access))
            for transition in transitions:
                self.assertTrue(checker.transition_rules(setools, policy, transition), str(transition))


if __name__ == "__main__":
    unittest.main()
