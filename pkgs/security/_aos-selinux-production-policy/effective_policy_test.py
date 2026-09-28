"""Unit tests for effective AOS sandbox SELinux policy checks."""

from __future__ import annotations

import unittest
from dataclasses import dataclass, replace
from types import SimpleNamespace

import effective_policy


@dataclass(frozen=True)
class FakeAttribute:
    """Expands a source attribute without hiding its concrete members."""

    name: str
    members: tuple[str, ...]

    def expand(self) -> tuple[str, ...]:
        return self.members

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class FakeRule:
    """Supplies the rule surface consumed by the checker."""

    text: str
    active: bool = True
    default: str | None = None
    source: str | FakeAttribute = ""

    def enabled(self) -> bool:
        return self.active

    def __str__(self) -> str:
        return self.text


class FakePolicy:
    """Carries query results and per-domain permissive state."""

    def __init__(self) -> None:
        self.permissive: set[str] = set()
        self.queries: list[dict[str, object]] = []
        self.allows = {
            access: [FakeRule(f"allow {access}")]
            for access in effective_policy.POSITIVE_ACCESS
        }
        self.transitions = {
            transition: [
                FakeRule(
                    f"type_transition {transition}",
                    default=transition.default,
                )
            ]
            for transition in effective_policy.TRANSITIONS
        }

    def lookup_type(self, domain: str) -> SimpleNamespace:
        return SimpleNamespace(ispermissive=domain in self.permissive)


class FakeQuery:
    """Maps SETools-style query arguments back to fixture records."""

    def __init__(self, policy: FakePolicy, **criteria: object) -> None:
        self.policy = policy
        self.criteria = criteria
        self.policy.queries.append(criteria)

    def results(self) -> list[FakeRule]:
        if self.criteria["ruletype"] == ["allow"]:
            source = self.criteria.get("source")
            target = self.criteria.get("target")
            object_class = str(self.criteria["tclass"][0])
            permission = str(self.criteria["perms"][0])

            return [
                replace(rule, source=rule.source or access.source)
                for access, rules in self.policy.allows.items()
                if (source is None or access.source == str(source))
                and (target is None or access.target == str(target))
                and access.object_class == object_class
                and access.permission == permission
                for rule in rules
            ]

        if "default" in self.criteria:
            if "source" not in self.criteria:
                return [
                    rule
                    for transition, rules in self.policy.transitions.items()
                    if transition.default == str(self.criteria["default"])
                    and transition.object_class == str(self.criteria["tclass"][0])
                    for rule in rules
                ]
            transition = effective_policy.Transition(
                str(self.criteria["source"]),
                str(self.criteria["target"]),
                str(self.criteria["tclass"][0]),
                str(self.criteria["default"]),
            )
            return self.policy.transitions.get(transition, [])

        return [
            rule
            for transition, rules in self.policy.transitions.items()
            if transition.source == str(self.criteria["source"])
            and transition.target == str(self.criteria["target"])
            and transition.object_class == str(self.criteria["tclass"][0])
            for rule in rules
        ]


FAKE_SETOOLS = SimpleNamespace(
    TERuleQuery=FakeQuery,
    TERuletype=SimpleNamespace(allow="allow", type_transition="type_transition"),
)


class EffectivePolicyTest(unittest.TestCase):
    """Exercises positive, negative, conditional, and permissive gates."""

    def test_complete_matrix_passes(self) -> None:
        evidence = effective_policy.check_policy(FAKE_SETOOLS, FakePolicy())

        self.assertEqual(
            len(evidence),
            len(effective_policy.ENFORCING_DOMAINS)
            + len(effective_policy.TRANSITIONS)
            + len(effective_policy.owner_policy.NO_DEFAULT_ENTRY)
            + len(effective_policy.owner_policy.ROOT_CUSTODY_CUTS)
            + 1
            + len(effective_policy.FORBIDDEN_PROVISIONER_TRANSITION_SOURCES)
            + len(effective_policy.POSITIVE_ACCESS)
            + len(effective_policy.NEGATIVE_ACCESS),
        )

    def test_view_preparer_cannot_modify_generic_ancestry_or_foreign_target(self) -> None:
        for target, object_class, permission in (
            ("var_lib_t", "dir", "add_name"),
            ("aos_sandbox_view_parent_t", "dir", "write"),
            ("aos_sandbox_cache_view_mount_t", "dir", "mounton"),
            ("bin_t", "file", "execute_no_trans"),
            ("aos_sandbox_source_journal_t", "file", "open"),
        ):
            with self.subTest(target=target, permission=permission):
                policy = FakePolicy()
                access = effective_policy.Access(
                    "aos_sandbox_source_view_preparer_t", target, object_class, permission,
                )
                policy.allows[access] = [FakeRule("foreign preparation permission", active=False)]
                with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_static_view_provider_dac_search_never_opens_protected_data(self) -> None:
        for target in (
            "aos_sandbox_source_journal_t",
            "aos_sandbox_cache_journal_t",
            "aos_sandbox_cache_object_t",
            "aos_sandbox_source_signer_credential_t",
            "aos_sandbox_controller_credential_t",
            "aos_method46_storage_floor_t",
            "aos_method46_controller_lock_t",
        ):
            with self.subTest(target=target):
                policy = FakePolicy()
                access = effective_policy.Access(
                    "aos_sandbox_runtime_roots_t", target, "file", "open",
                )
                policy.allows[access] = [FakeRule("foreign protected data access", active=False)]
                with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_signer_has_no_write_capability_or_foreign_seed_fallback(self) -> None:
        for domain, target, object_class, permission in (
            ("aos_sandbox_source_signer_t", "aos_sandbox_source_journal_t", "file", "write"),
            ("aos_sandbox_cache_signer_t", "aos_sandbox_cache_signer_t", "capability", "dac_read_search"),
            ("init_t", "aos_sandbox_source_signer_credential_t", "file", "read"),
            ("aos_sandbox_controller_t", "aos_sandbox_cache_signer_credential_t", "file", "read"),
        ):
            with self.subTest(domain=domain, permission=permission):
                policy = FakePolicy()
                access = effective_policy.Access(domain, target, object_class, permission)
                policy.allows[access] = [FakeRule("signer authority widening")]
                with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_protected_association_is_a_required_object_to_superblock_grant(self) -> None:
        for object_type, filesystem in (
            ("aos_sandbox_source_journal_t", "fs_t"),
            ("aos_sandbox_cache_view_mount_t", "tmpfs_t"),
            ("aos_method46_tpm_device_t", "device_t"),
        ):
            with self.subTest(object_type=object_type):
                policy = FakePolicy()
                access = effective_policy.Access(object_type, filesystem, "filesystem", "associate")
                policy.allows[access] = []
                with self.assertRaisesRegex(ValueError, "missing effective allow"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_transition_fails(self) -> None:
        policy = FakePolicy()
        transition = effective_policy.TRANSITIONS[0]
        policy.transitions[transition] = []

        with self.assertRaisesRegex(ValueError, "missing effective transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_normal_owner_has_no_shared_elf_default_promotion(self) -> None:
        policy = FakePolicy()
        transition = effective_policy.Transition(
            "init_t", "aos_sandbox_policy_authority_exec_t", "process",
            "aos_sandbox_policy_authority_t",
        )
        policy.transitions[transition] = [
            FakeRule("automatic Root entry", default=transition.default),
        ]
        with self.assertRaisesRegex(ValueError, "automatic entry transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_unknown_role_cannot_capture_or_write_root_endpoint(self) -> None:
        for object_class, permission in (
            ("fd", "use"), ("unix_stream_socket", "write"),
            ("file", "read"), ("process", "ptrace"), ("process", "transition"),
        ):
            with self.subTest(object_class=object_class, permission=permission):
                policy = FakePolicy()
                access = effective_policy.Access(
                    "unlisted_actor_t", "aos_sandbox_policy_authority_t",
                    object_class, permission,
                )
                policy.allows[access] = [FakeRule("unknown foreign Root custody")]
                with self.assertRaisesRegex(ValueError, "foreign normal Root custody"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_source_attribute_and_inactive_foreign_root_grants_fail(self) -> None:
        for active in (False, True):
            with self.subTest(active=active):
                policy = FakePolicy()
                attribute = FakeAttribute(
                    "root_capture_attribute", ("init_t", "unlisted_actor_t"),
                )
                access = effective_policy.Access(
                    attribute.name, "aos_sandbox_policy_authority_t", "fd", "use",
                )
                policy.allows[access] = [FakeRule(
                    "attribute-expanded Root custody", active=active, source=attribute,
                )]
                with self.assertRaisesRegex(ValueError, "foreign normal Root custody"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_controller_connect_does_not_grant_root_endpoint_ownership(self) -> None:
        for object_class, permission in (
            ("fd", "use"), ("unix_stream_socket", "read"),
            ("unix_stream_socket", "write"),
        ):
            policy = FakePolicy()
            access = effective_policy.Access(
                "aos_sandbox_controller_t", "aos_sandbox_policy_authority_t",
                object_class, permission,
            )
            policy.allows[access] = [FakeRule("delegated Root accepted FD")]
            with self.assertRaisesRegex(ValueError, "foreign normal Root custody"):
                effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_helper_cannot_open_unlock_or_truncate_loaned_lock(self) -> None:
        for permission in ("open", "lock", "setattr"):
            policy = FakePolicy()
            access = effective_policy.Access(
                "aos_method46_controller_helper_t", "aos_method46_controller_lock_t",
                "file", permission,
            )
            policy.allows[access] = [FakeRule("lock pathname/unlock/truncate escape")]
            with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_helper_cannot_enter_other_owner_or_read_its_credentials(self) -> None:
        for access in (
            effective_policy.Access(
                "aos_sandbox_controller_t", "aos_method46_storage_helper_t",
                "process", "transition",
            ),
            effective_policy.Access(
                "aos_method46_storage_helper_t", "aos_sandbox_storage_credential_t",
                "file", "read",
            ),
            effective_policy.Access(
                "aos_method46_storage_helper_t", "aos_method46_storage_floor_t",
                "file", "read",
            ),
        ):
            policy = FakePolicy()
            policy.allows[access] = [FakeRule("crossed helper custody")]
            with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_owner_cannot_change_manager_or_policy_or_cgroup(self) -> None:
        for access in (
            effective_policy.Access(
                "aos_sandbox_controller_t", "init_t", "system", "reload",
            ),
            effective_policy.Access(
                "aos_sandbox_storage_t", "systemd_unit_file_t", "service", "start",
            ),
            effective_policy.Access(
                "aos_sandbox_policy_authority_t", "security_t", "security", "setenforce",
            ),
            effective_policy.Access(
                "aos_sandbox_controller_t", "cgroup_t", "file", "write",
            ),
            effective_policy.Access(
                "aos_sandbox_policy_authority_t", "aos_sandbox_policy_authority_t",
                "process", "ptrace",
            ),
        ):
            policy = FakePolicy()
            policy.allows[access] = [FakeRule("owner authority escape")]
            with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_nspawn_transition_fails(self) -> None:
        policy = FakePolicy()
        transition = next(
            transition
            for transition in effective_policy.TRANSITIONS
            if transition.default == "aos_nspawn_t"
        )
        policy.transitions[transition] = []

        with self.assertRaisesRegex(ValueError, "missing effective transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_host_payload_pidfd_access_fails(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            "aos_sandbox_host_t", "aos_sandbox_payload_t", "file", "ioctl"
        )
        policy.allows[access] = []

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_publisher_label_authority_fails(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            "aos_sandbox_guest_root_publisher_t", "aos_sandbox_payload_bootstrap_exec_t", "file", "relabelto"
        )
        policy.allows[access] = []

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_host_cannot_relabel_guest_executable(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            "aos_sandbox_host_t",
            "aos_sandbox_payload_systemd_exec_t",
            "file",
            "relabelto",
        )
        policy.allows[access] = [FakeRule("Host guest executable relabel")]

        with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_payload_sys_admin_allow_fails(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            "aos_sandbox_payload_t", "*", "capability", "sys_admin"
        )
        policy.allows[access] = [FakeRule("payload CAP_SYS_ADMIN allow")]

        with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_nspawn_cannot_execute_guest_init_without_transition(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            "aos_nspawn_t",
            "aos_sandbox_payload_bootstrap_exec_t",
            "file",
            "execute_no_trans",
        )
        policy.allows[access] = [FakeRule("nspawn guest init execute without transition")]

        with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_kernel_cannot_execute_init_guard_without_transition(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            "kernel_t", "init_exec_t", "file", "execute_no_trans"
        )
        policy.allows[access] = [
            FakeRule("allow files_unconfined_type file_type:file execute_no_trans")
        ]

        with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_nspawn_cannot_skip_bootstrap_for_guest_systemd(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            "aos_nspawn_t", "aos_sandbox_payload_systemd_exec_t", "file", "execute"
        )
        policy.allows[access] = [FakeRule("nspawn direct guest systemd execute")]

        with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_allow_fails(self) -> None:
        policy = FakePolicy()
        access = effective_policy.POSITIVE_ACCESS[0]
        policy.allows[access] = []

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_provisioner_transition_fails(self) -> None:
        policy = FakePolicy()
        transition = next(
            transition
            for transition in effective_policy.TRANSITIONS
            if transition.default == effective_policy.PROVISIONER_DOMAIN
        )
        policy.transitions[transition] = []

        with self.assertRaisesRegex(ValueError, "missing effective transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_alternate_init_transition_fails_even_when_inactive(self) -> None:
        policy = FakePolicy()
        expected = next(
            transition
            for transition in effective_policy.TRANSITIONS
            if transition.default == effective_policy.PROVISIONER_DOMAIN
        )
        alternate = effective_policy.Transition(
            expected.source,
            expected.target,
            expected.object_class,
            "init_t",
        )
        policy.transitions[alternate] = [
            FakeRule("conditional alternate transition", active=False, default="init_t")
        ]

        with self.assertRaisesRegex(ValueError, "alternate provisioner transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_runtime_role_provisioner_transition_fails(self) -> None:
        policy = FakePolicy()
        source = effective_policy.DOMAINS[0]
        forbidden = effective_policy.Transition(
            source,
            effective_policy.PROVISIONER_EXECUTABLE,
            "process",
            effective_policy.PROVISIONER_DOMAIN,
        )
        policy.transitions[forbidden] = [
            FakeRule(
                "runtime role provisioner transition",
                default=effective_policy.PROVISIONER_DOMAIN,
            )
        ]

        with self.assertRaisesRegex(ValueError, "runtime role can transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_queries_expand_attributes_and_leave_wildcard_targets_unbound(self) -> None:
        policy = FakePolicy()

        effective_policy.check_policy(FAKE_SETOOLS, policy)

        self.assertTrue(policy.queries)
        for criteria in policy.queries:
            self.assertIs(criteria.get("source_indirect"), True)
            if "target" in criteria:
                self.assertIs(criteria.get("target_indirect"), True)

        wildcard_queries = [
            criteria
            for criteria in policy.queries
            if criteria.get("ruletype") == ["allow"] and "target" not in criteria
        ]
        self.assertEqual(
            len(wildcard_queries),
            sum(access.target == "*" for access in effective_policy.NEGATIVE_ACCESS),
        )

    def test_inactive_positive_conditional_does_not_count(self) -> None:
        policy = FakePolicy()
        access = effective_policy.POSITIVE_ACCESS[0]
        policy.allows[access] = [FakeRule("conditional allow", active=False)]

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_inactive_negative_conditional_still_fails(self) -> None:
        policy = FakePolicy()
        access = effective_policy.NEGATIVE_ACCESS[0]
        policy.allows[access] = [FakeRule("conditional forbidden allow", active=False)]

        with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_permissive_domain_fails(self) -> None:
        policy = FakePolicy()
        policy.permissive.add("aos_sandbox_namespace_inspector_t")

        with self.assertRaisesRegex(ValueError, "protected domain is permissive"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_permissive_payload_domain_fails(self) -> None:
        policy = FakePolicy()
        policy.permissive.add("aos_sandbox_payload_t")

        with self.assertRaisesRegex(ValueError, "protected domain is permissive"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_permissive_init_domain_fails(self) -> None:
        policy = FakePolicy()
        policy.permissive.add("init_t")

        with self.assertRaisesRegex(ValueError, "protected domain is permissive: init_t"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)


if __name__ == "__main__":
    unittest.main()
