"""Unit tests for effective AOS sandbox SELinux policy checks."""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from types import SimpleNamespace

import effective_policy


@dataclass(frozen=True)
class FakeRule:
    """Supplies the rule surface consumed by the checker."""

    text: str
    active: bool = True
    default: str | None = None

    def enabled(self) -> bool:
        return self.active

    def __str__(self) -> str:
        return self.text


class FakePolicy:
    """Carries query results and per-domain permissive state."""

    def __init__(self) -> None:
        self.permissive: set[str] = set()
        self.file_types: set[str] = set()
        self.attributes = {
            "domain": set(effective_policy.ENFORCING_DOMAINS),
            effective_policy.EXPLICIT_LOADER_ATTRIBUTE: set(effective_policy.EXPLICIT_LOADER_DOMAINS),
            effective_policy.NO_CONTEXT_TRANSLATION_ATTRIBUTE: {
                effective_policy.fuse_worker_policy.WORKER_DOMAIN
            },
        }
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
            source = str(self.criteria["source"])
            target = self.criteria.get("target")
            object_class = str(self.criteria["tclass"][0])
            permission = str(self.criteria["perms"][0])

            return [
                rule
                for access, rules in self.policy.allows.items()
                if access.source == source
                and (target is None or access.target == str(target))
                and access.object_class == object_class
                and access.permission == permission
                for rule in rules
            ]

        if "default" in self.criteria:
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


class FakeTypeAttribute:
    """Exposes fixture attribute members to the effective-policy checker."""

    def __init__(self, members: set[str]) -> None:
        self.members = members

    def expand(self) -> set[str]:
        return self.members


class FakeTypeAttributeQuery:
    """Returns each declared fixture attribute."""

    def __init__(self, policy: FakePolicy, name: str) -> None:
        self.policy = policy
        self.name = name

    def results(self) -> list[FakeTypeAttribute]:
        if self.name == "file_type":
            return [FakeTypeAttribute(self.policy.file_types)]
        members = self.policy.attributes.get(self.name)
        return [FakeTypeAttribute(members)] if members is not None else []


FAKE_SETOOLS = SimpleNamespace(
    TERuleQuery=FakeQuery,
    TERuletype=SimpleNamespace(allow="allow", type_transition="type_transition"),
    TypeAttributeQuery=FakeTypeAttributeQuery,
)


class EffectivePolicyTest(unittest.TestCase):
    """Exercises positive, negative, conditional, and permissive gates."""

    def assert_missing_allow_rejected(self, access: effective_policy.Access) -> None:
        """Remove one required rule and require the linked-policy check to fail."""
        policy = FakePolicy()
        policy.allows[access] = []

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def assert_forbidden_allow_rejected(self, access: effective_policy.Access) -> None:
        """Add one forbidden rule and require the linked-policy check to fail."""
        policy = FakePolicy()
        policy.allows[access] = [FakeRule("unexpected effective allow")]

        with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_complete_matrix_passes(self) -> None:
        evidence = effective_policy.check_policy(FAKE_SETOOLS, FakePolicy())

        self.assertEqual(
            len(evidence),
            len(effective_policy.ENFORCING_DOMAINS)
            + len(effective_policy.TRANSITIONS)
            + 1
            + len(effective_policy.FORBIDDEN_PROVISIONER_TRANSITION_SOURCES)
            + len(effective_policy.GUARDED_OBJECT_TYPES)
            + 2 * sum(len(domains) for _, domains in effective_policy.EXPLICIT_DOMAIN_ATTRIBUTES)
            + len(effective_policy.POSITIVE_ACCESS)
            + len(effective_policy.NEGATIVE_ACCESS),
        )

    def test_explicit_loader_membership_is_exact_and_preserves_domains(self) -> None:
        marker = effective_policy.EXPLICIT_LOADER_ATTRIBUTE
        for domain in effective_policy.EXPLICIT_LOADER_DOMAINS:
            with self.subTest(domain=domain):
                policy = FakePolicy()
                policy.attributes[marker].remove(domain)
                with self.assertRaisesRegex(ValueError, f"unexpected {marker} membership"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

                policy = FakePolicy()
                policy.attributes["domain"].remove(domain)
                with self.assertRaisesRegex(ValueError, "lost domain membership"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

        policy = FakePolicy()
        policy.attributes[marker].add("init_t")
        with self.assertRaisesRegex(ValueError, f"unexpected {marker} membership"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

        policy = FakePolicy()
        del policy.attributes[marker]
        with self.assertRaisesRegex(ValueError, f"exactly one {marker} attribute"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_raw_worker_exclusion_preserves_ordinary_context_translation(self) -> None:
        marker = effective_policy.NO_CONTEXT_TRANSLATION_ATTRIBUTE
        worker = effective_policy.fuse_worker_policy.WORKER_DOMAIN
        policy = FakePolicy()
        policy.attributes[marker].clear()
        with self.assertRaisesRegex(ValueError, f"unexpected {marker} membership"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

        policy = FakePolicy()
        policy.attributes[marker].add(effective_policy.GUEST_OWNER)
        with self.assertRaisesRegex(ValueError, f"unexpected {marker} membership"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

        self.assert_missing_allow_rejected(
            effective_policy.Access("init_t", "setrans_runtime_t", "sock_file", "open")
        )
        for access in (
            effective_policy.Access(worker, "setrans_runtime_t", "sock_file", "open"),
            effective_policy.Access(worker, worker, "unix_stream_socket", "create"),
            effective_policy.Access(worker, "setrans_t", "unix_stream_socket", "connectto"),
        ):
            with self.subTest(access=access):
                self.assert_forbidden_allow_rejected(access)

    def test_loader_exclusion_preserves_ordinary_textrel_and_explicit_worker_loads(self) -> None:
        self.assert_missing_allow_rejected(
            effective_policy.Access("init_t", "textrel_shlib_t", "file", "execmod")
        )
        worker = effective_policy.fuse_worker_policy.WORKER_DOMAIN
        for object_type in ("lib_t", "ld_so_t"):
            for permission in ("read", "map", "execute"):
                with self.subTest(object_type=object_type, permission=permission):
                    self.assert_missing_allow_rejected(
                        effective_policy.Access(worker, object_type, "file", permission)
                    )

        self.assert_forbidden_allow_rejected(
            effective_policy.Access(worker, "textrel_shlib_t", "file", "execmod")
        )

    def test_protected_network_type_cannot_join_file_type(self) -> None:
        policy = FakePolicy()
        policy.file_types.add(effective_policy.PROTECTED_DIRECTORIES[0])

        with self.assertRaisesRegex(ValueError, "inherited broad file_type"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_worker_objects_cannot_inherit_generic_file_grants(self) -> None:
        for object_type in effective_policy.fuse_worker_policy.WORKER_OBJECT_TYPES:
            with self.subTest(object_type=object_type):
                policy = FakePolicy()
                policy.file_types.add(object_type)
                with self.assertRaisesRegex(ValueError, "inherited broad file_type"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_worker_requires_real_host_sid_read_and_original_object_labels(self) -> None:
        worker = effective_policy.fuse_worker_policy.WORKER_DOMAIN
        for access in (
            effective_policy.Access("aos_sandbox_host_t", worker, "process", "getattr"),
            effective_policy.Access(worker, "aos_filesystem_fuse_worker_plan_t", "file", "map"),
            effective_policy.Access(worker, "aos_filesystem_fuse_worker_channel_t", "unix_stream_socket", "write"),
            effective_policy.Access(worker, "aos_filesystem_fuse_worker_cancel_t", "fifo_file", "read"),
        ):
            with self.subTest(access=access):
                self.assert_missing_allow_rejected(access)

    def test_worker_requires_boot_id_read_without_sysctl_mutation(self) -> None:
        worker = effective_policy.fuse_worker_policy.WORKER_DOMAIN
        for access in (
            effective_policy.Access(worker, "sysctl_t", "dir", "search"),
            effective_policy.Access(worker, "sysctl_kernel_t", "dir", "search"),
            effective_policy.Access(worker, "sysctl_kernel_t", "file", "open"),
            effective_policy.Access(worker, "sysctl_kernel_t", "file", "read"),
        ):
            with self.subTest(access=access):
                self.assert_missing_allow_rejected(access)

        for access in (
            effective_policy.Access(worker, "sysctl_t", "dir", "write"),
            effective_policy.Access(worker, "sysctl_kernel_t", "dir", "add_name"),
            effective_policy.Access(worker, "sysctl_kernel_t", "file", "write"),
            effective_policy.Access(worker, "sysctl_kernel_t", "file", "setattr"),
        ):
            with self.subTest(access=access):
                self.assert_forbidden_allow_rejected(access)

    def test_worker_cannot_import_owner_authority_or_create_transport(self) -> None:
        worker = effective_policy.fuse_worker_policy.WORKER_DOMAIN
        for access in (
            effective_policy.Access(worker, "init_t", "file", "read"),
            effective_policy.Access(worker, "init_t", "unix_stream_socket", "read"),
            effective_policy.Access(worker, "init_t", "unix_stream_socket", "connectto"),
            effective_policy.Access(worker, worker, "unix_stream_socket", "create"),
            effective_policy.Access(worker, "fuse_device_t", "chr_file", "open"),
            effective_policy.Access(worker, "fuse_device_t", "chr_file", "ioctl"),
            effective_policy.Access(worker, "bin_t", "file", "execute"),
        ):
            with self.subTest(access=access):
                self.assert_forbidden_allow_rejected(access)

    def test_protected_network_type_requires_exact_fs_association(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            effective_policy.PROTECTED_DIRECTORIES[0],
            "fs_t",
            "filesystem",
            "associate",
        )
        policy.allows[access] = []

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_protected_network_type_cannot_associate_unrelated_filesystem(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            effective_policy.PROTECTED_DIRECTORIES[0],
            "tmpfs_t",
            "filesystem",
            "associate",
        )
        policy.allows[access] = [FakeRule("unexpected tmpfs association")]

        with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_transition_fails(self) -> None:
        policy = FakePolicy()
        transition = effective_policy.TRANSITIONS[0]
        policy.transitions[transition] = []

        with self.assertRaisesRegex(ValueError, "missing effective transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_network_services_require_exact_nnp_guard(self) -> None:
        for domain in effective_policy.NETWORK_SERVICE_DOMAINS:
            with self.subTest(domain=domain):
                self.assert_missing_allow_rejected(
                    effective_policy.Access(
                        "init_t", domain, "process2", "nnp_transition"
                    )
                )

    def test_inspector_requires_pid1_opened_descriptor_use(self) -> None:
        self.assert_missing_allow_rejected(
            effective_policy.Access(
                effective_policy.INSPECTOR_DOMAIN, "init_t", "fd", "use"
            )
        )

    def test_inspector_requires_exact_enforcement_read(self) -> None:
        for access in (
            effective_policy.Access(
                effective_policy.INSPECTOR_DOMAIN, "security_t", "dir", "search"
            ),
            *effective_policy.accesses(
                effective_policy.INSPECTOR_DOMAIN,
                "security_t",
                "file",
                ("getattr", "open", "read"),
            ),
        ):
            with self.subTest(access=access):
                self.assert_missing_allow_rejected(access)

    def test_inspector_enforcement_read_cannot_become_administration(self) -> None:
        for access in (
            *effective_policy.accesses(
                effective_policy.INSPECTOR_DOMAIN,
                "security_t",
                "file",
                effective_policy.RECORD_MUTATIONS,
            ),
            *effective_policy.accesses(
                effective_policy.INSPECTOR_DOMAIN,
                "security_t",
                "security",
                ("load_policy", "read_policy", "setbool", "setenforce", "setsecparam"),
            ),
            effective_policy.Access(
                effective_policy.INSPECTOR_DOMAIN, "security_t", "dir", "read"
            ),
        ):
            with self.subTest(access=access):
                self.assert_forbidden_allow_rejected(access)

    def test_inspector_requires_inherited_journal_write(self) -> None:
        self.assert_missing_allow_rejected(
            effective_policy.Access(
                effective_policy.INSPECTOR_DOMAIN, "init_t", "unix_stream_socket", "write"
            )
        )

    def test_inspector_journal_exception_cannot_admit_connections_or_reads(self) -> None:
        for access in (
            *effective_policy.accesses(
                effective_policy.INSPECTOR_DOMAIN,
                "init_t",
                "unix_stream_socket",
                ("connect", "connectto"),
            ),
            effective_policy.Access(
                effective_policy.INSPECTOR_DOMAIN, "init_t", "unix_stream_socket", "read"
            ),
            effective_policy.Access(
                effective_policy.INSPECTOR_DOMAIN, "tmpfs_t", "sock_file", "write"
            ),
        ):
            with self.subTest(access=access):
                self.assert_forbidden_allow_rejected(access)

    def test_only_pid1_can_enter_runtime_roots_handoff(self) -> None:
        for access in (
            effective_policy.Access(
                "init_t", effective_policy.HANDOFF_EXECUTABLE, "file", "execute_no_trans"
            ),
            effective_policy.Access(
                effective_policy.INSPECTOR_DOMAIN,
                effective_policy.HANDOFF_EXECUTABLE,
                "file",
                "execute",
            ),
            effective_policy.Access(
                effective_policy.INSPECTOR_DOMAIN,
                effective_policy.HANDOFF_DOMAIN,
                "process",
                "transition",
            ),
        ):
            with self.subTest(access=access):
                self.assert_forbidden_allow_rejected(access)

    def test_other_network_service_cannot_use_pid1_descriptors(self) -> None:
        self.assert_forbidden_allow_rejected(
            effective_policy.Access(
                effective_policy.NETWORK_SERVICE_DOMAINS[0], "init_t", "fd", "use"
            )
        )

    def test_network_service_cannot_gain_nosuid_transition(self) -> None:
        self.assert_forbidden_allow_rejected(
            effective_policy.Access(
                "init_t",
                effective_policy.NETWORK_SERVICE_DOMAINS[0],
                "process2",
                "nosuid_transition",
            )
        )

    def test_inspector_requires_own_elf_mapping(self) -> None:
        for permission in ("execute", "map", "read"):
            with self.subTest(permission=permission):
                self.assert_missing_allow_rejected(
                    effective_policy.Access(
                        effective_policy.INSPECTOR_DOMAIN,
                        effective_policy.INSPECTOR_EXECUTABLE,
                        "file",
                        permission,
                    )
                )

    def test_other_role_cannot_execute_inspector_elf(self) -> None:
        self.assert_forbidden_allow_rejected(
            effective_policy.Access(
                effective_policy.HANDOFF_DOMAIN,
                effective_policy.INSPECTOR_EXECUTABLE,
                "file",
                "execute",
            )
        )

    def test_unrelated_nnp_transition_fails(self) -> None:
        self.assert_forbidden_allow_rejected(
            effective_policy.Access(
                "init_t", "aos_sandbox_host_t", "process2", "nnp_transition"
            )
        )

    def test_non_init_nosuid_transition_to_network_service_fails(self) -> None:
        self.assert_forbidden_allow_rejected(
            effective_policy.Access(
                effective_policy.HANDOFF_DOMAIN,
                effective_policy.NETWORK_SERVICE_DOMAINS[0],
                "process2",
                "nosuid_transition",
            )
        )

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

    def test_missing_fresh_manager_projection_permission_fails(self) -> None:
        for object_class in ("dir", "file"):
            with self.subTest(object_class=object_class):
                policy = FakePolicy()
                access = effective_policy.Access(
                    effective_policy.GUEST_OWNER,
                    "init_runtime_t",
                    object_class,
                    "relabelfrom",
                )
                policy.allows[access] = []

                with self.assertRaisesRegex(ValueError, "missing effective allow"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_original_guest_host_channel_permission_fails(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            effective_policy.GUEST_OWNER,
            "aos_sandbox_host_t",
            "unix_stream_socket",
            "read",
        )
        policy.allows[access] = []

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_tenant_cannot_read_or_execute_generic_host_files(self) -> None:
        for permission in ("entrypoint", "execute", "execute_no_trans", "map", "open", "read"):
            with self.subTest(permission=permission):
                policy = FakePolicy()
                access = effective_policy.Access(
                    effective_policy.GUEST_TENANT, "file_type", "file", permission
                )
                policy.allows[access] = [FakeRule("generic host file access")]

                with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_tenant_data_execution_permission_fails(self) -> None:
        for target in ("aos_sandbox_guest_tenant_data_t", "aos_sandbox_guest_store_t"):
            with self.subTest(target=target):
                policy = FakePolicy()
                access = effective_policy.Access(
                    effective_policy.GUEST_TENANT, target, "file", "entrypoint"
                )
                policy.allows[access] = []

                with self.assertRaisesRegex(ValueError, "missing effective allow"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_uid_zero_cannot_bypass_guest_owner_objects(self) -> None:
        for access in (
            effective_policy.Access(effective_policy.GUEST_TENANT, effective_policy.GUEST_OWNER, "file", "read"),
            effective_policy.Access(effective_policy.GUEST_TENANT, "aos_sandbox_guest_store_t", "file", "write"),
            effective_policy.Access(effective_policy.GUEST_TENANT, "cgroup_t", "file", "write"),
            effective_policy.Access(effective_policy.GUEST_TENANT, effective_policy.GUEST_OWNER, "process2", "nnp_transition"),
            effective_policy.Access(effective_policy.GUEST_OWNER, "file_type", "file", "execute_no_trans"),
        ):
            with self.subTest(access=access):
                policy = FakePolicy()
                policy.allows[access] = [FakeRule("attribute-expanded unsafe Guest allow")]
                with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_missing_owner_tenant_nnp_transition_fails(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(effective_policy.GUEST_OWNER, effective_policy.GUEST_TENANT, "process2", "nnp_transition")
        policy.allows[access] = []

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_guest_marker_has_only_the_fixed_publisher_writer(self) -> None:
        for subject in ("init_t", "aos_sandbox_host_t", effective_policy.GUEST_OWNER):
            with self.subTest(subject=subject):
                policy = FakePolicy()
                access = effective_policy.Access(
                    subject, effective_policy.GUEST_PUBLICATION, "file", "write"
                )
                policy.allows[access] = [FakeRule("unsafe marker writer")]

                with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
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
