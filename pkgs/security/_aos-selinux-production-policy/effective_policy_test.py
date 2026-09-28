"""Unit tests for effective AOS sandbox SELinux policy checks."""

from __future__ import annotations

import unittest
from dataclasses import dataclass, replace
from pathlib import Path
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
    target: FakeTypeAttribute | None = None
    source: FakeType | FakeTypeAttribute | FakeAttribute | None = None

    def enabled(self) -> bool:
        return self.active

    def __str__(self) -> str:
        return self.text


class FakePolicy:
    """Carries query results and per-domain permissive state."""

    def __init__(self) -> None:
        self.permissive: set[str] = set()
        self.file_types = (
            set(effective_policy.guest_file_policy.OWNER_CONTROL_READ_TYPES) | {"var_t"}
        )
        self.attributes = {
            "domain": set(effective_policy.ENFORCING_DOMAINS),
            effective_policy.EXPLICIT_LOADER_ATTRIBUTE: set(effective_policy.EXPLICIT_LOADER_DOMAINS),
            effective_policy.NO_CONTEXT_TRANSLATION_ATTRIBUTE: set(
                effective_policy.NO_CONTEXT_TRANSLATION_DOMAINS
            ),
            effective_policy.PRIVATE_ROOT_CUSTODY_ATTRIBUTE: {
                "aos_sandbox_policy_authority_t"
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

    def lookup_type(self, domain: str) -> FakeType:
        return FakeType(domain, domain in self.permissive)


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

            target_members = (
                self.policy.file_types if target == "file_type" else {str(target)}
            )
            matches = []
            for access, rules in self.policy.allows.items():
                if (
                    access.object_class != object_class
                    or access.permission != permission
                ):
                    continue
                for rule in rules:
                    concrete_source = rule.source or FakeType(access.source)
                    sources = (
                        concrete_source.expand()
                        if hasattr(concrete_source, "expand")
                        else {str(concrete_source)}
                    )
                    concrete_target = rule.target or FakeTypeAttribute(
                        self.policy.file_types
                        if access.target == "file_type"
                        else {access.target}
                    )
                    if source is not None and str(source) not in sources:
                        continue
                    if target is not None and not target_members.intersection(
                        concrete_target.expand()
                    ):
                        continue
                    matches.append(replace(
                        rule, source=concrete_source, target=concrete_target,
                    ))

            return matches

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


class FakeTypeAttribute:
    """Exposes fixture attribute members to the effective-policy checker."""

    def __init__(self, members: set[str]) -> None:
        self.members = members

    def expand(self) -> set[str]:
        return self.members


@dataclass(frozen=True)
class FakeType:
    """Exposes a canonical fixture type and its enforcing state."""

    name: str
    ispermissive: bool = False

    def __str__(self) -> str:
        return self.name


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
            + len(effective_policy.owner_policy.NO_DEFAULT_ENTRY)
            + len(effective_policy.owner_policy.ROOT_CUSTODY_CUTS)
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

    def test_raw_clients_exclusion_preserves_ordinary_context_translation(self) -> None:
        marker = effective_policy.NO_CONTEXT_TRANSLATION_ATTRIBUTE
        worker = effective_policy.fuse_worker_policy.WORKER_DOMAIN
        self.assertEqual(
            set(effective_policy.NO_CONTEXT_TRANSLATION_DOMAINS),
            {
                worker,
                "aos_method46_controller_helper_t",
                "aos_method46_storage_helper_t",
                "aos_sandbox_cache_signer_t",
                "aos_sandbox_source_signer_t",
            },
        )
        self.assertEqual(
            set(effective_policy.NO_CONTEXT_TRANSLATION_DOMAINS),
            {
                access.source for access in effective_policy.NEGATIVE_ACCESS
                if access.target == "*"
                and access.object_class == "unix_stream_socket"
                and access.permission == "connect"
            },
        )

        for domain in effective_policy.NO_CONTEXT_TRANSLATION_DOMAINS:
            with self.subTest(domain=domain):
                policy = FakePolicy()
                policy.attributes[marker].remove(domain)
                with self.assertRaisesRegex(ValueError, f"unexpected {marker} membership"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

                policy = FakePolicy()
                policy.attributes["domain"].remove(domain)
                with self.assertRaisesRegex(ValueError, "lost domain membership"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

        for ordinary in (
            "init_t", effective_policy.GUEST_OWNER, "aos_sandbox_controller_t",
            "aos_sandbox_policy_authority_t", "aos_sandbox_source_view_preparer_t",
            "aos_sandbox_cache_view_preparer_t",
        ):
            with self.subTest(ordinary=ordinary):
                policy = FakePolicy()
                policy.attributes[marker].add(ordinary)
                with self.assertRaisesRegex(ValueError, f"unexpected {marker} membership"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

        policy = FakePolicy()
        del policy.attributes[marker]
        with self.assertRaisesRegex(ValueError, f"exactly one {marker} attribute"):
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

    def test_helper_inherited_channels_remain_required(self) -> None:
        for role, helper in zip(
            effective_policy.owner_policy.HELPERS, effective_policy.owner_policy.HELPER_DOMAINS,
        ):
            owner = f"aos_sandbox_{role}_t"
            for permission in ("getattr", "getopt", "read", "setopt", "write"):
                with self.subTest(helper=helper, permission=permission):
                    self.assert_missing_allow_rejected(
                        effective_policy.Access(helper, owner, "unix_stream_socket", permission)
                    )

    def test_signer_inherited_listener_channels_remain_required(self) -> None:
        for signer in effective_policy.view_policy.SIGNER_DOMAINS:
            for permission in ("bind", "create", "getattr", "getopt", "listen", "setopt"):
                with self.subTest(signer=signer, permission=permission):
                    self.assert_missing_allow_rejected(
                        effective_policy.Access("init_t", signer, "unix_stream_socket", permission)
                    )

            self.assert_missing_allow_rejected(
                effective_policy.Access(
                    "aos_sandbox_policy_authority_t", signer, "unix_stream_socket", "connectto",
                )
            )

        self.assert_missing_allow_rejected(
            effective_policy.Access(
                "aos_sandbox_controller_t", "aos_sandbox_cache_signer_t",
                "unix_stream_socket", "connectto",
            )
        )

    def test_disabled_indirect_raw_client_socket_grant_is_forbidden(self) -> None:
        members = (*effective_policy.NO_CONTEXT_TRANSLATION_DOMAINS, "init_t")
        for client in effective_policy.NO_CONTEXT_TRANSLATION_DOMAINS:
            for permission in ("connect", "connectto", "create", "listen"):
                with self.subTest(client=client, permission=permission):
                    policy = FakePolicy()
                    # Both axes retain an ordinary member. Default-off grants
                    # remain forbidden even though no positive rule uses them.
                    access = effective_policy.Access(
                        "indirect_clients", "indirect_channels", "unix_stream_socket", permission,
                    )
                    policy.allows[access] = [FakeRule(
                        "disabled indirect raw-client socket grant", active=False,
                        source=FakeAttribute("indirect_clients", (client, "init_t")),
                        target=FakeTypeAttribute(set(members)),
                    )]
                    with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                        effective_policy.check_policy(FAKE_SETOOLS, policy)

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

    def test_host_requires_worker_image_inspection_without_execution_or_mutation(self) -> None:
        executable = effective_policy.fuse_worker_policy.WORKER_EXECUTABLE
        for permission in ("getattr", "open", "read"):
            with self.subTest(missing_permission=permission):
                self.assert_missing_allow_rejected(
                    effective_policy.Access("aos_sandbox_host_t", executable, "file", permission)
                )

        for permission in (
            "append", "create", "execute", "execute_no_trans", "execmod", "ioctl",
            "link", "map", "relabelfrom", "relabelto", "rename", "setattr", "unlink", "write",
        ):
            with self.subTest(forbidden_permission=permission):
                self.assert_forbidden_allow_rejected(
                    effective_policy.Access("aos_sandbox_host_t", executable, "file", permission)
                )

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

    def test_view_provider_entry_preserves_closed_boot_handoff(self) -> None:
        cache_preparer = "aos_sandbox_cache_view_preparer_t"
        for source in (effective_policy.HANDOFF_DOMAIN, cache_preparer):
            self.assertIn(
                effective_policy.Transition(
                    source,
                    effective_policy.PROVISIONER_EXECUTABLE,
                    "process",
                    effective_policy.PROVISIONER_DOMAIN,
                ),
                effective_policy.TRANSITIONS,
            )

        self.assertIn("init_t", effective_policy.FORBIDDEN_PROVISIONER_TRANSITION_SOURCES)
        self.assertNotIn(cache_preparer, effective_policy.FORBIDDEN_PROVISIONER_TRANSITION_SOURCES)
        self.assertIn(cache_preparer, effective_policy.owner_policy.NO_DEFAULT_ENTRY)
        self.assertNotIn(effective_policy.PROVISIONER_DOMAIN, effective_policy.owner_policy.NO_DEFAULT_ENTRY)
        self.assertNotIn(
            (effective_policy.PROVISIONER_DOMAIN, effective_policy.PROVISIONER_EXECUTABLE),
            effective_policy.DOMAIN_EXECUTABLES,
        )

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

    def test_root_custody_marker_is_exact_and_preserves_domain_membership(self) -> None:
        marker = effective_policy.PRIVATE_ROOT_CUSTODY_ATTRIBUTE
        root = "aos_sandbox_policy_authority_t"
        source = Path(__file__).with_name("owner_confinement.te").read_text()
        memberships = [
            line for line in source.splitlines()
            if line.startswith("typeattribute ") and line.endswith(f" {marker};")
        ]
        self.assertEqual(memberships, [f"typeattribute {root} {marker};"])

        policy = FakePolicy()
        policy.attributes[marker].clear()
        with self.assertRaisesRegex(ValueError, f"unexpected {marker} membership"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

        for other in ("init_t", "aos_sandbox_controller_t", "aos_method46_controller_helper_t"):
            with self.subTest(other=other):
                policy = FakePolicy()
                policy.attributes[marker].add(other)
                with self.assertRaisesRegex(ValueError, f"unexpected {marker} membership"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

        policy = FakePolicy()
        policy.attributes["domain"].remove(root)
        with self.assertRaisesRegex(ValueError, "lost domain membership"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

        policy = FakePolicy()
        del policy.attributes[marker]
        with self.assertRaisesRegex(ValueError, f"exactly one {marker} attribute"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_both_attribute_axes_cannot_hide_conditional_root_custody(self) -> None:
        root = "aos_sandbox_policy_authority_t"
        sources = FakeAttribute("mixed_root_sources", ("init_t", "unconfined_t"))
        targets = FakeTypeAttribute({root, "init_t"})
        for object_class, permission in effective_policy.owner_policy.ROOT_CUSTODY_CUTS:
            for active in (False, True):
                with self.subTest(object_class=object_class, permission=permission, active=active):
                    policy = FakePolicy()
                    access = effective_policy.Access(
                        sources.name, "mixed_root_targets", object_class, permission,
                    )
                    policy.allows[access] = [FakeRule(
                        "conditional both-axis Root custody", active=active,
                        source=sources, target=targets,
                    )]

                    with self.assertRaisesRegex(ValueError, "foreign normal Root custody"):
                        effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_root_exclusion_preserves_exact_pinned_pid1_inspection(self) -> None:
        root = "aos_sandbox_policy_authority_t"
        source = Path(__file__).with_name("owner_confinement.te").read_text()
        for object_class, permissions in (
            ("dir", ("getattr", "search", "open", "read", "lock", "ioctl")),
            ("file", ("getattr", "open", "read", "lock", "ioctl")),
            ("lnk_file", ("getattr", "read")),
        ):
            with self.subTest(object_class=object_class):
                self.assertIn(
                    f"allow init_t {root}:{object_class} {{ {' '.join(permissions)} }};",
                    source,
                )
                for permission in permissions:
                    self.assert_missing_allow_rejected(
                        effective_policy.Access("init_t", root, object_class, permission)
                    )

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

    def test_owner_status_uses_pinned_generic_unit_type(self) -> None:
        source = Path(__file__).with_name("owner_confinement.te").read_text()
        self.assertIn("type systemd_unit_t;", source)
        self.assertNotIn("systemd_unit_file_t", source)

        for domain in effective_policy.owner_policy.OWNER_DOMAINS:
            with self.subTest(domain=domain):
                access = effective_policy.Access(
                    domain, "systemd_unit_t", "service", "status"
                )
                self.assertIn(access, effective_policy.POSITIVE_ACCESS)
                self.assertIn(
                    f"allow {domain} systemd_unit_t:service status;", source
                )
                self.assert_missing_allow_rejected(access)

    def test_owner_generic_unit_access_stays_status_only(self) -> None:
        for domain in effective_policy.owner_policy.OWNER_DOMAINS:
            for permission in ("start", "stop", "reload", "enable", "disable"):
                with self.subTest(domain=domain, permission=permission):
                    self.assertIn(
                        effective_policy.Access(domain, "*", "service", permission),
                        effective_policy.NEGATIVE_ACCESS,
                    )
                    access = effective_policy.Access(
                        domain, "systemd_unit_t", "service", permission
                    )
                    self.assert_forbidden_allow_rejected(access)

    def test_owner_cannot_change_manager_or_policy_or_cgroup(self) -> None:
        for access in (
            effective_policy.Access(
                "aos_sandbox_controller_t", "init_t", "system", "reload",
            ),
            effective_policy.Access(
                "aos_sandbox_storage_t", "systemd_unit_t", "service", "start",
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

    def test_guest_anchor_source_keeps_var_traversal_separate_from_relabeling(self) -> None:
        """Pins explicit anchor grants; the binary checker covers inheritance."""
        source = Path(__file__).with_name("aos_sandbox.te").read_text()

        self.assertIn(
            "allow aos_sandbox_guest_owner_t var_t:dir { getattr open read search };",
            source,
        )
        self.assertIn(
            "allow aos_sandbox_guest_owner_t { root_t device_t tmpfs_t }:dir "
            "{ getattr open read relabelfrom search };",
            source,
        )
        self.assertNotIn(
            "allow aos_sandbox_guest_owner_t { root_t var_t device_t tmpfs_t }:dir",
            source,
        )

    def test_guest_protected_ancestor_relabel_rejects_indirect_conditionals(self) -> None:
        for source in (effective_policy.GUEST_OWNER, effective_policy.GUEST_TENANT):
            for active in (True, False):
                with self.subTest(source=source, active=active):
                    policy = FakePolicy()
                    access = effective_policy.Access(
                        "guest_domains", "guest_ancestors", "dir", "relabelfrom"
                    )
                    policy.allows[access] = [
                        FakeRule(
                            "conditional inherited ancestor relabel",
                            active=active,
                            source=FakeTypeAttribute({source}),
                            target=FakeTypeAttribute({"var_t", "var_lib_t"}),
                        )
                    ]

                    with self.assertRaisesRegex(
                        ValueError, f"forbidden allow exists.*{source}.*relabelfrom"
                    ):
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

    def test_guest_file_type_cohorts_admit_only_fixed_kernel_reads(self) -> None:
        cohorts = effective_policy.GUEST_FILE_TYPE_COHORTS
        for (source, permission), allowed in cohorts.items():
            for target in allowed:
                with self.subTest(source=source, permission=permission, target=target):
                    policy = FakePolicy()
                    access = effective_policy.Access(source, target, "file", permission)
                    policy.allows[access] = [
                        FakeRule("existing kernel/control read")
                    ]
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_guest_file_type_cohorts_reject_other_direct_file_types(self) -> None:
        for source, permission in effective_policy.GUEST_FILE_TYPE_COHORTS:
            with self.subTest(source=source, permission=permission):
                policy = FakePolicy()
                access = effective_policy.Access(source, "var_t", "file", permission)
                policy.allows[access] = [
                    FakeRule("unrelated host data")
                ]
                with self.assertRaisesRegex(
                    ValueError, "outside Guest file_type cohort.*var_t"
                ):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_guest_file_type_cohorts_reject_mixed_inherited_conditional_targets(self) -> None:
        for active in (True, False):
            with self.subTest(active=active):
                policy = FakePolicy()
                access = effective_policy.Access("domain", "mixed_files", "file", "read")
                policy.allows[access] = [
                    FakeRule(
                        "conditional inherited mixed target",
                        active=active,
                        source=FakeTypeAttribute({
                            effective_policy.GUEST_OWNER,
                            effective_policy.GUEST_TENANT,
                        }),
                        target=FakeTypeAttribute({"cpu_online_t", "var_t"}),
                    )
                ]
                with self.assertRaisesRegex(
                    ValueError, "outside Guest file_type cohort.*var_t"
                ):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_guest_kernel_read_exception_cannot_authorize_mapping_or_execution(self) -> None:
        for source in (effective_policy.GUEST_OWNER, effective_policy.GUEST_TENANT):
            for permission in ("map", "execute_no_trans"):
                with self.subTest(source=source, permission=permission):
                    policy = FakePolicy()
                    access = effective_policy.Access(source, "cpu_online_t", "file", permission)
                    policy.allows[access] = [
                        FakeRule("kernel read exception widened")
                    ]
                    with self.assertRaisesRegex(
                        ValueError, "outside Guest file_type cohort.*cpu_online_t"
                    ):
                        effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_tenant_cannot_inherit_owner_control_file_reads(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            effective_policy.GUEST_TENANT, "cgroup_t", "file", "read"
        )
        policy.allows[access] = [
            FakeRule("Owner control read exposed to Tenant")
        ]
        with self.assertRaisesRegex(ValueError, "outside Guest file_type cohort.*cgroup_t"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_guest_file_type_cohort_names_must_remain_canonical_members(self) -> None:
        policy = FakePolicy()
        policy.file_types.remove("cpu_online_t")
        with self.assertRaisesRegex(ValueError, "not a canonical member: cpu_online_t"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

        class AliasedPolicy(FakePolicy):
            def lookup_type(self, name: str) -> FakeType:
                if name == "cpu_online_t":
                    return FakeType("substituted_cpu_type")
                return super().lookup_type(name)

        with self.assertRaisesRegex(ValueError, "not a canonical member: cpu_online_t"):
            effective_policy.check_policy(FAKE_SETOOLS, AliasedPolicy())

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
