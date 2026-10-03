"""Unit tests for effective AOS sandbox SELinux policy checks."""

from __future__ import annotations

import os
import re
import unittest
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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


class FakeTERuleNoFilename(AttributeError):
    """Matches the selected SETools exception for a generic transition."""


class FakeInvalidType(ValueError):
    """Models the native absence exception without an installed policy."""


@dataclass(frozen=True)
class FakeRule:
    """Supplies the rule surface consumed by the checker."""

    text: str
    active: bool = True
    default: str | None = None
    target: FakeTypeAttribute | None = None
    source: FakeType | FakeTypeAttribute | FakeAttribute | None = None
    filename_value: str | None = None

    @property
    def filename(self) -> str:
        if self.filename_value is None:
            raise FakeTERuleNoFilename
        return self.filename_value

    def enabled(self) -> bool:
        return self.active

    def __str__(self) -> str:
        return self.text


@dataclass(frozen=True)
class FakeXpermRule(FakeRule):
    """Carries native-shaped selector DATA, including malformed observations."""

    perms: frozenset[object] = frozenset()
    xperm_type: str = "ioctl"


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
                    filename_value=(
                        transition.filename if isinstance(transition.filename, str) else None
                    ),
                )
            ]
            for transition in effective_policy.TRANSITIONS
        }
        self.xperms: dict[effective_policy.Access, list[FakeXpermRule]] = {}

    def lookup_type(self, domain: str) -> FakeType:
        return FakeType(domain, domain in self.permissive)


class FakeQuery:
    """Maps SETools-style query arguments back to fixture records."""

    def __init__(self, policy: FakePolicy, **criteria: object) -> None:
        self.policy = policy
        self.criteria = criteria
        self.policy.queries.append(criteria)

    def results(self) -> list[FakeRule]:
        if self.criteria["ruletype"] in (["allow"], ["allowxperm"]):
            source = self.criteria.get("source")
            target = self.criteria.get("target")
            object_class = str(self.criteria["tclass"][0])
            permission = str(self.criteria["perms"][0])

            target_members = (
                self.policy.file_types if target == "file_type" else {str(target)}
            )
            matches = []
            records = (
                self.policy.allows
                if self.criteria["ruletype"] == ["allow"]
                else self.policy.xperms
            )
            for access, rules in records.items():
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
                    if source is not None:
                        if self.criteria.get("source_regex"):
                            if not any(
                                re.search(str(source), str(member)) for member in sources
                            ):
                                continue
                        elif str(source) not in sources:
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
            return [
                rule
                for candidate, rules in self.policy.transitions.items()
                if (candidate.source, candidate.target, candidate.object_class, candidate.default)
                == (transition.source, transition.target, transition.object_class, transition.default)
                for rule in rules
            ]

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

    def expand(self) -> set[str]:
        return {self.name}

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
    TERuletype=SimpleNamespace(
        allow="allow", allowxperm="allowxperm", type_transition="type_transition",
    ),
    TypeAttributeQuery=FakeTypeAttributeQuery,
    exception=SimpleNamespace(
        TERuleNoFilename=FakeTERuleNoFilename, InvalidType=FakeInvalidType,
    ),
)


class EffectivePolicyTest(unittest.TestCase):
    """Exercises positive, negative, conditional, and permissive gates."""

    def _storage_policy(self) -> FakePolicy:
        """Uses the current custody cohort only for the new delivery vectors."""

        policy = FakePolicy()
        # Leave legacy fixture/expectations unchanged; new B vectors must
        # reach their own checks rather than fail an inherited stale cohort.
        policy.attributes[effective_policy.PRIVATE_ROOT_CUSTODY_ATTRIBUTE] = {
            "aos_sandbox_policy_authority_t", "aos_nix_offline_prepare_t",
            "aos_nix_offline_tpm_helper_t",
        }
        return policy

    def test_transition_no_filter_never_observes_filename(self) -> None:
        class UnobservableName:
            @property
            def filename(self):
                raise RuntimeError("legacy query must not observe filename")

        rule = UnobservableName()
        queries = SimpleNamespace(TERuleQuery=lambda policy, **criteria: SimpleNamespace(
            results=lambda: [rule],
        ))
        transition = effective_policy.Transition("source", "target", "file", "default")

        self.assertEqual(effective_policy.transition_rules(queries, None, transition), [rule])
        self.assertEqual(
            effective_policy.transition_candidates(queries, None, "source", "target", "file"),
            [rule],
        )
        evidence = effective_policy.check_policy(FAKE_SETOOLS, self._storage_policy())
        self.assertIn("transition\tkernel_t\tinit_exec_t\tprocess\tinit_t", evidence)

    def test_transition_named_unnamed_and_no_filter_are_disjoint(self) -> None:
        named = FakeRule("named", filename_value="selected")
        sibling = FakeRule("sibling", filename_value="other")
        generic = FakeRule("generic")
        rules = [named, generic, sibling]

        self.assertIs(effective_policy._transition_filename_rules(FAKE_SETOOLS, rules, None), rules)
        self.assertEqual(
            effective_policy._transition_filename_rules(FAKE_SETOOLS, rules, "selected"),
            [named],
        )
        self.assertEqual(
            effective_policy._transition_filename_rules(
                FAKE_SETOOLS, rules, effective_policy.Transition.UNNAMED,
            ),
            [generic],
        )
        self.assertEqual(
            effective_policy._transition_filename_rules(FAKE_SETOOLS, rules, "missing"), [],
        )

    def test_transition_unsupported_filename_observation_fails(self) -> None:
        for rule in (SimpleNamespace(filename=None), SimpleNamespace()):
            with self.subTest(rule=rule):
                with self.assertRaises((ValueError, AttributeError)):
                    effective_policy._transition_filename_rules(FAKE_SETOOLS, [rule], "selected")

        with self.assertRaisesRegex(ValueError, "unsupported.*selector"):
            effective_policy._transition_filename_rules(FAKE_SETOOLS, [], object())

    def test_storage_generic_promotion_cannot_satisfy_named_delivery(self) -> None:
        policy = self._storage_policy()
        transition = next(
            transition for transition in effective_policy.OWNER_TRANSITIONS
            if transition.filename == "storage-zfs-hold-key-v1"
        )
        policy.transitions[transition] = [FakeRule("generic impostor", default=transition.default)]

        with self.assertRaisesRegex(ValueError, "missing effective transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_storage_delivery_rejects_disabled_generic_and_named_sibling(self) -> None:
        credential = effective_policy.owner_policy.STORAGE_CREDENTIAL
        for name, default in (
            (None, credential),
            ("unknown-credential", credential),
            (None, "other_tmpfs_t"),
        ):
            with self.subTest(name=name, default=default):
                policy = self._storage_policy()
                transition = effective_policy.Transition(
                    "init_t", credential, "file", default, filename=name,
                )
                policy.transitions[transition] = [FakeRule(
                    "disabled delivery alternative", active=False, default=default,
                    filename_value=name,
                )]

                with self.assertRaisesRegex(ValueError, "unexpected Storage credential"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_storage_source_read_and_destination_copy_are_separate(self) -> None:
        owner = effective_policy.owner_policy
        for target, permission in (
            (owner.STORAGE_CREDENTIAL_SOURCE, "read"),
            (owner.STORAGE_CREDENTIAL, "write"),
        ):
            policy = self._storage_policy()
            policy.allows[effective_policy.Access("init_t", target, "file", permission)] = []
            with self.assertRaisesRegex(ValueError, "missing effective allow"):
                effective_policy.check_policy(FAKE_SETOOLS, policy)
        for domain, target, permission in (
            ("init_t", owner.STORAGE_CREDENTIAL_SOURCE, "write"),
            ("aos_sandbox_storage_t", owner.STORAGE_CREDENTIAL_SOURCE, "read"),
            ("aos_sandbox_controller_t", owner.STORAGE_CREDENTIAL_SOURCE, "open"),
            ("aos_sandbox_storage_t", owner.STORAGE_CREDENTIAL, "write"),
            ("init_t", owner.STORAGE_CREDENTIAL, "append"),
        ):
            with self.subTest(domain=domain, target=target, permission=permission):
                policy = self._storage_policy()
                access = effective_policy.Access(domain, target, "file", permission)
                policy.allows[access] = [FakeRule("unexpected source/delivery mutation")]
                with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_storage_source_never_inherits_domain_or_file_type(self) -> None:
        source = effective_policy.owner_policy.STORAGE_CREDENTIAL_SOURCE
        for attribute in ("domain", "file_type"):
            with self.subTest(attribute=attribute):
                policy = self._storage_policy()
                members = policy.file_types if attribute == "file_type" else policy.attributes[attribute]
                members.add(source)
                with self.assertRaisesRegex(ValueError, "Storage credential source inherited"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_gateway_is_enforcing_but_not_a_writer_or_default_entry(self) -> None:
        owner = effective_policy.owner_policy
        self.assertNotIn("git_gateway", owner.OWNERS)
        self.assertIn(owner.GATEWAY, effective_policy.ENFORCING_DOMAINS)
        self.assertIn(owner.GATEWAY, owner.NO_DEFAULT_ENTRY)

        policy = FakePolicy()
        policy.permissive.add(owner.GATEWAY)
        with self.assertRaisesRegex(ValueError, "permissive"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_gateway_requires_explicit_entry_and_read_only_hard_envelope_cells(self) -> None:
        owner = effective_policy.owner_policy
        for target, object_class, permission in (
            (owner.GATEWAY_EXECUTABLE, "file", "entrypoint"),
            (owner.GATEWAY_CREDENTIAL, "file", "read"),
            ("cgroup_t", "file", "read"),
            ("systemd_unit_t", "service", "status"),
            (owner.GATEWAY, "tcp_socket", "listen"),
        ):
            with self.subTest(target=target, permission=permission):
                access = effective_policy.Access(owner.GATEWAY, target, object_class, permission)
                self.assertIn(access, effective_policy.POSITIVE_ACCESS)
                self.assert_missing_allow_rejected(access)

    def test_gateway_rejects_automatic_shared_binary_entry(self) -> None:
        owner = effective_policy.owner_policy
        policy = FakePolicy()
        transition = effective_policy.Transition(
            "init_t", owner.GATEWAY_EXECUTABLE, "process", owner.GATEWAY,
        )
        policy.transitions[transition] = [
            FakeRule("automatic Gateway entry", default=transition.default),
        ]

        with self.assertRaisesRegex(ValueError, "automatic entry transition"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_gateway_refuses_manager_writer_helper_outbound_and_foreign_custody(self) -> None:
        owner = effective_policy.owner_policy
        for target, object_class, permission in (
            ("systemd_unit_t", "service", "start"),
            ("init_t", "system", "reload"),
            ("cgroup_t", "file", "write"),
            ("aos_sandbox_controller_state_t", "file", "open"),
            ("aos_sandbox_source_journal_t", "file", "read"),
            ("aos_method46_tpm_device_t", "chr_file", "open"),
            ("aos_method46_controller_helper_t", "process", "transition"),
            ("port_t", "tcp_socket", "name_connect"),
            (owner.GATEWAY, "udp_socket", "create"),
        ):
            with self.subTest(target=target, permission=permission):
                self.assert_forbidden_allow_rejected(
                    effective_policy.Access(owner.GATEWAY, target, object_class, permission)
                )

    def test_gateway_root_custody_fails_the_existing_all_source_cut_first(self) -> None:
        policy = FakePolicy()
        access = effective_policy.Access(
            effective_policy.owner_policy.GATEWAY,
            "aos_sandbox_policy_authority_t", "fd", "use",
        )
        policy.allows[access] = [FakeRule("foreign Gateway Root custody")]

        with self.assertRaisesRegex(ValueError, "foreign normal Root custody grant exists"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)

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
            + len(effective_policy.NEGATIVE_ACCESS)
            + 3,  # One closed delivery set and two source attribute cuts.
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

    def test_offline_helper_mapping_preserves_the_reexec_cut(self) -> None:
        owner = effective_policy.owner_policy
        for permission in ("entrypoint", "execute", "getattr", "map", "open", "read"):
            with self.subTest(permission=permission):
                access = effective_policy.Access(
                    owner.OFFLINE_HELPER, owner.OFFLINE_HELPER_EXECUTABLE,
                    "file", permission,
                )
                self.assertIn(access, effective_policy.POSITIVE_ACCESS)
                self.assertNotIn(access, effective_policy.NEGATIVE_ACCESS)

        self.assertIn(
            effective_policy.Access(owner.OFFLINE_HELPER, "*", "file", "execute_no_trans"),
            effective_policy.NEGATIVE_ACCESS,
        )
        evidence = effective_policy.check_policy(FAKE_SETOOLS, self._storage_policy())
        self.assertTrue(evidence)

    def test_offline_helper_missing_mapping_permission_refuses(self) -> None:
        owner = effective_policy.owner_policy
        for permission in ("entrypoint", "execute", "getattr", "map", "open", "read"):
            with self.subTest(permission=permission):
                policy = self._storage_policy()
                access = effective_policy.Access(
                    owner.OFFLINE_HELPER, owner.OFFLINE_HELPER_EXECUTABLE,
                    "file", permission,
                )
                policy.allows[access] = []

                with self.assertRaisesRegex(ValueError, "missing effective allow"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_offline_helper_mapping_does_not_allow_same_sid_reexec(self) -> None:
        owner = effective_policy.owner_policy
        self.assertIn(
            effective_policy.Access(owner.OFFLINE_HELPER, "*", "file", "execute_no_trans"),
            effective_policy.NEGATIVE_ACCESS,
        )
        for access in (
            effective_policy.Access(
                owner.OFFLINE_HELPER, owner.OFFLINE_HELPER_EXECUTABLE,
                "file", "execute_no_trans",
            ),
            effective_policy.Access(owner.OFFLINE_HELPER, "bin_t", "file", "execute_no_trans"),
            effective_policy.Access(owner.OFFLINE_HELPER, owner.OFFLINE_HELPER, "process", "transition"),
        ):
            with self.subTest(access=access):
                policy = self._storage_policy()
                policy.allows[access] = [FakeRule("unexpected helper re-exec")]

                with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                    effective_policy.check_policy(FAKE_SETOOLS, policy)

    def test_offline_helper_foreign_execution_cuts_remain_closed(self) -> None:
        owner = effective_policy.owner_policy
        for source in (
            "init_t", "aos_sandbox_controller_t", owner.GATEWAY,
            "aos_method46_controller_helper_t",
        ):
            for permission in ("execute", "execute_no_trans"):
                with self.subTest(source=source, permission=permission):
                    policy = self._storage_policy()
                    access = effective_policy.Access(
                        source, owner.OFFLINE_HELPER_EXECUTABLE, "file", permission,
                    )
                    self.assertIn(access, effective_policy.NEGATIVE_ACCESS)
                    policy.allows[access] = [FakeRule("unexpected foreign helper execution")]

                    with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                        effective_policy.check_policy(FAKE_SETOOLS, policy)

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

    def test_controller_selected_images_are_read_only_not_root_task_custody(self) -> None:
        controller = "aos_sandbox_controller_t"
        source = Path(__file__).with_name("owner_confinement.te").read_text()
        for object_type in (
            "aos_sandbox_policy_authority_profile_t",
            "aos_sandbox_policy_authority_exec_t",
            "init_exec_t",
        ):
            self.assertIn(
                f"allow {controller} {object_type}:file {{ getattr open read }};",
                source,
            )
            for permission in ("getattr", "open", "read"):
                self.assert_missing_allow_rejected(effective_policy.Access(
                    controller, object_type, "file", permission,
                ))

        root_image = "aos_sandbox_policy_authority_exec_t"
        for permission in ("execute", "execute_no_trans", "entrypoint", "map", "write"):
            policy = FakePolicy()
            access = effective_policy.Access(controller, root_image, "file", permission)
            policy.allows[access] = [FakeRule("selected image became executable or mutable")]
            with self.assertRaisesRegex(ValueError, "forbidden allow exists"):
                effective_policy.check_policy(FAKE_SETOOLS, policy)

        root = "aos_sandbox_policy_authority_t"
        for object_class, permission in effective_policy.owner_policy.ROOT_CUSTODY_CUTS:
            policy = FakePolicy()
            access = effective_policy.Access(controller, root, object_class, permission)
            policy.allows[access] = [FakeRule("selected input became Root process custody")]
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

    def test_guest_ancestor_mutant_evidence_accepts_either_expanded_target(self) -> None:
        support = Path(__file__).parent
        recipe_path = Path(
            os.environ.get(
                "AOS_SELINUX_PRODUCTION_RECIPE",
                str(support.parent / "aos-selinux-production-policy.nix"),
            )
        )
        recipe = recipe_path.read_text()
        case = recipe.split("              aos_sandbox_guest_ancestor_negative)\n", 1)[1]
        case = case.split("                ;;", 1)[0]
        target_check = re.search(r'grep -E "([^"]+)"', case)
        self.assertIsNotNone(target_check)
        assert target_check is not None
        target_pattern = target_check.group(1)

        for target in ("var_t", "var_lib_t"):
            self.assertRegex(f"Access(target='{target}')", target_pattern)
        for target in ("root_t", "var_t_other", "var_lib_t_other"):
            self.assertNotRegex(f"Access(target='{target}')", target_pattern)

        for guard in (
            'grep -F "aos_sandbox_guest_owner_t"',
            'grep -F "object_class=\'dir\'"',
            'grep -F "permission=\'relabelfrom\'"',
        ):
            self.assertIn(guard, case)

        mutant = (support / "aos_sandbox_guest_ancestor_negative.te").read_text()
        for target in ("var_t", "var_lib_t"):
            self.assertIn(
                f"typeattribute {target} aos_sandbox_negative_guest_ancestors;", mutant
            )
        self.assertIn("bool aos_sandbox_negative_guest_ancestors_enabled false;", mutant)

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


class SelectedLauncherImageIoctlTest(unittest.TestCase):
    """Checks closed offline image expectations without genuine FD authority."""

    def _selected_policy(self) -> FakePolicy:
        policy = FakePolicy()
        cells = effective_policy.owner_policy.SELECTED_LAUNCHER_IMAGE_IOCTL_CELLS
        for source, target in cells:
            access = effective_policy.Access(source, target, "file", "ioctl")
            policy.allows[access] = [FakeRule("fixed base image ioctl")]
            policy.xperms[access] = [FakeXpermRule(
                "fixed image selector", perms=frozenset({0x6686}),
            )]
        return policy

    def _check_selected(self, policy: FakePolicy) -> list[str]:
        with patch.object(
            effective_policy.owner_policy,
            "SELECTED_LAUNCHER_IMAGE_IOCTL_SELECTORS",
            frozenset({0x6686}),
        ):
            return effective_policy._check_selected_launcher_image_ioctls(FAKE_SETOOLS, policy)

    def test_default_data_and_actual_checker_tail_stay_closed(self) -> None:
        owner = effective_policy.owner_policy
        self.assertEqual(owner.SELECTED_LAUNCHER_IMAGE_IOCTL_CELLS, (
            ("aos_sandbox_mount_t", "init_exec_t"),
            ("aos_source_provider_t", "init_exec_t"),
        ))
        self.assertEqual(owner.SELECTED_LAUNCHER_IMAGE_IOCTL_SELECTORS, frozenset())

        policy = EffectivePolicyTest()._storage_policy()
        evidence = effective_policy.check_policy(FAKE_SETOOLS, policy)

        self.assertFalse(any(line.startswith("allowxperm\t") for line in evidence))
        self.assertEqual(evidence[-1], (
            f"deny\t{effective_policy.NEGATIVE_ACCESS[-1].source}\t"
            f"{effective_policy.NEGATIVE_ACCESS[-1].target}\t"
            f"{effective_policy.NEGATIVE_ACCESS[-1].object_class}\t"
            f"{effective_policy.NEGATIVE_ACCESS[-1].permission}"
        ))
        self.assertEqual(
            [query["ruletype"] for query in policy.queries[-2:]],
            [["allow"], ["allowxperm"]],
        )

    def test_exact_enabled_selectors_pass_in_fixed_pair_order(self) -> None:
        policy = self._selected_policy()
        cells = effective_policy.owner_policy.SELECTED_LAUNCHER_IMAGE_IOCTL_CELLS
        for rules in policy.xperms.values():
            rules.append(rules[0])

        evidence = self._check_selected(policy)

        self.assertEqual(evidence, [
            f"allowxperm\t{source}\t{target}\tfile\tioctl\t0x6686"
            for source, target in cells
        ])

    def test_missing_or_inactive_positive_witness_fails(self) -> None:
        for kind in ("base", "extended"):
            for inactive in (False, True):
                with self.subTest(kind=kind, inactive=inactive):
                    policy = self._selected_policy()
                    access = next(iter(policy.xperms))
                    records = policy.allows if kind == "base" else policy.xperms
                    records[access] = (
                        [replace(records[access][0], active=False)] if inactive else []
                    )

                    with self.assertRaisesRegex(ValueError, "missing selected-launcher"):
                        self._check_selected(policy)

    def test_complete_selector_sets_reject_excess_in_any_branch(self) -> None:
        selector_sets = (
            frozenset({0x6685}),
            frozenset({0x6685, 0x6686, 0x6687}),
            frozenset(range(0x6600, 0x6700)),
            frozenset({0xc0046686}),
            frozenset({"0x6686"}),
            frozenset(),
        )
        for selectors in selector_sets:
            for active in (False, True):
                with self.subTest(selectors=selectors, active=active):
                    policy = self._selected_policy()
                    access = next(iter(policy.xperms))
                    policy.xperms[access].append(FakeXpermRule(
                        "excess or malformed selector set", active=active, perms=selectors,
                    ))

                    with self.assertRaisesRegex(ValueError, "forbidden.*selectors"):
                        self._check_selected(policy)

    def test_both_attribute_axes_reject_foreign_pairs_in_any_branch(self) -> None:
        for kind in ("base", "extended"):
            for axis in ("source", "target"):
                for active in (False, True):
                    with self.subTest(kind=kind, axis=axis, active=active):
                        policy = self._selected_policy()
                        access = next(iter(policy.xperms))
                        records = policy.allows if kind == "base" else policy.xperms
                        members = (
                            {access.source, "aos_sandbox_storage_t"}
                            if axis == "source"
                            else {access.target, "other_image_t"}
                        )
                        records[access].append(replace(
                            records[access][0], active=active,
                            **{axis: FakeTypeAttribute(members)},
                        ))

                        with self.assertRaisesRegex(ValueError, "forbidden.*grant"):
                            self._check_selected(policy)

    def test_exact_two_source_attribute_can_supply_both_cells(self) -> None:
        policy = self._selected_policy()
        access = next(iter(policy.xperms))
        cells = effective_policy.owner_policy.SELECTED_LAUNCHER_IMAGE_IOCTL_CELLS
        source_attribute = FakeTypeAttribute({source for source, _ in cells})
        policy.allows = {access: [FakeRule("two fixed sources", source=source_attribute)]}
        policy.xperms = {access: [FakeXpermRule(
            "two fixed sources", source=source_attribute, perms=frozenset({0x6686}),
        )]}

        self.assertEqual(len(self._check_selected(policy)), 2)

    def test_default_rejects_base_and_extended_grants_even_if_inactive(self) -> None:
        cells = effective_policy.owner_policy.SELECTED_LAUNCHER_IMAGE_IOCTL_CELLS
        for kind in ("base", "extended"):
            for active in (False, True):
                with self.subTest(kind=kind, active=active):
                    policy = FakePolicy()
                    source, target = cells[0]
                    access = effective_policy.Access(source, target, "file", "ioctl")
                    if kind == "base":
                        policy.allows[access] = [FakeRule("default leak", active=active)]
                    else:
                        policy.xperms[access] = [FakeXpermRule(
                            "default leak", active=active, perms=frozenset({0x6686}),
                        )]

                    with self.assertRaisesRegex(ValueError, "forbidden.*grant"):
                        effective_policy._check_selected_launcher_image_ioctls(FAKE_SETOOLS, policy)

    def test_absent_default_types_still_scan_and_selected_absence_fails(self) -> None:
        cells = effective_policy.owner_policy.SELECTED_LAUNCHER_IMAGE_IOCTL_CELLS

        class AbsentSourcesPolicy(FakePolicy):
            def lookup_type(self, name: str) -> FakeType:
                if name != "init_exec_t":
                    raise FakeInvalidType(name)
                return super().lookup_type(name)

        policy = AbsentSourcesPolicy()
        self.assertEqual(
            effective_policy._check_selected_launcher_image_ioctls(FAKE_SETOOLS, policy), [],
        )
        self.assertEqual(len(policy.queries), 2)
        with self.assertRaisesRegex(ValueError, "missing selected-launcher image source"):
            self._check_selected(policy)

        source, target = cells[0]
        policy.xperms[effective_policy.Access(source, target, "file", "ioctl")] = [
            FakeXpermRule("unexpected retained rule", perms=frozenset({0x6686})),
        ]
        with self.assertRaisesRegex(ValueError, "forbidden.*grant"):
            effective_policy._check_selected_launcher_image_ioctls(FAKE_SETOOLS, policy)

    def test_aliases_and_nonabsence_errors_are_not_hidden(self) -> None:
        names = ("init_exec_t", "aos_sandbox_mount_t", "aos_source_provider_t")
        for aliased_name in names:
            class AliasedPolicy(FakePolicy):
                def lookup_type(self, name: str) -> FakeType:
                    return FakeType("substitute_t" if name == aliased_name else name)

            with self.subTest(name=aliased_name):
                with self.assertRaisesRegex(ValueError, "aliased"):
                    effective_policy._check_selected_launcher_image_ioctls(
                        FAKE_SETOOLS, AliasedPolicy(),
                    )

        class BrokenLookupPolicy(FakePolicy):
            def lookup_type(self, name: str) -> FakeType:
                raise RuntimeError("original lookup failure")

        with self.assertRaisesRegex(RuntimeError, "original lookup failure"):
            effective_policy._check_selected_launcher_image_ioctls(
                FAKE_SETOOLS, BrokenLookupPolicy(),
            )

    def test_query_keeps_full_native_sets_and_wrong_pairs_cannot_satisfy_positive(self) -> None:
        policy = self._selected_policy()
        self._check_selected(policy)
        for query in policy.queries:
            self.assertEqual(query["perms"], ["ioctl"])
            self.assertEqual(query["tclass"], ["file"])
            self.assertEqual(query["target"], "init_exec_t")
            self.assertIs(query["source_regex"], True)
            self.assertIs(query["source_indirect"], True)
            self.assertIs(query["target_indirect"], True)
            self.assertNotIn("xperms", query)
            self.assertNotIn("xperms_equal", query)
            self.assertNotIn("boolean", query)
            self.assertIsNone(re.search(str(query["source"]), "aos_sandbox_mount_t_other"))

        for changed in ({"source": "other_t"}, {"target": "other_image_t"}):
            with self.subTest(changed=changed):
                policy = self._selected_policy()
                access = next(iter(policy.xperms))
                policy.xperms[replace(access, **changed)] = policy.xperms.pop(access)
                with self.assertRaisesRegex(ValueError, "missing.*selectors"):
                    self._check_selected(policy)

    def test_original_check_failure_precedes_new_default_violation(self) -> None:
        policy = EffectivePolicyTest()._storage_policy()
        policy.allows[effective_policy.POSITIVE_ACCESS[0]] = []
        cells = effective_policy.owner_policy.SELECTED_LAUNCHER_IMAGE_IOCTL_CELLS
        source, target = cells[0]
        policy.allows[effective_policy.Access(source, target, "file", "ioctl")] = [
            FakeRule("later default image violation"),
        ]

        with self.assertRaisesRegex(ValueError, "missing effective allow"):
            effective_policy.check_policy(FAKE_SETOOLS, policy)
        self.assertFalse(any(query.get("source_regex") for query in policy.queries))

    def test_full_native_command_is_not_a_mac_selector_expectation(self) -> None:
        with patch.object(
            effective_policy.owner_policy,
            "SELECTED_LAUNCHER_IMAGE_IOCTL_SELECTORS",
            frozenset({0xc0046686}),
        ):
            with self.assertRaisesRegex(ValueError, "unsupported.*expectation"):
                effective_policy._check_selected_launcher_image_ioctls(FAKE_SETOOLS, FakePolicy())


class GitReadDelegationTest(unittest.TestCase):
    """Exercises selected DATA queries, never installed service authority."""

    def selected_policy(self) -> FakePolicy:
        policy = FakePolicy()
        positive, _, transitions = effective_policy.owner_policy.git_read_matrix(
            effective_policy.Access, effective_policy.Transition,
            effective_policy.accesses, effective_policy.DOMAINS,
        )
        for access in positive:
            policy.allows[access] = [FakeRule(f"fixed selected {access}")]
        for transition in transitions:
            policy.transitions[transition] = [FakeRule(
                "fixed named transition", default=transition.default,
                filename_value=transition.filename,
            )]
        return policy

    def test_selected_fixed_cells_and_no_automatic_default_change(self) -> None:
        self.assertEqual(effective_policy._check_git_read_delegation(
            FAKE_SETOOLS, self.selected_policy(),
        ), ["git-read-delegation\tselected-fixed-inspection-only"])
        self.assertNotIn(effective_policy.owner_policy.GIT_READ_RUNTIME,
                         FakePolicy().attributes["domain"])

    def test_disabled_write_and_foreign_task_read_are_rejected(self) -> None:
        for access in (
            effective_policy.Access(effective_policy.owner_policy.GATEWAY,
                effective_policy.owner_policy.GIT_READ_RUNTIME, "dir", "write"),
            effective_policy.Access(effective_policy.owner_policy.GATEWAY,
                "aos_sandbox_storage_t", "file", "read"),
        ):
            policy = self.selected_policy()
            policy.allows[access] = [FakeRule("disabled foreign grant", active=False)]
            with self.assertRaisesRegex(ValueError, "forbidden selected Git allow"):
                effective_policy._check_git_read_delegation(FAKE_SETOOLS, policy)

    def test_missing_current_task_cell_cannot_be_replaced_by_type_presence(self) -> None:
        policy = self.selected_policy()
        policy.allows[effective_policy.Access(effective_policy.owner_policy.GATEWAY,
            effective_policy.owner_policy.GIT_READ_CONTROLLER, "file", "open")] = []
        with self.assertRaisesRegex(ValueError, "missing selected Git allow"):
            effective_policy._check_git_read_delegation(FAKE_SETOOLS, policy)


if __name__ == "__main__":
    unittest.main()
