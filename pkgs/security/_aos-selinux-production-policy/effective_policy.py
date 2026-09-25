"""Check the effective AOS sandbox SELinux policy fail closed."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


DOMAINS = (
    "aos_sandbox_host_t",
    "aos_sandbox_network_publisher_t",
    "aos_sandbox_namespace_inspector_t",
    "aos_sandbox_network_lifecycle_worker_t",
    "aos_nspawn_t",
    "aos_sandbox_payload_t",
)
PAYLOAD_EXECUTABLE_TYPES = (
    "aos_sandbox_payload_bootstrap_exec_t",
    "aos_sandbox_payload_systemd_exec_t",
)
PROVISIONER_DOMAIN = "aos_sandbox_runtime_roots_t"
ENFORCING_DOMAINS = ("kernel_t", "init_t", PROVISIONER_DOMAIN, *DOMAINS)

DOMAIN_EXECUTABLES = (
    ("aos_sandbox_host_t", "aos_sandbox_host_exec_t"),
    ("aos_nspawn_t", "aos_nspawn_exec_t"),
    ("aos_sandbox_network_publisher_t", "aos_sandbox_network_publisher_exec_t"),
    ("aos_sandbox_namespace_inspector_t", "aos_sandbox_namespace_inspector_exec_t"),
    (
        "aos_sandbox_network_lifecycle_worker_t",
        "aos_sandbox_network_lifecycle_worker_exec_t",
    ),
    (PROVISIONER_DOMAIN, "aos_sandbox_runtime_roots_exec_t"),
)
PROVISIONER_EXECUTABLE = "aos_sandbox_runtime_roots_exec_t"
FORBIDDEN_PROVISIONER_TRANSITION_SOURCES = DOMAINS


@dataclass(frozen=True, order=True)
class Access:
    """Names one source, target, object class, and permission query."""

    source: str
    target: str
    object_class: str
    permission: str


@dataclass(frozen=True, order=True)
class Transition:
    """Names one required type transition."""

    source: str
    target: str
    object_class: str
    default: str


TRANSITIONS = (
    Transition("kernel_t", "init_exec_t", "process", "init_t"),
    Transition("init_t", "aos_sandbox_host_exec_t", "process", "aos_sandbox_host_t"),
    Transition("init_t", "aos_nspawn_exec_t", "process", "aos_nspawn_t"),
    Transition(
        "init_t",
        "aos_sandbox_network_publisher_exec_t",
        "process",
        "aos_sandbox_network_publisher_t",
    ),
    Transition(
        "init_t",
        "aos_sandbox_namespace_inspector_exec_t",
        "process",
        "aos_sandbox_namespace_inspector_t",
    ),
    Transition(
        "init_t",
        "aos_sandbox_network_lifecycle_worker_exec_t",
        "process",
        "aos_sandbox_network_lifecycle_worker_t",
    ),
    Transition(
        "init_t",
        PROVISIONER_EXECUTABLE,
        "process",
        PROVISIONER_DOMAIN,
    ),
    Transition(
        "aos_sandbox_network_publisher_t",
        "aos_sandbox_network_expected_staging_t",
        "file",
        "aos_sandbox_network_expected_record_t",
    ),
    Transition(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_spent_staging_t",
        "file",
        "aos_sandbox_network_spent_record_t",
    ),
)


def accesses(
    source: str,
    target: str,
    object_class: str,
    permissions: Iterable[str],
) -> tuple[Access, ...]:
    """Expands one permission set into individually auditable queries."""

    return tuple(Access(source, target, object_class, permission) for permission in permissions)


def execution_access() -> tuple[Access, ...]:
    """Builds the permissions required to use each declared transition."""

    checks: list[Access] = []
    for domain, executable in DOMAIN_EXECUTABLES:
        checks.extend(
            accesses(
                "init_t",
                executable,
                "file",
                ("execute", "getattr", "map", "open", "read"),
            )
        )
        checks.append(Access("init_t", domain, "process", "transition"))
        checks.append(Access(domain, executable, "file", "entrypoint"))

    return tuple(checks)


POSITIVE_ACCESS = (
    Access("kernel_t", "init_t", "process", "transition"),
    Access("kernel_t", "init_exec_t", "file", "execute"),
    Access("init_t", "init_exec_t", "file", "entrypoint"),
    *execution_access(),
    Access(PROVISIONER_DOMAIN, PROVISIONER_DOMAIN, "process", "setfscreate"),
    *accesses(
        PROVISIONER_DOMAIN,
        "root_t",
        "dir",
        ("getattr", "open", "read", "search"),
    ),
    Access(PROVISIONER_DOMAIN, "security_t", "filesystem", "getattr"),
    *accesses(
        PROVISIONER_DOMAIN,
        "security_t",
        "dir",
        ("getattr", "open", "read", "search"),
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "security_t",
        "file",
        ("getattr", "open", "read"),
    ),
    Access(PROVISIONER_DOMAIN, "proc_t", "filesystem", "getattr"),
    *accesses(
        PROVISIONER_DOMAIN,
        "proc_t",
        "dir",
        ("getattr", "open", "read", "search"),
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "proc_t",
        "file",
        ("getattr", "open", "read", "write"),
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "device_t",
        "dir",
        ("getattr", "open", "read", "search"),
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "device_t",
        "lnk_file",
        ("getattr", "read"),
    ),
    Access(PROVISIONER_DOMAIN, "fixed_disk_device_t", "blk_file", "getattr"),
    *accesses(
        PROVISIONER_DOMAIN,
        "var_t",
        "dir",
        ("add_name", "getattr", "open", "search", "write"),
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "var_lib_t",
        "dir",
        ("add_name", "create", "getattr", "open", "read", "search", "write"),
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "aos_sandbox_network_root_t",
        "dir",
        ("add_name", "create", "getattr", "open", "read", "search", "write"),
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "aos_sandbox_network_state_t",
        "dir",
        ("create", "getattr", "open", "read", "search"),
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "aos_sandbox_network_store_t",
        "dir",
        ("add_name", "create", "getattr", "open", "read", "search", "write"),
    ),
    *(
        access
        for directory in (
            "aos_sandbox_network_expected_staging_t",
            "aos_sandbox_network_expected_final_t",
            "aos_sandbox_network_spent_staging_t",
            "aos_sandbox_network_spent_final_t",
        )
        for access in accesses(
            PROVISIONER_DOMAIN,
            directory,
            "dir",
            ("create", "getattr", "open", "read", "search"),
        )
    ),
    *(
        access
        for domain in (
            "aos_sandbox_network_publisher_t",
            "aos_sandbox_namespace_inspector_t",
        )
        for directory in ("var_t", "var_lib_t", "aos_sandbox_network_root_t")
        for access in accesses(domain, directory, "dir", ("getattr", "open", "search"))
    ),
    *accesses(
        "aos_sandbox_network_publisher_t",
        "aos_sandbox_network_state_t",
        "dir",
        ("add_name", "getattr", "open", "read", "remove_name", "search", "write"),
    ),
    *accesses(
        "aos_sandbox_network_publisher_t",
        "aos_sandbox_network_state_t",
        "file",
        (
            "append",
            "create",
            "getattr",
            "ioctl",
            "lock",
            "open",
            "read",
            "rename",
            "setattr",
            "unlink",
            "write",
        ),
    ),
    *accesses(
        "aos_sandbox_network_publisher_t",
        "aos_sandbox_network_store_t",
        "dir",
        ("getattr", "open", "search"),
    ),
    *accesses(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_store_t",
        "dir",
        ("getattr", "open", "search"),
    ),
    *accesses(
        "aos_sandbox_network_publisher_t",
        "aos_sandbox_network_expected_staging_t",
        "dir",
        ("add_name", "getattr", "open", "read", "remove_name", "search", "write"),
    ),
    *accesses(
        "aos_sandbox_network_publisher_t",
        "aos_sandbox_network_expected_final_t",
        "dir",
        ("add_name", "getattr", "open", "read", "search", "write"),
    ),
    *accesses(
        "aos_sandbox_network_publisher_t",
        "aos_sandbox_network_expected_record_t",
        "file",
        ("create", "getattr", "ioctl", "open", "read", "rename", "write"),
    ),
    *accesses(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_expected_final_t",
        "dir",
        ("getattr", "open", "read", "search"),
    ),
    *accesses(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_expected_record_t",
        "file",
        ("getattr", "ioctl", "open", "read"),
    ),
    *accesses(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_spent_staging_t",
        "dir",
        ("add_name", "getattr", "open", "read", "remove_name", "search", "write"),
    ),
    *accesses(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_spent_final_t",
        "dir",
        ("add_name", "getattr", "open", "read", "search", "write"),
    ),
    *accesses(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_spent_record_t",
        "file",
        ("create", "getattr", "ioctl", "open", "read", "rename", "write"),
    ),
    Access(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_namespace_inspector_t",
        "capability",
        "sys_ptrace",
    ),
    Access(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_lifecycle_worker_t",
        "file",
        "read",
    ),
    Access(
        "aos_sandbox_namespace_inspector_t",
        "aos_sandbox_network_lifecycle_worker_t",
        "file",
        "ioctl",
    ),
    Access("aos_nspawn_t", "aos_nspawn_t", "capability", "sys_admin"),
    Access("aos_nspawn_t", "aos_nspawn_t", "capability", "sys_chroot"),
    Access("aos_nspawn_t", "aos_nspawn_t", "process", "setexec"),
    Access("aos_nspawn_t", "aos_sandbox_payload_t", "process", "transition"),
    *accesses(
        "aos_nspawn_t",
        "aos_sandbox_payload_bootstrap_exec_t",
        "file",
        ("execute", "getattr", "map", "open", "read"),
    ),
    Access(
        "aos_sandbox_payload_t",
        "aos_sandbox_payload_bootstrap_exec_t",
        "file",
        "entrypoint",
    ),
    *accesses(
        "aos_sandbox_payload_t",
        "aos_sandbox_payload_systemd_exec_t",
        "file",
        ("execute", "execute_no_trans", "getattr", "map", "open", "read"),
    ),
    Access("aos_sandbox_host_t", "aos_sandbox_payload_t", "file", "read"),
    Access("aos_sandbox_host_t", "aos_sandbox_payload_t", "file", "ioctl"),
    *(
        access
        for executable in PAYLOAD_EXECUTABLE_TYPES
        for access in accesses(
            "init_t", executable, "file", ("getattr", "open", "read", "relabelto")
        )
    ),
    *(
        access
        for executable in PAYLOAD_EXECUTABLE_TYPES
        for access in accesses(
            "aos_sandbox_host_t", executable, "file", ("getattr", "open", "read")
        )
    ),
)


PROTECTED_RECORDS = (
    "aos_sandbox_network_expected_record_t",
    "aos_sandbox_network_spent_record_t",
)
PROTECTED_DIRECTORIES = (
    "aos_sandbox_network_root_t",
    "aos_sandbox_network_state_t",
    "aos_sandbox_network_store_t",
    "aos_sandbox_network_expected_staging_t",
    "aos_sandbox_network_expected_final_t",
    "aos_sandbox_network_spent_staging_t",
    "aos_sandbox_network_spent_final_t",
)
PROTECTED_ANCESTOR_DIRECTORIES = ("var_t", "var_lib_t")
PUBLICATION_DIRECTORIES = {
    "aos_sandbox_network_expected_staging_t": "aos_sandbox_network_publisher_t",
    "aos_sandbox_network_expected_final_t": "aos_sandbox_network_publisher_t",
    "aos_sandbox_network_spent_staging_t": "aos_sandbox_namespace_inspector_t",
    "aos_sandbox_network_spent_final_t": "aos_sandbox_namespace_inspector_t",
}
FINAL_DIRECTORIES = (
    "aos_sandbox_network_expected_final_t",
    "aos_sandbox_network_spent_final_t",
)
DIRECTORY_INODE_MUTATIONS = (
    "relabelfrom",
    "relabelto",
    "rename",
    "rmdir",
    "setattr",
)
RECORD_MUTATIONS = (
    "append",
    "create",
    "link",
    "relabelfrom",
    "relabelto",
    "rename",
    "setattr",
    "unlink",
    "write",
)


def negative_access() -> tuple[Access, ...]:
    """Builds the complete deny matrix for protected roles."""

    checks: list[Access] = []

    # The first PID 1 exec must enter init_t; attribute-expanded file access
    # may not let kernel_t execute the guard while retaining its old domain.
    checks.append(Access("kernel_t", "init_exec_t", "file", "execute_no_trans"))

    # Runtime roles may traverse the shared /var ancestry but cannot mutate
    # names or the directory inodes that anchor the protected topology.
    for directory in PROTECTED_ANCESTOR_DIRECTORIES:
        for domain in DOMAINS:
            checks.extend(
                accesses(
                    domain,
                    directory,
                    "dir",
                    (
                        "add_name",
                        "create",
                        "relabelfrom",
                        "relabelto",
                        "remove_name",
                        "rename",
                        "rmdir",
                        "setattr",
                        "write",
                    ),
                )
            )

    # Runtime roles cannot replace, remove, or relabel the protected store or
    # any of its four role-bearing roots. The parent cannot gain or lose names.
    for directory in PROTECTED_DIRECTORIES:
        for domain in DOMAINS:
            checks.extend(accesses(domain, directory, "dir", DIRECTORY_INODE_MUTATIONS))
    for domain in DOMAINS:
        checks.append(Access(domain, domain, "process", "setfscreate"))
        checks.extend(
            accesses(
                domain,
                "aos_sandbox_network_store_t",
                "dir",
                ("add_name", "remove_name", "write"),
            )
        )
        checks.extend(
            accesses(
                domain,
                "aos_sandbox_network_root_t",
                "dir",
                ("add_name", "remove_name", "write"),
            )
        )

    # init_t selects the dedicated transition but owns none of the protected
    # object creation or topology authority. The upstream reference policy
    # gives its unconfined init domain self:setfscreate; that permission cannot
    # name or create these deliberately non-file_type objects without one of
    # the protected accesses asserted below.
    checks.append(Access("init_t", PROVISIONER_EXECUTABLE, "file", "execute_no_trans"))
    # init_t retains ordinary base-system administration of var_t/var_lib_t.
    # It cannot create a valid protected root because it has no create,
    # relabel, or inode-mutation permission on any protected AOS type.
    for directory in PROTECTED_DIRECTORIES:
        checks.extend(
            accesses(
                "init_t",
                directory,
                "dir",
                (
                    "add_name",
                    "create",
                    "relabelfrom",
                    "relabelto",
                    "remove_name",
                    "rename",
                    "rmdir",
                    "setattr",
                    "write",
                ),
            )
        )

    # The provisioner can create directories but cannot administer mounts,
    # inspect tasks, or write any record payload.
    checks.extend(
        (
            Access(PROVISIONER_DOMAIN, "*", "capability", "sys_admin"),
            Access(PROVISIONER_DOMAIN, "*", "cap_userns", "sys_admin"),
            Access(PROVISIONER_DOMAIN, "*", "capability", "sys_ptrace"),
            Access(PROVISIONER_DOMAIN, "*", "cap_userns", "sys_ptrace"),
            Access(PROVISIONER_DOMAIN, "*", "process", "ptrace"),
        )
    )
    for record in PROTECTED_RECORDS:
        checks.extend(accesses(PROVISIONER_DOMAIN, record, "file", RECORD_MUTATIONS))

    for domain in DOMAINS:
        if domain != "aos_sandbox_network_publisher_t":
            checks.extend(
                accesses(
                    domain,
                    "aos_sandbox_network_state_t",
                    "dir",
                    ("add_name", "remove_name", "write"),
                )
            )
            checks.extend(
                accesses(
                    domain,
                    "aos_sandbox_network_state_t",
                    "file",
                    RECORD_MUTATIONS,
                )
            )

    for domain in DOMAINS:
        checks.extend(
            accesses(
                domain,
                PROVISIONER_EXECUTABLE,
                "file",
                ("entrypoint", "execute", "execute_no_trans"),
            )
        )

    # Each staging/final pair has one publisher. Other runtime roles get no
    # namespace mutation permission, and nobody can remove a final record.
    for directory, owner in PUBLICATION_DIRECTORIES.items():
        for domain in DOMAINS:
            if domain != owner:
                checks.extend(
                    accesses(
                        domain,
                        directory,
                        "dir",
                        ("add_name", "remove_name", "write"),
                    )
                )
    for directory in FINAL_DIRECTORIES:
        for domain in DOMAINS:
            checks.append(Access(domain, directory, "dir", "remove_name"))

    record_owners = {
        "aos_sandbox_network_expected_record_t": "aos_sandbox_network_publisher_t",
        "aos_sandbox_network_spent_record_t": "aos_sandbox_namespace_inspector_t",
    }
    for record in PROTECTED_RECORDS:
        owner = record_owners[record]
        for domain in DOMAINS:
            forbidden = RECORD_MUTATIONS
            if domain == owner:
                # Creation needs write and rename on the final record type;
                # fs-verity rejects content writes after sealing. MAC still
                # withholds all metadata, relabel, link, and unlink authority.
                forbidden = (
                    "append",
                    "link",
                    "relabelfrom",
                    "relabelto",
                    "setattr",
                    "unlink",
                )
            checks.extend(accesses(domain, record, "file", forbidden))

    for domain in DOMAINS:
        if domain != "aos_nspawn_t":
            checks.append(Access(domain, "*", "capability", "sys_admin"))
        checks.append(Access(domain, "*", "cap_userns", "sys_admin"))
        if domain != "aos_sandbox_namespace_inspector_t":
            checks.append(Access(domain, "*", "capability", "sys_ptrace"))
        checks.append(Access(domain, "*", "cap_userns", "sys_ptrace"))

    for source in DOMAINS:
        checks.append(Access(source, "*", "process", "ptrace"))

    # Nspawn may enter the guest domain only through the fixed bootstrap.
    # It cannot execute bootstrap without the transition or skip directly to
    # guest systemd while retaining the mount-capable supervisor domain.
    checks.append(
        Access(
            "aos_nspawn_t",
            "aos_sandbox_payload_bootstrap_exec_t",
            "file",
            "execute_no_trans",
        )
    )
    checks.append(
        Access("aos_nspawn_t", "aos_sandbox_payload_systemd_exec_t", "file", "execute")
    )

    for domain in DOMAINS:
        for executable in PAYLOAD_EXECUTABLE_TYPES:
            checks.extend(
                accesses(
                    domain,
                    executable,
                    "file",
                    ("append", "create", "relabelto", "setattr", "unlink", "write"),
                )
            )

    return tuple(sorted(set(checks)))


NEGATIVE_ACCESS = negative_access()


def allow_rules(setools: Any, policy: Any, access: Access) -> list[Any]:
    """Returns attribute-expanded allow rules matching one access tuple."""

    criteria = {
        "ruletype": [setools.TERuletype.allow],
        "source": access.source,
        "source_indirect": True,
        "tclass": [access.object_class],
        "perms": [access.permission],
    }
    if access.target != "*":
        criteria["target"] = access.target
        criteria["target_indirect"] = True

    query = setools.TERuleQuery(policy, **criteria)
    return list(query.results())


def transition_rules(setools: Any, policy: Any, transition: Transition) -> list[Any]:
    """Returns attribute-expanded process transitions matching one domain."""

    query = setools.TERuleQuery(
        policy,
        ruletype=[setools.TERuletype.type_transition],
        source=transition.source,
        source_indirect=True,
        target=transition.target,
        target_indirect=True,
        tclass=[transition.object_class],
        default=transition.default,
    )
    return list(query.results())


def transition_candidates(
    setools: Any,
    policy: Any,
    source: str,
    target: str,
    object_class: str,
) -> list[Any]:
    """Returns every transition, including disabled alternatives, for one entry point."""

    query = setools.TERuleQuery(
        policy,
        ruletype=[setools.TERuletype.type_transition],
        source=source,
        source_indirect=True,
        target=target,
        target_indirect=True,
        tclass=[object_class],
    )
    return list(query.results())


def check_policy(setools: Any, policy: Any) -> list[str]:
    """Returns deterministic evidence lines or raises on a policy mismatch."""

    evidence: list[str] = []
    for domain in ENFORCING_DOMAINS:
        if policy.lookup_type(domain).ispermissive:
            raise ValueError(f"protected domain is permissive: {domain}")
        evidence.append(f"enforcing\t{domain}")

    for transition in TRANSITIONS:
        rules = [rule for rule in transition_rules(setools, policy, transition) if rule.enabled()]
        if not rules:
            raise ValueError(
                "missing effective transition: "
                f"{transition.source} {transition.target}:"
                f"{transition.object_class} {transition.default}"
            )
        evidence.append(
            "transition\t"
            f"{transition.source}\t{transition.target}\t"
            f"{transition.object_class}\t{transition.default}"
        )

    provisioner_candidates = transition_candidates(
        setools,
        policy,
        "init_t",
        PROVISIONER_EXECUTABLE,
        "process",
    )
    unexpected = [
        rule
        for rule in provisioner_candidates
        if str(rule.default) != PROVISIONER_DOMAIN
    ]
    if unexpected:
        rendered = " | ".join(sorted(str(rule) for rule in unexpected))
        raise ValueError(f"alternate provisioner transition exists: {rendered}")
    evidence.append(
        f"exclusive-transition\tinit_t\t{PROVISIONER_EXECUTABLE}\t"
        f"process\t{PROVISIONER_DOMAIN}"
    )

    for source in FORBIDDEN_PROVISIONER_TRANSITION_SOURCES:
        rules = transition_candidates(
            setools,
            policy,
            source,
            PROVISIONER_EXECUTABLE,
            "process",
        )
        if rules:
            rendered = " | ".join(sorted(str(rule) for rule in rules))
            raise ValueError(
                f"runtime role can transition through provisioner: {source}: {rendered}"
            )
        evidence.append(
            f"deny-transition\t{source}\t{PROVISIONER_EXECUTABLE}\tprocess"
        )

    for access in POSITIVE_ACCESS:
        rules = [rule for rule in allow_rules(setools, policy, access) if rule.enabled()]
        if not rules:
            raise ValueError(f"missing effective allow: {access}")
        evidence.append(
            f"allow\t{access.source}\t{access.target}\t"
            f"{access.object_class}\t{access.permission}"
        )

    for access in NEGATIVE_ACCESS:
        rules = allow_rules(setools, policy, access)
        if rules:
            # Reject disabled conditional grants too: a Boolean change must not
            # be able to widen any protected negative asserted by this gate.
            rendered = " | ".join(sorted(str(rule) for rule in rules))
            raise ValueError(f"forbidden allow exists: {access}: {rendered}")
        evidence.append(
            f"deny\t{access.source}\t{access.target}\t"
            f"{access.object_class}\t{access.permission}"
        )

    return evidence


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parses the command-line policy path."""

    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Checks one binary policy and prints its complete evidence matrix."""

    args = parse_args(argv)
    import setools

    policy = setools.SELinuxPolicy(str(args.policy))
    for line in check_policy(setools, policy):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
