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
)

DOMAIN_EXECUTABLES = (
    ("aos_sandbox_host_t", "aos_sandbox_host_exec_t"),
    ("aos_sandbox_network_publisher_t", "aos_sandbox_network_publisher_exec_t"),
    ("aos_sandbox_namespace_inspector_t", "aos_sandbox_namespace_inspector_exec_t"),
    (
        "aos_sandbox_network_lifecycle_worker_t",
        "aos_sandbox_network_lifecycle_worker_exec_t",
    ),
)


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
    Transition("init_t", "aos_sandbox_host_exec_t", "process", "aos_sandbox_host_t"),
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
    *execution_access(),
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
)


PROTECTED_RECORDS = (
    "aos_sandbox_network_expected_record_t",
    "aos_sandbox_network_spent_record_t",
)
PROTECTED_DIRECTORIES = (
    "aos_sandbox_network_store_t",
    "aos_sandbox_network_expected_staging_t",
    "aos_sandbox_network_expected_final_t",
    "aos_sandbox_network_spent_staging_t",
    "aos_sandbox_network_spent_final_t",
)
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

    # Runtime roles cannot replace, remove, or relabel the protected store or
    # any of its four role-bearing roots. The parent cannot gain or lose names.
    for directory in PROTECTED_DIRECTORIES:
        for domain in DOMAINS:
            checks.extend(accesses(domain, directory, "dir", DIRECTORY_INODE_MUTATIONS))
    for domain in DOMAINS:
        checks.extend(
            accesses(
                domain,
                "aos_sandbox_network_store_t",
                "dir",
                ("add_name", "remove_name", "write"),
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
        checks.append(Access(domain, "*", "capability", "sys_admin"))
        checks.append(Access(domain, "*", "cap_userns", "sys_admin"))
        if domain != "aos_sandbox_namespace_inspector_t":
            checks.append(Access(domain, "*", "capability", "sys_ptrace"))
        checks.append(Access(domain, "*", "cap_userns", "sys_ptrace"))

    for source in DOMAINS:
        checks.append(Access(source, "*", "process", "ptrace"))

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


def check_policy(setools: Any, policy: Any) -> list[str]:
    """Returns deterministic evidence lines or raises on a policy mismatch."""

    evidence: list[str] = []
    for domain in DOMAINS:
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
