"""Checks Guest access to the concrete members of refpolicy's file_type.

An indirect attribute query matches any overlapping member, not just blanket
attribute grants. These fixed, permission-specific cohorts admit the existing
kernel/control reads without accepting unrelated host data or executable files.
Custom Guest object types remain subject to the separate typed access matrix.
"""

from typing import Any, Iterable


OWNER_CONTROL_READ_TYPES = frozenset((
    "cgroup_t",
    "init_runtime_t",
    "proc_t",
    "security_t",
    "sysfs_t",
    "tmpfs_t",
    "cpu_online_t",
))


def cohorts(owner: str, tenant: str) -> dict[tuple[str, str], frozenset[str]]:
    """Returns the fixed exceptions to the existing Guest file_type denials."""

    empty = frozenset()
    return {
        (owner, "read"): OWNER_CONTROL_READ_TYPES,
        (owner, "map"): empty,
        (owner, "execute_no_trans"): empty,
        (tenant, "entrypoint"): empty,
        (tenant, "execute"): empty,
        (tenant, "execute_no_trans"): empty,
        (tenant, "map"): empty,
        # Pinned domain.te calls dev_read_cpu_online for every domain; this
        # exact sysfs inode is not a generic host-file read capability.
        (tenant, "open"): frozenset(("cpu_online_t",)),
        (tenant, "read"): frozenset(("cpu_online_t",)),
    }


def validate_names(policy: Any, file_types: set[str]) -> None:
    """Rejects missing, aliased or non-file_type exception names."""

    for name in sorted(OWNER_CONTROL_READ_TYPES):
        if str(policy.lookup_type(name)) != name or name not in file_types:
            raise ValueError(f"Guest file_type cohort is not a canonical member: {name}")


def violations(
    rules: Iterable[Any], file_types: set[str], allowed: frozenset[str]
) -> list[str]:
    """Reports forbidden concrete members, including disabled conditional grants."""

    forbidden = []
    for rule in rules:
        targets = {str(target) for target in rule.target.expand()}
        unexpected = (targets & file_types) - allowed
        if unexpected:
            forbidden.append(f"{rule}; unexpected file_type members={sorted(unexpected)}")

    return sorted(forbidden)
