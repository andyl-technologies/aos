"""Check the effective AOS sandbox SELinux policy fail closed."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Iterable, Sequence

import fuse_worker_policy
import guest_file_policy
import owner_policy
import rule_query
import view_policy


DOMAINS = (
    "aos_sandbox_host_t",
    "aos_sandbox_network_publisher_t",
    "aos_sandbox_namespace_inspector_t",
    "aos_sandbox_network_lifecycle_worker_t",
    "aos_nspawn_t",
    "aos_sandbox_guest_owner_t",
    "aos_sandbox_payload_t",
    fuse_worker_policy.WORKER_DOMAIN,
)
PAYLOAD_EXECUTABLE_TYPES = (
    "aos_sandbox_payload_bootstrap_exec_t",
    "aos_sandbox_payload_systemd_exec_t",
)
PROVISIONER_DOMAIN = "aos_sandbox_runtime_roots_t"
HANDOFF_DOMAIN = "aos_sandbox_runtime_roots_handoff_t"
HANDOFF_EXECUTABLE = "aos_sandbox_runtime_roots_handoff_exec_t"
GUEST_OWNER = "aos_sandbox_guest_owner_t"
GUEST_TENANT = "aos_sandbox_payload_t"
GUEST_FILE_TYPE_COHORTS = guest_file_policy.cohorts(GUEST_OWNER, GUEST_TENANT)
EXPLICIT_LOADER_ATTRIBUTE = "aos_explicit_loader_domain"
EXPLICIT_LOADER_DOMAINS = (fuse_worker_policy.WORKER_DOMAIN, GUEST_OWNER, GUEST_TENANT)
NO_CONTEXT_TRANSLATION_ATTRIBUTE = "aos_no_context_translation_domain"
NO_CONTEXT_TRANSLATION_DOMAINS = (
    fuse_worker_policy.WORKER_DOMAIN,
    *owner_policy.HELPER_DOMAINS,
    *view_policy.SIGNER_DOMAINS,
)
PRIVATE_ROOT_CUSTODY_ATTRIBUTE = "aos_private_root_custody_domain"
EXPLICIT_DOMAIN_ATTRIBUTES = (
    (EXPLICIT_LOADER_ATTRIBUTE, EXPLICIT_LOADER_DOMAINS),
    (NO_CONTEXT_TRANSLATION_ATTRIBUTE, NO_CONTEXT_TRANSLATION_DOMAINS),
    (PRIVATE_ROOT_CUSTODY_ATTRIBUTE, (
        "aos_sandbox_policy_authority_t",
        "aos_nix_offline_prepare_t",
        "aos_nix_offline_tpm_helper_t",
    )),
)
GUEST_ROOT_PUBLISHER = "aos_sandbox_guest_root_publisher_t"
GUEST_PUBLICATION = "aos_sandbox_guest_publication_t"
GUEST_PROTECTED_FILES = (
    "aos_sandbox_guest_owner_exec_t",
    "aos_sandbox_guest_store_t",
    "aos_sandbox_guest_config_t",
    "aos_sandbox_guest_runtime_metadata_t",
    "aos_sandbox_guest_private_t",
    GUEST_PUBLICATION,
)
ENFORCING_DOMAINS = (
    "kernel_t",
    "init_t",
    HANDOFF_DOMAIN,
    PROVISIONER_DOMAIN,
    GUEST_ROOT_PUBLISHER,
    *DOMAINS,
    *owner_policy.ENFORCING,
)

DOMAIN_EXECUTABLES = (
    ("aos_sandbox_host_t", "aos_sandbox_host_exec_t"),
    ("aos_nspawn_t", "aos_nspawn_exec_t"),
    ("aos_sandbox_network_publisher_t", "aos_sandbox_network_publisher_exec_t"),
    ("aos_sandbox_namespace_inspector_t", "aos_sandbox_namespace_inspector_exec_t"),
    (
        "aos_sandbox_network_lifecycle_worker_t",
        "aos_sandbox_network_lifecycle_worker_exec_t",
    ),
    (HANDOFF_DOMAIN, HANDOFF_EXECUTABLE),
    (fuse_worker_policy.WORKER_DOMAIN, fuse_worker_policy.WORKER_EXECUTABLE),
    ("aos_sandbox_guest_root_publisher_t", "aos_sandbox_guest_root_publisher_exec_t"),
)
NETWORK_SERVICE_DOMAINS = (
    "aos_sandbox_network_publisher_t",
    "aos_sandbox_namespace_inspector_t",
    "aos_sandbox_network_lifecycle_worker_t",
)
NNP_FIXED_SERVICE_DOMAINS = (*NETWORK_SERVICE_DOMAINS, fuse_worker_policy.WORKER_DOMAIN)
INSPECTOR_DOMAIN = "aos_sandbox_namespace_inspector_t"
INSPECTOR_EXECUTABLE = "aos_sandbox_namespace_inspector_exec_t"
PROVISIONER_EXECUTABLE = "aos_sandbox_runtime_roots_exec_t"
FORBIDDEN_PROVISIONER_TRANSITION_SOURCES = ("init_t", *DOMAINS, GUEST_ROOT_PUBLISHER)

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
PROTECTED_OBJECT_TYPES = (*PROTECTED_DIRECTORIES, *PROTECTED_RECORDS)
GUARDED_OBJECT_TYPES = (*PROTECTED_OBJECT_TYPES, *fuse_worker_policy.WORKER_OBJECT_TYPES)


@dataclass(frozen=True, order=True)
class Access:
    """Names one source, target, object class, and permission query."""

    source: str
    target: str
    object_class: str
    permission: str


class _UnnamedFilename(Enum):
    """Distinguishes an explicitly unnamed transition from no filtering."""

    VALUE = "unnamed"


@dataclass(frozen=True, order=True)
class Transition:
    """Names a type transition; None preserves the legacy unfiltered query."""

    source: str
    target: str
    object_class: str
    default: str
    filename: str | _UnnamedFilename | None = field(default=None, repr=False)
    UNNAMED: ClassVar[_UnnamedFilename] = _UnnamedFilename.VALUE


TRANSITIONS = (
    Transition("init_t", fuse_worker_policy.WORKER_EXECUTABLE, "process", fuse_worker_policy.WORKER_DOMAIN),
    Transition(GUEST_OWNER, "devpts_t", "chr_file", "aos_sandbox_guest_pty_t"),
    Transition(GUEST_ROOT_PUBLISHER, GUEST_PUBLICATION, "file", GUEST_PUBLICATION),
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
        HANDOFF_EXECUTABLE,
        "process",
        HANDOFF_DOMAIN,
    ),
    Transition(
        HANDOFF_DOMAIN,
        PROVISIONER_EXECUTABLE,
        "process",
        PROVISIONER_DOMAIN,
    ),
    Transition("init_t", "aos_sandbox_guest_root_publisher_exec_t", "process", "aos_sandbox_guest_root_publisher_t"),
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
    # Excluding the three explicit-loader roles must not remove ordinary host
    # textrel support or weaken their membership in the base domain boundary.
    Access("init_t", "textrel_shlib_t", "file", "execmod"),
    Access("init_t", "setrans_runtime_t", "sock_file", "open"),
    Access("init_t", "aos_sandbox_guest_root_publisher_t", "process2", "nnp_transition"),
    Access("kernel_t", "init_t", "process", "transition"),
    Access("kernel_t", "init_exec_t", "file", "execute"),
    Access("init_t", "init_exec_t", "file", "entrypoint"),
    *execution_access(),
    *(
        Access("init_t", domain, "process2", "nnp_transition")
        for domain in NNP_FIXED_SERVICE_DOMAINS
    ),
    *(
        access
        for source, target, object_class, permissions in fuse_worker_policy.POSITIVE_GROUPS
        for access in accesses(source, target, object_class, permissions)
    ),
    *accesses(
        INSPECTOR_DOMAIN,
        INSPECTOR_EXECUTABLE,
        "file",
        ("execute", "map", "read"),
    ),
    # PID 1 owns the accepted socket and executable FD; runtime admission
    # narrows inherited FDs, while protected-domain ptrace remains forbidden.
    Access(INSPECTOR_DOMAIN, "init_t", "fd", "use"),
    # Type-wide inherited stream writes are narrowed by the image-pinned launch
    # and FD contract; new init_t connections and stream reads remain forbidden.
    Access(INSPECTOR_DOMAIN, "init_t", "unix_stream_socket", "write"),
    Access(INSPECTOR_DOMAIN, "security_t", "dir", "search"),
    *accesses(
        INSPECTOR_DOMAIN,
        "security_t",
        "file",
        ("getattr", "open", "read"),
    ),
    *accesses(
        HANDOFF_DOMAIN,
        PROVISIONER_EXECUTABLE,
        "file",
        ("execute", "getattr", "map", "open", "read"),
    ),
    *accesses(
        HANDOFF_DOMAIN,
        PROVISIONER_DOMAIN,
        "process",
        ("noatsecure", "rlimitinh", "siginh", "transition"),
    ),
    Access(PROVISIONER_DOMAIN, PROVISIONER_EXECUTABLE, "file", "entrypoint"),
    Access(PROVISIONER_DOMAIN, PROVISIONER_EXECUTABLE, "file", "execute"),
    Access(HANDOFF_DOMAIN, "init_t", "fd", "use"),
    Access(HANDOFF_DOMAIN, HANDOFF_EXECUTABLE, "file", "execute"),
    Access(HANDOFF_DOMAIN, HANDOFF_EXECUTABLE, "file", "read"),
    Access(HANDOFF_DOMAIN, "security_t", "security", "read_policy"),
    Access(HANDOFF_DOMAIN, "fs_t", "filesystem", "getattr"),
    Access(PROVISIONER_DOMAIN, HANDOFF_DOMAIN, "fd", "use"),
    Access(PROVISIONER_DOMAIN, PROVISIONER_EXECUTABLE, "file", "map"),
    Access(PROVISIONER_DOMAIN, PROVISIONER_EXECUTABLE, "file", "read"),
    Access(PROVISIONER_DOMAIN, PROVISIONER_DOMAIN, "process", "setfscreate"),
    *accesses(
        PROVISIONER_DOMAIN,
        "root_t",
        "dir",
        ("getattr", "open", "read", "search"),
    ),
    Access(PROVISIONER_DOMAIN, "security_t", "filesystem", "getattr"),
    Access(PROVISIONER_DOMAIN, "fs_t", "filesystem", "getattr"),
    Access(PROVISIONER_DOMAIN, "security_t", "security", "read_policy"),
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
    Access(PROVISIONER_DOMAIN, "device_t", "blk_file", "getattr"),
    Access(PROVISIONER_DOMAIN, "fixed_disk_device_t", "blk_file", "getattr"),
    *(
        Access(object_type, "fs_t", "filesystem", "associate")
        for object_type in PROTECTED_OBJECT_TYPES
    ),
    *accesses(
        PROVISIONER_DOMAIN,
        "var_t",
        "dir",
        ("add_name", "getattr", "open", "read", "search", "write"),
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
    Access("aos_nspawn_t", GUEST_OWNER, "process", "transition"),
    *accesses(
        "aos_nspawn_t", GUEST_OWNER, "process2", ("nnp_transition", "nosuid_transition")
    ),
    *accesses(
        "aos_nspawn_t",
        "aos_sandbox_guest_store_t",
        "file",
        ("execute", "getattr", "map", "open", "read"),
    ),
    *accesses(
        "aos_nspawn_t", "aos_sandbox_guest_config_t", "file", ("getattr", "open", "read")
    ),
    *accesses(
        "aos_nspawn_t",
        "aos_sandbox_guest_runtime_metadata_t",
        "file",
        ("getattr", "open", "read", "setattr", "write"),
    ),
    Access(GUEST_OWNER, GUEST_TENANT, "process", "transition"),
    *accesses(GUEST_OWNER, GUEST_TENANT, "process2", ("nnp_transition", "nosuid_transition")),
    Access(GUEST_OWNER, GUEST_OWNER, "process", "setexec"),
    *(
        Access(target, filesystem, "filesystem", "associate")
        for target in (
            *PAYLOAD_EXECUTABLE_TYPES,
            *GUEST_PROTECTED_FILES,
            "aos_sandbox_guest_anchor_t",
            "aos_sandbox_guest_tenant_data_t",
        )
        for filesystem in ("fs_t", "tmpfs_t")
    ),
    Access("aos_sandbox_guest_pty_t", "devpts_t", "filesystem", "associate"),
    *accesses(
        GUEST_OWNER,
        "init_runtime_t",
        "dir",
        ("getattr", "open", "read", "relabelfrom", "search"),
    ),
    *accesses(
        GUEST_OWNER,
        "init_runtime_t",
        "file",
        ("getattr", "open", "read", "relabelfrom"),
    ),
    *(
        access
        for subject in (GUEST_OWNER, GUEST_TENANT)
        for access in accesses(subject, "aos_sandbox_guest_pty_t", "chr_file", ("getattr", "ioctl", "open", "read", "write"))
    ),
    *accesses(
        "aos_nspawn_t",
        "aos_sandbox_payload_bootstrap_exec_t",
        "file",
        ("execute", "getattr", "map", "open", "read"),
    ),
    Access(
        GUEST_OWNER,
        "aos_sandbox_payload_bootstrap_exec_t",
        "file",
        "entrypoint",
    ),
    *accesses(
        GUEST_OWNER,
        "aos_sandbox_payload_systemd_exec_t",
        "file",
        ("execute", "execute_no_trans", "getattr", "map", "open", "read"),
    ),
    Access("aos_sandbox_host_t", "aos_sandbox_payload_t", "file", "read"),
    Access("aos_sandbox_host_t", "aos_sandbox_payload_t", "file", "ioctl"),
    *accesses("aos_sandbox_host_t", GUEST_OWNER, "file", ("ioctl", "read")),
    *accesses(
        GUEST_OWNER,
        "aos_sandbox_host_t",
        "unix_stream_socket",
        ("connectto", "getattr", "getopt", "ioctl", "read", "setopt", "shutdown", "write"),
    ),
    Access(GUEST_TENANT, GUEST_OWNER, "fd", "use"),
    *accesses(GUEST_TENANT, GUEST_OWNER, "fifo_file", ("getattr", "ioctl", "open", "read", "write")),
    *accesses(
        GUEST_TENANT,
        "aos_sandbox_guest_tenant_data_t",
        "file",
        ("entrypoint", "execute", "execute_no_trans", "getattr", "map", "open", "read", "write"),
    ),
    Access(GUEST_TENANT, "aos_sandbox_guest_store_t", "file", "entrypoint"),
    *(
        access
        for subject in (GUEST_OWNER, GUEST_TENANT)
        for access in accesses(subject, "aos_sandbox_guest_store_t", "file", ("execute", "execute_no_trans", "getattr", "map", "open", "read"))
    ),
    *(
        access
        for target in GUEST_PROTECTED_FILES
        for access in accesses(
            GUEST_ROOT_PUBLISHER, target, "file", ("getattr", "open", "read", "relabelto")
        )
    ),
    *accesses(
        GUEST_ROOT_PUBLISHER,
        GUEST_PUBLICATION,
        "dir",
        ("add_name", "getattr", "open", "read", "remove_name", "search", "write"),
    ),
    *accesses(
        GUEST_ROOT_PUBLISHER,
        GUEST_PUBLICATION,
        "file",
        ("create", "getattr", "open", "read", "rename", "setattr", "unlink", "write"),
    ),
    *(
        access
        for subject in ("aos_sandbox_host_t", GUEST_OWNER)
        for access in accesses(subject, GUEST_PUBLICATION, "file", ("getattr", "open", "read"))
    ),
    *(
        access
        for executable in PAYLOAD_EXECUTABLE_TYPES
        for access in accesses(
            "aos_sandbox_guest_root_publisher_t", executable, "file", ("getattr", "open", "read", "relabelto")
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

    for source, target, object_class, permissions in fuse_worker_policy.negative_groups(DOMAINS):
        checks.extend(accesses(source, target, object_class, permissions))

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

    # init_t selects the dedicated handoff but cannot enter the provisioner
    # directly or retain that executable without its domain transition.
    checks.append(Access("init_t", PROVISIONER_EXECUTABLE, "file", "execute"))
    checks.append(Access("init_t", PROVISIONER_DOMAIN, "process", "transition"))
    checks.append(Access(PROVISIONER_DOMAIN, HANDOFF_EXECUTABLE, "file", "entrypoint"))
    checks.append(Access("init_t", HANDOFF_EXECUTABLE, "file", "execute_no_trans"))
    for domain in (PROVISIONER_DOMAIN, *DOMAINS):
        checks.append(Access(domain, HANDOFF_EXECUTABLE, "file", "execute"))
        checks.append(Access(domain, HANDOFF_DOMAIN, "process", "transition"))

    # NNP exceptions name only PID 1 and the separately sealed fixed services.
    # A nosuid exception remains forbidden until the logical overlay launch
    # route is qualified separately from the physical EROFS diagnostic route.
    for domain in (HANDOFF_DOMAIN, PROVISIONER_DOMAIN, *DOMAINS):
        checks.append(Access("init_t", domain, "process2", "nosuid_transition"))
        if domain not in NNP_FIXED_SERVICE_DOMAINS:
            checks.append(Access("init_t", domain, "process2", "nnp_transition"))
        for network_domain in NNP_FIXED_SERVICE_DOMAINS:
            checks.extend(
                accesses(
                    domain,
                    network_domain,
                    "process2",
                    ("nnp_transition", "nosuid_transition"),
                )
            )

    # The inspector's post-transition ELF mapping stays exclusive to its own
    # domain; init_t cannot bypass the transition with execute_no_trans.
    checks.append(Access("init_t", INSPECTOR_EXECUTABLE, "file", "execute_no_trans"))
    for domain in (HANDOFF_DOMAIN, PROVISIONER_DOMAIN, *DOMAINS):
        if domain != INSPECTOR_DOMAIN:
            checks.append(Access(domain, INSPECTOR_EXECUTABLE, "file", "execute"))

    # The fixed enforcement query needs selinuxfs reads. No directory listing,
    # mutation, policy readback, or SELinux administration is delegated.
    checks.extend(accesses(INSPECTOR_DOMAIN, "security_t", "file", RECORD_MUTATIONS))
    checks.extend(
        accesses(
            INSPECTOR_DOMAIN,
            "security_t",
            "dir",
            (
                "add_name",
                "create",
                "open",
                "read",
                "remove_name",
                "write",
                *DIRECTORY_INODE_MUTATIONS,
            ),
        )
    )
    checks.extend(
        accesses(
            INSPECTOR_DOMAIN,
            "security_t",
            "security",
            ("load_policy", "read_policy", "setbool", "setenforce", "setsecparam"),
        )
    )

    # The stderr exception has no pathname-opening or new-connection authority.
    # SELinux uses unix_stream_socket for AF_UNIX stream and seqpacket sockets;
    # accepted request I/O is a separate contract, never a connect exception.
    checks.extend(
        accesses(
            INSPECTOR_DOMAIN, "init_t", "unix_stream_socket", ("connect", "connectto")
        )
    )
    checks.append(Access(INSPECTOR_DOMAIN, "init_t", "unix_stream_socket", "read"))
    checks.append(Access(INSPECTOR_DOMAIN, "tmpfs_t", "sock_file", "write"))

    # The handoff has no mount, creation, mutable topology, or return-to-init
    # authority. SELinux's init_t:fd use permission is broad; stage0's
    # close_range is what excludes inherited descriptors before transition.
    checks.extend(
        (
            Access(HANDOFF_DOMAIN, "*", "capability", "sys_admin"),
            Access(HANDOFF_DOMAIN, "*", "capability", "sys_ptrace"),
            Access(HANDOFF_DOMAIN, "init_t", "process", "transition"),
            Access(HANDOFF_DOMAIN, HANDOFF_DOMAIN, "process", "setfscreate"),
        )
    )
    for directory in (*PROTECTED_ANCESTOR_DIRECTORIES, *PROTECTED_DIRECTORIES):
        checks.extend(
            accesses(
                HANDOFF_DOMAIN,
                directory,
                "dir",
                ("add_name", "create", "remove_name", "rename", "rmdir", "setattr", "write"),
            )
        )
    for record in PROTECTED_RECORDS:
        checks.extend(accesses(HANDOFF_DOMAIN, record, "file", RECORD_MUTATIONS))
    for domain in DOMAINS:
        if domain not in (INSPECTOR_DOMAIN, fuse_worker_policy.WORKER_DOMAIN):
            checks.append(Access(domain, "init_t", "fd", "use"))
        checks.append(Access(domain, HANDOFF_DOMAIN, "fd", "use"))

    # init_t owns none of the protected
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
            Access(PROVISIONER_DOMAIN, "init_t", "fd", "use"),
            Access(PROVISIONER_DOMAIN, "*", "capability", "sys_admin"),
            Access(PROVISIONER_DOMAIN, "*", "cap_userns", "sys_admin"),
            Access(PROVISIONER_DOMAIN, "*", "capability", "sys_ptrace"),
            Access(PROVISIONER_DOMAIN, "*", "cap_userns", "sys_ptrace"),
            Access(PROVISIONER_DOMAIN, "*", "process", "ptrace"),
        )
    )
    checks.extend(
        accesses(
            PROVISIONER_DOMAIN,
            "fs_t",
            "filesystem",
            (
                "associate",
                "mount",
                "quotaget",
                "quotamod",
                "relabelfrom",
                "relabelto",
                "remount",
                "unmount",
                "watch",
            ),
        )
    )
    for object_type in PROTECTED_OBJECT_TYPES:
        checks.extend(
            accesses(
                object_type,
                "fs_t",
                "filesystem",
                (
                    "mount",
                    "quotaget",
                    "quotamod",
                    "relabelfrom",
                    "relabelto",
                    "remount",
                    "unmount",
                    "watch",
                ),
            )
        )
        checks.append(Access(object_type, "tmpfs_t", "filesystem", "associate"))
    checks.extend(
        accesses(
            PROVISIONER_DOMAIN,
            "device_t",
            "blk_file",
            ("ioctl", "open", "read", "write"),
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
    checks.append(Access("aos_nspawn_t", "aos_sandbox_guest_store_t", "file", "execute_no_trans"))
    checks.extend(accesses("aos_nspawn_t", "aos_sandbox_guest_config_t", "file", RECORD_MUTATIONS))

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
    for executable in PAYLOAD_EXECUTABLE_TYPES:
        checks.append(Access("init_t", executable, "file", "relabelto"))

    # UID-zero tenant and same-UID SSH children are different subjects. A
    # domain-pair fd:use allow for stdio cannot grant these object permissions.
    checks.extend(accesses(GUEST_TENANT, GUEST_OWNER, "file", ("read", "map", "ioctl", "write")))
    checks.extend(accesses(GUEST_TENANT, GUEST_OWNER, "process", ("ptrace", "transition", "signal", "sigkill", "sigstop")))
    checks.extend(accesses(GUEST_TENANT, GUEST_OWNER, "process2", ("nnp_transition", "nosuid_transition")))
    checks.append(Access(GUEST_TENANT, GUEST_TENANT, "process", "setexec"))
    # The adversarial VM adds a separately named, never-installed fixture
    # entry module. Its measured Owner entry grant must not enter production.
    checks.append(Access(GUEST_OWNER, "aos_sandbox_guest_owner_exec_t", "file", "entrypoint"))
    for target in GUEST_PROTECTED_FILES:
        checks.extend(accesses(GUEST_TENANT, target, "file", RECORD_MUTATIONS))
        checks.extend(accesses(GUEST_TENANT, target, "dir", (*DIRECTORY_INODE_MUTATIONS, "add_name", "remove_name", "write")))
        checks.extend(accesses(GUEST_TENANT, target, "lnk_file", ("create", "rename", "relabelto", "relabelfrom", "setattr", "unlink")))
    for subject in ("init_t", *DOMAINS):
        checks.extend(accesses(subject, GUEST_PUBLICATION, "file", RECORD_MUTATIONS))
        checks.extend(
            accesses(subject, GUEST_PUBLICATION, "dir", ("add_name", "remove_name", "write"))
        )
    checks.extend(accesses(GUEST_TENANT, "aos_sandbox_guest_anchor_t", "dir", DIRECTORY_INODE_MUTATIONS))
    checks.extend(accesses(GUEST_TENANT, "aos_sandbox_guest_private_t", "sock_file", ("open", "read", "write")))
    # Linux also checks AF_UNIX SOCK_SEQPACKET against unix_stream_socket.
    checks.extend(accesses(GUEST_TENANT, GUEST_OWNER, "unix_stream_socket", ("connectto", "read", "write")))
    checks.extend(accesses(GUEST_TENANT, "cgroup_t", "file", ("write", "append", "setattr")))
    checks.extend(accesses(GUEST_TENANT, "cgroup_t", "dir", ("add_name", "remove_name", "create", "write", "setattr")))
    checks.extend(accesses(GUEST_OWNER, "aos_sandbox_guest_tenant_data_t", "file", ("read", "map", "execute_no_trans")))
    checks.extend(accesses(GUEST_OWNER, "file_type", "file", ("read", "map", "execute_no_trans")))
    checks.extend(accesses(GUEST_TENANT, "file_type", "file", ("entrypoint", "execute", "execute_no_trans", "map", "open", "read")))

    return tuple(sorted(set(checks)))


OWNER_POSITIVE, OWNER_NEGATIVE, OWNER_TRANSITIONS = owner_policy.matrix(
    Access, Transition, accesses, DOMAINS,
)
POSITIVE_ACCESS = (*POSITIVE_ACCESS, *OWNER_POSITIVE)
TRANSITIONS = (*TRANSITIONS, *OWNER_TRANSITIONS)
NEGATIVE_ACCESS = (*negative_access(), *OWNER_NEGATIVE)


def allow_rules(setools: Any, policy: Any, access: Access) -> list[Any]:
    """Returns attribute-expanded allow rules matching one access tuple."""

    criteria = {
        "ruletype": [setools.TERuletype.allow],
        "source_indirect": True,
        "tclass": [access.object_class],
        "perms": [access.permission],
    }
    if access.source != "*":
        criteria["source"] = access.source
    if access.target != "*":
        criteria["target"] = access.target
        criteria["target_indirect"] = True

    query = setools.TERuleQuery(policy, **criteria)
    return list(query.results())


def transition_rules(setools: Any, policy: Any, transition: Transition) -> list[Any]:
    """Returns the same expanded query, optionally selecting its actual name."""

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
    return _transition_filename_rules(setools, list(query.results()), transition.filename)


def transition_candidates(
    setools: Any,
    policy: Any,
    source: str,
    target: str,
    object_class: str,
    *,
    filename: str | _UnnamedFilename | None = None,
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
    return _transition_filename_rules(setools, list(query.results()), filename)


def _transition_filename_rules(
    setools: Any,
    rules: list[Any],
    filename: str | _UnnamedFilename | None,
) -> list[Any]:
    """Filters real filename properties without replacing SETools matching."""

    if filename is None:
        # Old queries must never inspect a filename or alter rule ordering.
        return rules
    if filename is not Transition.UNNAMED and not isinstance(filename, str):
        raise ValueError("unsupported transition filename selector")

    matching = []
    for rule in rules:
        try:
            observed = rule.filename
        except setools.exception.TERuleNoFilename:
            if filename is Transition.UNNAMED:
                matching.append(rule)
        else:
            if not isinstance(observed, str):
                raise ValueError("unsupported transition filename observation")
            if observed == filename:
                matching.append(rule)
    return matching


def attribute_members(setools: Any, policy: Any, name: str) -> set[str]:
    """Returns one effective attribute's expanded members, rejecting ambiguity."""

    attributes = list(setools.TypeAttributeQuery(policy, name=name).results())
    if len(attributes) != 1:
        raise ValueError(f"effective policy must contain exactly one {name} attribute")
    return {str(member) for member in attributes[0].expand()}


def _check_selected_launcher_image_ioctls(setools: Any, policy: Any) -> list[str]:
    """Checks the closed image cells using complete native ioctl selector sets.

    Empty expected DATA still rejects base and extended grants in every branch.
    This offline matrix observes 16-bit MAC selectors, not the full native ioctl
    command or the provenance/currentness of an actual received image FD.
    """

    cells = owner_policy.SELECTED_LAUNCHER_IMAGE_IOCTL_CELLS
    selectors = owner_policy.SELECTED_LAUNCHER_IMAGE_IOCTL_SELECTORS
    if type(selectors) is not frozenset or (selectors and selectors != {0x6686}):
        raise ValueError("unsupported selected-launcher ioctl expectation")

    image_target = cells[0][1]
    if str(policy.lookup_type(image_target)) != image_target:
        raise ValueError(f"selected-launcher image target is aliased: {image_target}")

    for source, _ in cells:
        try:
            observed = policy.lookup_type(source)
        except setools.exception.InvalidType as error:
            if selectors:
                raise ValueError(
                    f"missing selected-launcher image source: {source}"
                ) from error
        else:
            if str(observed) != source:
                raise ValueError(f"selected-launcher image source is aliased: {source}")

    # Regex criteria do not look up absent source types. Native indirect
    # matching still expands real attributes; never skip the default scan.
    source_pattern = (
        "^(?:" + "|".join(re.escape(source) for source, _ in cells) + ")$"
    )
    permitted_pairs = set(cells) if selectors else set()
    enabled_base_pairs: set[tuple[str, str]] = set()
    enabled_selectors = {cell: set() for cell in cells}

    for rule_type in (setools.TERuletype.allow, setools.TERuletype.allowxperm):
        query = setools.TERuleQuery(
            policy,
            ruletype=[rule_type],
            source=source_pattern,
            source_regex=True,
            source_indirect=True,
            target=image_target,
            target_indirect=True,
            tclass=["file"],
            perms=["ioctl"],
        )
        for rule in query.results():
            sources = {str(source) for source in rule.source.expand()}
            targets = {str(target) for target in rule.target.expand()}
            pairs = {(source, target) for source in sources for target in targets}
            if not pairs or pairs - permitted_pairs:
                raise ValueError(f"forbidden selected-launcher image ioctl grant: {rule}")

            if rule_type == setools.TERuletype.allow:
                if rule.enabled():
                    enabled_base_pairs.update(pairs)
                continue

            # Querying only 0x6686 would hide an excess range or driver grant.
            # Preserve the full native integer set, including inactive rules.
            observed_selectors = set(rule.perms)
            if (
                rule.xperm_type != "ioctl"
                or not observed_selectors
                or any(type(selector) is not int for selector in observed_selectors)
                or observed_selectors - selectors
            ):
                raise ValueError(
                    f"forbidden selected-launcher image ioctl selectors: {rule}"
                )
            if rule.enabled():
                for pair in pairs:
                    enabled_selectors[pair].update(observed_selectors)

    evidence = []
    for source, target in cells:
        if not selectors:
            continue
        pair = (source, target)
        if pair not in enabled_base_pairs:
            raise ValueError(f"missing selected-launcher base ioctl: {source} {target}")
        if enabled_selectors[pair] != selectors:
            raise ValueError(f"missing selected-launcher ioctl selectors: {source} {target}")
        evidence.append(f"allowxperm\t{source}\t{target}\tfile\tioctl\t0x6686")

    return evidence


def check_policy(setools: Any, policy: Any, *, git_read_delegation: bool = False) -> list[str]:
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
        line = (
            "transition\t"
            f"{transition.source}\t{transition.target}\t"
            f"{transition.object_class}\t{transition.default}"
        )
        if transition.filename is not None:
            name = (
                "<unnamed>"
                if transition.filename is Transition.UNNAMED
                else transition.filename
            )
            line += f"\tfilename={name}"
        evidence.append(line)

    # Reject all alternatives, including disabled rules; generic promotion
    # must not satisfy any of the three literal-name delivery checks.
    storage_credential = owner_policy.STORAGE_CREDENTIAL
    candidates = transition_candidates(
        setools, policy, "init_t", storage_credential, "file",
    )
    permitted = _transition_filename_rules(setools, candidates, Transition.UNNAMED)
    permitted = [rule for rule in permitted if str(rule.default) == "init_tmpfs_t"]
    for name in owner_policy.STORAGE_CREDENTIAL_NAMES:
        permitted.extend(
            rule for rule in _transition_filename_rules(setools, candidates, name)
            if str(rule.default) == storage_credential
        )
    if any(rule not in permitted for rule in candidates):
        raise ValueError("unexpected Storage credential delivery transition")
    evidence.append("exclusive-storage-credential-transitions")

    # Explicit normal-unit contexts must not promote another shared-ELF mode.
    for domain in owner_policy.NO_DEFAULT_ENTRY:
        query = setools.TERuleQuery(
            policy,
            ruletype=[setools.TERuletype.type_transition],
            source_indirect=True,
            target_indirect=True,
            tclass=["process"],
            default=domain,
        )
        if list(query.results()):
            raise ValueError(f"normal owner has automatic entry transition: {domain}")
        evidence.append(f"deny-default-entry\t{domain}")

    # Scan all sources, including attributes and domains not named by AOS.
    # A finite AOS role list cannot establish the Root nondelegation boundary.
    root = "aos_sandbox_policy_authority_t"
    for object_class, permission in owner_policy.ROOT_CUSTODY_CUTS:
        for rule in allow_rules(setools, policy, Access("*", root, object_class, permission)):
            source = rule.source
            expanded = source.expand() if hasattr(source, "expand") else (source,)
            permitted_sources = (
                {"init_t"}
                if (object_class, permission) == ("process", "transition")
                else {root, "init_t", "kernel_t"}
            )
            if {str(value) for value in expanded} - permitted_sources:
                raise ValueError(f"foreign normal Root custody grant exists: {rule}")
        evidence.append(f"deny-foreign-root\t{object_class}\t{permission}")

    provisioner_candidates = transition_candidates(
        setools,
        policy,
        HANDOFF_DOMAIN,
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
        f"exclusive-transition\t{HANDOFF_DOMAIN}\t{PROVISIONER_EXECUTABLE}\t"
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

    domains = attribute_members(setools, policy, "domain")
    for attribute, required_domains in EXPLICIT_DOMAIN_ATTRIBUTES:
        members = attribute_members(setools, policy, attribute)
        if members != set(required_domains):
            raise ValueError(f"unexpected {attribute} membership: {sorted(members)}")
        for domain in required_domains:
            if domain not in domains:
                raise ValueError(f"protected role lost domain membership: {domain}")
            evidence.append(f"member-attribute\t{domain}\t{attribute}")
            evidence.append(f"member-attribute\t{domain}\tdomain")

    file_types = attribute_members(setools, policy, "file_type")
    for attribute, members in (("domain", domains), ("file_type", file_types)):
        source = owner_policy.STORAGE_CREDENTIAL_SOURCE
        if source in members:
            raise ValueError(f"Storage credential source inherited {attribute}")
        evidence.append(f"deny-attribute\t{source}\t{attribute}")
    guest_file_policy.validate_names(policy, file_types)
    for object_type in GUARDED_OBJECT_TYPES:
        if object_type in file_types:
            raise ValueError(f"protected object inherited broad file_type: {object_type}")
        evidence.append(f"deny-attribute\t{object_type}\tfile_type")

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
        cohort = GUEST_FILE_TYPE_COHORTS.get((access.source, access.permission))
        if (
            access.target == "file_type"
            and access.object_class == "file"
            and cohort is not None
        ):
            violations = guest_file_policy.violations(rules, file_types, cohort)
            if violations:
                rendered = " | ".join(violations)
                raise ValueError(
                    "forbidden allow exists outside Guest file_type cohort: "
                    f"{access}: {rendered}"
                )
            evidence.append(
                f"deny-file-type-cohort\t{access.source}\tfile\t{access.permission}\t"
                f"allowed={','.join(sorted(cohort))}"
            )
            continue

        if rules:
            # Reject disabled conditional grants too: a Boolean change must not
            # be able to widen any protected negative asserted by this gate.
            rendered = " | ".join(sorted(str(rule) for rule in rules))
            raise ValueError(f"forbidden allow exists: {access}: {rendered}")
        evidence.append(
            f"deny\t{access.source}\t{access.target}\t"
            f"{access.object_class}\t{access.permission}"
        )

    evidence.extend(_check_selected_launcher_image_ioctls(setools, policy))
    if git_read_delegation:
        evidence.extend(_check_git_read_delegation(setools, policy))
    return evidence


def _check_git_read_delegation(setools: Any, policy: Any) -> list[str]:
    """Checks selected IPC/task cells without changing the default matrix."""

    runtime = owner_policy.GIT_READ_RUNTIME
    if str(policy.lookup_type(runtime)) != runtime:
        raise ValueError("Git inspection IPC type is aliased")
    for attribute in ("domain", "file_type"):
        if runtime in attribute_members(setools, policy, attribute):
            raise ValueError(f"Git inspection IPC inherited {attribute}")
    positive, negative, transitions = owner_policy.git_read_matrix(
        Access, Transition, accesses, DOMAINS,
    )
    for transition in transitions:
        if not any(rule.enabled() for rule in transition_rules(setools, policy, transition)):
            raise ValueError(f"missing selected Git transition: {transition}")
    for access in positive:
        if not any(rule.enabled() for rule in allow_rules(setools, policy, access)):
            raise ValueError(f"missing selected Git allow: {access}")
    for access in negative:
        if allow_rules(setools, policy, access):
            raise ValueError(f"forbidden selected Git allow exists: {access}")
    return ["git-read-delegation\tselected-fixed-inspection-only"]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parses the command-line policy path."""

    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("--git-read-delegation", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Checks one binary policy and prints its complete evidence matrix."""

    args = parse_args(argv)
    import setools

    policy = setools.SELinuxPolicy(str(args.policy))
    queries = rule_query.IndexedPolicyQueries(setools, policy)
    for line in check_policy(queries, policy, git_read_delegation=args.git_read_delegation):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
