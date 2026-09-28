"""Expected effective matrix for existing normal owners and private TPM helpers.

This is data for the existing SETools checker, not a second checker or an
installed-policy/currentness producer. Missing preparation and credential
label delivery are deliberately not papered over with init-domain grants.
"""

import view_policy


OWNERS = ("controller", "storage", "policy_authority")
HELPERS = ("controller", "storage")
OWNER_DOMAINS = tuple(f"aos_sandbox_{role}_t" for role in OWNERS)
HELPER_DOMAINS = tuple(f"aos_method46_{role}_helper_t" for role in HELPERS)
PREPARER_DOMAINS = (
    "aos_sandbox_cache_view_preparer_t",
    "aos_sandbox_source_view_preparer_t",
)
ENFORCING = (*OWNER_DOMAINS, *HELPER_DOMAINS, *PREPARER_DOMAINS, *view_policy.SIGNER_DOMAINS)
NO_DEFAULT_ENTRY = (*OWNER_DOMAINS, *PREPARER_DOMAINS, *view_policy.SIGNER_DOMAINS)
ROOT_CUSTODY_CUTS = (
    ("fd", "use"),
    ("unix_stream_socket", "read"),
    ("unix_stream_socket", "write"),
    ("file", "open"),
    ("file", "read"),
    ("file", "ioctl"),
    ("process", "ptrace"),
    ("process", "transition"),
)


def matrix(Access, Transition, accesses, ordinary_domains):
    """Returns queries consumed by the one shared attribute-expanded checker."""

    positive = []
    negative = []
    transitions = []
    all_roles = (
        *ordinary_domains,
        *ENFORCING,
        "aos_sandbox_guest_root_publisher_t",
        "init_t",
    )
    file_read = ("getattr", "open", "read")
    file_mutate = (
        "append", "create", "link", "lock", "rename", "setattr", "unlink", "write"
    )
    dir_mutate = (
        "add_name", "create", "remove_name", "rename", "rmdir", "setattr", "write"
    )

    for role, domain in zip(OWNERS, OWNER_DOMAINS):
        executable = f"aos_sandbox_{role}_exec_t"
        credential = f"aos_sandbox_{role}_credential_t"
        state = f"aos_sandbox_{role}_state_t"
        runtime = f"aos_sandbox_{role}_runtime_t"

        positive.extend(accesses(
            "init_t", executable, "file",
            ("execute", "execute_no_trans", "getattr", "map", "open", "read"),
        ))
        positive.extend((
            Access("init_t", domain, "process", "transition"),
            Access("init_t", domain, "process2", "nnp_transition"),
            Access(domain, executable, "file", "entrypoint"),
        ))
        positive.extend(accesses(domain, credential, "file", file_read))
        positive.extend(accesses(
            domain, state, "file",
            ("append", "create", "getattr", "lock", "open", "read", "rename", "setattr", "unlink", "write"),
        ))
        positive.extend(accesses(
            domain, state, "dir",
            ("add_name", "getattr", "open", "read", "remove_name", "search", "write"),
        ))
        positive.extend(accesses(domain, "sysctl_kernel_t", "file", file_read))
        positive.extend(accesses(domain, "cgroup_t", "file", file_read))
        positive.extend((
            Access(domain, "proc_t", "filesystem", "getattr"),
            Access(domain, "security_t", "filesystem", "getattr"),
        ))
        positive.extend(accesses(
            domain, "null_device_t", "chr_file", ("getattr", "open", "read", "write"),
        ))
        positive.extend((
            Access(domain, "init_t", "system", "status"),
            Access(domain, "systemd_unit_t", "service", "status"),
        ))
        transitions.append(Transition(domain, state, "file", state))
        transitions.append(Transition(domain, runtime, "sock_file", runtime))

        for other in all_roles:
            if other == domain:
                continue
            for object_type in (state, credential):
                negative.extend(accesses(other, object_type, "file", file_mutate))
                negative.extend(accesses(other, object_type, "dir", dir_mutate))
                negative.extend(accesses(other, object_type, "file", ("open", "read")))
        for permission in ("start", "stop", "reload", "enable", "disable"):
            negative.append(Access(domain, "*", "service", permission))
        for permission in ("start", "stop", "reload", "reboot", "halt"):
            negative.append(Access(domain, "*", "system", permission))
        negative.extend(accesses(
            domain, "cgroup_t", "file", ("append", "create", "setattr", "unlink", "write"),
        ))
        negative.extend(accesses(
            domain, "sysctl_kernel_t", "file", ("append", "setattr", "write"),
        ))
        negative.append(Access(domain, "aos_method46_tpm_device_t", "chr_file", "open"))

    root = "aos_sandbox_policy_authority_t"
    positive.extend(accesses(root, "init_exec_t", "file", ("getattr", "read")))
    positive.extend(accesses(root, root, "lnk_file", ("getattr", "read")))
    profile = "aos_sandbox_policy_authority_profile_t"
    for reader in (root, "init_t"):
        positive.extend(accesses(reader, profile, "file", file_read))
    for source in all_roles:
        negative.extend(accesses(source, profile, "file", file_mutate + ("execute", "execute_no_trans", "map")))
    # Preserve precisely the trusted PID 1 inspection removed from the generic
    # interface. This is the pinned refpolicy permission expansion, not a new
    # privileged peer or an exception to the all-source custody cut.
    for object_class, permissions in (
        ("dir", ("getattr", "search", "open", "read", "lock", "ioctl")),
        ("file", ("getattr", "open", "read", "lock", "ioctl")),
        ("lnk_file", ("getattr", "read")),
    ):
        positive.extend(accesses("init_t", root, object_class, permissions))

    for other in all_roles:
        if other == root or other == "init_t":
            continue
        negative.extend(accesses(other, root, "file", ("ioctl", "open", "read")))
        negative.append(Access(other, root, "fd", "use"))
        negative.extend(accesses(other, root, "unix_stream_socket", ("read", "write")))
        negative.append(Access(other, root, "process", "transition"))
    positive.append(Access(
        "aos_sandbox_controller_t", root, "unix_stream_socket", "connectto",
    ))
    positive.extend(accesses(
        "aos_sandbox_controller_t", "aos_sandbox_policy_authority_runtime_t",
        "sock_file", file_read + ("write",),
    ))
    negative.append(Access(root, "*", "file", "execute_no_trans"))

    provisioner = "aos_sandbox_runtime_roots_t"
    positive.append(Access(provisioner, provisioner, "capability", "chown"))
    for object_type, permissions in (
        (
            "aos_sandbox_controller_state_t",
            ("add_name", "create", "getattr", "open", "read", "search", "setattr", "write"),
        ),
        (
            "aos_method46_controller_floor_t",
            ("create", "getattr", "open", "read", "search", "setattr"),
        ),
        (
            "aos_sandbox_storage_state_t",
            ("add_name", "create", "getattr", "open", "read", "search", "write"),
        ),
        (
            "aos_method46_storage_floor_t",
            ("create", "getattr", "open", "read", "search"),
        ),
    ):
        positive.extend(accesses(provisioner, object_type, "dir", permissions))
        negative.extend(accesses(
            provisioner, object_type, "file", ("open", "read", *file_mutate),
        ))
    for object_type in ("aos_sandbox_storage_state_t", "aos_method46_storage_floor_t"):
        negative.append(Access(provisioner, object_type, "dir", "setattr"))

    for role, helper in zip(HELPERS, HELPER_DOMAINS):
        owner = f"aos_sandbox_{role}_t"
        lock = f"aos_method46_{role}_lock_t"
        floor = f"aos_method46_{role}_floor_t"
        transitions.append(Transition(owner, "aos_method46_helper_exec_t", "process", helper))
        transitions.append(Transition(owner, floor, "file", floor))
        positive.extend(accesses(
            owner, "aos_method46_helper_exec_t", "file",
            ("execute", "getattr", "map", "open", "read"),
        ))
        positive.extend((
            Access(owner, helper, "process", "transition"),
            Access(owner, helper, "process2", "nnp_transition"),
            Access(helper, "aos_method46_helper_exec_t", "file", "entrypoint"),
            Access(helper, owner, "fd", "use"),
        ))
        positive.extend(accesses(owner, helper, "file", file_read))
        positive.extend(accesses(
            helper, owner, "unix_stream_socket",
            ("getattr", "getopt", "read", "setopt", "write"),
        ))
        positive.extend(accesses(helper, lock, "file", ("getattr", "read", "write")))
        positive.extend((
            Access(helper, "proc_t", "filesystem", "getattr"),
            Access(helper, "security_t", "filesystem", "getattr"),
        ))
        positive.extend(accesses(
            helper, "aos_method46_tpm_device_t", "chr_file",
            ("getattr", "open", "read", "write"),
        ))
        negative.extend(accesses(
            helper, lock, "file",
            ("open", "lock", "append", "setattr", "rename", "unlink", "ioctl"),
        ))
        negative.extend(accesses(helper, floor, "file", ("open", "read", *file_mutate)))
        negative.extend(accesses(
            helper, "*", "unix_stream_socket", ("connect", "connectto", "create", "listen"),
        ))
        negative.append(Access(helper, "*", "file", "execute_no_trans"))
        negative.append(Access(helper, "aos_method46_tpm_device_t", "chr_file", "ioctl"))
        for other in all_roles:
            if other != owner:
                negative.append(Access(other, helper, "process", "transition"))
            if other not in (owner, helper):
                negative.extend(accesses(other, lock, "file", ("open", "read", *file_mutate)))
                negative.extend(accesses(other, floor, "file", ("open", "read", *file_mutate)))
        for foreign_role in HELPERS:
            if foreign_role != role:
                negative.append(Access(helper, f"aos_sandbox_{foreign_role}_t", "fd", "use"))
        negative.append(Access(helper, "aos_method46_helper_exec_t", "file", "execute"))

    for domain in ENFORCING:
        negative.extend(accesses(domain, "security_t", "file", ("append", "setattr", "write")))
        negative.extend(accesses(
            domain, "security_t", "security",
            ("load_policy", "setenforce", "setbool", "setsecparam"),
        ))
        negative.extend(accesses(domain, "*", "process", ("setexec", "setfscreate")))
        negative.append(Access(domain, "*", "process", "ptrace"))
        negative.append(Access(domain, "*", "process", "dyntransition"))
        negative.append(Access(domain, "*", "process", "setsockcreate"))
        negative.append(Access(domain, "*", "capability", "sys_ptrace"))
        negative.append(Access(domain, "*", "cap_userns", "sys_ptrace"))
        if domain not in PREPARER_DOMAINS:
            negative.append(Access(domain, "*", "capability", "sys_admin"))
            negative.append(Access(domain, "*", "cap_userns", "sys_admin"))

    view_positive, view_negative, view_transitions = view_policy.matrix(Access, Transition, accesses, all_roles)
    positive.extend(view_positive)
    negative.extend(view_negative)
    transitions.extend(view_transitions)
    return tuple(sorted(set(positive))), tuple(sorted(set(negative))), tuple(transitions)
