"""Expected effective matrix for existing normal owners and private TPM helpers.

This is data for the existing SETools checker, not a second checker or an
installed-policy/currentness producer. PID 1's explicit Root and Controller
credential delivery exceptions grant no owner state access or preparation
authority.
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
GATEWAY = "aos_sandbox_git_gateway_t"
GATEWAY_EXECUTABLE = "aos_sandbox_git_gateway_exec_t"
GATEWAY_CREDENTIAL = "aos_sandbox_git_gateway_credential_t"
OFFLINE_PREPARE = "aos_nix_offline_prepare_t"
OFFLINE_PREPARE_EXECUTABLE = "aos_nix_offline_prepare_exec_t"
OFFLINE_PREPARE_PROFILE = "aos_nix_offline_prepare_profile_t"
OFFLINE_PREPARE_CREDENTIAL = "aos_nix_offline_prepare_credential_t"
OFFLINE_PREPARE_STATE = "aos_nix_offline_prepare_state_t"
ENFORCING = (*OWNER_DOMAINS, *HELPER_DOMAINS, *PREPARER_DOMAINS, *view_policy.SIGNER_DOMAINS, GATEWAY, OFFLINE_PREPARE)
NO_DEFAULT_ENTRY = (*OWNER_DOMAINS, *PREPARER_DOMAINS, *view_policy.SIGNER_DOMAINS, GATEWAY, OFFLINE_PREPARE)
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

CREDENTIAL_PID1_FILE_DELIVERY = (
    "create", "getattr", "open", "read", "setattr", "unlink", "write",
)
CREDENTIAL_PID1_DIR_DELIVERY = (
    "add_name", "create", "getattr", "mounton", "open", "read", "relabelto",
    "remove_name", "search", "setattr", "write",
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
                if role in ("controller", "policy_authority") and other == "init_t" and object_type == credential:
                    negative.extend(accesses(other, object_type, "file", tuple(
                        permission for permission in (*file_mutate, "open", "read")
                        if permission not in CREDENTIAL_PID1_FILE_DELIVERY
                    )))
                    negative.extend(accesses(other, object_type, "dir", tuple(
                        permission for permission in dir_mutate
                        if permission not in CREDENTIAL_PID1_DIR_DELIVERY
                    )))
                else:
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

    # Actual Storage startup selects these read-only manager/task/fragment
    # observations; these type-wide cells are not pathname or owner authority.
    storage = "aos_sandbox_storage_t"
    for target in ("init_exec_t", "systemd_unit_t", "etc_t"):
        positive.extend(accesses(storage, target, "file", file_read))
    positive.extend((
        Access(storage, "init_t", "dir", "search"),
        Access(storage, "init_t", "lnk_file", "read"),
        Access(storage, "init_t", "file", "read"),
    ))
    for target in ("init_exec_t", "systemd_unit_t"):
        negative.extend(accesses(storage, target, "file", (
            *file_mutate, "execute", "execute_no_trans", "entrypoint", "map",
            "ioctl", "relabelfrom", "relabelto",
        )))
    negative.extend(accesses(storage, "init_t", "file", (
        *file_mutate, "getattr", "open", "map", "ioctl", "relabelfrom", "relabelto",
    )))
    negative.extend(accesses(storage, "init_t", "dir", (
        *dir_mutate, "getattr", "open", "read", "ioctl", "lock",
        "relabelfrom", "relabelto",
    )))
    negative.extend(accesses(storage, "init_t", "lnk_file", (
        "create", "getattr", "rename", "setattr", "unlink", "write",
        "relabelfrom", "relabelto",
    )))
    for target in ("usr_t", "proc_t"):
        negative.extend(accesses(storage, target, "file", file_read))

    # Gateway is not a writer-owning OWNERS role. The same checker observes
    # its sole explicit entry, transport/readback cells and authority denials.
    positive.extend(accesses(
        "init_t", GATEWAY_EXECUTABLE, "file",
        ("execute", "execute_no_trans", "getattr", "map", "open", "read"),
    ))
    positive.extend((
        Access("init_t", GATEWAY, "process", "transition"),
        Access("init_t", GATEWAY, "process2", "nnp_transition"),
        Access(GATEWAY, GATEWAY_EXECUTABLE, "file", "entrypoint"),
        Access(GATEWAY_CREDENTIAL, "tmpfs_t", "filesystem", "associate"),
        Access(GATEWAY, "systemd_unit_t", "service", "status"),
        Access(GATEWAY, "init_t", "system", "status"),
        Access(GATEWAY, "proc_t", "filesystem", "getattr"),
        Access(GATEWAY, "security_t", "filesystem", "getattr"),
        Access(GATEWAY, "node_t", "tcp_socket", "node_bind"),
        Access(GATEWAY, "unreserved_port_type", "tcp_socket", "name_bind"),
        Access(GATEWAY, "unlabeled_t", "tcp_socket", "recvfrom"),
        Access(GATEWAY, "unlabeled_t", "peer", "recv"),
    ))
    for target in (GATEWAY_CREDENTIAL, "cgroup_t", "sysctl_kernel_t", "systemd_unit_t", "usr_t", "security_t"):
        positive.extend(accesses(GATEWAY, target, "file", file_read))
    # Type-wide global-proc DATA reads, not fixed-path authorization. The
    # startup owner selects and retains only the genuine meminfo producer.
    positive.extend(accesses(GATEWAY, "proc_t", "file", file_read))
    negative.extend(accesses(GATEWAY, "proc_t", "file", file_mutate))
    positive.extend(accesses(
        GATEWAY, GATEWAY, "tcp_socket",
        ("accept", "bind", "create", "getattr", "getopt", "listen", "read", "setopt", "shutdown", "write"),
    ))
    positive.extend(accesses(GATEWAY, "netif_t", "netif", ("egress", "ingress")))
    positive.extend(accesses(GATEWAY, "node_t", "node", ("recvfrom", "sendto")))
    positive.extend(accesses(GATEWAY, "unlabeled_t", "packet", ("recv", "send")))

    for permission in ("start", "stop", "reload", "enable", "disable"):
        negative.append(Access(GATEWAY, "*", "service", permission))
    for permission in ("start", "stop", "reload", "reboot", "halt"):
        negative.append(Access(GATEWAY, "*", "system", permission))
    for target in (
        "cgroup_t", "sysctl_kernel_t", "aos_sandbox_source_journal_t",
        "aos_sandbox_cache_journal_t", "aos_sandbox_cache_object_t",
        *(f"aos_sandbox_{role}_state_t" for role in OWNERS),
    ):
        negative.extend(accesses(GATEWAY, target, "file", file_mutate))
        negative.extend(accesses(GATEWAY, target, "dir", dir_mutate))
    for target in (
        "aos_sandbox_source_journal_t", "aos_sandbox_cache_journal_t",
        "aos_sandbox_cache_object_t", *(f"aos_sandbox_{role}_state_t" for role in OWNERS),
    ):
        negative.extend(accesses(GATEWAY, target, "file", ("open", "read")))
    negative.extend(accesses(GATEWAY, "*", "file", ("execute_no_trans",)))
    negative.append(Access(GATEWAY, "*", "tcp_socket", "name_connect"))
    negative.append(Access(GATEWAY, "*", "udp_socket", "create"))
    negative.append(Access(GATEWAY, "*", "rawip_socket", "create"))
    negative.append(Access(GATEWAY, "aos_method46_tpm_device_t", "chr_file", "open"))
    for helper in HELPER_DOMAINS:
        negative.append(Access(GATEWAY, helper, "process", "transition"))
    for other in all_roles:
        if other not in (GATEWAY, "init_t"):
            negative.extend(accesses(other, GATEWAY_CREDENTIAL, "file", ("open", "read", *file_mutate)))
            negative.extend(accesses(other, GATEWAY_CREDENTIAL, "dir", dir_mutate))

    controller = "aos_sandbox_controller_t"
    controller_credential = "aos_sandbox_controller_credential_t"
    positive.extend(accesses("init_t", controller_credential, "file", CREDENTIAL_PID1_FILE_DELIVERY))
    positive.extend(accesses("init_t", controller_credential, "dir", CREDENTIAL_PID1_DIR_DELIVERY))
    transitions.append(Transition("init_t", controller_credential, "file", controller_credential))
    positive.extend(accesses(controller, controller_credential, "dir", ("getattr", "open", "read", "search")))
    positive.extend((
        Access(controller, "tmpfs_t", "filesystem", "getattr"),
        Access(controller_credential, "tmpfs_t", "filesystem", "associate"),
    ))
    negative.extend(accesses(controller, controller_credential, "file", (
        *file_mutate, "execute", "execute_no_trans", "entrypoint", "map",
        "relabelfrom", "relabelto",
    )))
    negative.extend(accesses(controller, controller_credential, "dir", (*dir_mutate, "relabelfrom", "relabelto")))
    negative.extend(accesses("init_t", controller_credential, "file", (
        "append", "link", "lock", "rename", "relabelfrom", "relabelto",
    )))
    negative.extend(accesses("init_t", controller_credential, "dir", ("rename", "rmdir", "relabelfrom")))
    controller_runtime = "aos_sandbox_controller_runtime_t"
    negative.extend(accesses("init_t", controller_runtime, "dir", (*dir_mutate, "open", "read", "search")))
    negative.extend(accesses("init_t", controller_runtime, "sock_file", (*file_mutate, "open", "read")))

    # Preparation is a separate manual principal, not an ordinary owner or
    # TPM helper. Existing purpose writers and manager mutation stay denied.
    positive.extend(accesses(
        "init_t", OFFLINE_PREPARE_EXECUTABLE, "file",
        ("execute", "execute_no_trans", "getattr", "map", "open", "read"),
    ))
    positive.extend((
        Access("init_t", OFFLINE_PREPARE, "process", "transition"),
        Access("init_t", OFFLINE_PREPARE, "process2", "nnp_transition"),
        Access(OFFLINE_PREPARE, OFFLINE_PREPARE_EXECUTABLE, "file", "entrypoint"),
        Access(OFFLINE_PREPARE, OFFLINE_PREPARE, "capability", "chown"),
        Access(OFFLINE_PREPARE, OFFLINE_PREPARE, "capability", "dac_override"),
        Access(OFFLINE_PREPARE, "init_t", "fd", "use"),
        Access(OFFLINE_PREPARE, "init_t", "system", "status"),
        Access(OFFLINE_PREPARE, "systemd_unit_t", "service", "status"),
        Access(OFFLINE_PREPARE_CREDENTIAL, "tmpfs_t", "filesystem", "associate"),
    ))
    for reader in (OFFLINE_PREPARE, "init_t"):
        positive.extend(accesses(reader, OFFLINE_PREPARE_PROFILE, "file", file_read))
    positive.extend(accesses(OFFLINE_PREPARE, OFFLINE_PREPARE_CREDENTIAL, "file", file_read))
    positive.extend(accesses(
        OFFLINE_PREPARE, OFFLINE_PREPARE_CREDENTIAL, "dir",
        ("getattr", "open", "read", "search"),
    ))
    positive.extend(accesses("init_t", OFFLINE_PREPARE_CREDENTIAL, "file", CREDENTIAL_PID1_FILE_DELIVERY))
    positive.extend(accesses("init_t", OFFLINE_PREPARE_CREDENTIAL, "dir", CREDENTIAL_PID1_DIR_DELIVERY))
    transitions.append(Transition("init_t", OFFLINE_PREPARE_CREDENTIAL, "file", OFFLINE_PREPARE_CREDENTIAL))
    positive.extend(accesses(
        OFFLINE_PREPARE, OFFLINE_PREPARE_STATE, "file",
        ("create", "getattr", "lock", "open", "read", "setattr", "write"),
    ))
    positive.extend(accesses(
        OFFLINE_PREPARE, OFFLINE_PREPARE_STATE, "dir",
        ("add_name", "create", "getattr", "open", "read", "search", "setattr", "write"),
    ))
    positive.extend(accesses(OFFLINE_PREPARE, "var_lib_t", "dir", ("add_name", "write")))
    # The canonical TE owns the literal basename; Transition's existing DATA
    # model checks presence, not a new independent filename-policy engine.
    transitions.append(Transition(OFFLINE_PREPARE, "var_lib_t", "dir", OFFLINE_PREPARE_STATE))
    transitions.append(Transition(OFFLINE_PREPARE, OFFLINE_PREPARE_STATE, "file", OFFLINE_PREPARE_STATE))
    for object_class, permissions in (
        ("dir", ("getattr", "search", "open", "read", "lock", "ioctl")),
        ("file", ("getattr", "open", "read", "lock", "ioctl")),
        ("lnk_file", ("getattr", "read")),
    ):
        positive.extend(accesses("init_t", OFFLINE_PREPARE, object_class, permissions))
    for target in ("security_t", "cgroup_t", "sysctl_kernel_t", "usr_t", "systemd_unit_t"):
        positive.extend(accesses(OFFLINE_PREPARE, target, "file", file_read))
    for permission in ("start", "stop", "reload", "enable", "disable"):
        negative.append(Access(OFFLINE_PREPARE, "*", "service", permission))
    for permission in ("start", "stop", "reload", "reboot", "halt"):
        negative.append(Access(OFFLINE_PREPARE, "*", "system", permission))
    negative.append(Access(OFFLINE_PREPARE, "*", "file", "execute_no_trans"))
    negative.append(Access(OFFLINE_PREPARE, "aos_method46_tpm_device_t", "chr_file", "open"))
    for target in ("cgroup_t", "sysctl_kernel_t"):
        negative.extend(accesses(OFFLINE_PREPARE, target, "file", file_mutate))
    for helper in HELPER_DOMAINS:
        negative.append(Access(OFFLINE_PREPARE, helper, "process", "transition"))
    for other in all_roles:
        negative.extend(accesses(other, OFFLINE_PREPARE_PROFILE, "file", file_mutate + ("execute", "execute_no_trans", "map")))
        if other != OFFLINE_PREPARE:
            negative.extend(accesses(other, OFFLINE_PREPARE_STATE, "file", (*file_mutate, "open", "read")))
            negative.extend(accesses(other, OFFLINE_PREPARE_STATE, "dir", dir_mutate))
        if other not in (OFFLINE_PREPARE, "init_t"):
            negative.extend(accesses(other, OFFLINE_PREPARE_CREDENTIAL, "file", (*file_mutate, "open", "read")))
            negative.extend(accesses(other, OFFLINE_PREPARE_CREDENTIAL, "dir", dir_mutate))
            negative.extend(accesses(other, OFFLINE_PREPARE, "file", ("ioctl", "open", "read")))
            negative.append(Access(other, OFFLINE_PREPARE, "fd", "use"))
            negative.extend(accesses(other, OFFLINE_PREPARE, "unix_stream_socket", ("read", "write")))
            negative.append(Access(other, OFFLINE_PREPARE, "process", "transition"))
    negative.extend(accesses(OFFLINE_PREPARE, OFFLINE_PREPARE_CREDENTIAL, "file", file_mutate))
    negative.extend(accesses(OFFLINE_PREPARE, OFFLINE_PREPARE_CREDENTIAL, "dir", dir_mutate))
    negative.extend(accesses(OFFLINE_PREPARE, OFFLINE_PREPARE_STATE, "file", ("append", "link", "rename", "unlink")))
    negative.extend(accesses(OFFLINE_PREPARE, OFFLINE_PREPARE_STATE, "dir", ("remove_name", "rename", "rmdir")))

    root = "aos_sandbox_policy_authority_t"
    root_credential = "aos_sandbox_policy_authority_credential_t"
    positive.extend(accesses("init_t", root_credential, "file", CREDENTIAL_PID1_FILE_DELIVERY))
    positive.extend(accesses("init_t", root_credential, "dir", CREDENTIAL_PID1_DIR_DELIVERY))
    transitions.append(Transition("init_t", root_credential, "file", root_credential))
    positive.extend(accesses(root, root_credential, "dir", ("getattr", "open", "read", "search")))
    negative.extend(accesses(root, root_credential, "file", file_mutate))
    negative.extend(accesses(root, root_credential, "dir", dir_mutate))
    positive.extend(accesses(root, "aos_sandbox_view_parent_t", "dir", ("getattr", "open", "search")))
    positive.append(Access(root, "tmpfs_t", "filesystem", "getattr"))
    positive.extend(accesses(root, "init_exec_t", "file", ("getattr", "read")))
    positive.extend(accesses(root, root, "lnk_file", ("getattr", "read")))
    profile = "aos_sandbox_policy_authority_profile_t"
    for reader in (root, "init_t", "aos_sandbox_controller_t"):
        positive.extend(accesses(reader, profile, "file", file_read))
    positive.extend(accesses(
        "aos_sandbox_controller_t", "aos_sandbox_policy_authority_exec_t", "file", file_read,
    ))
    positive.extend(accesses("aos_sandbox_controller_t", "init_exec_t", "file", file_read))
    negative.extend(accesses(
        "aos_sandbox_controller_t", "aos_sandbox_policy_authority_exec_t", "file",
        ("execute", "execute_no_trans", "entrypoint", "map", *file_mutate),
    ))
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
