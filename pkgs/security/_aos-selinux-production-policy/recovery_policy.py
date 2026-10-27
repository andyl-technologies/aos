"""Effective confinement contract for nonauthorizing Root history recovery."""

DOMAIN = "aos_sandbox_policy_recovery_t"
HISTORY = "aos_sandbox_policy_history_t"
RUNTIME = "aos_sandbox_policy_recovery_runtime_t"
ROOT = "aos_sandbox_policy_authority_t"
STATE = "aos_sandbox_policy_authority_state_t"
EXECUTABLE = "aos_sandbox_policy_authority_exec_t"


def matrix(Access, Transition, accesses, all_roles):
    """Checks exact entry, history-only reads and the private recovery listener."""
    read = ("getattr", "open", "read")
    mutate = (
        "append", "create", "link", "lock", "rename", "setattr", "unlink", "write",
    )
    dir_mutate = (
        "add_name", "create", "remove_name", "rename", "rmdir", "setattr", "write",
    )
    positive = [
        Access("init_t", DOMAIN, "process", "transition"),
        Access(DOMAIN, EXECUTABLE, "file", "entrypoint"),
        Access(HISTORY, "fs_t", "filesystem", "associate"),
        Access(RUNTIME, "tmpfs_t", "filesystem", "associate"),
        Access("aos_sandbox_controller_t", DOMAIN, "unix_stream_socket", "connectto"),
    ]
    positive.extend(accesses(
        "init_t", DOMAIN, "process2", ("nnp_transition", "nosuid_transition"),
    ))
    positive.extend(accesses("init_t", RUNTIME, "dir", ("mounton", "rmdir")))
    positive.extend(accesses(DOMAIN, "init_t", "unix_stream_socket", ("read", "write")))
    positive.extend(accesses(
        ROOT, HISTORY, "file",
        (*read, "append", "create", "ioctl", "lock", "rename", "setattr", "unlink", "write"),
    ))
    positive.extend(accesses(DOMAIN, HISTORY, "file", read))
    positive.extend(accesses(DOMAIN, STATE, "dir", (*read, "search")))
    positive.extend(accesses(
        DOMAIN, RUNTIME, "dir", (*read, "search", "add_name", "remove_name", "write"),
    ))
    positive.extend(accesses(
        DOMAIN, RUNTIME, "sock_file", (*read, "create", "setattr", "unlink", "write"),
    ))

    negative = list(accesses(
        DOMAIN, "*", "unix_stream_socket", ("connect", "connectto"),
    ))
    for other in (
        *all_roles, "aos_sandbox_runtime_roots_t", "aos_sandbox_runtime_roots_handoff_t",
    ):
        if other not in (DOMAIN, "init_t"):
            negative.extend(accesses(DOMAIN, other, "unix_stream_socket", ("read", "write")))
        if other != DOMAIN:
            negative.extend(accesses(
                DOMAIN, other, "unix_stream_socket",
                ("connect", "connectto", "create", "listen"),
            ))
        if other != ROOT:
            negative.extend(accesses(
                other, HISTORY, "file",
                (*mutate, "ioctl", "map", "execute", "execute_no_trans", "entrypoint",
                 "relabelfrom", "relabelto"),
            ))
        if other not in (ROOT, DOMAIN):
            negative.extend(accesses(other, HISTORY, "file", read))
        if other != "init_t":
            negative.extend(accesses(other, RUNTIME, "dir", ("mounton", "rmdir")))
            negative.append(Access(other, DOMAIN, "process", "transition"))
            negative.extend(accesses(
                other, DOMAIN, "process2", ("nnp_transition", "nosuid_transition"),
            ))

    negative.extend(accesses(
        DOMAIN, STATE, "dir", (*dir_mutate, "mounton", "relabelfrom", "relabelto"),
    ))
    negative.extend(accesses(
        DOMAIN, STATE, "file", (*read, *mutate, "ioctl", "map"),
    ))
    negative.append(Access(DOMAIN, DOMAIN, "user_namespace", "create"))
    for object_class, permissions in (
        ("tcp_socket", ("create", "name_connect")),
        ("udp_socket", ("create",)),
        ("rawip_socket", ("create",)),
        ("service", ("start", "stop", "reload", "enable", "disable")),
        ("system", ("start", "stop", "reload", "reboot", "halt")),
    ):
        negative.extend(accesses(DOMAIN, "*", object_class, permissions))

    transitions = [
        Transition(ROOT, STATE, "file", HISTORY, filename=name)
        for name in (
            "authority.journal", "authority.journal.lock", "authority.journal.compact.tmp",
        )
    ]
    transitions.extend((
        Transition(DOMAIN, RUNTIME, "sock_file", RUNTIME),
        Transition(
            "init_t", "var_run_t", "dir", RUNTIME,
            filename="sandbox-policy-cache-recovery",
        ),
    ))
    return positive, negative, transitions
