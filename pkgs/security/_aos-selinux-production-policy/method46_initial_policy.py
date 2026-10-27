"""Closed manual initializer expectations for the existing effective checker.

This module describes selected principals and exact custody cuts. It owns no
query engine and grants no startup, provisioning, signature or TPM authority.
"""

import method46_policy as journal


PURPOSES = journal.INITIAL_PURPOSES
SERVICES = journal.INITIAL_SERVICES
HELPERS = journal.INITIAL_HELPERS
DOMAINS = (*SERVICES, *HELPERS)
PROFILE = "aos_method46_initial_profile_t"
READ = journal.READ
FILE = (*READ, *journal.WRITE, "lock", *journal.FORBIDDEN)
COMMON_FILE = tuple(permission for permission in FILE if permission not in ("entrypoint", "execute_no_trans"))
DIR = (*COMMON_FILE, "add_name", "remove_name", "reparent", "search", "rmdir")
STREAM = (
    "ioctl", "read", "write", "create", "getattr", "setattr", "lock",
    "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen",
    "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "connectto",
)
ELF = ("entrypoint", "execute", "getattr", "map", "open", "read")
PID1_FILE_DELIVERY = ("create", "getattr", "open", "read", "setattr", "unlink", "write")
PID1_DIR_DELIVERY = (
    "add_name", "create", "getattr", "mounton", "open", "read", "relabelto",
    "remove_name", "search", "setattr", "write",
)
SERVICE_FLOOR = (*READ, "append", "create", "rename", "setattr", "unlink", "write")
SERVICE_LOCK = (*READ, "create", "lock", "setattr", "write")
HELPER_LOCK = ("getattr", "read", "write")
HELPER_CHANNEL = ("getattr", "getopt", "read", "setopt", "shutdown", "write")
SERVICE_CHANNEL = ("accept", "connect", "create", "getattr", "getopt", "read", "setopt", "shutdown", "write")
PID1_LISTENER = ("bind", "create", "getattr", "getopt", "listen", "read", "setopt", "shutdown", "write")
PID1_OUTPUT = ("connect", "create", "getattr", "getopt", "read", "setopt", "shutdown", "write")
CAPABILITIES = (
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
    "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
    "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
    "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
    "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
)
CAPABILITIES2 = (
    "mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend",
    "audit_read", "perfmon", "bpf", "checkpoint_restore",
)


def object_type(role, purpose):
    """Returns a fixed per-service object label."""

    return f"aos_method46_{role}_initial_{purpose}_t"


FIXED_ELF_ENTRIES = tuple(
    entry
    for role in PURPOSES
    for entry in (
        (journal.initial_service(role), object_type(role, "exec")),
        (journal.initial_helper(role), f"aos_method46_initial_{role}_helper_exec_t"),
    )
)
OBJECT_TYPES = (
    *((PROFILE,) if PURPOSES else ()),
    *(executable for _, executable in FIXED_ELF_ENTRIES),
    *(object_type(role, purpose) for role in PURPOSES for purpose in ("credential", "approval", "output")),
)
KNOWN_DOMAINS = tuple(domain for role in journal.ROLES
                      for domain in (journal.initial_service(role), journal.initial_helper(role)))
KNOWN_OBJECT_TYPES = (
    PROFILE,
    *(f"aos_method46_initial_{role}_helper_exec_t" for role in journal.ROLES),
    *(object_type(role, purpose) for role in journal.ROLES
      for purpose in ("exec", "credential", "approval", "output")),
)
PIDFD_CELLS = tuple(
    (journal.initial_service(role), target)
    for role in PURPOSES
    for target in (journal.initial_service(role), journal.initial_helper(role), "init_t", "unconfined_t")
)


def object_custody():
    """Returns all-source cuts covering every selected object permission."""

    rows = []
    if PURPOSES:
        rows.extend((PROFILE, "file", permission, frozenset(
            ("init_t", *SERVICES) if permission in READ else ()
        )) for permission in FILE)
    rows.extend((target, "process", permission, frozenset())
                for target in OBJECT_TYPES for permission in ("transition", "dyntransition"))
    for role in PURPOSES:
        service = journal.initial_service(role)
        helper = journal.initial_helper(role)
        for target, permissions, grants in (
            (object_type(role, "exec"), FILE, {
                service: ELF,
                "init_t": ("execute", "execute_no_trans", "getattr", "map", "open", "read"),
            }),
            (f"aos_method46_initial_{role}_helper_exec_t", FILE, {
                helper: ELF, service: tuple(permission for permission in ELF if permission != "entrypoint"),
            }),
            (object_type(role, "credential"), FILE, {service: READ, "init_t": PID1_FILE_DELIVERY}),
        ):
            rows.extend((target, "file", permission, frozenset(
                actor for actor, allowed in grants.items() if permission in allowed
            )) for permission in permissions)

        for target, object_class, permissions, grants in (
            (object_type(role, "credential"), "dir", DIR, {
                service: (*READ, "search"), "init_t": PID1_DIR_DELIVERY,
            }),
            (object_type(role, "approval"), "sock_file", COMMON_FILE, {
                service: ("getattr",), "init_t": PID1_FILE_DELIVERY,
                "unconfined_t": (*READ, "write"),
            }),
            (object_type(role, "output"), "unix_stream_socket", STREAM, {
                service: ("getattr", "read", "write"), "init_t": PID1_OUTPUT,
            }),
        ):
            rows.extend((target, object_class, permission, frozenset(
                actor for actor, allowed in grants.items() if permission in allowed
            )) for permission in permissions)
    return tuple(rows)


def private_custody():
    """Describes inherited channels and proc custody without foreign readers."""

    rows = []
    for role in PURPOSES:
        service = journal.initial_service(role)
        helper = journal.initial_helper(role)
        for target, peer, transition_source in (
            (service, helper, "init_t"), (helper, service, service),
        ):
            for object_class, permission in (
                ("fd", "use"), ("file", "open"), ("file", "read"),
                ("file", "ioctl"), ("process", "ptrace"),
                ("process", "transition"),
            ):
                permitted = set()
                if object_class == "fd":
                    permitted.update((target, peer, "init_t", "kernel_t"))
                elif object_class == "file":
                    permitted.update(("init_t", "kernel_t"))
                    if permission != "ioctl" or target == service:
                        permitted.add(target)
                    if target == helper:
                        permitted.add(service)
                elif permission == "transition":
                    permitted.add(transition_source)
                rows.append((target, object_class, permission, frozenset(permitted)))

        for permission in STREAM:
            permitted = set()
            if permission in SERVICE_CHANNEL:
                permitted.add(service)
            if permission in HELPER_CHANNEL:
                permitted.add(helper)
            if permission in PID1_LISTENER:
                permitted.add("init_t")
            if permission in ("read", "write"):
                permitted.add("kernel_t")
            if permission == "connectto":
                permitted.add("unconfined_t")
            rows.append((service, "unix_stream_socket", permission, frozenset(permitted)))
            rows.append((helper, "unix_stream_socket", permission, frozenset(
                {"kernel_t"} if permission in ("read", "write") else ()
            )))
    return tuple(rows)


def matrix(Access, Transition, accesses, actors):
    """Requires fixed entries and bounded delivery using the shared checker."""

    positive = []
    negative = []
    transitions = []
    for target, object_class, permission, permitted in (*object_custody(), *private_custody()):
        # These rows are all-source upper bounds. Native required operations
        # below are positive; tolerated manager/kernel inspection is not added.
        negative.extend(Access(actor, target, object_class, permission)
                        for actor in actors if actor not in permitted)
    for role in PURPOSES:
        service = journal.initial_service(role)
        helper = journal.initial_helper(role)
        credential = object_type(role, "credential")
        floor = f"aos_method46_{role}_floor_t"
        lock = f"aos_method46_{role}_lock_t"
        helper_exec = f"aos_method46_initial_{role}_helper_exec_t"
        positive.extend(accesses("init_t", service, "process", ("rlimitinh", "transition")))
        positive.extend(accesses("init_t", service, "process2", ("nnp_transition", "nosuid_transition")))
        positive.extend(accesses(service, service, "capability", ("chown", "dac_override")))
        positive.extend(accesses(service, "init_t", "fd", ("use",)))
        positive.extend(accesses(service, service, "unix_stream_socket", SERVICE_CHANNEL))
        positive.extend(accesses("init_t", service, "unix_stream_socket", PID1_LISTENER))

        positive.extend(accesses(service, credential, "file", READ))
        positive.extend(accesses(service, credential, "dir", (*READ, "search")))
        positive.extend(accesses("init_t", credential, "file", PID1_FILE_DELIVERY))
        positive.extend(accesses("init_t", credential, "dir", PID1_DIR_DELIVERY))
        positive.append(Access(credential, "tmpfs_t", "filesystem", "associate"))
        transitions.append(Transition("init_t", credential, "file", "init_tmpfs_t", filename=Transition.UNNAMED))
        transitions.extend(Transition("init_t", credential, "file", credential, filename=name)
                           for name in journal.INITIAL_CREDENTIAL_NAMES)

        positive.extend(accesses(service, floor, "file", SERVICE_FLOOR))
        positive.extend(accesses(service, lock, "file", SERVICE_LOCK))
        positive.extend(accesses(helper, lock, "file", HELPER_LOCK))
        transitions.append(Transition(service, floor, "file", floor, filename=Transition.UNNAMED))
        transitions.extend(Transition(service, floor, "file", lock, filename=name)
                           for name in ("session.journal.lock", "session-floor.journal.lock"))

        transitions.append(Transition(service, helper_exec, "process", helper, filename=Transition.UNNAMED))
        positive.extend(accesses(service, helper_exec, "file", ("execute", "getattr", "map", "open", "read")))
        positive.extend(accesses(service, helper, "process", ("getattr", "rlimitinh", "sigkill", "signal", "transition")))
        positive.extend(accesses(service, helper, "process2", ("nnp_transition", "nosuid_transition")))
        positive.extend(accesses(helper, helper, "process", ("getattr", "setcap")))
        positive.append(Access(helper, service, "process", "sigchld"))
        positive.append(Access(service, helper, "fd", "use"))
        positive.append(Access(helper, service, "fd", "use"))
        positive.extend(accesses(helper, service, "unix_stream_socket", HELPER_CHANNEL))
        positive.extend(accesses(service, service, "fifo_file", ("create", "getattr", "read", "write")))
        positive.extend(accesses(helper, service, "fifo_file", ("getattr", "write")))
        positive.extend(accesses(helper, "aos_method46_tpm_device_t", "chr_file", (*READ, "write")))

        positive.extend(accesses(service, PROFILE, "file", READ))
        positive.extend(accesses("init_t", PROFILE, "file", READ))

        output = object_type(role, "output")
        positive.extend(accesses(service, output, "unix_stream_socket", ("getattr", "read", "write")))
        positive.extend(accesses("init_t", output, "unix_stream_socket", PID1_OUTPUT))
        positive.append(Access(output, "init_t", "unix_stream_socket", "connectto"))
        approval = object_type(role, "approval")
        positive.append(Access(approval, "tmpfs_t", "filesystem", "associate"))
        positive.append(Access(service, approval, "sock_file", "getattr"))
        positive.extend(accesses("init_t", approval, "sock_file", PID1_FILE_DELIVERY))
        positive.extend(accesses("unconfined_t", approval, "sock_file", (*READ, "write")))
        positive.append(Access("unconfined_t", service, "unix_stream_socket", "connectto"))
        positive.extend(Access(source, target, "file", "ioctl") for source, target in PIDFD_CELLS if source == service)

        negative.extend(accesses(service, "aos_method46_tpm_device_t", "chr_file", ("open", "read", "write", "ioctl")))
        negative.extend(accesses(helper, "aos_method46_tpm_device_t", "chr_file", ("ioctl",)))
        negative.extend(accesses(helper, "*", "unix_stream_socket", ("accept", "bind", "connect", "connectto", "create", "listen")))
        negative.extend(accesses(helper, lock, "file", tuple(permission for permission in FILE if permission not in HELPER_LOCK)))
        negative.extend(accesses(helper, floor, "file", FILE))
        for domain in (service, helper):
            negative.append(Access(domain, "*", "file", "execute_no_trans"))
            for object_class, permissions in (
                ("capability", CAPABILITIES), ("capability2", CAPABILITIES2),
                ("cap_userns", CAPABILITIES), ("cap2_userns", CAPABILITIES2),
            ):
                negative.extend(Access(domain, "*", object_class, permission)
                                for permission in permissions
                                if not (domain == service and object_class == "capability"
                                        and permission in ("chown", "dac_override")))
            for object_class in ("tcp_socket", "udp_socket", "rawip_socket", "netlink_route_socket"):
                negative.append(Access(domain, "*", object_class, "create"))
    return positive, negative, transitions
