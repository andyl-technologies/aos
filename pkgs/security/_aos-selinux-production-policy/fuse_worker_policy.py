"""Exact fixed-worker object permissions and effective-policy deny matrix."""

WORKER_DOMAIN = "aos_filesystem_fuse_worker_t"
WORKER_EXECUTABLE = "aos_filesystem_fuse_worker_exec_t"
WORKER_PLAN = "aos_filesystem_fuse_worker_plan_t"
WORKER_CHANNEL = "aos_filesystem_fuse_worker_channel_t"
WORKER_CANCEL = "aos_filesystem_fuse_worker_cancel_t"
WORKER_OBJECT_TYPES = (WORKER_EXECUTABLE, WORKER_PLAN, WORKER_CHANNEL, WORKER_CANCEL)

# These type-wide grants are narrowed at runtime by immutable-image admission,
# the original five-role table and Mount's actual labelled-object custody.
POSITIVE_GROUPS = (
    (WORKER_DOMAIN, WORKER_EXECUTABLE, "file", ("execute", "getattr", "map", "open", "read")),
    (WORKER_DOMAIN, "init_t", "fd", ("use",)),
    (WORKER_DOMAIN, "init_t", "unix_stream_socket", ("write",)),
    (WORKER_DOMAIN, WORKER_CHANNEL, "unix_stream_socket", ("getattr", "getopt", "read", "write")),
    (WORKER_DOMAIN, WORKER_PLAN, "file", ("getattr", "map", "read")),
    (WORKER_DOMAIN, WORKER_CANCEL, "fifo_file", ("getattr", "read")),
    (WORKER_DOMAIN, "fuse_device_t", "chr_file", ("getattr", "read", "write")),
    (WORKER_DOMAIN, WORKER_DOMAIN, "dir", ("getattr", "open", "read", "search")),
    (WORKER_DOMAIN, WORKER_DOMAIN, "file", ("getattr", "open", "read")),
    (WORKER_DOMAIN, WORKER_DOMAIN, "lnk_file", ("getattr", "read")),
    (WORKER_DOMAIN, "proc_t", "dir", ("getattr", "open", "read", "search")),
    (WORKER_DOMAIN, "proc_t", "file", ("getattr", "open", "read")),
    (WORKER_DOMAIN, "sysctl_t", "dir", ("search",)),
    (WORKER_DOMAIN, "sysctl_kernel_t", "dir", ("search",)),
    (WORKER_DOMAIN, "sysctl_kernel_t", "file", ("getattr", "open", "read")),
    (WORKER_DOMAIN, "security_t", "dir", ("search",)),
    (WORKER_DOMAIN, "security_t", "file", ("getattr", "open", "read")),
    (WORKER_DOMAIN, "lib_t", "file", ("execute", "getattr", "map", "open", "read")),
    (WORKER_DOMAIN, "ld_so_t", "file", ("execute", "getattr", "map", "open", "read")),
    (WORKER_DOMAIN, "usr_t", "lnk_file", ("getattr", "read")),
    ("aos_sandbox_host_t", WORKER_EXECUTABLE, "file", ("getattr", "open", "read")),
    ("aos_sandbox_host_t", WORKER_DOMAIN, "process", ("getattr",)),
    ("aos_sandbox_host_t", WORKER_DOMAIN, "dir", ("getattr", "search")),
    ("aos_sandbox_host_t", WORKER_DOMAIN, "file", ("getattr", "open", "read")),
    ("init_t", "init_t", "process", ("setsockcreate",)),
    ("init_t", WORKER_CHANNEL, "unix_stream_socket", ("create", "getattr", "getopt", "read", "setopt", "write")),
    ("init_t", WORKER_PLAN, "file", ("getattr", "map", "open", "read", "relabelto", "setattr", "write")),
    ("init_t", WORKER_CANCEL, "fifo_file", ("getattr", "open", "read", "relabelto", "unlink", "write")),
    (WORKER_PLAN, "tmpfs_t", "filesystem", ("associate",)),
    (WORKER_CANCEL, "tmpfs_t", "filesystem", ("associate",)),
)


def negative_groups(runtime_domains: tuple[str, ...]) -> tuple[tuple, ...]:
    """Forbids new connections, authority imports and mutable worker inputs."""

    groups = [
        ("init_t", WORKER_EXECUTABLE, "file", ("execute_no_trans",)),
        ("aos_sandbox_host_t", WORKER_EXECUTABLE, "file", ("append", "create", "execute", "execute_no_trans", "execmod", "ioctl", "link", "map", "relabelfrom", "relabelto", "rename", "setattr", "unlink", "write")),
        (WORKER_DOMAIN, "*", "file", ("execute_no_trans", "execmod")),
        (WORKER_DOMAIN, "*", "process", ("execmem", "execstack", "setexec", "setfscreate", "setsockcreate")),
        (WORKER_DOMAIN, "*", "unix_stream_socket", ("create", "connect", "connectto", "bind", "listen", "accept")),
        (WORKER_DOMAIN, "init_t", "unix_stream_socket", ("read",)),
        (WORKER_DOMAIN, "*", "sock_file", ("create", "open", "read", "write", "unlink")),
        (WORKER_DOMAIN, WORKER_CHANNEL, "unix_stream_socket", ("setopt",)),
        (WORKER_DOMAIN, WORKER_PLAN, "file", ("append", "create", "open", "write", "setattr", "relabelto", "unlink")),
        (WORKER_DOMAIN, WORKER_CANCEL, "fifo_file", ("create", "open", "write", "setattr", "relabelto", "unlink")),
        (WORKER_DOMAIN, "fuse_device_t", "chr_file", ("open", "ioctl")),
        (WORKER_DOMAIN, "security_t", "dir", ("open", "read", "write", "add_name", "remove_name")),
        (WORKER_DOMAIN, "security_t", "file", ("write", "append", "setattr", "relabelto")),
        (WORKER_DOMAIN, "security_t", "security", ("read_policy", "load_policy", "setenforce", "setbool")),
        (WORKER_DOMAIN, "bin_t", "file", ("execute", "map")),
        (WORKER_DOMAIN, "usr_t", "lnk_file", ("create", "relabelto", "rename", "setattr", "unlink", "write")),
        (WORKER_DOMAIN, "sysctl_t", "dir", ("add_name", "remove_name", "write")),
        (WORKER_DOMAIN, "sysctl_kernel_t", "dir", ("add_name", "remove_name", "write")),
        (WORKER_DOMAIN, "sysctl_kernel_t", "file", ("append", "create", "relabelto", "setattr", "unlink", "write")),
    ]
    for domain in ("init_t", *runtime_domains):
        if domain == WORKER_DOMAIN:
            continue
        # Per-task proc inodes bear the actual task SID. Only self is readable;
        # anonymous init_t files cannot silently substitute for the plan type.
        groups.append((WORKER_DOMAIN, domain, "file", ("open", "read", "ioctl")))
        groups.append((WORKER_DOMAIN, domain, "process", ("getattr", "ptrace", "transition")))
        groups.append((domain, WORKER_EXECUTABLE, "file", ("execute",)))
    # PID 1's transition is separately required, not a forbidden execute.
    groups.remove(("init_t", WORKER_EXECUTABLE, "file", ("execute",)))
    return tuple(groups)
