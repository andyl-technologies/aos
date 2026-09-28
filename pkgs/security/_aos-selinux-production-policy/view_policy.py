"""Effective queries for the existing fixed view producers and signer peers.

The shared SETools checker expands these data, including attributes and
disabled conditional grants. This module grants no runtime proof authority.
"""

SIGNER_DOMAINS = (
    "aos_sandbox_source_signer_t",
    "aos_sandbox_cache_signer_t",
)


def matrix(Access, Transition, accesses, roles):
    """Returns the exact producer/read-only/association matrix."""

    positive = []
    negative = []
    transitions = []
    provisioner = "aos_sandbox_runtime_roots_t"
    actors = (*roles, provisioner)
    controller = "aos_sandbox_controller_t"
    root = "aos_sandbox_policy_authority_t"
    mutable_file = ("append", "create", "link", "rename", "setattr", "unlink", "write")
    mutable_dir = ("add_name", "create", "remove_name", "rename", "rmdir", "setattr", "write")

    for role, objects in (
        ("source", ("aos_sandbox_source_journal_t",)),
        ("cache", ("aos_sandbox_cache_journal_t", "aos_sandbox_cache_object_t")),
    ):
        preparer = f"aos_sandbox_{role}_view_preparer_t"
        signer = f"aos_sandbox_{role}_signer_t"
        entry = f"aos_sandbox_{role}_view_preparer_exec_t"
        signer_entry = f"aos_sandbox_{role}_signer_exec_t"
        mount = f"aos_sandbox_{role}_view_mount_t"
        credential = f"aos_sandbox_{role}_signer_credential_t"
        socket = f"aos_sandbox_{role}_signer_socket_t"

        for domain, executable in ((preparer, entry), (signer, signer_entry)):
            positive.extend((
                Access("init_t", domain, "process", "transition"),
                Access("init_t", domain, "process2", "nnp_transition"),
                Access(domain, executable, "file", "entrypoint"),
            ))
        positive.extend(accesses(
            preparer, "aos_sandbox_view_preparer_tool_exec_t", "file",
            ("execute", "execute_no_trans", "getattr", "map", "open", "read"),
        ))
        if role == "cache":
            positive.append(Access(preparer, "aos_sandbox_runtime_roots_exec_t", "file", "execute"))
            positive.append(Access(preparer, provisioner, "process", "transition"))
            transitions.append(Transition(preparer, "aos_sandbox_runtime_roots_exec_t", "process", provisioner))
        else:
            negative.append(Access(preparer, "aos_sandbox_runtime_roots_exec_t", "file", "execute"))
        positive.extend(accesses(preparer, preparer, "capability", (
            "chown", "dac_read_search", "setgid", "setuid", "sys_admin",
        )))
        positive.append(Access(preparer, preparer, "user_namespace", "create"))
        positive.append(Access(preparer, mount, "dir", "mounton"))
        positive.extend(accesses(preparer, "fs_t", "filesystem", ("getattr", "remount", "unmount")))
        positive.append(Access(preparer, "tmpfs_t", "filesystem", "getattr"))
        positive.extend(accesses(signer, credential, "file", ("getattr", "open", "read")))
        positive.extend(accesses(signer, socket, "sock_file", ("getattr", "open", "read")))
        positive.extend(accesses("init_t", signer, "unix_stream_socket", (
            "bind", "create", "getattr", "getopt", "listen", "setopt",
        )))
        positive.append(Access(root, signer, "unix_stream_socket", "connectto"))
        positive.extend(accesses(root, socket, "sock_file", ("getattr", "open", "read", "write")))

        for object_type in objects:
            positive.extend(accesses(controller, object_type, "file", (
                "append", "create", "getattr", "lock", "open", "read",
                "rename", "setattr", "unlink", "write",
            )))
            positive.extend(accesses(signer, object_type, "file", ("getattr", "lock", "open", "read")))
            positive.append(Access(preparer, object_type, "file", "getattr"))
            positive.append(Access(object_type, "fs_t", "filesystem", "associate"))
            positive.extend(accesses(provisioner, object_type, "dir", (
                "create", "getattr", "open", "read", "search", "setattr",
            )))
            readers = {controller, signer}
            if object_type == "aos_sandbox_cache_journal_t":
                readers.add(root)
            for actor in actors:
                if actor != controller:
                    negative.extend(accesses(actor, object_type, "file", mutable_file))
                if actor not in (controller, provisioner):
                    negative.extend(accesses(actor, object_type, "dir", mutable_dir))
                if actor not in readers:
                    negative.extend(accesses(actor, object_type, "file", ("open", "read")))
        # Only the private copied tools are an explicit same-domain exec surface.
        negative.append(Access(preparer, "bin_t", "file", "execute_no_trans"))
        negative.extend(accesses(preparer, "var_lib_t", "dir", mutable_dir))
        negative.extend(accesses(preparer, "aos_sandbox_view_parent_t", "dir", mutable_dir))
        negative.append(Access(preparer, f"aos_sandbox_{'cache' if role == 'source' else 'source'}_view_mount_t", "dir", "mounton"))
        negative.append(Access(signer, "*", "file", "execute_no_trans"))
        negative.extend(accesses(signer, "*", "capability", (
            "chown", "dac_read_search", "setgid", "setuid", "sys_admin", "sys_ptrace",
        )))
        negative.extend(accesses(signer, "*", "unix_stream_socket", ("connect", "connectto", "create", "listen")))
        for actor in actors:
            if actor != signer:
                negative.extend(accesses(actor, credential, "file", ("open", "read", *mutable_file)))
        positive.append(Access(mount, "tmpfs_t", "filesystem", "associate"))
        positive.append(Access(credential, "tmpfs_t", "filesystem", "associate"))
        positive.append(Access(socket, "tmpfs_t", "filesystem", "associate"))

    positive.append(Access(controller, "aos_sandbox_cache_signer_t", "unix_stream_socket", "connectto"))
    positive.append(Access(provisioner, provisioner, "capability", "dac_read_search"))
    positive.append(Access("aos_sandbox_view_parent_t", "fs_t", "filesystem", "associate"))
    positive.append(Access("aos_method46_tpm_device_t", "device_t", "filesystem", "associate"))
    for role in ("controller", "storage"):
        for kind in ("floor", "lock"):
            positive.append(Access(f"aos_method46_{role}_{kind}_t", "fs_t", "filesystem", "associate"))

    protected_files = (
        "aos_sandbox_view_parent_t",
        "aos_sandbox_source_journal_t",
        "aos_sandbox_cache_journal_t",
        "aos_sandbox_cache_object_t",
        "aos_sandbox_source_signer_credential_t",
        "aos_sandbox_cache_signer_credential_t",
        *(f"aos_sandbox_{role}_{kind}_t"
          for role in ("controller", "storage", "policy_authority")
          for kind in ("state", "credential")),
        *(f"aos_method46_{role}_{kind}_t"
          for role in ("controller", "storage")
          for kind in ("floor", "lock")),
    )
    for object_type in protected_files:
        negative.extend(accesses(provisioner, object_type, "file", ("open", "read")))
    return sorted(set(positive)), sorted(set(negative)), sorted(set(transitions))
