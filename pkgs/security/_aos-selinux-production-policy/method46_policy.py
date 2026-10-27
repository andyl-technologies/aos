"""Closed method-46 main-journal custody DATA for the shared policy checker.

Dedicated main labels keep future manual initializers from inheriting access
to unrelated Controller history or generic floor files. These expectations
grant no runtime authority and do not select initial provisioning roles.
"""

ROLES = ("controller", "storage")
MAIN_TYPES = tuple(f"aos_method46_{role}_main_t" for role in ROLES)
MAIN_NAMES = ("session.journal", "session.journal.compact.tmp")
READ = ("getattr", "open", "read")
WRITE = ("append", "create", "rename", "setattr", "unlink", "write")
FORBIDDEN = (
    "audit_access", "entrypoint", "execmod", "execute", "execute_no_trans",
    "ioctl", "link", "map", "mounton", "quotaon", "relabelfrom", "relabelto",
    "watch", "watch_mount", "watch_mountns", "watch_reads", "watch_sb", "watch_with_perm",
)


def main_sources(role, permission):
    """Returns the complete source cohort for one main-journal permission."""

    permitted = set()
    if permission in (*READ, *WRITE) or (role == "controller" and permission == "lock"):
        permitted.add(f"aos_sandbox_{role}_t")
    if role == "controller":
        if permission in READ:
            permitted.add("aos_sandbox_policy_authority_t")
        if permission == "getattr":
            permitted.add("aos_sandbox_cache_view_preparer_t")
    return frozenset(permitted)


def matrix(Access, Transition, accesses, actors):
    """Requires normal-writer operations and denies delegation or execution."""

    positive = []
    negative = []
    transitions = []
    for role, main in zip(ROLES, MAIN_TYPES):
        owner = f"aos_sandbox_{role}_t"
        floor = f"aos_method46_{role}_floor_t"
        positive.append(Access(main, "fs_t", "filesystem", "associate"))
        transitions.extend(
            Transition(owner, floor, "file", main, filename=name)
            for name in MAIN_NAMES
        )

        for permission in (*READ, *WRITE, "lock", *FORBIDDEN):
            permitted = main_sources(role, permission)
            positive.extend(Access(actor, main, "file", permission) for actor in permitted)
            negative.extend(
                Access(actor, main, "file", permission)
                for actor in actors if actor not in permitted
            )

    return positive, negative, transitions
