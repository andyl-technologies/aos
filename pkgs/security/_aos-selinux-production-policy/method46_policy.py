"""Closed method-46 journal and initial-intent custody DATA.

Dedicated main labels keep future manual initializers from inheriting access
to unrelated Controller history or generic floor files. These expectations
grant no runtime authority and do not select initial provisioning roles.
"""

ROLES = ("controller", "storage")
MAIN_TYPES = tuple(f"aos_method46_{role}_main_t" for role in ROLES)
MAIN_NAMES = ("session.journal", "session.journal.compact.tmp")
INTENT_TYPES = tuple(f"aos_method46_{role}_initial_intent_t" for role in ROLES)
INTENT_NAMES = ("session-floor.initial-intent", "session-floor.initial-intent.pending")
PROTECTED_TYPES = (*MAIN_TYPES, *INTENT_TYPES)
# The same query engine checks both object families. Intent custody is empty
# until the separately selected initial roles exist; normal writers cannot
# create a generic floor inode under either reserved intent name.
CUSTODY_OBJECTS = (
    *((role, "main", main, MAIN_NAMES) for role, main in zip(ROLES, MAIN_TYPES)),
    *((role, "initial-intent", intent, INTENT_NAMES) for role, intent in zip(ROLES, INTENT_TYPES)),
)
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


def custody_sources(role, family, permission):
    """Returns every allowed file actor for one protected object family."""

    if family == "main":
        return main_sources(role, permission)
    if family == "initial-intent":
        return frozenset()
    raise ValueError(f"unknown method46 object family: {family}")


def matrix(Access, Transition, accesses, actors):
    """Requires normal-writer operations and denies delegation or execution."""

    positive = []
    negative = []
    transitions = []
    for role, family, object_type, names in CUSTODY_OBJECTS:
        owner = f"aos_sandbox_{role}_t"
        floor = f"aos_method46_{role}_floor_t"
        positive.append(Access(object_type, "fs_t", "filesystem", "associate"))
        transitions.extend(
            Transition(owner, floor, "file", object_type, filename=name)
            for name in names
        )

        for permission in (*READ, *WRITE, "lock", *FORBIDDEN):
            permitted = custody_sources(role, family, permission)
            positive.extend(Access(actor, object_type, "file", permission) for actor in permitted)
            negative.extend(
                Access(actor, object_type, "file", permission)
                for actor in actors if actor not in permitted
            )

    return positive, negative, transitions
