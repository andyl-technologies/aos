"""Closed method-46 journal and initial-intent custody DATA.

Dedicated main labels keep selected manual initializers from inheriting access
to unrelated Controller history or generic floor files. These expectations
grant no runtime authority; the closed build recipe selects matching roles.
"""

ROLES = ("controller", "storage")
# Only the closed Nix renderer replaces these immutable initializers. Policy
# observations, runtime flags and mere type presence never select a purpose.
INITIAL_PURPOSES = ()
INITIAL_CREDENTIAL_NAMES = ()
if (INITIAL_PURPOSES != tuple(role for role in ROLES if role in INITIAL_PURPOSES)
        or (INITIAL_PURPOSES and (len(INITIAL_CREDENTIAL_NAMES) != 36
                                or len(set(INITIAL_CREDENTIAL_NAMES)) != 36))
        or (not INITIAL_PURPOSES and INITIAL_CREDENTIAL_NAMES)):
    raise ValueError("invalid closed method46 initial-purpose DATA")


def initial_service(role):
    """Returns the fixed manual service type for one endpoint."""

    return f"aos_method46_{role}_initial_t"


def initial_helper(role):
    """Returns the fixed private helper type for one endpoint."""

    return f"aos_method46_initial_{role}_helper_t"


INITIAL_SERVICES = tuple(initial_service(role) for role in INITIAL_PURPOSES)
INITIAL_HELPERS = tuple(initial_helper(role) for role in INITIAL_PURPOSES)
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
    if role in INITIAL_PURPOSES and permission in (*READ, "write"):
        permitted.add(initial_service(role))
    return frozenset(permitted)


def custody_sources(role, family, permission):
    """Returns every allowed file actor for one protected object family."""

    if family == "main":
        return main_sources(role, permission)
    if family == "initial-intent":
        if role in INITIAL_PURPOSES and permission in (*READ, "create", "rename", "write"):
            return frozenset({initial_service(role)})
        return frozenset()
    raise ValueError(f"unknown method46 object family: {family}")


def transition_sources(role, family):
    """Returns the closed creators of one family under literal reserved names."""

    sources = {f"aos_sandbox_{role}_t"}
    if family == "initial-intent" and role in INITIAL_PURPOSES:
        sources.add(initial_service(role))
    return frozenset(sources)


def matrix(Access, Transition, accesses, actors):
    """Requires normal-writer operations and denies delegation or execution."""

    positive = []
    negative = []
    transitions = []
    for role, family, object_type, names in CUSTODY_OBJECTS:
        floor = f"aos_method46_{role}_floor_t"
        positive.append(Access(object_type, "fs_t", "filesystem", "associate"))
        transitions.extend(
            Transition(source, floor, "file", object_type, filename=name)
            for source in sorted(transition_sources(role, family))
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
