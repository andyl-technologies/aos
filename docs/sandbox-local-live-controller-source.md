# Closed Controller LocalLive consumer source

`AOSLCS01` is a signable but unsigned Controller source, formed only from an
open protected attachment-source Acquire dispatch. Its constructor rechecks the
exact durable attempt and authorized packet, current desired attachment,
current (not historical) View revision, consumer namespace target, separate
source Host scope, lease, and Controller journal sequence under one writer-held
borrow. The fixed source binds the named consumer, both Host assignments,
logical live-export generation, attachment and View versions, exact acquisition
attempt, Host boot and bounded deadlines, and the consumer runtime/scope handles
needed to compare a Storage-audience Host method-34 query.

The logical export ID is **not** a physical Storage partition. The Controller
does not own Storage's current catalog, clone journal, or signed lease; a future
Storage join must independently resolve the exact export and source assignment
to its current physical origin and partition. The copied sequence is not a
transferable Controller lock. There is no Controller signing credential or
consumer of these bytes, and a matching method-34 request provides no cgroup
FD, kernel grant, or authority to release one. LocalLive acquisition, public
Ready, and descriptor egress remain closed.

If this source is later signed, the Controller signer and Storage verifier need
independent, pinned role-specific key custody, a generation/rotation rule, and
a same-cut protocol that keeps Controller, Storage catalog/clone, Host terminal,
and kernel deny-stage owner current through an exact durable CAS and recoverable
handoff. A signature over a copied `AOSLCS01` alone cannot supply that custody.
