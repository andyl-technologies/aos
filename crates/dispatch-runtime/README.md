# Dispatch runtime

Dispatch sessions provide bounded assignment-solving environments. Each session
binds an execution provider, backend capability profile, stable resource grant,
worker lifecycle, pending queue, prepared-input budget, and terminal retention.
Cloned handles share those limits.

Warm profiles reuse application-owned workers; fresh profiles retire each worker
after one solve. The subprocess provider inherits application accounting and
discloses its lack of an independent memory boundary. The optional Linux systemd
provider establishes managed worker policy before allocation. A cooperative
embedded provider accepts explicitly supplied Rust backends without claiming
hard termination or independent OOM containment. Custom supervisors implement the
same provider interface.

The `dispatch-worker` executable validates portable problems, coordinates the
selected native process, and independently verifies candidates. Deadlines cover
queueing, materialization, solving, and verification. Termination, candidate
validity, and backend search evidence remain separate result axes.

Callers close sessions explicitly with drain or cancellation and inspect the
cleanup report. Dropping a handle does not guarantee asynchronous cleanup. Solver
resources and modeled placement resources are separate accounting systems.

The [user guide](https://github.com/andyl-technologies/aos/blob/master/docs/users/dispatch.md)
contains a complete session example and documents resource guarantees and results.
Portable consumers need no AOS package manager or shared solver daemon.
