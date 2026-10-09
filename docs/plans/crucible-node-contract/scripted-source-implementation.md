# Finite scripted request sources

`HostModel::ScriptedSource` is an owned synchronous host model for producing
actual public block or 9p requests. It supplies an output-only `data/output`
lane and connects to the ordinary input lane of an installed I/O node. No
external-input declaration, controller-supplied execution proof, or raw buffer
injection is involved. The I/O node executes the original native request codec
and retains its actual overlay, filesystem session and pending response queue.

The installed source profile names an independently enrolled script content
reference and its consumer node. Portable selections never contain host paths.
The operator registry supplies a complete regular-file artifact under bounded
no-follow reads; the factory verifies its expected content before decoding or
allocating a native source. Schema definitions, interface IDs, ordering and
correlation definitions match the installed storage request lane exactly.

## Native inventory and timing

The immutable script contains one request kind and one to sixteen ordered
requests. Each request has a physical picosecond instant and complete original
octets. Equal-time requests preserve script order. Construction checks native
request decoding, per-frame bounds and response geometry; unsupported editions,
decreasing instants, excessive inventories and trailing bytes are refused.
The source retains independent verified payload identities as well as the
complete original script bytes.

Every group of requests at an instant has two distinct native transitions:

1. Evaluation at reaction microstep zero marks the group evaluated.
2. Publication at microstep one advances the cursor and returns the original
   request octets in native FIFO order.

A half-open grant that reaches the publication coordinate can evaluate the
group while retaining its unpublished transition. Parking never skips an
unexecuted request. The next producer bound comes from the actual remaining
script and its retained cursor; an exhausted source reports `AfterInstant`
at the maximum representable instant. No ingress, autonomous worker, guest
timer, cancellation queue, seeded fault or independent clock input can create
an earlier output in this installed profile.

## Exact continuation

The source native codec retains its complete immutable script, cursor,
administrative clock and evaluated-but-unpublished flag. Reconstruction checks
the original script byte-for-byte, rejects impossible or partial equal-time
group cursors, and preserves the pending transition without reevaluation.
The surrounding `HostModelNode` codec additionally retains actual original
operation receipts, immutable staged input cuts, publication sequence,
acknowledgement status and payload/evidence custody. Source reconstruction
checks native cursor/publication-sequence agreement and the captured causal cut.

Ordinary publication acknowledgement and continuation validation remain tied
to the original host operation and local activation authority. A digest or
decoded saved state does not create new operation authority. Fresh restore
admission uses installed continuation qualification and the common readiness
and whole-world activation barrier.

Native complete capture and exact continuation reuse the qualified host codec.
The generated source profile initially refuses durable restart independently;
the installed world factory must authenticate the coordinator and every
connected FIFO, credit and publication-custody domain before advertising
durable whole-world archives. This component provides no CPU, external hardware
or nondeterministic execution qualification.

## Verification

Focused native tests cover truncated and trailing script records, changed
immutable futures, payload/response bounds, skipped-request refusal and two
independent cold cursor reconstructions with identical subsequent FIFO bytes.
The actual host-adapter test executes a split evaluation/publication cut,
retains original retry receipts, and reconstructs two fresh inactive native
nodes from that pending cut before comparing their actual publications.
Installed source-to-storage integration additionally checks ordinary directed
connections, real request effects and response custody; the central installed
factory owns that enrollment and its acceptance evidence.
