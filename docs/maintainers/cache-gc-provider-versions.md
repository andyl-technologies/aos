# Cache GC provider versions

R2 cache garbage collection requires the provider upload incarnation captured
by a complete cache inventory. Identical bytes, content hash, size, and ETag
can belong to a later upload of the same object key; they do not authorize
deleting that later upload.

Inventory captures the provider version with its byte evidence and confirms
the same version, size, and ETag through a guarded inventory HEAD. Reusing a
previously verified digest requires an exact listing and prior inventory
version match. The version is retained in staged listing evidence, staged
object observations, and the published object placement.

The reviewed physical action includes that version in its manifest and
confirmation digest. Applying the plan requires the published observation
to retain the reviewed version. The resulting deletion job freezes the same
value, and claiming an attempt copies it into the durable request receipt.
The controller supplies the receipt's value to the physical delete
precondition. Retry and crash recovery reuse the receipt; they cannot select
a replacement version from a live provider HEAD.

The forward migration leaves existing version fields absent. An old R2
inventory must be rescanned before a new deletion plan can be created. Old
R2 actions cannot be newly applied or jobs newly claimed without a captured
version. Existing terminal results can still be replayed, and a persisted
response can be finalized without performing another backend deletion.
An unsafe pending legacy R2 job remains visible for reviewed abandonment; it
does not occupy the runnable-job page ahead of fresh, versioned work. Rescan
and review a new plan after resolving that old active job.

Local filesystem and external backends retain their optional provider version
contract. Their existing reviewed digests remain compatible when the version
is absent. These rules apply to both narinfo and shared NAR physical actions;
the existing narinfo-before-NAR ordering remains in effect.
