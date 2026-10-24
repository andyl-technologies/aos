# Original deterministic result reuse

The owning node executor supports an explicit result-reuse workflow through
`NodeObservationService::reuse_cache`, local control edition six and
`crucible node cache-reuse`. The workflow returns a successful original observed
result under its original execution nonce. It does not allocate a new native
world, publish a new observation, restore a snapshot or reconstruct a prefix.

## Admission and compatibility

The executor loads the original authoritative observation lifecycle and verifies
the complete result closure, including request, scenario, configuration, incoming
and outgoing traces and retained native evidence. A reservation, quarantine or
unsuccessful outcome cannot become a cache hit. The complete coupled owner roster
must pass the actual `CacheReuse` capability gate before profile regeneration.
A nondeterministic or unqualified owner taints the whole result. A conditional
boundary transcript cannot waive that gate; this workflow has no conditional
qualification verifier.

The cache key includes canonical complete executor capabilities and the original
input-context identity. It consequently binds scenario, configuration, world,
implementation/model owners, guarantees and materialization claims. The result
identity and source nonce remain separate: equal keys do not merge independent
physical observations or authorize substituting another retained result.

The owning catalog remeasures its installed controller and companion, regenerates
the exact selected profiles and checks original scenario/configuration/input
identity against the retained request. Backend or model changes refuse before
any replacement world allocation. Scenario bytes and descriptive provider names
cannot enroll implementations or qualification.

## Source retirement and retention

Original observed ledger and dispatch-reservation refs remain the authoritative
GC roots. Reuse introduces no second cache index or independent native-state
root. The repository's GC exclusion fence protects the complete original result
through verification and response construction.

Path enrollment still measures the original installed file; a missing or changed
path refuses. Explicit independently enrolled `ArchiveOnly` identities may check
complete immutable bytes embedded in the original scenario. Bounded temporary
files exist only for pure installed profile regeneration and are deleted after
verification. They do not restore native state, enroll new assets or permit
fresh construction. The original catalog remains unchanged.

## Local caller

`node cache-reuse --socket SOCKET --request REQUEST.json` sends a closed
`crucible.node-cache-reuse` edition-one request containing the original execution,
installed selections and exact original scenario/configuration bytes. An optional
`expected_cache_key` pins a previously returned key. Without it, exact original
selection is still mandatory and the verified key is returned in the receipt.
Control editions one through five cannot carry this command; legacy observation,
HostState, NativeState and terminal request bytes remain unchanged.

The receipt names `crucible.node-cache-receipt`, preserves original result bytes,
source execution and observed-result identity, and supplies the verified cache
key. These portable values carry no execution, terminal or restore authority.

## Verification scope

The actual normal executor runs finite Source→Block requests which write and read
original correlated bytes. After authentic original-world retirement, deletion
of the source/base paths and actor restart with independently pinned archive-only
identities, reuse returns identical original bytes twice. Activation,
reservation and ledger refs remain unchanged. Changed backend, model, run
configuration or cache key and corrupt original native evidence refuse. A genuine
mixed Clock/reference execution remains nondeterministic and cannot reuse its
result as deterministic evidence.

An actual source-built CLI process test stops the source daemon, removes the
immutable assets and starts a fresh daemon. It verifies identical original
result, nonce, outgoing/evidence identities and status through edition six.
Wrong key refusal and old wire compatibility are tested independently.

These checks qualify successful result reuse for the existing installed finite
host workload. They do not qualify a new snapshot backend, arbitrary guest/device
models, counterfactual minimization, fault/RNG/debug state, or unrecorded ingress.
