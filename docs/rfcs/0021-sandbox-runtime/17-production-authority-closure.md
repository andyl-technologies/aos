# Production authority closure

This amendment is normative for RFC-0021 production admission. A canonical
format, a signed claim, a protected journal entry, and a fresh observation are
different kinds of evidence. None substitutes for the owner that establishes
the underlying fact. A production effect remains unavailable until the complete
authority chain below is connected and recoverable.

## Shared trust and currentness rules

- Each signing role has a pinned, role-specific public key and key generation
  supplied by privileged deployment configuration. A request, project packet,
  or unprivileged controller may carry a signature but may not nominate the key
  that makes it trusted. Missing, rotated, or indeterminate trust fails closed.
- Cross-owner authority requires a writer-held lease or an ordered multi-owner
  barrier. The barrier must keep the exact protected heads fixed from the final
  read through the authority record's durable compare-and-swap and the effect
  handoff, or require an equivalent atomic epoch check at each crossing. A
  sequence of individually fresh reads is not a cross-journal transaction.
- The authority record commits the owner, lease or barrier epoch, target
  operation, exact input digests, every independent head and generation, and
  the signer generation. Replay and recovery compare the same fields; a legacy
  record without them cannot confer production effect authority.
- Protected state is never repaired by accepting a caller-provided replacement
  key, head, timestamp, path, or receipt. Ambiguous commits retain custody and
  resolve through the owning journal and authenticated inventory.

## Parentless Create policy binding

The signed project layer is provenance, not proof that its ancestry, cache,
revocation, or compiler/deployment claims are current. The root policy issuer
must independently read the current protected public-operation and projection
join, publisher generation, project layer, ancestry head, cache-domain head,
revocation head, and compiler/deployment head. It must bind the exact target
Create, normalized compiler input, and candidate policy to those heads under
the cross-owner barrier above. A versioned root-owned binding is committed by
compare-and-swap before publication; effect handoff must retain or re-establish
the same authority cut. AOSPCB01 records lacking these independent bindings
are untrusted historical evidence. They cannot authorize publication or
effects, and an owner encountering one must fail closed until explicit
migration or reissuance under the new fence.

For the DAC-protected physical Cache names, root may instead consume a
separately provisioned Cache-only signed currentness readback from the physical
owner. This delegation is limited to named Cache root, lock, and manifest
currentness; it does not delegate Controller, source-domain, cache-domain,
revocation, compiler, or root publication authority. Root must pin the Cache
signer independently, create a fresh challenge under its writer, and verify
the response while the physical Cache flock and all other owners remain held
in canonical order through the root compare-and-swap and recoverable effect
handoff. The receipt must bind exact named identities, durable head, current
quota envelope, revocation, and the all-owner cut. A signature or persisted
pin alone never opens Create. The current Cache owner shares the Controller
UID, so this is delegated same-UID trust, not process isolation.
The closed `AOSPHQ05` Cache readback exchange may durably spend a root challenge
and verify that signer, but its root-source cut is not the all-owner cut and
its acknowledgement is not a publication or effect capability.

## Execution admission and observation

`CreateExecution` admission commits the accepted command, holder-proven public
key, principal, audit identity, and mutation fence. A protected admission owner
then obtains, independently and under current assignment authority:

- the payload boot identity, runtime profile and observed argument limit;
- canonical current environment bytes, descriptor, and generation;
- the exact parent resource profile, admitted execution sublimits, and durable
  broker-ledger output-byte admission and reservation, including a zero-byte
  stream-mode claim; and
- guest credential policy and the authorized UID, GID, and supplementary groups.

The guest credential producer reads the exact v2 SandboxSpec selected by the
current signed assignment. Its explicit identity policy fixes all three
credential dimensions for that incarnation; v1 specs have no such producer.
The protected readback must compare the complete credential set in the
execution specification, the assignment tuple, and the accepted Create
request before retaining the specification. A mapping-range check alone does
not confer authority. Assignment currentness is rechecked across the durable
handoff under the shared barrier above. A missing policy, legacy descriptor,
unmapped ID, or mismatched group set fails closed.

The admission owner constructs and durably retains one canonical
`ExecutionSpecV1` for the exact execution ID and source operation before Host
authorization. The authenticated
Host handoff must support every valid bounded v1 specification, including the
maximum-size canonical specification plus its framing, through an explicitly
versioned frame or protected content-custody protocol. A 64 KiB-only request
cannot silently truncate or reject otherwise valid v1 executions while
claiming the production path is complete. Host Apply and Query each bind the
exact specification digest,
assignment, and retained attempt; adding this to Query requires a versioned
wire and semantic change. `Authorized` and `Starting` are not public `RUNNING`;
only authenticated guest/Host `Running` evidence may advance that projection.
Terminal state requires authenticated result and capture disposition.

For a public `ExecutionResult`, `exited_at` is the Controller's first durably
published verification time, not the Guest kernel's process-exit time. The
current signed Guest Observe carries an exit-status i32 (`-1` means no code)
or cancellation marker but no wall-clock timestamp or signal identity. An
exited stream/PTY execution with a nonnegative signed exit code has no
detached capture to settle, so it may publish `EXIT_CODE` plus that durable
observation time. A negative or unknown exit code cannot be relabeled as a
signal, and detached capture cannot be published until its physical Storage
disposition is verified. Neither case may synthesize a public terminal result
from an inferred status. The signed cancellation marker likewise does not
supply a portable termination kind or exact process status, so public
`CANCELED` projection remains closed for this slice.

This projection rule does not activate Create, Host launch, Observe scheduling,
public `RUNNING`, or the attach route.

An authenticated Host Authorize completion can reserve the first Host Observe
operation under protected Controller custody. The AOSCOB01 record binds its
distinct deterministic operation ID to the original AOSCSI01 Create spec,
source-operation commitment, and exact `AOSEXE01` authorization receipt. An
ambiguous append must cold-reopen; replay must match that record before a Host
Observe grant. The receipt is accepted only with the typed Create binding
minted by signed Host Authorize classification; its prefix alone is not proof.
Reservation replay also rejects a later Operation or Effect ledger claim on
the derived Observe ID until an exact reconciler operation/effect protocol is
implemented.
The reservation is not an Observe completion or dispatch authority. Production
Controller operation dispatch still has no already-authorized Observe caller;
the Create cross-owner handoff and durable effect replay must be completed
before the reservation can be consumed.

## Storage execution-output reserve authority

The Controller is the issuer of one Storage-audience logical-output reserve
source for an accepted execution Create. Under its protected accepted-Create,
parent-resource, assignment, original `AOSCIA01` Host attempt, and current
`AOSCIS01` Host settlement, it must sign a plan committing the execution and
Create IDs, expected v2 output-claim digest and exact stdout/stderr ceilings,
assignment, original Host request and `AOSEOR02`/`AOSHOP01` digests, Host boot,
one original Storage request ID, deadline, and complete source digest. A signed
Controller source establishes its issuance, not the Host's protected v2 claim.

Storage must obtain a same-session authenticated Host readback through the
fixed Storage-to-Host broker-session audience before reserving. Host must
independently cold-read its protected v2 `AOSEOR02` output claim and original
`AOSHOP01` reservation correlation, verify every source field and current
assignment against the Controller-signed accepted-Create source, and bind its
signed outcome to the exact source, broker-session transcript, protected Host
head, and boot.
Caller-supplied claim fields, currentness scalars, a checksum, or a historical
Host response cannot replace this readback.

Storage must verify the Controller plan and authenticated Host outcome together
under the ordered owner barrier, then recheck the externally provisioned
`AOSOCK01` credential and the existing, exclusively held output journal and
lock with its `AOSEOC01` configuration. One atomic Storage transaction must
bind the original request ID and signed-source digest to the exact `AOSEOR03`
row; Stream and PTY also retain their zero-byte row. The logical row neither
proves physical ZFS backing nor permits Host Apply, capture, or public Create
completion.

After ambiguous transport or append, recovery must cold-reopen the same
Storage writer and query that original request and source against both the
durable marker and `AOSEOR03`. An exact committed match returns the original
record digest; a conflict or unresolved journal tail fails closed. Proven
absence can use only the still-current, unexpired original source and request
ID, never a newly issued attempt. The fixed Storage/Host broker-session pair
requires independently pinned manifests and role-local hello and record or
outcome keys; Storage also requires its offline-provisioned output key and
journal. Missing, rotated, or mismatched credentials keep reserve closed. No
Storage reserve method or method-41 candidate is enabled by this requirement.

## Opaque capability handles

Capability UID remains the public resource identity and a non-authorizing
lookup header. A capability handle is a distinct 32-byte CSPRNG value, issued
by the protected capability owner and returned only to the authenticated
holder. The owner durably retains a replay-stable handle under protected
custody and resolves its domain-separated digest against the exact capability
UID, holder principal, certificate-key binding, and record version. Every use
performs that lookup under a current authenticated TLS peer and repeats policy,
expiry, revocation, scope, and grant checks; handle
possession or a UID header alone never authorizes an operation. Attenuation
issues a new child handle. Renewal atomically retires the predecessor and
issues a new handle; idempotent replay returns the same committed result.
Revocation invalidates every handle for the affected capability. Raw handles
do not enter public resource projections, audit events, metrics, or logs.

## Installed Host readiness

Production `BackendReadiness` requires independent measurement of the deployed
payload filter, proof that the actual zero-capability hostd can inspect a
shifted payload through its pidfd, installed transient-unit readback, and
actual payload MAC, capability, no-new-privileges, and seccomp observations.
The AOSHPB02 phase-zero report binds the packaged inspector executable and
requires PID 1 unit readback plus kernel observations of the shifted target's
zero capabilities, no-new-privileges state, and installed seccomp filter.
Zero-capability hostd separately checks pidfd namespace access to that fixed
target. This does not prove access to an actual nspawn payload or its installed
filter and MAC state. All evidence must bind the current boot, immutable
executable and root pins, exact runtime profile, and trusted deployment
generation. Missing evidence keeps launch unavailable.

## Completion evidence

Focused codec and owner tests do not qualify these production connections.
Before enablement, exercise crash recovery across each authority record and
effect boundary, rotated or stale keys and heads, replay and transport loss,
maximum valid execution-spec size, holder-channel substitution, real Host and
guest readback, and the installed public endpoint. The required hermetic,
portability, VM, ABI, license-boundary, and release gates remain independent
completion criteria.
