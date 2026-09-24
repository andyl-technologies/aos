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

It constructs and durably retains one canonical `ExecutionSpecV1` for the exact
execution ID and source operation before Host authorization. The authenticated
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
The signed phase-zero inspector report and a hostd self-probe are useful but
do not establish hostd's access to a separate shifted target. All evidence
must bind the current boot, immutable executable and root pins, exact runtime
profile, and trusted deployment generation. Missing evidence keeps launch
unavailable.

## Completion evidence

Focused codec and owner tests do not qualify these production connections.
Before enablement, exercise crash recovery across each authority record and
effect boundary, rotated or stale keys and heads, replay and transport loss,
maximum valid execution-spec size, holder-channel substitution, real Host and
guest readback, and the installed public endpoint. The required hermetic,
portability, VM, ABI, license-boundary, and release gates remain independent
completion criteria.
