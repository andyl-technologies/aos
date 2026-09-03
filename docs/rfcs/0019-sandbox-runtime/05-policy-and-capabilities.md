# Capabilities and policy language

## Authoring and resolved policy

Humans normally author sandbox policy through AOS Nix modules and project
configuration. The controller resolves those inputs against site and project
ceilings into a canonical, immutable policy document. Nodes receive the
resolved policy and its digest; they do not evaluate user-authored Nix.

The policy is a typed declarative intermediate representation, not a general
scripting language. It has no arbitrary expressions, callbacks, regular
process execution, embedded WASM, or backend option escape hatch.

The policy has four independent sections:

1. authority and delegation;
2. namespace and view construction;
3. hard resource enforcement; and
4. advisory optimization.

Each compiled revision of the first three is immutable. An incarnation may
activate a newer revision through the explicit generation-replacement protocol;
changing policy never mutates a revision in place. The optimization profile
may advance independently when the change cannot affect authorization,
observable namespace semantics, or correctness.

## Structural authority

Authority is expressed as typed grants rather than an ordered allow/deny rule
list. Resource classes include:

- immutable artifact tree;
- live workspace export;
- private writable delta;
- secret projection;
- device;
- network endpoint;
- IPC or Unix-socket service;
- cache read domain;
- cache publication domain;
- execution and interactive access;
- snapshot, suspend, resume, and delete; and
- child creation and further delegation.

Each grant contains a typed operation set. File operations distinguish
traversal, metadata read, content read, execute, create, mutate content,
remove, rename, link, and metadata mutation. A socket is a service capability,
not a read-write file. Devices and secrets use their own semantics.

Allowlist grants default deny. Denials imposed by node or project ceilings
cannot be overridden by a more specific child request. Two grants that produce
conflicting destination or identity semantics fail policy compilation.

## Selectors

Closed selectors may identify:

- a normalized view-relative path prefix;
- an exact portable object or tree digest;
- membership in a named immutable set;
- an AOS package or closure relationship;
- source-provided metadata with a registered key schema;
- a verified provenance predicate; or
- a named sandbox export.

Selectors never contain absolute host paths. Globs, compound boolean trees,
negation, named sets, and provenance lookup are accepted only with hard limits
on serialized size, nesting depth, branch count, evaluation work, set size,
and explanation output.

Selectors requiring content classification run during indexing or bounded open
preparation. They cannot be evaluated on kernel reads once passthrough has
begun. Unknown classification under a hard allowlist is denial; optimization
classifiers may report no decision.

Authority-bearing content or provenance classification applies only to an
authenticated immutable revision or a transactional source generation pinned
from classification through use. A one-time content inspection cannot
authorize a live mutable native view whose bytes may change. Such views use
structural export/path grants; content classification on them is advisory only.

## View construction

Namespace construction uses closed typed actions:

- include or exclude a source subtree;
- attach a separately authorized source at a view-relative destination;
- present normalized metadata;
- select immutable, live, private-CoW, or publishable-staging mutation; and
- require semantic features such as hard links, xattrs, execute, or sparse
  extents.

A substitution or bind action refers to a preauthorized logical source handle.
It cannot contain a host source path. Composition is validated as a DAG with
bounded depth and fanout before any mount or index is created.

## Resources

Every hard numeric resource has an explicit value variant:

```text
inherit
bounded(value)
unlimited(authority_reference)
```

This applies to CPU, memory, PIDs, open files, mount count, descendant count,
storage, tmpfs, cache reservation, pinned bytes, metadata entries, mapped-index
bytes, in-flight fetch bytes, in-flight decompressed bytes, and publication
staging.

The resolved policy contains concrete effective bounds. It also states which
kernel or service enforces each bound. If a required enforcement mechanism is
unavailable, the sandbox remains failed or pending; it does not start with a
warning.

## Advisory optimization

Optimization rules may select:

- eager versus lazy materialization;
- foreground or speculative fetch priority;
- subtree or dependency-graph prefetch;
- sequential, executable-dependency, interpreter, or learned readahead;
- cache tier preference;
- co-location preference; and
- index retention hints.

These rules cannot grant a source, change the namespace, change identity,
enable execution, select a broader disclosure domain, or weaken a hard limit.
The compiler proves that every optimization action refers only to resources
already admitted by the authority and view plans.

Foreground kernel faults preempt speculative work. Advisory work has its own
reservation pool and is canceled before it can cause a hard admission failure.

## Conflict and ordering semantics

Security does not depend on user-assigned priority. The compiler applies this
fixed order:

1. validate and normalize inputs;
2. intersect authority ceilings;
3. resolve and validate namespace composition;
4. prove requested backend semantics and resource enforcement;
5. derive advisory actions constrained to the authorized result; and
6. produce a canonical explanation and digest.

Within an advisory family, the most-specific path may win and an explicit
priority may break equal-specificity ties. Original input order is never a
hidden security boundary. Ambiguity after the documented ordering is a compile
error.

## Policy revisions and replacement

The resolved security policy, view plan, and resource plan are immutable and
content addressed. A lease binds their digests. A replacement is prepared in
parallel, validated, and switched under the sandbox mutation lock.

An optimization-only revision may be installed without remounting. It is
versioned independently and reports which advice is active. Reclassifying a
disclosure domain, revoking an export, changing UID presentation, changing
mount flags, or reducing authority is not optimization and requires a security
replacement or stop.

## Capability issuance

Authentication proves the caller identity; a capability proves a specific
delegated authority. V1 uses controller-resolved opaque capability records,
not portable self-authorizing bearer tokens. A random capability handle is
accepted only over the authenticated holder channel to which the record is
bound. Possession of the handle on another channel grants nothing.

The controller issues a short-lived record after evaluating current policy. A
record binds:

- capability UID, issuer, audience, and authenticated holder identity;
- root subject and project;
- resource kind;
- sandbox UID and incarnation for an existing runtime-bound resource;
- parent/project scope and an expected-absence selector for pre-creation
  authority;
- operations and immutable resource selectors;
- effective policy digest;
- assignment epoch where node scoped;
- issue time, expiry, revocation-scope UID, and revocation generation;
- maximum delegation depth and fanout; and
- carved resource budgets and the parent decision/audit UID.

Remote clients prove the bound identity with the normal mutually authenticated
session or another explicitly registered proof-of-possession key. In-sandbox
authority is channel bound to a broker-created control socket and its peer
identity; no token is copied into the guest environment or command line. Key
rotation follows the transport trust system, and capability lookup always
checks the current revocation generation.

The controller is online for issuance, renewal, delegation, and public use.
Nodes do not validate a general caller capability offline. They receive a
separate audience-specific assignment lease over the authenticated node
protocol. That lease is short enough to fail closed during a partition and
cannot be renewed by the sandbox.

A caller capability authorizes creation or mutation; it is not the durable
authorization for the resulting sandbox, attachment, or mount. Accepted
desired state stores the resolved policy decision and revocation scope.
Expiration of the initiating caller session therefore does not accidentally
delete a long-lived resource, while a policy revocation explicitly reconciles
the resource according to its revocation mode.

Delegation is broker mediated: a parent presents its authority to the control
service, which issues a strictly attenuated child capability. Sandboxes do not
receive signing keys for arbitrary offline delegation chains.

A future federated or offline capability format requires a separate RFC
covering canonical claims, proof of possession, replay, issuer/audience trust,
rotation, revocation distribution, and attenuation verification. Its bytes are
not frozen into `aos.sandbox.v1`.

## Explanation

Every policy resolution can return:

- requested, ceiling, and effective policy digests;
- the source of each effective bound;
- rejected or narrowed grants;
- selected and rejected backend capabilities;
- advisory actions and omissions; and
- stable machine-readable decision reasons.

Explanation output is bounded and redacts concealed resource identity. It is
available before create through `aos sandbox plan` and after create through
`aos sandbox inspect`.
