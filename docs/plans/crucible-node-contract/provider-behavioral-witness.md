# Source-owned public provider behavioral witness

This plan defines an observation artifact for the fixed installed public
checksum profile. The artifact does not issue a qualification certificate.
The separate installed qualification policy verifies it before accepting any
behavioral class. Existing protocol-only reports and test logs remain useful
evidence with their existing scope.

## Emitter boundary

The emitter is an Apache host process using the actual public Unix-socket
provider and its separately owned controlled companion. It measures the
actual peer through kernel credentials and retained process identity, checks
the independently measured provider and companion executables, and retains
their original private launch/supervision resources. The emitter does not link
native simulator code or call private emulator headers.

Its initial accepted scope is limited to the fixed base-provider,
quantized-checksum timing, and external-device role contracts. Detailed CPU
fidelity, exact timing, physical suspension, capture, continuation, branching,
hardware KVM, and arbitrary vendor qualification remain excluded.

A predeclared witness plan identifies the complete case population and all
expected independent oracles before native launch. Changing that population,
fixture, oracle, limits, environment, or profile changes the plan identity.
Unexpected, absent, repeated, uncertain, or unsupported required cases cannot
be converted into a successful report.

## Exact scope records

The report carries the following immutable scope references:

| Scope | Required source-bound evidence |
| --- | --- |
| Emitter | Independently measured executable, source/build/tool definition identities, and report-format schema |
| Provider and controller | Actual measured executable/source identities and installed public protocol/profile definition |
| Companion | Independently measured running executable/source identity, original owner/incarnation/generation, and genuine parent/private-group enrollment |
| Model | Exact regenerated descriptor, implementation, configuration, operating contract, capabilities, guarantees, and binding identities |
| Environment | Declared native platform and resource enforcement definition; host-clock uncertainty and physical budgets distinct from logical positions |
| Case population | Immutable complete case definitions, applicability/exclusion mapping, fixture, and independent oracle identities |
| Execution | Original world/owner scope, prepared native resources, readies, complete activation, and original operation/input identities |

A digest supplied by the provider does not establish any of these facts.
Measurements come from the emitter's retained native process and build
installation. The installed acceptance policy independently checks those
measurements against the immutable source-built package tuple.

## Bounded observation snapshot API

The provider client can expose a read-only bounded snapshot of its original
post-Hello controls. The API returns plain data such as:

```text
ReferenceController::observation_snapshot(origin_scoped_keys, content_refs, limits)
    -> ReferenceObservationSnapshot {
         schema_version: 1,
         encoding: "retained-canonical-envelope-v1",
         scope,
         requests,
         objects
       }
```

The snapshot does not mutate journals, continue operations, acknowledge output,
release resources, authenticate receipts, or replace unknown outcomes. Every
request retains its original method, IDs, owner scope, body, identity, and
actual transport sequence. Every response retains the latest authentic decoded
response and scope. The existing client journal does not retain arbitrary
noncanonical wire encodings or a complete history of interim responses. The
snapshot therefore contains canonical encodings of retained original envelopes;
it does not claim to reconstruct a byte-for-byte stream history. The fixed
source-built provider emits canonical envelopes, while arbitrary vendor wire
history requires a separately implemented capture facility.

An `ObservedRequestKey` always includes `RequestOrigin` and the request ID.
The client resolves it from the corresponding original endpoint journal;
equal IDs in opposite directions remain distinct. `ObservedRequest` includes
that key, original request identity, canonical request bytes, and an explicitly
nullable latest response. Referenced content is copied from verified immutable received byte
custody, with complete metadata and original hashes. Absence remains absence.

`ObservationLimits` independently bounds request count, selected content count,
and aggregate raw bytes, with hard ceilings of 4096 requests, 4096 selected
objects, and 64 MiB. Serialized base64 expansion has a separate positive
64 MiB maximum through `ReferenceObservationSnapshot::encode`. Explicit
selection alone does not prove a complete native receipt closure or a complete
case population; the source-owned issuer verifies both obligations.

`ObservationScope` carries the measured peer executable and PID, admitted
session/incarnation/connection/epoch, exact selected features, and complete
immutable binding compatibility. Companion enrollment, source/tool identities,
environment, predeclared cases, and oracle results come from the independent
issuer rather than being inferred from this transport snapshot.

When the common runtime owns the controller, the harness installs an opt-in
`ObservationHandle` before the first original control:

```text
handle = controller.observe(limits)
controller moves into its original supervised native node
handle.request_keys()
handle.content_references()
handle.snapshot(selected_keys, selected_refs, selected_output_limits)
    -> RecordedReferenceObservation {
         recording_complete,
         observed_unknown,
         recording_failure,
         evidence
       }
```

The archive reserves its raw-byte arena and bounded request/content metadata
slots before native controls. It is thread-safe inert data custody; the handle
can survive retirement of the native source. The controller privately records
actual retained originals after controls, including failures, without exposing
its socket, handshake registrar, acknowledgement functions, or process handles.
The default controller has no recorder. Installing recording after controls or
replacing an existing recorder refuses.

Recording failures and unresolved control outcomes are sticky. A dropped
in-progress observation guard marks incompleteness, preserving previously
retained bytes. Overflow never replaces a native return or converts Unknown
into NoEffects. An incomplete archive remains readable for the originals it
retained; it cannot produce an accepted qualification result. The issuer
independently accounts for every predeclared case and original scope.

The initial archive binds one actual connection. It refuses changed connection
identity or epoch rather than inferring the birth connection of historical
requests from a replacement stream. Qualification of actual reconnect history
requires a separately implemented original connection-birth recording path.

The API reserves finite object/reference/byte bounds before copying. It does
not return unbounded iterators over native state or reconstruct response bodies
from a terminal status. Objects with mismatched digest, length, media type,
scope, or conflicting original bytes refuse.

Hello, admission token, resume token, and private bootstrap secret material are
excluded before any snapshot hashing or persistence. Redacting a secret after
hashing the original is insufficient. The emitter retains the live original
registrar and private secrets in supervised memory; public evidence contains
separately verified nonsecret installation and scope facts. A report must not
traverse a referenced private bootstrap object merely because its digest is
reachable from an arbitrary received object.

The snapshot refuses credential-shaped fields in selected envelopes and JSON
content. It also refuses accidental copies of the known admission token in raw
or base64 form. It never serializes the bootstrap itself. Independently selected
nonsecret public admission records and receipts remain available to the issuer;
their hashes do not confer native authority.

## Case evidence

Each planned case produces one bounded result record containing:

1. Its original case definition, fixture, independent oracle, and scope.
2. Actual post-Hello request/response frames and original native receipt
   content closure selected by the fixed source-defined codec.
3. Exact original input octets, stage/cut/inventory, input batch, custody ACK,
   grant, native run/close results, publication, and consumption ACK as
   applicable.
4. Independently calculated expected checksum and the actual original native
   output bytes, including the tested empty/nonempty and multi-producer cases.
5. Original refused or Unknown outcomes, retained custody, and actual cleanup
   evidence for negative cases.
6. Physical deadline/budget observations and their uncertainty, distinct from
   admitted logical positions and modeled timestamps.

The independent oracle reads the predeclared fixture bytes and algorithm
definition. It cannot derive the expected output by copying the provider's
output, its receipt digest, or the emitter's success flag. Event IDs, provider
native FIFO, coordinator ordering, stage identity, and immutable batch hash
are checked as separate obligations.

Failed host bookkeeping after genuine Input acceptance is a separate negative
case. The actual peer's completed response and accepted batch custody are
retained; the host acknowledgement remains absent. The original opaque input,
payload, provenance, cut, sequence, request, and native resources survive.
Identical retry cannot produce another native acceptance.

The artifact format can store a compact manifest with bounded content objects
in a local evidence directory. Original evidence stays outside the repository
and release assets. The manifest names exact content identities; missing raw
objects cannot be replaced by test log text.

## Independent acceptance gate

The source-built package gate independently resolves and validates the entire
required evidence closure. It checks:

- The exact installed implementation/profile/configuration/environment tuple.
- The actual measured emitter, provider, controller, companion, source, and
  tool identities.
- The complete predeclared case population and trusted applicability mapping.
- Original scopes, raw requests/responses, complete source-defined receipt
  semantics, immutable input/output octets, native budgets, and cleanup.
- Independent oracle results and all required positive/negative outcomes.
- Qualification class, exercised state/interaction domains, and exclusions.

The gate does not accept a Boolean verdict, protocol report, source inspection,
mock adapter, successful boot, or passing parser as a substitute for the
required native behavioral evidence. Source inspection supports the explicitly
defined source obligations; it does not manufacture live timing or exact
continuation results.

Accepted fixed-profile evidence can then satisfy the separate installed
behavioral ledger conjunct. It cannot weaken scenario admission, bypass native
owner verification, advertise another profile's capabilities, or certify a
generic third-party provider.

## Implementation sequence

1. Add isolated bounded observation snapshot records/helpers. Keep secrets and
   native authority outside the portable artifact.
2. Add the source-owned fixed-profile plan, oracle, and actual endpoint runner
   under mandatory finite native supervision.
3. Emit original evidence from real cases, including accepted-input uncertainty
   and same-incarnation original-operation reconciliation.
4. Add the independently verifying hermetic package gate and its adverse
   altered/missing/foreign/incomplete evidence cases.
5. Wire accepted evidence into the installed behavioral ledger and selectable
   public CNP factory. Existing unqualified paths continue to refuse.
