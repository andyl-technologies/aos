# Vendor protocol conformance runner

`crucible-node-conformance` exercises an actual external provider through public
CNP/1 envelopes. Its portable plans and reports use schema version 1. The
library implementation is `crucible_node_provider::conformance`; a trusted host
can supply its own `ProbeConnector` and `ProbeSession` without coupling the
runner to an engine or native implementation.

The runner establishes protocol behavior for the tested plan. It does not mint
execution authority or behavioral qualification. A successful capture response
does not prove complete future-affecting state coverage, and a successful
quantized response does not prove physical pause or CPU-model accuracy. Those
claims require the independent realized-provider experiments and accepted
evidence authorities in RFC-0025 chapter 08.

## Running a separately installed provider

Build the source package with `aos-dev build package crucible --no-out-link`.
Start the selected provider under its own trusted launch and supervision policy,
then run:

```text
crucible-node-conformance SOCKET EXPECTED_EXECUTABLE PLAN REPORT [PRIVATE_BINDINGS]
```

The Linux connector obtains actual `SO_PEERCRED`, requires the caller's effective
UID, and compares `/proc/PID/exe` bytes with the independently selected installed
executable. A full listening backlog refuses promptly. Each send and reply share
one three-second absolute deadline; a peer cannot extend it by sending one byte
at a time. The report also records the actual harness executable identity.

`REPORT` is a new caller-selected file. An existing file is refused. Exit status
0 means all planned cases and required checks passed; 1 means the report retains
a failure or omitted required check; 2 means setup, plan decoding or report
publication failed. Reports are ordinary evidence artifacts outside the source
repository and release machinery.

## Portable plans and private bindings

A plan contains `schema_version`, a fixture revision identifier, a finite
`required_checks` set, and ordered `steps`. `exchange` steps contain a complete
public CNP request envelope, its expected response shape, independent field
assertions, and optional captures. `malformed` steps send exact hostile bytes
behind the public four-byte frame length. `disconnect` steps fence the current
stream while preserving the fact that native operations may remain unresolved.

`canonical_content` constructs bounded canonical JSON from original captured
receipts and retains its exact ContentRef and Bytes in fresh private bindings.
`receive_blob` accepts one promised provider-origin BlobBegin/Chunk/Finish
transfer, verifies complete contiguous bytes against the original ContentRef,
and positively acknowledges independent probe custody. `inspect_content`
verifies those exact bytes and applies independent field oracles to the decoded
JSON. None of these local steps authenticates a native receipt or settles
publication custody. Native publication requires its separate consumption
operation. A request sequence may use `{"$sequence":"outgoing"}` to preserve
both directions' actual frame sequences after finite content-transfer replies.
`identity` decodes one selected CNP schema and applies its normative identity
projection to a fresh private binding. Typed projections normalize equivalent
accepted version/phase spellings and retain NodeBinding's exclusion of live
authority. Raw arbitrary hash domains are not accepted. An empty JSON Pointer
selects the complete original object.

Request templates and assertion values resolve an exact object of this form:

```json
{"$binding":"provider-incarnation"}
```

The separate private-binding file is a JSON object mapping names to values. It
supplies the launch token and controller nonce through the launcher's private
channel. Hello admission tokens, challenge bytes and resume tokens must use
private binding objects; inline credential values are refused before plan
hashing. The plan can capture fresh values from original replies:

```json
{
  "provider-incarnation":"/body/result/incarnation_id",
  "resume-token":"/body/result/resume_token"
}
```

Captured values cannot overwrite earlier evidence. A changed resumed value
uses a fresh binding name and explicit assertions against the original session,
incarnation, operation identity and retained outcome. The runner bounds plans to
16 MiB and 4096 steps, field oracles to 256 per exchange, and retained bindings
to 4096 values and 64 MiB. Unknown plan fields, duplicate JSON keys and duplicate
case identities refuse before a connection is opened.

## Required coverage and oracles

The supplied plan must declare the checks it requires. Reports retain missing
checks rather than treating omitted tests as passing. The available obligations
include hello and limits, unsupported contracts, descriptor/binding identity,
paused preparation, preactivation grant refusal, inputs, bounded grants,
capture or truthful capture refusal, duplicates, same-incarnation reconnect,
resource limits, malformed frames, publication and release. Positive content
uploads, world activation and consumed retirement each have separate check
classifications.

The runner independently decodes every ordinary request and method-specific
reply. It checks the complete original scope, sequence, nonce, feature selection,
receiving ceilings and resumed operation roster. Classifications must exercise
the corresponding method and operation kind. Resource cases must expect
`RESOURCE_EXHAUSTED`; activation-gate cases must expect `INVALID_STATE` with
`not_started` effect certainty. Changed duplicates must expect `CONFLICT`.

Independent JSON Pointer assertions compare exact reply values with test-authority
oracles. Tests for repeatability, capture fidelity and hidden timing state require
additional native observations and future-trajectory comparisons. Matching two
serializer hashes or retrying until an application output matches is insufficient.

A failure fences the stream and leaves dependent cases `not_executed`. The tool
does not retry uncertain effects, discard earlier failures, replace operation IDs,
or report a timeout as successful peer disconnection. The provider's surviving
native owners, journals, pending outputs and resource containment remain the
responsibility of its trusted supervisor.

Reports retain measured endpoint identities, the canonical plan identity, fixture
revision, all case verdicts, required-check omissions and request/reply identities.
Hello request/reply identities are absent so handshake credentials do not enter
report hashes. Reports exclude raw control bodies, private tokens and captured
payloads. Synthetic
protocol-unit tests remain distinct from the actual controlled-process reference
profile and from vendor behavioral qualification evidence.

## Controlled reference-service integration

The source-built integration suite launches `crucible-reference-provider` with
its independently measured `crucible-reference-device` child. Private admission
and bootstrap configuration travel through framed stdin; private fixture and
socket directories are inaccessible to other users. The probes use public
CNP/1 envelopes over the actual Unix endpoint, including the packaged runner
CLI, rather than calling dispatcher functions or substituting reply fixtures.

The suite verifies initial and resumed handshakes, original request replay and
changed-request conflict, negotiated receiving limits, unsupported required
features, malformed-stream fencing, and compact credential-free report output.
Its complete native-window scenario exercises withheld preparation, graph
admission, refusal before world activation, the complete activation transaction,
truthful capture refusal, retained input bytes, and an actual stateful checksum
window. It checks operation-credit exhaustion while that window's publication
is still retained.

The probe receives and verifies the original output, physical measurement,
pending inventory, staged observation batch and stop receipt. Closing the
window creates a separate committed batch, which is also transferred and
verified against the fixed publication boundary. A matching consumed receipt
then retires the original operation and acknowledges the child publication;
shutdown confirms actual child reaping before owner release. The reference
profile remains nondeterministic and does not advertise capture or exact
continuation. These experiments establish protocol and custody behavior for
this controlled checksum implementation, without qualifying CPU fidelity or
additional vendor implementations.
