# Native Hybrid ingress application bodies

The selected Managed outer workflow calls `finish_managed_storage_window` for
all process-stable epochs. It invokes the current held codec over every captured
Native outbound original and every Worker original ingress, and consumes the
published general execute attempt collector. Unsupported, failed, omitted and
unassigned rows remain in the full inventory and make the corresponding final
assessment incomplete. Existing per-invocation codec and global corpus limits
are unchanged.

## Existing checks and actual frames

The Native Hybrid ingress middleware emits
`native_ingress_application_body_observation` after a response body is dropped
or a cancelled invocation loses its last owner. It retains only hashes, counts,
fixed stages, actual observation times and the existing nonauthorizing fleet
request ID. `requestConsumed` counts application frames actually exposed to the
Native body reader. `replyOffered` counts frames offered by Native, and is not a
claim about bytes received by the Worker or client. Empty, unread, prefix, error,
overflow, cancellation and EOF outcomes remain distinct. Trailers and frames are
forwarded unchanged; there is no additional reader, database query, permission,
provider dispatch or HTTP field.

Core request-scoped records hash the exact context of already-performed actor,
visibility, repository-grant, read-policy and catalogue checks. A rejected check
stays rejected. A hash is neither a new authorization nor proof of a later SQL
state. The task-local collector is bounded to 32 records and 128 KiB of serialized
input per context. Native log records are bounded to 16 KiB; an unavailable,
oversized or incomplete observation cannot become a positive receipt.

## Source and capture joins

`boundaries.ingressObservationSources` selects two exact hashes from the current
reviewed Native source:

- `nativeHandlerSourceSha256`: `server.rs || server/hybrid_observation.rs`.
- `checkedContextSourceSha256`: `hybrid_ingress/observation.rs` in Core.

The selected executable and complete source provenance remain independently
required. The current codec source commitment is the SHA-256 of the ordered
bytes `main.rs || files.rs || classify.rs || storage_work.rs || ingress.rs ||
controls.rs`. Historical helper or console provenance cannot be relabelled.

The collector reopens owner-private log/body/header references, checks their
actual retained process and file window, and joins exactly one event to one
original and received request ID. Method, phase, target, compact header, status,
body hashes and counts must agree. An envelope refusal has no authenticated
phase; its offered phase remains bound by both independent proxy captures.
Native exposed prefixes must match the corresponding prefix of the complete
independently captured body. Reused or unassigned events refuse coverage.

## Body classification and limits

Shared production DTOs and observation predicates classify exact small protected
controls, OCI Distribution controls, selected semantic browse replies and
canonical documentation. Successful small-control decoding asserts no MAC or
current permission. Refused protected controls accept only their known fixed
source-owned status/type/text and bounded typed request. Other refusal bodies
remain unsupported. Canonical documentation is counted as document body bytes;
unknown JSON fields and substituted document digests refuse classification.

A partial metadata-only body can be classified after full upstream body decoding
and exact exposed-prefix matching without inventing acceptance. A partial
content-bearing body needs a reviewed byte mapping and remains unresolved here.
Expected refusals are counted separately from successful existing checks; they
cannot borrow another invocation's acceptance.

The final consumer's `complete` describes complete captured body classification
and its required existing joins. `capturedApplicationObjectByteUpperBound` is a
bound on the full independently captured object-body partition.
`capturedApplicationBodyBytes` retains exact original-request and full-reply
counts from the correlated actual body references, including controls. It does not
invent actual Native consumption: `nativeConsumedApplicationBytes` and
`nativeBulkBytes` remain null when that consumption is unknown. Independent
current actor, SQL, purpose, placement and provider evidence retain their
separate actual scopes. No supplied status, digest dictionary or configured
zero supplies them. These are application payload observations, not TLS wire
billing, provider qualification or a five-machine runtime result.
