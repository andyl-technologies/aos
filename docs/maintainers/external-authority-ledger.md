# External physical authority control proposal

This milestone connects the reviewed `storage_authority` contracts to a Worker
control ledger and the existing Native storage-work client. It does not admit
provider object operations or enable external DELETE. Its protocol transports
publication, explicit denial recovery, and fresh watermark lookup.

## Permanent identity and deployment ownership

`guard_namespace_id` identifies the actual configured immutable executor/object
DO namespace. Several approved physical buckets can share it. Each object scope
contains that namespace, its permanent `physical_authority_id`, and the full
bucket-relative key. Binding IDs, credential generations, signing regions and
endpoint aliases do not split the object fence.

The Worker requires operator-controlled `HUB_EXTERNAL_GUARD_NAMESPACE_ID` and
`HUB_EXTERNAL_STORAGE_EXECUTOR_ID`. Ordinary requests and SQL restoration cannot
set them. Missing configuration rejects authority control. The configured
namespace must be verified against actual provider deployment resources; an
arbitrary matching string is not ownership evidence. The current SDK does not
independently discover that resource identity from the DO binding.

The new `HYBRID_AUTHORITY_STATE` binding owns one fixed-address SQLite DO. Its
durable domain pin prevents changing a configuration label from selecting an
empty ledger in the same namespace. Deployment automation must also preserve
both actual ledger and object-guard namespace resources. Rebinding the class,
deleting its storage, or restoring its state backwards is outside the safe
contract. Such a deployment must fail admission until independently reviewed
recovery establishes the retained physical identity and outstanding effects.

The publication retains the exact immutable attestation and every binding fact
it references. Desired admission may select a sorted subset of those facts,
matching the SQL contract. Auxiliary attested associations remain permanently
reserved but cannot resolve object work scopes until explicitly admitted with
their own attested writer coverage. Narrowing admission never trims or rewrites
an existing attestation.

`CreatePhysicalStorageAuthority.qualified_managed_prefix` is the immutable root-
reviewed ceiling covered by initial zero-operation qualification. It is required
in specification JSON; missing legacy fields fail closed rather than being
inferred from an attestation or provider observation. Empty explicitly qualifies
the whole bucket. The ledger reserves this creation ceiling even if the first
published admission is blocked or its attestation is already narrow. Later
attestations may narrow or reopen inside that ceiling with renewed exclusive
evidence; expansion beyond it rejects. SQL snapshot or delivery order cannot
choose a different ceiling. No prefix change settles existing pending effects.
Prefixes use the existing canonical binding form without leading or trailing
slashes. Containment follows path components: `foo/root` includes
`foo/root/object`, but does not include `foo`, `foo/root-other`, or `foobar/root`.

Global permanent reservations cover authority identity, exact canonical alias,
physical-resource evidence digest, alias IDs, immutable binding associations,
attestations and qualified managed prefix. An evidence digest reserves an already
approved fact; equality or inequality does not prove provider equivalence.
Alias ownership cannot transfer or merge after blocking or retirement. Root
approval remains responsible for proving that newly approved aliases identify
the same resource and that the namespace is exclusive and initially qualified.

## Fresh authenticated reconciliation

The bounded control endpoint uses the existing paired `StorageWorkKey` with
distinct request and response signature domains. Each Native exchange creates
a new 256-bit nonce and a maximum thirty-second deadline. The Worker response
authenticates its configured domain, nonce, full request digest, response time,
latest durable watermark, and any exact control receipt. Wrong-domain signatures,
changed responses and old responses for another nonce reject.

Ordinary publication advances only from its exact predecessor generation and
admission digest. Immutable reservations, full desired head, compact watermark
and control receipt commit in one SQLite transaction. An exact old control
replays its receipt alongside the latest watermark, including a later blocked
or retired generation. It cannot supply a fresh stale watermark after SQL
restore. Changed fact bundles at the same generation reject.

`DenyFromWatermark` can deliver the current blocked or retired SQL decision
across undelivered history. It retains that publication's SQL predecessor and
digest, and separately compares the exact freshly authenticated remote
watermark. Only a strictly higher denied floor can apply. Equal-generation
forks, known conflicting predecessor digests, backwards decisions and changes
after retirement reject. A denial has no alias/association member bundle.

The transaction stores the unchanged target publication receipt plus an
immutable denial-transition record containing the full transport payload and
its original remote CAS. Exact denial replay requires those same facts and CAS;
fresh nonces are not the operation identity. It returns the latest watermark.
Ordinary exact publication replay still proves the entire target bundle after
response loss. Skipped admissions receive no remote receipt or SQL
acknowledgement. All earlier reservations, receipts and pending object effects
remain unchanged. Denial is not drainage or provider capability revocation.

Native callers must invoke SQL reconciliation and
`storage_authority_admission_for_remote` with the verified fresh watermark.
Neither an old SQL acknowledgement nor receipt acknowledgement authorizes I/O.
An expired attestation prevents new admission but preserves historical control
receipts and the latest watermark. Retirement is terminal.

## Supported control limits

The proposal preserves the SQL contract's 256 associations and 256 attested
credential members, and supports 256 exact aliases per publication. Encoded
messages have a 768 KiB cap and reject before publication when oversized. The
serialized publication also reserves the maximum ordinary Publish request envelope
for deployment identities up to 128 bytes, namespace identities up to 255 bytes,
a 64-byte nonce, escaped JSON strings, and bounded integer timestamps. Both
model publication validation and exact request validation enforce these budgets
before writes. The count limit does not guarantee that every combination of
SQL-legal maximum-length fields fits; aggregate refusal leaves SQL desired
state pending and grants no provider admission.

The denial wrapper adds its explicit remote CAS without reducing the ordinary
Publish budget. Denied publications have no member collections; exact complete
denial requests still enforce the same 768 KiB cap before durable writes.

Model validation streams JSON into a capped byte counter and stops at the
limit, avoiding a second oversized encoded allocation before refusal. The
already-constructed model and SQL reads retain their own allocation bounds.

The actual Worker SDK transaction adapter partitions writes into API calls of
at most 128 pairs, all inside one SQLite-backed storage transaction. It does
not interpret that per-call cap as a transaction-total or membership limit.
Cloudflare documents the [multi-key call bound and transaction
semantics](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
and the [SQLite key/value size
limit](https://developers.cloudflare.com/durable-objects/platform/limits/).
The full publication stays below that backend's 2 MB value bound. The class
must remain SQLite-backed; this proposal does not qualify legacy KV storage.

The focused actual SQLite regression publishes 256 associations across the
same bounded API batches. An injected failure after the first batch rolls back
all reservations, head and receipt; the exact subsequent retry commits them.
It exercises the journal contract through AOS SQLx SQLite, rather than claiming
that this is a real workerd or cloud qualification.

## Remaining object integration and performance

The prerequisite object journal now wraps `StorageAuthorityObjectScope`; its
earlier ad-hoc approval-map constructor is available only in tests. Production
scope resolution must use these approved facts. The object adapter must independently validate the
addressed guard and fresh admission, match the exact current binding snapshot
and attested credential, and retain pending before provider effects. The
separate `StorageGuardStamp` is issued by the addressed object guard's durable
acknowledgement. This milestone never invents an incarnation or backfills one
from provider HEAD, ETag, SQL inventory, or credential rotation.

All previously audited direct writers and HEAD paths, presigned client PUT
issuers, credential probes, OCI staging cleanup, metadata writes and multipart
completion still require integration. Native/Workers-only direct writers must
reject guarded authorities. Existing client capabilities and provider requests
require explicit settlement or a genuinely unused namespace before activation.

The ledger stores rare root control and serves compact watermark reads. Bulk
bodies must bypass it and the object DO; addressed object guards coordinate
compact metadata only. Strict fresh revocation checks would add an authority
RPC and load on this single control object for each checked effect. That cost
needs actual latency/throughput qualification. This milestone uses no stale
cache and makes no unlimited scaling claim. It does not yet issue dispatch
permits or solve the admission/revocation race for in-flight object work.

No authority control operation accesses object pending state. Timers, expiry,
credential rotation, later HEAD, positive probes and SQL terminal state never
clear unknown provider effects. Receipt retirement and physical reclamation in
versioned S3 buckets remain unsupported. External DELETE remains disabled until
all visible writers, admission barriers and provider accounting are qualified.


## Journal value encoding

The Durable Object stores each entry as a versioned JSON string,
`{"version":1,"value":...}`. The outer bulk-write object contains strings,
so full SQL `i64` fields retain exact values through the JavaScript bridge.
Reading unsupported or legacy encodings fails closed; it never becomes a
missing authority, empty reservation, or fresh admission floor. This dormant
ledger has no implicit live-state migration or automatic reset.

The ordinary-value workerd artifact qualification and a later full-range
qualification remain separate evidence. A complete release qualification must
publish an exact `i64::MAX` attestation timestamp through the signed route and
verify the same durable state after restart. It must also qualify current
aggregate byte-budget corrections in the coherent production artifact.
