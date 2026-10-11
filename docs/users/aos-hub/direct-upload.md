# Qualify and activate hybrid direct uploads

Direct uploads use the hybrid topology: Native owns admission and publication,
while the Worker grants exact multipart UploadPart requests and verifies the
closed private source before promotion. Installation prepares the protected
runtime. Production dispatch requires an independently signed acceptance of the
exact current Worker source, hosted script version, profile, clock and queues.

Build the source-based installer with `bash ./aos-dev build package
aos-hub-cloudflare`. Use one persistent provider credential through Wrangler's
existing `CLOUDFLARE_API_TOKEN` or browser login. The account provisioning
credential stays with provider tooling. The bucket-scoped R2 S3 pair is a
separate persistent runtime credential, supplied through owner-private files and
delivered only as Worker secrets. Native never receives that pair. Routine
deployments preserve existing omitted secrets; uploads do not mint new tokens.

## Prepare the fixed deployment

Select the Worker name, public and private Native origins, deployment ID,
private R2 bucket, permanent bucket namespace, two dedicated queue names and a
purpose-specific KV namespace. Create or adopt the KV namespace using your
existing provider tooling. Use separate ingress, storage-work, physical guard,
durable journal and optional conformance control keys. Native and the Worker
must share the ingress, storage-work and guard keys for their respective roles.

Store the R2 profile in the closed JSON format documented in
[`HybridDirectUploadDeployConfig`](../../../crates/aos-hub/src/cloudflare/direct_upload.rs).
Its credential generation and public secret version reference identify the
persistent pair. Install a fixed `bounded_utc` clock policy with a conservative
uncertainty below thirty seconds. `clockQualification` is the stable commitment
returned by `DirectClockPolicy::commitment()`. The private policy digest is
`direct_private_stage_policy_commitment(policyId, namespace)`, committing to
denied public and unauthorized reads and one guarded physical writer. These
installed commitments contain no measured report digests. Actual clock and
privacy observations belong only in the independently signed acceptance.
The profile contains no secret values or manually selected credential fingerprint.
Install the independently trusted reviewer public key as a separate file
containing 64 lowercase hexadecimal characters. Neither the acceptance document
nor the registry supplies its own verifier.

Set these operator-selected values and file paths before running the example:
`WORKER_NAME`, `BUCKET`, `DEPLOYMENT_ID`, `PUBLIC_ORIGIN`, `NATIVE_ORIGIN`,
`ACCEPTANCE_NAMESPACE_ID`, `BULK_QUEUE`, `METADATA_QUEUE`, `MAX_PARALLEL_OBJECTS`,
`BULK_MAX_INVOCATIONS`, `METADATA_MAX_INVOCATIONS`,
`PROFILE_FILE`, `REVIEWER_PUBLIC_KEY_FILE`, `INGRESS_KEY_FILE`,
`STORAGE_WORK_KEY_FILE`, `GUARD_KEY_FILE`, `JOURNAL_KEY_FILE`,
`S3_ACCESS_KEY_FILE`, `S3_SECRET_KEY_FILE` and `CONFORMANCE_KEY_FILE`.
Select fixed `MAX_PROVIDER_REQUESTS` (two through thirty-two) and
`MAX_OBJECT_BYTES` (positive, within the direct object cap) for isolated
qualification before deploying. These are candidate limits, not acceptance.
Secret files must be ordinary owner-private files in trusted directories and
contain exact printable key bytes without leading or trailing whitespace. Native consumes
these same bytes; the installer rejects a newline instead of changing the key.

```sh
hybrid_config=(
  --name "$WORKER_NAME" --bucket "$BUCKET"
  --deployment-id "$DEPLOYMENT_ID"
  --external-url "$PUBLIC_ORIGIN" --native-origin-url "$NATIVE_ORIGIN"
  --direct-upload-profile-file "$PROFILE_FILE"
  --direct-upload-qualification-public-key-file "$REVIEWER_PUBLIC_KEY_FILE"
  --direct-upload-acceptance-namespace-id "$ACCEPTANCE_NAMESPACE_ID"
  --direct-upload-bulk-queue "$BULK_QUEUE"
  --direct-upload-metadata-queue "$METADATA_QUEUE"
  --direct-upload-maximum-parallel-objects "$MAX_PARALLEL_OBJECTS"
  --direct-upload-bulk-maximum-concurrent-invocations "$BULK_MAX_INVOCATIONS"
  --direct-upload-metadata-maximum-concurrent-invocations "$METADATA_MAX_INVOCATIONS"
  --direct-upload-conformance
  --direct-upload-qualification
  --direct-upload-qualification-maximum-provider-requests "$MAX_PROVIDER_REQUESTS"
  --direct-upload-qualification-maximum-object-bytes "$MAX_OBJECT_BYTES"
)

./result/bin/aos-hub worker render-hybrid-config "${hybrid_config[@]}" > wrangler.toml
./result/bin/aos-hub worker install-hybrid "${hybrid_config[@]}" \
  --hybrid-ingress-key-file "$INGRESS_KEY_FILE" \
  --storage-work-key-file "$STORAGE_WORK_KEY_FILE" \
  --direct-upload-guard-key-file "$GUARD_KEY_FILE" \
  --direct-upload-journal-key-file "$JOURNAL_KEY_FILE" \
  --direct-upload-access-key-id-file "$S3_ACCESS_KEY_FILE" \
  --direct-upload-secret-access-key-file "$S3_SECRET_KEY_FILE" \
  --direct-upload-conformance-key-file "$CONFORMANCE_KEY_FILE"
```

The installer attaches the stable reviewer verifier, acceptance KV binding,
version metadata, physical journal classes and separate queues. It ensures a
bounded abandoned-multipart cleanup policy on the selected bucket. Configure
and independently inspect provider privacy and exact-origin browser upload CORS
before qualification. Each participating isolate has one aggregate object and
provider pool. Bulk uses at most one less than its object/request ceiling;
metadata borrows unused slots up to the same ceiling and can still progress
while bulk holds its full allowance. Separate global queue invocation limits
are explicitly selected between one and thirty-two. Batch sizes default to the
bulk class ceiling and metadata aggregate ceiling; optional batch overrides
must fit those bounds. With invocation limits `Ib`/`Im` and batch sizes
`Bb`/`Bm`, up to `Ib + Im` global invocations and `Ib*Bb + Im*Bm` delivered jobs
can coexist across isolates. The isolate ceiling is not a global job limit.
Independent evidence must cover actual consumer configuration readback,
all-metadata parallel capacity and metadata progress under bulk load.
Metadata qualification exercises the production narinfo parser, whose source
limit is 256 KiB: it must positively verify at least the smaller of that limit
and the accepted object ceiling. Bulk and runtime measurements must cover the
full accepted object ceiling. This does not measure registry JSON publication
throughput; that workload requires its own publication measurements.

Keep the completed Worker version unchanged throughout measurement and
activation. Updating code, bindings or secrets changes the hosted script version
and requires new measurements and acceptance.

## Capture actual evidence and obtain independent acceptance

Capture the current protected public projection with the existing guard key:

```sh
./result/bin/aos-hub worker inspect-hybrid-direct-upload "${hybrid_config[@]}" \
  --direct-upload-guard-key-file "$GUARD_KEY_FILE" > deployment-identity.json

./result/bin/aos-hub-direct-sdk-conformance \
  --endpoint "$PUBLIC_ORIGIN" --account-id "$ACCOUNT_ID" --bucket "$BUCKET" \
  --control-key-file "$CONFORMANCE_KEY_FILE" \
  --output-dir "$SDK_EVIDENCE_DIRECTORY"
```

Set `ACCOUNT_ID` from the selected profile and use a fresh owner-private
`SDK_EVIDENCE_DIRECTORY`. Browser qualification also supplies
`--browser-origin "$BROWSER_ORIGIN"`. The protected hosted probe records actual
ordinary R2 Create, Complete, Head, streamed whole-object and range reads,
streamed range UploadPart copy, Abort, negative late parts, separate object
versions and direct S3 checksum rejection. It retains unknown effects and never
grants production acceptance. Its output includes `sdk-document.json` and an
evidence manifest identifying the additional unmeasured requirements.

The separate qualification opt-in permits only protected isolated fixture work
with the installed candidate bounds and the conformance control key, using
distinct authentication domains. It grants no logical publication or normal
upload authority. Its measurements must exercise the same bounded provider pool
and reserved bulk/metadata queue capacities used by the production runtime.

Independently collect and retain mutation-clock observations, provider and Worker
namespace privacy readback, physical writer exclusivity, bounded source-size and
verification-duration samples, provider request concurrency and both queue class
measurements. The SDK probe alone does not measure those requirements. Queue
reports must identify the actual same compiled source and current hosted version.
The private namespace report must establish zero independent writers bypassing
the guard. Retain the raw reports whose SHA-256 commitments appear in the closed
measurement documents.

For managed public-read privacy, retain the actual bucket public/custom-domain
policy API readback, an authenticated-positive exact existing object and the
complete anonymous reply from that same object's managed public endpoint.
Correlate the account, bucket and endpoint explicitly. Denials `401`, `403` or
`404` can be reviewed; a bare S3 endpoint's missing-authentication `400` does not
qualify disabled public access. A substring check cannot certify absence of
partial leaks or exclusive physical writers.

An independent reviewer accepts the full
[`DirectWorkerQualificationArtifact`](../../../crates/aos-hub-core/src/direct_upload/worker_qualification.rs).
The artifact binds the discovered complete managed credential fingerprint, every
external protected profile selected, clock uncertainty, runtime ceilings, both
queues, SDK observations, report commitments and original validity cutoff.
Its Ed25519 signature covers the canonical domain-separated identity produced by
`signing_bytes()`, including the complete evidence digest, reviewer identity,
deployment, public origin, source and hosted version. The operator installer
does not create this signature or turn an arbitrary digest into qualification.
The separate [independent review tool](direct-upload-review.md) prepares a
candidate from actual retained reports and signs only an explicitly reviewed
candidate hash under the separately installed reviewer key.

For external-only deployments, select a closed transport clock file with
`--direct-upload-clock-file` instead of the managed profile and omit the managed
S3 and SDK probe options. Capture only exact independently selected external
providers with `inspect-hybrid-direct-upload
--direct-upload-external-selectors-file "$SELECTORS_FILE"`. The shared artifact
requires full accepted external wrappers and the same measured runtime, clock
and separate queues. Production installation accepts hosted execution only.
Explicit emulated external acceptance is restricted to the qualification build.
When the emulator does not support a global queue invocation bound, its actual
consumer readback and signed delivery policy record that bound as `null`.
This grants no global invocation cap claim. Observed batch sizes, participating
isolate object/provider ceilings, mixed metadata progress and exact installed
runtime bytes still require independent review. Hosted delivery requires an
explicit numeric invocation bound for each queue.
External direct providers currently require objects of at least one byte until
exact-incarnation zero-byte deletion is independently qualified. Use a qualified
managed profile for empty objects; otherwise discovery refuses that capability.
Hybrid direct-required operation does not fall back to Native bulk transfer.

## Activate the unchanged version

Supply the independently signed document as `ACCEPTANCE_FILE`:

```sh
./result/bin/aos-hub worker activate-hybrid-direct-upload "${hybrid_config[@]}" \
  --direct-upload-acceptance-file "$ACCEPTANCE_FILE" \
  --direct-upload-guard-key-file "$GUARD_KEY_FILE"
```

Activation checks the reviewer signature and validity, obtains a fresh signed
projection from the current Worker, and compares its actual source, hosted
version, material-derived profiles, trusted verifier, clock and queue bindings.
It writes only the checked artifact to the purpose-specific KV key
`aos.direct-upload.acceptance.v1/<deployment>/<source>/<current-script>` using
the existing provider credential. It does not deploy another Worker version.
KV propagation can delay availability; missing or stale records keep new
dispatch closed. Install the same independent artifact and separately trusted
reviewer key map into Native's hybrid direct runtime, as described by the
[hybrid deployment policy](../../rfcs/0023-hub-hybrid-topology/05-state-deployment-and-portability.md).

Routine `worker deploy-hybrid` updates preserve omitted existing protected
secrets. Any resulting hosted version needs fresh qualification and acceptance
before new direct effects. Preserve the permanent namespaces and journals across
updates and credential rotation; an unknown provider effect remains fenced until
its original positive terminal receipt is reconciled.
