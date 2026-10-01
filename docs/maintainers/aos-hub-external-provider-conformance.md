# External S3 provider conformance

`aos-hub-provider-conformance` runs a bounded storage experiment on the
operator's machine. It uses the shared ordinary `S3Surface` SigV4 signer and
strict provider receipt parsers with an explicit HTTPS client. It does not run
inside the Native Hub service and does not route object bodies through Native
control RPCs.

The resulting closed observation report is input to independent provider and
private policy review. It does not emit an accepted `ProviderContract`, approve
writer closure, configure a Worker, sign runtime acceptance, or establish
Worker SDK compatibility. The actual deployed Worker still needs its separate
queue and streamed verification experiment with an object of at least 2 GiB.

## Protected inputs

Select an already reviewed private stage namespace and its exact policy
reference. The policy review must cover the actual writers, credential closure
and source immutability assumptions. Anonymous denial from this experiment is
one observation; it cannot establish that complete policy by itself.

The closed configuration file has this shape. Paths resolve relative to the
configuration file. The endpoint is an HTTPS origin, with no path, query,
userinfo or fragment. The staging prefix must end in `.aos-direct-upload`.

```json
{
  "version": 1,
  "endpoint": "https://storage.example",
  "bucket": "reviewed-private-bucket",
  "staging_prefix": "reviewed-scope/.aos-direct-upload",
  "credential_file": "credentials.json",
  "private_policy_file": "private-policy.json",
  "policy_review_file": "independent-policy-review.json",
  "policy_review_sha256": "<explicitly reviewed lowercase SHA-256>",
  "tls_ca_file": null
}
```

The credential file is closed JSON with `access_key`, `secret_key` and `region`
strings. It must be a regular file owned by the invoking Unix user, with no
group or other permissions. Symlinks are refused. Pass the file path through
configuration; do not put credentials or signed part URLs in arguments. An
optional PEM CA file adds the selected provider CA without disabling TLS
verification.

`private-policy.json` contains the exact existing `DirectPrivateStagePolicyRef`
JSON fields: `policyId`, `policyDigest` and `namespace`. The tool checks its shared
core commitment. It also hashes the independent policy review file and requires
the selected `policy_review_sha256`; it does not manufacture a review or infer
its approval from provider responses.

## Run and retained state

Build with the source-built development environment or use the packaged binary.
The package includes this operator binary alongside the other Hub tools.

```text
aos-hub-provider-conformance run \
  --config-file operator-config.json \
  --journal-directory new-provider-run \
  --output new-provider-observations.json

aos-hub-provider-conformance status \
  --journal-directory new-provider-run
```

The journal directory and report must be new. The tool selects a unique child
under `.aos-direct-qualification/<run-id>` inside the reviewed staging prefix.
It creates a private journal and synchronizes each immutable mutation intent
before dispatch. It retains request and authorization commitments, exact part
digests and completion manifests. Bounded response commitments are retained
separately from validated effect observations. Signed URLs and credential values
are never stored in the journal or report; errors are value-free.

Automatic retries and redirects are disabled. A lost response, malformed
positive receipt, failed verification or unknown mutation leaves its original
intent retained. Running against the same journal refuses to dispatch again.
`status` reads the files without provider requests; it never clears unknown
effects by expiration, absence, timeout or cleanup. Successful experiments
retain three positively verified objects, reported as `retained_known_objects`.

## Observations and review scope

The source object is 5 MiB plus 32 KiB, split into two legal multipart parts.
The report binds the actual executable hash, package version, original run,
selected provider coordinates, private policy reference and review commitment.
The same production orchestration performs these experiments:

| Observation | Actual check |
| --- | --- |
| Ordinary Create and Complete | Exact positive provider XML for the original bucket, key and upload; HTTP success alone is insufficient |
| Direct part integrity | Length and Content-MD5 signed into the exact part request; changed bytes produce an identified checksum refusal before the original good part is sent |
| Closed upload after Complete | The original part authorization minted before Complete receives `NoSuchUpload` afterward |
| Completed source identity | HEAD matches the positive Complete ETag and expected size; full streamed GET hashes the actual bytes under that original ETag |
| Private completed stage | Anonymous GET to the positively verified object receives an identified 401, 403 or 404 denial |
| Streamed copy | Exact ranged GET with original `If-Match`, size, range, version and SHA checks, followed by checksummed multipart upload and destination rehash |
| Provider multipart copy | Actual signed `UploadPartCopy` with exact source and byte ranges; positive CopyPart and Complete receipts plus full destination SHA and size |
| Source consistency | Original source is read and rehashed again after provider copy under the retained ETag/version |
| Abort closure | A distinct original upload receives positive Abort, then its original earlier part authorization receives `NoSuchUpload` |

The ordinary provider copy signer deliberately relies on the independently
reviewed private immutable source and has no invented source condition header.
Its explicit source read before and after the experiment checks that selected
incarnation; it does not prove future immutability or replace the production
physical guard's reservation.

Independent review can use these observations and their exact report commitment
for the existing `ProviderContract` properties. It must separately bind the
reviewed contract identifier, private policy and selected provider deployment.
Hosted Cloudflare runtime claims require actual hosted evidence; an emulator
experiment remains emulator evidence. Neither this report nor a copied set of
positive property flags activates normal direct-upload discovery.
