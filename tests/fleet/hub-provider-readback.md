# Read-only provider observations

`aos-hub-provider-readback` performs a finite selection of metadata reads against
an existing S3-compatible bucket and, optionally, the Cloudflare R2 API. It
does not upload, fetch object contents, abort multipart uploads, change bucket
policy, create credentials, retry, or install acceptance.

## Inputs and scope

The selection and credentials arrive through two distinct inherited descriptors
numbered at least 3. Each must refer to an owned, single-link regular
file without group or other access (normally mode 0600 or 0400). Anonymous
temporary files and pipes are refused. Credential values and
credential-file hashes are never included in receipts or error text.

The selection is closed JSON, for example:

```json
{
  "version": 1,
  "provider": "s3",
  "endpoint": "https://storage.example",
  "bucket": "example-bucket",
  "prefix": "tenant/qualification",
  "objectKeys": ["tenant/qualification/object"],
  "operations": ["bucket_head", "cors", "lifecycle", "objects", "multipart", "object_head"],
  "accountId": null,
  "tokenId": null,
  "tokenKind": null,
  "startsAt": 1800000000,
  "expiresAt": 1800000300,
  "maximumResponseBytes": 1048576
}
```

The timestamps are examples, not a usable window. The original window is at most
300 seconds. Wall, BOOTTIME and monotonic deadlines all remain active; two seconds
are reserved inside that window for retention. The deadline is checked again
after durable intent publication and before the sole request dispatch, and at
each exposed response chunk and EOF. There is no automatic continuation.

S3 operations are `bucket_head`, `cors`, `lifecycle`, `location`, `versioning`,
`policy`, `objects`, `multipart`, and `object_head`. Prefixes and keys are
restricted to ASCII letters, digits, slash, dot, underscore and hyphen, without
empty or traversal components. Each selected object key is below the exact
prefix. At most 16 object HEADs are selected. Each listing reads just one page
of at most 1,000 entries. The returned object page must echo the selected bucket
and prefix; pagination remains explicitly incomplete.

R2 operations additionally include `r2_bucket`, `r2_cors`, `r2_lifecycle`,
`token_verify`, and `token_details`. They use the fixed official Cloudflare API
origin. The selection names an account ID, and token operations specify `user`
or `account`; token details also require the exact token ID. User token reads
are `/user/tokens/...`; account token reads are `/accounts/<id>/tokens/...`.
No token-list or token-creation operation exists.

Credentials are closed JSON with optional `s3` (`accessKey`, `secretKey`,
`region`) and optional `cloudflareToken`. Only already-provisioned credential
material is consumed. Session credentials are unsupported and refused by the
closed schema. SigV4 uses the existing Core signer with an expiry bounded by
the remaining original window. A successful HEAD never renews source authority.

## Build and invocation

The separate `_hub-provider-readback.nix` recipe uses the selected AOS Native
Cargo contract and vendor input, without changing the ordinary Native package.
It compiles a SHA-256 commitment over the eight listed implementation/test
inputs. An executable without that compiled commitment refuses before opening
the credential descriptor. The recipe includes nine offline Native contract
cases; two additional Core cases cover the closed metadata signer. No new
Cargo dependency or lockfile entry is required.

An owner opens the two private files, passes their descriptors to the selected
source-built executable, and supplies a fresh output directory below an
existing private parent:

```text
aos-hub-provider-readback --selection-fd 3 --credentials-fd 4 --output-dir PRIVATE_NEW_DIRECTORY
```

Descriptors must actually be inherited, rather than named as command-line file
contents. Redirects, proxy discovery and HTTP retry are disabled. TLS uses the
ordinary trusted HTTPS verification path. Output creation checks and holds each
ancestor without following links; the immediate parent is owner-private.

## Observations and limits

The journal contains selected metadata, the actual producer executable hash,
byte count, PID/start ticks/UID/boot and network/mount namespaces, durable intent,
and per-call response observations. Intent records semantic method/route,
constructed target and header-field byte counts, and zero request-body bytes.
Authentication values, signed query contents and their hashes are excluded.
Transport-added headers, TLS framing and billed bytes remain unknown.

Responses retain status, selected safe headers, exact exposed application-body
count, EOF and outcome. Bodies are buffered only up to the selected bound.
Partial, oversized, credential-reflecting or credential-bearing token responses
have no persisted body or body hash. Complete safe bodies are retained privately
with their actual hash and byte count. Encoded responses remain measured bytes;
schema interpretation requires identity encoding. Network failure does not
claim an authenticated TLS response or remote drain.

An object page reports exact listed keys, sizes, strong ETags and truncation.
Other bucket metadata and multipart pages retain their bounded raw response;
their interpretation remains unknown. A successful Cloudflare API envelope
retains its observed result, independently of effective-permission or credential
association claims. Token status is not proof of bucket permission. Denial
statuses do not establish bucket absence, object absence or global exclusion.

The tool returns **2** after retaining observations, including incomplete or
refused responses, and **1** on a preparation, custody or retention failure.
`qualificationComplete` is always false. Full inventory, effective permissions,
global writer closure, provider settlement and remote drain remain null. This
metadata tool does not prove physical object integrity; that requires a
separately qualified storage-local integrity operation without Native transit.

## Test scope

The local contracts exercise finite route construction, exact prefix selection,
mutating/bulk selector refusal, expiry, actual private-file modes/counts,
create-only and symlink custody, bounded exposed bytes, secret reflection and
escaped JSON secret fields, typed list scope/truncation, and token permission
unknowns. These tests do not contact providers or qualify live TLS, IAM,
storage contents, performance, or Hosted acceptance.

Official request and permission contracts are documented by
[Cloudflare R2](https://developers.cloudflare.com/api/resources/r2/subresources/buckets/),
[Cloudflare account tokens](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/),
[S3 CORS](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketCors.html),
[S3 multipart listing](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html),
and [S3 policy actions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html).
