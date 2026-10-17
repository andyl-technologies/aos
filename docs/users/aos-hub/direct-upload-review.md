# Independent direct-upload acceptance review

`aos-hub-direct-review` prepares an unsigned candidate from actual retained
observations and signs only an explicitly selected candidate hash. It runs
offline and writes new files. Activation remains a separate installer action
against the unchanged Worker version.

Install the independent public verifier, profile, clock policy, qualification
limits and queue bindings before collecting observations. Keep the reviewer seed
separate from Worker secrets. The seed file contains exactly 32 raw Ed25519
bytes, has owner-only access, and lives under trusted directories; symlinks,
hard links, FIFOs and oversized files are refused. The public file contains
64 lowercase hexadecimal characters, optionally followed by one newline.
Generate the stable preinstalled clock policy with the shared serializer:

```sh
aos-hub-direct-review clock-policy --uncertainty-seconds "$CLOCK_UNCERTAINTY_SECONDS"
```

This produces a public policy and commitment. It asserts no measurements or
readiness; install its fixed values before capturing the unchanged script.

## Collect and select actual inputs

The source-built Cloudflare package supplies `aos-hub-direct-qualification`.
Select actual regular source files and their dependency classes in its private
manifest. Its protected isolated run creates no logical publication authority:

```sh
aos-hub-direct-qualification \
  --origin "$WORKER_ORIGIN" \
  --control-key-file "$QUALIFICATION_KEY_FILE" \
  --identity-file deployment-identity.json \
  --manifest-file qualification-sources.json \
  --output-dir qualification-observations
```

Retain the immutable original, complete authenticated control replies and their
MAC records. Independently inspect their provenance and exact installed
source/script/profile. A pending run, unknown effect, terminal replay or missing
same-isolate overlap cannot substitute for positive fresh measurements.
The driver checks protected reply authentication during capture. The reviewer
tool checks selected file commitments and internal consistency; it does not
verify the private control-key MAC itself or establish actual network provenance
from arbitrary operator files. Independent human review of retained captures,
authentication records and installation observations completes that evidence
chain before selecting a candidate hash for signing.
Every selected receipt must explicitly identify a fresh verification. Provider
counter differences describe activity in that isolate during the interval;
they cannot attribute unrelated overlapping dispatches to the selected object.

Write a closed version-one selection JSON. Every selected file is an explicit
`{"path":"relative-or-absolute-path","sha256":"actual-lowercase-file-hash"}`.
Relative paths resolve beside the selection file. The public Rust schema is
[`DirectReviewSelection`](../../../crates/aos-hub/src/direct_upload_review/selection.rs).
It contains:

- Exact execution kind, reviewer identity, deployment/origin, compiled source,
  current script and deployed Worker name.
- Explicit runtime object/provider ceilings, verification/settlement bounds,
  issue time and immutable expiry; quantities use decimal strings.
- `documents`: installed public verifier, actual protected deployment identity,
  and, where required, hosted SDK, privacy and installed-artifact documents.
- `reports`: unique `clock`, `runtime`, `bulk_queue`, `metadata_queue`,
  `mixed_load`, `bulk_configuration` and `metadata_configuration` raw reports.
  Managed use also requires `privacy`, `privacy_policy` and
  `sdk_checksum_rejection`.
- `captureFiles`: complete authenticated qualification reply bytes referenced
  by raw rows. `privacyFiles` retains complete HTTP metadata, header/body files
  and the independently evaluated writer review document.
- `installedFiles`: selected source/distribution NAR, Wasm, shim and runtime
  binding bytes. Emulator execution additionally requires runner and runtime
  executable bytes matched to the independent live-process report.

The helper derives measured counts, sizes, intervals and peaks from those raw
rows, then compares actual receipt counters and immutable proofs. It requires
all-metadata local saturation and positive metadata completion while the bulk
allowance is held in the same isolate. Global hosted queue invocation caps are
checked against actual provider readback. Unsupported emulator caps are `null`;
they grant no global concurrency claim.

For managed privacy, retain successful managed/custom-domain API replies tied
to the exact account and bucket, an authenticated positive exact object and
complete anonymous provider/unauthorized Worker replies for that object. Disabled
managed public endpoints may refuse with 401, 403 or 404. An unauthenticated S3
400 response does not qualify. Inspect full replies for disclosure and evaluate
writer exclusivity independently; payload occurrence counts establish neither.
The closed writer assessment separates authorized provisioning/key-installation
custody from runtime mutation paths. It records actual namespaces/key prefixes
and retained source/policy evidence for known mutating APIs, including SDK
conformance and enabled isolated qualification. A known selected-namespace guard
bypass prevents a zero-writer acceptance. Account token totals and a partial
binding inventory do not establish this assessment.
The public capture interfaces are documented in
[privacy.rs](../../../crates/aos-hub/src/direct_upload_review/privacy.rs).

## Review, then sign the exact candidate

```sh
aos-hub-direct-review prepare \
  --selection-file selection.json \
  --output candidate.json
```

Inspect the candidate and all selected raw evidence. Record the exact candidate
SHA-256 printed by preparation only after independent review. Select that
reviewed hash explicitly for signing:

```sh
aos-hub-direct-review sign \
  --selection-file selection.json \
  --candidate-file candidate.json \
  --candidate-sha256 "$REVIEWED_CANDIDATE_SHA256" \
  --reviewer-key-file "$REVIEWER_SEED_FILE" \
  --reviewer-public-key-file "$INSTALLED_REVIEWER_PUBLIC_FILE" \
  --output independently-accepted.json
```

Signing rereads selected inputs, checks current validity and installed verifier
agreement, and rechecks candidate bytes immediately before the signature.
Outputs contain no local input or private-key paths. No observations are
manufactured and no acceptance record is activated by either command. Use the
[direct-upload activation procedure](direct-upload.md) with the independently
signed artifact and fresh discovery of the unchanged exact Worker version.

To derive the public registry lookup key with the same serializer used by the
runtime, select the exact observed audience and unchanged script:

```sh
aos-hub-direct-review registry-key \
  --deployment-id "$DEPLOYMENT_ID" \
  --source-digest "$OBSERVED_SOURCE_DIGEST" \
  --script-version "$OBSERVED_SCRIPT_VERSION"
```

This command writes no registry record and grants no acceptance. An emulator
operator must independently install the signed artifact into the same observed
runtime and retain its separate trusted verifier and unsupported global queue
invocation classification.
