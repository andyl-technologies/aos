# Local OCI SDK review fixture

This offline workflow is restricted to `oci_documents` with
`emulated_managed_sdk` execution. It grants no Direct upload, presigning,
external S3, Copy, mirror or Hosted permission. The Worker loader exists only in
`do-e2e`; Native requires explicit Hybrid opt-in and its separately installed
reviewer map and guard key. Normal Hosted/Direct verification is unchanged.

The signed `sdkObservationScope` is required and is exactly
`anchor_create_and_conditional_read`. Its zero post-cutoff effect count describes
one retained create-only anchor PUT and conditional full GET, both positively
completed inside that original's window. It does **not** qualify business
expiry-refusal, throughput, aggregate memory, queues or a real Cloudflare account.
Those require the later matching-source runtime workflow and retained evidence.

## Select a real pair

Build and independently review one exact Native ELF, Worker distribution,
filtered source and tool closure. Retain their actual NARs/hashes and build
receipts. Do not relabel an earlier namespace/anchor observation as a new build:
`expectedSourceDigest` and `expectedScriptVersion` must equal both the namespace
report and the authenticated Clock replies. The assembler hashes the actual
source and distribution with the selected source-built Nix executable; it does
not accept a caller's NAR hash without comparing those bytes.

Use a fresh owner-private persistence root and an isolated
`oci-sdk-qualification-<32 lowercase hex>` R2 namespace. Install a new ephemeral
fixture verifier, the OCI-only KV attachment and the exact clock/capacity policy
before observation. No artifact is installed yet, so business OCI work must
refuse. The source-built reviewer is the existing `aos-hub-direct-review` binary;
its existing Direct commands and package inclusion remain unchanged.

```text
aos-hub-direct-review oci-sdk-fixture-key \
  --private-output private/reviewer.seed --public-output private/reviewer.public
```

Keep the raw seed private; independently select/install its public verifier and
reviewer ID. Never use a real signing key for this fixture. Neither key creation
nor the assembler configures trust or dispatches provider work.

Observe the actual source-built Native process before artifact activation:

```text
aos-hub-direct-review oci-sdk-observe-native --pid PID --executable NATIVE_ELF \
  --configuration-output private/native-configuration.json \
  --observation-output private/native-observation.json
```

The private configuration contains the actual process argv/environment, which
may contain secrets. The public report contains hashes, process identity and
lifetime only. The Native loader checks the current ELF against the signed
observation. Its configuration commitment is audit evidence, not a live
configuration attestation. Acceptance activation and any restart require fresh
operator custody/current configuration checks; they cannot infer readiness from
this bootstrap report.

Use the published namespace observer to join the actual socket peer, runner and
workerd lifetimes, files and installed R2 mapping. Retain at least two signed
readonly Clock exchanges with exact request/reply bytes, signatures and real
send/receive UTC brackets. Use the actual installed conformance secret; the tool
rechecks it against the private runner configuration and keeps it distinct from
the journal key. No caller clock PASS/summary is accepted.

After separate authorization of the local fixture effect, retain a fresh
one-shot anchor original before dispatch and its actual positive receipt. An
unknown/expired/missing receipt cannot qualify. Do not replay or clean up an
unknown original; preserve it separately. The original embeds the exact selected
namespace bytes; the receipt must bind that original, payload size/full SHA,
real SDK version, strong ETag and exactly one PUT/GET. SQL inspection or a
configured namespace string cannot replace those observations.

## Prepare and review exact bytes

`OciSdkReviewSelection` is a closed JSON contract documented by the source in
`crates/aos-hub/src/oci_sdk_review/selection.rs`. Relative file locators resolve
beside the selection. Every retained document is selected by exact SHA-256;
inputs/keys/outputs require private file and ancestor custody. Use a trusted
private working directory with relative evidence paths when an execution
environment exposes foreign-owned absolute ancestors; do not weaken custody. Installed regular
files are streamed with size and replacement checks. NAR observations have a
fixed 60-second/16-GiB bound and bounded memory.

```text
aos-hub-direct-review oci-sdk-prepare \
  --selection-file private/selection.json --output private/candidate.json
```

Independently review the complete candidate and its printed SHA. The candidate
contains no private input paths or key material. It explicitly states the narrow
observed-operation scope and preserves the selected original issue/cutoff.

```text
aos-hub-direct-review oci-sdk-sign --selection-file private/selection.json \
  --candidate-file private/candidate.json --candidate-sha256 REVIEWED_SHA \
  --reviewer-key-file private/reviewer.seed \
  --reviewer-public-key-file private/reviewer.public \
  --output private/acceptance.json
```

Signing rebuilds all selected facts and matches the independently installed
verifier. It never overwrites output, renews the original or activates a Worker.
A candidate from the historical diagnostic build remains only that build's
candidate, even if another source later has identical object bytes.

## Installation and business gate

The separate owner-private runner control stages only the dedicated
`HUB_OCI_SDK_EMULATOR_ACCEPTANCE` slot derived by `oci-sdk-registry-key`.
The runner reports `stored`, not cryptographic acceptance. Configure its
`ociSdkAcceptanceRegistryKey` using the exact Rust command result before
namespace/anchor observation; changing it changes the configuration commitment.
The source-owned `_hub-oci-sdk-install.py` client retains its exact request before
dispatch, compares the actual
runner peer/lifetime, and checks actual KV readback bytes. Verify those bytes
again with `oci-sdk-verify` and the separate installed verifier/source pins.
Conflicting KV values must refuse; an uncertain control reply is not an
installation receipt. No generic Direct registry may be written.

Only after independent review of the tool, signed artifact and exact new
Native/Worker tuple may the matching-source business fixture exercise
noncanonical manifests/configs, materialization, graph/tag publication,
replay/lost reply and current-authority refusals. Source/model gates, the small
anchor and artifact installation alone are not that qualification.
