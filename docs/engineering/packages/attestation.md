# Package and generation attestation

AOS extends PCR 15 with a record describing the committed native host package
generation, so a remote verifier can bind a TPM quote to the exact package set a
host activated. Measured boot (PCRs 7, 11, and 12) covers the image; PCR 15
covers what the package runtime committed on top of it. The verifier workflow is
in the [CLI reference](../../users/aos/cli.md#verify-runtime-attestation-evidence),
and the trust obligations are in
[Maintain the AOS trust model](../../maintainers/trust-model.md#maintain-runtime-attestation-bindings).

| Piece | Location |
| --- | --- |
| Event log, PCR extension, quotes, and replay | `crates/packages/aos-package-manager/src/package_attestation.rs` |
| Generation evidence record | `crates/packages/aos-package-manager/src/attestation/native.rs` |
| Package measurement tuple | `aos_registry_format::measurement` |
| Registry feature flag | `attestation-v1` in `aos_registry_format::consumer` |
| Quote smoke test | `tests/fleet/package-attestation-quote.nix` |

## Event log

Measurements are appended to `/run/log/aos-packages.cel`, a JSON-lines log in
the `aos-package-cel-v1` format. Each record carries its sequence number, PCR
index (15), the `sha256` bank digest, the event type, and the canonical event
text, plus type-specific fields. The event types are:

- `aos-pcr-baseline`: the PCR 15 value observed before AOS appended events, so
  replay can start from a known value;
- `aos-generation-attestation`: a committed generation, identified by its
  journal sequence and desired-content digest together with the activation
  identifier;
- `aos-package-set` and `aos-package`: a package set and the per-package tuples
  it contains. Activation does not currently emit these; the verifier replays
  and catalog-checks them when a log contains them.

Generation measurement keeps the complete canonical record in the CEL and passes
only its SHA-256 digest to the TPM helper, so large records never become
command-line arguments. These events are not mirrored into systemd's userspace
measurement log.

On a host without a TPM, the record is still appended so the evidence stays
inspectable, and PCR 15 is not touched. Once a TPM extension has been
attempted, its CEL event is retained even if the helper reports failure, which
lets a retry recover safely from an ambiguous post-extension error.

## Package tuple

A package event commits to the package name, version, authenticated payload
root digest, and a binding digest over its native companions:

```text
aos-package-v1|name=<length>:<name>|version=<length>:<version>|root-digest=<length>:<digest>|manifest-digest=<length>:<digest>
```

The measured value is the SHA-256 of that text. Length prefixes let a verifier
replay the log without guessing separators. The `manifest-digest` field is the
deployment envelope's document digest when the package has no other companions;
otherwise it is the digest of a canonical JSON object binding the deployment,
documentation, and qualification companion locators together
(`native_package_binding_digest`). Registries that publish these values
advertise the `attestation-v1` package feature.

## Generation evidence

When the boot backend commits a host generation
(`sysroot/image_rollout/boot_commit.rs`), `attestation::native::persist` writes a
`GenerationEvidence` record to `gen-<N>/gen-attestation.json` in the system
profile, measures it into PCR 15 when a TPM is present, and stores a quote over
it in `gen-<N>/gen-attestation-quote/`. A pending transaction file fixes the
activation identifier before PCR extension, so recovery reuses it and rejects
changed inputs.

The record binds the generation number, journal sequence, desired
content digest, and immutable evaluation-input descriptor to the original
admission evidence for each input root: its NAR hash, size, references, and the
signed release or image authority that admitted it. The image section carries
the selected sysroot, its boot-artifact contract, and pins for the ready-phase
PCR 11 value and the dm-verity root hash. Measurement refuses to proceed unless
the live PCR 11 matches the authenticated pin.

Admission receipts remain evidence of the original authority; they never become
trust anchors because their names appear in a quoted record. Expected values
come from verifier-owned policy and catalogs, never from the host being checked.

## Quotes and verification

`apm attest quote` creates an endorsement key and attestation key with the
AOS-built TPM tools and quotes `sha256:7,11,12,15` over a verifier nonce. The
tool paths and TCTI can be overridden through `AOS_TPM2_*` environment
variables, which the fleet harness uses with a software TPM.

`apm attest enroll` records a quote bundle's AK/EK identity into a verifier
catalog together with its enrollment proof. `apm attest catalog` prints the
golden package measurements from registry metadata. `apm attest verify` replays
the CEL from its baseline, checks the result against a quoted or supplied PCR 15
value, checks each package tuple against the golden catalog, and, when given a
generation record and policy, checks the generation evidence.

A PCR value without its event log and verifier policy is not meaningful
evidence. PCR 15 does not measure inactive downloads, user-profile packages,
implicit dependencies as separate identities, or arbitrary store contents; those
bytes are admitted through the registry's signed realization graph.
