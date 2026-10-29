# Controlled External Mirror functional review

The source-built `aos-hub-direct-review` tool prepares a finite emulator-only
External Mirror candidate. Its shared artifact has a separate functional purpose;
it cannot represent Hosted throughput, memory, production readiness, provider
drain, or whole-workflow Native byte qualification.

## Actual selection and review

`ExternalMirrorReviewSelection` is a closed camelCase version-1 JSON document.
Its scalar fields are `reviewerKeyId`, `reviewerPublicKey`, `deploymentId`,
`publicOrigin`, `sourceDigest`, `scriptVersion`, `profileDigest`, `upstreamBase`,
`placementPrefix`, `maximumObjectBytes`, `issuedAt`, and `validUntil`, followed by
`inputs` and `clocks`. Every file reference is `{path, sha256, byteSize}`, where
`byteSize` is a JSON integer and paths are absolute or relative to the selection.
Private evidence documents are reopened with bounded owner-private custody;
installed immutable executable and distribution files are hashed in chunks.

`inputs` selects the signed `prerequisiteArtifact` and separately trusted
`prerequisiteReviewKeys`; `artifactManifest`, `workerInstallation`, `wasm`,
`script`, `runner`, `runtimeExecutable`, `nativeServingExecutable`,
`configuration`, `namespace`, `nativeObservation`, `nativeInput`,
`nativeReadiness`, `listExport`, `providerReport`,
`providerConformanceExecutable`, `nixStoreExecutable`, and `conformanceKey`.
`providerJournal` is the actual private journal directory. Each of two to 32
`clocks` selects `request`, `reply`, and `authentication` files in the existing
closed Clock observation format. The tool verifies each exact original's
signature, nonce, source, cutoff, and independently recorded timestamp bracket.

The manifest binds actual `commonSourceStorePath`, `workerSourceStorePath`,
`nativeSourceStorePath`, `workerDistributionStorePath`, `workerSourceDigest`,
`workerScriptVersion`, and `nativeServingRole`. Its `nativeServing`,
`normalNative`, `wasm`, `script`, `runner`, `runtimeExecutable`, and
`providerConformance` records are `{file, sha256, byteSize, storePath, deriver}`.
Read-only queries of the selected source-built `nix-store` check the actual
reported output derivers. The serving role is
`controlled_external_oci_native_origin`; its selected executable is the actual
serving helper ELF. The ordinary Native executable remains a separate mandatory
release tuple member and cannot stand for that helper.

`nativeObservation` binds `version`, `role`, `pid`, decimal-string `startTicks`,
`ownerUid`, `executableSha256`, `arguments`, `commandLineSha256`,
`commonSourceStorePath`, `workerSourceStorePath`, `servingStorePath`,
`servingDeriver`, `inputSha256`, and `readinessSha256`. The tool observes the
actual live process before and after checking its exact input, post-constructor
readiness, argv, executable, and selected Direct prerequisite files. A path/hash
alone does not claim that an unrelated process consumed those inputs.

The actual installed configuration must contain the distinct functional flag,
public verifier, reviewer ID, and dedicated KV binding before observation. Its
Mirror domain is the current shared profile plus actual List cohort, issuer
installation, and provider contract. The tool matches these to the installed
Object configuration and the shared validated current List publication export.
That export is a current snapshot observation; it does not reconstruct past IAM.
The physical namespace is the actual External Object Guard/Hybrid Binding State
readback, not an OCI R2 namespace.

The unchanged source-owned `copy-contract` projector reopens the complete actual
provider report and journal. This reviewer supports its guarded-versionless
Read/closure proof with the actual reported maximum conditional range. It refuses
versioned functional inputs until a projector provides the corresponding genuine
versioned evidence. Production physical support for versioned objects remains
independent. Empty-PUT qualification is retained as actually observed and is not
invented from another successful closure.

## Explicit commands

All prepare/sign/verify/key commands run on the Native guest containing the
original live serving helper and private review inputs:

```text
aos-hub-direct-review mirror-functional-fixture-key --private-output SEED --public-output PUBLIC
aos-hub-direct-review mirror-functional-prepare --selection-file SELECTION --output CANDIDATE
aos-hub-direct-review mirror-functional-sign --selection-file SELECTION --candidate-file CANDIDATE --candidate-sha256 REVIEWED_SHA --reviewer-key-file SEED --reviewer-public-key-file PUBLIC --output ARTIFACT
aos-hub-direct-review mirror-functional-verify --selection-file SELECTION --artifact-file ARTIFACT
aos-hub-direct-review mirror-functional-registry-key --selection-file SELECTION --artifact-file ARTIFACT
```

Key creation is explicit and separate from preparation. An independent checkpoint
must select the exact prepared candidate SHA and a private seed matching the
initially installed Mirror verifier. Preparation does not sign. Signing reopens
all inputs, refuses substituted candidates and reused reviewer keys, and clips
validity to the immutable current Direct prerequisite window. The Mirror key
must differ by decoded public-key bytes from selected Direct and Hosted keys,
including differently cased hex spellings of the same key.

Only the reserved `.aos-mirror-qualification/<32-lower-hex>/final` root and its
`full` and `pull-through` children apply. The fixture upstream is exactly
`https://aos.andyl.org:4778/fleet-mirror/<same-run>`. The administrative object
ceiling remains beneath the actual independently accepted prerequisite ceiling.

## Called byte installer and process transition

`_hub-external-mirror-functional.py` exposes:

```text
prepare_mirror_functional(machine, tools, selection_file, output_file)
sign_mirror_functional(machine, tools, selection_file, candidate_file, reviewed_candidate_sha256, reviewer_key_file, reviewer_public_key_file, output_file)
install_mirror_functional(native, worker, tools, selection_file, artifact_file, socket_file, worker_process)
```

The selected bundle supplies its existing guest Python/read/namespace transport
helpers. `tools.reviewer` is the selected source-built executable. Preparation
returns the exact candidate SHA for the independent checkpoint. Signing requires
that explicit SHA. Installation performs Native verification and shared Rust key
derivation, then sends Worker the closed request
`{version:1, kind:"external-mirror-functional-install", artifactBase64,
artifactSha256, key}`. It half-closes its request writer because the actual runner
dispatches on EOF, and retains exact private request and response byte references.

The eight-field stored reply is `{version, status, key, artifactSha256, byteSize,
runnerPid, runnerStartTicks, artifactBase64}`. The installer checks complete bytes,
decimal-string size, current Worker process/namespace/configuration, and a second
Native verification. Stored/readback bytes are not business acceptance.

All original selection verification ends while the original Native helper is
live. After storing the artifact, the caller gracefully stops that helper and
launches a distinct successor with the exact optional functional triplet. It
retains both lifetimes, inputs, readiness, and stop facts. The artifact binds the
same serving ELF/source/profile, not a PID. The successor's real shared loader
and current constructor checks establish its own readiness; the old observation
is never relabeled or silently reused for the successor process.
