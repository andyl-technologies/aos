//! Complete offline verification over captured release bytes.
//!
//! Filesystem capture is intentionally outside this crate. Native and Worker
//! callers must first capture a no-follow, regular-file-only tree, then pass
//! the immutable bytes here so all runtimes share semantic verification.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use serde::Serialize;

use crate::artifact::BundlePath;
use crate::canonical;
use crate::digest::Sha256Digest;
use crate::manifest::{MANIFEST_DOMAIN, MANIFEST_ENVELOPE_V1, ManifestEnvelopeV1};
use crate::plan::ReleasePlanV1;
use crate::signing::{SignerRole, TrustedEd25519Key, verify_ed25519_response};
use crate::state::{JournalEntryV1, ReleaseState};

/// Exact captured regular file supplied to the pure verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedFile {
    /// Normalized path below the bundle root.
    pub path: BundlePath,
    /// Exact captured byte length.
    pub size_bytes: u64,
    /// SHA-256 computed while streaming the captured regular file.
    pub sha256: Sha256Digest,
}

/// Successful verification counts for stable machine output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSummary {
    /// Stable verifier result schema.
    pub schema_version: &'static str,
    /// Immutable release identity.
    pub release_id: String,
    /// Exact calendar version.
    pub version: String,
    /// Frozen plan digest.
    pub plan_digest: Sha256Digest,
    /// Final manifest payload digest.
    pub manifest_digest: Sha256Digest,
    /// Number of exact payload files verified.
    pub artifact_count: usize,
    /// Number of public evidence records verified.
    pub evidence_count: usize,
    /// Number of distinct manifest signatures verified.
    pub signatures_verified: usize,
}

#[derive(Serialize)]
struct BundleDigestInput<'a> {
    manifest_envelope_digest: Sha256Digest,
    files: Vec<BundleDigestFile<'a>>,
}

#[derive(Serialize)]
struct BundleDigestFile<'a> {
    path: &'a str,
    size_bytes: u64,
    sha256: Sha256Digest,
}

/// Computes the identity of exact manifest-envelope and captured payload bytes.
///
/// # Errors
///
/// Returns an error when captured paths are duplicated or the closed digest
/// input cannot be represented as canonical JSON.
pub fn bundle_digest(
    manifest_envelope_bytes: &[u8],
    files: &[CapturedFile],
) -> Result<Sha256Digest> {
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|file| file.path.as_str());
    if ordered.windows(2).any(|pair| pair[0].path == pair[1].path) {
        bail!("captured bundle contains a duplicate path");
    }
    let input = BundleDigestInput {
        manifest_envelope_digest: Sha256Digest::of_bytes(manifest_envelope_bytes),
        files: ordered
            .into_iter()
            .map(|file| BundleDigestFile {
                path: file.path.as_str(),
                size_bytes: file.size_bytes,
                sha256: file.sha256,
            })
            .collect(),
    };
    Sha256Digest::of_canonical("aos.release.bundle/v1", &input)
}

/// Verifies canonical plan/envelope bytes, signatures, schema semantics, and
/// exact captured bundle closure.
///
/// `files` contains every regular file below the bundle root except the root
/// `release-manifest.json` envelope itself. It therefore includes the exact
/// `release-plan.json` bytes.
///
/// # Errors
///
/// Returns an error for noncanonical or ambiguous JSON, schema or policy
/// failure, identity drift, invalid/insufficient signatures, duplicate or
/// untrusted signer keys, missing/extra/aliased paths, or content mismatch.
pub fn verify_release(
    plan_bytes: &[u8],
    manifest_envelope_bytes: &[u8],
    files: &[CapturedFile],
    trusted_keys: &[TrustedEd25519Key],
) -> Result<VerificationSummary> {
    canonical::require_canonical(plan_bytes, "release plan")?;
    let plan: ReleasePlanV1 = canonical::from_slice(plan_bytes, "release plan")?;
    plan.validate()?;
    let plan_digest = Sha256Digest::of_bytes(plan_bytes);

    canonical::require_canonical(manifest_envelope_bytes, "release manifest envelope")?;
    let envelope: ManifestEnvelopeV1 =
        canonical::from_slice(manifest_envelope_bytes, "release manifest envelope")?;
    if envelope.schema_version != MANIFEST_ENVELOPE_V1 {
        bail!("unsupported release manifest envelope schema");
    }
    let manifest_digest = Sha256Digest::of_canonical(MANIFEST_DOMAIN, &envelope.payload)?;
    if envelope.payload_digest != manifest_digest || envelope.payload.plan_digest != plan_digest {
        bail!("release manifest or plan digest mismatch");
    }
    envelope.payload.validate(&plan)?;
    let signatures_verified = verify_manifest_signatures(&plan, &envelope, trusted_keys)?;
    verify_file_closure(&envelope, files)?;

    Ok(VerificationSummary {
        schema_version: "aos.release.verification-result/v1",
        release_id: plan.release_id,
        version: plan.version,
        plan_digest,
        manifest_digest,
        artifact_count: envelope.payload.artifacts.len(),
        evidence_count: envelope.payload.evidence.len(),
        signatures_verified,
    })
}

/// Verifies an append-only journal captured by the caller.
///
/// # Errors
///
/// Returns an error for an invalid entry, discontinuous sequence, digest or
/// plan mismatch, illegal state transition, or manifest identity drift.
pub fn verify_journal(entries: &[JournalEntryV1]) -> Result<ReleaseState> {
    let first = entries
        .first()
        .ok_or_else(|| anyhow::anyhow!("release journal is empty"))?;
    let plan_digest = first.plan_digest;
    let mut expected_manifest = None;
    let mut previous_digest = None;
    let mut state = None;

    for (index, entry) in entries.iter().enumerate() {
        entry.validate()?;
        let expected_sequence = u64::try_from(index)
            .context("journal entry index exceeds u64")?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("journal sequence overflow"))?;
        if entry.sequence != expected_sequence
            || entry.plan_digest != plan_digest
            || entry.previous_entry_digest != previous_digest
            || entry.prior_state != state
        {
            bail!(
                "release journal continuity mismatch at sequence {}",
                entry.sequence
            );
        }
        if let Some(previous_state) = state
            && !previous_state.can_transition_to(entry.new_state)
        {
            bail!(
                "illegal release state transition at sequence {}",
                entry.sequence
            );
        }
        if let Some(manifest) = entry.manifest_digest {
            if expected_manifest.is_some_and(|expected| expected != manifest) {
                bail!("release journal manifest identity changed");
            }
            expected_manifest = Some(manifest);
        }
        previous_digest = Some(Sha256Digest::of_canonical(
            "aos.release.journal-entry/v1",
            entry,
        )?);
        state = Some(entry.new_state);
    }
    state.ok_or_else(|| anyhow::anyhow!("release journal is empty"))
}

fn verify_manifest_signatures(
    plan: &ReleasePlanV1,
    envelope: &ManifestEnvelopeV1,
    trusted_keys: &[TrustedEd25519Key],
) -> Result<usize> {
    let requirement = plan
        .signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .ok_or_else(|| anyhow::anyhow!("release evidence signer policy is absent"))?;
    let trusted: BTreeMap<_, _> = trusted_keys
        .iter()
        .map(|key| (key.key_id.as_str(), key))
        .collect();
    if trusted.len() != trusted_keys.len() {
        bail!("trusted key input contains duplicate key ids");
    }

    let mut verified = BTreeSet::new();
    for signature in &envelope.signatures {
        let request = &signature.request;
        if request.role != SignerRole::ReleaseEvidence
            || request.registry != plan.registry
            || request.release_id != plan.release_id
            || request.plan_digest != envelope.payload.plan_digest
            || request.manifest_digest != Some(envelope.payload_digest)
            || request.payload_digest != envelope.payload_digest
            || request.provider_revision != requirement.provider_revision
            || !requirement.key_ids.contains(&request.key_id)
        {
            bail!("manifest signature request is outside the frozen signer policy");
        }
        if !verified.insert(request.key_id.as_str()) {
            bail!("manifest envelope repeats a signer key");
        }
        let key = trusted
            .get(request.key_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("trusted key absent for {}", request.key_id))?;
        verify_ed25519_response(request, &signature.response, key)?;
    }
    if verified.len() < usize::from(requirement.threshold) {
        bail!("manifest signature threshold is not satisfied");
    }
    Ok(verified.len())
}

fn verify_file_closure(envelope: &ManifestEnvelopeV1, files: &[CapturedFile]) -> Result<()> {
    let expected: BTreeMap<_, _> = envelope
        .payload
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect();
    let mut seen = BTreeSet::new();
    for file in files {
        if !seen.insert(file.path.as_str()) {
            bail!("captured bundle contains duplicate path {}", file.path);
        }
        let artifact = expected
            .get(file.path.as_str())
            .ok_or_else(|| anyhow::anyhow!("extra bundle file {}", file.path))?;
        if artifact.size_bytes != file.size_bytes || artifact.sha256 != file.sha256 {
            bail!("bundle file identity mismatch: {}", file.path);
        }
    }
    if seen.len() != expected.len() {
        let missing = expected
            .keys()
            .find(|path| !seen.contains(**path))
            .copied()
            .unwrap_or("unknown");
        bail!("bundle file is missing: {missing}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::artifact::{ArtifactKind, ArtifactRecord, BundlePath, Compression};
    use crate::canonical;
    use crate::digest::Sha256Digest;
    use crate::manifest::{
        FinalArtifactSet, MANIFEST_DOMAIN, MANIFEST_ENVELOPE_V1, ManifestEnvelopeV1,
        ManifestSignature, PackageResult, ReleaseManifestV1,
    };
    use crate::plan::{
        PackagePlan, PlannedArtifact, PlannedArtifactSet, PlatformCell, ReleaseClass,
        ReleasePlanV1, RetentionPolicy, SourceIdentity,
    };
    use crate::platform::{MatrixCell, Platform};
    use crate::signing::{
        SignatureAlgorithm, SignatureResponseV1, SignerRequirement, SignerRole, SigningOperation,
        SigningRequestV1, TrustedEd25519Key,
    };
    use crate::state::{JournalEntryV1, ReleaseState};
    use crate::{CANONICAL_REGISTRY, RELEASE_JOURNAL_ENTRY_V1};

    use super::{CapturedFile, verify_journal, verify_release};

    const OID: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::of_bytes(label)
    }

    fn signer(role: SignerRole) -> SignerRequirement {
        SignerRequirement {
            role,
            key_ids: vec![format!("key-{role:?}").to_ascii_lowercase()],
            threshold: 1,
            provider_revision: "provider-v1".to_owned(),
        }
    }

    fn matrix<T: Clone>(x86_artifact: T) -> Vec<PlatformCell<T>> {
        [
            Platform::X86_64Linux,
            Platform::Aarch64Linux,
            Platform::X86_64Darwin,
            Platform::Aarch64Darwin,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, platform)| PlatformCell {
            platform,
            decision: if index == 0 {
                MatrixCell::Artifact {
                    artifact: x86_artifact.clone(),
                }
            } else {
                MatrixCell::NotApplicable {
                    rule: "fixture-rule-v1".to_owned(),
                    reason: "fixture package is target-specific".to_owned(),
                }
            },
        })
        .collect()
    }

    struct ReleaseFixture {
        plan: Vec<u8>,
        envelope: Vec<u8>,
        files: Vec<CapturedFile>,
        key: TrustedEd25519Key,
    }

    fn release_fixture() -> anyhow::Result<ReleaseFixture> {
        let plan = ReleasePlanV1 {
            schema_version: crate::RELEASE_PLAN_V1.to_owned(),
            release_id: "release-2026.9.0-dev.20260903.1".to_owned(),
            version: "2026.9.0-dev.20260903.1".to_owned(),
            release_class: ReleaseClass::Edge,
            registry: CANONICAL_REGISTRY.to_owned(),
            registry_base_commit: OID.to_owned(),
            registry_base_generation: 7,
            source: SourceIdentity {
                commit: OID.to_owned(),
                tree_digest: digest("tree"),
                protected_branch: "master".to_owned(),
                source_tag: "release/2026.9.0-dev.20260903.1".to_owned(),
                contributor_authorization_digest: digest("authorization"),
            },
            packages: vec![PackagePlan {
                name: "example".to_owned(),
                publication: Some(crate::inventory::PackagePublicationMetadata {
                    version: "1.0.0".to_owned(),
                    description: "Example package".to_owned(),
                    homepage: None,
                    license_expression: "Apache-2.0".to_owned(),
                    maintainers: vec!["Example Maintainer".to_owned()],
                }),
                platforms: matrix(PlannedArtifactSet {
                    artifacts: vec![PlannedArtifact {
                        id: "package/example/x86_64-linux".to_owned(),
                        derivation: Some(
                            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv".to_owned(),
                        ),
                        output: Some("out".to_owned()),
                        store_path: Some(
                            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example".to_owned(),
                        ),
                        source_store_paths: vec![],
                    }],
                }),
            }],
            images: Vec::new(),
            gates: Vec::new(),
            staging_deployment_id: "hub-staging-v1".to_owned(),
            production_deployment_id: "hub-production-v1".to_owned(),
            signers: [
                SignerRole::Registry,
                SignerRole::Cache,
                SignerRole::Provenance,
                SignerRole::ReleaseEvidence,
                SignerRole::TufEdge,
            ]
            .into_iter()
            .map(signer)
            .collect(),
            intended_channels: Vec::new(),
            retention: RetentionPolicy {
                policy_id: "retention-v1".to_owned(),
                policy_digest: digest("retention"),
                require_corresponding_source: true,
            },
            public_evidence_policy_digest: digest("evidence-policy"),
            restricted_operator_policy_digest: digest("operator-policy"),
        };
        let plan_bytes = canonical::to_vec(&plan)?;
        let package_bytes = b"canonical fixture package".to_vec();
        let artifacts = vec![
            ArtifactRecord {
                id: "control/release-plan".to_owned(),
                kind: ArtifactKind::ReleasePlan,
                platform: None,
                system_variant: None,
                path: BundlePath::parse("release-plan.json")?,
                size_bytes: u64::try_from(plan_bytes.len())?,
                sha256: Sha256Digest::of_bytes(&plan_bytes),
                media_type: "application/json".to_owned(),
                compression: Compression::None,
                derivation: None,
                output: None,
                store_path: None,
                nar_hash: None,
                relationships: Vec::new(),
            },
            ArtifactRecord {
                id: "package/example/x86_64-linux".to_owned(),
                kind: ArtifactKind::PackageNar,
                platform: Some(Platform::X86_64Linux),
                system_variant: None,
                path: BundlePath::parse("packages/example.nar")?,
                size_bytes: u64::try_from(package_bytes.len())?,
                sha256: Sha256Digest::of_bytes(&package_bytes),
                media_type: "application/x-nix-nar".to_owned(),
                compression: Compression::None,
                derivation: Some(
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv".to_owned(),
                ),
                output: Some("out".to_owned()),
                store_path: Some("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example".to_owned()),
                nar_hash: Some(digest("nar")),
                relationships: Vec::new(),
            },
        ];
        let manifest = ReleaseManifestV1 {
            schema_version: crate::RELEASE_MANIFEST_V1.to_owned(),
            release_id: plan.release_id.clone(),
            version: plan.version.clone(),
            release_class: plan.release_class,
            registry: plan.registry.clone(),
            plan_digest: Sha256Digest::of_bytes(&plan_bytes),
            source_commit: plan.source.commit.clone(),
            packages: vec![PackageResult {
                name: "example".to_owned(),
                platforms: matrix(FinalArtifactSet {
                    artifact_ids: vec!["package/example/x86_64-linux".to_owned()],
                }),
            }],
            images: Vec::new(),
            artifacts,
            evidence: Vec::new(),
        };
        let manifest_digest = Sha256Digest::of_canonical(MANIFEST_DOMAIN, &manifest)?;
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let request = SigningRequestV1 {
            schema_version: "aos.release.signing-request/v1".to_owned(),
            request_id: "manifest-signature-1".to_owned(),
            nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            plan_digest: manifest.plan_digest,
            manifest_digest: Some(manifest_digest),
            role: SignerRole::ReleaseEvidence,
            key_id: "key-releaseevidence".to_owned(),
            provider_revision: "provider-v1".to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            operation: SigningOperation::SignPayload,
            context: crate::signing::SigningContext::Payload {
                artifact_kind: "release-manifest".to_owned(),
            },
            payload_digest: manifest_digest,
            approval_policy_digest: plan.restricted_operator_policy_digest,
        };
        let request_digest = request.digest()?;
        let signature = signing_key.sign(request_digest.as_bytes());
        let response = SignatureResponseV1 {
            schema_version: "aos.release.signature-response/v1".to_owned(),
            request_digest,
            role: request.role,
            key_id: request.key_id.clone(),
            provider_revision: request.provider_revision.clone(),
            algorithm: request.algorithm,
            provider_operation_id: "fixture-operation-1".to_owned(),
            verification_identity: "fixture-release-key".to_owned(),
            verification_material_digest: digest("fixture-public-key"),
            output_digest: None,
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        };
        let envelope = ManifestEnvelopeV1 {
            schema_version: MANIFEST_ENVELOPE_V1.to_owned(),
            payload: manifest,
            payload_digest: manifest_digest,
            signatures: vec![ManifestSignature { request, response }],
        };
        let envelope_bytes = canonical::to_vec(&envelope)?;
        let files = vec![
            CapturedFile {
                path: BundlePath::parse("release-plan.json")?,
                size_bytes: u64::try_from(plan_bytes.len())?,
                sha256: Sha256Digest::of_bytes(&plan_bytes),
            },
            CapturedFile {
                path: BundlePath::parse("packages/example.nar")?,
                size_bytes: u64::try_from(package_bytes.len())?,
                sha256: Sha256Digest::of_bytes(&package_bytes),
            },
        ];
        let trusted_key = TrustedEd25519Key {
            key_id: "key-releaseevidence".to_owned(),
            public_key: signing_key.verifying_key().to_bytes(),
        };
        Ok(ReleaseFixture {
            plan: plan_bytes,
            envelope: envelope_bytes,
            files,
            key: trusted_key,
        })
    }

    fn entry(
        sequence: u64,
        previous_entry_digest: Option<Sha256Digest>,
        prior_state: Option<ReleaseState>,
        new_state: ReleaseState,
    ) -> JournalEntryV1 {
        JournalEntryV1 {
            schema_version: RELEASE_JOURNAL_ENTRY_V1.to_owned(),
            sequence,
            previous_entry_digest,
            plan_digest: Sha256Digest::of_bytes("plan"),
            manifest_digest: (new_state >= ReleaseState::Finalized)
                .then(|| Sha256Digest::of_bytes("manifest")),
            prior_state,
            new_state,
            operation_ids: Vec::new(),
            evidence: Vec::new(),
            recorded_at: "2026-09-03T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn journal_verifier_rejects_skipped_state() -> anyhow::Result<()> {
        let first = entry(1, None, None, ReleaseState::Planned);
        let first_digest = Sha256Digest::of_canonical("aos.release.journal-entry/v1", &first)?;
        let skipped = entry(
            2,
            Some(first_digest),
            Some(ReleaseState::Planned),
            ReleaseState::Staged,
        );
        assert!(verify_journal(&[first, skipped]).is_err());
        Ok(())
    }

    #[test]
    fn complete_release_fixture_verifies() -> anyhow::Result<()> {
        let fixture = release_fixture()?;
        let summary = verify_release(
            &fixture.plan,
            &fixture.envelope,
            &fixture.files,
            &[fixture.key],
        )?;
        assert_eq!(summary.artifact_count, 2);
        assert_eq!(summary.signatures_verified, 1);
        Ok(())
    }

    #[test]
    fn release_fixture_rejects_extra_and_changed_files() -> anyhow::Result<()> {
        let mut fixture = release_fixture()?;
        fixture.files.push(CapturedFile {
            path: BundlePath::parse("extra")?,
            size_bytes: 0,
            sha256: Sha256Digest::of_bytes([]),
        });
        assert!(
            verify_release(
                &fixture.plan,
                &fixture.envelope,
                &fixture.files,
                std::slice::from_ref(&fixture.key),
            )
            .is_err()
        );

        fixture.files.pop();
        fixture.files[1].sha256 = Sha256Digest::of_bytes("changed");
        assert!(
            verify_release(
                &fixture.plan,
                &fixture.envelope,
                &fixture.files,
                &[fixture.key],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn release_fixture_rejects_signature_replay() -> anyhow::Result<()> {
        let fixture = release_fixture()?;
        let mut value = canonical::parse_json(&fixture.envelope, "manifest envelope")?;
        value["signatures"][0]["request"]["release_id"] =
            serde_json::Value::String("release-other".to_owned());
        let replayed = canonical::canonical_json(&value)?;
        assert!(verify_release(&fixture.plan, &replayed, &fixture.files, &[fixture.key]).is_err());
        Ok(())
    }
}
