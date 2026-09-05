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
    use std::collections::BTreeMap;

    use crate::RELEASE_JOURNAL_ENTRY_V1;
    use crate::artifact::{
        ArtifactKind, ArtifactRecord, ArtifactRelation, ArtifactRelationship, BundlePath,
        Compression,
    };
    use crate::canonical;
    use crate::digest::Sha256Digest;
    use crate::evidence::{EvidenceRecord, GateRequirement, GateResult};
    use crate::manifest::{
        FinalArtifactSet, ImageResult, MANIFEST_DOMAIN, MANIFEST_ENVELOPE_V1, ManifestEnvelopeV1,
        ManifestSignature, PackageResult, ReleaseManifestV1,
    };
    use crate::plan::{
        ImagePlan, PackagePlan, PlannedArtifact, PlannedArtifactSet, PlatformCell, ReleaseClass,
        ReleasePlanV1, RetentionPolicy, SourceIdentity,
    };
    use crate::platform::{MatrixCell, Platform};
    use crate::registry::MAIN_REGISTRY;
    use crate::signing::{
        SignatureAlgorithm, SignatureResponseV1, SignerRequirement, SignerRole, SigningOperation,
        SigningRequestV1, TrustedEd25519Key,
    };
    use crate::state::{JournalEntryV1, ReleaseState};

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

    fn planned(ids: &[String]) -> PlannedArtifactSet {
        PlannedArtifactSet {
            artifacts: ids
                .iter()
                .map(|id| PlannedArtifact {
                    id: id.clone(),
                    derivation: None,
                    output: None,
                    store_path: None,
                    source_store_paths: Vec::new(),
                })
                .collect(),
        }
    }

    fn final_set(ids: &[String]) -> FinalArtifactSet {
        FinalArtifactSet {
            artifact_ids: ids.to_vec(),
        }
    }

    fn package_id(platform: Platform) -> String {
        format!("package/example/{platform}")
    }

    fn image_ids(platform: Platform) -> Vec<(String, ArtifactKind)> {
        [
            ("logical-disk", ArtifactKind::LogicalDisk),
            ("raw", ArtifactKind::RawImage),
            ("qcow2", ArtifactKind::Qcow2Image),
            ("vmdk", ArtifactKind::VmdkImage),
            ("vhd", ArtifactKind::VhdImage),
            ("uki", ArtifactKind::Uki),
            ("recovery-uki", ArtifactKind::RecoveryUki),
            ("recovery-bundle", ArtifactKind::RecoveryBundle),
            ("metadata", ArtifactKind::ImageMetadata),
        ]
        .into_iter()
        .map(|(name, kind)| (format!("image/server/{platform}/{name}"), kind))
        .collect()
    }

    fn artifact(
        id: String,
        kind: ArtifactKind,
        platform: Option<Platform>,
        system_variant: Option<&str>,
        relationships: Vec<ArtifactRelationship>,
    ) -> anyhow::Result<(ArtifactRecord, Vec<u8>)> {
        let bytes = format!("exact bytes for {id}").into_bytes();
        let path = BundlePath::parse(format!("objects/{id}"))?;
        Ok((
            ArtifactRecord {
                id,
                kind,
                platform,
                system_variant: system_variant.map(str::to_owned),
                path,
                size_bytes: u64::try_from(bytes.len())?,
                sha256: Sha256Digest::of_bytes(&bytes),
                media_type: "application/octet-stream".to_owned(),
                compression: Compression::None,
                derivation: None,
                output: None,
                store_path: None,
                nar_hash: None,
                relationships,
            },
            bytes,
        ))
    }

    struct ReleaseFixture {
        plan: Vec<u8>,
        envelope: Vec<u8>,
        files: Vec<CapturedFile>,
        key: TrustedEd25519Key,
    }

    fn release_fixture() -> anyhow::Result<ReleaseFixture> {
        let package_cells: Vec<PlatformCell<PlannedArtifactSet>> = Platform::ALL
            .into_iter()
            .map(|platform| {
                let ids = vec![package_id(platform)];
                PlatformCell {
                    platform,
                    decision: MatrixCell::Artifact {
                        artifact: planned(&ids),
                    },
                }
            })
            .collect();
        let image_cells: Vec<PlatformCell<PlannedArtifactSet>> = Platform::LINUX
            .into_iter()
            .map(|platform| {
                let ids = image_ids(platform)
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect::<Vec<_>>();
                PlatformCell {
                    platform,
                    decision: MatrixCell::Artifact {
                        artifact: planned(&ids),
                    },
                }
            })
            .collect();
        let plan = ReleasePlanV1 {
            schema_version: crate::RELEASE_PLAN_V1.to_owned(),
            qualification: None,
            qualification_predecessor: None,
            release_id: "release-2026.9.0".to_owned(),
            version: "2026.9.0".to_owned(),
            release_class: ReleaseClass::Stable,
            registry: MAIN_REGISTRY.to_owned(),
            registry_base_commit: OID.to_owned(),
            registry_base_generation: 7,
            source: SourceIdentity {
                commit: OID.to_owned(),
                tree_digest: digest("tree"),
                protected_branch: "master".to_owned(),
                source_tag: "release/2026.9.0".to_owned(),
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
                platforms: package_cells.clone(),
            }],
            images: vec![ImagePlan {
                system_variant: "server".to_owned(),
                platforms: image_cells.clone(),
            }],
            gates: vec![GateRequirement {
                policy_id: "full-matrix-qualification-v1".to_owned(),
                policy_digest: digest("full-matrix-qualification-policy"),
                required_for_stable: true,
            }],
            staging_deployment_id: "hub-staging-v1".to_owned(),
            production_deployment_id: "hub-production-v1".to_owned(),
            signers: [
                SignerRole::Registry,
                SignerRole::Cache,
                SignerRole::Provenance,
                SignerRole::ReleaseEvidence,
                SignerRole::Qualification,
                SignerRole::TufRoot,
                SignerRole::TufTargets,
                SignerRole::TufStable,
                SignerRole::TufSnapshot,
                SignerRole::TufTimestamp,
                SignerRole::SecureBootDb,
                SignerRole::KernelModule,
                SignerRole::PcrPolicy,
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
        let mut payloads = Vec::<(ArtifactRecord, Vec<u8>)>::new();
        for (id, kind) in [
            ("registry/catalog", ArtifactKind::RegistryObject),
            ("cache/example.narinfo", ArtifactKind::NarInfo),
            ("source/example", ArtifactKind::Source),
            ("provenance/example", ArtifactKind::Provenance),
            ("sbom/release", ArtifactKind::Sbom),
            ("license/example", ArtifactKind::License),
        ] {
            payloads.push(artifact(id.to_owned(), kind, None, None, Vec::new())?);
        }
        for platform in Platform::ALL {
            payloads.push(artifact(
                package_id(platform),
                ArtifactKind::PackageNar,
                Some(platform),
                None,
                vec![
                    ArtifactRelationship {
                        relation: ArtifactRelation::CorrespondingSource,
                        target: "source/example".to_owned(),
                    },
                    ArtifactRelationship {
                        relation: ArtifactRelation::LicensedBy,
                        target: "license/example".to_owned(),
                    },
                ],
            )?);
        }
        for platform in Platform::LINUX {
            for (id, kind) in image_ids(platform) {
                payloads.push(artifact(
                    id,
                    kind,
                    Some(platform),
                    Some("server"),
                    Vec::new(),
                )?);
            }
        }
        let (evidence_artifact, evidence_bytes) = artifact(
            "evidence/full-matrix-qualification".to_owned(),
            ArtifactKind::Evidence,
            None,
            None,
            Vec::new(),
        )?;
        let evidence_report_digest = evidence_artifact.sha256;
        payloads.push((evidence_artifact, evidence_bytes));
        let mut artifacts = vec![ArtifactRecord {
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
        }];
        artifacts.extend(payloads.iter().map(|(record, _)| record.clone()));
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
                platforms: package_cells
                    .into_iter()
                    .map(|cell| {
                        let ids = vec![package_id(cell.platform)];
                        PlatformCell {
                            platform: cell.platform,
                            decision: MatrixCell::Artifact {
                                artifact: final_set(&ids),
                            },
                        }
                    })
                    .collect(),
            }],
            images: vec![ImageResult {
                system_variant: "server".to_owned(),
                platforms: image_cells
                    .into_iter()
                    .map(|cell| {
                        let ids = image_ids(cell.platform)
                            .into_iter()
                            .map(|(id, _)| id)
                            .collect::<Vec<_>>();
                        PlatformCell {
                            platform: cell.platform,
                            decision: MatrixCell::Artifact {
                                artifact: final_set(&ids),
                            },
                        }
                    })
                    .collect(),
            }],
            artifacts,
            evidence: vec![EvidenceRecord {
                qualification: None,
                id: "full-matrix-qualification".to_owned(),
                policy_id: "full-matrix-qualification-v1".to_owned(),
                policy_digest: digest("full-matrix-qualification-policy"),
                platform: None,
                subjects: Platform::ALL
                    .into_iter()
                    .map(package_id)
                    .chain(
                        Platform::LINUX
                            .into_iter()
                            .flat_map(image_ids)
                            .map(|(id, _)| id),
                    )
                    .collect(),
                result: GateResult::Passed,
                report_digest: evidence_report_digest,
                authority_id: "native-qualification-coordinator".to_owned(),
                nonce: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
                ),
                started_at: "2026-09-03T00:00:00Z".to_owned(),
                finished_at: "2026-09-03T00:01:00Z".to_owned(),
            }],
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
        let mut files = vec![CapturedFile {
            path: BundlePath::parse("release-plan.json")?,
            size_bytes: u64::try_from(plan_bytes.len())?,
            sha256: Sha256Digest::of_bytes(&plan_bytes),
        }];
        for (artifact, bytes) in payloads {
            files.push(CapturedFile {
                path: artifact.path,
                size_bytes: u64::try_from(bytes.len())?,
                sha256: Sha256Digest::of_bytes(&bytes),
            });
        }
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

    fn qualification_fixture() -> anyhow::Result<(ReleasePlanV1, crate::manifest::ReleaseManifestV1)>
    {
        let fixture = release_fixture()?;
        let mut plan: ReleasePlanV1 = canonical::from_slice(&fixture.plan, "fixture plan")?;
        let envelope: ManifestEnvelopeV1 =
            canonical::from_slice(&fixture.envelope, "fixture manifest")?;
        let mut manifest = envelope.payload;
        let mut policy: crate::qualification::QualificationContractV1 = canonical::from_slice(
            include_bytes!("../tests/fixtures/qualification-contract.json"),
            "contract",
        )?;
        policy.package_rules = plan
            .packages
            .iter()
            .map(|package| crate::qualification::PackageRule {
                name: package.name.clone(),
                role: crate::qualification::PackageRole::GeneralCatalog,
                inherit_dependency_obligations: true,
            })
            .collect();
        plan.schema_version = crate::RELEASE_PLAN_V2.into();
        plan.qualification_predecessor =
            Some(crate::qualification_evidence::QualificationPredecessor {
                registry: plan.registry.clone(),
                release_id: "preceding-snapshot".into(),
                manifest_digest: digest("predecessor"),
            });
        plan.gates = policy.gates(plan.release_class)?;
        plan.public_evidence_policy_digest =
            Sha256Digest::of_canonical(crate::qualification::CONTRACT_V1, &policy)?;
        plan.qualification = Some(policy);
        for platform in Platform::LINUX {
            let (mut value, _) = artifact(
                format!("oci/{platform}"),
                ArtifactKind::OciManifest,
                Some(platform),
                None,
                Vec::new(),
            )?;
            value.kind = ArtifactKind::OciManifest;
            manifest.artifacts.push(value);
        }
        let (value, _) = artifact(
            "oci/index".into(),
            ArtifactKind::OciIndex,
            None,
            None,
            Vec::new(),
        )?;
        manifest.artifacts.push(value);
        plan.validate()?;
        Ok((plan, manifest))
    }

    fn observations(
        plan: &ReleasePlanV1,
        manifest: &crate::manifest::ReleaseManifestV1,
        phase: crate::qualification::QualificationPhase,
    ) -> anyhow::Result<Vec<EvidenceRecord>> {
        crate::qualification_evidence::cases(plan, manifest, phase)?
            .into_iter()
            .map(|case| {
                Ok(EvidenceRecord {
                    id: format!("qualification/{}", case.id),
                    policy_id: case.requirement_id.clone(),
                    policy_digest: case.policy_digest,
                    platform: case.platform,
                    subjects: case.subjects.clone(),
                    result: GateResult::Passed,
                    report_digest: digest("observed-report"),
                    authority_id: "fixture-executor".into(),
                    nonce: Some("a".repeat(64)),
                    started_at: "2026-09-01T00:00:00Z".into(),
                    finished_at: "2026-09-01T00:00:01Z".into(),
                    qualification: Some(crate::qualification_evidence::QualificationObservation {
                        case_digest: case.digest()?,
                        executor_digest: digest("executor"),
                        environment_digest: digest("environment"),
                        checks: case
                            .checks
                            .iter()
                            .map(|check| {
                                (
                                    check.clone(),
                                    crate::qualification_evidence::CheckObservation {
                                        passed: true,
                                        detail: "fixture observation".into(),
                                    },
                                )
                            })
                            .collect(),
                        observed_seconds: 1,
                        operations: BTreeMap::from([("requests".into(), 1)]),
                        predecessor: case.predecessor,
                    }),
                })
            })
            .collect()
    }

    #[test]
    fn shared_contract_has_exact_package_image_and_release_cases() -> anyhow::Result<()> {
        use crate::qualification::{QualificationPhase, QualificationScope};
        let (plan, manifest) = qualification_fixture()?;
        let cases =
            crate::qualification_evidence::cases(&plan, &manifest, QualificationPhase::Staging)?;
        let package_cases: Vec<_> = cases
            .iter()
            .filter(|case| case.requirement_id == "package-function")
            .collect();
        assert_eq!(package_cases.len(), 4);
        assert!(
            package_cases
                .iter()
                .all(|case| case.subjects.len() == 1 && case.platform.is_some())
        );
        assert!(
            cases
                .iter()
                .filter(|case| case.requirement_id.starts_with("image-"))
                .all(|case| case.platform.is_some_and(Platform::supports_images))
        );
        assert!(
            cases
                .iter()
                .find(|case| case.requirement_id == "operator-recovery")
                .unwrap()
                .platform
                .is_none()
        );
        let policy = plan.qualification.as_ref().unwrap();
        assert!(
            policy
                .requirements
                .iter()
                .any(|gate| gate.scope == QualificationScope::Containers)
        );
        let records = observations(&plan, &manifest, QualificationPhase::Staging)?;
        crate::qualification_evidence::validate_observations(
            &plan,
            &manifest,
            QualificationPhase::Staging,
            &records,
            "2026-09-01T00:00:02Z",
        )?;
        Ok(())
    }

    #[test]
    fn qualification_binds_private_plan_without_requesting_it_as_a_public_object()
    -> anyhow::Result<()> {
        use crate::qualification::QualificationPhase;
        let (plan, manifest) = qualification_fixture()?;
        let private_plan = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == ArtifactKind::ReleasePlan)
            .unwrap();
        let mut changed_plan = plan.clone();
        changed_plan.release_id = "different-release".into();
        for phase in [
            QualificationPhase::Build,
            QualificationPhase::Staging,
            QualificationPhase::Rollout,
            QualificationPhase::Complete,
        ] {
            let original = crate::qualification_evidence::cases(&plan, &manifest, phase)?;
            let changed = crate::qualification_evidence::cases(&changed_plan, &manifest, phase)?;
            assert!(!original.is_empty());
            for (before, after) in original.iter().zip(&changed) {
                assert!(!before.subjects.contains(&private_plan.id));
                assert_ne!(before.digest()?, after.digest()?);
            }
        }
        Ok(())
    }

    #[test]
    fn missing_oci_artifact_and_removed_plan_gate_fail_closed() -> anyhow::Result<()> {
        let (mut plan, mut manifest) = qualification_fixture()?;
        plan.gates.pop();
        assert!(plan.validate().is_err());
        let (plan, _) = qualification_fixture()?;
        manifest
            .artifacts
            .retain(|artifact| artifact.kind != ArtifactKind::OciManifest);
        assert!(
            crate::qualification_evidence::cases(
                &plan,
                &manifest,
                crate::qualification::QualificationPhase::Staging
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn qualification_rejects_missing_failed_replayed_and_stale_observations() -> anyhow::Result<()>
    {
        use crate::qualification::QualificationPhase;
        let (plan, manifest) = qualification_fixture()?;
        let records = observations(&plan, &manifest, QualificationPhase::Staging)?;
        let check = |records: &[EvidenceRecord], now| {
            crate::qualification_evidence::validate_observations(
                &plan,
                &manifest,
                QualificationPhase::Staging,
                records,
                now,
            )
        };
        let now = "2026-09-01T00:00:02Z";
        assert!(check(&records[1..], now).is_err());
        let mut failed = records.clone();
        failed[0].result = GateResult::Failed;
        assert!(check(&failed, now).is_err());
        let mut replay = records.clone();
        replay[0].qualification.as_mut().unwrap().case_digest = digest("another-case");
        assert!(check(&replay, now).is_err());
        let mut missing = records.clone();
        missing[0].qualification.as_mut().unwrap().checks.clear();
        assert!(check(&missing, now).is_err());
        let mut future = records.clone();
        future[0].finished_at = "2026-09-02T00:00:00Z".into();
        assert!(check(&future, now).is_err());
        assert!(check(&records, "2026-10-02T00:00:02Z").is_err());
        let mut wrong_prior = records.clone();
        let update = wrong_prior
            .iter_mut()
            .find(|record| record.policy_id == "image-update-recovery")
            .unwrap();
        update.qualification.as_mut().unwrap().predecessor = None;
        assert!(check(&wrong_prior, now).is_err());
        assert!(
            crate::qualification_evidence::validate_observations(
                &plan,
                &manifest,
                QualificationPhase::Complete,
                &records,
                now
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn completion_requires_measured_soak_and_nonzero_operation_denominators() -> anyhow::Result<()>
    {
        use crate::qualification::QualificationPhase;
        let (plan, manifest) = qualification_fixture()?;
        let mut records = observations(&plan, &manifest, QualificationPhase::Complete)?;
        let check = |records: &[EvidenceRecord]| {
            crate::qualification_evidence::validate_observations(
                &plan,
                &manifest,
                QualificationPhase::Complete,
                records,
                "2026-09-15T00:00:01Z",
            )
        };
        assert!(check(&records).is_err());
        records[0].finished_at = "2026-09-15T00:00:00Z".into();
        records[0].qualification.as_mut().unwrap().observed_seconds = 1209600;
        check(&records)?;
        records[0]
            .qualification
            .as_mut()
            .unwrap()
            .operations
            .clear();
        assert!(check(&records).is_err());
        Ok(())
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
    fn qualification_admission_is_fresh_and_bound_to_the_frozen_plan() -> anyhow::Result<()> {
        use crate::qualification_admission::QualificationAdmissionV1;
        let (plan, _) = qualification_fixture()?;
        let role = plan
            .signers
            .iter()
            .find(|role| role.role == SignerRole::Qualification)
            .unwrap();
        let mut admission = QualificationAdmissionV1 {
            schema_version: "aos.release.qualification-admission/v1".into(),
            phase: crate::qualification::QualificationPhase::Complete,
            rollout: None,
            registry: plan.registry.clone(),
            release_id: plan.release_id.clone(),
            plan_digest: Sha256Digest::of_bytes(canonical::to_vec(&plan)?),
            manifest_digest: digest("manifest"),
            publication_receipt_digest: digest("publication"),
            journal_digest: digest("journal"),
            report_digest: digest("report"),
            policy_digest: plan.public_evidence_policy_digest,
            authority_id: role.key_ids[0].clone(),
            admitted_at: "2026-09-01T00:00:00Z".into(),
        };
        assert!(admission.validate(&plan, "2026-09-01T00:10:00Z").is_ok());
        assert!(admission.validate(&plan, "2026-09-01T00:10:01Z").is_err());
        assert!(admission.validate(&plan, "2026-08-31T23:59:59Z").is_err());
        admission.plan_digest = digest("another plan");
        assert!(admission.validate(&plan, "2026-09-01T00:00:00Z").is_err());
        Ok(())
    }

    #[test]
    fn independent_review_rejects_missing_duplicate_and_replayed_acceptance() -> anyhow::Result<()>
    {
        use crate::qualification_admission::{QualificationReviewV1, verify_reviews};
        use crate::receipt::{
            RECEIPT_SIGNATURE_DOMAIN, SIGNED_RECEIPT_V1, SignedReceiptEnvelopeV1,
        };
        let fixture = release_fixture()?;
        let (plan, _) = qualification_fixture()?;
        let report = b"exact reviewed observations";
        let review = QualificationReviewV1 {
            schema_version: "aos.release.qualification-review/v1".into(),
            plan_digest: Sha256Digest::of_bytes(canonical::to_vec(&plan)?),
            report_digest: Sha256Digest::of_bytes(report),
            authority_id: fixture.key.key_id.clone(),
            accepted: true,
        };
        let signature = SigningKey::from_bytes(&[7_u8; 32]).sign(
            Sha256Digest::separated(RECEIPT_SIGNATURE_DOMAIN, canonical::to_vec(&review)?)
                .as_bytes(),
        );
        let envelope = SignedReceiptEnvelopeV1 {
            schema_version: SIGNED_RECEIPT_V1.into(),
            key_id: fixture.key.key_id.clone(),
            payload: serde_json::to_value(review)?,
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        };
        let bytes = canonical::to_vec(&envelope)?;
        let keys = [fixture.key];
        assert!(verify_reviews(&plan, report, &[bytes.clone()], &keys).is_ok());
        assert!(verify_reviews(&plan, report, &[], &keys).is_err());
        assert!(verify_reviews(&plan, report, &[bytes.clone(), bytes.clone()], &keys).is_err());
        assert!(verify_reviews(&plan, b"changed report", &[bytes], &keys).is_err());
        Ok(())
    }

    #[test]
    fn observations_cannot_be_replayed_for_changed_bytes_with_the_same_artifact_ids()
    -> anyhow::Result<()> {
        use crate::qualification::QualificationPhase;
        let (plan, mut manifest) = qualification_fixture()?;
        let evidence = observations(&plan, &manifest, QualificationPhase::Staging)?;
        let artifact = manifest
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.kind == ArtifactKind::PackageNar)
            .unwrap();
        artifact.sha256 = digest("changed package bytes, unchanged logical artifact id");
        assert!(
            crate::qualification_evidence::validate_observations(
                &plan,
                &manifest,
                QualificationPhase::Staging,
                &evidence,
                "2026-09-01T00:00:02Z",
            )
            .is_err()
        );
        let (mut another_plan, manifest) = qualification_fixture()?;
        another_plan.release_id = "another-release-with-the-same-artifacts".into();
        assert!(
            crate::qualification_evidence::validate_observations(
                &another_plan,
                &manifest,
                QualificationPhase::Staging,
                &evidence,
                "2026-09-01T00:00:02Z",
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn archival_plans_are_readable_but_cannot_authorize_new_publication() -> anyhow::Result<()> {
        let fixture = release_fixture()?;
        let legacy: ReleasePlanV1 = canonical::from_slice(&fixture.plan, "archival plan")?;
        legacy.validate()?;
        assert!(legacy.require_current_qualification().is_err());
        let (current, _) = qualification_fixture()?;
        current.require_current_qualification()?;
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
        assert_eq!(summary.artifact_count, 30);
        assert_eq!(summary.evidence_count, 1);
        assert_eq!(summary.signatures_verified, 1);
        Ok(())
    }

    #[test]
    fn release_plan_rejects_an_empty_gate_set() -> anyhow::Result<()> {
        let fixture = release_fixture()?;
        let mut plan: ReleasePlanV1 = canonical::from_slice(&fixture.plan, "release plan")?;
        plan.gates.clear();

        assert!(plan.validate().is_err());
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
