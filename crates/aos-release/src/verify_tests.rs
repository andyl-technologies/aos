//! Release fixtures shared by unit tests, and offline verifier tests.
//!
//! [`release_fixture`] is a signed stable release on `andyl/main` built from
//! the shipped contract fixture, with every production-tier destination and
//! passing build evidence. [`qualification_fixture`] decodes its plan and
//! manifest, and [`testing_fixture`] turns it into an edge release on
//! `andyl/experimental` whose `production/edge` destination uses the change-scoped
//! smoke profile.

use anyhow::Context as _;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::BTreeMap;

use crate::artifact::{
    ArtifactKind, ArtifactRecord, ArtifactRelation, ArtifactRelationship, BundlePath, Compression,
    ImageArtifactIdentity,
};
use crate::canonical;
use crate::digest::Sha256Digest;
use crate::evidence::{EvidenceRecord, GateResult};
use crate::manifest::{
    FinalArtifactSet, ImageResult, MANIFEST_DOMAIN, MANIFEST_ENVELOPE_V1, ManifestEnvelopeV1,
    ManifestSignature, PackageResult, ReleaseManifestV1,
};
use crate::plan::{
    ImagePlan, PackagePlan, PlannedArtifact, PlannedArtifactSet, PlannedSurface, PlatformCell,
    ReleaseClass, ReleasePlan, RequestedDestination, RetentionPolicy, SourceIdentity, SurfaceKind,
    SurfaceRole, class_allows_channel_kind, planned_destinations,
};
use crate::platform::{MatrixCell, Platform};
use crate::qualification::change_scope::{CHANGE_SCOPE, ChangedPackageCell};
use crate::qualification::{ChangeScope, QualificationContract, QualificationPhase};
use crate::registry::{MAIN_REGISTRY, EXPERIMENTAL_REGISTRY, registry_policy};
use crate::signing::{
    SignatureAlgorithm, SignatureResponse, SignerRequirement, SignerRole, SigningOperation,
    SigningRequest, TrustedEd25519Key,
};

use super::{CapturedFile, verify_release};

/// Destination whose soak profile selects every current obligation.
pub(crate) const STABLE: &str = "production/stable";

/// Change-scoped smoke destination of the testing fixture.
pub(crate) const EDGE: &str = "production/edge";

const OID: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

pub(crate) fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(label)
}

pub(crate) fn signer(role: SignerRole) -> SignerRequirement {
    SignerRequirement {
        role,
        key_ids: vec![format!("key-{role:?}").to_ascii_lowercase()],
        threshold: 1,
        provider_revision: "provider-v1".to_owned(),
    }
}

pub(crate) fn planned(ids: &[String]) -> PlannedArtifactSet {
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

pub(crate) fn final_set(ids: &[String]) -> FinalArtifactSet {
    FinalArtifactSet {
        artifact_ids: ids.to_vec(),
    }
}

pub(crate) fn package_id(platform: Platform) -> String {
    format!("package/example/{platform}")
}

fn image_ids(platform: Platform) -> Vec<(String, ArtifactKind)> {
    [
        ("logical-disk", ArtifactKind::Image),
        ("raw", ArtifactKind::Image),
        ("qcow2", ArtifactKind::Image),
        ("vmdk", ArtifactKind::Image),
        ("vhd", ArtifactKind::Image),
        ("uki", ArtifactKind::Image),
        ("recovery-uki", ArtifactKind::Image),
        ("recovery-bundle", ArtifactKind::Image),
        ("metadata", ArtifactKind::Image),
    ]
    .into_iter()
    .map(|(name, kind)| (format!("image/server/{platform}/{name}"), kind))
    .collect()
}

pub(crate) fn artifact(
    id: String,
    kind: ArtifactKind,
    platform: Option<Platform>,
    system_variant: Option<&str>,
    relationships: Vec<ArtifactRelationship>,
) -> anyhow::Result<(ArtifactRecord, Vec<u8>)> {
    let bytes = format!("exact bytes for {id}").into_bytes();
    artifact_with_bytes(id, kind, platform, system_variant, relationships, bytes)
}

/// Builds an artifact record for exact payload bytes.
fn artifact_with_bytes(
    id: String,
    kind: ArtifactKind,
    platform: Option<Platform>,
    system_variant: Option<&str>,
    mut relationships: Vec<ArtifactRelationship>,
    bytes: Vec<u8>,
) -> anyhow::Result<(ArtifactRecord, Vec<u8>)> {
    let path = BundlePath::parse(format!("objects/{id}"))?;
    let image = if kind == ArtifactKind::Image {
        let platform = platform.context("test image artifact lacks a platform")?;
        let role = id
            .rsplit('/')
            .next()
            .context("test image artifact lacks a local id")?;
        let contract_artifact = image_contract_id(platform);
        relationships.push(ArtifactRelationship {
            relation: ArtifactRelation::Documents,
            target: contract_artifact.clone(),
        });
        Some(ImageArtifactIdentity {
            contract_schema: "aos.test.image-provider/v1".to_owned(),
            contract_artifact,
            role: format!("aos.test.image-artifact.{role}/v1"),
        })
    } else {
        None
    };

    Ok((
        ArtifactRecord {
            id,
            kind,
            platform,
            system_variant: system_variant.map(str::to_owned),
            image,
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

pub(crate) struct ReleaseFixture {
    pub plan: Vec<u8>,
    pub envelope: Vec<u8>,
    pub files: Vec<CapturedFile>,
    pub key: TrustedEd25519Key,
}

pub(crate) fn release_fixture() -> anyhow::Result<ReleaseFixture> {
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
    let mut qualification = current_contract()?;
    qualification.package_rules = vec![crate::qualification::PackageRule {
        name: "example".to_owned(),
        role: crate::qualification::PackageRole::GeneralCatalog,
        inherit_dependency_obligations: true,
        execution: None,
    }];
    let mut plan = ReleasePlan {
        schema_version: crate::RELEASE_PLAN.to_owned(),
        qualification,
        qualification_predecessor: Some(crate::qualification_evidence::QualificationPredecessor {
            registry: MAIN_REGISTRY.to_owned(),
            release_id: "preceding-snapshot".into(),
            manifest_digest: digest("predecessor"),
        }),
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
            platform_versions: BTreeMap::new(),
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
            SignerRole::Channel,
        ]
        .into_iter()
        .map(signer)
        .collect(),
        surfaces: hub_surfaces(),
        destinations: Vec::new(),
        change_scope: None,
        profile_overrides: Vec::new(),
        retention: RetentionPolicy {
            policy_id: "retention-v1".to_owned(),
            policy_digest: digest("retention"),
            require_corresponding_source: true,
        },
        public_evidence_policy_digest: digest("evidence-policy"),
        restricted_operator_policy_digest: digest("operator-policy"),
    };
    rebind(&mut plan)?;
    plan.validate()?;
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
                    relation: ArtifactRelation::AuthenticatedBy,
                    target: "cache/example.narinfo".to_owned(),
                },
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
    // Image metadata carries the capabilities the qualification fixture binds.
    let metadata = canonical::canonical_json(&crate::test_support::qualification::metadata()?)?;
    for platform in Platform::LINUX {
        payloads.push(artifact(
            image_contract_id(platform),
            ArtifactKind::Provenance,
            Some(platform),
            None,
            Vec::new(),
        )?);
        for (id, kind) in image_ids(platform) {
            let bytes = if id.ends_with("/metadata") {
                metadata.clone()
            } else {
                format!("exact bytes for {id}").into_bytes()
            };
            payloads.push(artifact_with_bytes(
                id,
                kind,
                Some(platform),
                Some("server"),
                Vec::new(),
                bytes,
            )?);
        }
        payloads.push(artifact(
            format!("oci/{platform}"),
            ArtifactKind::OciManifest,
            Some(platform),
            None,
            Vec::new(),
        )?);
    }
    payloads.push(artifact(
        "oci/index".into(),
        ArtifactKind::OciIndex,
        None,
        None,
        Vec::new(),
    )?);
    let (evidence_artifact, evidence_bytes) = artifact(
        "evidence/build".to_owned(),
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
        image: None,
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
    let mut manifest = ReleaseManifestV1 {
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
        evidence: Vec::new(),
    };
    manifest.evidence = observations(&plan, &manifest, None, QualificationPhase::Build)?
        .into_iter()
        .map(|mut record| {
            record.report_digest = evidence_report_digest;
            record
        })
        .collect();
    let manifest_digest = Sha256Digest::of_canonical(MANIFEST_DOMAIN, &manifest)?;
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let request = SigningRequest {
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
    let response = SignatureResponse {
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
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
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

/// Parses the shipped contract fixture.
pub(crate) fn current_contract() -> anyhow::Result<QualificationContract> {
    crate::test_support::qualification::contract()
}

/// Returns the fixture's staging and production Hub surfaces.
pub(crate) fn hub_surfaces() -> Vec<PlannedSurface> {
    vec![
        PlannedSurface {
            role: SurfaceRole::Staging,
            kind: SurfaceKind::Hub,
            origin: "https://aos.staging.andyl.org".into(),
            readback_origin: None,
            identity: "hub-staging-v1".into(),
        },
        PlannedSurface {
            role: SurfaceRole::Production,
            kind: SurfaceKind::Hub,
            origin: "https://aos.andyl.org".into(),
            readback_origin: None,
            identity: "hub-production-v1".into(),
        },
    ]
}

/// Requests every contract destination compatible with the plan's tier and class.
pub(crate) fn requested(plan: &ReleasePlan) -> anyhow::Result<Vec<RequestedDestination>> {
    let contract = &plan.qualification;
    let tier = registry_policy(&plan.registry)?.tier();
    Ok(contract
        .destinations_for(tier)
        .filter(|cell| class_allows_channel_kind(plan.release_class, &cell.channel))
        .map(|cell| RequestedDestination {
            surface: cell.surface,
            channel: cell.channel.clone(),
            effective: None,
        })
        .collect())
}

/// Re-derives destinations and the policy digest after a test edits the contract.
pub(crate) fn rebind(plan: &mut ReleasePlan) -> anyhow::Result<()> {
    let requested = requested(plan)?;
    let contract = &plan.qualification;
    plan.destinations = planned_destinations(
        contract,
        &plan.registry,
        &requested,
        plan.change_scope.as_ref(),
    )?;
    plan.public_evidence_policy_digest = contract.digest()?;
    Ok(())
}

/// Decodes the signed stable release fixture on `andyl/main`.
pub(crate) fn qualification_fixture() -> anyhow::Result<(ReleasePlan, ReleaseManifestV1)> {
    let fixture = release_fixture()?;
    let plan: ReleasePlan = canonical::from_slice(&fixture.plan, "fixture plan")?;
    let envelope: ManifestEnvelopeV1 =
        canonical::from_slice(&fixture.envelope, "fixture manifest")?;
    Ok((plan, envelope.payload))
}

/// Converts the stable fixture into an edge release on `andyl/experimental`.
///
/// The recorded change scope marks OCI artifacts and one package cell as
/// changed, and images as unchanged.
pub(crate) fn testing_fixture() -> anyhow::Result<(ReleasePlan, ReleaseManifestV1)> {
    let (mut plan, mut manifest) = qualification_fixture()?;
    plan.registry = EXPERIMENTAL_REGISTRY.into();
    plan.version = "2026.9.0-dev.20260901.1".into();
    plan.release_class = ReleaseClass::Edge;
    plan.source.source_tag = format!("release/{}", plan.version);
    for signer in &mut plan.signers {
        if signer.role == SignerRole::TufStable {
            *signer = self::signer(SignerRole::TufEdge);
        }
    }
    if let Some(predecessor) = &mut plan.qualification_predecessor {
        predecessor.registry = plan.registry.clone();
    }
    plan.change_scope = Some(ChangeScope {
        schema_version: CHANGE_SCOPE.into(),
        predecessor_manifest_digest: Some(digest("predecessor")),
        image_affecting: false,
        container_affecting: true,
        changed_package_cells: vec![ChangedPackageCell {
            package: "example".into(),
            platform: Platform::X86_64Linux,
        }],
        reason: "fixture: one package cell and the OCI image changed".into(),
    });
    rebind(&mut plan)?;
    plan.validate()?;

    manifest.registry = plan.registry.clone();
    manifest.version = plan.version.clone();
    manifest.release_class = plan.release_class;
    Ok((plan, manifest))
}

/// Synthesizes passing observations for every case of one destination and phase.
pub(crate) fn observations(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    destination: Option<&str>,
    phase: QualificationPhase,
) -> anyhow::Result<Vec<EvidenceRecord>> {
    crate::qualification_evidence::cases(plan, manifest, destination, phase)?
        .into_iter()
        .map(|case| {
            let assessment_only = case.claim.as_ref().is_some_and(|claim| {
                claim.minimum_assurance == crate::qualification::claims::AssuranceLevel::A1
            });
            let assessment = crate::test_support::qualification::assessment(&case)?;
            let environment = if assessment_only {
                None
            } else {
                crate::test_support::qualification::environment(&case)?
            };
            let capabilities = crate::test_support::qualification::capabilities(&case)?;
            let mut environment_digest = environment
                .as_ref()
                .map(|environment| environment.digest())
                .transpose()?
                .or_else(|| {
                    assessment
                        .as_ref()
                        .map(|assessment| assessment.scope_digest)
                })
                .unwrap_or(digest("environment"));
            let mut operations = crate::test_support::qualification::measurements();
            if case.target.is_none() {
                operations = BTreeMap::from([("requests".into(), 1)]);
            }
            if assessment_only {
                operations.clear();
            }
                let mut checks = case
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
                    .collect::<BTreeMap<_, _>>();
                let native_adapter_matrix = if case.requirement_id
                    == crate::qualification_evidence::NATIVE_ADAPTER_MATRIX_REQUIREMENT
                {
                    let authored = &case.native_operation_spec.as_ref().context("matrix fixture case lacks its exact specification")?.cohorts[0];
                    let spec = authored.matrix_spec.clone();
                    let component = |name: &str, component_digest: Sha256Digest| {
                        crate::qualification_evidence::NativeAdapterMatrixComponentIdentity {
                            name: name.into(),
                            version: "fixture-v1".into(),
                            digest: component_digest,
                        }
                    };
                    let executor_digest = digest("executor");
                    let matrix_environment =
                        crate::qualification_evidence::NativeAdapterMatrixEnvironment {
                            schema_version:
                                "aos.release.native-adapter-matrix-environment/v1".into(),
                            status:
                                crate::qualification_evidence::NativeAdapterMatrixEnvironmentStatus::Production,
                            platform: Platform::X86_64Linux,
                            scenario_registry_digest: executor_digest,
                            candidate_subjects_digest: case.subjects_digest,
                            predecessor_manifest_digest: case
                                .predecessor
                                .as_ref()
                                .context("matrix fixture case lacks its predecessor")?
                                .manifest_digest,
                            unqualified_reason: None,
                            cohort: Some("fixture-cohort".into()),
                            qemu: Some(component("qemu", digest("qemu"))),
                            firmware: Some(component("firmware", digest("firmware"))),
                            guest_kernel: Some(component("guest-kernel", digest("guest kernel"))),
                            fault_injection_tool: Some(component(
                                "fault-injection-tool",
                                digest("fault tool"),
                            )),
                            harness: Some(component("matrix-harness", digest("harness closure"))),
                        };
                    environment_digest =
                        Sha256Digest::of_bytes(canonical::to_vec(&matrix_environment)?);
                    let probe_kind = |postcondition: &str| -> anyhow::Result<&'static str> {
                        Ok(match postcondition {
                            "durable-attempt-state-classified" => "journal-timeline",
                            "at-most-one-resource-owner" => "ownership-inventory",
                            "foreign-resources-unchanged" => "foreign-resource-snapshot",
                            "dependent-effects-not-executed" => "dependency-barrier",
                            "fresh-receiving-authority" => "authority-incarnation",
                            "compatible-state-adopted" => "state-adoption",
                            "exactly-one-resource-owner" => "exact-ownership-inventory",
                            "transfer-rejected-before-candidate-effect" => "transfer-rejection",
                            "predecessor-remains-sole-owner" => "predecessor-ownership",
                            "current-grants-reauthorized" => "authority-grants",
                            "retained-target-identity-preserved" => "target-identity",
                            "prerequisite-failure-recorded" => "prerequisite-failure",
                            "foreign-attempt-rejected-before-mutation" => {
                                "foreign-attempt-rejection"
                            }
                            _ => anyhow::bail!("matrix fixture has an unknown postcondition"),
                        })
                    };
                    let cells = crate::qualification_evidence::native_adapter_applicable_cells(
                        &spec,
                    )
                        .into_iter()
                        .map(|cell| {
                            let cell_digest = Sha256Digest::of_bytes(canonical::to_vec(cell)?);
                            let disposition = crate::qualification_evidence::native_adapter_expected_disposition(cell)
                                .ok_or_else(|| anyhow::anyhow!("matrix fixture has an unknown scenario"))?;
                            let cohort_subject = serde_json::json!({
                                "schema": "aos.release.native-adapter-cell-cohort-subject/v1",
                                "cell_id": cell.id,
                                "cell_digest": cell_digest,
                                "boundary": cell.boundary,
                                "failure": cell.failure,
                                "candidate": cell.candidate,
                                "predecessor": cell.predecessor,
                                "subject": {
                                    "schema": "aos.test.native-adapter-cohort-subject/v1",
                                    "operation": cell.id,
                                },
                            });
                            let cohort_subject_digest = Sha256Digest::of_bytes(
                                canonical::to_vec(&cohort_subject)?,
                            );
                            let probes = cell
                                .postconditions
                                .iter()
                                .map(|postcondition| {
                                    let observations = BTreeMap::from([(
                                        "fixture-observation".into(),
                                        serde_json::json!(format!(
                                            "{}:{postcondition}",
                                            cell.id
                                        )),
                                    )]);
                                    let observation_digest = Sha256Digest::of_bytes(
                                        canonical::to_vec(&observations)?,
                                    );
                                    Ok((
                                        postcondition.clone(),
                                        crate::qualification_evidence::NativeAdapterPostconditionProbe {
                                            schema_version: "aos.release.native-adapter-postcondition-probe/v1".into(),
                                            kind: probe_kind(postcondition)?.into(),
                                            cell_id: cell.id.clone(),
                                            cell_digest,
                                            disposition: disposition.into(),
                                            subject_digest: case.subjects_digest,
                                            cohort_subject_digest,
                                            observation_digest,
                                            observations,
                                        },
                                    ))
                                })
                                .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
                            Ok(crate::qualification_evidence::NativeAdapterCellObservation {
                                id: cell.id.clone(),
                                cell_digest,
                                environment_digest,
                                cohort_subject: Some(cohort_subject),
                                postconditions: cell
                                    .postconditions
                                    .iter()
                                    .map(|postcondition| {
                                        (
                                            postcondition.clone(),
                                            crate::qualification_evidence::CheckObservation {
                                                passed: true,
                                                detail: "fixture postcondition".into(),
                                            },
                                        )
                                    })
                                    .collect(),
                                probes,
                            })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    let matrix =
                        crate::qualification_evidence::NativeAdapterMatrixObservation {
                            schema_version:
                                crate::qualification_evidence::NATIVE_ADAPTER_MATRIX_OBSERVATION_V1
                                    .into(),
                            environment: matrix_environment,
                            cohorts: vec![crate::test_support::qualification::native_cohort_observation(authored, cells)],
                        };
                    let passed =
                        crate::qualification_evidence::validate_native_adapter_matrix_observation(
                            &case,
                            environment_digest,
                            executor_digest,
                            &matrix,
                        )?;
                    let matrix_check = case
                        .checks
                        .iter()
                        .find(|check| {
                            check.as_str()
                                == crate::qualification_evidence::NATIVE_ADAPTER_MATRIX_CHECK
                        })
                        .context("matrix fixture case lacks its policy check")?;
                    checks.insert(
                        matrix_check.clone(),
                        crate::qualification_evidence::native_adapter_matrix_check(
                            &matrix, passed,
                        )?,
                    );
                    operations = BTreeMap::from([
                        (
                            "matrix_cells_reported".into(),
                            u64::try_from(matrix.cohorts[0].cells.len())?,
                        ),
                        (
                            "matrix_postconditions_reported".into(),
                            matrix.cohorts[0].cells.iter().try_fold(0_u64, |count, cell| {
                                Ok::<_, std::num::TryFromIntError>(
                                    count + u64::try_from(cell.postconditions.len())?,
                                )
                            })?,
                        ),
                    ]);
                    Some(matrix)
                } else {
                    None
                };
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
                    environment,
                    capabilities,
                    assessment,
                    native_adapter_matrix,
                    case_digest: case.digest()?,
                    executor_digest: digest("executor"),
                    environment_digest,
                    checks,
                    observed_seconds: if assessment_only { 0 } else { 1 },
                    operations,
                    predecessor: case.predecessor,
                }),
            })
        })
        .collect()
}

#[test]
fn target_package_versions_bind_outputs_and_reject_unpublished_targets() -> anyhow::Result<()> {
    let (mut plan, _) = qualification_fixture()?;
    plan.packages[0]
        .platform_versions
        .insert(Platform::Aarch64Linux, "0.9.0".into());

    let cell = plan.packages[0]
        .platforms
        .iter_mut()
        .find(|cell| cell.platform == Platform::Aarch64Linux)
        .unwrap();
    let MatrixCell::Artifact { artifact } = &mut cell.decision else {
        panic!("fixture requires a published Arm Linux package");
    };
    artifact.artifacts[0].derivation =
        Some("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv".into());
    artifact.artifacts[0].output = Some("out".into());
    artifact.artifacts[0].store_path =
        Some("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-example".into());

    let outputs = crate::build::planned_nix_outputs(&plan)?;
    assert_eq!(outputs.values().next().unwrap().version, "0.9.0");
    plan.validate()?;

    // A target version equal to the default is not an override.
    plan.packages[0]
        .platform_versions
        .insert(Platform::Aarch64Linux, "1.0.0".into());
    assert!(plan.validate().is_err());

    // A target version must name a publishable cell.
    plan.packages[0]
        .platform_versions
        .insert(Platform::Aarch64Linux, "0.9.0".into());
    plan.packages[0]
        .platforms
        .iter_mut()
        .find(|cell| cell.platform == Platform::Aarch64Linux)
        .unwrap()
        .decision = MatrixCell::NotApplicable {
        rule: "excluded-target".into(),
        reason: "Target is not published".into(),
    };
    assert!(plan.validate().is_err());
    Ok(())
}

#[test]
fn package_artifact_requires_its_exact_signed_narinfo() -> anyhow::Result<()> {
    let fixture = release_fixture()?;
    let plan: ReleasePlan = canonical::from_slice(&fixture.plan, "fixture plan")?;
    let envelope: ManifestEnvelopeV1 =
        canonical::from_slice(&fixture.envelope, "fixture manifest")?;
    let mut manifest = envelope.payload;
    for artifact in manifest
        .artifacts
        .iter_mut()
        .filter(|artifact| artifact.kind == ArtifactKind::PackageNar)
    {
        artifact
            .relationships
            .retain(|relationship| relationship.relation != ArtifactRelation::AuthenticatedBy);
    }

    assert!(manifest.validate(&plan).is_err());
    Ok(())
}

#[test]
fn signed_plans_keep_their_exact_canonical_bytes() -> anyhow::Result<()> {
    let fixture = release_fixture()?;
    let plan: ReleasePlan = canonical::from_slice(&fixture.plan, "release plan")?;
    plan.require_publishable_qualification()?;
    assert_eq!(canonical::to_vec(&plan)?, fixture.plan);

    let mut unknown = plan;
    unknown.schema_version = "aos.release.plan/v0".into();
    assert!(unknown.validate().is_err());
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
    let (_, manifest) = qualification_fixture()?;
    assert_eq!(summary.artifact_count, 33);
    assert_eq!(summary.evidence_count, manifest.evidence.len());
    assert!(summary.evidence_count > 0);
    assert_eq!(summary.signatures_verified, 1);
    Ok(())
}

#[test]
fn release_plan_rejects_a_destination_without_its_gates() -> anyhow::Result<()> {
    let fixture = release_fixture()?;
    let mut plan: ReleasePlan = canonical::from_slice(&fixture.plan, "release plan")?;
    plan.destinations[0].gates.clear();

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

fn image_contract_id(platform: Platform) -> String {
    format!("provenance/image/server/{platform}/provider-contract")
}
