//! Finalized closed release manifest and signed envelope.
//!
//! The manifest inventories every regular payload file beneath the bundle
//! root. `release-manifest.json` is the signed root envelope itself and is the
//! only file not recursively listed by its payload.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactKind, ArtifactRecord, require_identifier};
use crate::digest::Sha256Digest;
use crate::evidence::EvidenceRecord;
use crate::plan::{PlatformCell, ReleaseClass, ReleasePlanV1};
use crate::platform::{
    MatrixCell, require_complete_image_platforms, require_complete_package_platforms,
};
use crate::signing::{SignatureResponseV1, SigningRequestV1};
use crate::{CANONICAL_REGISTRY, RELEASE_MANIFEST_V1};

/// Signature domain for the final manifest payload.
pub const MANIFEST_DOMAIN: &str = "aos.release.manifest/v1";

/// Schema id for the signed manifest envelope stored at the bundle root.
pub const MANIFEST_ENVELOPE_V1: &str = "aos.release.manifest-envelope/v1";

/// Final artifact ids that satisfy one matrix cell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalArtifactSet {
    /// Stable logical ids resolved by the artifact inventory.
    pub artifact_ids: Vec<String>,
}

/// Final package result across all four platforms.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageResult {
    /// Canonical package name.
    pub name: String,
    /// One final decision for each package platform.
    pub platforms: Vec<PlatformCell<FinalArtifactSet>>,
}

/// Final system-image result across both Linux platforms.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageResult {
    /// Canonical system variant.
    pub system_variant: String,
    /// One final decision for each Linux platform.
    pub platforms: Vec<PlatformCell<FinalArtifactSet>>,
}

/// Final immutable payload signed before staging begins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifestV1 {
    /// Exact manifest schema identifier.
    pub schema_version: String,
    /// Immutable release identity.
    pub release_id: String,
    /// Exact SemVer-compatible calendar version.
    pub version: String,
    /// Release maturity and authorization class.
    pub release_class: ReleaseClass,
    /// Canonical public registry identity.
    pub registry: String,
    /// Digest of the frozen canonical plan.
    pub plan_digest: Sha256Digest,
    /// Exact source Git commit inherited from the plan.
    pub source_commit: String,
    /// Final package matrix.
    pub packages: Vec<PackageResult>,
    /// Final Linux image matrix.
    pub images: Vec<ImageResult>,
    /// Exact regular payload files in the bundle.
    pub artifacts: Vec<ArtifactRecord>,
    /// Public gate and qualification evidence.
    pub evidence: Vec<EvidenceRecord>,
}

impl ReleaseManifestV1 {
    /// Validates the finalized manifest against its frozen plan.
    ///
    /// # Errors
    ///
    /// Returns an error for identity drift, malformed or incomplete matrices,
    /// unresolved or mismatched artifacts, extra/missing planned cells,
    /// duplicate ids/paths, dangling relationships, failed required evidence,
    /// or a missing exact `release-plan.json` artifact.
    pub fn validate(&self, plan: &ReleasePlanV1) -> Result<()> {
        if self.schema_version != RELEASE_MANIFEST_V1 {
            bail!(
                "unsupported release manifest schema: {}",
                self.schema_version
            );
        }
        if self.registry != CANONICAL_REGISTRY
            || self.registry != plan.registry
            || self.release_id != plan.release_id
            || self.version != plan.version
            || self.release_class != plan.release_class
            || self.source_commit != plan.source.commit
        {
            bail!("release manifest identity differs from its frozen plan");
        }

        let artifacts = validate_artifacts(&self.artifacts)?;
        let plan_artifacts: Vec<_> = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == ArtifactKind::ReleasePlan)
            .collect();
        if plan_artifacts.len() != 1
            || plan_artifacts[0].path.as_str() != "release-plan.json"
            || plan_artifacts[0].sha256 != self.plan_digest
        {
            bail!("manifest must bind one exact release-plan.json artifact");
        }

        if self.packages.len() != plan.packages.len() || self.images.len() != plan.images.len() {
            bail!("final matrix cardinality differs from the plan");
        }
        let planned_packages: BTreeMap<_, _> = plan
            .packages
            .iter()
            .map(|value| (&value.name, value))
            .collect();
        let mut seen_packages = BTreeSet::new();
        for package in &self.packages {
            if !seen_packages.insert(&package.name) {
                bail!("duplicate final package {}", package.name);
            }
            let planned = planned_packages
                .get(&package.name)
                .ok_or_else(|| anyhow::anyhow!("unplanned package {}", package.name))?;
            validate_final_cells(&package.platforms, &planned.platforms, false, &artifacts)?;
        }

        let planned_images: BTreeMap<_, _> = plan
            .images
            .iter()
            .map(|value| (&value.system_variant, value))
            .collect();
        let mut seen_images = BTreeSet::new();
        for image in &self.images {
            if !seen_images.insert(&image.system_variant) {
                bail!("duplicate final image variant {}", image.system_variant);
            }
            let planned = planned_images.get(&image.system_variant).ok_or_else(|| {
                anyhow::anyhow!("unplanned image variant {}", image.system_variant)
            })?;
            validate_final_cells(&image.platforms, &planned.platforms, true, &artifacts)?;
        }

        let required_gates: BTreeSet<_> = plan
            .gates
            .iter()
            .filter(|gate| {
                gate.required_for_stable || !plan.release_class.requires_complete_matrix()
            })
            .map(|gate| (&gate.policy_id, gate.policy_digest))
            .collect();
        let mut seen_evidence = BTreeSet::new();
        let mut passed_gates = BTreeSet::new();
        for evidence in &self.evidence {
            evidence.validate()?;
            if !seen_evidence.insert(&evidence.id) {
                bail!("duplicate evidence id {}", evidence.id);
            }
            let report_found = self.artifacts.iter().any(|artifact| {
                artifact.kind == ArtifactKind::Evidence
                    && artifact.sha256 == evidence.report_digest
                    && evidence
                        .subjects
                        .iter()
                        .all(|subject| artifacts.contains_key(subject.as_str()))
            });
            if !report_found {
                bail!("evidence {} lacks its exact report or subject", evidence.id);
            }
            if evidence.result == crate::evidence::GateResult::Passed {
                passed_gates.insert((&evidence.policy_id, evidence.policy_digest));
            }
        }
        if !required_gates.is_subset(&passed_gates) {
            bail!("manifest lacks passing evidence for every selected required gate");
        }
        if plan.release_class.requires_complete_matrix() {
            validate_production_supply_chain(self, &artifacts)?;
            validate_production_images(self, &artifacts)?;
        }
        Ok(())
    }
}

fn validate_production_supply_chain(
    manifest: &ReleaseManifestV1,
    artifacts: &BTreeMap<&str, &ArtifactRecord>,
) -> Result<()> {
    for kind in [
        ArtifactKind::RegistryObject,
        ArtifactKind::NarInfo,
        ArtifactKind::Source,
        ArtifactKind::Provenance,
        ArtifactKind::Sbom,
        ArtifactKind::License,
    ] {
        if !manifest
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == kind)
        {
            bail!("production release lacks required {kind:?} artifact evidence");
        }
    }
    for package in manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::PackageNar)
    {
        let has_source = package.relationships.iter().any(|relationship| {
            relationship.relation == crate::artifact::ArtifactRelation::CorrespondingSource
                && artifacts
                    .get(relationship.target.as_str())
                    .is_some_and(|target| target.kind == ArtifactKind::Source)
        });
        let has_license = package.relationships.iter().any(|relationship| {
            relationship.relation == crate::artifact::ArtifactRelation::LicensedBy
                && artifacts
                    .get(relationship.target.as_str())
                    .is_some_and(|target| target.kind == ArtifactKind::License)
        });
        if !has_source || !has_license {
            bail!(
                "production package {} lacks exact corresponding-source or license evidence",
                package.id
            );
        }
    }
    Ok(())
}

fn validate_production_images(
    manifest: &ReleaseManifestV1,
    artifacts: &BTreeMap<&str, &ArtifactRecord>,
) -> Result<()> {
    let required = [
        ArtifactKind::LogicalDisk,
        ArtifactKind::RawImage,
        ArtifactKind::Qcow2Image,
        ArtifactKind::VmdkImage,
        ArtifactKind::VhdImage,
        ArtifactKind::Uki,
        ArtifactKind::RecoveryUki,
        ArtifactKind::RecoveryBundle,
        ArtifactKind::ImageMetadata,
    ];
    for image in &manifest.images {
        for cell in &image.platforms {
            let MatrixCell::Artifact { artifact } = &cell.decision else {
                bail!("production image matrix contains a non-artifact cell");
            };
            let kinds = artifact
                .artifact_ids
                .iter()
                .filter_map(|id| artifacts.get(id.as_str()).map(|artifact| artifact.kind))
                .collect::<BTreeSet<_>>();
            if required.iter().any(|kind| !kinds.contains(kind)) {
                bail!(
                    "production image {}/{} lacks its complete finalized format set",
                    image.system_variant,
                    cell.platform
                );
            }
        }
    }
    Ok(())
}

/// One request and response embedded in the signed manifest envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    /// Complete request authorized by the external signer.
    pub request: SigningRequestV1,
    /// Public response returned by the signer.
    pub response: SignatureResponseV1,
}

/// Signed root file stored as `release-manifest.json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEnvelopeV1 {
    /// Exact envelope schema identifier.
    pub schema_version: String,
    /// Final closed release payload.
    pub payload: ReleaseManifestV1,
    /// Domain-separated digest of the canonical payload.
    pub payload_digest: Sha256Digest,
    /// Threshold signatures over role-bound requests for the payload.
    pub signatures: Vec<ManifestSignature>,
}

fn validate_artifacts(artifacts: &[ArtifactRecord]) -> Result<BTreeMap<&str, &ArtifactRecord>> {
    let mut ids = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for artifact in artifacts {
        artifact.validate()?;
        if ids.insert(artifact.id.as_str(), artifact).is_some() {
            bail!("duplicate artifact id {}", artifact.id);
        }
        if !paths.insert(artifact.path.as_str()) {
            bail!("duplicate artifact path {}", artifact.path);
        }
        if artifact.path.as_str() == "release-manifest.json" {
            bail!("manifest payload cannot recursively inventory its envelope");
        }
    }
    for artifact in artifacts {
        for relationship in &artifact.relationships {
            if !ids.contains_key(relationship.target.as_str()) {
                bail!("artifact {} has a dangling relationship", artifact.id);
            }
        }
    }
    Ok(ids)
}

fn validate_final_cells(
    final_cells: &[PlatformCell<FinalArtifactSet>],
    planned_cells: &[PlatformCell<crate::plan::PlannedArtifactSet>],
    image: bool,
    artifacts: &BTreeMap<&str, &ArtifactRecord>,
) -> Result<()> {
    if image {
        require_complete_image_platforms(final_cells.iter().map(|cell| &cell.platform))?;
    } else {
        require_complete_package_platforms(final_cells.iter().map(|cell| &cell.platform))?;
    }
    if final_cells.len() != planned_cells.len() {
        bail!("final matrix contains a missing or duplicate platform cell");
    }
    let planned_by_platform: BTreeMap<_, _> = planned_cells
        .iter()
        .map(|cell| (cell.platform, &cell.decision))
        .collect();
    for cell in final_cells {
        cell.decision.validate()?;
        let planned = planned_by_platform
            .get(&cell.platform)
            .ok_or_else(|| anyhow::anyhow!("unplanned platform cell {}", cell.platform))?;
        match (&cell.decision, *planned) {
            (
                MatrixCell::Artifact {
                    artifact: final_set,
                },
                MatrixCell::Artifact {
                    artifact: planned_set,
                },
            ) => {
                let planned_ids: Vec<_> = planned_set
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.id.as_str())
                    .collect();
                if final_set.artifact_ids.is_empty()
                    || !final_set
                        .artifact_ids
                        .iter()
                        .map(String::as_str)
                        .eq(planned_ids.iter().copied())
                {
                    bail!("final artifact ids differ from the planned cell");
                }
                let mut unique = BTreeSet::new();
                for (id, planned_artifact) in
                    final_set.artifact_ids.iter().zip(&planned_set.artifacts)
                {
                    if !unique.insert(id) {
                        bail!("matrix cell contains duplicate artifact id {id}");
                    }
                    let artifact = artifacts.get(id.as_str()).ok_or_else(|| {
                        anyhow::anyhow!("matrix references missing artifact {id}")
                    })?;
                    if artifact
                        .platform
                        .is_some_and(|platform| platform != cell.platform)
                    {
                        bail!("artifact {id} has the wrong platform for its matrix cell");
                    }
                    if image && !artifact.kind.is_linux_image() {
                        bail!("image matrix cell references non-image artifact {id}");
                    }
                    if planned_artifact.derivation.is_some()
                        && (artifact.derivation.as_deref()
                            != planned_artifact.derivation.as_deref()
                            || artifact.output.as_deref() != planned_artifact.output.as_deref()
                            || artifact.store_path.as_deref()
                                != planned_artifact.store_path.as_deref())
                    {
                        bail!("artifact {id} differs from its planned Nix identity");
                    }
                }
            }
            (
                MatrixCell::NotApplicable {
                    rule: left_rule,
                    reason: left_reason,
                },
                MatrixCell::NotApplicable {
                    rule: right_rule,
                    reason: right_reason,
                },
            ) if left_rule == right_rule && left_reason == right_reason => {}
            (
                MatrixCell::Blocked {
                    required_work: left_work,
                    failure_evidence: left_evidence,
                },
                MatrixCell::Blocked {
                    required_work: right_work,
                    failure_evidence: right_evidence,
                },
            ) if left_work == right_work && left_evidence == right_evidence => {}
            _ => bail!("final matrix decision differs from its frozen plan"),
        }
    }
    Ok(())
}

/// Validates a stable public manifest identifier.
///
/// # Errors
///
/// Returns an error under the same conditions as the shared identifier check.
pub fn validate_manifest_identifier(value: &str) -> Result<()> {
    require_identifier(value, "manifest identifier")
}
