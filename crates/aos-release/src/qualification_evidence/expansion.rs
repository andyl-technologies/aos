//! Case expansion from the frozen plan and final artifact matrix.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};

use super::QualificationCase;
use super::selection::{requires_predecessor, select};
use crate::artifact::{ArtifactKind, ArtifactRecord, ArtifactRelation};
use crate::digest::Sha256Digest;
use crate::manifest::ReleaseManifestV1;
use crate::plan::ReleasePlan;
use crate::platform::{MatrixCell, Platform};
use crate::qualification::claims::{AssuranceLevel, merge_measurements};
use crate::qualification::{
    EffectiveProfile, PackageExecution, QualificationMethod, QualificationPhase,
    QualificationRequirement, QualificationScope, QualificationTarget, TargetKind,
};

/// Expands only applicable cases for one destination and phase from the
/// frozen artifact matrix.
///
/// `destination` names a planned destination (such as
/// `production/stable`); its frozen gates select the requirements and claims,
/// its change scope restricts package cells when the profile is
/// change-scoped, and its soak sets the A3 observation window. `None` expands
/// the union of every planned destination (or, for a qualification snapshot,
/// every predecessor-independent contract obligation), which is how build
/// evidence and manifest structure are checked.
///
/// # Errors
/// Returns an error for an invalid plan, an unknown destination, missing
/// required image/OCI artifacts, missing predecessor, empty subjects, or
/// noncanonical requirement identities.
pub fn cases(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    destination: Option<&str>,
    phase: QualificationPhase,
) -> Result<Vec<QualificationCase>> {
    expand(plan, manifest, destination, phase, None)
}

/// Expands cases, cross-checking a separately verified effective profile.
pub(super) fn expand(
    plan: &ReleasePlan,
    manifest: &ReleaseManifestV1,
    destination: Option<&str>,
    phase: QualificationPhase,
    effective: Option<&EffectiveProfile>,
) -> Result<Vec<QualificationCase>> {
    plan.validate()?;
    let selection = select(plan, destination, phase, effective)?;
    let contract = selection.contract;
    let package_roles = inherited_package_roles(contract, manifest)?;
    let mut requirements: Vec<_> = selection
        .requirements
        .iter()
        .map(|requirement| ((*requirement).clone(), None))
        .collect();
    for claim in &selection.claims {
        let target = contract
            .targets
            .iter()
            .find(|target| target.id == claim.target)
            .ok_or_else(|| anyhow::anyhow!("claim target is absent"))?;
        let mut checks = BTreeSet::new();
        let mut measurements = BTreeMap::new();
        for id in &claim.requirements {
            let requirement = contract
                .requirements
                .iter()
                .find(|requirement| &requirement.id == id)
                .ok_or_else(|| anyhow::anyhow!("claim requirement is absent"))?;
            checks.extend(requirement.checks.iter().cloned());
            merge_measurements(&mut measurements, &requirement.measurements)?;
        }
        if claim.minimum_assurance == AssuranceLevel::A1 {
            checks = BTreeSet::from(["reviewed-compatibility-assessment".to_owned()]);
            measurements.clear();
        }
        requirements.push((
            QualificationRequirement {
                id: format!("claim-{}", claim.id),
                phase,
                scope: match target.kind {
                    TargetKind::Image => QualificationScope::Images,
                    TargetKind::Container => QualificationScope::Containers,
                },
                method: if claim.minimum_assurance == AssuranceLevel::A1 {
                    QualificationMethod::Operator
                } else {
                    QualificationMethod::Automated
                },
                native_operation_spec: None,
                production_only: false,
                checks: checks.into_iter().collect(),
                measurements,
                regressions: Vec::new(),
                invalidated_by: Vec::new(),
            },
            Some((*claim).clone()),
        ));
    }
    let mut result = Vec::new();
    let plan_digest = Sha256Digest::of_bytes(crate::canonical::to_vec(plan)?);
    for (requirement, claim) in requirements {
        let policy_digest = selection.policy_digest(&requirement.id)?;
        let mut add = |suffix: String,
                       platform: Option<Platform>,
                       target: Option<QualificationTarget>,
                       mut subjects: Vec<String>|
         -> Result<()> {
            subjects.sort();
            subjects.dedup();
            if subjects.is_empty() {
                bail!(
                    "qualification requirement {} has no artifacts for {suffix}",
                    requirement.id
                );
            }
            let package_rule = if requirement.scope == QualificationScope::Packages {
                let (name, _) = suffix
                    .rsplit_once('/')
                    .ok_or_else(|| anyhow::anyhow!("invalid package case identity"))?;
                Some(
                    contract
                        .package_rules
                        .iter()
                        .find(|rule| rule.name == name)
                        .ok_or_else(|| {
                            anyhow::anyhow!("package case lacks its criticality classification")
                        })?,
                )
            } else {
                None
            };
            let predecessor = if requires_predecessor(&requirement.id)
                || claim.as_ref().is_some_and(|claim| {
                    claim.minimum_assurance >= AssuranceLevel::A2
                        && claim.requirements.iter().any(|id| requires_predecessor(id))
                })
                || package_rule.is_some_and(|rule| {
                    matches!(rule.execution, Some(PackageExecution::RecoveryImage { .. }))
                }) {
                Some(plan.qualification_predecessor.clone().ok_or_else(|| {
                    anyhow::anyhow!("qualification execution requires a frozen predecessor")
                })?)
            } else {
                None
            };
            let package_role = if let Some(rule) = package_rule {
                let direct = rule.role;
                let inherited = subjects
                    .iter()
                    .filter_map(|subject| package_roles.get(subject))
                    .copied()
                    .max()
                    .unwrap_or(direct);

                Some(direct.max(inherited))
            } else {
                None
            };
            let artifacts = subjects
                .iter()
                .map(|id| {
                    manifest
                        .artifacts
                        .iter()
                        .find(|artifact| artifact.id == *id)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "qualification subject {id} has no final artifact record"
                            )
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            let subjects_digest =
                Sha256Digest::of_canonical("aos.release.qualification-subjects/v1", &artifacts)?;
            result.push(QualificationCase {
                schema_version: super::QUALIFICATION_CASE.to_owned(),
                claim: claim.clone(),
                measurements: requirement.measurements.clone(),
                minimum_observed_seconds: claim
                    .as_ref()
                    .is_some_and(|claim| claim.minimum_assurance == AssuranceLevel::A3)
                    .then_some(selection.soak_seconds),
                id: format!("{}/{suffix}", requirement.id),
                requirement_id: requirement.id.clone(),
                native_operation_spec: requirement.native_operation_spec.clone(),
                policy_digest,
                plan_digest,
                subjects_digest,
                phase,
                platform,
                package_role,
                target,
                subjects,
                checks: requirement.checks.clone(),
                method: requirement.method,
                predecessor,
            });
            Ok(())
        };
        match requirement.scope {
            QualificationScope::Release => add(
                "release".to_owned(),
                None,
                None,
                manifest
                    .artifacts
                    .iter()
                    // The plan is a private control input already bound by
                    // plan_digest, not an anonymously downloadable object.
                    // Evidence cannot include itself in its own subject hash.
                    .filter(|artifact| {
                        !matches!(
                            artifact.kind,
                            ArtifactKind::ReleasePlan | ArtifactKind::Evidence
                        )
                    })
                    .map(|artifact| artifact.id.clone())
                    .collect(),
            )?,
            QualificationScope::Packages => {
                for package in &manifest.packages {
                    for cell in &package.platforms {
                        // Change-scoped profiles exercise only changed cells.
                        if selection.package_scope.is_some_and(|scope| {
                            !scope.affects_package(&package.name, cell.platform)
                        }) {
                            continue;
                        }
                        if let MatrixCell::Artifact { artifact } = &cell.decision {
                            let rule = contract
                                .package_rules
                                .iter()
                                .find(|rule| rule.name == package.name)
                                .ok_or_else(|| {
                                    anyhow::anyhow!("package lacks its criticality classification")
                                })?;
                            let mut subjects = artifact.artifact_ids.clone();
                            if let Some(execution) = &rule.execution {
                                let system_variant = execution.system_variant();
                                let image = manifest
                                    .images
                                    .iter()
                                    .find(|image| image.system_variant == system_variant)
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "package {} requires absent execution image variant {}",
                                            package.name,
                                            system_variant
                                        )
                                    })?;
                                let image_cell = image
                                    .platforms
                                    .iter()
                                    .find(|image_cell| image_cell.platform == cell.platform)
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "package {} execution image lacks platform {}",
                                            package.name,
                                            cell.platform
                                        )
                                    })?;
                                let MatrixCell::Artifact {
                                    artifact: image_artifact,
                                } = &image_cell.decision
                                else {
                                    bail!(
                                        "package {} execution image platform is not an artifact",
                                        package.name
                                    );
                                };
                                subjects.extend(image_artifact.artifact_ids.iter().cloned());
                                if let PackageExecution::K3sFleet { topology, .. } = execution {
                                    subjects.extend(k3s_fleet_subjects(
                                        manifest,
                                        cell.platform,
                                        *topology,
                                    )?);
                                }
                            }
                            add(
                                format!("{}/{}", package.name, cell.platform),
                                Some(cell.platform),
                                None,
                                subjects,
                            )?;
                        }
                    }
                }
            }
            QualificationScope::Images => {
                for target in contract
                    .targets
                    .iter()
                    .filter(|target| target.kind == TargetKind::Image)
                    .filter(|target| claim.as_ref().is_none_or(|claim| claim.target == target.id))
                {
                    for image in &manifest.images {
                        let cell = image
                            .platforms
                            .iter()
                            .find(|cell| cell.platform == target.platform);
                        match cell.map(|cell| &cell.decision) {
                            Some(MatrixCell::Artifact { artifact }) => add(
                                format!("{}/{}", image.system_variant, target.id),
                                Some(target.platform),
                                Some(target.clone()),
                                artifact.artifact_ids.clone(),
                            )?,
                            _ if target.required => {
                                bail!("missing required image target {}", target.id)
                            }
                            _ => {}
                        }
                    }
                    if target.required && manifest.images.is_empty() {
                        bail!("missing required image matrix");
                    }
                }
            }
            QualificationScope::Containers => {
                for target in contract
                    .targets
                    .iter()
                    .filter(|target| target.kind == TargetKind::Container)
                    .filter(|target| claim.as_ref().is_none_or(|claim| claim.target == target.id))
                {
                    let subjects: Vec<_> = manifest
                        .artifacts
                        .iter()
                        .filter(|artifact| {
                            artifact.kind == ArtifactKind::OciIndex
                                || (matches!(
                                    artifact.kind,
                                    ArtifactKind::OciManifest | ArtifactKind::OciBlob
                                ) && artifact.platform == Some(target.platform))
                        })
                        .map(|artifact| artifact.id.clone())
                        .collect();
                    let has_manifest = manifest.artifacts.iter().any(|artifact| {
                        artifact.kind == ArtifactKind::OciManifest
                            && artifact.platform == Some(target.platform)
                    });
                    let has_index = manifest
                        .artifacts
                        .iter()
                        .any(|artifact| artifact.kind == ArtifactKind::OciIndex);
                    if target.required && (!has_manifest || !has_index) {
                        bail!(
                            "missing required OCI index/platform manifest for {}",
                            target.id
                        );
                    }
                    if has_manifest && has_index {
                        add(
                            target.id.clone(),
                            Some(target.platform),
                            Some(target.clone()),
                            subjects,
                        )?;
                    }
                }
            }
        }
    }
    result.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(result)
}

/// Binds every service package and the published workload used by a K3s fleet.
fn k3s_fleet_subjects(
    manifest: &ReleaseManifestV1,
    platform: Platform,
    topology: crate::qualification::K3sTopology,
) -> Result<Vec<String>> {
    if !platform.supports_images() {
        bail!("K3s fleet qualification requires a Linux platform");
    }

    let mut subjects = Vec::new();
    for name in topology.packages() {
        let package = manifest
            .packages
            .iter()
            .find(|package| package.name == name)
            .ok_or_else(|| anyhow::anyhow!("K3s fleet lacks package {name}"))?;
        let cell = package
            .platforms
            .iter()
            .find(|cell| cell.platform == platform)
            .ok_or_else(|| anyhow::anyhow!("K3s fleet package {name} lacks platform {platform}"))?;
        let MatrixCell::Artifact { artifact } = &cell.decision else {
            bail!("K3s fleet package {name}/{platform} is not an artifact");
        };
        subjects.extend(artifact.artifact_ids.iter().cloned());
    }

    // The release manifest currently carries one published OCI index. Reject
    // ambiguity instead of selecting a workload by ordering or a mutable tag.
    let indexes: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::OciIndex)
        .collect();
    let manifests: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.kind == ArtifactKind::OciManifest && artifact.platform == Some(platform)
        })
        .collect();
    if indexes.len() != 1 || manifests.len() != 1 {
        bail!("K3s fleet requires one published OCI index and platform manifest");
    }
    subjects.extend(indexes.into_iter().map(|artifact| artifact.id.clone()));
    subjects.extend(manifests.into_iter().map(|artifact| artifact.id.clone()));
    subjects.extend(
        manifest
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.kind == ArtifactKind::OciBlob && artifact.platform == Some(platform)
            })
            .map(|artifact| artifact.id.clone()),
    );
    Ok(subjects)
}

fn inherited_package_roles(
    contract: &crate::qualification::QualificationContract,
    manifest: &ReleaseManifestV1,
) -> Result<BTreeMap<String, crate::qualification::PackageRole>> {
    let artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let rules = contract
        .package_rules
        .iter()
        .map(|rule| (rule.name.as_str(), rule.role))
        .collect::<BTreeMap<_, _>>();
    let mut roles = BTreeMap::new();

    for package in &manifest.packages {
        let role = rules
            .get(package.name.as_str())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("package case lacks its criticality classification"))?;
        for cell in &package.platforms {
            let MatrixCell::Artifact { artifact } = &cell.decision else {
                continue;
            };
            propagate_package_role(&artifacts, &artifact.artifact_ids, role, &mut roles)?;
        }
    }

    Ok(roles)
}

fn propagate_package_role(
    artifacts: &BTreeMap<&str, &ArtifactRecord>,
    roots: &[String],
    role: crate::qualification::PackageRole,
    roles: &mut BTreeMap<String, crate::qualification::PackageRole>,
) -> Result<()> {
    let mut pending = roots.to_vec();

    while let Some(id) = pending.pop() {
        if roles.get(&id).is_some_and(|current| *current >= role) {
            continue;
        }
        let artifact = artifacts
            .get(id.as_str())
            .ok_or_else(|| anyhow::anyhow!("package closure references missing artifact {id}"))?;
        roles.insert(id, role);
        pending.extend(
            artifact
                .relationships
                .iter()
                .filter(|relationship| relationship.relation == ArtifactRelation::Contains)
                .map(|relationship| relationship.target.clone()),
        );
    }

    Ok(())
}
