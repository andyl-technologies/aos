//! Change scope: which artifact populations differ from the predecessor.
//!
//! A change-scoped profile applies image claims only when the release is
//! image-affecting, container claims only when an OCI artifact changed, and
//! `package-function` only to package cells whose artifact set changed. The
//! scope is computed once at plan time and recorded in the plan; admission
//! recomputes it from final manifests and requires the recorded scope to cover
//! the recomputed one. Without a predecessor manifest every population is
//! affecting.
//!
//! ```json
//! {"schema_version":"aos.release.change-scope/v1",
//!  "predecessor_manifest_digest":"sha256:...",
//!  "image_affecting":false,"container_affecting":true,
//!  "changed_package_cells":[{"package":"aos","platform":"x86_64-linux"}],
//!  "reason":"3 of 12 package cells changed; OCI artifacts changed"}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactKind;
use crate::digest::Sha256Digest;
use crate::manifest::{MANIFEST_DOMAIN, ReleaseManifestV1};
use crate::plan::{QUALIFICATION_SNAPSHOT_RELEASE_PREFIX, ReleasePlan};
use crate::platform::{MatrixCell, Platform};

/// Exact change-scope schema identifier.
pub const CHANGE_SCOPE: &str = "aos.release.change-scope/v1";

/// One package platform cell whose artifact set differs from the predecessor.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedPackageCell {
    /// Canonical package name.
    pub package: String,
    /// Exact platform of the changed cell.
    pub platform: Platform,
}

/// Recorded determination of what a release changes relative to its predecessor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeScope {
    /// Exact document schema.
    pub schema_version: String,
    /// Identity of the compared predecessor manifest; absent when unavailable.
    pub predecessor_manifest_digest: Option<Sha256Digest>,
    /// Whether any system-image artifact differs.
    pub image_affecting: bool,
    /// Whether any OCI artifact differs.
    pub container_affecting: bool,
    /// Sorted package cells whose artifact set differs.
    pub changed_package_cells: Vec<ChangedPackageCell>,
    /// Human-readable account of the determination.
    pub reason: String,
}

impl ChangeScope {
    /// Constructs the fail-closed scope in which every population is affecting.
    #[must_use]
    pub fn everything(current: &ReleaseManifestV1, reason: impl Into<String>) -> Self {
        Self {
            schema_version: CHANGE_SCOPE.to_owned(),
            predecessor_manifest_digest: None,
            image_affecting: true,
            container_affecting: true,
            changed_package_cells: sorted_cells(artifact_cells(current).into_keys()),
            reason: reason.into(),
        }
    }

    /// Constructs the fail-closed scope for a plan that has no predecessor.
    #[must_use]
    pub fn everything_planned(plan: &ReleasePlan, reason: impl Into<String>) -> Self {
        Self {
            schema_version: CHANGE_SCOPE.to_owned(),
            predecessor_manifest_digest: None,
            image_affecting: true,
            container_affecting: true,
            changed_package_cells: sorted_cells(planned_cells(plan).into_keys()),
            reason: reason.into(),
        }
    }

    /// Returns whether a package cell's artifacts are in scope.
    #[must_use]
    pub fn affects_package(&self, package: &str, platform: Platform) -> bool {
        self.changed_package_cells
            .iter()
            .any(|cell| cell.package == package && cell.platform == platform)
    }

    /// Validates the document shape and fail-closed invariants.
    ///
    /// # Errors
    /// Returns an error for a wrong schema, unsorted or duplicate cells, an
    /// empty reason, or a scope without a predecessor that excludes anything.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CHANGE_SCOPE {
            bail!("unsupported change scope schema");
        }
        if self.reason.trim().is_empty() {
            bail!("change scope requires a recorded reason");
        }
        if self
            .changed_package_cells
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            bail!("changed package cells must be unique and sorted");
        }
        if self.predecessor_manifest_digest.is_none()
            && (!self.image_affecting || !self.container_affecting)
        {
            bail!("a change scope without a predecessor must treat every population as affecting");
        }
        Ok(())
    }

    /// Requires this recorded scope to include everything `recomputed` found changed.
    ///
    /// A plan-time scope derived from store paths may over-approximate; it may
    /// never omit a population that the final manifests show to differ.
    ///
    /// # Errors
    /// Returns an error when `recomputed` marks a population or package cell
    /// affecting that this scope does not.
    pub fn covers(&self, recomputed: &Self) -> Result<()> {
        if (recomputed.image_affecting && !self.image_affecting)
            || (recomputed.container_affecting && !self.container_affecting)
        {
            bail!("recorded change scope omits an affected image or container population");
        }
        for cell in &recomputed.changed_package_cells {
            if !self.affects_package(&cell.package, cell.platform) {
                bail!(
                    "recorded change scope omits changed package cell {}/{}",
                    cell.package,
                    cell.platform
                );
            }
        }
        Ok(())
    }
}

/// Classifies a final manifest against its predecessor's final manifest.
///
/// Image, OCI, and per-cell package artifact digests are compared. A missing
/// predecessor, or a predecessor that is a non-public qualification snapshot,
/// makes everything affecting.
///
/// # Errors
/// Returns an error when the predecessor manifest cannot be canonically
/// encoded for its identity.
pub fn classify(
    current: &ReleaseManifestV1,
    predecessor: Option<&ReleaseManifestV1>,
) -> Result<ChangeScope> {
    let Some(predecessor) = predecessor else {
        return Ok(ChangeScope::everything(
            current,
            "no predecessor manifest is available; every population is affecting",
        ));
    };
    if predecessor
        .release_id
        .starts_with(QUALIFICATION_SNAPSHOT_RELEASE_PREFIX)
    {
        return Ok(ChangeScope::everything(
            current,
            "predecessor is a qualification snapshot; every population is affecting",
        ));
    }

    let current_digests = artifact_digests(current);
    let predecessor_digests = artifact_digests(predecessor);
    let image_affecting = image_identity(current, &current_digests)
        != image_identity(predecessor, &predecessor_digests);
    let container_affecting = container_identity(current, &current_digests)
        != container_identity(predecessor, &predecessor_digests);
    let current_cells = artifact_cells(current);
    let predecessor_cells = artifact_cells(predecessor);
    let changed = current_cells
        .into_iter()
        .filter(|(cell, ids)| {
            let current_identity = cell_identity(ids, &current_digests);
            predecessor_cells.get(cell).is_none_or(|previous| {
                cell_identity(previous, &predecessor_digests) != current_identity
            })
        })
        .map(|(cell, _)| cell);
    let changed_package_cells = sorted_cells(changed);
    let reason = format!(
        "{} package cells changed; images {}; containers {}",
        changed_package_cells.len(),
        if image_affecting {
            "changed"
        } else {
            "unchanged"
        },
        if container_affecting {
            "changed"
        } else {
            "unchanged"
        },
    );

    Ok(ChangeScope {
        schema_version: CHANGE_SCOPE.to_owned(),
        predecessor_manifest_digest: Some(Sha256Digest::of_canonical(
            MANIFEST_DOMAIN,
            predecessor,
        )?),
        image_affecting,
        container_affecting,
        changed_package_cells,
        reason,
    })
}

/// Classifies a frozen plan against its predecessor's final manifest.
///
/// Planning precedes building, so this compares planned Nix store paths with
/// the predecessor's recorded store paths. Any cell whose store paths are not
/// fully known on both sides is treated as changed, so the plan-time scope
/// over-approximates and [`ChangeScope::covers`] holds against the
/// manifest-derived scope of a reproducible build.
///
/// # Errors
/// Returns an error when the predecessor manifest cannot be canonically
/// encoded for its identity.
pub fn classify_plan(
    plan: &ReleasePlan,
    predecessor: Option<&ReleaseManifestV1>,
) -> Result<ChangeScope> {
    let Some(predecessor) = predecessor else {
        return Ok(ChangeScope::everything_planned(
            plan,
            "no predecessor manifest is available; every population is affecting",
        ));
    };
    if predecessor
        .release_id
        .starts_with(QUALIFICATION_SNAPSHOT_RELEASE_PREFIX)
    {
        return Ok(ChangeScope::everything_planned(
            plan,
            "predecessor is a qualification snapshot; every population is affecting",
        ));
    }

    let predecessor_paths = store_paths(predecessor);
    let predecessor_cells = artifact_cells(predecessor);
    let planned_images: BTreeSet<_> = plan
        .images
        .iter()
        .flat_map(|image| image.platforms.iter())
        .filter_map(|cell| planned_paths(&cell.decision))
        .flatten()
        .collect();
    let predecessor_images: Option<BTreeSet<_>> = predecessor
        .images
        .iter()
        .flat_map(|image| image.platforms.iter())
        .filter_map(|cell| match &cell.decision {
            MatrixCell::Artifact { artifact } => Some(&artifact.artifact_ids),
            MatrixCell::Blocked { .. } | MatrixCell::NotApplicable { .. } => None,
        })
        .flatten()
        .map(|id| {
            predecessor_paths
                .get(id.as_str())
                .copied()
                .map(str::to_owned)
        })
        .collect();
    let image_affecting = planned_images.is_empty()
        || predecessor_images.is_none_or(|previous| previous != planned_images);

    let changed = planned_cells(plan).into_iter().filter(|(cell, paths)| {
        let Some(paths) = paths else {
            return true;
        };
        let previous: Option<BTreeSet<String>> = predecessor_cells.get(cell).map(|ids| {
            ids.iter()
                .filter_map(|id| {
                    predecessor_paths
                        .get(id.as_str())
                        .map(|path| (*path).to_owned())
                })
                .collect()
        });
        previous.is_none_or(|previous| previous != *paths)
    });
    let changed_package_cells = sorted_cells(changed.map(|(cell, _)| cell));

    Ok(ChangeScope {
        schema_version: CHANGE_SCOPE.to_owned(),
        predecessor_manifest_digest: Some(Sha256Digest::of_canonical(
            MANIFEST_DOMAIN,
            predecessor,
        )?),
        image_affecting,
        // OCI artifacts are assembled outside Nix store-path identity, so a
        // plan cannot prove them unchanged before the build.
        container_affecting: true,
        changed_package_cells,
        reason:
            "planned store paths compared with the predecessor manifest; containers assumed changed"
                .to_owned(),
    })
}

fn artifact_digests(manifest: &ReleaseManifestV1) -> BTreeMap<&str, Sha256Digest> {
    manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact.sha256))
        .collect()
}

fn store_paths(manifest: &ReleaseManifestV1) -> BTreeMap<&str, &str> {
    manifest
        .artifacts
        .iter()
        .filter_map(|artifact| {
            artifact
                .store_path
                .as_deref()
                .map(|path| (artifact.id.as_str(), path))
        })
        .collect()
}

/// Package cells carrying artifacts, keyed by cell, with their artifact ids.
fn artifact_cells(manifest: &ReleaseManifestV1) -> BTreeMap<ChangedPackageCell, Vec<String>> {
    manifest
        .packages
        .iter()
        .flat_map(|package| {
            package
                .platforms
                .iter()
                .filter_map(|cell| match &cell.decision {
                    MatrixCell::Artifact { artifact } => Some((
                        ChangedPackageCell {
                            package: package.name.clone(),
                            platform: cell.platform,
                        },
                        artifact.artifact_ids.clone(),
                    )),
                    MatrixCell::Blocked { .. } | MatrixCell::NotApplicable { .. } => None,
                })
        })
        .collect()
}

/// Planned package cells with their complete store-path sets, or `None` when
/// any planned artifact lacks a Nix identity.
fn planned_cells(plan: &ReleasePlan) -> BTreeMap<ChangedPackageCell, Option<BTreeSet<String>>> {
    plan.packages
        .iter()
        .flat_map(|package| {
            package
                .platforms
                .iter()
                .filter(|cell| matches!(cell.decision, MatrixCell::Artifact { .. }))
                .map(|cell| {
                    (
                        ChangedPackageCell {
                            package: package.name.clone(),
                            platform: cell.platform,
                        },
                        planned_paths(&cell.decision),
                    )
                })
        })
        .collect()
}

fn planned_paths(
    decision: &MatrixCell<crate::plan::PlannedArtifactSet>,
) -> Option<BTreeSet<String>> {
    match decision {
        MatrixCell::Artifact { artifact } => artifact
            .artifacts
            .iter()
            .map(|planned| planned.store_path.clone())
            .collect(),
        MatrixCell::Blocked { .. } | MatrixCell::NotApplicable { .. } => None,
    }
}

fn cell_identity(
    ids: &[String],
    digests: &BTreeMap<&str, Sha256Digest>,
) -> BTreeSet<(String, Option<Sha256Digest>)> {
    ids.iter()
        .map(|id| (id.clone(), digests.get(id.as_str()).copied()))
        .collect()
}

fn image_identity(
    manifest: &ReleaseManifestV1,
    digests: &BTreeMap<&str, Sha256Digest>,
) -> BTreeSet<(String, Option<Sha256Digest>)> {
    manifest
        .images
        .iter()
        .flat_map(|image| image.platforms.iter())
        .filter_map(|cell| match &cell.decision {
            MatrixCell::Artifact { artifact } => Some(&artifact.artifact_ids),
            MatrixCell::Blocked { .. } | MatrixCell::NotApplicable { .. } => None,
        })
        .flatten()
        .map(|id| (id.clone(), digests.get(id.as_str()).copied()))
        .collect()
}

fn container_identity(
    manifest: &ReleaseManifestV1,
    digests: &BTreeMap<&str, Sha256Digest>,
) -> BTreeSet<(String, Option<Sha256Digest>)> {
    manifest
        .artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.kind,
                ArtifactKind::OciIndex | ArtifactKind::OciManifest | ArtifactKind::OciBlob
            )
        })
        .map(|artifact| {
            (
                artifact.id.clone(),
                digests.get(artifact.id.as_str()).copied(),
            )
        })
        .collect()
}

fn sorted_cells(cells: impl Iterator<Item = ChangedPackageCell>) -> Vec<ChangedPackageCell> {
    let mut cells: Vec<_> = cells.collect();
    cells.sort();
    cells.dedup();
    cells
}
