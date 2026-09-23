//! Offline production replay capture access for imported campaign archives.
//!
//! An executable archive authenticates the selected finding, candidate bundle,
//! and replay capture closure. This module reuses the live capture decoder and
//! keeps the imported store read-only while preparing a fresh private replay.

use crucible::ReproductionArtifact;
use crucible_campaign::{
    CampaignArchiveManifestId, CampaignFindingTriageReplayRole, CampaignRepository,
    CampaignRepositoryError, FindingId,
};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crucible::{ContentHash, VmArchitecture};
use crucible_qemu::{QemuLaunchArtifactIdentity, QemuLaunchArtifactIdentityError};

use crate::finding_production_replay::{
    FindingProductionReplayAsset, FindingProductionReplayCapture,
    FindingProductionReplayCaptureError, FindingProductionReplayCaptureLimits,
    FindingProductionReplayDeployment, FindingProductionReplayRootImageFormat,
};
use crate::finding_replay_capture_store::{
    FindingReplayCaptureStore, FindingReplayCaptureStoreError, LoadedFindingReplayCapture,
};

/// Loads one fully authenticated production capture from an imported archive.
///
/// The archive must contain a complete campaign snapshot with retained exact
/// pins. The capture remains bound to the selected candidate reproduction and
/// finding signature; an incomplete role cannot be treated as a replay recipe.
///
/// # Errors
///
/// Returns [`CampaignFindingHandoffError`] when archive membership, candidate
/// evidence, capture bytes, model reproduction, or durable bindings disagree.
pub fn load_archived_finding_production_capture(
    repository: &CampaignRepository,
    archive: CampaignArchiveManifestId,
    finding_id: FindingId,
    role: CampaignFindingTriageReplayRole,
) -> Result<FindingProductionReplayCapture, CampaignFindingHandoffError> {
    let finding = repository.inspect_archived_exact_finding(archive, finding_id)?;
    let candidate_id = finding
        .latest_candidate_bundle()
        .ok_or(CampaignFindingHandoffError::MissingCandidateBundle)?;
    let candidate = repository.load_finding_candidate_bundle(candidate_id)?;
    let references = candidate
        .replay_captures()
        .ok_or(CampaignFindingHandoffError::MissingCaptureSet)?;
    let captures = FindingReplayCaptureStore::load_set_from_repository(repository, references)?;

    let (index, reproduction_id) = match role {
        CampaignFindingTriageReplayRole::MinimizationOriginal => (0, candidate.reproduction()),
        CampaignFindingTriageReplayRole::MinimizationSelected => (1, candidate.minimized()),
        CampaignFindingTriageReplayRole::VerificationOriginal => (2, candidate.reproduction()),
        CampaignFindingTriageReplayRole::VerificationSelected => (3, candidate.minimized()),
    };
    let selected = captures
        .into_iter()
        .nth(index)
        .ok_or(CampaignFindingHandoffError::MissingCaptureSet)?;
    let bytes = match selected {
        LoadedFindingReplayCapture::Complete { bytes, .. } => bytes,
        LoadedFindingReplayCapture::Incomplete(reason) => {
            return Err(CampaignFindingHandoffError::IncompleteCapture { reason });
        }
    };

    let reproduction = repository.load_reproduction_artifact(reproduction_id)?;
    let model = ReproductionArtifact::from_compact_binary(reproduction.payload())?;
    let limits = FindingProductionReplayCaptureLimits::for_reproduction(&model);
    let capture = FindingProductionReplayCapture::from_canonical_bytes(&bytes, limits)?;
    capture.validate_binding(reproduction_id, finding.signature())?;
    if capture.model_reproduction() != reproduction.payload() {
        return Err(CampaignFindingHandoffError::ModelReproductionMismatch);
    }
    Ok(capture)
}

/// Private guest paths for one architecture of a retained production replay.
#[derive(Debug)]
pub struct MaterializedFindingReplayGuest {
    architecture: VmArchitecture,
    kernel: PathBuf,
    root_image: PathBuf,
    kernel_cmdline_prefix: Option<String>,
}

impl MaterializedFindingReplayGuest {
    /// Returns the architecture selected by the captured scenario.
    #[must_use]
    pub const fn architecture(&self) -> VmArchitecture {
        self.architecture
    }

    /// Returns the private kernel path.
    #[must_use]
    pub fn kernel(&self) -> &Path {
        &self.kernel
    }

    /// Returns the private root-image path.
    #[must_use]
    pub fn root_image(&self) -> &Path {
        &self.root_image
    }

    /// Returns the captured kernel command-line prefix, when present.
    #[must_use]
    pub fn kernel_cmdline_prefix(&self) -> Option<&str> {
        self.kernel_cmdline_prefix.as_deref()
    }
}

/// Owned private files needed by a standalone production replay.
///
/// The temporary directory and every file disappear when this owner drops.
#[derive(Debug)]
pub struct MaterializedFindingReplayGuestAssets {
    directory: tempfile::TempDir,
    guest_assets: Vec<MaterializedFindingReplayGuest>,
    initrd: Option<PathBuf>,
    root_image_format: FindingProductionReplayRootImageFormat,
}

impl MaterializedFindingReplayGuestAssets {
    /// Returns the private directory that owns all materialized files.
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }

    /// Returns the captured guest kernel and root paths by architecture.
    #[must_use]
    pub fn guest_assets(&self) -> &[MaterializedFindingReplayGuest] {
        &self.guest_assets
    }

    /// Returns the shared captured initrd path, when configured.
    #[must_use]
    pub fn initrd(&self) -> Option<&Path> {
        self.initrd.as_deref()
    }

    /// Returns the captured root-image format.
    #[must_use]
    pub const fn root_image_format(&self) -> FindingProductionReplayRootImageFormat {
        self.root_image_format
    }
}

/// Materializes embedded guest assets under a new private temporary directory.
///
/// The installed QEMU/plugin pair must match the capture's marker-derived
/// runtime identity. Equal content hashes share one file; every file is
/// rehashed before it is written and created with owner-only permissions.
///
/// # Errors
///
/// Returns [`CampaignFindingHandoffError`] when the installed runtime differs,
/// a retained asset disagrees with its identity, or private file creation fails.
pub fn materialize_finding_replay_guest_assets(
    deployment: &FindingProductionReplayDeployment,
    qemu: &Path,
    plugin: &Path,
    parent: &Path,
) -> Result<MaterializedFindingReplayGuestAssets, CampaignFindingHandoffError> {
    let installed = QemuLaunchArtifactIdentity::authenticate(qemu, plugin)?;
    let required = deployment.runtime();
    if installed.qemu_build_id() != required.qemu_build_id()
        || installed.qemu_atomic_patch_hash() != required.qemu_atomic_patch_hash()
        || installed.plugin_abi() != required.plugin_abi()
        || installed.shmem_abi_version() != required.shmem_abi_version()
    {
        return Err(CampaignFindingHandoffError::RuntimeIdentityMismatch);
    }

    let directory = tempfile::Builder::new()
        .prefix("crucible-finding-replay-")
        .tempdir_in(parent)?;
    let mut paths = BTreeMap::new();
    let guest_assets = deployment
        .guest_assets()
        .iter()
        .map(|asset| {
            Ok(MaterializedFindingReplayGuest {
                architecture: asset.architecture(),
                kernel: materialize_asset(directory.path(), asset.kernel(), &mut paths)?,
                root_image: materialize_asset(directory.path(), asset.root_image(), &mut paths)?,
                kernel_cmdline_prefix: asset.kernel_cmdline_prefix().map(ToOwned::to_owned),
            })
        })
        .collect::<Result<Vec<_>, CampaignFindingHandoffError>>()?;
    let initrd = deployment
        .initrd()
        .map(|asset| materialize_asset(directory.path(), asset, &mut paths))
        .transpose()?;

    Ok(MaterializedFindingReplayGuestAssets {
        directory,
        guest_assets,
        initrd,
        root_image_format: deployment.root_image_format(),
    })
}

fn materialize_asset(
    directory: &Path,
    asset: &FindingProductionReplayAsset,
    paths: &mut BTreeMap<ContentHash, PathBuf>,
) -> Result<PathBuf, CampaignFindingHandoffError> {
    let identity = asset.identity();
    if ContentHash::from_bytes(asset.bytes()) != identity {
        return Err(CampaignFindingHandoffError::GuestAssetHashMismatch);
    }
    if let Some(path) = paths.get(&identity) {
        return Ok(path.clone());
    }

    let path = directory.join(identity.to_hex());
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(asset.bytes())?;
    file.sync_all()?;
    paths.insert(identity, path.clone());
    Ok(path)
}

/// Failure to authenticate or reconstruct one imported finding capture.
#[derive(Debug, Error)]
pub enum CampaignFindingHandoffError {
    /// The selected finding has no retained candidate bundle.
    #[error("archived finding has no candidate bundle")]
    MissingCandidateBundle,
    /// The candidate bundle has no portable production capture outcomes.
    #[error("archived finding candidate has no production capture set")]
    MissingCaptureSet,
    /// The selected capture role was durably marked incomplete.
    #[error("archived finding capture role is incomplete: {reason:?}")]
    IncompleteCapture {
        /// Stable retained reason for the incomplete role.
        reason: crucible_campaign::FindingReplayCaptureIncomplete,
    },
    /// The embedded model reproduction differs from the retained record.
    #[error("archived production capture model reproduction differs from candidate")]
    ModelReproductionMismatch,
    /// The installed QEMU/plugin pair differs from the capture requirement.
    #[error("installed QEMU/plugin identity differs from archived replay")]
    RuntimeIdentityMismatch,
    /// An embedded guest asset differs from its committed content identity.
    #[error("archived guest asset content hash mismatch")]
    GuestAssetHashMismatch,
    /// The installed QEMU/plugin marker pair failed authentication.
    #[error(transparent)]
    RuntimeAuthentication(#[from] QemuLaunchArtifactIdentityError),
    /// A private materialized guest file could not be created or persisted.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An archive, finding, candidate, or reproduction object failed validation.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// A retained capture manifest or chunk failed validation.
    #[error(transparent)]
    CaptureStore(#[from] FindingReplayCaptureStoreError),
    /// The model reproduction payload was malformed.
    #[error(transparent)]
    Model(#[from] crucible::EngineError),
    /// The decoded production capture failed validation.
    #[error(transparent)]
    ProductionCapture(#[from] FindingProductionReplayCaptureError),
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixture setup and exact filesystem assertions.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn embedded_guest_asset_materializes_once_with_private_permissions() {
        let directory = tempfile::tempdir().expect("private materialization directory");
        let asset = FindingProductionReplayAsset::from_bytes(b"guest kernel".to_vec());
        let mut paths = BTreeMap::new();

        let first = materialize_asset(directory.path(), &asset, &mut paths)
            .expect("materialize authenticated asset");
        let second = materialize_asset(directory.path(), &asset, &mut paths)
            .expect("deduplicate authenticated asset");

        assert_eq!(first, second);
        assert_eq!(paths.len(), 1);
        assert_eq!(
            std::fs::read(&first).expect("read materialized asset"),
            asset.bytes()
        );
        assert_eq!(
            std::fs::metadata(&first)
                .expect("materialized asset metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
