//! Durable private archive import through campaign application composition.
//!
//! Compact archive inventory and authenticated RAM descendants are copied under
//! real retention fences. An archive-only ref protects the completed closure
//! before the private directory may be published by its caller.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use crucible_campaign::{CampaignArchiveInspection, CampaignRepository, CampaignRepositoryError};
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement, ImmutableBlobBackend,
    MutableRefBackend, ObjectKind, RefCasOutcome, RefName, StoreError,
};
use crucible_cas::ram::{LeasedRamRoot, RamRetention, RamStore, RamStoreError, RamStoreLimits};
use thiserror::Error;

/// Keeps imported RAM roots retained until the private archive is consumed.
pub struct CampaignArchiveImportOwnership {
    _roots: Vec<LeasedRamRoot>,
}

/// Reports failed private archive admission, copying, or durable ownership.
#[derive(Debug, Error)]
pub enum CampaignArchiveImportError {
    /// Directory preparation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A storage operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// An authenticated RAM operation failed.
    #[error(transparent)]
    Ram(#[from] RamStoreError),
    /// Whole-world archive verification failed.
    #[error(transparent)]
    Campaign(#[from] CampaignRepositoryError),
    /// The completed copy violated an archive invariant.
    #[error("private archive import is invalid: {0}")]
    Invalid(&'static str),
}

fn invalid(reason: &'static str) -> CampaignArchiveImportError {
    CampaignArchiveImportError::Invalid(reason)
}

/// Copies a private archive's complete authenticated closure and installs ownership.
///
/// The destination object directory must be new. The returned owner retains RAM
/// sources while the caller prepares its private application state; the durable
/// archive ref remains after that owner is dropped.
///
/// # Errors
///
/// Returns an error for canceled or bounded operations, unauthenticated source
/// data, failed durable writes, an incomplete destination closure, or conflicting
/// destination ownership. Failure never grants execution authority.
pub fn import_campaign_archive_objects(
    source: &CampaignRepository,
    destination: &Path,
    destination_refs: Arc<DirectoryRefBackend>,
    inspection: &CampaignArchiveInspection,
    boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
) -> Result<CampaignArchiveImportOwnership, CampaignArchiveImportError> {
    std::fs::create_dir(destination)?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))?;
    let source_blobs = source.blob_backend();
    let destination = Arc::new(DirectoryBlobBackend::new(
        "finding-bundle-branch-private",
        destination,
    ));
    // Retention precedes discovery and publication, and returned root leases
    // keep the private namespace protected until its archive ref is installed.
    let ram_retentions = if inspection.manifest().ram_roots().is_empty() {
        None
    } else {
        Some((
            source.ram_retention_authority().acquire()?,
            crucible_cas::ram::FencedRamRetention::acquire(destination_refs.clone())?,
        ))
    };
    let mut ram_bindings = BTreeMap::new();
    for id in inspection.retained_objects() {
        boundary()?;
        let blob = source_blobs.read(*id, None)?;
        if id.kind() == ObjectKind::ExactManifest && id.schema_version() == 6 {
            let bytes = blob.read_all(64 * 1024 * 1024)?;
            if !id.authenticates(&bytes) {
                return Err(invalid("private archive world binding is corrupt"));
            }
            let world = ContentEnvelope::from_canonical_bytes(&bytes)
                .map_err(|_| invalid("private archive world envelope is invalid"))?;
            for child in world.children() {
                if child.role().starts_with("ram-root-") {
                    if !inspection.manifest().ram_roots().contains(&child.id()) {
                        return Err(invalid(
                            "private archive world names an unselected RAM root",
                        ));
                    }
                    ram_bindings.insert(child.id(), *id);
                }
            }
        }
        // RAM roots are published by their own descendant-first operation.
        if inspection.manifest().ram_roots().contains(id) {
            continue;
        }
        let receipt = destination.put_if_absent(*id, &blob)?;
        if receipt.id != *id || !receipt.is_durable() {
            return Err(invalid("private archive object lacks a durable placement"));
        }
    }
    let Some((source_retention, destination_retention)) = &ram_retentions else {
        return finish_import(
            destination,
            destination_refs,
            inspection,
            Vec::new(),
            boundary,
        );
    };
    let durability = DurabilityRequirement::new(1, false)?;
    let source_ram = RamStore::new(source_blobs, durability, RamStoreLimits::default())?;
    let destination_ram =
        RamStore::new(destination.clone(), durability, RamStoreLimits::default())?;
    let mut operation = blake3::Hasher::new();
    operation.update(b"crucible.finding.private-branch-archive-copy.v1\0");
    operation.update(inspection.manifest_id().content_id().encode().as_bytes());
    let operation = *operation.finalize().as_bytes();
    let mut ownership = Vec::with_capacity(inspection.manifest().ram_roots().len());
    for id in inspection.manifest().ram_roots() {
        let world = *ram_bindings
            .get(id)
            .ok_or_else(|| invalid("private archive RAM root has no retained world owner"))?;
        let lease = source_retention.retain_root(*id)?;
        let root = source_ram.open(lease, boundary)?;
        let stored = source_ram.transfer_archive_to(
            &root,
            world,
            &destination_ram,
            "private-finding-branch",
            operation,
            destination_retention,
            boundary,
        )?;
        ownership.push(stored.root().clone());
    }
    finish_import(
        destination,
        destination_refs,
        inspection,
        ownership,
        boundary,
    )
}

fn finish_import(
    destination: Arc<DirectoryBlobBackend>,
    destination_refs: Arc<DirectoryRefBackend>,
    inspection: &CampaignArchiveInspection,
    roots: Vec<LeasedRamRoot>,
    boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
) -> Result<CampaignArchiveImportOwnership, CampaignArchiveImportError> {
    let imported = CampaignRepository::new(destination, destination_refs.clone());
    let actual =
        imported.inspect_campaign_archive_with_boundary(inspection.manifest_id(), boundary)?;
    if &actual != inspection {
        return Err(invalid(
            "destination archive differs from authenticated source",
        ));
    }

    boundary()?;
    let name = RefName::new("archives/imported-finding-archive")?;
    match destination_refs.compare_exchange(&name, None, inspection.manifest_id().content_id())? {
        RefCasOutcome::Advanced { next } if next == inspection.manifest_id().content_id() => {}
        _ => return Err(invalid("archive ownership was not installed")),
    }
    Ok(CampaignArchiveImportOwnership { _roots: roots })
}
