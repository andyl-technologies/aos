//! Corrupts one real leased directory-CAS inode after native source admission.
//!
//! Normal reads always use the original quota-bound backend. The adversary
//! resolves only the actual requested page through its authenticated root,
//! retains the writable descriptor and original byte, and restores it only
//! after native process and source-worker cleanup.

use super::*;
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{ContentId, ImmutableBlobBackend, StoreError};
use crucible_cas::owned_decode::DecodeBudget;
use std::error::Error;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

pub(super) struct StoredCorruption {
    backend: Arc<dyn ImmutableBlobBackend>,
    directory: PathBuf,
    damage: Mutex<Option<DamagedObject>>,
}

struct DamagedObject {
    file: File,
    identity: ContentId,
    offset: u64,
    original: u8,
    _credit: crucible_cas::owned_decode::ResourceLoan,
}

impl StoredCorruption {
    pub(super) fn new(backend: Arc<dyn ImmutableBlobBackend>, directory: PathBuf) -> Self {
        Self {
            backend,
            directory,
            damage: Mutex::new(None),
        }
    }

    pub(super) fn damage_requested_page(
        &self,
        backing: &dyn QemuRamBacking,
        region_id: &str,
        page_index: u64,
        boundary: &mut dyn FnMut()
            -> Result<(), crucible_qemu::ram_source::QemuRamReadBoundaryError>,
    ) -> Result<(ContentId, usize), QemuRamSourceError> {
        boundary()?;
        let authority = self
            .backend
            .metadata_resources()
            .map_err(retain_store_error)?;
        let budget = DecodeBudget::for_store(Arc::clone(&authority)).map_err(retain_failure)?;
        let _scope = budget.enter();
        let root = ContentId::parse(backing.root_object_id()).map_err(retain_store_error)?;
        let regions = backing.root_record().topology().regions();
        let ordinal = regions
            .iter()
            .position(|region| region.id() == region_id)
            .ok_or(QemuRamSourceError::Ownership)?;
        let region = &regions[ordinal];
        let length = region
            .geometry()
            .valid_length(page_index)
            .map_err(retain_failure)?;
        let root_envelope = self.read_envelope(root, boundary)?;
        if root_envelope.schema_name() != "crucible.ram.root" {
            return Err(QemuRamSourceError::Ownership);
        }
        let mut identity = child(&root_envelope, &format!("region-{ordinal:08x}"))?;
        drop(root_envelope);
        for bit in (0..region.geometry().height()).rev() {
            let envelope = self.read_envelope(identity, boundary)?;
            if envelope.schema_name() != "crucible.ram.tree" {
                return Err(QemuRamSourceError::Ownership);
            }
            identity = child(
                &envelope,
                if (page_index >> bit) & 1 == 0 {
                    "left"
                } else {
                    "right"
                },
            )?;
        }
        let leaf = self.read_envelope(identity, boundary)?;
        let page = child(&leaf, "page")?;
        drop(leaf);
        let envelope = self.read_envelope(page, boundary)?;
        if envelope.schema_name() != "crucible.ram.page" {
            return Err(QemuRamSourceError::Ownership);
        }
        drop(envelope);

        // Credit precedes opening the actual writable descriptor; it remains
        // live until restoration and final close, including failed cleanup.
        let credit = authority
            .reserve_resources(1, corruption_ownership_bytes(&self.directory, page)?)
            .map_err(retain_store_error)?;
        let digest = page.digest();
        let shard = format!("{:02x}", digest[0]);
        let path = self
            .directory
            .join("objects")
            .join(shard)
            .join(page.encode());
        budget.check().map_err(retain_failure)?;
        let file = File::from(
            rustix::fs::open(
                &path,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| QemuRamSourceError::Io(error.into()))?,
        );
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(QemuRamSourceError::Ownership);
        }
        let offset = metadata.len() - 1;
        let mut original = [0];
        file.read_exact_at(&mut original, offset)?;
        let mut retained = self
            .damage
            .lock()
            .map_err(|_| QemuRamSourceError::Ownership)?;
        if retained.is_some() {
            return Err(QemuRamSourceError::Ownership);
        }
        *retained = Some(DamagedObject {
            file,
            identity: page,
            offset,
            original: original[0],
            _credit: credit,
        });
        let damaged = retained.as_ref().ok_or(QemuRamSourceError::Ownership)?;
        boundary()?;
        damaged
            .file
            .write_all_at(&[damaged.original ^ 1], damaged.offset)?;
        damaged.file.sync_all()?;
        boundary()?;
        budget.check().map_err(retain_failure)?;

        // The actual normal backend must now reject its own retained inode.
        let refused = self
            .backend
            .read(page, None)
            .and_then(|handle| handle.read_all(crucible_cas::ram::MAX_RAM_OBJECT_BYTES));
        if !matches!(refused, Err(StoreError::Corrupt { id }) if id == page) {
            return Err(QemuRamSourceError::Ownership);
        }
        boundary()?;
        Ok((page, usize::try_from(length).map_err(retain_failure)?))
    }

    fn read_envelope(
        &self,
        id: ContentId,
        boundary: &mut dyn FnMut()
            -> Result<(), crucible_qemu::ram_source::QemuRamReadBoundaryError>,
    ) -> Result<ContentEnvelope, QemuRamSourceError> {
        boundary()?;
        let (maximum_bytes, maximum_children) = match id.kind() {
            crucible_cas::content_store::ObjectKind::ExactManifest => {
                (crucible_cas::ram::MAX_RAM_OBJECT_BYTES, 4096)
            }
            crucible_cas::content_store::ObjectKind::RamTree => (4096, 2),
            crucible_cas::content_store::ObjectKind::RamExtent => (8192, 0),
            _ => return Err(QemuRamSourceError::Ownership),
        };
        let bytes = self
            .backend
            .read(id, None)
            .and_then(|handle| handle.read_all(maximum_bytes))
            .map_err(retain_store_error)?;
        if !id.authenticates(&bytes) {
            return Err(QemuRamSourceError::Ownership);
        }
        let envelope =
            ContentEnvelope::from_canonical_bytes_with_child_limit(&bytes, maximum_children)
                .map_err(retain_failure)?;
        boundary()?;
        Ok(envelope)
    }

    pub(super) fn restore_after_join(
        &self,
        boundary: &mut dyn FnMut()
            -> Result<(), crucible_qemu::ram_source::QemuRamReadBoundaryError>,
    ) -> Result<(), QemuRamSourceError> {
        let mut retained = self
            .damage
            .lock()
            .map_err(|_| QemuRamSourceError::Ownership)?;
        let damaged = retained.as_ref().ok_or(QemuRamSourceError::Ownership)?;
        boundary()?;
        damaged
            .file
            .write_all_at(&[damaged.original], damaged.offset)?;
        damaged.file.sync_all()?;
        boundary()?;
        let budget = DecodeBudget::for_store(
            self.backend
                .metadata_resources()
                .map_err(retain_store_error)?,
        )
        .map_err(retain_failure)?;
        let _scope = budget.enter();
        let bytes = self
            .backend
            .read(damaged.identity, None)
            .and_then(|handle| handle.read_all(crucible_cas::ram::MAX_RAM_OBJECT_BYTES))
            .map_err(retain_store_error)?;
        if !damaged.identity.authenticates(&bytes) {
            return Err(QemuRamSourceError::Ownership);
        }
        boundary()?;
        budget.check().map_err(retain_failure)?;
        *retained = None;
        Ok(())
    }
}

fn corruption_ownership_bytes(
    directory: &std::path::Path,
    id: ContentId,
) -> Result<u64, QemuRamSourceError> {
    // Four path/name buffers can coexist during open and its diagnostics;
    // doubling the actual bound allows geometric PathBuf capacity growth.
    let path_bytes = directory
        .as_os_str()
        .as_bytes()
        .len()
        .checked_add("/objects/00/".len())
        .and_then(|bytes| bytes.checked_add(id.encoded_len()))
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or(QemuRamSourceError::Ownership)?;
    let ownership_bytes = path_bytes
        .checked_add(std::mem::size_of::<DamagedObject>() + 2 * std::mem::size_of::<usize>())
        .ok_or(QemuRamSourceError::Ownership)?;
    u64::try_from(ownership_bytes).map_err(retain_failure)
}

fn child(envelope: &ContentEnvelope, role: &str) -> Result<ContentId, QemuRamSourceError> {
    envelope
        .children()
        .iter()
        .find(|child| child.role() == role)
        .map(|child| child.id())
        .ok_or(QemuRamSourceError::Ownership)
}

fn retain_store_error(source: StoreError) -> QemuRamSourceError {
    retain_failure(source)
}

fn retain_failure(source: impl Error + Send + Sync + 'static) -> QemuRamSourceError {
    QemuRamSourceError::BackingFailure {
        kind: crucible::BackendOperationalFailureKind::Unavailable,
        source: crucible::BackendOperationalCause::new(source),
    }
}

pub(super) fn corrupted_object_in_chain(error: &(dyn Error + 'static)) -> Option<ContentId> {
    let mut current = Some(error);
    for _ in 0..32 {
        let source = current?;
        if let Some(StoreError::Corrupt { id }) = source.downcast_ref::<StoreError>() {
            return Some(*id);
        }
        current = source.source();
    }
    None
}
