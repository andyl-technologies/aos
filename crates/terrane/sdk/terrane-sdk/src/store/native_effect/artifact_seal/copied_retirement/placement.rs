//! Retains actual eligible destination container descriptors without chunk reads.
//!
//! Copied containers do not acquire fabricated creation journals. These holds
//! check their actual inventory-bound detached indexes and metadata-only pack
//! descriptors under the caller's complete retained native Frame. They confer
//! no elapsed observation, ownership, lineage or deletion authority.

use super::super::{
    FencePolicy, File, MetadataStamp, NativeEffectFailure, Path, PathBuf, Worker,
    check_opened_name, open_native,
};
use crate::bucket::publication::receipts::GcPackRead;
use crate::pack::{PackId, PackIndexSnapshot};
use std::io::{self, Read};
use std::time::SystemTime;

/// Owns metadata-only inputs already observed through current eligible DATA.
///
/// This neutral copy can cross the native executor boundary without retaining a
/// borrowed catalog. It carries no creator journal, lineage or permission.
pub(super) struct PlacementInput {
    inventory: terrane_format::bucket::PackInventoryEntry,
    pack_path: PathBuf,
    metadata: std::fs::Metadata,
    index: crate::bucket::publication::receipts::RecordRead,
    snapshot: PackIndexSnapshot,
}

impl PlacementInput {
    /// Copies the exact checked metadata and detached-index observations.
    pub(super) fn observed(read: &GcPackRead) -> Self {
        Self {
            inventory: read.inventory().clone(),
            pack_path: read.pack_path().to_path_buf(),
            metadata: read.metadata().clone(),
            index: read.index().clone(),
            snapshot: read.snapshot().clone(),
        }
    }

    fn inventory(&self) -> &terrane_format::bucket::PackInventoryEntry {
        &self.inventory
    }

    fn pack_path(&self) -> &Path {
        &self.pack_path
    }

    fn metadata(&self) -> &std::fs::Metadata {
        &self.metadata
    }

    fn index(&self) -> &crate::bucket::publication::receipts::RecordRead {
        &self.index
    }

    fn snapshot(&self) -> &PackIndexSnapshot {
        &self.snapshot
    }
}

fn unavailable(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Observation {
    stamp: MetadataStamp,
    length: u64,
    modified: SystemTime,
    changed: (i64, i64),
}

impl Observation {
    #[cfg(unix)]
    fn read(metadata: &std::fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            stamp: MetadataStamp::checked(metadata)?,
            length: metadata.len(),
            modified: metadata.modified()?,
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    fn read(_metadata: &std::fs::Metadata) -> io::Result<Self> {
        Err(unavailable(
            "native copied placement requires local descriptor identity",
        ))
    }
}

struct Opened {
    file: File,
    path: PathBuf,
    observation: Observation,
    owner: u32,
}

impl Opened {
    fn open(path: PathBuf, metadata: &std::fs::Metadata, owner: u32) -> io::Result<Self> {
        let observation = Observation::read(metadata)?;
        FencePolicy::Payload { owner }.validate(observation.stamp)?;
        let opened = Self {
            file: open_native(&path, false)?,
            path,
            observation,
            owner,
        };
        opened.check()?;
        Ok(opened)
    }

    fn check(&self) -> io::Result<()> {
        check_opened_name(&self.file, &self.path, false)?;
        let descriptor = Observation::read(&self.file.metadata()?)?;
        let named = Observation::read(&std::fs::symlink_metadata(&self.path)?)?;
        FencePolicy::Payload { owner: self.owner }.validate(descriptor.stamp)?;
        FencePolicy::Payload { owner: self.owner }.validate(named.stamp)?;
        if descriptor != self.observation || named != self.observation {
            return Err(unavailable(
                "copied placement descriptor or named incarnation changed",
            ));
        }
        Ok(())
    }
}

/// Holds an actual eligible pack and its detached index without creator claims.
pub(super) struct Placement {
    pack: Opened,
    index: Opened,
}

impl Placement {
    /// Opens the actual observed pair and compares its complete detached index.
    ///
    /// # Errors
    /// Refuses another path, owner, incarnation, inventory size or detached-index
    /// body. The pack descriptor is never read and no journal is synthesized.
    pub(super) fn open(observed: &PlacementInput, root: &Path, owner: u32) -> io::Result<Self> {
        let inventory = observed.inventory();
        let id = PackId::from_random_bytes(inventory.pack_id);
        if observed.pack_path() != root.join(id.pack_key())
            || observed.index().path() != root.join(id.index_key())
        {
            return Err(unavailable(
                "copied placement names differ from actual namespace inventory",
            ));
        }
        let expected = observed
            .index()
            .bytes()
            .ok_or_else(|| unavailable("copied placement detached index observation is absent"))?;
        let metadata = observed
            .index()
            .metadata()
            .ok_or_else(|| unavailable("copied placement detached index metadata is absent"))?;
        if observed.metadata().len() != inventory.pack_size
            || metadata.len() != inventory.index_size
            || u64::try_from(expected.len()).map_err(io::Error::other)? != inventory.index_size
        {
            return Err(unavailable("copied placement inventory size changed"));
        }
        let pack = Opened::open(
            observed.pack_path().to_path_buf(),
            observed.metadata(),
            owner,
        )?;
        let mut index = Opened::open(observed.index().path().to_path_buf(), metadata, owner)?;

        // The detached index has already passed the eligible catalog's canonical
        // hash/header/offset validation. Compare the same bounded actual bytes
        // on this retained descriptor; do not inspect any data-pack body.
        let capacity = expected
            .len()
            .checked_add(1)
            .ok_or_else(|| unavailable("copied placement detached index read bound overflow"))?;
        let mut actual = Vec::with_capacity(capacity);
        (&mut index.file)
            .take(u64::try_from(capacity).map_err(io::Error::other)?)
            .read_to_end(&mut actual)?;
        if actual != expected {
            return Err(unavailable("copied placement detached index bytes changed"));
        }
        let identity = terrane_format::identity::TERRANE_V1
            .from_digest(
                terrane_format::identity::IdentityKind::Index,
                &inventory.index_hash,
            )
            .map_err(io::Error::other)?;
        terrane_format::identity::TERRANE_V1
            .verify(&identity, &actual)
            .map_err(io::Error::other)?;
        let decoded = PackIndexSnapshot::decode(&actual, observed.snapshot().generation())
            .map_err(io::Error::other)?;
        let body_end = inventory
            .pack_size
            .checked_sub(inventory.index_size)
            .and_then(|size| size.checked_add(terrane_format::pack_format::HEADER_SIZE as u64))
            .and_then(|size| size.checked_sub(terrane_format::pack_format::FOOTER_SIZE as u64))
            .ok_or_else(|| unavailable("copied placement container body bound overflow"))?;
        if decoded != *observed.snapshot()
            || decoded.header().id().as_bytes() != &inventory.pack_id
            || decoded.entries().iter().any(|entry| {
                entry
                    .offset()
                    .checked_add(u64::from(entry.body_len()))
                    .is_none_or(|end| end > body_end)
            })
        {
            return Err(unavailable(
                "copied placement detached index association differs",
            ));
        }
        let result = Self { pack, index };
        result.check()?;
        Ok(result)
    }

    /// Rechecks both retained descriptors and their actual names.
    ///
    /// # Errors
    /// Refuses physical replacement, mutation, ownership or path changes.
    pub(super) fn check(&self) -> io::Result<()> {
        self.pack.check()?;
        self.index.check()
    }

    /// Synchronizes actual retained eligible descriptors under complete refresh.
    ///
    /// # Errors
    /// Refuses changed placement, current Frame predicates or real sync failure.
    /// This observes actual durability without reading chunk bodies or granting
    /// any copied preparation or ownership acknowledgment itself.
    pub(super) fn synchronize(&self, worker: &mut Worker) -> Result<(), NativeEffectFailure> {
        worker.refresh(&[])?;
        self.check()?;
        worker.file_sync(&self.pack.file, &[])?;
        self.check()?;

        // Both file_sync calls retain complete physical pre/post refreshes.
        worker.file_sync(&self.index.file, &[])?;
        self.check()?;
        worker.refresh(&[])
    }
}
