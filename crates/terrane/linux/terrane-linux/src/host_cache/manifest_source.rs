//! Retains actual verified manifest-pack descriptors without minting a pin.
//!
//! The native owner must synchronize these files and their canonical parents,
//! persist the actual retention pin, and retain quota/cancellation custody before
//! it can create a manifest publication receipt. This read-only source cannot
//! authorize publication, adoption, serving or release of reconstruction data.

use super::{NativeHostLayout, NativeHostMetadataReader};
use rustix::fs::{Mode, OFlags, openat};
use std::{
    collections::BTreeMap,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    sync::{Arc, OnceLock},
};
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::{
    host::{
        cache::{HostDomainLocation, HostReadLimits, reconstruct_pack_index},
        publication::{PublicationClaim, PublicationRecipe},
    },
    pack::{EntryKind, PackClass, PackId, PackReader},
    repository::MetadataValidator,
    store::ByteRange,
};

/// Holds verified actual metadata-pack and detached-index read descriptors.
///
/// This source is not a durable retention receipt. Its privately opened files
/// and retained root prevent arbitrary file or boolean substitution, but the
/// native writer still has to establish actual synchronized pin ownership.
pub struct NativeManifestSource {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    claim: PublicationClaim,
    pack_id: PackId,
    pack_identity: Identity,
    range: ByteRange,
    pack: File,
    index: File,
    pack_metadata: Metadata,
    index_metadata: Metadata,
    pack_directory: File,
    shard_directory: File,
    read_observation: OnceLock<Arc<crate::publisher_local::client::EncodedReadObservation>>,
}

impl NativeManifestSource {
    /// Opens and independently verifies actual canonical metadata and index files.
    ///
    /// The metadata lookup supplies a candidate pack key and range; neither is
    /// trusted until this operation opens the actual retained-directory files,
    /// verifies every pack body, compares the exact detached index and checks
    /// the canonical manifest bytes at the selected body range.
    ///
    /// # Errors
    /// Refuses non-manifest identities, missing/corrupt/mutating files, unsafe
    /// native custody, another pack class, resource limits and schema failures.
    pub async fn open(
        reader: &NativeHostMetadataReader,
        identity: &Identity,
        limits: HostReadLimits,
    ) -> io::Result<Self> {
        if identity.kind() != IdentityKind::Manifest {
            return Err(invalid("manifest source requires a manifest identity"));
        }
        let entry = reader.get_entry(identity).await.map_err(invalid)?;
        let layout = Arc::clone(reader.layout());
        layout.recheck()?;
        let objects = layout
            .directories
            .get("objects")
            .ok_or_else(|| invalid("retained objects directory is absent"))?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let packs = openat(objects, "pack", flags, Mode::empty())?;
        let shard = openat(
            &packs,
            format!("{:02x}", entry.pack_id.as_bytes()[0]),
            flags,
            Mode::empty(),
        )?;
        let parent = rustix::fs::fstat(&shard)?;
        let class = rustix::fs::fstat(objects)?;
        if parent.st_dev != class.st_dev
            || parent.st_uid != class.st_uid
            || parent.st_gid != class.st_gid
            || parent.st_mode & 0o7777 != 0o2770
        {
            return Err(invalid(
                "metadata shard differs from shared content custody",
            ));
        }
        let shard_file = File::from(shard);
        let mut pack =
            super::owner::open_regular_at(&shard_file, &format!("{}.pack", entry.pack_id))?;
        let mut index =
            super::owner::open_regular_at(&shard_file, &format!("{}.idx", entry.pack_id))?;
        let pack_metadata = pack.metadata()?;
        let index_metadata = index.metadata()?;
        for metadata in [&pack_metadata, &index_metadata] {
            if !metadata.is_file()
                || metadata.dev() != parent.st_dev
                || metadata.uid() != parent.st_uid
                || metadata.gid() != parent.st_gid
                || metadata.mode() & 0o002 != 0
            {
                return Err(invalid("metadata source differs from native shard custody"));
            }
        }
        if layout.directory_binding("objects")?.0 != parent.st_dev {
            return Err(invalid(
                "metadata shard differs from retained domain device",
            ));
        }

        let bytes = read_bounded(&mut pack, &pack_metadata, limits)?;
        let index_bytes = read_bounded(&mut index, &index_metadata, limits)?;
        let profile = layout.layout().chunk_profile();
        let verified = reconstruct_pack_index(
            &bytes,
            entry.pack_id,
            profile,
            &MetadataValidator::new(profile.clone()),
            &BTreeMap::new(),
            limits,
        )
        .map_err(invalid)?;
        if index_bytes != verified.bytes() {
            return Err(invalid("actual detached index differs from verified pack"));
        }
        let pack_reader = PackReader::open(&bytes).map_err(invalid)?;
        if pack_reader.header().class() != PackClass::Meta {
            return Err(invalid(
                "reconstruction manifest is not in an ordinary metadata pack",
            ));
        }
        if !pack_reader.entries().iter().any(|record| {
            record.kind() == EntryKind::Manifest
                && record.hash().as_slice() == identity.digest()
                && record.offset() == entry.range.start
                && u64::from(record.body_len()) == entry.range.length
        }) {
            return Err(invalid(
                "manifest range is not its authoritative native pack entry",
            ));
        }
        let start = usize::try_from(entry.range.start).map_err(invalid)?;
        let end = start
            .checked_add(usize::try_from(entry.range.length).map_err(invalid)?)
            .ok_or_else(|| invalid("metadata body range overflow"))?;
        if bytes.get(start..end) != Some(entry.canonical.as_slice()) {
            return Err(invalid("actual metadata body differs from verified lookup"));
        }
        let descriptor =
            Descriptor::from_identity(&TERRANE_V1, identity, &entry.canonical).map_err(invalid)?;
        let claim = PublicationClaim::new(
            layout.layout().domain().to_owned(),
            PublicationRecipe::Manifest {
                object: descriptor,
                canonical_manifest: entry.canonical,
            },
            profile,
        )?;
        layout.recheck()?;
        let source = Self {
            layout,
            claim,
            pack_id: entry.pack_id,
            pack_identity: verified.pack_identity().clone(),
            range: entry.range,
            pack,
            index,
            pack_metadata,
            index_metadata,
            pack_directory: File::from(packs),
            shard_directory: shard_file,
            read_observation: OnceLock::new(),
        };
        source.recheck()?;
        Ok(source)
    }

    /// Borrows the claim verified against this actual ordinary metadata source.
    pub fn claim(&self) -> &PublicationClaim {
        &self.claim
    }

    /// Returns the existing pack key identifier, without granting durability.
    pub fn pack_id(&self) -> PackId {
        self.pack_id
    }

    /// Borrows the verified identity of the complete actual pack bytes.
    pub fn pack_identity(&self) -> &Identity {
        &self.pack_identity
    }

    /// Returns the canonical manifest's exact body range in the retained pack.
    pub fn range(&self) -> ByteRange {
        self.range
    }

    /// Rechecks retained native source incarnations without creating a pin.
    ///
    /// # Errors
    /// Returns native errors or refuses modified source metadata or replaced roots.
    pub fn recheck(&self) -> io::Result<()> {
        if let Some(observation) = self.read_observation.get() {
            observation.check_readable()?;
        }
        self.recheck_backing().inspect_err(|_| {
            if let Some(observation) = self.read_observation.get() {
                observation.reject(1);
            }
        })?;
        if let Some(observation) = self.read_observation.get() {
            observation.check_readable()?;
        }
        Ok(())
    }

    /// Shares rejection only after the physical owner binds both actual members.
    ///
    /// # Errors
    /// Refuses substitution of an already bound original publisher observation.
    pub(crate) fn bind_read_observation(
        &self,
        observation: Arc<crate::publisher_local::client::EncodedReadObservation>,
    ) -> io::Result<()> {
        if self.read_observation.get().is_none() {
            // Only the physical executor binds this once; public readers cannot
            // construct observations or supply native registration authority.
            let _ = self.read_observation.set(Arc::clone(&observation));
        }
        if !self
            .read_observation
            .get()
            .is_some_and(|actual| Arc::ptr_eq(actual, &observation))
        {
            return Err(invalid("metadata source changed original read observation"));
        }
        self.recheck()
    }

    fn recheck_backing(&self) -> io::Result<()> {
        self.layout.recheck()?;
        if !same_file(&self.pack_metadata, &self.pack.metadata()?)
            || !same_file(&self.index_metadata, &self.index.metadata()?)
        {
            return Err(invalid("retained manifest source changed"));
        }
        let objects = self
            .layout
            .directories
            .get("objects")
            .ok_or_else(|| invalid("retained objects directory is absent"))?;
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let packs = openat(objects, "pack", flags, Mode::empty())?;
        let shard = openat(
            &packs,
            format!("{:02x}", self.pack_id.as_bytes()[0]),
            flags,
            Mode::empty(),
        )?;
        for (retained, current) in [
            (&self.pack_directory, &packs),
            (&self.shard_directory, &shard),
        ] {
            let expected = retained.metadata()?;
            let actual = rustix::fs::fstat(current)?;
            if expected.dev() != actual.st_dev || expected.ino() != actual.st_ino {
                return Err(invalid("canonical metadata parent directory was replaced"));
            }
        }
        for (name, expected) in [
            (format!("{}.pack", self.pack_id), &self.pack_metadata),
            (format!("{}.idx", self.pack_id), &self.index_metadata),
        ] {
            let current = File::from(openat(
                &shard,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            if !same_file(expected, &current.metadata()?) {
                return Err(invalid("canonical manifest source pathname was replaced"));
            }
        }
        Ok(())
    }

    /// Synchronizes actual metadata files and their fixed canonical parents.
    ///
    /// The caller must retain native quota and future-capacity custody. This
    /// operation alone creates neither a durable policy pin nor a receipt.
    ///
    /// # Errors
    /// Returns any synchronization error or refuses changed sources or parents.
    pub(super) fn synchronize(&self) -> io::Result<()> {
        self.recheck()?;
        self.pack.sync_all()?;
        self.index.sync_all()?;
        self.shard_directory.sync_all()?;
        self.pack_directory.sync_all()?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let objects = self
            .layout
            .directories
            .get("objects")
            .ok_or_else(|| invalid("retained objects directory is absent"))?;
        File::from(openat(objects, ".", flags, Mode::empty())?).sync_all()?;
        File::from(openat(&self.layout.root, ".", flags, Mode::empty())?).sync_all()?;
        self.recheck()
    }

    /// Borrows the actual read-only pack and index while retaining source custody.
    pub(crate) fn files(&self) -> (&File, &File) {
        (&self.pack, &self.index)
    }

    /// Borrows the actual domain root and provisioning guard behind this source.
    pub(super) fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        &self.layout
    }
}

fn read_bounded(file: &mut File, before: &Metadata, limits: HostReadLimits) -> io::Result<Vec<u8>> {
    if before.len() > limits.max_allocation_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "metadata source exceeds operator read budget",
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref().take(before.len()).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len() || !same_file(before, &file.metadata()?) {
        return Err(invalid("metadata source changed during bounded read"));
    }
    Ok(bytes)
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
