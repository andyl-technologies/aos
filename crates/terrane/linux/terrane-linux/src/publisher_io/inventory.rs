//! Resolves bounded recovery candidates without minting content or service proof.
//!
//! Sealed manifest descriptors come from verified retained metadata. Inline
//! candidates require genuine kernel sealing and exact chunk identity. Encoded
//! chunks retain only bounded frame-declared sizes until independent HOST-14
//! verification. Pages retain one owner-issued snapshot, never caller offsets.
//! Unhandled private staging or publication-state remnants fail the whole scan.
//! Existing bindings require exhaustive independent native reconciliation.
//! Private descendants must retain the actual layout-root project assignment,
//! with inheritance enabled on directories. These read-only comparisons grant
//! no quota or recovery-completion receipt: configured runtime separately binds
//! the retained root to authenticated finite quotas before physical readiness.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use rustix::fs::{self, Mode, OFlags};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_format::pack_format::{HEADER_SIZE, Header};
use terrane_sdk::host::cache::{
    HostDomainLocation, HostReadLimits, inspect_standalone_length, maximum_encoded_chunk_bytes,
};
use terrane_sdk::host::publication::{PublicationClaim, PublicationRecipe};
use terrane_sdk::store::{LocalFs, TokioLocalFs};

use super::{NativeBodyKey, NativeCommandResult, NativePublisherConfig};
use crate::host_cache::{NativeHostLayout, NativeHostMetadataReader, NativeManifestSource};

#[path = "inventory_state.rs"]
mod state;

#[path = "inventory_leases.rs"]
mod lease_records;

#[path = "inventory_startup.rs"]
mod startup;

#[path = "inventory_pending_manifest.rs"]
mod pending_manifest;

/// Retains actual generated temporary inodes until startup cleanup completes.
pub(super) struct RetainedScratch {
    directory: File,
    files: Vec<(String, File)>,
}

const MAX_CANDIDATES: usize = 4096;
const PAGE_SIZE: usize = 64;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Custody {
    Publisher,
    Content,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InodeKind {
    File,
    Directory,
}

struct Snapshot {
    keys: Vec<NativeBodyKey>,
    offset: usize,
    cursor: Vec<u8>,
}

// No claim is reconstructed from private publication-state bytes. Manifest
// sources retain their verified canonical or pending pair through the binding
// decision, without claiming a durable cache pin or restoration authority.
enum SealedClaim {
    Inline(PublicationClaim),
    Manifest(Box<NativeManifestSource>),
    PendingManifest(Box<pending_manifest::PendingManifest>),
}

impl SealedClaim {
    fn claim(&self) -> &PublicationClaim {
        match self {
            Self::Inline(claim) => claim,
            Self::Manifest(source) => source.claim(),
            Self::PendingManifest(source) => source.claim(),
        }
    }

    fn key(&self) -> NativeBodyKey {
        NativeBodyKey::Sealed {
            descriptor: self.claim().descriptor().clone(),
        }
    }

    fn recheck(&self, inventory: &NativeInventory) -> io::Result<()> {
        if let Self::PendingManifest(source) = self {
            source.recheck(inventory)?;
        }
        if let Self::Manifest(source) = self {
            source.recheck()?;
            for file in [source.files().0, source.files().1] {
                inventory.check(file, Custody::Content, InodeKind::File)?;
            }
            source.recheck()?;
        }
        Ok(())
    }
}

pub(super) struct NativeInventory {
    root: File,
    location: HostDomainLocation,
    content_uid: u32,
    content_gid: u32,
    snapshot: Option<Snapshot>,
}

impl RetainedScratch {
    /// Confirms actual cleanup and parent durability before startup succeeds.
    ///
    /// # Errors
    /// Rejects surviving scratch, changed namespaces or synchronization failure.
    pub(super) fn verify_removed(&self) -> io::Result<()> {
        startup::verify_removed(self)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn source(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn open(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    // Classify the retained inode without opening devices or blocking on FIFOs.
    // Only the verified regular file/directory is reopened for actual reads.
    let retained = File::from(fs::openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let expected = retained.metadata()?;
    if (directory && !expected.is_dir()) || (!directory && !expected.is_file()) {
        return Err(invalid("unexpected inventory inode type"));
    }
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    // This procfs link names our retained descriptor, never a caller path.
    let file = File::from(fs::open(
        format!("/proc/self/fd/{}", retained.as_raw_fd()),
        flags,
        Mode::empty(),
    )?);
    let observed = file.metadata()?;
    if (observed.dev(), observed.ino()) != (expected.dev(), expected.ino()) {
        return Err(invalid("inventory inode changed during retained reopen"));
    }
    Ok(file)
}

fn charge(budget: &mut usize) -> io::Result<()> {
    *budget = budget
        .checked_sub(1)
        .ok_or_else(|| invalid("inventory physical entry budget exceeded"))?;
    Ok(())
}

fn names(directory: &File, remaining: usize) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::Dir::read_from(directory)? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= remaining {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "inventory namespace budget exceeded",
            ));
        }
        names.push(std::str::from_utf8(bytes).map_err(source)?.to_owned());
    }
    names.sort();
    Ok(names)
}

fn require_empty(directory: &File, budget: usize, message: &'static str) -> io::Result<()> {
    if !names(directory, budget)?.is_empty() {
        return Err(invalid(message));
    }
    Ok(())
}

fn digest(name: &str, size: usize) -> io::Result<Vec<u8>> {
    if name.len() != size * 2
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("unexpected inventory key name"));
    }
    let (pairs, _) = name.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            let nibble = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            Ok((nibble(pair[0]) << 4) | nibble(pair[1]))
        })
        .collect()
}

fn bytes(file: &mut File, bound: usize) -> io::Result<Vec<u8>> {
    if !file.metadata()?.is_file() || file.metadata()?.len() > bound as u64 {
        return Err(invalid(
            "inventory body exceeds its native type or allocation bound",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(invalid("inventory body grew beyond its allocation bound"));
    }
    Ok(bytes)
}

impl NativeInventory {
    pub(super) fn new(config: &NativePublisherConfig, root: &File) -> io::Result<Self> {
        Ok(Self {
            root: root.try_clone()?,
            location: HostDomainLocation::new(
                config.layout_root.clone(),
                config.domain.clone(),
                config.profile.clone(),
            )
            .map_err(source)?,
            content_uid: config.content_uid,
            content_gid: config.content_gid,
            snapshot: None,
        })
    }

    /// Retains validated generated scratch through actual startup cleanup.
    ///
    /// # Errors
    /// Rejects malformed names, unsafe physical state or exhausted bounds.
    pub(super) fn startup_scratch(&self) -> io::Result<RetainedScratch> {
        startup::capture(self)
    }

    pub(super) fn reset(&mut self) {
        self.snapshot = None;
    }

    pub(super) async fn page(
        &mut self,
        cursor: Option<Vec<u8>>,
    ) -> io::Result<NativeCommandResult> {
        match cursor {
            None => {
                // A fresh scan invalidates any previous owner continuation.
                self.snapshot = None;
                let keys = self.scan().await?;
                self.snapshot = Some(Snapshot {
                    keys,
                    offset: 0,
                    cursor: Vec::new(),
                });
            }
            Some(cursor)
                if self.snapshot.as_ref().is_some_and(|snapshot| {
                    !snapshot.cursor.is_empty() && snapshot.cursor == cursor
                }) => {}
            Some(_) => return Err(invalid("unknown or expired inventory continuation")),
        }
        let snapshot = self
            .snapshot
            .as_mut()
            .ok_or_else(|| io::Error::other("inventory snapshot unavailable"))?;
        let end = snapshot
            .offset
            .saturating_add(PAGE_SIZE)
            .min(snapshot.keys.len());
        let keys = snapshot.keys[snapshot.offset..end].to_vec();
        let next_cursor = if end < snapshot.keys.len() {
            let cursor = TokioLocalFs.random_bytes(32).await?;
            // Commit progression only after the fallible native token effect.
            snapshot.offset = end;
            snapshot.cursor = cursor.clone();
            Some(cursor)
        } else {
            self.snapshot = None;
            None
        };
        Ok(NativeCommandResult::Inventory { keys, next_cursor })
    }

    fn check_project(&self, file: &File, kind: InodeKind) -> io::Result<()> {
        // The retained root comes from native preparation, not request fields.
        // Configured startup independently authenticates its finite quota. The
        // installed confinement prevents future setter changes but cannot make
        // preexisting foreign-project descendants safe merely by observing it.
        let root = crate::host_quota::NativeProject::inspect(&self.root)?;
        let actual = crate::host_quota::NativeProject::inspect(file)?;
        if !root.inherit
            || actual.device != root.device
            || actual.project_id != root.project_id
            || (kind == InodeKind::Directory && !actual.inherit)
        {
            return Err(invalid("inventory inode project or inheritance changed"));
        }
        Ok(())
    }

    fn check(&self, file: &File, custody: Custody, kind: InodeKind) -> io::Result<()> {
        let metadata = file.metadata()?;
        let encoded = custody == Custody::Content;
        let directory = kind == InodeKind::Directory;
        if metadata.dev() != self.root.metadata()?.dev()
            || metadata.is_dir() != directory
            || (!directory && !metadata.is_file())
            || metadata.uid()
                != if encoded {
                    self.content_uid
                } else {
                    rustix::process::geteuid().as_raw()
                }
            || (encoded && metadata.gid() != self.content_gid)
            || metadata.mode() & if encoded { 0o002 } else { 0o022 } != 0
        {
            return Err(invalid("inventory inode custody changed"));
        }
        self.check_project(file, kind)
    }

    // Candidate keys grant no content authority. A missing seal, wrong length or
    // permissive file mode is decided by funded adoption, which can quarantine
    // the actual inode. Directory, state-record and adopted-body checks stay strict.
    fn check_sealed_candidate(&self, file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.dev() != self.root.metadata()?.dev()
        {
            return Err(invalid("sealed candidate inode custody changed"));
        }
        self.check_project(file, InodeKind::File)
    }

    async fn sealed(&self, name: &str, file: &mut File) -> io::Result<SealedClaim> {
        self.check_sealed_candidate(file)?;
        let claimed_digest = digest(name, 32)?;
        // Actual Chunk identity verification proves the inline kind; length by
        // itself never establishes the kind of a manifest-named sealed inode.
        if file.metadata()?.len() <= self.location.chunk_profile().minimum() as u64 {
            let plaintext = bytes(file, self.location.chunk_profile().minimum())?;
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &claimed_digest)
                .map_err(source)?;
            if let Ok(descriptor) = Descriptor::from_identity(&TERRANE_V1, &identity, &plaintext) {
                let claim = PublicationClaim::new(
                    self.location.domain().to_owned(),
                    PublicationRecipe::Inline {
                        chunk: descriptor.clone(),
                    },
                    self.location.chunk_profile(),
                )?;
                return Ok(SealedClaim::Inline(claim));
            }
        }
        let layout = Arc::new(NativeHostLayout::inspect(self.location.clone())?);
        let expected = self.root.metadata()?;
        if layout.directory_binding("layout-root")? != (expected.dev(), expected.ino()) {
            return Err(invalid("inventory metadata root incarnation changed"));
        }
        let reader = NativeHostMetadataReader::open(layout, HostReadLimits::default())
            .await
            .map_err(source)?;
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Manifest, &claimed_digest)
            .map_err(source)?;
        // Only canonical absence permits an inventory-only pending source.
        // Corrupt canonical metadata stays an error; no private state or sealed
        // plaintext supplies a manifest descriptor during this namespace scan.
        match reader.get_entry(&identity).await {
            Ok(_) => {}
            Err(error) if matches!(error.kind(), terrane_sdk::store::StoreErrorKind::Absent(_)) => {
                return pending_manifest::find(self, &identity)
                    .map(|source| SealedClaim::PendingManifest(Box::new(source)));
            }
            Err(error) => return Err(source(error)),
        }
        let manifest =
            NativeManifestSource::open(&reader, &identity, HostReadLimits::default()).await?;
        // This read-only scan has not changed publication state. Keep the full
        // verified source behind one allocation before any binding decision,
        // retaining its original descriptors and provisioning guard together.
        let verified = SealedClaim::Manifest(Box::new(manifest));
        verified.recheck(self)?;
        Ok(verified)
    }

    fn chunk(&self, name: &str, codec: u8, file: &mut File) -> io::Result<NativeBodyKey> {
        self.check(file, Custody::Content, InodeKind::File)?;
        let digest = digest(name, 32)?;
        let encoded = bytes(
            file,
            maximum_encoded_chunk_bytes(self.location.chunk_profile()).map_err(source)?,
        )?;
        if encoded.first() != Some(&codec) {
            return Err(invalid(
                "inventory chunk codec disagrees with its canonical name",
            ));
        }
        let length =
            inspect_standalone_length(&encoded, self.location.chunk_profile()).map_err(source)?;
        let descriptor = Descriptor::from_wire(
            &TERRANE_V1,
            TERRANE_V1.algorithm(),
            TERRANE_V1.domain(IdentityKind::Chunk).map_err(source)?,
            &digest,
            length as u64,
        )
        .map_err(source)?;
        Ok(NativeBodyKey::Chunk { descriptor, codec })
    }

    fn scan_private_remnants(&self, budget: &mut usize) -> io::Result<File> {
        charge(budget)?;
        let staging = open(&self.root, "staging", true)?;
        self.check(&staging, Custody::Publisher, InodeKind::Directory)?;
        if staging.metadata()?.mode() & 0o7777 != 0o700 {
            return Err(invalid("publisher staging root is not private"));
        }
        let publisher_id = std::process::id().to_string();
        let staging_names = names(&staging, *budget)?;
        if staging_names.len() != 1 {
            return Err(invalid(
                "publisher staging incarnation is missing or unreconciled",
            ));
        }
        for name in staging_names {
            charge(budget)?;
            if name != publisher_id {
                return Err(invalid("unreconciled publisher staging namespace entry"));
            }
            let directory = open(&staging, &name, true)?;
            self.check(&directory, Custody::Publisher, InodeKind::Directory)?;
            if directory.metadata()?.mode() & 0o7777 != 0o700 {
                return Err(invalid("publisher staging incarnation is not private"));
            }
            require_empty(
                &directory,
                *budget,
                "unreconciled publisher staging contents",
            )?;
        }

        charge(budget)?;
        let state = open(&self.root, "state", true)?;
        let metadata = state.metadata()?;
        if metadata.dev() != self.root.metadata()?.dev()
            || (metadata.uid() != 0 && metadata.uid() != rustix::process::geteuid().as_raw())
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid("publisher state parent custody changed"));
        }
        charge(budget)?;
        self.check_project(&state, InodeKind::Directory)?;
        let publication = open(&state, "publication", true)?;
        self.check(&publication, Custody::Publisher, InodeKind::Directory)?;
        if publication.metadata()?.mode() & 0o7777 != 0o700 {
            return Err(invalid("publisher publication state is not private"));
        }
        Ok(publication)
    }

    async fn scan(&self) -> io::Result<Vec<NativeBodyKey>> {
        let mut keys = Vec::new();
        let mut budget = MAX_CANDIDATES;
        self.check_project(&self.root, InodeKind::Directory)?;
        let publication = self.scan_private_remnants(&mut budget)?;
        let mut state = state::StateInventory::open(self, publication, &mut budget)?;
        for (class, encoded) in [("sealed", false), ("chunks", true)] {
            charge(&mut budget)?;
            let directory = open(&self.root, class, true)?;
            self.check(
                &directory,
                if encoded {
                    Custody::Content
                } else {
                    Custody::Publisher
                },
                InodeKind::Directory,
            )?;
            for shard in names(&directory, budget)? {
                charge(&mut budget)?;
                digest(&shard, 1)?;
                let shard_directory = open(&directory, &shard, true)?;
                self.check(
                    &shard_directory,
                    if encoded {
                        Custody::Content
                    } else {
                        Custody::Publisher
                    },
                    InodeKind::Directory,
                )?;
                for name in names(&shard_directory, budget)? {
                    charge(&mut budget)?;
                    let mut file = open(&shard_directory, &name, false)?;
                    let key = if encoded {
                        let (hash, codec) = name
                            .split_once('.')
                            .ok_or_else(|| invalid("invalid inventory chunk name"))?;
                        let codec: u8 = codec.parse().map_err(source)?;
                        if name != format!("{hash}.{codec}") || !hash.starts_with(&shard) {
                            return Err(invalid("noncanonical inventory chunk shard or codec"));
                        }
                        self.chunk(hash, codec, &mut file)?
                    } else {
                        if !name.starts_with(&shard) {
                            return Err(invalid("invalid inventory sealed shard"));
                        }
                        let verified = self.sealed(&name, &mut file).await?;
                        let key = verified.key();
                        state
                            .reconcile(self, &shard_directory, &name, &mut file, verified)
                            .await?;
                        key
                    };
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
        }
        self.scan_packs(&mut keys, &mut budget)?;
        charge(&mut budget)?;
        let pending = open(&self.root, "pending-delete", true)?;
        self.check(&pending, Custody::Publisher, InodeKind::Directory)?;
        for name in names(&pending, budget)? {
            charge(&mut budget)?;
            digest(&name, 32)?;
            let mut file = open(&pending, &name, false)?;
            let key = if file.metadata()?.uid() == rustix::process::geteuid().as_raw() {
                self.sealed(&name, &mut file).await?.key()
            } else {
                self.pending_encoded(&name, &mut file)?
            };
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        state.finish(self)?;
        Ok(keys)
    }

    fn scan_packs(&self, keys: &mut Vec<NativeBodyKey>, budget: &mut usize) -> io::Result<()> {
        charge(budget)?;
        let objects = open(&self.root, "objects", true)?;
        self.check(&objects, Custody::Content, InodeKind::Directory)?;
        for name in names(&objects, *budget)? {
            charge(budget)?;
            match name.as_str() {
                "pack" => {}
                "index" => {
                    // The SDK catalog is ordinary host-owned metadata, outside
                    // the publisher's body registry. Recognizing this root does
                    // not validate its children or prove an empty namespace:
                    // native recovery independently compares its complete
                    // selected catalog and retained inodes before Resume.
                    let catalog = open(&objects, &name, true)?;
                    let metadata = catalog.metadata()?;
                    if metadata.uid() != 0
                        || metadata.gid() != 0
                        || metadata.mode() & 0o7777 != 0o755
                        || metadata.dev() != self.root.metadata()?.dev()
                    {
                        return Err(invalid("portable catalog root custody changed"));
                    }
                    self.check_project(&catalog, InodeKind::Directory)?;
                }
                _ => return Err(invalid("unreconciled inventory objects namespace entry")),
            }
        }
        let packs = match open(&objects, "pack", true) {
            Ok(packs) => packs,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        self.check(&packs, Custody::Content, InodeKind::Directory)?;
        for shard in names(&packs, *budget)? {
            charge(budget)?;
            digest(&shard, 1)?;
            let directory = open(&packs, &shard, true)?;
            self.check(&directory, Custody::Content, InodeKind::Directory)?;
            for name in names(&directory, *budget)? {
                charge(budget)?;
                let (id, extension) = name
                    .split_once('.')
                    .ok_or_else(|| invalid("invalid inventory pack name"))?;
                if !matches!(extension, "pack" | "idx") || !id.starts_with(&shard) {
                    return Err(invalid("invalid inventory pack shard or extension"));
                }
                let pack_id = digest(id, 16)?
                    .try_into()
                    .map_err(|_| invalid("invalid pack identifier"))?;
                let file = open(&directory, &name, false)?;
                self.check(&file, Custody::Content, InodeKind::File)?;
                let key = NativeBodyKey::Pack { pack_id };
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        Ok(())
    }

    fn pending_encoded(&self, name: &str, file: &mut File) -> io::Result<NativeBodyKey> {
        self.check(file, Custody::Content, InodeKind::File)?;
        let mut header_bytes = [0; HEADER_SIZE];
        match file.read_exact(&mut header_bytes) {
            Ok(()) => {
                if let Ok(header) = Header::decode(&header_bytes) {
                    for kind in [IdentityKind::Pack, IdentityKind::Index] {
                        if crate::publisher_io::bodies::content_digest(file, kind)? == name {
                            return Ok(NativeBodyKey::Pack {
                                pack_id: *header.id(),
                            });
                        }
                    }
                    return Err(invalid(
                        "pending pack/index content identity contradicts its name",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(error) => return Err(error),
        }
        file.seek(SeekFrom::Start(0))?;
        let mut codec = [0];
        file.read_exact(&mut codec)?;
        self.chunk(name, codec[0], file)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use terrane_format::chunking::ChunkProfile;

    #[test]
    fn retained_open_rejects_symlinks_and_wrong_inode_kinds() {
        let root = File::open("/").unwrap();
        assert!(open(&root, "dev/null", false).is_err());
        assert!(open(&root, "proc/self", true).is_err());
        assert!(open(&root, "dev", false).is_err());
    }

    #[test]
    fn physical_entry_budget_counts_directories_and_bodies() {
        let mut budget = 2;
        charge(&mut budget).unwrap();
        charge(&mut budget).unwrap();
        assert!(charge(&mut budget).is_err());
        assert_eq!(budget, 0);
    }

    #[test]
    fn private_remnant_names_prevent_empty_namespace_classification() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let path = std::env::temp_dir().join(format!(
            "terrane-private-inventory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        let directory = File::open(&path).unwrap();
        let scan = || require_empty(&directory, MAX_CANDIDATES, "unreconciled private contents");

        // This tests name coverage only. Actual project/inheritance inspection
        // requires a provisioned native filesystem in the fresh-process VM.
        scan().unwrap();
        for name in [
            "incomplete",
            ".binding-interrupted",
            "retirement-existing.toml",
            "unknown",
        ] {
            let remnant = path.join(name);
            std::fs::write(&remnant, b"unreconciled").unwrap();
            assert!(scan().is_err());
            std::fs::remove_file(remnant).unwrap();
        }
        std::fs::create_dir(path.join("stale")).unwrap();
        assert!(scan().is_err());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn key_parser_refuses_noncanonical_names() {
        assert_eq!(digest("00ff", 2).unwrap(), [0, 255]);
        for malformed in ["00FF", "0xff", "000", "../a", "gggg"] {
            assert!(digest(malformed, 2).is_err());
        }

        let identity = TERRANE_V1.calculate(IdentityKind::Chunk, b"lease").unwrap();
        let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, b"lease").unwrap();
        let sealed = descriptor.encode();
        assert!(lease_records::validate_key(&sealed).is_ok());

        let mut chunk = vec![1, 2];
        chunk.extend_from_slice(&sealed);
        chunk.push(0);
        assert!(lease_records::validate_key(&chunk).is_ok());

        let mut pack = vec![2];
        pack.extend_from_slice(&[7; 16]);
        pack.push(0);
        assert!(lease_records::validate_key(&pack).is_ok());
        *pack.last_mut().unwrap() = 1;
        assert!(lease_records::validate_key(&pack).is_ok());

        let mut wrong_codec = chunk.clone();
        wrong_codec[1] = 3;
        *chunk.last_mut().unwrap() = 1;
        *pack.last_mut().unwrap() = 2;
        for malformed in [vec![1], vec![2], wrong_codec, chunk, pack] {
            assert!(lease_records::validate_key(&malformed).is_err());
        }

        let tree = TERRANE_V1.calculate(IdentityKind::Node, b"lease").unwrap();
        let tree = Descriptor::from_identity(&TERRANE_V1, &tree, b"lease").unwrap();
        assert!(lease_records::validate_key(&tree.encode()).is_err());
    }

    #[test]
    fn snapshot_pages_use_single_use_owner_cursors() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            // This fixture tests pagination of unverified names only. It grants
            // no native inspection, quota, content or serving authority.
            let keys: Vec<_> = (0u8..130)
                .map(|value| {
                    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &[value]).unwrap();
                    NativeBodyKey::Sealed {
                        descriptor: Descriptor::from_identity(&TERRANE_V1, &identity, &[value])
                            .unwrap(),
                    }
                })
                .collect();
            let mut inventory = NativeInventory {
                root: File::open("/").unwrap(),
                location: HostDomainLocation::new(
                    "/".into(),
                    "public".into(),
                    ChunkProfile::cdc_1m([0; 32]),
                )
                .unwrap(),
                content_uid: 840,
                content_gid: 845,
                snapshot: Some(Snapshot {
                    keys: keys.clone(),
                    offset: 0,
                    cursor: vec![17; 32],
                }),
            };
            let first = inventory.page(Some(vec![17; 32])).await.unwrap();
            let NativeCommandResult::Inventory {
                keys: page,
                next_cursor: Some(cursor),
            } = first
            else {
                panic!("bounded continuation expected")
            };
            assert_eq!(page, keys[..64]);
            assert!(inventory.page(Some(vec![17; 32])).await.is_err());
            let second = inventory.page(Some(cursor)).await.unwrap();
            let NativeCommandResult::Inventory {
                keys: page,
                next_cursor: Some(cursor),
            } = second
            else {
                panic!("bounded continuation expected")
            };
            assert_eq!(page, keys[64..128]);
            let last = inventory.page(Some(cursor.clone())).await.unwrap();
            let NativeCommandResult::Inventory {
                keys: page,
                next_cursor: None,
            } = last
            else {
                panic!("complete snapshot expected")
            };
            assert_eq!(page, keys[128..]);
            assert!(inventory.page(Some(cursor)).await.is_err());
        });
    }
}
