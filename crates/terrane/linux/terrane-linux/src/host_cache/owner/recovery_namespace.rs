//! Observes every shared namespace entry without granting content authority.
//!
//! Candidate inventories intentionally omit coordination files and unrelated
//! object children. Recovery needs this separate bounded physical observation
//! before it can claim an empty namespace. Private publisher directories remain
//! the publisher's responsibility; this module cannot prove complete recovery.
//!
//! Startup may discard only existing generated chunk and detached-index scratch:
//!
//! ```text
//! chunks/<two lowercase hex digits>/.terrane-tmp:<32 lowercase hex digits>
//! objects/pack/<two lowercase hex digits>/.terrane-tmp:<32 lowercase hex digits>
//! ```
//!
//! Cleanup precedes native adoption and retains original readonly inode custody.
//! Canonical names and unrelated files are never classified as scratch.

mod quarantine;
#[cfg(feature = "surface-fuse")]
mod surface;

use super::NativeCachePreparation;
use crate::{
    host_cache::{NativeHostLayout, NativeManifestSource, VerifiedStandaloneChunk},
    host_quota::NativeProject,
    quota_confinement::Installed,
};
use rustix::fs::{AtFlags, Dir, Mode, OFlags, open, openat, statat, unlinkat};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{File, Metadata},
    io,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStringExt, fs::MetadataExt},
    },
    path::PathBuf,
    sync::Arc,
};
use terrane_sdk::host::cache::HostDomainLocation;

struct DirectoryObservation {
    file: Arc<File>,
    relative: PathBuf,
    metadata: Metadata,
    names: Vec<OsString>,
}

struct EntryObservation {
    parent: Arc<File>,
    name: OsString,
    relative: PathBuf,
    inode: File,
    metadata: Metadata,
}

/// Retains actual shared names, including unrecognized and temporary entries.
///
/// Construction is restricted to genuine native preparation. This observation
/// proves neither valid content nor private namespace coverage, durable policy
/// reconstruction, source pinning or permission to Resume.
pub(super) struct SharedNamespaceObservation {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    confinement: Arc<Installed>,
    uid: u32,
    gid: u32,
    project_id: u32,
    max_entries: usize,
    directories: Vec<DirectoryObservation>,
    entries: Vec<EntryObservation>,
    portable: Option<Arc<super::recovery_portable::PortableCatalog>>,
    // Opaque native custody is separate from every verified content source.
    quarantine: BTreeMap<PathBuf, crate::host_cache::NativeQuarantinedInode>,
}

impl SharedNamespaceObservation {
    /// Borrows actual retained descriptors for post-barrier allocation observation.
    pub(super) fn retained_inodes(&self) -> impl Iterator<Item = &File> {
        self.directories
            .iter()
            .map(|directory| directory.file.as_ref())
            .chain(self.entries.iter().map(|entry| &entry.inode))
    }

    /// Enumerates actual names with one finite budget across all shared roots.
    ///
    /// No entry is filtered by spelling or inode type. Iterative traversal avoids
    /// stack growth for unexpected nested directories. A symlink, FIFO or device
    /// is observed only through O_PATH, never opened for reading.
    ///
    /// # Errors
    /// Refuses stale preparation, changed custody, unreadable directories,
    /// exhausted name budgets and directory replacement during observation.
    pub(super) fn inspect(preparation: &NativeCachePreparation) -> io::Result<Self> {
        preparation.confinement.check_current()?;
        preparation.layout().recheck()?;
        let mut observed = Self {
            layout: Arc::clone(preparation.layout()),
            confinement: Arc::clone(&preparation.confinement),
            uid: preparation.config.content_uid,
            gid: preparation.config.content_gid,
            project_id: preparation.config.project_id,
            max_entries: preparation.config.inventory_entries,
            directories: Vec::new(),
            entries: Vec::new(),
            portable: preparation.portable.clone(),
            quarantine: BTreeMap::new(),
        };
        let mut pending = Vec::new();
        for label in ["chunks", "objects", "quarantine"] {
            let retained = observed
                .layout
                .directories
                .get(label)
                .ok_or_else(|| invalid("missing shared namespace root"))?;
            let file = Arc::new(File::from(openat(
                retained,
                ".",
                directory_flags(),
                Mode::empty(),
            )?));
            observed.check_root(&file)?;
            pending.push((file, PathBuf::from(label)));
        }
        while let Some((directory, relative)) = pending.pop() {
            let before = directory.metadata()?;
            let remaining = observed
                .max_entries
                .checked_sub(observed.entries.len())
                .ok_or_else(|| invalid("shared namespace observation budget underflow"))?;
            let names = read_names(&directory, remaining)?;
            for name in &names {
                let inode = File::from(openat(
                    &directory,
                    name,
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
                let metadata = inode.metadata()?;
                if metadata.dev() != observed.layout.directory_binding("layout-root")?.0 {
                    return Err(invalid("shared namespace crosses the retained filesystem"));
                }
                let relative = relative.join(name);
                if metadata.is_dir() {
                    let readable = reopen_directory(&inode, &metadata)?;
                    observed.check_directory(&relative, &readable)?;
                    pending.push((Arc::new(readable), relative.clone()));
                }
                observed.entries.push(EntryObservation {
                    parent: Arc::clone(&directory),
                    name: name.clone(),
                    relative,
                    inode,
                    metadata,
                });
            }
            if !same_inode(&before, &directory.metadata()?) {
                return Err(invalid("shared directory changed during enumeration"));
            }
            observed.directories.push(DirectoryObservation {
                file: directory,
                relative,
                metadata: before,
                names,
            });
        }
        if let Some(portable) = &observed.portable {
            for path in portable.files() {
                if !observed.entries.iter().any(|entry| &entry.relative == path) {
                    return Err(invalid(
                        "validated portable catalog file absent from shared scan",
                    ));
                }
            }
        }
        observed.check_current()?;
        Ok(observed)
    }

    /// Rechecks actual names and retained inode identity without trusting stamps alone.
    ///
    /// # Errors
    /// Refuses stale confinement/roots, changed configured custody, new/removed
    /// names, replaced entries and changed inode metadata.
    pub(super) fn check_current(&self) -> io::Result<()> {
        self.confinement.check_current()?;
        self.layout.recheck()?;
        for label in ["chunks", "objects", "quarantine"] {
            let root = self
                .layout
                .directories
                .get(label)
                .ok_or_else(|| invalid("missing retained shared namespace root"))?;
            self.check_root(&File::from(openat(
                root,
                ".",
                directory_flags(),
                Mode::empty(),
            )?))?;
        }
        for directory in &self.directories {
            self.check_directory(&directory.relative, &directory.file)?;
            if !same_inode(&directory.metadata, &directory.file.metadata()?)
                || read_names(&directory.file, self.max_entries)? != directory.names
            {
                return Err(invalid("shared namespace changed after observation"));
            }
        }
        for observation in self.quarantine.values() {
            observation.check_current()?;
        }
        for entry in &self.entries {
            let current = File::from(openat(
                &entry.parent,
                &entry.name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            if !same_inode(&entry.metadata, &entry.inode.metadata()?)
                || !same_inode(&entry.metadata, &current.metadata()?)
            {
                return Err(invalid("shared namespace entry changed after observation"));
            }
            if let Some(portable) = &self.portable
                && portable.is_file(&entry.relative)
            {
                let name = entry
                    .name
                    .to_str()
                    .ok_or_else(|| invalid("portable catalog name is not UTF-8"))?;
                let file = super::open_regular_at(&entry.parent, name)?;
                portable.check_file(
                    &entry.relative,
                    &file,
                    &entry.metadata,
                    self.project_id,
                    self.layout.directory_binding("layout-root")?.0,
                )?;
            }
        }
        Ok(())
    }

    /// Discards generated chunk and index scratch under original directory custody.
    ///
    /// Every candidate is classified and checked before the first unlink. Exact
    /// inode snapshots are carried through the effects, including multiple
    /// temporary links to one inode. A surviving canonical link is preserved.
    /// The caller must take a fresh shared observation after cleanup, before
    /// any candidate adoption or completed-recovery authority exists.
    ///
    /// # Errors
    /// Refuses malformed generated names, nonregular or foreign/project-mismatched
    /// scratch, changed retained or named inodes, failed unlink/directory sync,
    /// or a surviving/replaced temporary name. Partial progress grants no service.
    pub(super) fn discard_uncommitted_temporaries(&self) -> io::Result<usize> {
        let mut files = Vec::new();
        files
            .try_reserve_exact(self.entries.len())
            .map_err(io::Error::other)?;
        let mut current = BTreeMap::new();
        for entry in &self.entries {
            if !uncommitted_temporary(entry)? {
                continue;
            }
            if !entry.metadata.is_file() {
                return Err(invalid("generated scratch is not a regular inode"));
            }
            let name = entry
                .name
                .to_str()
                .ok_or_else(|| invalid("generated scratch is not UTF-8"))?;
            let file = super::open_regular_at(&entry.parent, name)?;
            self.check_temporary(&file, &entry.metadata)?;
            let inode = (entry.metadata.dev(), entry.metadata.ino());
            if let Some(previous) = current.insert(inode, file.metadata()?)
                && (!same_inode(&previous, &entry.metadata)
                    || previous.nlink() != entry.metadata.nlink())
            {
                return Err(invalid(
                    "temporary aliases disagree about original inode custody",
                ));
            }
            files.push((entry, file));
        }
        self.check_current()?;

        for (entry, file) in &files {
            self.confinement.check_current()?;
            self.layout.recheck()?;
            self.check_root(&entry.parent)?;
            let inode = (entry.metadata.dev(), entry.metadata.ino());
            let before = current
                .get(&inode)
                .ok_or_else(|| invalid("scratch lost its original inode snapshot"))?;
            let name = entry
                .name
                .to_str()
                .ok_or_else(|| invalid("generated scratch is not UTF-8"))?;
            let named = super::open_regular_at(&entry.parent, name)?;
            self.check_temporary(&named, before)?;
            self.check_temporary(file, before)?;

            unlinkat(&entry.parent, name, AtFlags::empty())?;
            entry.parent.sync_all()?;
            let after = file.metadata()?;
            let links = before
                .nlink()
                .checked_sub(1)
                .ok_or_else(|| invalid("scratch link count underflow"))?;
            if !same_payload_binding(before, &after) || after.nlink() != links {
                return Err(invalid("scratch unlink changed another inode or payload"));
            }
            match statat(&entry.parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(invalid("scratch name survived or was replaced")),
            }
            // Unlink legitimately changes ctime and nlink on every alias. Carry
            // that actual outcome into the next alias comparison; bytes, owner,
            // mode and mtime must retain their original bindings throughout.
            current.insert(inode, after);
        }
        self.confinement.check_current()?;
        self.layout.recheck()?;
        Ok(files.len())
    }

    fn check_temporary(&self, file: &File, before: &Metadata) -> io::Result<()> {
        let observed = file.metadata()?;
        if !observed.is_file()
            || !same_inode(before, &observed)
            || observed.nlink() == 0
            || observed.nlink() != before.nlink()
            || observed.uid() != self.uid
            || observed.gid() != self.gid
            || !matches!(observed.mode() & 0o7777, 0o600 | 0o640)
            || observed.dev() != self.layout.directory_binding("layout-root")?.0
            || NativeProject::inspect(file)?.project_id != self.project_id
        {
            return Err(invalid("scratch differs from original native custody"));
        }
        Ok(())
    }

    /// Reports whether entries contain only checked non-serving namespace members.
    ///
    /// Scaffolds, portable metadata and authenticated quarantine custody supply no
    /// content or complete recovery evidence. Quarantine remains physically charged.
    pub(super) fn only_nonresident_entries(&self) -> bool {
        self.entries.iter().all(|entry| {
            self.is_nonresident_metadata(entry) || self.quarantine.contains_key(&entry.relative)
        })
    }

    /// Requires every ordinary shared file to be in an actual verified source closure.
    ///
    /// Canonical names alone grant no exception: both pack and exact derived
    /// index must match the genuine source's retained kernel inode and metadata.
    /// Every source must also be represented in the exhaustive original scan.
    /// This classifies namespace/content custody only; durable pins, original
    /// publisher context and final source verification remain owner obligations.
    ///
    /// # Errors
    /// Refuses another domain/root/project, changed source, an absent closure
    /// member or any unaccounted, temporary, unrelated or nonregular shared entry.
    /// Checked opaque quarantine entries remain outside the content closure.
    pub(super) fn require_sources(
        &self,
        sources: &[Arc<NativeManifestSource>],
        chunks: &[Arc<VerifiedStandaloneChunk>],
        metadata: &[Arc<crate::host_cache::DerivedIndexRepair>],
    ) -> io::Result<()> {
        self.check_current()?;
        let mut expected = BTreeMap::<PathBuf, Metadata>::new();
        for source in sources {
            if !Arc::ptr_eq(&self.layout, source.layout()) {
                return Err(invalid(
                    "metadata source belongs to another retained domain root",
                ));
            }
            source.recheck()?;
            let id = source.pack_id();
            let base = PathBuf::from("objects/pack").join(format!("{:02x}", id.as_bytes()[0]));
            for (suffix, file) in [("pack", source.files().0), ("idx", source.files().1)] {
                let metadata = file.metadata()?;
                let project = NativeProject::inspect(file)?;
                if !metadata.is_file()
                    || metadata.uid() != self.uid
                    || metadata.gid() != self.gid
                    || metadata.mode() & 0o002 != 0
                    || project.project_id != self.project_id
                    || project.device != self.layout.directory_binding("layout-root")?.0
                    || (project.device, project.inode) != (metadata.dev(), metadata.ino())
                {
                    return Err(invalid(
                        "verified source differs from configured shared charge custody",
                    ));
                }
                let path = base.join(format!("{id}.{suffix}"));
                if expected
                    .get(&path)
                    .is_some_and(|previous| !same_inode(previous, &metadata))
                {
                    return Err(invalid(
                        "one metadata key resolves to conflicting retained inodes",
                    ));
                }
                expected.insert(path, metadata);
            }
        }
        for source in metadata {
            if !Arc::ptr_eq(&self.layout, source.layout()) {
                return Err(invalid(
                    "metadata pair belongs to another retained domain root",
                ));
            }
            source.pair_bytes()?;
            let id = source.pack_id();
            let base = PathBuf::from("objects/pack").join(format!("{:02x}", id.as_bytes()[0]));
            let index = source
                .present_index_file()
                .ok_or_else(|| invalid("verified metadata index absent"))?;
            for (suffix, file) in [("pack", source.pack_file()), ("idx", index)] {
                let metadata = file.metadata()?;
                let project = NativeProject::inspect(file)?;
                if !metadata.is_file()
                    || metadata.uid() != self.uid
                    || metadata.gid() != self.gid
                    || metadata.mode() & 0o7777 != 0o640
                    || metadata.nlink() != 1
                    || project.project_id != self.project_id
                    || project.device != self.layout.directory_binding("layout-root")?.0
                    || (project.device, project.inode) != (metadata.dev(), metadata.ino())
                {
                    return Err(invalid(
                        "metadata pair differs from configured shared custody",
                    ));
                }
                let path = base.join(format!("{id}.{suffix}"));
                if expected.insert(path, metadata).is_some() {
                    return Err(invalid("duplicate metadata source in verified closure"));
                }
            }
        }
        for chunk in chunks {
            if !Arc::ptr_eq(&self.layout, chunk.layout()) {
                return Err(invalid(
                    "standalone source belongs to another retained root",
                ));
            }
            chunk.check_current()?;
            let metadata = chunk.file().metadata()?;
            let project = NativeProject::inspect(chunk.file())?;
            if !metadata.is_file()
                || metadata.uid() != self.uid
                || metadata.gid() != self.gid
                || metadata.mode() & 0o7777 != 0o640
                || metadata.nlink() != 1
                || project.project_id != self.project_id
                || project.device != self.layout.directory_binding("layout-root")?.0
                || (project.device, project.inode) != (metadata.dev(), metadata.ino())
            {
                return Err(invalid(
                    "standalone source differs from shared charge custody",
                ));
            }
            let hash: String = chunk
                .identity()
                .digest()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let path = PathBuf::from("chunks")
                .join(&hash[..2])
                .join(format!("{hash}.{}", chunk.codec()));
            if expected.insert(path, metadata).is_some() {
                return Err(invalid("duplicate standalone source in verified closure"));
            }
        }
        for entry in &self.entries {
            if self.is_nonresident_metadata(entry) || self.quarantine.contains_key(&entry.relative)
            {
                continue;
            }
            let Some(source) = expected.remove(&entry.relative) else {
                return Err(invalid(
                    "unsupported shared namespace entry outside verified source closure",
                ));
            };
            if !entry.metadata.is_file()
                || !same_inode(&source, &entry.metadata)
                || !same_inode(&source, &entry.inode.metadata()?)
            {
                return Err(invalid(
                    "observed shared member differs from verified source inode",
                ));
            }
        }
        if !expected.is_empty() {
            return Err(invalid(
                "verified source closure was absent from exhaustive shared scan",
            ));
        }
        Ok(())
    }

    fn is_nonresident_metadata(&self, entry: &EntryObservation) -> bool {
        empty_scaffold(entry)
            || self.portable.as_ref().is_some_and(|portable| {
                if entry.metadata.is_dir() {
                    portable.is_directory(&entry.relative)
                } else {
                    entry.metadata.is_file() && portable.is_file(&entry.relative)
                }
            })
    }

    fn check_directory(&self, relative: &std::path::Path, file: &File) -> io::Result<()> {
        if let Some(portable) = &self.portable
            && portable.is_directory(relative)
        {
            return portable.check_directory(
                relative,
                file,
                self.project_id,
                self.layout.directory_binding("layout-root")?.0,
            );
        }
        self.check_root(file)
    }

    fn check_root(&self, file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        let project = NativeProject::inspect(file)?;
        if !metadata.is_dir()
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() & 0o7777 != 0o2770
            || project.project_id != self.project_id
            || !project.inherit
            || metadata.dev() != self.layout.directory_binding("layout-root")?.0
        {
            return Err(invalid(
                "shared root differs from configured native custody",
            ));
        }
        Ok(())
    }
}

/// Recognizes generated scratch only in canonical chunk or detached-index shards.
fn uncommitted_temporary(entry: &EntryObservation) -> io::Result<bool> {
    if !entry.name.as_encoded_bytes().starts_with(b".terrane-tmp") {
        return Ok(false);
    }
    let components = entry.relative.iter().collect::<Vec<_>>();
    let known_parent = match components.as_slice() {
        [root, shard, _] if *root == "chunks" => canonical_shard(shard),
        [root, packs, shard, _] if *root == "objects" && *packs == "pack" => canonical_shard(shard),
        _ => false,
    };
    if !known_parent {
        // A matching spelling elsewhere is not a recognized uncommitted write.
        // Keep it for exhaustive recovery instead of deleting another class.
        return Ok(false);
    }
    let suffix = entry
        .name
        .to_str()
        .and_then(|name| name.strip_prefix(".terrane-tmp:"))
        .ok_or_else(|| invalid("malformed generated scratch name"))?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("malformed generated scratch identifier"));
    }
    Ok(true)
}

/// Checks unchanged payload custody while allowing the known unlink's metadata.
fn same_payload_binding(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

fn empty_scaffold(entry: &EntryObservation) -> bool {
    if !entry.metadata.is_dir() {
        return false;
    }
    let components = entry.relative.iter().collect::<Vec<_>>();
    match components.as_slice() {
        [root, shard] if *root == "chunks" => canonical_shard(shard),
        [root, packs] if *root == "objects" && *packs == "pack" => true,
        [root, packs, shard] if *root == "objects" && *packs == "pack" => canonical_shard(shard),
        _ => false,
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn reopen_directory(inode: &File, before: &Metadata) -> io::Result<File> {
    let file = File::from(open(
        format!("/proc/self/fd/{}", inode.as_raw_fd()),
        directory_flags() & !OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    if !same_inode(before, &file.metadata()?) || !same_inode(before, &inode.metadata()?) {
        return Err(invalid("classified shared directory changed during reopen"));
    }
    Ok(file)
}

/// Enumerates every raw child name with a finite allocation/count policy.
///
/// # Errors
/// Refuses native enumeration failure or the configured name budget.
pub(super) fn read_names(directory: &File, remaining: usize) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    for entry in Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if names.len() >= remaining {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "shared namespace observation budget exceeded",
            ));
        }
        names.push(OsString::from_vec(name.to_bytes().to_vec()));
    }
    names.sort();
    Ok(names)
}

fn canonical_shard(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.len() == 2
            && name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn same_inode(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Read;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 16];
            File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut random)
                .unwrap();
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = std::env::temp_dir().join(format!("terrane-recovery-names-{suffix}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    // The native fixture executes this unchanged case on actual ext4; some
    // builder filesystems reject non-UTF-8 names before enumeration can run.
    #[cfg_attr(
        not(feature = "native-test-fixtures"),
        ignore = "requires the ext4 native fixture for raw filename bytes"
    )]
    #[test]
    fn actual_name_scan_counts_coordination_unknown_and_non_utf8_entries() {
        let fixture = Fixture::new();
        let non_utf8 = OsString::from_vec(vec![0xff]);
        std::fs::write(fixture.0.join(".terrane-tmp:0123"), []).unwrap();
        std::fs::write(fixture.0.join(&non_utf8), []).unwrap();
        std::fs::create_dir(fixture.0.join("unrecognized")).unwrap();
        let directory = File::open(&fixture.0).unwrap();
        rustix::fs::mkfifoat(&directory, "fifo", Mode::from_raw_mode(0o600)).unwrap();

        let names = read_names(&directory, 4).unwrap();
        assert_eq!(names.len(), 4);
        assert!(names.contains(&non_utf8));
        assert!(names.contains(&OsString::from(".terrane-tmp:0123")));
        assert!(names.contains(&OsString::from("unrecognized")));
        assert!(names.contains(&OsString::from("fifo")));
        assert_eq!(
            read_names(&directory, 3).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
    }

    #[test]
    fn actual_directory_reopen_retains_classified_inode_across_name_replacement() {
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.0.join("child")).unwrap();
        let parent = File::open(&fixture.0).unwrap();
        let retained = File::from(
            openat(
                &parent,
                "child",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .unwrap(),
        );
        std::fs::rename(fixture.0.join("child"), fixture.0.join("retained")).unwrap();
        std::fs::create_dir(fixture.0.join("child")).unwrap();
        let metadata = retained.metadata().unwrap();

        let reopened = reopen_directory(&retained, &metadata).unwrap();
        assert!(same_inode(&metadata, &reopened.metadata().unwrap()));
        assert_ne!(
            reopened.metadata().unwrap().ino(),
            std::fs::metadata(fixture.0.join("child")).unwrap().ino()
        );
    }
}
