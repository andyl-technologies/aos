//! Observes every shared namespace entry without granting content authority.
//!
//! Candidate inventories intentionally omit coordination files and unrelated
//! object children. Recovery needs this separate bounded physical observation
//! before it can claim an empty namespace. Private publisher directories remain
//! the publisher's responsibility; this module cannot prove complete recovery.

use super::NativeCachePreparation;
use crate::{
    host_cache::{NativeHostLayout, NativeManifestSource},
    host_quota::NativeProject,
    quota_confinement::Installed,
};
use rustix::fs::{Dir, Mode, OFlags, open, openat};
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
                    observed.check_root(&readable)?;
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
                metadata: before,
                names,
            });
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
            self.check_root(&directory.file)?;
            if !same_inode(&directory.metadata, &directory.file.metadata()?)
                || read_names(&directory.file, self.max_entries)? != directory.names
            {
                return Err(invalid("shared namespace changed after observation"));
            }
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
        }
        Ok(())
    }

    /// Reports whether all observed entries are recognized empty shard scaffolds.
    ///
    /// This is shared-name absence only, never complete recovery evidence.
    pub(super) fn only_empty_scaffolds(&self) -> bool {
        self.entries.iter().all(empty_scaffold)
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
    /// member or any loose, temporary, unrelated or nonregular shared entry.
    pub(super) fn require_metadata_sources(
        &self,
        sources: &[Arc<NativeManifestSource>],
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
        for entry in &self.entries {
            if empty_scaffold(entry) {
                continue;
            }
            let Some(source) = expected.remove(&entry.relative) else {
                return Err(invalid(
                    "unsupported shared namespace entry outside verified metadata closure",
                ));
            };
            if !entry.metadata.is_file()
                || !same_inode(&source, &entry.metadata)
                || !same_inode(&source, &entry.inode.metadata()?)
            {
                return Err(invalid(
                    "observed metadata member differs from verified source inode",
                ));
            }
        }
        if !expected.is_empty() {
            return Err(invalid(
                "verified metadata closure was absent from exhaustive shared scan",
            ));
        }
        Ok(())
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
