//! Checks ordinary portable catalog metadata separately from mutable cache bodies.
//!
//! A checked portable snapshot supplies comparison bytes only. The shared-name
//! scan still opens and retains each actual native inode, checks its project and
//! host custody, compares its complete bounded bytes, and rejects unknown names.
//! Catalog membership grants no resident source, lease, publication or deletion
//! authority. Only the native Ready opener installs this comparison projection.

use crate::host_quota::NativeProject;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, Metadata},
    io,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
};
use terrane_sdk::bucket::portable_reader::ValidatedPortableBucket;

pub(super) struct PortableCatalog {
    files: BTreeMap<PathBuf, Vec<u8>>,
    directories: BTreeSet<PathBuf>,
}

impl PortableCatalog {
    pub(super) fn new(snapshot: &ValidatedPortableBucket) -> io::Result<Self> {
        let root = Path::new("objects/index");
        let mut files = BTreeMap::new();
        let mut directories = BTreeSet::from([root.to_owned()]);
        for (key, bytes) in snapshot.selected_entries() {
            let path = Path::new(key);
            if !path.starts_with(root) {
                continue;
            }
            if path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err(invalid("noncanonical portable catalog key"));
            }
            let Some(bytes) = bytes else { continue };
            let mut parent = path.parent();
            while let Some(path) = parent.filter(|path| path.starts_with(root)) {
                directories.insert(path.to_owned());
                parent = path.parent();
            }
            files.insert(path.to_owned(), bytes.to_vec());
        }
        if files.is_empty() {
            return Err(invalid("validated portable catalog is empty"));
        }
        Ok(Self { files, directories })
    }

    pub(super) fn is_directory(&self, path: &Path) -> bool {
        self.directories.contains(path)
    }

    pub(super) fn is_file(&self, path: &Path) -> bool {
        self.files.contains_key(path)
    }

    pub(super) fn files(&self) -> impl Iterator<Item = &PathBuf> {
        self.files.keys()
    }

    pub(super) fn check_directory(
        &self,
        path: &Path,
        file: &File,
        project_id: u32,
        device: u64,
    ) -> io::Result<()> {
        if !self.is_directory(path) {
            return Err(invalid(
                "directory is outside the validated portable catalog",
            ));
        }
        check_custody(file, project_id, device, true)
    }

    pub(super) fn check_file(
        &self,
        path: &Path,
        file: &File,
        original: &Metadata,
        project_id: u32,
        device: u64,
    ) -> io::Result<()> {
        let expected = self
            .files
            .get(path)
            .ok_or_else(|| invalid("file is outside the validated portable catalog"))?;
        check_custody(file, project_id, device, false)?;
        let before = file.metadata()?;
        if before.dev() != original.dev()
            || before.ino() != original.ino()
            || before.len() != expected.len() as u64
        {
            return Err(invalid("portable catalog inode or length changed"));
        }
        let mut actual = vec![0; expected.len()];
        file.read_exact_at(&mut actual, 0)?;
        let after = file.metadata()?;
        if actual != *expected
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(invalid(
                "portable catalog bytes changed during native comparison",
            ));
        }
        Ok(())
    }
}

fn check_custody(file: &File, project_id: u32, device: u64, directory: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    let project = NativeProject::inspect(file)?;
    if metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.dev() != device
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
        || metadata.mode() & 0o7777 != if directory { 0o755 } else { 0o644 }
        || (!directory && metadata.nlink() != 1)
        || project.project_id != project_id
        || project.inherit != directory
        || (project.device, project.inode) != (metadata.dev(), metadata.ino())
    {
        return Err(invalid(
            "portable catalog differs from original host custody",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
