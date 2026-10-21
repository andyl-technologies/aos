//! Captures and rechecks only the original namespace and actual mkdir events.

use super::{Entry, MAX_ENTRIES, NativeInitialHostScaffold};
use crate::host_quota::{
    DomainProvisioningGuard, NativeProject, open_host_path, require_host_root_namespace_boundary,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, Metadata},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt},
    },
    sync::Arc,
};
use terrane_sdk::bucket::enrollment::NativeInitialBucketEnrollment;

const FIXED_DIRECTORIES: [&str; 11] = [
    "chunks",
    "objects",
    "sealed",
    "staging",
    "quarantine",
    "pending-delete",
    "state",
    "objects/pack",
    "objects/index",
    "state/cache",
    "state/publication",
];

pub(super) fn host_root() -> io::Result<()> {
    require_host_root_namespace_boundary()?;
    if !rustix::process::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "initial enrollment requires actual host UID zero",
        ));
    }
    Ok(())
}

pub(super) fn create(
    initial: NativeInitialBucketEnrollment,
    guard: DomainProvisioningGuard,
) -> io::Result<NativeInitialHostScaffold> {
    host_root()?;
    if initial.operator_uid() != 0 {
        return Err(io::Error::other(
            "fresh bucket was not created by host UID zero",
        ));
    }
    initial.verify_inline().map_err(io::Error::other)?;
    let mut directories = Vec::new();
    let mut files = Vec::new();
    for directory in initial.directories() {
        let readable = File::from(rustix::fs::openat(
            directory.descriptor(),
            c".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        directories.push(capture(
            directory.path().to_owned(),
            readable,
            directory.observed_metadata().clone(),
            None,
            false,
        )?);
    }
    for file in initial.files() {
        files.push(capture(
            file.path().to_owned(),
            file.descriptor().try_clone()?,
            file.observed_metadata().clone(),
            Some(file.expected_bytes().to_vec()),
            false,
        )?);
    }
    if directories.len() + files.len() + FIXED_DIRECTORIES.len() > MAX_ENTRIES {
        return Err(io::Error::other("initial scaffold entry bound exceeded"));
    }
    let mut scaffold = NativeInitialHostScaffold {
        initial,
        guard,
        identity: Arc::new(()),
        directories,
        files,
        faulted: false,
    };
    recheck(&scaffold)?;
    for relative in FIXED_DIRECTORIES {
        let path = scaffold.root().join(relative);
        if scaffold.directories.iter().any(|entry| entry.path == path) {
            continue;
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("fixed directory lacks parent"))?;
        let index = scaffold
            .directories
            .iter()
            .position(|entry| entry.path == parent)
            .ok_or_else(|| io::Error::other("fixed parent is not retained"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("fixed directory lacks name"))?;
        // An existing unrecognized entry is never adopted. mkdirat must itself
        // report the actual absent-name creation event under the retained parent.
        recheck(&scaffold)?;
        let before = scaffold.directories[index].descriptor.metadata()?;
        rustix::fs::mkdirat(
            &scaffold.directories[index].descriptor,
            name,
            rustix::fs::Mode::from_raw_mode(0o700),
        )?;
        let opened = File::from(rustix::fs::openat(
            &scaffold.directories[index].descriptor,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        opened.sync_all()?;
        scaffold.directories[index].descriptor.sync_all()?;
        let after = scaffold.directories[index].descriptor.metadata()?;
        if !same_identity_and_custody(&before, &after)
            || before.nlink().checked_add(1) != Some(after.nlink())
        {
            return Err(io::Error::other("mkdir changed unrelated parent custody"));
        }
        let metadata = opened.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.dev() != before.dev() {
            return Err(io::Error::other(
                "created directory lacks original host custody",
            ));
        }
        scaffold.directories[index].current = after;
        scaffold
            .directories
            .push(capture(path, opened, metadata, None, true)?);
        recheck(&scaffold)?;
    }
    Ok(scaffold)
}

fn capture(
    path: std::path::PathBuf,
    descriptor: File,
    original: Metadata,
    bytes: Option<Vec<u8>>,
    created: bool,
) -> io::Result<Entry> {
    if !same_metadata(&descriptor.metadata()?, &original)
        || (bytes.is_some() && (!original.is_file() || original.nlink() != 1))
        || (bytes.is_none() && !original.is_dir())
    {
        return Err(io::Error::other("initial inode preimage changed"));
    }
    let project = NativeProject::inspect(&descriptor)?;
    Ok(Entry {
        path,
        descriptor,
        current: original.clone(),
        original,
        original_project: project.clone(),
        current_project: project,
        bytes,
        created,
    })
}

pub(super) fn same_identity_and_custody(a: &Metadata, b: &Metadata) -> bool {
    (a.dev(), a.ino(), a.mode(), a.uid(), a.gid(), a.rdev())
        == (b.dev(), b.ino(), b.mode(), b.uid(), b.gid(), b.rdev())
}

pub(super) fn same_metadata(a: &Metadata, b: &Metadata) -> bool {
    same_identity_and_custody(a, b)
        && (
            a.nlink(),
            a.len(),
            a.blocks(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.nlink(),
            b.len(),
            b.blocks(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
}

pub(super) fn check_entry(entry: &Entry) -> io::Result<()> {
    let named = std::fs::symlink_metadata(&entry.path)?;
    let opened = entry.descriptor.metadata()?;
    if named.file_type().is_symlink()
        || !same_metadata(&named, &entry.current)
        || !same_metadata(&opened, &entry.current)
        || NativeProject::inspect(&entry.descriptor)? != entry.current_project
    {
        return Err(io::Error::other("retained scaffold preimage changed"));
    }
    if let Some(expected) = &entry.bytes {
        if !opened.is_file() || opened.nlink() != 1 || opened.len() != expected.len() as u64 {
            return Err(io::Error::other("original regular file membership changed"));
        }
        let mut bytes = vec![0; expected.len()];
        entry.descriptor.read_exact_at(&mut bytes, 0)?;
        if bytes != *expected || !same_metadata(&entry.descriptor.metadata()?, &entry.current) {
            return Err(io::Error::other("original regular bytes changed"));
        }
    }
    let named_after = std::fs::symlink_metadata(&entry.path)?;
    if named_after.file_type().is_symlink()
        || !same_metadata(&named_after, &entry.current)
        || !same_metadata(&entry.descriptor.metadata()?, &entry.current)
        || NativeProject::inspect(&entry.descriptor)? != entry.current_project
    {
        return Err(io::Error::other(
            "retained scaffold closing preimage changed",
        ));
    }
    Ok(())
}

pub(super) fn recheck(scaffold: &NativeInitialHostScaffold) -> io::Result<()> {
    observe_namespace(scaffold)?.close()
}

/// Retains the same phase preimages between bounded enumeration and closing.
///
/// This private borrow grants no enrollment or mutation authority. It prevents
/// receipt-bound setters from advancing the phase before closing verification.
pub(super) struct ObservedNamespace<'a> {
    scaffold: &'a NativeInitialHostScaffold,
}

impl ObservedNamespace<'_> {
    pub(super) fn close(self) -> io::Result<()> {
        host_root()?;
        // No second tree walk or refreshed expected values: close every held
        // inode, name, project and exact body on the original phase preimages.
        for entry in self.scaffold.directories.iter().chain(&self.scaffold.files) {
            check_entry(entry)?;
        }
        for path in [self.scaffold.root(), self.scaffold.control()] {
            let entry = self
                .scaffold
                .directories
                .iter()
                .find(|entry| entry.path == path)
                .ok_or_else(|| io::Error::other("original namespace root missing at closing"))?;
            let current = open_host_path(path, true)?;
            if !same_metadata(&current.metadata()?, &entry.current) {
                return Err(io::Error::other(
                    "original namespace ancestry changed at closing",
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn observe_namespace(
    scaffold: &NativeInitialHostScaffold,
) -> io::Result<ObservedNamespace<'_>> {
    host_root()?;
    if scaffold.faulted {
        return Err(io::Error::other(
            "initial scaffold requires administrative recovery",
        ));
    }
    let root = scaffold
        .directories
        .iter()
        .find(|entry| entry.path == scaffold.root())
        .ok_or_else(|| io::Error::other("original root is missing"))?;
    if scaffold.guard.identity()? != (root.original.dev(), root.original.ino()) {
        return Err(io::Error::other(
            "provisioning guard belongs to another root",
        ));
    }
    // An independent shared description conflicts with an actual exclusive
    // guard. A supplied shared guard would permit this probe and is rejected.
    match DomainProvisioningGuard::shared(&root.descriptor) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
        Ok(_) => return Err(io::Error::other("exclusive provisioning guard required")),
    }
    for path in [scaffold.root(), scaffold.control()] {
        let descriptor = open_host_path(path, true)?;
        let entry = scaffold
            .directories
            .iter()
            .find(|entry| entry.path == path)
            .ok_or_else(|| io::Error::other("original namespace root missing"))?;
        if !same_metadata(&descriptor.metadata()?, &entry.current) {
            return Err(io::Error::other("original namespace ancestry changed"));
        }
    }
    let mut expected = BTreeMap::new();
    let mut inodes = BTreeSet::new();
    for entry in scaffold.directories.iter().chain(&scaffold.files) {
        check_entry(entry)?;
        if entry.current.dev() != root.current.dev()
            || !inodes.insert((entry.current.dev(), entry.current.ino()))
            || expected
                .insert(
                    entry.path.clone(),
                    (entry.current.dev(), entry.current.ino()),
                )
                .is_some()
        {
            return Err(io::Error::other(
                "initial scaffold inode aliases or crosses devices",
            ));
        }
    }
    let mut seen = BTreeSet::from([scaffold.root().to_owned(), scaffold.control().to_owned()]);
    for directory in &scaffold.directories {
        let mut stream = rustix::fs::Dir::read_from(&directory.descriptor)?;
        for entry in &mut stream {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let path = directory.path.join(std::ffi::OsStr::from_bytes(name));
            let metadata = std::fs::symlink_metadata(&path)?;
            if seen.len() >= MAX_ENTRIES
                || metadata.file_type().is_symlink()
                || expected.get(&path) != Some(&(metadata.dev(), metadata.ino()))
                || !seen.insert(path)
            {
                return Err(io::Error::other(
                    "unrecognized or replaced initial scaffold entry",
                ));
            }
        }
    }
    if seen.len() != expected.len() {
        return Err(io::Error::other("initial scaffold namespace is incomplete"));
    }
    Ok(ObservedNamespace { scaffold })
}
