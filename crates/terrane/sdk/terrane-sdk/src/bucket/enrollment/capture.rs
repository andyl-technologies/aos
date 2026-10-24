//! Seals and independently rechecks the bounded exact fresh namespace.

use super::super::super::super::super::{FencePolicy, MetadataStamp, NativeOpenedDirectory};
use super::super::super::corrupt;
use super::super::{bootstrap, io_failure};
use super::{Activated, Directory, Leaf, NativeInitialBucketEnrollment};
use crate::store::{StoreErrorKind, StoreFailure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, Metadata},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};
use terrane_format::{
    bucket::BucketKey,
    gc::publication::{Activation, BackendRegistration, PublicationCommit},
};

const MAX_ENTRIES: usize = 1024;
const MAX_DEPTH: usize = 32;
const MAX_LEAF_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 1024 * 1024;

/// Seals complete final metadata while retaining the actual fresh creator.
///
/// # Errors
/// Refuses changed original bindings/transcripts, incomplete or extra entries,
/// oversized data, unsafe inode types or ownership and native I/O failures.
pub(super) fn seal(input: Activated) -> Result<NativeInitialBucketEnrollment, StoreFailure> {
    bootstrap::validate_stage(&input.request, &input.binding, &input.staged)?;
    if bootstrap::binding(&input.request, &input.directories, &input.exclusions)? != input.binding {
        return Err(corrupt());
    }
    let creator = input.request.creator.as_ref().ok_or_else(corrupt)?;
    let root = input
        .directories
        .iter()
        .find(|directory| directory.path == input.request.root)
        .ok_or_else(corrupt)?;
    if !Arc::ptr_eq(&creator.root, &root.file) || !creator.stamp.same_incarnation(root.stamp) {
        return Err(corrupt());
    }
    for directory in input.directories.iter() {
        directory.check().map_err(io_failure)?;
    }
    for name in &input.frame.names {
        name.check(&input.exclusions).map_err(io_failure)?;
    }

    // The acknowledged native genesis fixes this set. Enumeration may only
    // match it; an extra regular file or empty directory never becomes evidence.
    let expected = expected_leaves(&input)?;
    let expected_directories =
        directory_set(&input.request.root, &input.request.control, expected.keys())?;
    let mut directories = Vec::new();
    for path in [&input.request.root, &input.request.control] {
        let original = input
            .directories
            .iter()
            .find(|directory| &directory.path == path)
            .ok_or_else(corrupt)?;
        directories.push(Directory {
            metadata: original.file.metadata().map_err(io_failure)?,
            original: copy_directory(original),
        });
    }
    let mut files = Vec::new();
    let mut seen = BTreeSet::from([input.request.root.clone(), input.request.control.clone()]);
    let mut position = 0;
    while position < directories.len() {
        let directory = &directories[position];
        directory.original.check().map_err(io_failure)?;
        let path = directory.original.path.clone();
        let parent = Arc::clone(&directory.original.file);
        let mut stream =
            rustix::fs::Dir::read_from(&parent).map_err(|error| io_failure(error.into()))?;
        for entry in &mut stream {
            let entry = entry.map_err(|error| io_failure(error.into()))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let child = path.join(std::ffi::OsStr::from_bytes(name));
            check_entry_bound(
                &child,
                &input.request.root,
                &input.request.control,
                seen.len(),
            )?;
            if !seen.insert(child.clone()) {
                return Err(corrupt());
            }
            if expected_directories.contains(&child) {
                let policy = directory_policy(&input, &child);
                let opened = open_child(&parent, entry.file_name(), policy)?;
                let metadata = opened.metadata().map_err(io_failure)?;
                let original = bootstrap::directory(&child, policy)?;
                if !same_metadata(
                    &metadata,
                    &original.file.metadata().map_err(io_failure)?,
                    false,
                ) || !input
                    .frame
                    .names
                    .iter()
                    .any(|name| name.path == child && name.stamp.same_incarnation(original.stamp))
                {
                    return Err(corrupt());
                }
                directories.push(Directory { original, metadata });
            } else if let Some(bytes) = expected.get(&child) {
                let policy = if child.starts_with(&input.request.control) {
                    FencePolicy::ProtectedRecord {
                        owner: input.request.operator_uid,
                    }
                } else {
                    FencePolicy::Payload {
                        owner: input.request.operator_uid,
                    }
                };
                let file = open_child(&parent, entry.file_name(), policy)?;
                let metadata = file.metadata().map_err(io_failure)?;
                let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
                policy.validate(stamp).map_err(io_failure)?;
                // Equal bytes alone do not establish the creator's leaf. Match
                // the final acknowledged physical preimage before retaining it.
                if !input.frame.reads.iter().any(|read| {
                    read.path == child
                        && read.expected.as_deref() == Some(bytes.as_slice())
                        && read
                            .metadata
                            .is_some_and(|expected| stamp.same_incarnation(expected))
                }) {
                    return Err(corrupt());
                }
                check_device(&parent, &file)?;
                let leaf = Leaf {
                    path: child,
                    file,
                    metadata,
                    expected: bytes.clone(),
                    policy,
                };
                verify_leaf(&leaf)?;
                files.push(leaf);
            } else {
                return Err(corrupt());
            }
        }
        directories[position].original.check().map_err(io_failure)?;
        position += 1;
    }
    if seen.len() != expected_directories.len() + expected.len()
        || directories.len() != expected_directories.len()
        || files.len() != expected.len()
    {
        return Err(corrupt());
    }
    let identities = directories
        .iter()
        .map(|entry| (entry.metadata.dev(), entry.metadata.ino()))
        .chain(
            files
                .iter()
                .map(|entry| (entry.metadata.dev(), entry.metadata.ino())),
        )
        .collect::<BTreeSet<_>>();
    if identities.len() != seen.len() {
        return Err(corrupt());
    }
    directories.sort_by(|left, right| left.original.path.cmp(&right.original.path));
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let receipt = NativeInitialBucketEnrollment {
        request: input.request,
        original_directories: input.directories,
        exclusions: input.exclusions,
        binding: input.binding,
        genesis: input.staged.transaction,
        directories,
        files,
    };
    verify(&receipt)?;
    Ok(receipt)
}

fn expected_leaves(input: &Activated) -> Result<BTreeMap<PathBuf, Vec<u8>>, StoreFailure> {
    let request = &input.request;
    let mut leaves = BTreeMap::new();
    for change in &input.staged.transaction.changes {
        if let Some(bytes) = &change.new {
            leaves.insert(request.root.join(&change.key), bytes.clone());
        }
    }
    leaves.insert(
        request.root.join(&input.staged.transaction.snapshot.key),
        input.staged.snapshot_bytes.clone(),
    );
    leaves.insert(
        request.root.join("publication/PORTABLE"),
        input
            .staged
            .transaction
            .snapshot
            .encode()
            .map_err(|_| corrupt())?,
    );
    leaves.insert(
        request.root.join(
            BucketKey::parse("CAPABILITIES")
                .map_err(|_| corrupt())?
                .lock_name(),
        ),
        Vec::new(),
    );
    let transaction = input.staged.transaction.encode().map_err(|_| corrupt())?;
    let transaction_key = format!(
        "publication/transactions/{}",
        bootstrap::operation(&input.staged)
    );
    let slot = PublicationCommit {
        revision: 0,
        predecessor: None,
        transaction_key: transaction_key.clone(),
        transaction_digest: *blake3::hash(&transaction).as_bytes(),
    }
    .encode()
    .map_err(|_| corrupt())?;
    leaves.insert(request.control.join(transaction_key), transaction);
    leaves.insert(request.control.join("publication/commits/0"), slot.clone());
    leaves.insert(
        request.control.join("backend-registration.cbor"),
        BackendRegistration {
            binding: input.binding.clone(),
            activation: Activation::Active,
            genesis: Some(*blake3::hash(&slot).as_bytes()),
        }
        .encode()
        .map_err(|_| corrupt())?,
    );
    let total = leaves.values().try_fold(0usize, |total, bytes| {
        if bytes.len() > MAX_LEAF_BYTES {
            return Err(capacity());
        }
        total.checked_add(bytes.len()).ok_or_else(capacity)
    })?;
    if total > MAX_TOTAL_BYTES {
        return Err(capacity());
    }
    Ok(leaves)
}

fn directory_set<'a>(
    root: &Path,
    control: &Path,
    leaves: impl Iterator<Item = &'a PathBuf>,
) -> Result<BTreeSet<PathBuf>, StoreFailure> {
    let mut directories = BTreeSet::from([root.to_owned(), control.to_owned(), root.join("gc")]);
    for leaf in leaves {
        let base = if leaf.starts_with(root) {
            root
        } else if leaf.starts_with(control) {
            control
        } else {
            return Err(corrupt());
        };
        let mut parent = leaf.parent().ok_or_else(corrupt)?;
        while parent != base {
            if !parent.starts_with(base) {
                return Err(corrupt());
            }
            directories.insert(parent.to_owned());
            parent = parent.parent().ok_or_else(corrupt)?;
        }
    }
    Ok(directories)
}

fn copy_directory(original: &NativeOpenedDirectory) -> NativeOpenedDirectory {
    NativeOpenedDirectory {
        file: Arc::clone(&original.file),
        path: original.path.clone(),
        stamp: original.stamp,
        policy: original.policy,
        parents: bootstrap::copy_parents(&original.parents),
    }
}

fn directory_policy(input: &Activated, path: &Path) -> FencePolicy {
    if path.starts_with(&input.request.control) {
        FencePolicy::PrivateControlDirectory {
            owner: input.request.operator_uid,
        }
    } else {
        FencePolicy::NamespaceDirectory {
            owner: input.request.operator_uid,
        }
    }
}

#[cfg(target_os = "linux")]
/// Pins an actually classified inode before any readable open is permitted.
struct ClassifiedChild {
    retained: File,
    metadata: Metadata,
    directory: bool,
}

#[cfg(target_os = "linux")]
fn classify_child(
    parent: &File,
    name: &std::ffi::CStr,
    policy: FencePolicy,
) -> Result<ClassifiedChild, StoreFailure> {
    use rustix::fs::{Mode, OFlags};

    // O_PATH pins the inode without invoking a device's open method or waiting
    // for a FIFO writer. No readable descriptor exists before classification.
    let retained = File::from(
        rustix::fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io_failure(error.into()))?,
    );
    let metadata = retained.metadata().map_err(io_failure)?;
    let directory = match policy {
        FencePolicy::NamespaceDirectory { .. } | FencePolicy::PrivateControlDirectory { .. } => {
            true
        }
        FencePolicy::Payload { .. } | FencePolicy::ProtectedRecord { .. } => false,
        _ => return Err(corrupt()),
    };
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(corrupt());
    }
    policy
        .validate(MetadataStamp::checked(&metadata).map_err(io_failure)?)
        .map_err(io_failure)?;
    check_device(parent, &retained)?;
    Ok(ClassifiedChild {
        retained,
        metadata,
        directory,
    })
}

#[cfg(target_os = "linux")]
fn reopen_child(classified: ClassifiedChild) -> Result<File, StoreFailure> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::AsRawFd;

    // This directory must be actual procfs. Its numeric child names our private
    // still-live descriptor, never a re-resolved caller namespace pathname.
    let proc = rustix::fs::open(
        "/proc/self/fd",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| io_failure(error.into()))?;
    if rustix::fs::fstatfs(&proc)
        .map_err(|error| io_failure(error.into()))?
        .f_type
        != rustix::fs::PROC_SUPER_MAGIC
    {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported));
    }
    let mut flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if classified.directory {
        flags |= OFlags::DIRECTORY;
    }
    let file = File::from(
        rustix::fs::openat(
            &proc,
            classified.retained.as_raw_fd().to_string(),
            flags,
            Mode::empty(),
        )
        .map_err(|error| io_failure(error.into()))?,
    );
    let opened = file.metadata().map_err(io_failure)?;
    let retained = classified.retained.metadata().map_err(io_failure)?;
    if (classified.directory && !opened.is_dir())
        || (!classified.directory && !opened.is_file())
        || !same_metadata(&opened, &classified.metadata, !classified.directory)
        || !same_metadata(&retained, &classified.metadata, !classified.directory)
    {
        return Err(corrupt());
    }
    Ok(file)
}

fn open_child(
    parent: &File,
    name: &std::ffi::CStr,
    policy: FencePolicy,
) -> Result<File, StoreFailure> {
    #[cfg(target_os = "linux")]
    {
        reopen_child(classify_child(parent, name, policy)?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, name, policy);
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

fn check_device(parent: &File, child: &File) -> Result<(), StoreFailure> {
    if parent.metadata().map_err(io_failure)?.dev() != child.metadata().map_err(io_failure)?.dev() {
        return Err(corrupt());
    }
    Ok(())
}

fn check_entry_bound(
    path: &Path,
    root: &Path,
    control: &Path,
    entries: usize,
) -> Result<(), StoreFailure> {
    let base = if path.starts_with(root) {
        root
    } else {
        control
    };
    if entries >= MAX_ENTRIES
        || path
            .strip_prefix(base)
            .map_err(|_| corrupt())?
            .components()
            .count()
            > MAX_DEPTH
    {
        return Err(capacity());
    }
    Ok(())
}

fn same_metadata(actual: &Metadata, expected: &Metadata, regular: bool) -> bool {
    (
        actual.dev(),
        actual.ino(),
        actual.uid(),
        actual.gid(),
        actual.mode(),
    ) == (
        expected.dev(),
        expected.ino(),
        expected.uid(),
        expected.gid(),
        expected.mode(),
    ) && (!regular
        || (
            actual.nlink(),
            actual.len(),
            actual.mtime(),
            actual.mtime_nsec(),
            actual.ctime(),
            actual.ctime_nsec(),
        ) == (
            expected.nlink(),
            expected.len(),
            expected.mtime(),
            expected.mtime_nsec(),
            expected.ctime(),
            expected.ctime_nsec(),
        ))
}

fn verify_leaf(leaf: &Leaf) -> Result<(), StoreFailure> {
    let named = std::fs::symlink_metadata(&leaf.path).map_err(io_failure)?;
    let opened = leaf.file.metadata().map_err(io_failure)?;
    leaf.policy
        .validate(MetadataStamp::checked(&opened).map_err(io_failure)?)
        .map_err(io_failure)?;
    if !same_metadata(&named, &leaf.metadata, true)
        || !same_metadata(&opened, &leaf.metadata, true)
        || leaf.expected.len() > MAX_LEAF_BYTES
        || opened.len() != leaf.expected.len() as u64
    {
        return Err(corrupt());
    }
    let mut bytes = vec![0; leaf.expected.len()];
    leaf.file.read_exact_at(&mut bytes, 0).map_err(io_failure)?;
    if bytes != leaf.expected
        || !same_metadata(
            &leaf.file.metadata().map_err(io_failure)?,
            &leaf.metadata,
            true,
        )
        || !same_metadata(
            &std::fs::symlink_metadata(&leaf.path).map_err(io_failure)?,
            &leaf.metadata,
            true,
        )
    {
        return Err(corrupt());
    }
    Ok(())
}

/// Rechecks the complete original preimage without acquiring another exclusion.
///
/// # Errors
/// Refuses changed original descriptors or bodies, extra/missing/aliased entries,
/// unsafe metadata and native enumeration or positioned-read failures.
pub(super) fn verify(receipt: &NativeInitialBucketEnrollment) -> Result<(), StoreFailure> {
    for directory in receipt.original_directories.iter() {
        directory.check().map_err(io_failure)?;
    }
    if bootstrap::binding(
        &receipt.request,
        &receipt.original_directories,
        &receipt.exclusions,
    )? != receipt.binding
    {
        return Err(corrupt());
    }
    let creator = receipt.request.creator.as_ref().ok_or_else(corrupt)?;
    if !creator.stamp.same_incarnation(
        MetadataStamp::checked(&creator.root.metadata().map_err(io_failure)?)
            .map_err(io_failure)?,
    ) {
        return Err(corrupt());
    }
    let mut expected = BTreeMap::new();
    for directory in &receipt.directories {
        directory.original.check().map_err(io_failure)?;
        if !same_metadata(
            &directory.original.file.metadata().map_err(io_failure)?,
            &directory.metadata,
            false,
        ) {
            return Err(corrupt());
        }
        expected.insert(
            directory.original.path.clone(),
            (directory.metadata.dev(), directory.metadata.ino()),
        );
    }
    for leaf in &receipt.files {
        verify_leaf(leaf)?;
        expected.insert(
            leaf.path.clone(),
            (leaf.metadata.dev(), leaf.metadata.ino()),
        );
    }
    let mut seen = BTreeSet::from([
        receipt.request.root.clone(),
        receipt.request.control.clone(),
    ]);
    for directory in &receipt.directories {
        let mut stream = rustix::fs::Dir::read_from(&directory.original.file)
            .map_err(|error| io_failure(error.into()))?;
        for entry in &mut stream {
            let entry = entry.map_err(|error| io_failure(error.into()))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let path = directory
                .original
                .path
                .join(std::ffi::OsStr::from_bytes(name));
            check_entry_bound(
                &path,
                &receipt.request.root,
                &receipt.request.control,
                seen.len(),
            )?;
            let metadata = std::fs::symlink_metadata(&path).map_err(io_failure)?;
            if metadata.file_type().is_symlink()
                || expected.get(&path) != Some(&(metadata.dev(), metadata.ino()))
                || !seen.insert(path)
            {
                return Err(corrupt());
            }
        }
        directory.original.check().map_err(io_failure)?;
    }
    if seen.len() != expected.len() {
        return Err(corrupt());
    }
    Ok(())
}

fn capacity() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Capacity)
}

#[cfg(all(test, feature = "tokio", target_os = "linux"))]
#[path = "opener_tests.rs"]
mod opener_tests;
