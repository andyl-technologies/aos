//! Exact physical comparison of a populated guest root with its pinned template.
//!
//! The caller supplies two independently protected, quiescent directory trees:
//! the immutable AOS package template and the workspace's mounted root. This
//! scanner compares every template entry and hashes its path, type, mode, and
//! content. Runtime-created files may exist outside that fixed entry set.

use std::fs::{self, File, Metadata};
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8] = b"aos.sandbox.guest-root-tree.v1\0";
const MAXIMUM_ENTRIES: usize = 250_000;
const MAXIMUM_PATH_BYTES: usize = 4096;
const MAXIMUM_FILE_BYTES: u64 = 512 * 1_048_576;

/// Compares every package-template entry with a protected workspace root.
///
/// The returned digest covers every compared path, file type, mode, regular
/// file byte, and symlink target. The caller must prove the workspace is the
/// exact attached dataset and that neither tree can be mutated concurrently.
///
/// # Errors
///
/// Returns an error for missing or substituted entries, unsafe ownership or
/// modes, unsupported file types, oversized trees, or filesystem I/O failure.
pub fn compare_guest_root_template_v1(
    template: &Path,
    workspace: &Path,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    if !template.is_absolute() || !workspace.is_absolute() {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    let source = fs::symlink_metadata(template)?;
    let destination = fs::symlink_metadata(workspace)?;
    verify_pair(&source, &destination, EntryKind::Directory)?;

    let mut state = TreeHashState {
        digest: Sha256::new(),
        entries: 0,
    };
    state.digest.update(DOMAIN);
    compare_directory(template, workspace, Path::new(""), &mut state)?;
    if state.entries == 0 {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    Ok(state.digest.finalize().into())
}

struct TreeHashState {
    digest: Sha256,
    entries: usize,
}

#[derive(Clone, Copy)]
enum EntryKind {
    Directory,
    Regular,
    Symlink,
}

fn compare_directory(
    template: &Path,
    workspace: &Path,
    relative: &Path,
    state: &mut TreeHashState,
) -> Result<(), GuestRootTreeErrorV1> {
    let mut names = fs::read_dir(template)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    for name in names {
        state.entries = state
            .entries
            .checked_add(1)
            .filter(|count| *count <= MAXIMUM_ENTRIES)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
        let child_relative = relative.join(&name);
        let path_bytes = child_relative.as_os_str().as_bytes();
        if path_bytes.is_empty() || path_bytes.len() > MAXIMUM_PATH_BYTES {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }

        let source_path = template.join(&name);
        let destination_path = workspace.join(&name);
        let source = fs::symlink_metadata(&source_path)?;
        let destination = fs::symlink_metadata(&destination_path)?;
        let kind = classify(&source)?;
        verify_pair(&source, &destination, kind)?;
        hash_entry_header(state, path_bytes, kind, source.permissions().mode());

        match kind {
            EntryKind::Directory => {
                compare_directory(&source_path, &destination_path, &child_relative, state)?
            }
            EntryKind::Regular => {
                let source_digest = hash_file(&source_path, source.len())?;
                let destination_digest = hash_file(&destination_path, destination.len())?;
                if source_digest != destination_digest {
                    return Err(GuestRootTreeErrorV1::InvalidTree);
                }
                state.digest.update(source.len().to_be_bytes());
                state.digest.update(source_digest);
            }
            EntryKind::Symlink => {
                let source_target = fs::read_link(&source_path)?;
                let destination_target = fs::read_link(&destination_path)?;
                if source_target != destination_target {
                    return Err(GuestRootTreeErrorV1::InvalidTree);
                }
                let target = source_target.as_os_str().as_bytes();
                let length =
                    u32::try_from(target.len()).map_err(|_| GuestRootTreeErrorV1::InvalidTree)?;
                state.digest.update(length.to_be_bytes());
                state.digest.update(target);
            }
        }
    }
    Ok(())
}

fn classify(metadata: &Metadata) -> Result<EntryKind, GuestRootTreeErrorV1> {
    let kind = metadata.file_type();
    if kind.is_dir() {
        Ok(EntryKind::Directory)
    } else if kind.is_file() {
        Ok(EntryKind::Regular)
    } else if kind.is_symlink() {
        Ok(EntryKind::Symlink)
    } else {
        Err(GuestRootTreeErrorV1::InvalidTree)
    }
}

fn verify_pair(
    source: &Metadata,
    destination: &Metadata,
    kind: EntryKind,
) -> Result<(), GuestRootTreeErrorV1> {
    let expected_type = match kind {
        EntryKind::Directory => source.is_dir() && destination.is_dir(),
        EntryKind::Regular => source.is_file() && destination.is_file(),
        EntryKind::Symlink => {
            source.file_type().is_symlink() && destination.file_type().is_symlink()
        }
    };
    let protected_mode = matches!(kind, EntryKind::Symlink)
        || source.mode() & 0o022 == 0 && destination.mode() & 0o022 == 0;
    if !expected_type
        || source.uid() != 0
        || destination.uid() != 0
        || !protected_mode
        || source.mode() & 0o7777 != destination.mode() & 0o7777
        || !matches!(kind, EntryKind::Directory) && source.len() != destination.len()
    {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    Ok(())
}

fn hash_entry_header(state: &mut TreeHashState, path: &[u8], kind: EntryKind, mode: u32) {
    state.digest.update((path.len() as u16).to_be_bytes());
    state.digest.update(path);
    state.digest.update([match kind {
        EntryKind::Directory => 1,
        EntryKind::Regular => 2,
        EntryKind::Symlink => 3,
    }]);
    state.digest.update((mode & 0o7777).to_be_bytes());
}

fn hash_file(path: &PathBuf, length: u64) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    if length > MAXIMUM_FILE_BYTES {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != length || opened.uid() != 0 {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut remaining = length;
    while remaining != 0 {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Err(GuestRootTreeErrorV1::InvalidTree);
        }
        digest.update(&buffer[..count]);
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or(GuestRootTreeErrorV1::InvalidTree)?;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    Ok(digest.finalize().into())
}

/// Reports a physical guest-root mismatch or filesystem failure.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootTreeErrorV1 {
    /// The template or workspace tree is missing, unsafe, substituted, or oversized.
    #[error("guest root tree is invalid")]
    InvalidTree,
    /// A filesystem operation failed during physical comparison.
    #[error("guest root tree I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
