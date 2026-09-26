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
    compare_guest_root_tree(template, workspace, true)
}

/// Measures an offline build-user-owned template with the runtime tree algorithm.
///
/// Nix installs derivation outputs as root-owned only after the build phase.
/// This entry point keeps every type, mode, byte, and symlink check identical
/// while deferring UID-zero enforcement to the runtime protected readback.
///
/// # Errors
///
/// Returns an error for malformed or unsafe template entries, excessive
/// content, unsupported types, or filesystem failure.
pub fn measure_offline_guest_root_template_v1(
    template: &Path,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    compare_guest_root_tree(template, template, false)
}

fn compare_guest_root_tree(
    template: &Path,
    workspace: &Path,
    require_root_ownership: bool,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    if !template.is_absolute() || !workspace.is_absolute() {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    let source = fs::symlink_metadata(template)?;
    let destination = fs::symlink_metadata(workspace)?;
    verify_pair(
        &source,
        &destination,
        EntryKind::Directory,
        require_root_ownership,
    )?;

    let mut state = TreeHashState {
        digest: Sha256::new(),
        entries: 0,
    };
    state.digest.update(DOMAIN);
    compare_directory(
        template,
        workspace,
        Path::new(""),
        &mut state,
        require_root_ownership,
    )?;
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
    require_root_ownership: bool,
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
        verify_pair(&source, &destination, kind, require_root_ownership)?;
        hash_entry_header(state, path_bytes, kind, source.permissions().mode());

        match kind {
            EntryKind::Directory => compare_directory(
                &source_path,
                &destination_path,
                &child_relative,
                state,
                require_root_ownership,
            )?,
            EntryKind::Regular => {
                let source_digest = hash_file(&source_path, source.len(), require_root_ownership)?;
                let destination_digest =
                    hash_file(&destination_path, destination.len(), require_root_ownership)?;
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
    require_root_ownership: bool,
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
        || require_root_ownership && (source.uid() != 0 || destination.uid() != 0)
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

fn hash_file(
    path: &PathBuf,
    length: u64,
    require_root_ownership: bool,
) -> Result<[u8; 32], GuestRootTreeErrorV1> {
    if length > MAXIMUM_FILE_BYTES {
        return Err(GuestRootTreeErrorV1::InvalidTree);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != length || require_root_ownership && opened.uid() != 0 {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn offline_digest_tracks_bytes_modes_and_links() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let file = root.join("agent");
        fs::write(&file, b"first").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o500)).unwrap();
        std::os::unix::fs::symlink("agent", root.join("current")).unwrap();

        let first = measure_offline_guest_root_template_v1(&root).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&file, b"second").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o500)).unwrap();
        let second = measure_offline_guest_root_template_v1(&root).unwrap();
        assert_ne!(first, second);

        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        let third = measure_offline_guest_root_template_v1(&root).unwrap();
        assert_ne!(second, third);
    }
}
