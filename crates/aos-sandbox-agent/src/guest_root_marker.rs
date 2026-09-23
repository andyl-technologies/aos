//! Atomic protected marker publication and physical guest-root readback.
//!
//! The fixed marker is written only after every template entry has been
//! compared with the workspace. A crash before rename leaves no active proof;
//! a crash after rename is resolved by reading back the exact canonical record
//! and remeasuring the tree. This module does not itself authorize a workspace
//! path or an assignment: its privileged caller must supply both from
//! authenticated Storage state and retained mount custody.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::guest_root_publication::GuestRootPublicationProofV1;
use crate::guest_root_tree::compare_guest_root_template_v1;

const MARKER_DIRECTORY: &str = "etc/aos/sandbox-guest-root";
const MARKER_FILE: &str = "publication-v1";
const NEXT_FILE: &str = "publication-v1.next";
const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;

/// Atomically publishes an assignment-bound proof after full tree comparison.
///
/// A matching previously published marker is a readback replay. A conflicting
/// marker fails closed. A torn, inactive `.next` file may be replaced only
/// after its exact protected path and file type have been checked.
///
/// # Errors
///
/// Returns an error for an unprotected path, mismatched tree or proof,
/// conflicting publication, malformed replay, or filesystem failure.
pub fn publish_guest_root_marker_v1(
    template: &Path,
    workspace: &Path,
    proof: GuestRootPublicationProofV1,
) -> Result<(), GuestRootMarkerErrorV1> {
    publish_guest_root_marker_before_v1(template, workspace, proof, || true)
}

/// Publishes the marker only while a protected effect deadline is live.
///
/// The callback is checked after the potentially long complete-tree scan and
/// immediately before each marker mutation. An expired effect never creates
/// launch authority, even if copying finished just before expiry.
///
/// # Errors
///
/// Returns an error for an expired deadline, mismatched physical tree, unsafe
/// marker path, or filesystem failure.
pub fn publish_guest_root_marker_before_v1(
    template: &Path,
    workspace: &Path,
    proof: GuestRootPublicationProofV1,
    mut before_deadline: impl FnMut() -> bool,
) -> Result<(), GuestRootMarkerErrorV1> {
    let measured = compare_guest_root_template_v1(template, workspace)
        .map_err(|_| GuestRootMarkerErrorV1::InvalidPublication)?;
    if measured != proof.root_tree_digest {
        return Err(GuestRootMarkerErrorV1::InvalidPublication);
    }
    check_deadline(&mut before_deadline)?;
    let encoded = proof
        .encode()
        .map_err(|_| GuestRootMarkerErrorV1::InvalidPublication)?;
    let directory = marker_directory(workspace);
    check_deadline(&mut before_deadline)?;
    prepare_directory(workspace, &directory)?;
    let visible = directory.join(MARKER_FILE);
    match fs::symlink_metadata(&visible) {
        Ok(_) => return read_guest_root_marker_v1(template, workspace, proof),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let next = directory.join(NEXT_FILE);
    match fs::symlink_metadata(&next) {
        Ok(metadata) => {
            verify_file(&metadata)?;
            check_deadline(&mut before_deadline)?;
            fs::remove_file(&next)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    check_deadline(&mut before_deadline)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(&next)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    check_deadline(&mut before_deadline)?;
    fs::set_permissions(&next, fs::Permissions::from_mode(0o400))?;
    let directory_file = File::open(&directory)?;
    check_deadline(&mut before_deadline)?;
    rustix::fs::renameat_with(
        &directory_file,
        NEXT_FILE,
        &directory_file,
        MARKER_FILE,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    directory_file.sync_all()?;

    read_guest_root_marker_v1(template, workspace, proof)
}

fn check_deadline(
    before_deadline: &mut impl FnMut() -> bool,
) -> Result<(), GuestRootMarkerErrorV1> {
    if before_deadline() {
        Ok(())
    } else {
        Err(GuestRootMarkerErrorV1::Deadline)
    }
}

/// Reads the exact marker and remeasures every immutable template entry.
///
/// # Errors
///
/// Returns an error if the marker, ownership, assignment-bound proof, or
/// physical package tree differs from the protected expected values.
pub fn read_guest_root_marker_v1(
    template: &Path,
    workspace: &Path,
    expected: GuestRootPublicationProofV1,
) -> Result<(), GuestRootMarkerErrorV1> {
    let directory = marker_directory(workspace);
    verify_directory(&directory)?;
    let marker = directory.join(MARKER_FILE);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(&marker)?;
    verify_file(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(267).read_to_end(&mut bytes)?;
    let observed = GuestRootPublicationProofV1::decode(&bytes)
        .map_err(|_| GuestRootMarkerErrorV1::InvalidPublication)?;
    if observed != expected {
        return Err(GuestRootMarkerErrorV1::InvalidPublication);
    }
    let measured = compare_guest_root_template_v1(template, workspace)
        .map_err(|_| GuestRootMarkerErrorV1::InvalidPublication)?;
    if measured != expected.root_tree_digest {
        return Err(GuestRootMarkerErrorV1::InvalidPublication);
    }
    Ok(())
}

fn marker_directory(workspace: &Path) -> PathBuf {
    workspace.join(MARKER_DIRECTORY)
}

fn prepare_directory(workspace: &Path, directory: &Path) -> Result<(), GuestRootMarkerErrorV1> {
    for component in ["etc", "etc/aos"] {
        verify_directory(&workspace.join(component))?;
    }
    match fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    verify_directory(directory)
}

fn verify_directory(path: &Path) -> Result<(), GuestRootMarkerErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(GuestRootMarkerErrorV1::InvalidPublication);
    }
    Ok(())
}

fn verify_file(metadata: &fs::Metadata) -> Result<(), GuestRootMarkerErrorV1> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 266
    {
        return Err(GuestRootMarkerErrorV1::InvalidPublication);
    }
    Ok(())
}

/// Reports a guest-root marker or physical readback failure.
#[derive(Debug, thiserror::Error)]
pub enum GuestRootMarkerErrorV1 {
    /// The admitted effect window ended before marker publication.
    #[error("guest-root marker publication deadline expired")]
    Deadline,
    /// Publication evidence, ownership, or the physical tree is not exact.
    #[error("guest-root publication is invalid")]
    InvalidPublication,
    /// A filesystem operation failed at the protected marker boundary.
    #[error("guest-root marker I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
