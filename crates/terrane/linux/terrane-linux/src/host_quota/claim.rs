//! Retains and revalidates a host administrative project-ownership claim.
//!
//! Claim bytes belong to the host embedding's protected administrative format;
//! they are never a client assertion or a Terrane content/wire representation.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Bounds one protected host administrative claim record.
pub const MAX_PROJECT_CLAIM_BYTES: usize = 1024 * 1024;

/// Derives the sole administrative filename for one native filesystem project.
///
/// # Errors
/// Returns an error for the reserved project identifier zero.
pub fn project_claim_name(filesystem_uuid: &[u8; 16], project_id: u32) -> io::Result<String> {
    if project_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero project claim identifier",
        ));
    }
    let mut name = String::with_capacity(48);
    use std::fmt::Write;
    for byte in filesystem_uuid {
        write!(&mut name, "{byte:02x}").map_err(io::Error::other)?;
    }
    write!(&mut name, "-{project_id}.toml").map_err(io::Error::other)?;
    Ok(name)
}

/// Retains a real protected claim and its exact host-authorized canonical bytes.
///
/// The host embedding must choose one common registry for all ledgers sharing a
/// filesystem and project namespace. This type checks native custody, the actual
/// registry incarnation, the derived project filename and immutable bytes on
/// every observation. It does not infer registry placement from a client path.
pub struct RetainedProjectClaim {
    path: PathBuf,
    anchor: PathBuf,
    anchor_bytes: Vec<u8>,
    registry: File,
    registry_device: u64,
    registry_inode: u64,
    filesystem_uuid: [u8; 16],
    project_id: u32,
    expected: Vec<u8>,
}

impl RetainedProjectClaim {
    /// Opens a host-selected registry and verifies an already durable claim.
    ///
    /// The protected sibling anchor bytes bind the registry incarnation across
    /// registry replacement and loss. Both records are re-read on verification;
    /// the embedding supplies their canonical administrative serialization.
    ///
    /// # Errors
    /// Returns errors for unsupported host-root custody, an unsafe or changed
    /// registry, a missing or unsafe record, excessive size or differing bytes.
    pub fn open(
        registry_path: &Path,
        anchor_path: &Path,
        anchor_bytes: &[u8],
        filesystem_uuid: [u8; 16],
        project_id: u32,
        expected: &[u8],
    ) -> io::Result<Self> {
        super::require_host_root_namespace_boundary()?;
        if expected.is_empty()
            || expected.len() > MAX_PROJECT_CLAIM_BYTES
            || anchor_bytes.is_empty()
            || anchor_bytes.len() > 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "project claim size bound exceeded",
            ));
        }
        project_claim_name(&filesystem_uuid, project_id)?;
        let registry = super::open_host_path(registry_path, true)?;
        let metadata = registry.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(io::Error::other(
                "project registry lacks private root custody",
            ));
        }
        let claim = Self {
            path: registry_path.to_path_buf(),
            anchor: anchor_path.to_path_buf(),
            anchor_bytes: anchor_bytes.to_vec(),
            registry,
            registry_device: metadata.dev(),
            registry_inode: metadata.ino(),
            filesystem_uuid,
            project_id,
            expected: expected.to_vec(),
        };
        claim.verify(&filesystem_uuid, project_id)?;
        Ok(claim)
    }

    /// Verifies the current actual registry and the exact claimed native project.
    ///
    /// # Errors
    /// Returns errors for another project's claim, registry replacement or loss,
    /// record mutation, unsafe ownership, malformed record size or native I/O.
    pub fn verify(&self, filesystem_uuid: &[u8; 16], project_id: u32) -> io::Result<()> {
        if filesystem_uuid != &self.filesystem_uuid || project_id != self.project_id {
            return Err(io::Error::other(
                "claim belongs to another filesystem project",
            ));
        }
        let mut anchor = super::open_host_path(&self.anchor, false)?;
        let metadata = anchor.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() != self.anchor_bytes.len() as u64
        {
            return Err(io::Error::other("project registry anchor custody changed"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut anchor)
            .take(1025)
            .read_to_end(&mut bytes)?;
        if bytes != self.anchor_bytes {
            return Err(io::Error::other("project registry anchor changed"));
        }
        let current = super::open_host_path(&self.path, true)?;
        for directory in [&current, &self.registry] {
            let metadata = directory.metadata()?;
            if metadata.uid() != 0
                || metadata.mode() & 0o7777 != 0o700
                || metadata.dev() != self.registry_device
                || metadata.ino() != self.registry_inode
            {
                return Err(io::Error::other("project registry incarnation changed"));
            }
        }
        let name = CString::new(project_claim_name(filesystem_uuid, project_id)?)
            .map_err(|_| io::Error::other("invalid project claim filename"))?;
        // SAFETY: the retained directory and terminated derived filename remain
        // live; no links are followed and nonregular entries cannot block open.
        let raw = unsafe {
            libc::openat(
                self.registry.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new descriptor with unique ownership.
        let mut record = unsafe { File::from_raw_fd(raw) };
        let before = record.metadata()?;
        if !before.is_file()
            || before.uid() != 0
            || before.mode() & 0o7777 != 0o600
            || before.len() != self.expected.len() as u64
        {
            return Err(io::Error::other(
                "project claim lacks exact protected record custody",
            ));
        }
        let mut bytes = Vec::with_capacity(self.expected.len());
        Read::by_ref(&mut record)
            .take(MAX_PROJECT_CLAIM_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        let after = record.metadata()?;
        if bytes != self.expected
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mode() != after.mode()
            || before.uid() != after.uid()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(io::Error::other(
                "project claim changed or belongs to another owner",
            ));
        }
        Ok(())
    }
}
