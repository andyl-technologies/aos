//! Shares the exact retained File identity and entropy operations for private inputs.
//!
//! Expected content is supplied by the independently measured host binding.
//! These operations do not select that binding or issue native authority.

use super::*;
use crate::node_contract::RuntimeError;

pub(super) fn read_revision(file: &File) -> Result<HostRevision, RuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
    if !metadata.is_file() {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(HostRevision {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

pub(super) fn authenticate_private_file(
    process: u32,
    thread: ThreadId,
    host_executable: &ContentRef,
    host_file: &File,
    host_revision: &HostRevision,
) -> Result<(), RuntimeError> {
    if process != std::process::id() || thread != std::thread::current().id() {
        return Err(RuntimeError::ForeignAuthority);
    }
    let current = File::open("/proc/self/exe").map_err(|_| RuntimeError::OwnerUnavailable)?;
    if read_revision(host_file)? != *host_revision
        || read_revision(&current)? != *host_revision
        || host_revision.length != host_executable.length.get()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let domain = b"cnp.blob.v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&(domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update(&host_revision.length.to_be_bytes());
    let mut scratch = [0u8; HOST_EXECUTABLE_STREAM_BYTES];
    let mut offset = 0u64;
    while offset < host_revision.length {
        let remaining = host_revision.length - offset;
        let length = usize::try_from(remaining.min(scratch.len() as u64))
            .map_err(|_| RuntimeError::ResourceLimit)?;
        host_file
            .read_exact_at(&mut scratch[..length], offset)
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        hasher.update(&scratch[..length]);
        offset += length as u64;
    }
    let digest = hasher.finalize().to_hex();
    if host_executable.hash.algorithm != "blake3-256"
        || host_executable.hash.domain != "cnp.blob.v1"
        || host_executable.hash.digest != digest.as_str()
        || host_executable.media_type != "application/octet-stream"
        || read_revision(host_file)? != *host_revision
        || read_revision(&current)? != *host_revision
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    if process != std::process::id() || thread != std::thread::current().id() {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

/// Fills the original key in place; a failed partial key remains with its owner.
pub(super) fn fill_private_key(key: &mut [u8; 32]) -> Result<(), RuntimeError> {
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(key))
        .map_err(|_| RuntimeError::OwnerUnavailable)
}

/// Names only new concrete helper-call operands and forwarding returns.
pub(super) const fn delegation_controls() -> usize {
    std::mem::size_of::<u32>()
        + std::mem::size_of::<ThreadId>()
        + std::mem::size_of::<&ContentRef>()
        + std::mem::size_of::<&File>()
        + std::mem::size_of::<&HostRevision>()
        + std::mem::size_of::<Result<(), RuntimeError>>()
        + std::mem::size_of::<&mut [u8; 32]>()
        + std::mem::size_of::<Result<(), RuntimeError>>()
}
