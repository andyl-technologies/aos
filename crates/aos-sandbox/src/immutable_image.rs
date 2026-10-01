//! Shared bounded immutable-file measurement without any authority conversion.
//!
//! This is nonauthorizing measurement: callers independently select the image,
//! role and original launch custody. Offset-independent hashing retains the
//! original file and rechecks its read-only current name around every digest.

use std::fs::{File, Metadata};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, Mode, OFlags, StatVfsMountFlags, fstatvfs, openat};
use sha2::{Digest as _, Sha256};

const MAXIMUM_IMAGE_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(all(target_os = "linux", feature = "git-helper-mechanics"))]
pub(crate) mod git_helper;

/// Reports unavailable or changed nonauthorizing immutable-file custody.
#[derive(Debug, thiserror::Error)]
pub enum ImmutableImageErrorV1 {
    /// A required file or kernel observation is unavailable.
    #[error("immutable image observation unavailable")]
    Unavailable,
    /// The original name, metadata or bounded content differs.
    #[error("immutable image custody or content differs")]
    Provisioning,
}

/// Retains measured bytes and read-only file custody without granting authority.
pub struct RetainedImmutableFileV1 {
    file: File,
    path: PathBuf,
    digest: [u8; 32],
    identity: (u64, u64, u64),
    maximum_bytes: u64,
    executable: bool,
}

impl RetainedImmutableFileV1 {
    /// Compares one immutable executable against separately selected bytes.
    ///
    /// # Errors
    /// Rejects unavailable, mutable, renamed, oversized or unequal files.
    pub fn open(path: PathBuf, digest: [u8; 32]) -> Result<Self, ImmutableImageErrorV1> {
        Self::open_with_profile(path, Some(digest), MAXIMUM_IMAGE_BYTES, true)
    }

    /// Pins observed immutable image policy, not an independent authorization.
    ///
    /// # Errors
    /// Rejects unavailable, mutable, renamed or oversized unit fragments.
    pub fn observe_fragment(path: PathBuf) -> Result<Self, ImmutableImageErrorV1> {
        Self::open_with_profile(path, None, 64 * 1024, false)
    }

    /// Retains bounded immutable bytes with an optional comparison digest.
    ///
    /// An observed digest or caller-supplied pathname is never image authority.
    ///
    /// # Errors
    /// Rejects unsafe names, metadata, mount flags, lengths or comparison bytes.
    pub fn open_with_profile(
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<Self, ImmutableImageErrorV1> {
        if !path.starts_with("/nix/store")
            || std::fs::canonicalize(&path).map_err(|_| ImmutableImageErrorV1::Provisioning)?
                != path
        {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        let file = File::from(
            openat(
                CWD,
                &path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?,
        );
        Self::retain_with_profile(path, file, expected_digest, maximum_bytes, executable)
    }

    /// Retains an original file and compares its current immutable name.
    ///
    /// This measures custody only; it does not authenticate the file's supplier.
    ///
    /// # Errors
    /// Rejects unsafe names, metadata, mount flags, lengths or comparison bytes.
    pub fn retain_with_profile(
        path: PathBuf,
        file: File,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<Self, ImmutableImageErrorV1> {
        if !path.starts_with("/nix/store")
            || std::fs::canonicalize(&path).map_err(|_| ImmutableImageErrorV1::Provisioning)?
                != path
        {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        let metadata = file
            .metadata()
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
        let mut measured = Self {
            file,
            path,
            digest: [0; 32],
            identity: identity(&metadata),
            maximum_bytes,
            executable,
        };
        measured.validate_names()?;
        let observed = measured.current_digest()?;
        if expected_digest.is_some_and(|digest| digest != observed) {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        measured.digest = observed;
        measured.revalidate()?;
        Ok(measured)
    }

    /// Rechecks the same original immutable file, name and bounded bytes.
    ///
    /// # Errors
    /// Rejects changed or unavailable custody, metadata, mounts or content.
    pub fn revalidate(&self) -> Result<(), ImmutableImageErrorV1> {
        self.validate_names()?;
        if self.current_digest()? != self.digest {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.validate_names()
    }

    /// Compares a process's actual executed inode with this retained file.
    ///
    /// # Errors
    /// Rejects unavailable task-file access or a different executed inode.
    pub fn require_executed(&self, pid: u32) -> Result<(), ImmutableImageErrorV1> {
        let executable = File::open(format!("/proc/{pid}/exe"))
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
        if identity(
            &executable
                .metadata()
                .map_err(|_| ImmutableImageErrorV1::Unavailable)?,
        ) != self.identity
        {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        Ok(())
    }

    /// Borrows the measured immutable pathname, not a launch authorization.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the retained device, inode and byte length.
    pub const fn physical_identity(&self) -> (u64, u64, u64) {
        self.identity
    }

    /// Observes the original file's current device, inode and byte length.
    ///
    /// # Errors
    /// Rejects unavailable descriptor metadata.
    pub fn observed_identity(&self) -> Result<(u64, u64, u64), ImmutableImageErrorV1> {
        self.file
            .metadata()
            .map(|metadata| identity(&metadata))
            .map_err(|_| ImmutableImageErrorV1::Unavailable)
    }

    /// Reads bounded bytes between rechecks without moving the shared offset.
    ///
    /// # Errors
    /// Rejects changed custody, length overflow or incomplete reads.
    pub fn read_bounded(&self) -> Result<Vec<u8>, ImmutableImageErrorV1> {
        self.revalidate()?;
        let length =
            usize::try_from(self.identity.2).map_err(|_| ImmutableImageErrorV1::Provisioning)?;
        let mut bytes = vec![0; length];
        self.file
            .read_exact_at(&mut bytes, 0)
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
        self.revalidate()?;
        Ok(bytes)
    }

    fn validate_names(&self) -> Result<(), ImmutableImageErrorV1> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
        let named = std::fs::symlink_metadata(&self.path)
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
        let mount = fstatvfs(&self.file).map_err(|_| ImmutableImageErrorV1::Unavailable)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7222 != 0
            || self.executable && metadata.mode() & 0o100 == 0
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > self.maximum_bytes
            || identity(&metadata) != self.identity
            || identity(&named) != self.identity
            || !named.is_file()
            || !mount.f_flag.contains(StatVfsMountFlags::RDONLY)
            || self.executable && mount.f_flag.contains(StatVfsMountFlags::NOEXEC)
        {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        Ok(())
    }

    fn current_digest(&self) -> Result<[u8; 32], ImmutableImageErrorV1> {
        let mut hash = Sha256::new();
        let mut buffer = [0; 8192];
        let mut total = 0_u64;
        loop {
            let count = self
                .file
                .read_at(&mut buffer, total)
                .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .filter(|value| *value <= self.maximum_bytes)
                .ok_or(ImmutableImageErrorV1::Unavailable)?;
            hash.update(&buffer[..count]);
        }
        if total != self.identity.2 {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        Ok(hash.finalize().into())
    }
}

/// Rejects file-status flags that do not describe a read-only data descriptor.
///
/// # Errors
/// Rejects path-only, writable, append or truncating descriptors.
pub fn require_readonly_launch_flags(flags: OFlags) -> Result<(), ImmutableImageErrorV1> {
    if flags
        .intersects(OFlags::PATH | OFlags::WRONLY | OFlags::RDWR | OFlags::APPEND | OFlags::TRUNC)
    {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    Ok(())
}

fn identity(metadata: &Metadata) -> (u64, u64, u64) {
    (metadata.dev(), metadata.ino(), metadata.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek as _, SeekFrom, Write as _};

    #[test]
    fn immutable_image_hashing_ignores_and_preserves_shared_file_offset() {
        let mut file = tempfile::tempfile().unwrap();
        let bytes = b"bounded original image bytes";
        file.write_all(bytes).unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
        let mut duplicate = file.try_clone().unwrap();
        let mut measurement = RetainedImmutableFileV1 {
            identity: identity(&file.metadata().unwrap()),
            file,
            path: PathBuf::from("/hash-only-test-not-image-authority"),
            digest: [0; 32],
            maximum_bytes: bytes.len() as u64,
            executable: false,
        };
        let expected: [u8; 32] = Sha256::digest(bytes).into();

        assert_eq!(measurement.current_digest().unwrap(), expected);
        assert_eq!(duplicate.stream_position().unwrap(), 7);
        duplicate.seek(SeekFrom::Start(3)).unwrap();
        assert_eq!(measurement.current_digest().unwrap(), expected);
        assert_eq!(duplicate.stream_position().unwrap(), 3);
        measurement.maximum_bytes -= 1;
        assert!(measurement.current_digest().is_err());
        // Hashing test-local bytes never admits a package/launcher image.
        assert!(measurement.revalidate().is_err());
    }
}
