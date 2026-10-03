//! Shared bounded immutable-file measurement without any authority conversion.
//!
//! This is nonauthorizing measurement: callers independently select the image,
//! role and original launch custody. Offset-independent hashing retains the
//! original file and rechecks its read-only current name around every digest.

use std::fs::{File, Metadata};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, Mode, OFlags, StatVfsMountFlags, fstatvfs, openat};
use sha2::{Digest as _, Sha256};

use crate::tpm_nv_custody::credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};

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

// This is measurement storage, never selected-profile or role authority. The
// administrative admission owner parks it before entering fallible checks.
#[derive(Default)]
pub(crate) struct PendingImmutableFileV1 {
    file: Option<File>,
    path: Option<PathBuf>,
    measured: Option<RetainedImmutableFileV1>,
    complete: bool,
    bytes: Vec<u8>,
}

impl PendingImmutableFileV1 {
    pub(crate) fn park_original(&mut self, file: File) {
        self.file = Some(file);
    }

    pub(crate) fn original(&self) -> Result<&File, ImmutableImageErrorV1> {
        self.file.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)
    }

    pub(crate) fn open_and_measure(
        &mut self,
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.path = Some(path);
        let path = self.path.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)?;
        require_immutable_path(path)?;
        let file = File::from(
            openat(
                CWD,
                path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?,
        );
        self.file = Some(file);
        self.measure_parked(expected_digest, maximum_bytes, executable)
    }

    pub(crate) fn measure_original(
        &mut self,
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.path = Some(path);
        self.measure_parked(expected_digest, maximum_bytes, executable)
    }

    fn measure_parked(
        &mut self,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<(), ImmutableImageErrorV1> {
        let path = self.path.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)?;
        require_immutable_path(path)?;
        let metadata = self.original()?.metadata()
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;

        // Both removals are checked together. An impossible missing slot still
        // returns its actual originals to this reservoir before refusal.
        let originals = (self.file.take(), self.path.take());
        let (file, path) = match originals {
            (Some(file), Some(path)) => (file, path),
            (file, path) => {
                self.file = file;
                self.path = path;
                return Err(ImmutableImageErrorV1::Provisioning);
            }
        };
        self.measured = Some(RetainedImmutableFileV1 {
            file,
            path,
            digest: [0; 32],
            identity: identity(&metadata),
            maximum_bytes,
            executable,
        });
        self.measured.as_mut().ok_or(ImmutableImageErrorV1::Provisioning)?
            .complete_measurement(expected_digest)?;
        self.complete = true;
        Ok(())
    }

    pub(crate) fn read_bounded(&mut self) -> Result<(), ImmutableImageErrorV1> {
        let measured = self.measurement()?;
        let length = measured.bounded_read_length()?;
        self.bytes = vec![0; length];
        self.measured.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)?
            .read_original_buffer(&mut self.bytes)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn measurement(&self) -> Result<&RetainedImmutableFileV1, ImmutableImageErrorV1> {
        if !self.complete {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.measured.as_ref().ok_or(ImmutableImageErrorV1::Provisioning)
    }

    pub(crate) fn take_measurement(&mut self) -> Option<RetainedImmutableFileV1> {
        if !self.complete {
            return None;
        }
        self.complete = false;
        self.measured.take()
    }

    // Restores only the same already-measured tuple member after an assembly
    // invariant refusal. The administrative attempt remains permanently ended.
    pub(crate) fn restore_measurement(&mut self, measured: Option<RetainedImmutableFileV1>) {
        self.complete = measured.is_some();
        self.measured = measured;
    }
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
        require_immutable_path(&path)?;
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
        require_immutable_path(&path)?;
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
        measured.complete_measurement(expected_digest)?;
        Ok(measured)
    }

    fn complete_measurement(
        &mut self,
        expected_digest: Option<[u8; 32]>,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.validate_names()?;
        let observed = self.current_digest()?;
        if expected_digest.is_some_and(|digest| digest != observed) {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.digest = observed;
        self.revalidate()
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

    // Only the genuine Core offline owner selects this original. Park the
    // returned duplicate before its subsequent image/purpose bookends; this
    // private seam adds no path, executable selection or authority factory.
    pub(crate) fn duplicate_nix_offline_original_into(
        &self, slot: &mut Option<OwnedFd>,
    ) -> std::io::Result<()> {
        if slot.is_some() {
            return Err(std::io::Error::other("offline executable slot is occupied"));
        }
        *slot = Some(rustix::io::fcntl_dupfd_cloexec(&self.file, 3)?);
        Ok(())
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

    /// Compares fixed offline helper executable DATA from the same original pidfd.
    ///
    /// The lower reservoir owns the actual executed inode before HELLO. A
    /// returned tuple alone is not an image proof; this method obtains it only
    /// through that reservoir's original-process and liveness bookends. The
    /// purpose caller still owns loader, startup, MAC and session comparisons.
    ///
    /// # Errors
    /// Returns the actual lower descriptor/process error. `Ok(false)` reports
    /// an original inode mismatch without inventing a native cause. Neither
    /// this method nor the lower DATA holder establishes process retirement.
    pub fn matches_nix_offline_executed_original_v5(
        &self,
        original: &aos_sandbox_linux::pidfd::PidFd,
        observations: &mut aos_sandbox_linux::pidfd::PidFdProcObservationsV1,
    ) -> Result<bool, aos_sandbox_linux::Error> {
        Ok(observations.observe_nix_offline_helper_executable_v1(original)? == self.identity)
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

    /// Compares bounded maps DATA with this original loader's current identity.
    ///
    /// This is the canonical helper loader-mapping comparison, not a process
    /// admission. A genuine caller must acquire the maps through its retained
    /// original process and apply executable, liveness and purpose checks.
    ///
    /// # Errors
    /// Rejects unavailable original metadata, a non-UTF8 selected path or an
    /// oversized maps record. `Ok(false)` reports no matching executable map.
    pub fn mapped_in_helper_data_v5(&self, maps: &str) -> Result<bool, ImmutableImageErrorV1> {
        if maps.len() > 64 * 1024 {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        let (device_id, expected_inode, _) = self.observed_identity()?;
        let device = format!(
            "{:02x}:{:02x}",
            rustix::fs::major(device_id),
            rustix::fs::minor(device_id)
        );
        let expected_path = self.path().to_str().ok_or(ImmutableImageErrorV1::Provisioning)?;
        Ok(maps.lines().any(|line| {
            let mut fields = line.split_whitespace();
            let _address = fields.next();
            let executable = fields.next().is_some_and(|value| value.contains('x'));
            let _offset = fields.next();
            let observed_device = fields.next();
            let inode = fields.next().and_then(|value| value.parse::<u64>().ok());
            let path = fields.next();
            executable
                && observed_device == Some(device.as_str())
                && inode == Some(expected_inode)
                && path == Some(expected_path)
                && fields.next().is_none()
        }))
    }

    /// Reads bounded bytes between rechecks without moving the shared offset.
    ///
    /// # Errors
    /// Rejects changed custody, length overflow or incomplete reads.
    pub fn read_bounded(&self) -> Result<Vec<u8>, ImmutableImageErrorV1> {
        let length = self.bounded_read_length()?;
        let mut bytes = vec![0; length];
        self.read_original_buffer(&mut bytes)?;
        Ok(bytes)
    }

    fn bounded_read_length(&self) -> Result<usize, ImmutableImageErrorV1> {
        self.revalidate()?;
        usize::try_from(self.identity.2).map_err(|_| ImmutableImageErrorV1::Provisioning)
    }

    fn read_original_buffer(&self, bytes: &mut [u8]) -> Result<(), ImmutableImageErrorV1> {
        self.file
            .read_exact_at(bytes, 0)
            .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
        self.revalidate()
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

fn require_immutable_path(path: &Path) -> Result<(), ImmutableImageErrorV1> {
    if !path.starts_with("/nix/store")
        || std::fs::canonicalize(path).map_err(|_| ImmutableImageErrorV1::Provisioning)? != path
    {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    Ok(())
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

/// Measures an original PID 1 file against the image-built backend artifact.
///
/// The file must come from the caller's genuine original launch capture. This
/// shared measurement does not authenticate its supplier, confer floor or
/// worker authority, or establish continuous identity after manager reexec.
///
/// # Errors
///
/// Rejects missing compiled selection, unsafe artifact metadata, malformed
/// pins, unavailable cloning, writable descriptors, or changed image custody.
pub fn retain_original_backend_pid1_v1(
    original: &File,
) -> Result<RetainedImmutableFileV1, ImmutableImageErrorV1> {
    let path = PathBuf::from(
        option_env!("AOS_METHOD46_TPM_PID1").ok_or(ImmutableImageErrorV1::Unavailable)?,
    );
    let package = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or(ImmutableImageErrorV1::Provisioning)?;
    let pin = read_immutable_image_pin_v1(
        &package.join("share/aos"),
        "backend-policy-artifact-v2",
        74,
        4096,
    )?;
    if !pin.starts_with(b"AOSBPA02\n") {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    let digest = decode_immutable_sha256_pin_v1(
        pin.get(9..74).ok_or(ImmutableImageErrorV1::Provisioning)?,
    )?;

    // Clone this original inode, never reopen a nominally selected PID 1 image.
    let file = original
        .try_clone()
        .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
    let flags = rustix::fs::fcntl_getfl(&file)
        .map_err(|_| ImmutableImageErrorV1::Unavailable)?;
    require_readonly_launch_flags(flags)?;
    RetainedImmutableFileV1::retain_with_profile(
        path,
        file,
        Some(digest),
        MAXIMUM_IMAGE_BYTES,
        true,
    )
}

/// Reads bounded root-owned immutable image-pin DATA through the shared reader.
///
/// A pathname and returned bytes are not independent image authorization.
///
/// # Errors
///
/// Rejects missing pins, unsafe metadata, bounds, or incomplete reads.
pub fn read_immutable_image_pin_v1(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, ImmutableImageErrorV1> {
    let metadata = std::fs::symlink_metadata(directory.join(name))
        .map_err(|_| ImmutableImageErrorV1::Provisioning)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o222 != 0
    {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    read_optional_bounded_role_credential_v1(
        directory,
        name,
        minimum,
        maximum,
        false,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(|_| ImmutableImageErrorV1::Provisioning)?
    .ok_or(ImmutableImageErrorV1::Provisioning)
}

/// Decodes exact lowercase SHA-256 pin DATA terminated by one newline.
///
/// # Errors
///
/// Rejects any length, character, or terminator outside the canonical form.
pub fn decode_immutable_sha256_pin_v1(
    bytes: &[u8],
) -> Result<[u8; 32], ImmutableImageErrorV1> {
    if bytes.len() != 65
        || bytes[64] != b'\n'
        || bytes[..64]
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return Err(ImmutableImageErrorV1::Provisioning);
    }
    let mut digest = [0; 32];
    for (index, pair) in bytes[..64].chunks_exact(2).enumerate() {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        digest[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(digest)
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
