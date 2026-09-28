//! Measures the fixed helper ELF and loader under immutable lower-store custody.
//!
//! The source-built package records hashes after explicit stripping. The parent
//! retains both files and checks the actually executed inode and loader mapping
//! before releasing index auth to the private child. Subsequent checks retain
//! the same read-only names, contents and process instance; the helper never
//! execs or forks after this observation.

use std::fs::{File, Metadata};
use std::io::Read as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, Mode, OFlags, StatVfsMountFlags, fstatvfs, openat};
use sha2::{Digest as _, Sha256};

use super::super::FloorErrorV1;
use crate::fixed_role_credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};

const MAXIMUM_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_MAPS_BYTES: u64 = 64 * 1024;

pub(super) struct MeasuredHelperImageV1 {
    executable: MeasuredFileV1,
    loader: MeasuredFileV1,
}

pub(super) struct MeasuredFileV1 {
    file: File,
    path: PathBuf,
    digest: [u8; 32],
    identity: (u64, u64, u64),
    maximum_bytes: u64,
    executable: bool,
}

impl MeasuredHelperImageV1 {
    pub(super) fn open() -> Result<Self, FloorErrorV1> {
        let path =
            PathBuf::from(option_env!("AOS_METHOD46_TPM_HELPER").ok_or(FloorErrorV1::Unavailable)?);
        let relative = path
            .strip_prefix("/nix/store")
            .map_err(|_| FloorErrorV1::Provisioning)?;
        if relative.components().count() != 3
            || relative
                .components()
                .nth(1)
                .is_none_or(|part| part.as_os_str() != "libexec")
            || path
                .file_name()
                .is_none_or(|name| name != "aos-method46-tpm-helper")
        {
            return Err(FloorErrorV1::Provisioning);
        }
        let directory = path.parent().ok_or(FloorErrorV1::Provisioning)?;
        let executable_pin = read_pin(directory, "aos-method46-tpm-helper.sha256", 65, 65)?;
        let executable_digest = decode_hash(&executable_pin)?;
        let loader_pin = read_pin(directory, "aos-method46-tpm-helper.loader", 79, 578)?;
        let mut lines = loader_pin.split_inclusive(|byte| *byte == b'\n');
        let loader_path = lines.next().ok_or(FloorErrorV1::Provisioning)?;
        let loader_digest = decode_hash(lines.next().ok_or(FloorErrorV1::Provisioning)?)?;
        if lines.next().is_some() || loader_path.last() != Some(&b'\n') || loader_path.len() > 513 {
            return Err(FloorErrorV1::Provisioning);
        }
        let loader_path = PathBuf::from(
            std::str::from_utf8(&loader_path[..loader_path.len() - 1])
                .map_err(|_| FloorErrorV1::Provisioning)?,
        );
        let mut image = Self {
            executable: MeasuredFileV1::open(path, executable_digest)?,
            loader: MeasuredFileV1::open(loader_path, loader_digest)?,
        };
        image.revalidate()?;
        Ok(image)
    }

    pub(super) fn path(&self) -> &Path {
        &self.executable.path
    }

    pub(super) fn require_executed(&self, pid: u32) -> Result<(), FloorErrorV1> {
        self.executable.require_executed(pid)?;
        let mut maps = String::new();
        File::open(format!("/proc/{pid}/maps"))
            .map_err(|_| FloorErrorV1::Unavailable)?
            .take(MAXIMUM_MAPS_BYTES + 1)
            .read_to_string(&mut maps)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        if maps.len() as u64 > MAXIMUM_MAPS_BYTES {
            return Err(FloorErrorV1::Provisioning);
        }
        let metadata = self
            .loader
            .file
            .metadata()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let device = format!(
            "{:02x}:{:02x}",
            rustix::fs::major(metadata.dev()),
            rustix::fs::minor(metadata.dev())
        );
        let expected_path = self
            .loader
            .path
            .to_str()
            .ok_or(FloorErrorV1::Provisioning)?;
        let mapped = maps.lines().any(|line| {
            let mut fields = line.split_whitespace();
            let _address = fields.next();
            let executable = fields.next().is_some_and(|value| value.contains('x'));
            let _offset = fields.next();
            let observed_device = fields.next();
            let inode = fields.next().and_then(|value| value.parse::<u64>().ok());
            let path = fields.next();
            executable
                && observed_device == Some(device.as_str())
                && inode == Some(metadata.ino())
                && path == Some(expected_path)
                && fields.next().is_none()
        });
        if !mapped {
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(())
    }

    pub(super) fn revalidate(&mut self) -> Result<(), FloorErrorV1> {
        self.executable.revalidate()?;
        self.loader.revalidate()
    }
}

impl MeasuredFileV1 {
    fn open(path: PathBuf, digest: [u8; 32]) -> Result<Self, FloorErrorV1> {
        Self::open_with_profile(path, Some(digest), MAXIMUM_IMAGE_BYTES, true)
    }

    /// Pins observed immutable image policy, not an independent authorization.
    pub(super) fn observe_fragment(path: PathBuf) -> Result<Self, FloorErrorV1> {
        Self::open_with_profile(path, None, 64 * 1024, false)
    }

    pub(super) fn open_pid1(
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<Self, FloorErrorV1> {
        let path =
            PathBuf::from(option_env!("AOS_METHOD46_TPM_PID1").ok_or(FloorErrorV1::Unavailable)?);
        let package = path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or(FloorErrorV1::Provisioning)?;
        let pin = read_pin(
            &package.join("share/aos"),
            "backend-policy-artifact-v2",
            74,
            4096,
        )?;
        if !pin.starts_with(b"AOSBPA02\n") {
            return Err(FloorErrorV1::Provisioning);
        }
        let digest = decode_hash(pin.get(9..74).ok_or(FloorErrorV1::Provisioning)?)?;
        // Retain the actual launch inode, not a reopened package image asserted
        // to be executing. OpenFile runs before service UID/proc confinement.
        let file = launch_image
            .file()
            .try_clone()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let flags = rustix::fs::fcntl_getfl(&file).map_err(|_| FloorErrorV1::Unavailable)?;
        require_readonly_launch_flags(flags)?;
        Self::retain_with_profile(path, file, Some(digest), MAXIMUM_IMAGE_BYTES, true)
    }

    fn open_with_profile(
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<Self, FloorErrorV1> {
        if !path.starts_with("/nix/store")
            || std::fs::canonicalize(&path).map_err(|_| FloorErrorV1::Provisioning)? != path
        {
            return Err(FloorErrorV1::Provisioning);
        }
        let file = File::from(
            openat(
                CWD,
                &path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| FloorErrorV1::Unavailable)?,
        );
        Self::retain_with_profile(path, file, expected_digest, maximum_bytes, executable)
    }

    fn retain_with_profile(
        path: PathBuf,
        file: File,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<Self, FloorErrorV1> {
        if !path.starts_with("/nix/store")
            || std::fs::canonicalize(&path).map_err(|_| FloorErrorV1::Provisioning)? != path
        {
            return Err(FloorErrorV1::Provisioning);
        }
        let metadata = file.metadata().map_err(|_| FloorErrorV1::Unavailable)?;
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
            return Err(FloorErrorV1::Provisioning);
        }
        measured.digest = observed;
        measured.revalidate()?;
        Ok(measured)
    }

    pub(super) fn revalidate(&mut self) -> Result<(), FloorErrorV1> {
        self.validate_names()?;
        if self.current_digest()? != self.digest {
            return Err(FloorErrorV1::Provisioning);
        }
        self.validate_names()
    }

    pub(super) fn require_executed(&self, pid: u32) -> Result<(), FloorErrorV1> {
        let executable =
            File::open(format!("/proc/{pid}/exe")).map_err(|_| FloorErrorV1::Unavailable)?;
        if identity(
            &executable
                .metadata()
                .map_err(|_| FloorErrorV1::Unavailable)?,
        ) != self.identity
        {
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(())
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    fn validate_names(&self) -> Result<(), FloorErrorV1> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let named = std::fs::symlink_metadata(&self.path).map_err(|_| FloorErrorV1::Unavailable)?;
        let mount = fstatvfs(&self.file).map_err(|_| FloorErrorV1::Unavailable)?;
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
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(())
    }

    fn current_digest(&mut self) -> Result<[u8; 32], FloorErrorV1> {
        let mut hash = Sha256::new();
        let mut buffer = [0; 8192];
        let mut total = 0_u64;
        loop {
            let count = self
                .file
                .read_at(&mut buffer, total)
                .map_err(|_| FloorErrorV1::Unavailable)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .filter(|value| *value <= self.maximum_bytes)
                .ok_or(FloorErrorV1::Unavailable)?;
            hash.update(&buffer[..count]);
        }
        if total != self.identity.2 {
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(hash.finalize().into())
    }
}

fn require_readonly_launch_flags(flags: OFlags) -> Result<(), FloorErrorV1> {
    if flags
        .intersects(OFlags::PATH | OFlags::WRONLY | OFlags::RDWR | OFlags::APPEND | OFlags::TRUNC)
    {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

fn identity(metadata: &Metadata) -> (u64, u64, u64) {
    (metadata.dev(), metadata.ino(), metadata.len())
}

fn read_pin(
    directory: &Path,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, FloorErrorV1> {
    let metadata =
        std::fs::symlink_metadata(directory.join(name)).map_err(|_| FloorErrorV1::Provisioning)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o222 != 0
    {
        return Err(FloorErrorV1::Provisioning);
    }
    read_optional_bounded_role_credential_v1(
        directory,
        name,
        minimum,
        maximum,
        false,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(|_| FloorErrorV1::Provisioning)?
    .ok_or(FloorErrorV1::Provisioning)
}

fn decode_hash(bytes: &[u8]) -> Result<[u8; 32], FloorErrorV1> {
    if bytes.len() != 65
        || bytes[64] != b'\n'
        || bytes[..64]
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return Err(FloorErrorV1::Provisioning);
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

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, SeekFrom, Write as _};

    use super::*;

    #[test]
    fn tpm_floor_helper_image_hash_is_exact_lowercase_and_bounded() {
        assert_eq!(
            decode_hash(&[b"09".repeat(32), b"\n".to_vec()].concat()).unwrap(),
            [9; 32]
        );
        for bytes in [
            b"".to_vec(),
            b"A".repeat(65),
            b"0".repeat(64),
            [b"0".repeat(64), b"\n\0".to_vec()].concat(),
        ] {
            assert!(decode_hash(&bytes).is_err());
        }
    }

    #[test]
    fn tpm_floor_pid1_launch_image_rejects_non_readonly_descriptor_flags() {
        assert!(require_readonly_launch_flags(OFlags::RDONLY | OFlags::CLOEXEC).is_ok());
        for flags in [
            OFlags::WRONLY,
            OFlags::RDWR,
            OFlags::PATH,
            OFlags::RDONLY | OFlags::APPEND,
            OFlags::RDONLY | OFlags::TRUNC,
        ] {
            assert!(require_readonly_launch_flags(flags).is_err());
        }
    }

    #[test]
    fn tpm_floor_image_hashing_ignores_and_preserves_shared_file_offset() {
        let mut file = tempfile::tempfile().unwrap();
        let bytes = b"bounded original image bytes";
        file.write_all(bytes).unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
        let mut duplicate = file.try_clone().unwrap();
        let mut measurement = MeasuredFileV1 {
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
