//! Loads and rechecks fixed systemd credentials through protected directories.
//!
//! Ancestors are root-owned until ownership transitions to the service UID.
//! Symlinks, writable ancestors, nonregular files, excess bytes, and changed
//! file metadata are rejected. No key or certificate bytes appear in errors.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags, open, openat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::PublicApiSessionError;

const MAXIMUM_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const NAMES: [&str; 4] = [
    "public-api-server-cert",
    "public-api-server-key",
    "public-api-client-ca",
    "public-api-principals",
];

pub(super) struct Credentials {
    path: PathBuf,
    uid: u32,
    directory_identity: (u64, u64),
    digests: [[u8; 32]; 4],
}

impl Credentials {
    pub(super) fn load() -> Result<(Self, [Zeroizing<Vec<u8>>; 4]), PublicApiSessionError> {
        let path = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or(PublicApiSessionError::Configuration)?;
        let uid = rustix::process::geteuid().as_raw();
        let directory = open_directory(&path, uid)?;
        let stat =
            rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
        let bytes = read_all(&directory, uid)?;
        let digests = std::array::from_fn(|index| Sha256::digest(&*bytes[index]).into());
        let retained = Self {
            path,
            uid,
            directory_identity: (stat.st_dev, stat.st_ino),
            digests,
        };
        retained.recheck()?;
        Ok((retained, bytes))
    }

    pub(super) fn recheck(&self) -> Result<(), PublicApiSessionError> {
        if rustix::process::geteuid().as_raw() != self.uid {
            return Err(PublicApiSessionError::Stale);
        }
        let directory = open_directory(&self.path, self.uid)?;
        let stat = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Stale)?;
        if (stat.st_dev, stat.st_ino) != self.directory_identity {
            return Err(PublicApiSessionError::Stale);
        }
        let bytes = read_all(&directory, self.uid)?;
        for (bytes, expected) in bytes.iter().zip(self.digests) {
            let actual: [u8; 32] = Sha256::digest(&**bytes).into();
            if actual != expected {
                return Err(PublicApiSessionError::Stale);
            }
        }
        Ok(())
    }
}

fn open_directory(path: &Path, uid: u32) -> Result<OwnedFd, PublicApiSessionError> {
    if !path.is_absolute() {
        return Err(PublicApiSessionError::Configuration);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open("/", flags, Mode::empty()).map_err(|_| PublicApiSessionError::Configuration)?;
    let mut service_owned = false;
    for component in path.components() {
        let stat =
            rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
        if stat.st_mode & 0o022 != 0
            || (stat.st_uid != 0 && stat.st_uid != uid)
            || (service_owned && stat.st_uid != uid)
        {
            return Err(PublicApiSessionError::Configuration);
        }
        service_owned |= stat.st_uid == uid;
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .map_err(|_| PublicApiSessionError::Configuration)?;
            }
            _ => return Err(PublicApiSessionError::Configuration),
        }
    }
    let stat = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
    if stat.st_uid != uid || stat.st_mode & 0o077 != 0 {
        return Err(PublicApiSessionError::Configuration);
    }
    Ok(directory)
}

fn read_all(
    directory: &OwnedFd,
    uid: u32,
) -> Result<[Zeroizing<Vec<u8>>; 4], PublicApiSessionError> {
    Ok([
        read_one(directory, NAMES[0], uid)?,
        read_one(directory, NAMES[1], uid)?,
        read_one(directory, NAMES[2], uid)?,
        read_one(directory, NAMES[3], uid)?,
    ])
}

fn read_one(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
) -> Result<Zeroizing<Vec<u8>>, PublicApiSessionError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| PublicApiSessionError::Configuration)?;
    let mut file = File::from(descriptor);
    let before = file
        .metadata()
        .map_err(|_| PublicApiSessionError::Configuration)?;
    if !before.is_file()
        || before.uid() != uid
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAXIMUM_CREDENTIAL_BYTES
    {
        return Err(PublicApiSessionError::Configuration);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(MAXIMUM_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PublicApiSessionError::Configuration)?;
    let after = file
        .metadata()
        .map_err(|_| PublicApiSessionError::Configuration)?;
    if before.len() != bytes.len() as u64 || identity(&before) != identity(&after) {
        return Err(PublicApiSessionError::Stale);
    }
    Ok(bytes)
}

fn identity(
    metadata: &std::fs::Metadata,
) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn accepts_only_private_single_link_regular_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let path = directory.path().join("credential");
        std::fs::write(&path, b"protected bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let bytes = read_one(&descriptor, "credential", uid).unwrap();

        assert_eq!(&**bytes, b"protected bytes");
        assert!(read_one(&descriptor, "credential", uid.wrapping_add(1)).is_err());

        symlink("credential", directory.path().join("symlink")).unwrap();
        assert!(read_one(&descriptor, "symlink", uid).is_err());

        std::fs::hard_link(&path, directory.path().join("hardlink")).unwrap();
        assert!(read_one(&descriptor, "credential", uid).is_err());
        assert!(read_one(&descriptor, "hardlink", uid).is_err());
    }

    #[test]
    fn rejects_public_empty_oversized_and_nonregular_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        for (name, bytes, mode) in [
            ("public", vec![1], 0o444),
            ("empty", vec![], 0o400),
            (
                "oversized",
                vec![1; MAXIMUM_CREDENTIAL_BYTES as usize + 1],
                0o400,
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();

            assert!(read_one(&descriptor, name, uid).is_err());
        }
        std::fs::create_dir(directory.path().join("directory")).unwrap();

        assert!(read_one(&descriptor, "directory", uid).is_err());
        assert!(open_directory(Path::new("relative"), uid).is_err());
    }
}
