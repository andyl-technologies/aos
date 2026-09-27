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
const ENTITLEMENT_NAME: &str = "public-api-entitlements";
const ENTITLEMENT_KEY_NAME: &str = "public-api-entitlement-public-key";
const OPERATOR_RECOVERY_KEY_NAME: &str = "operator-recovery-controller-key-v1";
const OPERATOR_STORAGE_OWNER_KEY_NAME: &str = "operator-recovery-storage-owner-key-v1";
const PROJECT_AUTHORIZATION_ISSUER_NAME: &str = "project-authorization-issuer-v2";
const CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME: &str = "controller-source-tree-seed-issuer-v1";

/// Retains one fixed protected credential and rejects replacement before use.
pub(crate) struct PinnedSystemdCredential {
    name: &'static str,
    path: PathBuf,
    uid: u32,
    directory_identity: (u64, u64),
    file_identity: CredentialIdentity,
    bytes: Zeroizing<Vec<u8>>,
}

/// Existing operator recovery callers share the same protected file custody.
pub(crate) type PinnedOperatorRecoveryKeyV1 = PinnedSystemdCredential;

impl PinnedSystemdCredential {
    /// Opens the dedicated controller recovery key from systemd credentials.
    pub(crate) fn load() -> Result<Self, PublicApiSessionError> {
        Self::load_named(OPERATOR_RECOVERY_KEY_NAME)
    }

    /// Opens the independently pinned Storage owner public key.
    pub(crate) fn load_storage_owner_public() -> Result<Self, PublicApiSessionError> {
        Self::load_named(OPERATOR_STORAGE_OWNER_KEY_NAME)
    }

    /// Opens the separate public project-authorization issuer pin.
    pub(crate) fn load_project_authorization_issuer_v2() -> Result<Self, PublicApiSessionError> {
        Self::load_named(PROJECT_AUTHORIZATION_ISSUER_NAME)
    }

    /// Opens the separate public Controller Source-tree seed issuer pin.
    pub(crate) fn load_controller_source_tree_seed_issuer_v1() -> Result<Self, PublicApiSessionError>
    {
        Self::load_named(CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME)
    }

    fn load_named(name: &'static str) -> Result<Self, PublicApiSessionError> {
        let path = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or(PublicApiSessionError::Configuration)?;
        Self::open_named(path, name)
    }

    fn open(path: PathBuf) -> Result<Self, PublicApiSessionError> {
        Self::open_named(path, OPERATOR_RECOVERY_KEY_NAME)
    }

    fn open_named(path: PathBuf, name: &'static str) -> Result<Self, PublicApiSessionError> {
        let uid = rustix::process::geteuid().as_raw();
        let directory = open_directory(&path, uid)?;
        let stat =
            rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
        let (bytes, file_identity) = read_one_with_identity(&directory, name, uid)?;
        let retained = Self {
            name,
            path,
            uid,
            directory_identity: (stat.st_dev, stat.st_ino),
            file_identity,
            bytes,
        };
        retained.recheck()?;
        Ok(retained)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reopens the fixed path and proves that its inode and bytes are unchanged.
    pub(crate) fn recheck(&self) -> Result<(), PublicApiSessionError> {
        if rustix::process::geteuid().as_raw() != self.uid {
            return Err(PublicApiSessionError::Stale);
        }
        let directory = open_directory(&self.path, self.uid)?;
        let stat = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Stale)?;
        if (stat.st_dev, stat.st_ino) != self.directory_identity {
            return Err(PublicApiSessionError::Stale);
        }
        let (bytes, identity) = read_one_with_identity(&directory, self.name, self.uid)?;
        if identity != self.file_identity || bytes != self.bytes {
            return Err(PublicApiSessionError::Stale);
        }
        Ok(())
    }
}

/// Reads the current separately provisioned first-capability authority.
///
/// Both names are fixed by the controller. The caller supplies no key path or
/// trust root, and the same protected directory rules as public TLS apply.
pub(crate) fn load_entitlement_credentials()
-> Result<[Zeroizing<Vec<u8>>; 2], PublicApiSessionError> {
    let path = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or(PublicApiSessionError::Configuration)?;
    let uid = rustix::process::geteuid().as_raw();
    let directory = open_directory(&path, uid)?;
    let before = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Configuration)?;
    let bytes = [
        read_one(&directory, ENTITLEMENT_NAME, uid)?,
        read_one(&directory, ENTITLEMENT_KEY_NAME, uid)?,
    ];
    let after = rustix::fs::fstat(&directory).map_err(|_| PublicApiSessionError::Stale)?;
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
        return Err(PublicApiSessionError::Stale);
    }
    Ok(bytes)
}

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
    read_one_with_identity(directory, name, uid).map(|(bytes, _)| bytes)
}

type CredentialIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

fn read_one_with_identity(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
) -> Result<(Zeroizing<Vec<u8>>, CredentialIdentity), PublicApiSessionError> {
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
    Ok((bytes, identity(&after)))
}

fn identity(metadata: &std::fs::Metadata) -> CredentialIdentity {
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

    use ed25519_dalek::SigningKey;

    use crate::hierarchy::source_seed::{
        PinnedControllerSourceTreeSeedIssuerV1, encode_controller_source_tree_seed_credential_v1,
    };

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
        assert!(read_one(&descriptor, PROJECT_AUTHORIZATION_ISSUER_NAME, uid).is_err());

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

    #[test]
    fn recovery_credential_identity_detects_same_bytes_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let key_path = directory.path().join(OPERATOR_RECOVERY_KEY_NAME);
        std::fs::write(&key_path, b"same secret bytes").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let (original, original_identity) =
            read_one_with_identity(&descriptor, OPERATOR_RECOVERY_KEY_NAME, uid).unwrap();

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"same secret bytes").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(replacement, key_path).unwrap();
        let (new_bytes, new_identity) =
            read_one_with_identity(&descriptor, OPERATOR_RECOVERY_KEY_NAME, uid).unwrap();

        assert_eq!(original, new_bytes);
        assert_ne!(original_identity, new_identity);
    }

    #[test]
    fn source_seed_issuer_absence_malformed_bytes_and_rotation_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let name = CONTROLLER_SOURCE_TREE_SEED_ISSUER_NAME;
        let path = directory.path().join(name);

        assert!(read_one_with_identity(&descriptor, name, uid).is_err());

        std::fs::write(&path, [0; 80]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let (malformed, _) = read_one_with_identity(&descriptor, name, uid).unwrap();
        assert!(PinnedControllerSourceTreeSeedIssuerV1::decode(&malformed).is_err());

        let key = SigningKey::from_bytes(&[41; 32]);
        let valid =
            encode_controller_source_tree_seed_credential_v1(7, &key.verifying_key()).unwrap();
        let first = directory.path().join("first");
        std::fs::write(&first, valid).unwrap();
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(first, &path).unwrap();
        let (bytes, identity) = read_one_with_identity(&descriptor, name, uid).unwrap();
        assert_eq!(
            PinnedControllerSourceTreeSeedIssuerV1::decode(&bytes)
                .unwrap()
                .generation(),
            7
        );

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, valid).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::rename(replacement, path).unwrap();
        let (new_bytes, new_identity) = read_one_with_identity(&descriptor, name, uid).unwrap();

        assert_eq!(bytes, new_bytes);
        assert_ne!(identity, new_identity);
    }
}
