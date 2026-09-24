//! Retained protected endpoint files and path-bound currentness checks.
//!
//! A loaded endpoint retains the directory, manifest, and two role-local
//! secret descriptors. Each check compares both those retained objects and a
//! fresh no-follow reopening through the captured absolute path. Opposite-role
//! secret names are checked for absence with metadata lookup and are never
//! opened.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use aos_sandbox_linux::protected_file::{self, ExactReadError};
use ed25519_dalek::SigningKey;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, Stat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::BrokerSessionSecurityError;
use crate::manifest::{BROKER_SESSION_SECURITY_MANIFEST_BYTES, BrokerSessionSecurityManifestV1};

pub(crate) const MANIFEST_NAME: &str = "broker-session-manifest";
const CLIENT_HELLO_KEY_NAME: &str = "client-hello-signing-key";
const CLIENT_RECORD_KEY_NAME: &str = "client-record-signing-key";
const BROKER_HELLO_KEY_NAME: &str = "broker-hello-signing-key";
const BROKER_OUTCOME_KEY_NAME: &str = "broker-outcome-signing-key";
const SECRET_BYTES: usize = 48;
const SECRET_KEY_ID_BYTES: usize = 16;
const SECRET_SEED_BYTES: usize = 32;

#[derive(Clone, Copy)]
pub(crate) enum EndpointRole {
    Client,
    Broker,
}

impl EndpointRole {
    const fn local_files(self) -> [(&'static str, &'static str, usize); 2] {
        match self {
            Self::Client => [
                (CLIENT_HELLO_KEY_NAME, "client hello key", 0),
                (CLIENT_RECORD_KEY_NAME, "client record key", 2),
            ],
            Self::Broker => [
                (BROKER_HELLO_KEY_NAME, "broker hello key", 1),
                (BROKER_OUTCOME_KEY_NAME, "broker outcome key", 3),
            ],
        }
    }

    const fn opposite_files(self) -> [&'static str; 2] {
        match self {
            Self::Client => [BROKER_HELLO_KEY_NAME, BROKER_OUTCOME_KEY_NAME],
            Self::Broker => [CLIENT_HELLO_KEY_NAME, CLIENT_RECORD_KEY_NAME],
        }
    }
}

// Exclude st_blocks: filesystem writeback may change allocation after the
// endpoint is sealed, while identity, timestamps, and exact bytes stay fixed.
#[derive(Clone, Copy, Eq, PartialEq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
    link_count: u64,
    special_device: u64,
    size: i64,
    block_size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl MetadataSnapshot {
    const fn capture(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            owner: stat.st_uid,
            group: stat.st_gid,
            link_count: stat.st_nlink,
            special_device: stat.st_rdev,
            size: stat.st_size,
            block_size: stat.st_blksize,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

struct ManifestFile {
    descriptor: OwnedFd,
    metadata: MetadataSnapshot,
    exact: [u8; BROKER_SESSION_SECURITY_MANIFEST_BYTES],
    digest: [u8; 32],
}

pub(crate) struct SecretFile {
    descriptor: OwnedFd,
    metadata: MetadataSnapshot,
    exact: Box<Zeroizing<[u8; SECRET_BYTES]>>,
    label: &'static str,
}

impl SecretFile {
    pub(crate) fn key_id(&self) -> &[u8] {
        &self.exact[..SECRET_KEY_ID_BYTES]
    }

    pub(crate) fn seed(&self) -> Result<&[u8; SECRET_SEED_BYTES], BrokerSessionSecurityError> {
        let seed = &self.exact[SECRET_KEY_ID_BYTES..];
        seed.try_into()
            .map_err(|_| BrokerSessionSecurityError::KeyMaterial { object: self.label })
    }
}

/// Retains one role's protected file set without exposing its descriptors.
pub(crate) struct ProtectedEndpointFiles {
    path: PathBuf,
    owner: u32,
    role: EndpointRole,
    directory: OwnedFd,
    directory_metadata: MetadataSnapshot,
    manifest_file: ManifestFile,
    secrets: [SecretFile; 2],
    manifest: BrokerSessionSecurityManifestV1,
}

impl ProtectedEndpointFiles {
    pub(crate) fn load(
        path: &Path,
        role: EndpointRole,
    ) -> Result<Self, BrokerSessionSecurityError> {
        validate_absolute_fixed_path(path)?;
        let owner = rustix::process::geteuid().as_raw();
        let directory = open_directory(path)?;
        let directory_metadata = validate_directory(&directory, owner)?;
        require_opposite_absent(&directory, role)?;

        let manifest_file = load_manifest(&directory, owner)?;
        rustix::fs::flock(
            &manifest_file.descriptor,
            FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::AGAIN {
                BrokerSessionSecurityError::AlreadyInUse
            } else {
                BrokerSessionSecurityError::filesystem("manifest", "lock")
            }
        })?;
        let manifest = BrokerSessionSecurityManifestV1::decode(&manifest_file.exact)?;
        manifest.require_all_active()?;

        let [first, second] = role.local_files();
        let secrets = [
            load_secret(&directory, owner, first.0, first.1)?,
            load_secret(&directory, owner, second.0, second.1)?,
        ];
        validate_local_keys(&manifest, &secrets, [first.2, second.2])?;

        let files = Self {
            path: path.to_path_buf(),
            owner,
            role,
            directory,
            directory_metadata,
            manifest_file,
            secrets,
            manifest,
        };
        files.revalidate()?;
        Ok(files)
    }

    pub(crate) const fn manifest(&self) -> &BrokerSessionSecurityManifestV1 {
        &self.manifest
    }

    pub(crate) fn client_hello_seed(
        &self,
    ) -> Result<&[u8; SECRET_SEED_BYTES], BrokerSessionSecurityError> {
        if !matches!(self.role, EndpointRole::Client) {
            return Err(BrokerSessionSecurityError::KeyMaterial {
                object: "client hello key",
            });
        }
        self.secrets[0].seed()
    }

    pub(crate) fn broker_hello_seed(
        &self,
    ) -> Result<&[u8; SECRET_SEED_BYTES], BrokerSessionSecurityError> {
        if !matches!(self.role, EndpointRole::Broker) {
            return Err(BrokerSessionSecurityError::KeyMaterial {
                object: "broker hello key",
            });
        }
        self.secrets[0].seed()
    }

    pub(crate) fn client_record_seed(
        &self,
    ) -> Result<&[u8; SECRET_SEED_BYTES], BrokerSessionSecurityError> {
        if !matches!(self.role, EndpointRole::Client) {
            return Err(BrokerSessionSecurityError::KeyMaterial {
                object: "client record key",
            });
        }
        self.secrets[1].seed()
    }

    pub(crate) fn broker_outcome_seed(
        &self,
    ) -> Result<&[u8; SECRET_SEED_BYTES], BrokerSessionSecurityError> {
        if !matches!(self.role, EndpointRole::Broker) {
            return Err(BrokerSessionSecurityError::KeyMaterial {
                object: "broker outcome key",
            });
        }
        self.secrets[1].seed()
    }

    pub(crate) fn revalidate(&self) -> Result<(), BrokerSessionSecurityError> {
        if rustix::process::geteuid().as_raw() != self.owner {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        validate_retained_directory(&self.directory, self.owner, self.directory_metadata)?;
        require_opposite_absent(&self.directory, self.role)?;
        validate_retained_manifest(&self.manifest_file, self.owner)?;
        for secret in &self.secrets {
            validate_retained_secret(secret, self.owner)?;
        }

        let reopened_directory =
            open_directory(&self.path).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if validate_directory(&reopened_directory, self.owner)? != self.directory_metadata {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        require_opposite_absent(&reopened_directory, self.role)?;
        let reopened_manifest = load_manifest(&reopened_directory, self.owner)?;
        if reopened_manifest.metadata != self.manifest_file.metadata
            || reopened_manifest.digest != self.manifest_file.digest
            || reopened_manifest.exact != self.manifest_file.exact
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        for (secret, (name, label, _)) in self.secrets.iter().zip(self.role.local_files()) {
            let reopened = load_secret(&reopened_directory, self.owner, name, label)?;
            if reopened.metadata != secret.metadata || reopened.exact[..] != secret.exact[..] {
                return Err(BrokerSessionSecurityError::Currentness);
            }
        }
        Ok(())
    }
}

fn validate_absolute_fixed_path(path: &Path) -> Result<(), BrokerSessionSecurityError> {
    if !protected_file::is_absolute_fixed_path(path) {
        return Err(BrokerSessionSecurityError::DirectoryPath);
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<OwnedFd, BrokerSessionSecurityError> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BrokerSessionSecurityError::filesystem("endpoint directory", "open"))
}

fn validate_directory(
    descriptor: &OwnedFd,
    owner: u32,
) -> Result<MetadataSnapshot, BrokerSessionSecurityError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| BrokerSessionSecurityError::filesystem("endpoint directory", "inspect"))?;
    require_directory_metadata(&stat, owner)?;
    Ok(MetadataSnapshot::capture(&stat))
}

fn require_directory_metadata(stat: &Stat, owner: u32) -> Result<(), BrokerSessionSecurityError> {
    if FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == owner
        && stat.st_mode & 0o7777 == 0o500
    {
        Ok(())
    } else {
        Err(BrokerSessionSecurityError::Metadata {
            object: "endpoint directory",
        })
    }
}

fn validate_retained_directory(
    descriptor: &OwnedFd,
    owner: u32,
    expected: MetadataSnapshot,
) -> Result<(), BrokerSessionSecurityError> {
    if validate_directory(descriptor, owner)? == expected {
        Ok(())
    } else {
        Err(BrokerSessionSecurityError::Currentness)
    }
}

fn require_opposite_absent(
    directory: &OwnedFd,
    role: EndpointRole,
) -> Result<(), BrokerSessionSecurityError> {
    for name in role.opposite_files() {
        match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Ok(_) => return Err(BrokerSessionSecurityError::OppositeRoleSecret),
            Err(_) => {
                return Err(BrokerSessionSecurityError::filesystem(
                    "opposite-role secret name",
                    "inspect",
                ));
            }
        }
    }
    Ok(())
}

fn load_manifest(
    directory: &OwnedFd,
    owner: u32,
) -> Result<ManifestFile, BrokerSessionSecurityError> {
    let descriptor = open_child(directory, MANIFEST_NAME, "manifest")?;
    let before = validate_child_metadata(
        &descriptor,
        owner,
        BROKER_SESSION_SECURITY_MANIFEST_BYTES,
        "manifest",
    )?;
    let exact =
        read_exact_positioned::<BROKER_SESSION_SECURITY_MANIFEST_BYTES>(&descriptor, "manifest")?;
    let repeated =
        read_exact_positioned::<BROKER_SESSION_SECURITY_MANIFEST_BYTES>(&descriptor, "manifest")?;
    let after = validate_child_metadata(
        &descriptor,
        owner,
        BROKER_SESSION_SECURITY_MANIFEST_BYTES,
        "manifest",
    )?;
    if before != after || exact != repeated {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    let digest = Sha256::digest(exact).into();
    Ok(ManifestFile {
        descriptor,
        metadata: before,
        exact,
        digest,
    })
}

fn load_secret(
    directory: &OwnedFd,
    owner: u32,
    name: &'static str,
    label: &'static str,
) -> Result<SecretFile, BrokerSessionSecurityError> {
    load_secret_with_between_reads(directory, owner, name, label, || Ok(()))
}

fn load_secret_with_between_reads<Between>(
    directory: &OwnedFd,
    owner: u32,
    name: &'static str,
    label: &'static str,
    between_reads: Between,
) -> Result<SecretFile, BrokerSessionSecurityError>
where
    Between: FnOnce() -> Result<(), BrokerSessionSecurityError>,
{
    let descriptor = open_child(directory, name, label)?;
    let before = validate_child_metadata(&descriptor, owner, SECRET_BYTES, label)?;
    let exact = read_secret_positioned(&descriptor, label)?;
    between_reads()?;
    let repeated = read_secret_positioned(&descriptor, label)?;
    let after = validate_child_metadata(&descriptor, owner, SECRET_BYTES, label)?;
    if before != after || exact[..] != repeated[..] {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(SecretFile {
        descriptor,
        metadata: before,
        exact,
        label,
    })
}

fn open_child(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
) -> Result<OwnedFd, BrokerSessionSecurityError> {
    protected_file::open_nofollow_child(directory, name)
        .map_err(|_| BrokerSessionSecurityError::filesystem(label, "open"))
}

fn validate_child_metadata(
    descriptor: &OwnedFd,
    owner: u32,
    exact_size: usize,
    label: &'static str,
) -> Result<MetadataSnapshot, BrokerSessionSecurityError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| BrokerSessionSecurityError::filesystem(label, "inspect"))?;
    let expected_size = i64::try_from(exact_size)
        .map_err(|_| BrokerSessionSecurityError::Metadata { object: label })?;
    require_child_metadata(&stat, owner, expected_size, label)?;
    Ok(MetadataSnapshot::capture(&stat))
}

fn require_child_metadata(
    stat: &Stat,
    owner: u32,
    expected_size: i64,
    label: &'static str,
) -> Result<(), BrokerSessionSecurityError> {
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == owner
        && stat.st_nlink == 1
        && stat.st_mode & 0o7777 == 0o400
        && stat.st_size == expected_size
    {
        Ok(())
    } else {
        Err(BrokerSessionSecurityError::Metadata { object: label })
    }
}

fn read_exact_positioned<const N: usize>(
    descriptor: &OwnedFd,
    label: &'static str,
) -> Result<[u8; N], BrokerSessionSecurityError> {
    let mut output = [0_u8; N];
    protected_file::read_exact_positioned(descriptor, &mut output)
        .map_err(|error| exact_read_error(error, label))?;
    Ok(output)
}

fn exact_read_error(error: ExactReadError, label: &'static str) -> BrokerSessionSecurityError {
    match error {
        ExactReadError::Read => BrokerSessionSecurityError::filesystem(label, "read"),
        ExactReadError::TrailingBytes => BrokerSessionSecurityError::Metadata { object: label },
    }
}

fn read_secret_positioned(
    descriptor: &OwnedFd,
    label: &'static str,
) -> Result<Box<Zeroizing<[u8; SECRET_BYTES]>>, BrokerSessionSecurityError> {
    read_secret_with(label, |buffer, position| {
        rustix::io::pread(descriptor, buffer, position)
    })
}

fn read_secret_with(
    label: &'static str,
    read_at: impl FnMut(&mut [u8], u64) -> rustix::io::Result<usize>,
) -> Result<Box<Zeroizing<[u8; SECRET_BYTES]>>, BrokerSessionSecurityError> {
    // Secret bytes enter their final heap allocation directly. Every early
    // return drops this already-zeroizing owner, including partial reads.
    let mut output = Box::new(Zeroizing::new([0_u8; SECRET_BYTES]));
    protected_file::read_exact_positioned_with(&mut output[..], read_at)
        .map_err(|error| exact_read_error(error, label))?;
    Ok(output)
}

fn validate_retained_manifest(
    file: &ManifestFile,
    owner: u32,
) -> Result<(), BrokerSessionSecurityError> {
    let before = validate_child_metadata(
        &file.descriptor,
        owner,
        BROKER_SESSION_SECURITY_MANIFEST_BYTES,
        "manifest",
    )?;
    let exact = read_exact_positioned::<BROKER_SESSION_SECURITY_MANIFEST_BYTES>(
        &file.descriptor,
        "manifest",
    )?;
    let repeated = read_exact_positioned::<BROKER_SESSION_SECURITY_MANIFEST_BYTES>(
        &file.descriptor,
        "manifest",
    )?;
    let after = validate_child_metadata(
        &file.descriptor,
        owner,
        BROKER_SESSION_SECURITY_MANIFEST_BYTES,
        "manifest",
    )?;
    if before == file.metadata
        && after == before
        && exact == file.exact
        && repeated == exact
        && <[u8; 32]>::from(Sha256::digest(exact)) == file.digest
    {
        Ok(())
    } else {
        Err(BrokerSessionSecurityError::Currentness)
    }
}

fn validate_retained_secret(
    file: &SecretFile,
    owner: u32,
) -> Result<(), BrokerSessionSecurityError> {
    let before = validate_child_metadata(&file.descriptor, owner, SECRET_BYTES, file.label)?;
    let exact = read_secret_positioned(&file.descriptor, file.label)?;
    let repeated = read_secret_positioned(&file.descriptor, file.label)?;
    let after = validate_child_metadata(&file.descriptor, owner, SECRET_BYTES, file.label)?;
    if before == file.metadata
        && after == before
        && exact[..] == file.exact[..]
        && repeated[..] == exact[..]
    {
        Ok(())
    } else {
        Err(BrokerSessionSecurityError::Currentness)
    }
}

fn validate_local_keys(
    manifest: &BrokerSessionSecurityManifestV1,
    secrets: &[SecretFile; 2],
    indices: [usize; 2],
) -> Result<(), BrokerSessionSecurityError> {
    for (secret, index) in secrets.iter().zip(indices) {
        let pin = &manifest.key_pins()[index];
        let seed = secret.seed()?;
        if secret.key_id() != pin.signer().key_id() || seed.iter().all(|byte| *byte == 0) {
            return Err(BrokerSessionSecurityError::KeyMaterial {
                object: secret.label,
            });
        }
        // The crate enables ed25519-dalek's `zeroize` feature, so this
        // temporary wipes its secret key bytes on drop.
        let signing_key = SigningKey::from_bytes(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let fingerprint = <[u8; 32]>::from(Sha256::digest(public_key));
        if &public_key != pin.public_key() || fingerprint != pin.signer().public_key_digest() {
            return Err(BrokerSessionSecurityError::KeyMaterial {
                object: secret.label,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    struct ScriptedReader {
        steps: VecDeque<rustix::io::Result<Vec<u8>>>,
    }

    impl ScriptedReader {
        fn read_at(&mut self, output: &mut [u8], _position: u64) -> rustix::io::Result<usize> {
            let bytes = self.steps.pop_front().unwrap_or(Ok(Vec::new()))?;
            if bytes.len() > output.len() {
                return Ok(output.len() + 1);
            }
            output[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    #[test]
    fn broker_directory_and_child_open_reject_final_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let endpoint = temporary.path().join("endpoint");
        fs::create_dir(&endpoint).unwrap();
        symlink(&endpoint, temporary.path().join("endpoint-link")).unwrap();
        fs::write(endpoint.join("secret"), [0x41_u8; SECRET_BYTES]).unwrap();
        symlink("secret", endpoint.join("secret-link")).unwrap();

        assert!(open_directory(&endpoint).is_ok());
        assert!(open_directory(&temporary.path().join("endpoint-link")).is_err());
        let directory = open_directory(&endpoint).unwrap();
        assert!(open_child(&directory, "secret-link", "secret").is_err());
    }

    #[test]
    fn renamed_secret_name_is_detected_against_retained_descriptor() {
        let temporary = tempfile::tempdir().unwrap();
        let secret_path = temporary.path().join("secret");
        fs::write(&secret_path, [0x41_u8; SECRET_BYTES]).unwrap();
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o400)).unwrap();
        let directory = open_directory(temporary.path()).unwrap();
        let owner = rustix::process::geteuid().as_raw();
        let retained = load_secret(&directory, owner, "secret", "secret").unwrap();

        fs::rename(&secret_path, temporary.path().join("old-secret")).unwrap();
        fs::write(&secret_path, [0x41_u8; SECRET_BYTES]).unwrap();
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o400)).unwrap();

        let retained_changed = validate_retained_secret(&retained, owner).is_err();
        let reopened = load_secret(&directory, owner, "secret", "secret").unwrap();
        assert_eq!(retained.exact[..], reopened.exact[..]);
        assert!(retained_changed || retained.metadata != reopened.metadata);
    }

    #[test]
    fn effective_owner_is_part_of_directory_and_child_profiles() {
        let temporary = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("temporary directory failed: {error}"));
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("directory permissions failed: {error}"));
        let directory = open_directory(temporary.path())
            .unwrap_or_else(|error| panic!("directory open failed: {error}"));
        let directory_stat = rustix::fs::fstat(&directory)
            .unwrap_or_else(|error| panic!("directory stat failed: {error}"));
        assert!(require_directory_metadata(&directory_stat, directory_stat.st_uid).is_ok());
        assert!(
            require_directory_metadata(&directory_stat, directory_stat.st_uid.wrapping_add(1))
                .is_err()
        );

        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("temporary permissions failed: {error}"));
        let child_path = temporary.path().join("child");
        fs::write(&child_path, [1_u8; 48])
            .unwrap_or_else(|error| panic!("child write failed: {error}"));
        fs::set_permissions(&child_path, fs::Permissions::from_mode(0o400))
            .unwrap_or_else(|error| panic!("child permissions failed: {error}"));
        let child = rustix::fs::open(
            &child_path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap_or_else(|error| panic!("child open failed: {error}"));
        let child_stat =
            rustix::fs::fstat(&child).unwrap_or_else(|error| panic!("child stat failed: {error}"));
        assert!(require_child_metadata(&child_stat, child_stat.st_uid, 48, "child").is_ok());
        assert!(
            require_child_metadata(&child_stat, child_stat.st_uid.wrapping_add(1), 48, "child")
                .is_err()
        );
    }

    #[test]
    fn secret_reads_are_partial_safe_and_fail_closed_on_error() {
        let mut partial = ScriptedReader {
            steps: [
                Ok(vec![0x41; 7]),
                Ok(vec![0x42; 13]),
                Ok(vec![0x43; 28]),
                Ok(Vec::new()),
            ]
            .into(),
        };
        let secret = read_secret_with("test secret", |buffer, position| {
            partial.read_at(buffer, position)
        })
        .unwrap_or_else(|error| panic!("partial secret read failed: {error}"));
        assert_eq!(&secret[..7], &[0x41; 7]);
        assert_eq!(&secret[7..20], &[0x42; 13]);
        assert_eq!(&secret[20..], &[0x43; 28]);

        let mut error_after_partial = ScriptedReader {
            steps: [Ok(vec![0x51; 16]), Err(rustix::io::Errno::IO)].into(),
        };
        assert!(
            read_secret_with("test secret", |buffer, position| {
                error_after_partial.read_at(buffer, position)
            })
            .is_err()
        );

        let source = include_str!("protected_files.rs");
        let generic_secret_read = ["read_exact_positioned::<", "SECRET_BYTES>"].concat();
        let secret_hash = ["Sha256::digest(", "exact.as_ref())"].concat();
        let retained_digest = ["secret", ".digest"].concat();
        assert!(!source.contains(&generic_secret_read));
        assert!(!source.contains(&secret_hash));
        assert!(!source.contains(&retained_digest));
    }

    #[test]
    fn mutation_between_complete_secret_reads_is_rejected() {
        let temporary = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("temporary directory failed: {error}"));
        let secret_path = temporary.path().join("secret");
        fs::write(&secret_path, [0x61; SECRET_BYTES])
            .unwrap_or_else(|error| panic!("secret write failed: {error}"));
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o400))
            .unwrap_or_else(|error| panic!("secret permissions failed: {error}"));
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("directory permissions failed: {error}"));
        let directory = open_directory(temporary.path())
            .unwrap_or_else(|error| panic!("directory open failed: {error}"));
        let owner = rustix::process::geteuid().as_raw();

        let result =
            load_secret_with_between_reads(&directory, owner, "secret", "test secret", || {
                fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                fs::write(&secret_path, [0x62; SECRET_BYTES])
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o400))
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                Ok(())
            });
        assert!(matches!(
            result,
            Err(BrokerSessionSecurityError::Currentness)
        ));
    }
}
