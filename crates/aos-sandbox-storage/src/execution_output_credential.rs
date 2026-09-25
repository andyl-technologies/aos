//! Fixed Storage credential and startup custody for the output journal.
//!
//! The root-owned external source and systemd credential copy must contain
//! identical capacity and MAC key bytes. Both are pinned while the existing
//! journal's authenticated AOSEOC01 configuration is replayed. This custody
//! does not provision a journal or enable an output RPC.
//!
//! ```text
//! credential = AOSOCK01 | capacity:u64be | key-id[16] | secret[32]
//! journal    = AOSEOC01 | capacity:u64be | key-id[16] | hmac[32]
//! ```

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, open, openat2};
use zeroize::Zeroizing;

use crate::execution_output::{ExecutionOutputLedgerKeyV1, ExecutionOutputLedgerV1};
use crate::operator_recovery_credentials::{
    FileIdentity, PinnedCredential, open_directory, read_credential,
};
use crate::service::StorageServiceError;

const CREDENTIAL_NAME: &str = "storage-execution-output-key-v1";
const JOURNAL_NAME: &str = "execution-output.journal";
const MAGIC: &[u8; 8] = b"AOSOCK01";
const CREDENTIAL_BYTES: usize = 64;

/// Pins the output capacity and key alongside its exclusive journal writer.
pub struct StorageExecutionOutputCustodyV1 {
    source: PinnedSource,
    directory: PathBuf,
    directory_identity: FileIdentity,
    credential: PinnedCredential,
    ledger: ExecutionOutputLedgerV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: i64,
    modified: i64,
    modified_nanoseconds: u64,
    changed: i64,
    changed_nanoseconds: u64,
}

struct PinnedSource {
    path: PathBuf,
    identity: SourceIdentity,
    bytes: Zeroizing<Vec<u8>>,
}

impl StorageExecutionOutputCustodyV1 {
    /// Loads an externally provisioned credential and existing output ledger.
    ///
    /// # Errors
    ///
    /// Rejects absent, unsafe, or changed credentials and any missing,
    /// malformed, uncommitted, or mismatched protected journal state.
    pub fn open(state_root: &Path, source_path: &Path) -> Result<Self, StorageServiceError> {
        let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or_else(|| invalid("output credential directory is absent"))?;
        Self::open_from_directory(&directory, source_path, state_root)
    }

    fn open_from_directory(
        directory: &Path,
        source_path: &Path,
        state_root: &Path,
    ) -> Result<Self, StorageServiceError> {
        let source = read_source(source_path)?;
        let (fd, directory_identity) = open_directory(directory)?;
        let credential = read_credential(&fd, CREDENTIAL_NAME, CREDENTIAL_BYTES)?;
        if credential.bytes != source.bytes {
            return Err(invalid("output credential differs from protected source"));
        }
        let (capacity, key) = decode_credential(&credential.bytes)?;
        let ledger = ExecutionOutputLedgerV1::open_existing_root_owned(
            state_root,
            JOURNAL_NAME,
            capacity,
            key,
        )
        .map_err(|_| invalid("existing output ledger is unavailable or mismatched"))?;

        let custody = Self {
            source,
            directory: directory.to_path_buf(),
            directory_identity,
            credential,
            ledger,
        };
        custody.recheck(state_root)?;
        Ok(custody)
    }

    /// Rechecks both credential and writer identity before and after ingress.
    ///
    /// # Errors
    ///
    /// Rejects any credential rotation, protected pathname change, or poisoned
    /// journal. The caller must exit rather than reopen in the same process.
    pub fn recheck(&self, state_root: &Path) -> Result<(), StorageServiceError> {
        let source = read_source(&self.source.path)?;
        if source.identity != self.source.identity || source.bytes != self.source.bytes {
            return Err(invalid("output credential source changed"));
        }
        let (fd, identity) = open_directory(&self.directory)?;
        if identity != self.directory_identity {
            return Err(invalid("output credential directory changed"));
        }
        let current = read_credential(&fd, CREDENTIAL_NAME, CREDENTIAL_BYTES)?;
        if current.identity != self.credential.identity || current.bytes != self.credential.bytes {
            return Err(invalid("output credential changed"));
        }
        if current.bytes != source.bytes {
            return Err(invalid("output credential differs from protected source"));
        }
        self.ledger
            .recheck_root_owned_custody(state_root, JOURNAL_NAME)
            .map_err(|_| invalid("output journal custody changed"))
    }
}

fn read_source(path: &Path) -> Result<PinnedSource, StorageServiceError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("output credential source path is invalid"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("output credential source path is invalid"))?;
    let directory = open_protected_parent(parent)?;
    let (identity, bytes) = read_source_leaf(&directory, name, 0)?;
    Ok(PinnedSource {
        path: path.to_path_buf(),
        identity,
        bytes,
    })
}

fn open_protected_parent(path: &Path) -> Result<OwnedFd, StorageServiceError> {
    if !path.is_absolute() {
        return Err(invalid("output credential source path is not absolute"));
    }
    let mut directory = open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| invalid("output credential source root is unavailable"))?;
    validate_parent(&directory)?;

    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat2(
                    &directory,
                    name,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(|_| invalid("output credential source ancestor is unsafe"))?;
                validate_parent(&directory)?;
            }
            _ => return Err(invalid("output credential source path is invalid")),
        }
    }
    Ok(directory)
}

fn validate_parent(directory: &OwnedFd) -> Result<(), StorageServiceError> {
    let stat = fstat(directory).map_err(|_| invalid("output credential source ancestor failed"))?;
    if !is_root_controlled_directory(stat.st_mode, stat.st_uid) {
        return Err(invalid(
            "output credential source ancestor is not root controlled",
        ));
    }
    Ok(())
}

fn is_root_controlled_directory(mode: u32, uid: u32) -> bool {
    FileType::from_raw_mode(mode) == FileType::Directory && uid == 0 && mode & 0o022 == 0
}

fn read_source_leaf(
    directory: &OwnedFd,
    name: &OsStr,
    expected_uid: u32,
) -> Result<(SourceIdentity, Zeroizing<Vec<u8>>), StorageServiceError> {
    let descriptor = openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| invalid("output credential source file is unsafe"))?;
    let before = fstat(&descriptor).map_err(|_| invalid("output credential source stat failed"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != expected_uid
        || !matches!(before.st_mode & 0o7777, 0o400 | 0o600)
        || before.st_nlink != 1
        || before.st_size != CREDENTIAL_BYTES as i64
    {
        return Err(invalid("output credential source protection is invalid"));
    }

    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(vec![0; CREDENTIAL_BYTES]);
    file.read_exact(&mut bytes)
        .map_err(|_| invalid("output credential source read failed"))?;
    let mut extra = [0; 1];
    if file
        .read(&mut extra)
        .map_err(|_| invalid("output credential source read failed"))?
        != 0
    {
        return Err(invalid("output credential source changed"));
    }
    let after = fstat(&file).map_err(|_| invalid("output credential source stat failed"))?;
    if source_identity(&before) != source_identity(&after) {
        return Err(invalid("output credential source changed"));
    }
    Ok((source_identity(&after), bytes))
}

fn source_identity(stat: &rustix::fs::Stat) -> SourceIdentity {
    SourceIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        uid: stat.st_uid,
        gid: stat.st_gid,
        links: stat.st_nlink,
        size: stat.st_size,
        modified: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    }
}

fn decode_credential(
    bytes: &[u8],
) -> Result<(u64, ExecutionOutputLedgerKeyV1), StorageServiceError> {
    let bytes: &[u8; CREDENTIAL_BYTES] = bytes
        .try_into()
        .map_err(|_| invalid("output credential has wrong length"))?;
    if &bytes[..8] != MAGIC {
        return Err(invalid("output credential has wrong format"));
    }

    let capacity = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| invalid("output capacity is invalid"))?,
    );
    let key_id = bytes[16..32]
        .try_into()
        .map_err(|_| invalid("output key identity is invalid"))?;
    let secret = bytes[32..64]
        .try_into()
        .map_err(|_| invalid("output key is invalid"))?;
    let key = ExecutionOutputLedgerKeyV1::new(key_id, secret)
        .map_err(|_| invalid("output key is invalid"))?;
    Ok((capacity, key))
}

fn invalid(message: &str) -> StorageServiceError {
    StorageServiceError::Activation(message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use tempfile::TempDir;

    use super::*;

    fn credential() -> [u8; CREDENTIAL_BYTES] {
        let mut bytes = [0; CREDENTIAL_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..16].copy_from_slice(&123_u64.to_be_bytes());
        bytes[16..32].copy_from_slice(&[7; 16]);
        bytes[32..64].copy_from_slice(&[9; 32]);
        bytes
    }

    #[test]
    fn credential_requires_fixed_format_and_nonzero_key() {
        assert!(decode_credential(&credential()).is_ok());

        let mut wrong_magic = credential();
        wrong_magic[0] ^= 1;
        assert!(decode_credential(&wrong_magic).is_err());
        assert!(decode_credential(&credential()[..63]).is_err());

        let mut no_key_id = credential();
        no_key_id[16..32].fill(0);
        assert!(decode_credential(&no_key_id).is_err());

        let mut no_secret = credential();
        no_secret[32..64].fill(0);
        assert!(decode_credential(&no_secret).is_err());
    }

    #[test]
    fn source_leaf_rejects_links_public_modes_and_aliases() {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let descriptor = open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let source = directory.path().join("output.key");
        fs::write(&source, credential()).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let (identity, bytes) =
            read_source_leaf(&descriptor, OsStr::new("output.key"), uid).unwrap();
        assert_eq!(bytes.as_slice(), credential());
        assert_eq!(identity.uid, uid);

        symlink("output.key", directory.path().join("alias.key")).unwrap();
        assert!(read_source_leaf(&descriptor, OsStr::new("alias.key"), uid).is_err());

        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_source_leaf(&descriptor, OsStr::new("output.key"), uid).is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();

        fs::hard_link(&source, directory.path().join("linked.key")).unwrap();
        assert!(read_source_leaf(&descriptor, OsStr::new("output.key"), uid).is_err());
    }

    #[test]
    fn source_parent_requires_root_owner_and_nonwritable_mode() {
        assert!(is_root_controlled_directory(0o040755, 0));
        assert!(is_root_controlled_directory(0o040700, 0));
        assert!(!is_root_controlled_directory(0o040777, 0));
        assert!(!is_root_controlled_directory(0o040775, 0));
        assert!(!is_root_controlled_directory(0o040755, 1000));
        assert!(!is_root_controlled_directory(0o100600, 0));
    }
}
