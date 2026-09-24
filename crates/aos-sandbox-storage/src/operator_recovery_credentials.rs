//! Fixed root-owned systemd credentials for the Storage operator sidecar.
//!
//! The two role keys are independently provisioned. No caller supplies their
//! paths or values through an RPC packet, and every ingress rechecks the
//! retained directory, inode, and exact bytes before touching protected state.
//!
//! ```text
//! controller-public = AOSORCP1 | version:u16be=1 | reserved[6]=0
//!                     | key-id[16] | generation:u64be | public[32]
//! storage-owner    = AOSORSK2 | version:u16be=1 | reserved[6]=0
//!                     | owner-id[16] | generation:u64be
//!                     | public[32] | ed25519-seed[32]
//! ```

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat, openat2};
use zeroize::Zeroizing;

use crate::operator_recovery::StorageOperatorRecoveryOwnerV1;
use crate::service::StorageServiceError;

const CONTROLLER_NAME: &str = "operator-recovery-controller-public-key-v1";
const OWNER_NAME: &str = "operator-recovery-storage-owner-key-v1";
const CONTROLLER_MAGIC: &[u8; 8] = b"AOSORCP1";
const OWNER_MAGIC: &[u8; 8] = b"AOSORSK2";
const CONTROLLER_BYTES: usize = 72;
const OWNER_BYTES: usize = 104;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    ctime: i64,
    ctime_nsec: u64,
}

struct PinnedCredential {
    name: &'static str,
    identity: FileIdentity,
    bytes: Zeroizing<Vec<u8>>,
}

/// Pins both independent role keys for the lifetime of the Storage service.
pub struct StorageOperatorRecoveryCredentialsV1 {
    directory: PathBuf,
    directory_identity: FileIdentity,
    controller: PinnedCredential,
    owner: PinnedCredential,
    controller_key: VerifyingKey,
    controller_generation: u64,
    owner_key: SigningKey,
    owner_id: [u8; 16],
    owner_generation: u64,
}

impl StorageOperatorRecoveryCredentialsV1 {
    /// Loads the two fixed systemd keys and rejects absent or unsafe custody.
    ///
    /// # Errors
    ///
    /// Rejects missing or changed files, non-root ownership, aliases, unsafe
    /// permissions, malformed records, or role-key reuse.
    pub fn load() -> Result<Self, StorageServiceError> {
        let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or_else(|| invalid("credential directory is absent"))?;
        let (fd, directory_identity) = open_directory(&directory)?;
        let controller = read_credential(&fd, CONTROLLER_NAME, CONTROLLER_BYTES)?;
        let owner = read_credential(&fd, OWNER_NAME, OWNER_BYTES)?;
        let (_, controller_generation, controller_key) = decode_controller(&controller.bytes)?;
        let (owner_id, owner_generation, owner_key) = decode_owner(&owner.bytes)?;
        if controller_key == owner_key.verifying_key() {
            return Err(invalid("operator role keys are not independent"));
        }
        let retained = Self {
            directory,
            directory_identity,
            controller,
            owner,
            controller_key,
            controller_generation,
            owner_key,
            owner_id,
            owner_generation,
        };
        retained.recheck()?;
        Ok(retained)
    }

    /// Reopens both fixed leaves and proves that identity and bytes are unchanged.
    ///
    /// # Errors
    ///
    /// Rejects any changed directory, inode, metadata, or key bytes.
    pub fn recheck(&self) -> Result<(), StorageServiceError> {
        let (fd, identity) = open_directory(&self.directory)?;
        if identity != self.directory_identity {
            return Err(invalid("operator credential directory changed"));
        }
        for retained in [&self.controller, &self.owner] {
            let current = read_credential(&fd, retained.name, retained.bytes.len())?;
            if current.identity != retained.identity || current.bytes != retained.bytes {
                return Err(invalid("operator credential changed"));
            }
        }
        Ok(())
    }

    /// Opens the exclusive root-owned receipt journal under the Storage state root.
    ///
    /// # Errors
    ///
    /// Rejects stale credentials, unsafe protected state, or retained key
    /// generations incompatible with earlier repair attempts.
    pub fn open_owner(
        &self,
        state_root: &Path,
    ) -> Result<StorageOperatorRecoveryOwnerV1, StorageServiceError> {
        self.recheck()?;
        StorageOperatorRecoveryOwnerV1::open(
            state_root,
            "operator-recovery.journal",
            self.controller_key,
            self.controller_generation,
            self.owner_key.clone(),
            self.owner_id,
            self.owner_generation,
        )
        .map_err(|_| invalid("operator receipt journal is unavailable"))
    }
}

fn open_directory(path: &Path) -> Result<(OwnedFd, FileIdentity), StorageServiceError> {
    if !path.is_absolute() {
        return Err(invalid("operator credential directory is not absolute"));
    }
    let fd = openat2(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| invalid("operator credential directory is unsafe"))?;
    let stat = fstat(&fd).map_err(|_| invalid("operator credential directory is unavailable"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o077 != 0
    {
        return Err(invalid(
            "operator credential directory protection is invalid",
        ));
    }
    Ok((fd, identity(&stat)))
}

fn read_credential(
    directory: &OwnedFd,
    name: &'static str,
    length: usize,
) -> Result<PinnedCredential, StorageServiceError> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| invalid("operator credential is absent"))?;
    let before = fstat(&fd).map_err(|_| invalid("operator credential metadata is unavailable"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o077 != 0
        || before.st_nlink != 1
        || before.st_size != length as i64
    {
        return Err(invalid("operator credential protection is invalid"));
    }
    let mut file = File::from(fd);
    let mut bytes = Zeroizing::new(vec![0; length]);
    file.read_exact(&mut bytes)
        .map_err(|_| invalid("operator credential read failed"))?;
    let after = fstat(&file).map_err(|_| invalid("operator credential changed"))?;
    if identity(&before) != identity(&after) {
        return Err(invalid("operator credential changed"));
    }
    Ok(PinnedCredential {
        name,
        identity: identity(&after),
        bytes,
    })
}

fn identity(stat: &rustix::fs::Stat) -> FileIdentity {
    FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        size: stat.st_size as u64,
        ctime: stat.st_ctime,
        ctime_nsec: stat.st_ctime_nsec,
    }
}

fn decode_controller(bytes: &[u8]) -> Result<([u8; 16], u64, VerifyingKey), StorageServiceError> {
    let bytes: &[u8; CONTROLLER_BYTES] = bytes
        .try_into()
        .map_err(|_| invalid("controller recovery key has wrong length"))?;
    if &bytes[..8] != CONTROLLER_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
    {
        return Err(invalid("controller recovery key record is invalid"));
    }
    let key_id: [u8; 16] = bytes[16..32]
        .try_into()
        .map_err(|_| invalid("controller recovery key identity is invalid"))?;
    let generation = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| invalid("controller recovery key generation is invalid"))?,
    );
    let public: [u8; 32] = bytes[40..72]
        .try_into()
        .map_err(|_| invalid("controller recovery public key is invalid"))?;
    let key = VerifyingKey::from_bytes(&public)
        .map_err(|_| invalid("controller recovery public key is invalid"))?;
    if key_id == [0; 16] || generation == 0 || public == [0; 32] {
        return Err(invalid("controller recovery key identity is absent"));
    }
    Ok((key_id, generation, key))
}

fn decode_owner(bytes: &[u8]) -> Result<([u8; 16], u64, SigningKey), StorageServiceError> {
    let bytes: &[u8; OWNER_BYTES] = bytes
        .try_into()
        .map_err(|_| invalid("Storage owner key has wrong length"))?;
    if &bytes[..8] != OWNER_MAGIC || bytes[8..10] != 1_u16.to_be_bytes() || bytes[10..16] != [0; 6]
    {
        return Err(invalid("Storage owner key record is invalid"));
    }
    let owner_id: [u8; 16] = bytes[16..32]
        .try_into()
        .map_err(|_| invalid("Storage owner identity is invalid"))?;
    let generation = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| invalid("Storage owner generation is invalid"))?,
    );
    let public: [u8; 32] = bytes[40..72]
        .try_into()
        .map_err(|_| invalid("Storage owner public key is invalid"))?;
    let seed = Zeroizing::new(
        bytes[72..104]
            .try_into()
            .map_err(|_| invalid("Storage owner secret key is invalid"))?,
    );
    let key = SigningKey::from_bytes(&seed);
    if owner_id == [0; 16]
        || generation == 0
        || *seed == [0; 32]
        || key.verifying_key().to_bytes() != public
    {
        return Err(invalid("Storage owner key binding is invalid"));
    }
    Ok((owner_id, generation, key))
}

fn invalid(message: &'static str) -> StorageServiceError {
    StorageServiceError::Activation(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller_record(key: &SigningKey) -> [u8; CONTROLLER_BYTES] {
        let mut bytes = [0; CONTROLLER_BYTES];
        bytes[..8].copy_from_slice(CONTROLLER_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..32].copy_from_slice(&[1; 16]);
        bytes[32..40].copy_from_slice(&1_u64.to_be_bytes());
        bytes[40..72].copy_from_slice(&key.verifying_key().to_bytes());
        bytes
    }

    fn owner_record(key: &SigningKey) -> [u8; OWNER_BYTES] {
        let mut bytes = [0; OWNER_BYTES];
        bytes[..8].copy_from_slice(OWNER_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..32].copy_from_slice(&[2; 16]);
        bytes[32..40].copy_from_slice(&3_u64.to_be_bytes());
        bytes[40..72].copy_from_slice(&key.verifying_key().to_bytes());
        bytes[72..104].copy_from_slice(&key.to_bytes());
        bytes
    }

    #[test]
    fn fixed_role_records_reject_rotation_and_cross_role_substitution() {
        let controller_key = SigningKey::from_bytes(&[11; 32]);
        let owner_key = SigningKey::from_bytes(&[12; 32]);
        let mut controller = controller_record(&controller_key);
        let mut owner = owner_record(&owner_key);
        assert_eq!(decode_controller(&controller).unwrap().1, 1);
        assert_eq!(decode_owner(&owner).unwrap().1, 3);
        assert!(decode_controller(&owner).is_err());
        assert!(decode_owner(&controller).is_err());

        controller[32..40].copy_from_slice(&0_u64.to_be_bytes());
        assert!(decode_controller(&controller).is_err());
        owner[40] ^= 1;
        assert!(decode_owner(&owner).is_err());
        owner = owner_record(&owner_key);
        owner[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert!(decode_owner(&owner).is_err());
    }
}
