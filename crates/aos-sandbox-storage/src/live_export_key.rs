//! Protected StorageExport signing-key custody for preliminary LocalLive leases.
//!
//! ```text
//! AOSSLK01 | version:u16be=1 | reserved[6]=0 |
//! authority-id[16] | authority-generation:u64be | authority-digest[32] |
//! key-id[16] | key-generation:u64be | ed25519-public[32] |
//! ed25519-seed[32]
//! ```
//!
//! The fixed file is root-owned mode 0600 beneath a root-owned mode-0700
//! directory. The owner checks the exact current pathname, inode, metadata,
//! public key, and seed before each signature. Rotation requires a new owner
//! process and an independently updated SourceProvider verifier manifest. A
//! signature from this key alone never authorizes LocalLive acquisition.

use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::{Component, Path, PathBuf};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::storage_live_export_lease::{
    SignedStorageLiveExportLeaseV1, StorageLiveExportLeaseV1, StorageLiveExportSignerV1,
    StorageLiveExportVerifierV1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use rustix::fs::{FileType, Mode, OFlags, Stat};
use zeroize::Zeroizing;

const KEY_FILE: &str = "storage-live-export-key-v1";
const MAGIC: &[u8; 8] = b"AOSSLK01";
const VERSION: u16 = 1;
const KEY_BYTES: usize = 160;

/// Rejects unsafe, changed, or internally inconsistent StorageExport key state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageLiveExportKeyErrorV1 {
    /// Root-controlled filesystem custody was not established or has changed.
    #[error("protected StorageExport key custody is unavailable")]
    Custody,
    /// The exact versioned key record or its public-key binding is invalid.
    #[error("protected StorageExport key record is invalid")]
    InvalidRecord,
}

/// Owns one root-protected key and a pinned current key-record identity.
///
/// This type is deliberately private to Storage. Future lease issuance must
/// first prove a protected export publication, current physical origin, and
/// authenticated cross-process consumer plan, then independently revalidate
/// a read-only clone and enforcing KernelExportGrant through its protected
/// owner. No API can currently sign an arbitrary caller-assembled lease.
pub(crate) struct StorageLiveExportKeyV1 {
    directory: OwnedFd,
    directory_path: PathBuf,
    directory_device: u64,
    directory_inode: u64,
    key_device: u64,
    key_inode: u64,
    record: Zeroizing<[u8; KEY_BYTES]>,
    signer: StorageLiveExportSignerV1,
    verifier: StorageLiveExportVerifierV1,
    seed: Zeroizing<[u8; 32]>,
    expected_owner: u32,
}

impl StorageLiveExportKeyV1 {
    /// Opens the fixed, root-controlled StorageExport key directory.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportKeyErrorV1`] unless every path component and
    /// the exact key record satisfy protected ownership, mode, and content
    /// checks. It never creates or generates signing authority.
    pub(crate) fn open_root_owned(directory: &Path) -> Result<Self, StorageLiveExportKeyErrorV1> {
        Self::open_with_owner(directory, 0)
    }

    fn open_with_owner(
        directory: &Path,
        expected_owner: u32,
    ) -> Result<Self, StorageLiveExportKeyErrorV1> {
        let directory_path = directory.to_path_buf();
        let directory = open_protected_directory(directory, expected_owner)?;
        let directory_identity =
            rustix::fs::fstat(&directory).map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
        let (record, key_device, key_inode) = read_key_record(&directory, expected_owner)?;
        let (signer, verifier, seed) = decode_key_record(&record)?;
        Ok(Self {
            directory,
            directory_path,
            directory_device: directory_identity.st_dev,
            directory_inode: directory_identity.st_ino,
            key_device,
            key_inode,
            record,
            signer,
            verifier,
            seed,
            expected_owner,
        })
    }

    const fn verifier(&self) -> StorageLiveExportVerifierV1 {
        self.verifier
    }

    // The kernel grant owner is absent. Keep this method private until an
    // enforcing current-use grant and terminal revocation can be revalidated
    // independently of Storage and the Provider.
    fn sign(
        &self,
        lease: StorageLiveExportLeaseV1,
    ) -> Result<SignedStorageLiveExportLeaseV1, StorageLiveExportKeyErrorV1> {
        self.validate_current()?;
        let unsigned = SignedStorageLiveExportLeaseV1::new(lease, self.signer, [1; 64]);
        let signature = SigningKey::from_bytes(&self.seed)
            .sign(&unsigned.signing_message())
            .to_bytes();
        let signed = SignedStorageLiveExportLeaseV1::new(lease, self.signer, signature);
        self.validate_current()?;
        Ok(signed)
    }

    fn validate_current(&self) -> Result<(), StorageLiveExportKeyErrorV1> {
        let current_directory =
            open_protected_directory(&self.directory_path, self.expected_owner)?;
        let current_identity = rustix::fs::fstat(&current_directory)
            .map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
        if (current_identity.st_dev, current_identity.st_ino)
            != (self.directory_device, self.directory_inode)
        {
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
        let (record, device, inode) = read_key_record(&self.directory, self.expected_owner)?;
        if (device, inode) != (self.key_device, self.key_inode) || *record != *self.record {
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
        let (signer, verifier, seed) = decode_key_record(&record)?;
        if signer != self.signer || verifier != self.verifier || seed != self.seed {
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
        Ok(())
    }
}

pub(crate) fn open_protected_directory(
    path: &Path,
    expected_owner: u32,
) -> Result<OwnedFd, StorageLiveExportKeyErrorV1> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(StorageLiveExportKeyErrorV1::Custody);
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let descriptor = rustix::fs::open(
            ancestor,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
        let identity =
            rustix::fs::fstat(&descriptor).map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
        if FileType::from_raw_mode(identity.st_mode) != FileType::Directory
            || (identity.st_uid != 0 && identity.st_uid != expected_owner)
            || identity.st_mode & 0o022 != 0
            || (ancestor == path
                && (identity.st_uid != expected_owner || identity.st_mode & 0o777 != 0o700))
        {
            return Err(StorageLiveExportKeyErrorV1::Custody);
        }
        if ancestor == path {
            return Ok(descriptor);
        }
    }
    Err(StorageLiveExportKeyErrorV1::Custody)
}

fn read_key_record(
    directory: &OwnedFd,
    expected_owner: u32,
) -> Result<(Zeroizing<[u8; KEY_BYTES]>, u64, u64), StorageLiveExportKeyErrorV1> {
    let descriptor = rustix::fs::openat(
        directory.as_fd(),
        KEY_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
    let before =
        rustix::fs::fstat(&descriptor).map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != expected_owner
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size != KEY_BYTES as i64
        || before.st_dev == 0
        || before.st_ino == 0
    {
        return Err(StorageLiveExportKeyErrorV1::Custody);
    }

    let file = File::from(descriptor);
    let mut record = Zeroizing::new([0; KEY_BYTES]);
    file.read_exact_at(&mut *record, 0)
        .map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
    let mut repeated = Zeroizing::new([0; KEY_BYTES]);
    file.read_exact_at(&mut *repeated, 0)
        .map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
    let after = rustix::fs::fstat(&file).map_err(|_| StorageLiveExportKeyErrorV1::Custody)?;
    if !same_stable_file_metadata(&before, &after) || *record != *repeated {
        return Err(StorageLiveExportKeyErrorV1::Custody);
    }
    Ok((record, before.st_dev, before.st_ino))
}

// A double-read is valid only while the exact protected file identity and
// change indicators remain stable across both reads.
pub(crate) fn same_stable_file_metadata(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_size == after.st_size
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_nlink == after.st_nlink
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn decode_key_record(
    record: &[u8; KEY_BYTES],
) -> Result<
    (
        StorageLiveExportSignerV1,
        StorageLiveExportVerifierV1,
        Zeroizing<[u8; 32]>,
    ),
    StorageLiveExportKeyErrorV1,
> {
    if &record[..8] != MAGIC || record[8..10] != VERSION.to_be_bytes() || record[10..16] != [0; 6] {
        return Err(StorageLiveExportKeyErrorV1::InvalidRecord);
    }
    let signer = StorageLiveExportSignerV1::new(
        record[16..32]
            .try_into()
            .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?,
        u64::from_be_bytes(
            record[32..40]
                .try_into()
                .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?,
        ),
        ObjectDigest::from_bytes(
            record[40..72]
                .try_into()
                .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?,
        ),
        record[72..88]
            .try_into()
            .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?,
        u64::from_be_bytes(
            record[88..96]
                .try_into()
                .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?,
        ),
    )
    .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?;
    let public_key = record[96..128]
        .try_into()
        .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?;
    let seed = Zeroizing::new(
        record[128..160]
            .try_into()
            .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?,
    );
    if *seed == [0; 32] || SigningKey::from_bytes(&seed).verifying_key().to_bytes() != public_key {
        return Err(StorageLiveExportKeyErrorV1::InvalidRecord);
    }
    let verifier = StorageLiveExportVerifierV1::new(signer, public_key)
        .map_err(|_| StorageLiveExportKeyErrorV1::InvalidRecord)?;
    Ok((signer, verifier, seed))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn canonical_record() -> [u8; KEY_BYTES] {
        let seed = [7; 32];
        let mut record = [0; KEY_BYTES];
        record[..8].copy_from_slice(MAGIC);
        record[8..10].copy_from_slice(&VERSION.to_be_bytes());
        record[16..32].copy_from_slice(&[1; 16]);
        record[32..40].copy_from_slice(&1_u64.to_be_bytes());
        record[40..72].copy_from_slice(&[2; 32]);
        record[72..88].copy_from_slice(&[3; 16]);
        record[88..96].copy_from_slice(&1_u64.to_be_bytes());
        record[96..128].copy_from_slice(&SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        record[128..].copy_from_slice(&seed);
        record
    }

    #[test]
    fn record_rejects_version_padding_and_key_mismatch() {
        let canonical = canonical_record();
        assert!(decode_key_record(&canonical).is_ok());

        for index in [0, 8, 10, 96, 128] {
            let mut changed = canonical;
            changed[index] ^= 1;
            assert!(decode_key_record(&changed).is_err(), "changed byte {index}");
        }

        for field in [16..32, 40..72, 72..88, 128..160] {
            let mut changed = canonical;
            changed[field].fill(0);
            assert!(decode_key_record(&changed).is_err());
        }
    }

    #[test]
    fn protected_file_readback_rejects_unsafe_mode_and_replacement() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key_path = directory.path().join(KEY_FILE);
        fs::write(&key_path, canonical_record()).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let descriptor = rustix::fs::open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let owner = rustix::fs::fstat(&descriptor).unwrap().st_uid;
        let (_, initial_device, initial_inode) = read_key_record(&descriptor, owner).unwrap();

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_key_record(&descriptor, owner),
            Err(StorageLiveExportKeyErrorV1::Custody)
        ));
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, canonical_record()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(replacement, &key_path).unwrap();

        let (_, replacement_device, replacement_inode) =
            read_key_record(&descriptor, owner).unwrap();
        assert_ne!(
            (initial_device, initial_inode),
            (replacement_device, replacement_inode)
        );
    }
}
