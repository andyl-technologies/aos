//! Protected Provider trust for Storage's dedicated ZFS-hold receipt signer.
//!
//! The `AOSZHV01` public-key manifest is separate from the six backend
//! attestation keys and is retained at
//! `/var/lib/aos/source-provider/backend-authority/current-zfs-hold-receipt-verifier`.
//! It is loaded only for native receipt inspection, so an absent file leaves
//! that path closed without changing unrelated Provider startup.
//!
//! ```text
//! AOSZHV01 | version:u16be=1 | reserved[6]=0 |
//! storage-authority-id[16] | authority-generation:u64be |
//! authority-digest[32] | key-id[16] | key-generation:u64be |
//! ed25519-public[32] | sha256(ed25519-public)[32]
//! ```

use std::os::fd::OwnedFd;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedStorageZfsHoldReceiptV1, StorageZfsHoldReceiptV1, StorageZfsHoldSignerV1,
    StorageZfsHoldVerifierV1,
};
use rustix::fs::{FileType, FlockOperation, Mode, OFlags, Stat};
use sha2::{Digest as _, Sha256};

use crate::ProviderLedgerError;
use crate::backend_verifier::ProtectedBackendVerifierV1;

const FILE_NAME: &str = "current-zfs-hold-receipt-verifier";
const MAGIC: &[u8; 8] = b"AOSZHV01";
const VERSION: u16 = 1;
const MANIFEST_BYTES: usize = 160;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl FileIdentity {
    const fn from_stat(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            owner: stat.st_uid,
            group: stat.st_gid,
            links: stat.st_nlink,
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

/// Retains the exact protected ZFS-hold receipt verifier and its file identity.
pub(crate) struct ProtectedStorageZfsHoldVerifierV1 {
    backend: Arc<ProtectedBackendVerifierV1>,
    manifest: OwnedFd,
    identity: FileIdentity,
    exact_manifest: [u8; MANIFEST_BYTES],
    verifier: StorageZfsHoldVerifierV1,
}

impl ProtectedStorageZfsHoldVerifierV1 {
    /// Opens the dedicated manifest only beneath the already protected owner.
    pub(crate) fn load(
        backend: Arc<ProtectedBackendVerifierV1>,
    ) -> Result<Self, ProviderLedgerError> {
        backend.revalidate()?;
        let manifest = open_manifest(backend.protected_directory())?;
        let group = rustix::process::getegid().as_raw();
        let identity = manifest_identity(&manifest, group)?;
        rustix::fs::flock(&manifest, FlockOperation::NonBlockingLockExclusive).map_err(
            |error| {
                if error == rustix::io::Errno::AGAIN {
                    ProviderLedgerError::InvalidTransition("ZFS hold verifier is already in use")
                } else {
                    ProviderLedgerError::Corrupt("ZFS hold verifier lock")
                }
            },
        )?;
        let exact_manifest = read_manifest(&manifest)?;
        let verifier = decode_manifest(&exact_manifest)?;
        let (signer, public_key) = verifier.projection();
        let (authority_id, _, _) = signer.authority();
        let (key_id, _) = signer.key();
        if !backend.excludes_zfs_hold_receipt_signer(authority_id, key_id, public_key) {
            return Err(ProviderLedgerError::Corrupt(
                "ZFS hold receipt signer overlaps backend attestation role",
            ));
        }

        let retained = Self {
            backend,
            manifest,
            identity,
            exact_manifest,
            verifier,
        };
        retained.revalidate()?;
        Ok(retained)
    }

    /// Rechecks retained and path-opened bytes under the protected directory.
    pub(crate) fn revalidate(&self) -> Result<(), ProviderLedgerError> {
        self.backend.revalidate()?;
        let group = rustix::process::getegid().as_raw();
        if manifest_identity(&self.manifest, group)? != self.identity
            || read_manifest(&self.manifest)? != self.exact_manifest
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let reopened = open_manifest(self.backend.protected_directory())?;
        if manifest_identity(&reopened, group)? != self.identity
            || read_manifest(&reopened)? != self.exact_manifest
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        self.backend.revalidate()
    }

    /// Checks the protocol signature, trusted time, and exact expected subject.
    ///
    /// This is a nonauthorizing prerequisite. The caller must separately prove
    /// durable challenge replay exclusion and trusted Storage head currentness.
    pub(crate) fn verify_for(
        &self,
        signed: &SignedStorageZfsHoldReceiptV1,
        expected: &StorageZfsHoldReceiptV1,
    ) -> Result<(), ProviderLedgerError> {
        self.revalidate()?;
        let now_seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        if now_seconds <= 0 {
            return Err(ProviderLedgerError::Unavailable);
        }
        self.verifier
            .verify_for(signed, expected, now_seconds)
            .map_err(|_| ProviderLedgerError::Unavailable)?;
        self.revalidate()
    }
}

fn decode_manifest(
    bytes: &[u8; MANIFEST_BYTES],
) -> Result<StorageZfsHoldVerifierV1, ProviderLedgerError> {
    if bytes[..8] != *MAGIC || bytes[8..10] != VERSION.to_be_bytes() || bytes[10..16] != [0; 6] {
        return Err(ProviderLedgerError::Corrupt("ZFS hold verifier header"));
    }
    let public_key: [u8; 32] = bytes[96..128]
        .try_into()
        .map_err(|_| ProviderLedgerError::Corrupt("ZFS hold verifier key"))?;
    if Sha256::digest(public_key).as_slice() != &bytes[128..160] {
        return Err(ProviderLedgerError::Corrupt("ZFS hold verifier key digest"));
    }
    let signer = StorageZfsHoldSignerV1::new(
        array(bytes, 16)?,
        u64_at(bytes, 32)?,
        ObjectDigest::from_bytes(array(bytes, 40)?),
        array(bytes, 72)?,
        u64_at(bytes, 88)?,
    )
    .map_err(|_| ProviderLedgerError::Corrupt("ZFS hold verifier signer"))?;
    StorageZfsHoldVerifierV1::new(signer, public_key)
        .map_err(|_| ProviderLedgerError::Corrupt("ZFS hold verifier public key"))
}

fn open_manifest(directory: &OwnedFd) -> Result<OwnedFd, ProviderLedgerError> {
    rustix::fs::openat(
        directory,
        FILE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ProviderLedgerError::Unavailable)
}

fn manifest_identity(
    descriptor: &OwnedFd,
    group: u32,
) -> Result<FileIdentity, ProviderLedgerError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| ProviderLedgerError::Corrupt("ZFS hold verifier metadata"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_gid != group
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o440
        || usize::try_from(stat.st_size).ok() != Some(MANIFEST_BYTES)
    {
        return Err(ProviderLedgerError::Corrupt("ZFS hold verifier metadata"));
    }
    Ok(FileIdentity::from_stat(&stat))
}

fn read_manifest(descriptor: &OwnedFd) -> Result<[u8; MANIFEST_BYTES], ProviderLedgerError> {
    let mut bytes = [0; MANIFEST_BYTES];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = rustix::io::pread(descriptor, &mut bytes[offset..], offset as u64)
            .map_err(|_| ProviderLedgerError::Corrupt("ZFS hold verifier read"))?;
        if count == 0 {
            return Err(ProviderLedgerError::Corrupt("ZFS hold verifier truncated"));
        }
        offset += count;
    }
    let mut trailing = [0; 1];
    if rustix::io::pread(descriptor, &mut trailing, MANIFEST_BYTES as u64)
        .map_err(|_| ProviderLedgerError::Corrupt("ZFS hold verifier read"))?
        != 0
    {
        return Err(ProviderLedgerError::Corrupt(
            "ZFS hold verifier trailing bytes",
        ));
    }
    Ok(bytes)
}

fn array<const N: usize>(
    bytes: &[u8; MANIFEST_BYTES],
    offset: usize,
) -> Result<[u8; N], ProviderLedgerError> {
    bytes[offset..offset + N]
        .try_into()
        .map_err(|_| ProviderLedgerError::Corrupt("ZFS hold verifier truncated"))
}

fn u64_at(bytes: &[u8; MANIFEST_BYTES], offset: usize) -> Result<u64, ProviderLedgerError> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn manifest() -> [u8; MANIFEST_BYTES] {
        let mut bytes = [0; MANIFEST_BYTES];
        let public = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..32].copy_from_slice(&[1; 16]);
        bytes[32..40].copy_from_slice(&2_u64.to_be_bytes());
        bytes[40..72].copy_from_slice(&[3; 32]);
        bytes[72..88].copy_from_slice(&[4; 16]);
        bytes[88..96].copy_from_slice(&5_u64.to_be_bytes());
        bytes[96..128].copy_from_slice(&public);
        bytes[128..160].copy_from_slice(&Sha256::digest(public));
        bytes
    }

    #[test]
    fn dedicated_verifier_manifest_rejects_mutated_header_key_and_digest() {
        assert!(decode_manifest(&manifest()).is_ok());
        for index in [0, 8, 10, 16, 32, 40, 72, 88, 96, 128] {
            let mut bytes = manifest();
            bytes[index] ^= 1;
            if [16, 32, 40, 72, 88].contains(&index) {
                assert!(decode_manifest(&bytes).is_ok());
            } else {
                assert!(decode_manifest(&bytes).is_err());
            }
        }

        for range in [16..32, 32..40, 40..72, 72..88, 88..96] {
            let mut bytes = manifest();
            bytes[range].fill(0);
            assert!(decode_manifest(&bytes).is_err());
        }

        let mut weak_key = manifest();
        weak_key[96..128].fill(0);
        weak_key[128..160].copy_from_slice(&Sha256::digest([0_u8; 32]));
        assert!(decode_manifest(&weak_key).is_err());
    }
}
