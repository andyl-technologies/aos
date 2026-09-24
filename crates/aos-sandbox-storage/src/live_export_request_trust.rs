//! Protected signer pins for Provider-to-Storage LocalLive requests.
//!
//! ```text
//! AOSSLT01 | version:u16be=1 | reserved[6]=0 | generation:u64be |
//! provider-signer[112] | provider-ed25519-public[32] |
//! root-mount-signer[112] | root-mount-ed25519-public[32]
//! ```
//!
//! Each signer is authority ID, authority generation, authority digest, key
//! ID, key generation, and SHA-256 public-key digest. The fixed root-owned
//! record is double-read and anchored in a protected journal. Replacement
//! requires exactly one generation step; rollback and same-generation key
//! equivocation fail closed. Keys supplied with a request are never trusted.

use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedStorageLiveExportRequestV1, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
};
use ed25519_dalek::VerifyingKey;
use rustix::fs::{FileType, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use crate::live_export_key::open_protected_directory;

const TRUST_FILE: &str = "storage-live-export-request-trust-v1";
const JOURNAL_FILE: &str = "storage-live-export-request-trust.journal";
const JOURNAL_HEAD_KEY: &[u8] = b"live-export-request-trust-head-v1";
const MAGIC: &[u8; 8] = b"AOSSLT01";
const VERSION: u16 = 1;
const SIGNER_BYTES: usize = 112;
const KEY_BYTES: usize = 32;
const RECORD_BYTES: usize = 24 + 2 * (SIGNER_BYTES + KEY_BYTES);
const JOURNAL_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-request-trust.v1\0";

/// Reports absent, changed, or invalid protected request trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StorageLiveExportRequestTrustErrorV1 {
    /// The root-owned file or durable journal is not current.
    #[error("Storage live-export request trust custody is unavailable")]
    Custody,
    /// Signer metadata, generation, or key material is invalid.
    #[error("Storage live-export request trust record is invalid")]
    InvalidRecord,
    /// The plan does not authenticate under both independently pinned keys.
    #[error("Storage live-export request signers are unauthenticated")]
    Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustRecordV1 {
    generation: u64,
    provider_signer: SourceProviderSigningKeyV1,
    provider_public_key: [u8; KEY_BYTES],
    root_signer: SourceProviderSigningKeyV1,
    root_public_key: [u8; KEY_BYTES],
}

/// Retains two independent current signers under Storage-owned custody.
pub(crate) struct StorageLiveExportRequestTrustV1 {
    journal: Journal,
    directory: OwnedFd,
    directory_path: PathBuf,
    directory_device: u64,
    directory_inode: u64,
    file_device: u64,
    file_inode: u64,
    bytes: [u8; RECORD_BYTES],
    record: TrustRecordV1,
}

impl StorageLiveExportRequestTrustV1 {
    /// Opens current root-owned trust without accepting caller-supplied keys.
    ///
    /// # Errors
    ///
    /// Returns custody or record errors for unsafe paths, files, journal
    /// rollback, weak keys, or inconsistent fingerprints.
    pub(crate) fn open_root_owned(
        directory_path: &Path,
    ) -> Result<Self, StorageLiveExportRequestTrustErrorV1> {
        let directory = open_protected_directory(directory_path, 0)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        let directory_identity = rustix::fs::fstat(&directory)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        let (bytes, file_device, file_inode) = read_trust(&directory, 0)?;
        let record = parse_trust(&bytes)?;
        let mut journal =
            Journal::open_protected_at(directory_path, JOURNAL_FILE, journal_limits())
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
                .0;
        reconcile_head(&mut journal, &bytes, record.generation)?;

        Ok(Self {
            journal,
            directory,
            directory_path: directory_path.to_path_buf(),
            directory_device: directory_identity.st_dev,
            directory_inode: directory_identity.st_ino,
            file_device,
            file_inode,
            bytes,
            record,
        })
    }

    /// Verifies the complete signed plan against both current protected pins.
    ///
    /// # Errors
    ///
    /// Returns custody errors when the trust record changed or signature
    /// errors when either independent signer fails strict verification.
    pub(crate) fn verify(
        &self,
        request: &SignedStorageLiveExportRequestV1,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.validate_current()?;
        request
            .verify(
                &self.record.provider_signer,
                &self.record.provider_public_key,
                &self.record.root_signer,
                &self.record.root_public_key,
            )
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Signature)?;
        self.validate_current()
    }

    pub(crate) fn validate_current(&self) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        let current_directory = open_protected_directory(&self.directory_path, 0)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        let identity = rustix::fs::fstat(&current_directory)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        if (identity.st_dev, identity.st_ino) != (self.directory_device, self.directory_inode) {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        let (bytes, device, inode) = read_trust(&self.directory, 0)?;
        if (device, inode) != (self.file_device, self.file_inode)
            || bytes != self.bytes
            || parse_trust(&bytes)? != self.record
            || self
                .journal
                .get(RecordNamespace::AuthorityPublication, JOURNAL_HEAD_KEY)
                != Some(self.bytes.as_slice())
        {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        Ok(())
    }
}

fn read_trust(
    directory: &OwnedFd,
    expected_owner: u32,
) -> Result<([u8; RECORD_BYTES], u64, u64), StorageLiveExportRequestTrustErrorV1> {
    let descriptor = rustix::fs::openat(
        directory.as_fd(),
        TRUST_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    let before = rustix::fs::fstat(&descriptor)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != expected_owner
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size != RECORD_BYTES as i64
        || before.st_dev == 0
        || before.st_ino == 0
    {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }

    let file = File::from(descriptor);
    let mut bytes = [0; RECORD_BYTES];
    let mut repeated = [0; RECORD_BYTES];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    file.read_exact_at(&mut repeated, 0)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    let after =
        rustix::fs::fstat(&file).map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_nlink != after.st_nlink
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
        || bytes != repeated
    {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok((bytes, before.st_dev, before.st_ino))
}

fn parse_trust(
    bytes: &[u8; RECORD_BYTES],
) -> Result<TrustRecordV1, StorageLiveExportRequestTrustErrorV1> {
    if &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_be_bytes() || bytes[10..16] != [0; 6] {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    let generation = u64::from_be_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?,
    );
    if generation == 0 {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    let (provider_signer, provider_public_key) =
        parse_signer(&bytes[24..168], SourceProviderKeyUsageV1::ProviderOutcome)?;
    let (root_signer, root_public_key) =
        parse_signer(&bytes[168..312], SourceProviderKeyUsageV1::RootMountRecord)?;
    if provider_signer.authority_id() == root_signer.authority_id()
        || provider_public_key == root_public_key
    {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    Ok(TrustRecordV1 {
        generation,
        provider_signer,
        provider_public_key,
        root_signer,
        root_public_key,
    })
}

fn parse_signer(
    bytes: &[u8],
    usage: SourceProviderKeyUsageV1,
) -> Result<(SourceProviderSigningKeyV1, [u8; KEY_BYTES]), StorageLiveExportRequestTrustErrorV1> {
    if bytes.len() != SIGNER_BYTES + KEY_BYTES {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    let public_key = field::<KEY_BYTES>(bytes, 112)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
    if verifying_key.is_weak() {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    let signer = SourceProviderSigningKeyV1::new(
        field(bytes, 0)?,
        u64::from_be_bytes(field(bytes, 16)?),
        ObjectDigest::from_bytes(field(bytes, 24)?),
        field(bytes, 56)?,
        u64::from_be_bytes(field(bytes, 72)?),
        ObjectDigest::from_bytes(field(bytes, 80)?),
        usage,
    )
    .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
    if signer.public_key_digest() != ObjectDigest::from_bytes(Sha256::digest(public_key).into()) {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    Ok((signer, public_key))
}

fn field<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], StorageLiveExportRequestTrustErrorV1> {
    bytes
        .get(offset..offset + N)
        .ok_or(StorageLiveExportRequestTrustErrorV1::InvalidRecord)?
        .try_into()
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)
}

fn reconcile_head(
    journal: &mut Journal,
    bytes: &[u8; RECORD_BYTES],
    generation: u64,
) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
    let mut authority = journal
        .claim_protected_authority(RecordNamespace::AuthorityPublication)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    let previous = authority
        .get(JOURNAL_HEAD_KEY)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
        .map(ToOwned::to_owned);
    let needs_commit = match previous {
        None => {
            if !authority
                .is_materialized_empty()
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
                || generation != 1
            {
                return Err(StorageLiveExportRequestTrustErrorV1::Custody);
            }
            true
        }
        Some(previous) if previous == bytes => false,
        Some(previous) => {
            let previous: [u8; RECORD_BYTES] = previous
                .try_into()
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
            validate_transition(&previous, generation)?;
            true
        }
    };
    if needs_commit {
        let hash = Sha256::new()
            .chain_update(JOURNAL_DOMAIN)
            .chain_update(bytes)
            .finalize();
        let transaction_id: [u8; 16] = hash[..16]
            .try_into()
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                JOURNAL_HEAD_KEY.to_vec(),
                bytes.to_vec(),
            )],
        )
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        authority
            .commit(&transaction)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    }
    if authority
        .records()
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
        .collect::<Vec<_>>()
        != vec![(JOURNAL_HEAD_KEY, bytes.as_slice())]
    {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok(())
}

fn validate_transition(
    previous: &[u8; RECORD_BYTES],
    next_generation: u64,
) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
    let old = parse_trust(previous)?;
    if next_generation
        != old
            .generation
            .checked_add(1)
            .ok_or(StorageLiveExportRequestTrustErrorV1::InvalidRecord)?
    {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok(())
}

const fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 1024 * 1024,
        maximum_record_bytes: RECORD_BYTES,
        maximum_key_bytes: 64,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 1024,
        maximum_transactions: 256,
        maximum_materialized_bytes: RECORD_BYTES + 64,
        maximum_materialized_records: 1,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use ed25519_dalek::SigningKey;

    use super::*;

    fn fixture() -> [u8; RECORD_BYTES] {
        let provider_key = SigningKey::from_bytes(&[17; 32]);
        let root_key = SigningKey::from_bytes(&[18; 32]);
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..24].copy_from_slice(&1_u64.to_be_bytes());
        for (offset, authority, key, seed) in
            [(24, 21, &provider_key, 25), (168, 31, &root_key, 35)]
        {
            bytes[offset..offset + 16].fill(authority);
            bytes[offset + 16..offset + 24].copy_from_slice(&1_u64.to_be_bytes());
            bytes[offset + 24..offset + 56].fill(authority + 1);
            bytes[offset + 56..offset + 72].fill(seed);
            bytes[offset + 72..offset + 80].copy_from_slice(&1_u64.to_be_bytes());
            bytes[offset + 80..offset + 112]
                .copy_from_slice(&Sha256::digest(key.verifying_key().as_bytes()));
            bytes[offset + 112..offset + 144].copy_from_slice(key.verifying_key().as_bytes());
        }
        bytes
    }

    #[test]
    fn trust_record_pins_distinct_root_and_provider_keys() {
        let bytes = fixture();
        let trust = parse_trust(&bytes).unwrap();
        assert_eq!(trust.generation, 1);
        assert_ne!(trust.provider_public_key, trust.root_public_key);
        assert_eq!(
            trust.provider_signer.usage(),
            SourceProviderKeyUsageV1::ProviderOutcome
        );
        assert_eq!(
            trust.root_signer.usage(),
            SourceProviderKeyUsageV1::RootMountRecord
        );
    }

    #[test]
    fn malformed_or_substituted_trust_fails_closed() {
        let original = fixture();
        for index in [0, 9, 10, 23, 104, 136, 248, 280] {
            let mut changed = original;
            changed[index] ^= 1;
            assert!(parse_trust(&changed).is_err(), "changed byte {index}");
        }
        let mut same_authority = original;
        same_authority[168..184].copy_from_slice(&original[24..40]);
        assert!(parse_trust(&same_authority).is_err());
    }

    #[test]
    fn trust_generation_requires_one_step_and_rejects_rollback() {
        let original = fixture();
        assert!(validate_transition(&original, 2).is_ok());
        assert!(validate_transition(&original, 1).is_err());
        assert!(validate_transition(&original, 3).is_err());

        let mut successor = original;
        successor[16..24].copy_from_slice(&2_u64.to_be_bytes());
        assert!(validate_transition(&successor, 1).is_err());
    }

    #[test]
    fn protected_trust_readback_rejects_mode_and_replacement() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let trust_path = directory.path().join(TRUST_FILE);
        fs::write(&trust_path, fixture()).unwrap();
        fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o600)).unwrap();

        let descriptor = rustix::fs::open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let owner = rustix::fs::fstat(&descriptor).unwrap().st_uid;
        let (bytes, device, inode) = read_trust(&descriptor, owner).unwrap();
        assert_eq!(bytes, fixture());

        fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_trust(&descriptor, owner),
            Err(StorageLiveExportRequestTrustErrorV1::Custody)
        ));

        let replacement = directory.path().join("replacement");
        fs::write(&replacement, fixture()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &trust_path).unwrap();
        let (_, replaced_device, replaced_inode) = read_trust(&descriptor, owner).unwrap();
        assert_ne!((device, inode), (replaced_device, replaced_inode));
    }
}
