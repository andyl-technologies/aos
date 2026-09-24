//! Private descriptor custody for detached read-only LocalLive clones.
//!
//! ```text
//! key   = provider-authority-id[16] | generation:u64be | plan-id[16]
//! value = AOSSLM02 | version:u16be=2 | state:u8 | reserved[5]=0 |
//!         request-readback-digest[32] | boot-id[16] |
//!         clone-mount-id:u64be | root-device:u64be | root-inode:u64be |
//!         holder-cgroup-id:u64be=0 | grant-epoch:u64be=0
//! ```
//!
//! The journal lives under Storage's protected writable state root, not its
//! immutable authority directory. No clone FD leaves Storage. The worker has
//! terminated before construction, so process death closes Storage's sole
//! remaining clone reference. An active record found after cold restart is
//! uncertain and cannot be reused; it does not resurrect an FD or imply a
//! kernel grant. The v2 record rejects the v1 direct active-to-closed
//! transition. Its zero holder/epoch fields state that this private clone has
//! never been handed to a grant owner.

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::MountId;
use rustix::fs::{FileType, OFlags, StatVfsMountFlags};
use sha2::{Digest as _, Sha256};

use crate::live_export_request_readback::StorageLiveExportReadbackV1;

const JOURNAL_FILE: &str = "storage-live-export-clones.journal";
const MAGIC: &[u8; 8] = b"AOSSLM02";
const VERSION: u16 = 2;
const KEY_BYTES: usize = 40;
const VALUE_BYTES: usize = 104;
const ACTIVE: u8 = 1;
const STOPPING: u8 = 2;
const CLOSED: u8 = 3;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-clone.v2\0";
const LOCAL_CLOSURE_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-local-closure.v2\0";

/// Reports unsafe clone custody, replay, or physical identity.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageLiveExportCloneErrorV1 {
    /// The protected clone lifecycle record is absent, malformed, or conflicts.
    #[error("Storage live-export clone lifecycle is uncertain")]
    Uncertain,
    /// The detached descriptor lacks the expected read-only physical identity.
    #[error("Storage live-export clone descriptor is invalid")]
    Physical,
    /// Protected journal custody or commit failed.
    #[error("Storage live-export clone journal failed: {0}")]
    Journal(#[from] JournalError),
}

/// Retains one private detached mount until explicit local revocation.
pub(crate) struct StorageLiveExportCloneV1 {
    mount: OwnedFd,
    key: [u8; KEY_BYTES],
    value: [u8; VALUE_BYTES],
}

/// Commits only local FD closure, never a holder or KernelExportGrant release.
#[must_use]
pub(crate) struct StoragePrivateCloneClosureV2 {
    digest: ObjectDigest,
}

impl StoragePrivateCloneClosureV2 {
    /// Returns the durable local-closure commitment for diagnostics.
    pub(crate) const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

impl StorageLiveExportCloneV1 {
    /// Verifies the received worker FD and durably records its exact identity.
    ///
    /// No caller receives an FD accessor. The already quiescent worker and
    /// this object are the complete current reference set; future FD egress
    /// requires a separate grant-aware owner and terminal release protocol.
    pub(crate) fn retain(
        mount: OwnedFd,
        readback: &StorageLiveExportReadbackV1,
        ledger: &mut StorageLiveExportCloneLedgerV1,
    ) -> Result<Self, StorageLiveExportCloneErrorV1> {
        let source = readback.source();
        let boot = KernelBootId::current()
            .map_err(|_| StorageLiveExportCloneErrorV1::Physical)?
            .into_bytes();
        let stat =
            rustix::fs::fstat(&mount).map_err(|_| StorageLiveExportCloneErrorV1::Physical)?;
        let mount_id = MountId::from_fd(mount.as_fd())
            .map_err(|_| StorageLiveExportCloneErrorV1::Physical)?
            .get();
        let flags = rustix::fs::fstatvfs(&mount)
            .map_err(|_| StorageLiveExportCloneErrorV1::Physical)?
            .f_flag;
        let status =
            rustix::fs::fcntl_getfl(&mount).map_err(|_| StorageLiveExportCloneErrorV1::Physical)?;
        let descriptor =
            rustix::io::fcntl_getfd(&mount).map_err(|_| StorageLiveExportCloneErrorV1::Physical)?;
        if boot != source.origin_boot_id()
            || stat.st_dev != source.origin_device()
            || stat.st_ino != source.origin_inode()
            || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || mount_id == source.origin_mount_id()
            || !flags.contains(
                StatVfsMountFlags::RDONLY | StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV,
            )
            || !status.contains(OFlags::PATH)
            || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(StorageLiveExportCloneErrorV1::Physical);
        }
        let key = replay_key(readback)?;
        let value = record_value(
            readback.digest(),
            boot,
            mount_id,
            stat.st_dev,
            stat.st_ino,
            ACTIVE,
        )?;
        ledger.record_new(key, value)?;
        Ok(Self { mount, key, value })
    }

    /// Rechecks the retained physical object without upgrading it to authority.
    pub(crate) fn validate_current(&self) -> Result<(), StorageLiveExportCloneErrorV1> {
        let stat =
            rustix::fs::fstat(&self.mount).map_err(|_| StorageLiveExportCloneErrorV1::Physical)?;
        let mount_id = MountId::from_fd(self.mount.as_fd())
            .map_err(|_| StorageLiveExportCloneErrorV1::Physical)?
            .get();
        let flags = rustix::fs::fstatvfs(&self.mount)
            .map_err(|_| StorageLiveExportCloneErrorV1::Physical)?
            .f_flag;
        let status = rustix::fs::fcntl_getfl(&self.mount)
            .map_err(|_| StorageLiveExportCloneErrorV1::Physical)?;
        let descriptor = rustix::io::fcntl_getfd(&self.mount)
            .map_err(|_| StorageLiveExportCloneErrorV1::Physical)?;
        let boot = KernelBootId::current()
            .map_err(|_| StorageLiveExportCloneErrorV1::Physical)?
            .into_bytes();
        if boot != self.value[48..64]
            || mount_id.to_be_bytes() != self.value[64..72]
            || stat.st_dev.to_be_bytes() != self.value[72..80]
            || stat.st_ino.to_be_bytes() != self.value[80..88]
            || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || !flags.contains(
                StatVfsMountFlags::RDONLY | StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV,
            )
            || !status.contains(OFlags::PATH)
            || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(StorageLiveExportCloneErrorV1::Physical);
        }
        Ok(())
    }

    /// Stops the private clone, drops Storage's FD, then records local closure.
    ///
    /// The worker has already quiesced, and no clone FD can leave this type.
    /// The stop transition is durable before dropping the descriptor. A crash
    /// before the final commit leaves an active/stopping record that cold
    /// startup rejects. This cannot prove release of an escaped FD or mmap,
    /// and no grant-aware handoff is reachable from this API.
    pub(crate) fn revoke_local(
        self,
        ledger: &mut StorageLiveExportCloneLedgerV1,
    ) -> Result<StoragePrivateCloneClosureV2, StorageLiveExportCloneErrorV1> {
        self.validate_current()?;

        let key = self.key;
        let mut stopping = self.value;
        stopping[10] = STOPPING;
        ledger.record_transition(key, stopping, ACTIVE, STOPPING)?;

        let mut closed = self.value;
        closed[10] = CLOSED;
        drop(self);
        ledger.record_transition(key, closed, STOPPING, CLOSED)?;
        Ok(StoragePrivateCloneClosureV2 {
            digest: local_closure_digest(key, closed),
        })
    }
}

/// Owns the durable, non-authorizing clone lifecycle journal.
pub(crate) struct StorageLiveExportCloneLedgerV1 {
    journal: Journal,
}

impl StorageLiveExportCloneLedgerV1 {
    /// Opens protected Storage custody; unresolved active records stay closed.
    pub(crate) fn open_root_owned(directory: &Path) -> Result<Self, StorageLiveExportCloneErrorV1> {
        let mut journal = Journal::open_protected_at(directory, JOURNAL_FILE, journal_limits())?.0;
        let authority = journal.claim_protected_authority(RecordNamespace::AuthorityPublication)?;
        ensure_cold_records_closed(authority.records()?)?;
        drop(authority);
        Ok(Self { journal })
    }

    fn record_new(
        &mut self,
        key: [u8; KEY_BYTES],
        value: [u8; VALUE_BYTES],
    ) -> Result<(), StorageLiveExportCloneErrorV1> {
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::AuthorityPublication)?;
        ensure_new(authority.get(&key)?)?;
        authority.commit(&transaction(key, value)?)?;
        if authority.get(&key)? != Some(value.as_slice()) {
            return Err(StorageLiveExportCloneErrorV1::Uncertain);
        }
        Ok(())
    }

    fn record_transition(
        &mut self,
        key: [u8; KEY_BYTES],
        value: [u8; VALUE_BYTES],
        previous_state: u8,
        next_state: u8,
    ) -> Result<(), StorageLiveExportCloneErrorV1> {
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::AuthorityPublication)?;
        ensure_transition_matches(authority.get(&key)?, &value, previous_state, next_state)?;
        authority.commit(&transaction(key, value)?)?;
        if authority.get(&key)? != Some(value.as_slice()) {
            return Err(StorageLiveExportCloneErrorV1::Uncertain);
        }
        Ok(())
    }
}

fn ensure_new(previous: Option<&[u8]>) -> Result<(), StorageLiveExportCloneErrorV1> {
    if previous.is_some() {
        return Err(StorageLiveExportCloneErrorV1::Uncertain);
    }
    Ok(())
}

fn ensure_transition_matches(
    previous: Option<&[u8]>,
    next: &[u8; VALUE_BYTES],
    previous_state: u8,
    next_state: u8,
) -> Result<(), StorageLiveExportCloneErrorV1> {
    let current = previous.ok_or(StorageLiveExportCloneErrorV1::Uncertain)?;
    if !canonical_record(current)
        || !canonical_record(next)
        || !matches!(
            (previous_state, next_state),
            (ACTIVE, STOPPING) | (STOPPING, CLOSED)
        )
        || current[10] != previous_state
        || next[10] != next_state
        || current[..10] != next[..10]
        || current[11..] != next[11..]
    {
        return Err(StorageLiveExportCloneErrorV1::Uncertain);
    }
    Ok(())
}

fn canonical_record(value: &[u8]) -> bool {
    value.len() == VALUE_BYTES
        && &value[..8] == MAGIC
        && value[8..10] == VERSION.to_be_bytes()
        && matches!(value[10], ACTIVE | STOPPING | CLOSED)
        && value[11..16] == [0; 5]
        && value[16..48] != [0; 32]
        && value[48..64] != [0; 16]
        && value[64..72] != [0; 8]
        && value[72..80] != [0; 8]
        && value[80..88] != [0; 8]
        && value[88..104] == [0; 16]
}

fn replay_key(
    readback: &StorageLiveExportReadbackV1,
) -> Result<[u8; KEY_BYTES], StorageLiveExportCloneErrorV1> {
    let (provider, generation, plan) = readback.replay_identity();
    if provider == [0; 16] || generation == 0 || plan == [0; 16] {
        return Err(StorageLiveExportCloneErrorV1::Uncertain);
    }
    let mut key = [0; KEY_BYTES];
    key[..16].copy_from_slice(&provider);
    key[16..24].copy_from_slice(&generation.to_be_bytes());
    key[24..40].copy_from_slice(&plan);
    Ok(key)
}

fn canonical_key(key: &[u8]) -> bool {
    key.len() == KEY_BYTES
        && key[..16] != [0; 16]
        && key[16..24] != [0; 8]
        && key[24..40] != [0; 16]
}

fn ensure_cold_records_closed<'a>(
    records: impl Iterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<(), StorageLiveExportCloneErrorV1> {
    for (key, value) in records {
        if !canonical_key(key) || !canonical_record(value) || value[10] != CLOSED {
            return Err(StorageLiveExportCloneErrorV1::Uncertain);
        }
    }
    Ok(())
}

fn record_value(
    digest: ObjectDigest,
    boot: [u8; 16],
    mount_id: u64,
    device: u64,
    inode: u64,
    state: u8,
) -> Result<[u8; VALUE_BYTES], StorageLiveExportCloneErrorV1> {
    if digest.as_bytes() == &[0; 32]
        || boot == [0; 16]
        || mount_id == 0
        || device == 0
        || inode == 0
        || !matches!(state, ACTIVE | STOPPING | CLOSED)
    {
        return Err(StorageLiveExportCloneErrorV1::Uncertain);
    }
    let mut value = [0; VALUE_BYTES];
    value[..8].copy_from_slice(MAGIC);
    value[8..10].copy_from_slice(&VERSION.to_be_bytes());
    value[10] = state;
    value[16..48].copy_from_slice(digest.as_bytes());
    value[48..64].copy_from_slice(&boot);
    value[64..72].copy_from_slice(&mount_id.to_be_bytes());
    value[72..80].copy_from_slice(&device.to_be_bytes());
    value[80..88].copy_from_slice(&inode.to_be_bytes());
    Ok(value)
}

fn local_closure_digest(key: [u8; KEY_BYTES], closed: [u8; VALUE_BYTES]) -> ObjectDigest {
    let hash = Sha256::new()
        .chain_update(LOCAL_CLOSURE_DOMAIN)
        .chain_update(key)
        .chain_update(closed)
        .finalize();
    ObjectDigest::from_bytes(hash.into())
}

fn transaction(
    key: [u8; KEY_BYTES],
    value: [u8; VALUE_BYTES],
) -> Result<JournalTransaction, StorageLiveExportCloneErrorV1> {
    let hash = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(key)
        .chain_update(value)
        .finalize();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&hash[..16]);
    Ok(JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::AuthorityPublication,
            key.to_vec(),
            value.to_vec(),
        )],
    )?)
}

const fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: 256,
        maximum_key_bytes: KEY_BYTES,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 512,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: 8 * 1024 * 1024,
        maximum_materialized_records: 65_536,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;

    #[test]
    fn record_is_versioned_and_rejects_zero_physical_identity() {
        assert!(record_value(ObjectDigest::from_bytes([1; 32]), [1; 16], 0, 3, 4, ACTIVE).is_err());
        let value =
            record_value(ObjectDigest::from_bytes([1; 32]), [1; 16], 2, 3, 4, ACTIVE).unwrap();
        assert_eq!(&value[..8], MAGIC);
        assert_eq!(value[10], ACTIVE);
        assert_eq!(&value[11..16], &[0; 5]);
        assert!(canonical_record(&value));

        for (index, changed) in [(0, 0), (9, 3), (10, 4), (11, 1)] {
            let mut tampered = value;
            tampered[index] = changed;
            assert!(!canonical_record(&tampered), "changed byte {index}");
        }
        let mut zero_digest = value;
        zero_digest[16..48].fill(0);
        assert!(!canonical_record(&zero_digest));
        let mut forged_holder = value;
        forged_holder[88] = 1;
        assert!(!canonical_record(&forged_holder));
        let mut old_version = value;
        old_version[..8].copy_from_slice(b"AOSSLM01");
        old_version[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(!canonical_record(&old_version));
        assert!(!canonical_record(&old_version[..88]));
        assert!(!canonical_record(&value[..VALUE_BYTES - 1]));
    }

    #[test]
    fn active_clone_survives_crash_prefix_and_rejects_reuse_or_forged_close() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(JOURNAL_FILE);
        let key = [7; KEY_BYTES];
        let active =
            record_value(ObjectDigest::from_bytes([1; 32]), [2; 16], 3, 4, 5, ACTIVE).unwrap();
        let mut journal = Journal::open(&path, journal_limits()).unwrap().0;
        journal.commit(&transaction(key, active).unwrap()).unwrap();
        drop(journal);

        let mut tail = fs::OpenOptions::new().append(true).open(&path).unwrap();
        tail.write_all(&[0xa0, 0x53, 0x17]).unwrap();
        tail.sync_all().unwrap();
        drop(tail);

        let reopened = Journal::open(&path, journal_limits()).unwrap().0;
        let recovered = reopened.get(RecordNamespace::AuthorityPublication, &key);
        assert!(ensure_new(recovered).is_err());
        assert!(recovered.is_some_and(|value| value[10] == ACTIVE));
        assert!(
            ensure_cold_records_closed(reopened.records(RecordNamespace::AuthorityPublication))
                .is_err()
        );
        let mut stopping = active;
        stopping[10] = STOPPING;
        assert!(ensure_transition_matches(recovered, &stopping, ACTIVE, STOPPING).is_ok());
        let mut forged = stopping;
        forged[64] ^= 1;
        assert!(ensure_transition_matches(recovered, &forged, ACTIVE, STOPPING).is_err());
        let mut closed = active;
        closed[10] = CLOSED;
        assert!(ensure_transition_matches(recovered, &closed, ACTIVE, CLOSED).is_err());

        drop(reopened);
        let mut writable = Journal::open(&path, journal_limits()).unwrap().0;
        writable
            .commit(&transaction(key, stopping).unwrap())
            .unwrap();
        drop(writable);
        let stopped = Journal::open(&path, journal_limits()).unwrap().0;
        let recovered_stopping = stopped.get(RecordNamespace::AuthorityPublication, &key);
        assert!(ensure_transition_matches(recovered_stopping, &closed, STOPPING, CLOSED).is_ok());
        assert!(
            ensure_cold_records_closed(stopped.records(RecordNamespace::AuthorityPublication))
                .is_err()
        );
        drop(stopped);
        let mut writable = Journal::open(&path, journal_limits()).unwrap().0;
        writable.commit(&transaction(key, closed).unwrap()).unwrap();
        drop(writable);
        let recovered_closed = Journal::open(&path, journal_limits()).unwrap().0;
        assert!(
            ensure_cold_records_closed(
                recovered_closed.records(RecordNamespace::AuthorityPublication)
            )
            .is_ok()
        );
        assert_ne!(local_closure_digest(key, closed).as_bytes(), &[0; 32]);
    }
}
