//! Fixed protected persistence for dormant callback registration snapshots.
//!
//! One namespace-50 record retains a canonical connection-scoped snapshot,
//! monotone generation, predecessor head, and exact snapshot digest. The owner
//! opens only the compiled Mount-worker root and basename. It installs no
//! callback, listener, route, descriptor transport, or background task.
//!
//! ```text
//! AOSFRJ02 || version:u16be=2 || generation:u64be || previous-head[32] ||
//! connection-binding[32] || reducer-commitment[32] || snapshot-digest[32] ||
//! snapshot-length:u32be || canonical-snapshot[..] || record-digest[32]
//! ```

use std::path::Path;

use aos_filesystem_view::{DurableRegistrationRecord, DurableStateLimits, MetadataConnection};
use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::DormantFuseRequestDeadlineV2;

const PROTECTED_ROOT: &str = "/var/lib/aos/sandbox-mount/filesystem-worker";
const PROTECTED_JOURNAL: &str = "registrations.journal";
const KEY: &[u8; 8] = b"AOSFRJ02";
const MAGIC: &[u8; 8] = b"AOSFRJ02";
const VERSION: u16 = 2;
const PREFIX_BYTES: usize = 150;
const DIGEST_BYTES: usize = 32;
const MAXIMUM_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const RECORD_DOMAIN: &[u8] = b"aos.filesystem-fuse.registration-record.v2\0";
const SNAPSHOT_DOMAIN: &[u8] = b"aos.filesystem-fuse.registration-snapshot.v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.filesystem-fuse.registration-transaction.v2\0";

fn limits() -> JournalLimits {
    let maximum_record_bytes = PREFIX_BYTES + MAXIMUM_SNAPSHOT_BYTES + DIGEST_BYTES + 1024;
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes,
        maximum_key_bytes: KEY.len(),
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: maximum_record_bytes + 1024,
        maximum_transactions: 65_536,
        maximum_materialized_bytes: maximum_record_bytes,
        maximum_materialized_records: 1,
    }
}

/// Reports fixed protected registration persistence failure without paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtectedFuseRegistrationErrorV2 {
    /// The fixed protected journal could not establish durable authority.
    #[error("protected FUSE registration storage is unavailable")]
    Storage,
    /// Current state differed from the exact expected CAS predecessor or target.
    #[error("protected FUSE registration state is not current")]
    Currentness,
}

/// Owns the fixed protected filesystem-worker registration journal.
///
/// The constructor accepts no path, basename, namespace, or resource limits.
#[must_use = "retain the fixed owner while callback registration authority is live"]
pub struct ProtectedFuseRegistrationOwnerV2 {
    journal: Journal,
}

impl core::fmt::Debug for ProtectedFuseRegistrationOwnerV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedFuseRegistrationOwnerV2([redacted])")
    }
}

impl ProtectedFuseRegistrationOwnerV2 {
    /// Opens and completely validates the fixed protected registration journal.
    ///
    /// This source-only constructor creates no directory and performs no
    /// callback or transport activation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the compiled root already satisfies protected
    /// ownership and the complete journal is canonical and bounded.
    pub fn open_fixed_protected() -> Result<Self, ProtectedFuseRegistrationErrorV2> {
        let (journal, _) =
            Journal::open_protected_at(Path::new(PROTECTED_ROOT), PROTECTED_JOURNAL, limits())
                .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
        let mut owner = Self { journal };
        let _ = owner.read_current()?;
        Ok(owner)
    }

    pub(crate) fn load_current_registration_state(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        durable_limits: DurableStateLimits,
    ) -> Result<
        ([u8; 32], [u8; 32], Vec<DurableRegistrationRecord>),
        ProtectedFuseRegistrationErrorV2,
    > {
        let Some(current) = self.read_current()? else {
            return Ok(([0; 32], [0; 32], Vec::new()));
        };
        if current.connection_binding != connection.connection_binding() {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        let codec = connection
            .durable_state_codec(durable_limits)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Currentness)?;
        let records = codec
            .decode_registrations(&current.snapshot)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Currentness)?;
        if records
            .iter()
            .any(|record| record.callback_reducer_commitment() != current.reducer_commitment)
        {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        Ok((current.head(), current.reducer_commitment, records))
    }

    pub(super) fn replace<'owner>(
        &'owner mut self,
        expected_head: &mut [u8; 32],
        request: DormantFuseRequestDeadlineV2,
        connection_binding: [u8; 32],
        reducer_commitment: [u8; 32],
        canonical: Vec<u8>,
    ) -> ProtectedFuseRegistrationCommitResultV2<'owner> {
        let result = (|| {
            let current = self.read_current()?;
            if current.as_ref().map_or([0; 32], RegistrationRecordV2::head) != *expected_head {
                return Err(ProtectedFuseRegistrationErrorV2::Currentness);
            }
            let target = RegistrationTargetV2::successor(
                current.as_ref(),
                connection_binding,
                reducer_commitment,
                canonical,
            )?;
            *expected_head = target.replacement.head();
            Ok(ProtectedFuseRegistrationRecoveryV2 { target, request })
        })();
        match result {
            Ok(recovery) => self.commit_or_recover(recovery),
            Err(error) => ProtectedFuseRegistrationCommitResultV2::Rejected { error },
        }
    }

    pub(super) fn recover<'owner>(
        &'owner mut self,
        recovery: ProtectedFuseRegistrationRecoveryV2,
    ) -> ProtectedFuseRegistrationCommitResultV2<'owner> {
        self.commit_or_recover(recovery)
    }

    pub(super) fn recovery_target_is_current(
        &mut self,
        recovery: &ProtectedFuseRegistrationRecoveryV2,
    ) -> Result<bool, ProtectedFuseRegistrationErrorV2> {
        Ok(self.read_current()?.as_ref() == Some(&recovery.target.replacement))
    }

    pub(super) fn confirm_recovery_readback<'owner>(
        &'owner mut self,
        recovery: ProtectedFuseRegistrationRecoveryV2,
    ) -> ProtectedFuseRegistrationCommitResultV2<'owner> {
        match self.confirm(&recovery.target.replacement) {
            Ok(readback) => ProtectedFuseRegistrationCommitResultV2::Confirmed(readback),
            Err(error) => {
                ProtectedFuseRegistrationCommitResultV2::RecoveryRequired { error, recovery }
            }
        }
    }

    fn commit_or_recover<'owner>(
        &'owner mut self,
        recovery: ProtectedFuseRegistrationRecoveryV2,
    ) -> ProtectedFuseRegistrationCommitResultV2<'owner> {
        let result = (|| {
            let current = self.read_current()?;
            if current.as_ref() != Some(&recovery.target.replacement) {
                if !recovery.target.matches_predecessor(current.as_ref()) {
                    return Err(ProtectedFuseRegistrationErrorV2::Currentness);
                }
                self.commit(&recovery.target.replacement)?;
            }
            self.confirm(&recovery.target.replacement)
        })();
        match result {
            Ok(readback) => ProtectedFuseRegistrationCommitResultV2::Confirmed(readback),
            Err(error) => {
                ProtectedFuseRegistrationCommitResultV2::RecoveryRequired { error, recovery }
            }
        }
    }

    fn confirm<'owner>(
        &'owner mut self,
        target: &RegistrationRecordV2,
    ) -> Result<ProtectedFuseRegistrationReadbackV2<'owner>, ProtectedFuseRegistrationErrorV2> {
        let current = self
            .read_current()?
            .ok_or(ProtectedFuseRegistrationErrorV2::Currentness)?;
        if current != *target {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        let snapshot = self
            .journal
            .claim_protected_authority(RecordNamespace::FilesystemWorkerRegistration)
            .and_then(|authority| authority.snapshot())
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
        Ok(ProtectedFuseRegistrationReadbackV2 {
            owner: self,
            snapshot,
            generation: current.generation,
            head: current.head(),
            connection_binding: current.connection_binding,
            reducer_commitment: current.reducer_commitment,
            snapshot_digest: current.snapshot_digest,
        })
    }

    fn read_current(
        &mut self,
    ) -> Result<Option<RegistrationRecordV2>, ProtectedFuseRegistrationErrorV2> {
        let authority = self
            .journal
            .claim_protected_authority(RecordNamespace::FilesystemWorkerRegistration)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
        let mut records = authority
            .records()
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
        let current = match records.next() {
            Some((key, value)) if key == KEY => Some(RegistrationRecordV2::decode(value)?),
            Some(_) => return Err(ProtectedFuseRegistrationErrorV2::Currentness),
            None => None,
        };
        if records.next().is_some() {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        Ok(current)
    }

    fn commit(
        &mut self,
        replacement: &RegistrationRecordV2,
    ) -> Result<(), ProtectedFuseRegistrationErrorV2> {
        let value = replacement.encode()?;
        let transaction = JournalTransaction::new(
            transaction_id(replacement)?,
            vec![JournalRecord::put(
                RecordNamespace::FilesystemWorkerRegistration,
                KEY.to_vec(),
                value,
            )],
        )
        .map_err(|_| ProtectedFuseRegistrationErrorV2::Currentness)?;
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::FilesystemWorkerRegistration)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
        validate_commit_predecessor(&authority, replacement.previous_head)?;
        let preflight = authority
            .preflight_transactions(core::slice::from_ref(&transaction))
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
        authority
            .validate_preflight_for_effect(&preflight, core::slice::from_ref(&transaction))
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Currentness)?;
        validate_commit_predecessor(&authority, replacement.previous_head)?;
        authority
            .commit(&transaction)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
        Ok(())
    }
}

fn validate_commit_predecessor(
    authority: &aos_sandbox::ProtectedJournalAuthority<'_>,
    expected_head: [u8; 32],
) -> Result<(), ProtectedFuseRegistrationErrorV2> {
    let current = authority
        .get(KEY)
        .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
    let current_head = current
        .map(RegistrationRecordV2::decode)
        .transpose()?
        .as_ref()
        .map_or([0; 32], RegistrationRecordV2::head);
    if current_head != expected_head {
        return Err(ProtectedFuseRegistrationErrorV2::Currentness);
    }
    Ok(())
}

/// Classifies exact protected registration CAS and readback.
#[must_use = "consume confirmed readback or retain ambiguous recovery ownership"]
pub enum ProtectedFuseRegistrationCommitResultV2<'owner> {
    /// The target is the exact current durable record.
    Confirmed(ProtectedFuseRegistrationReadbackV2<'owner>),
    /// Storage became ambiguous and the exact CAS target must be reopened.
    RecoveryRequired {
        /// Closed protected persistence failure.
        error: ProtectedFuseRegistrationErrorV2,
        /// Exact expected predecessor and replacement bytes.
        recovery: ProtectedFuseRegistrationRecoveryV2,
    },
    /// No mutation occurred because current state was invalid.
    Rejected {
        /// Closed validation failure proving that no CAS target was prepared.
        error: ProtectedFuseRegistrationErrorV2,
    },
}

/// Retains one exact registration CAS across protected-owner reopen.
#[must_use = "recover this exact expected predecessor or replacement"]
pub struct ProtectedFuseRegistrationRecoveryV2 {
    target: RegistrationTargetV2,
    request: DormantFuseRequestDeadlineV2,
}

impl ProtectedFuseRegistrationRecoveryV2 {
    pub(super) fn matches(
        &self,
        connection_binding: [u8; 32],
        reducer_commitment: [u8; 32],
        canonical: &[u8],
    ) -> bool {
        self.target.replacement.connection_binding == connection_binding
            && self.target.replacement.reducer_commitment == reducer_commitment
            && self.target.replacement.snapshot_digest == snapshot_digest(canonical)
            && self.target.replacement.snapshot == canonical
    }

    pub(super) fn replacement_head(&self) -> [u8; 32] {
        self.target.replacement.head()
    }

    pub(super) const fn request(&self) -> DormantFuseRequestDeadlineV2 {
        self.request
    }
}

/// Holds an exact readback and the fixed owner's unique mutable borrow.
#[must_use = "consume immediately at its callback effect or cleanup boundary"]
pub struct ProtectedFuseRegistrationReadbackV2<'owner> {
    owner: &'owner mut ProtectedFuseRegistrationOwnerV2,
    snapshot: aos_sandbox::ProtectedJournalSnapshot,
    generation: u64,
    head: [u8; 32],
    connection_binding: [u8; 32],
    reducer_commitment: [u8; 32],
    snapshot_digest: [u8; 32],
}

impl ProtectedFuseRegistrationReadbackV2<'_> {
    pub(super) fn validate(
        self,
        connection_binding: [u8; 32],
        reducer_commitment: [u8; 32],
        canonical: &[u8],
    ) -> Result<Self, ProtectedFuseRegistrationErrorV2> {
        let authority = self
            .owner
            .journal
            .claim_protected_authority(RecordNamespace::FilesystemWorkerRegistration)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?;
        authority
            .validate_snapshot_for_effect(&self.snapshot)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Currentness)?;
        let current = authority
            .get(KEY)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Storage)?
            .ok_or(ProtectedFuseRegistrationErrorV2::Currentness)?;
        let record = RegistrationRecordV2::decode(current)?;
        if self.generation != record.generation
            || self.head != record.head()
            || self.connection_binding != connection_binding
            || self.connection_binding != record.connection_binding
            || self.reducer_commitment != reducer_commitment
            || self.reducer_commitment != record.reducer_commitment
            || self.snapshot_digest != snapshot_digest(canonical)
            || self.snapshot_digest != record.snapshot_digest
            || record.snapshot != canonical
        {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        drop(authority);
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistrationTargetV2 {
    expected_generation: u64,
    expected_head: [u8; 32],
    expected_snapshot_digest: [u8; 32],
    replacement: RegistrationRecordV2,
}

impl RegistrationTargetV2 {
    fn successor(
        current: Option<&RegistrationRecordV2>,
        connection_binding: [u8; 32],
        reducer_commitment: [u8; 32],
        snapshot: Vec<u8>,
    ) -> Result<Self, ProtectedFuseRegistrationErrorV2> {
        if connection_binding == [0; 32]
            || reducer_commitment == [0; 32]
            || snapshot.len() > MAXIMUM_SNAPSHOT_BYTES
        {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        let expected_generation = current.map_or(0, |record| record.generation);
        let expected_head = current.map_or([0; 32], RegistrationRecordV2::head);
        let expected_snapshot_digest = current.map_or([0; 32], |record| record.snapshot_digest);
        let generation = expected_generation
            .checked_add(1)
            .ok_or(ProtectedFuseRegistrationErrorV2::Currentness)?;
        let replacement = RegistrationRecordV2::new(
            generation,
            expected_head,
            connection_binding,
            reducer_commitment,
            snapshot,
        )?;
        Ok(Self {
            expected_generation,
            expected_head,
            expected_snapshot_digest,
            replacement,
        })
    }

    fn matches_predecessor(&self, current: Option<&RegistrationRecordV2>) -> bool {
        match current {
            Some(record) => {
                record.generation == self.expected_generation
                    && record.head() == self.expected_head
                    && record.snapshot_digest == self.expected_snapshot_digest
            }
            None => {
                self.expected_generation == 0
                    && self.expected_head == [0; 32]
                    && self.expected_snapshot_digest == [0; 32]
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistrationRecordV2 {
    generation: u64,
    previous_head: [u8; 32],
    connection_binding: [u8; 32],
    reducer_commitment: [u8; 32],
    snapshot_digest: [u8; 32],
    snapshot: Vec<u8>,
}

impl RegistrationRecordV2 {
    fn new(
        generation: u64,
        previous_head: [u8; 32],
        connection_binding: [u8; 32],
        reducer_commitment: [u8; 32],
        snapshot: Vec<u8>,
    ) -> Result<Self, ProtectedFuseRegistrationErrorV2> {
        if generation == 0
            || (generation == 1) != (previous_head == [0; 32])
            || connection_binding == [0; 32]
            || reducer_commitment == [0; 32]
            || snapshot.len() > MAXIMUM_SNAPSHOT_BYTES
        {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        Ok(Self {
            generation,
            previous_head,
            connection_binding,
            reducer_commitment,
            snapshot_digest: snapshot_digest(&snapshot),
            snapshot,
        })
    }

    fn head(&self) -> [u8; 32] {
        record_digest(&self.encode_without_digest())
    }

    fn encode_without_digest(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(PREFIX_BYTES + self.snapshot.len());
        value.extend_from_slice(MAGIC);
        value.extend_from_slice(&VERSION.to_be_bytes());
        value.extend_from_slice(&self.generation.to_be_bytes());
        value.extend_from_slice(&self.previous_head);
        value.extend_from_slice(&self.connection_binding);
        value.extend_from_slice(&self.reducer_commitment);
        value.extend_from_slice(&self.snapshot_digest);
        value.extend_from_slice(&(self.snapshot.len() as u32).to_be_bytes());
        value.extend_from_slice(&self.snapshot);
        value
    }

    fn encode(&self) -> Result<Vec<u8>, ProtectedFuseRegistrationErrorV2> {
        if self.snapshot_digest != snapshot_digest(&self.snapshot) {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        let mut value = self.encode_without_digest();
        let digest = record_digest(&value);
        value.extend_from_slice(&digest);
        Ok(value)
    }

    fn decode(value: &[u8]) -> Result<Self, ProtectedFuseRegistrationErrorV2> {
        if value.len() < PREFIX_BYTES + DIGEST_BYTES
            || value.len() > PREFIX_BYTES + MAXIMUM_SNAPSHOT_BYTES + DIGEST_BYTES
            || value.get(..8) != Some(MAGIC.as_slice())
            || read_u16(value, 8)? != VERSION
        {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        let generation = read_u64(value, 10)?;
        let previous_head = read_array(value, 18)?;
        let connection_binding = read_array(value, 50)?;
        let reducer_commitment = read_array(value, 82)?;
        let expected_snapshot_digest = read_array(value, 114)?;
        let snapshot_length = usize::try_from(read_u32(value, 146)?)
            .map_err(|_| ProtectedFuseRegistrationErrorV2::Currentness)?;
        let snapshot_end = PREFIX_BYTES
            .checked_add(snapshot_length)
            .ok_or(ProtectedFuseRegistrationErrorV2::Currentness)?;
        let digest_end = snapshot_end
            .checked_add(DIGEST_BYTES)
            .ok_or(ProtectedFuseRegistrationErrorV2::Currentness)?;
        let snapshot = value
            .get(PREFIX_BYTES..snapshot_end)
            .ok_or(ProtectedFuseRegistrationErrorV2::Currentness)?
            .to_vec();
        if digest_end != value.len()
            || expected_snapshot_digest != snapshot_digest(&snapshot)
            || read_array::<32>(value, snapshot_end)? != record_digest(&value[..snapshot_end])
        {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        let record = Self::new(
            generation,
            previous_head,
            connection_binding,
            reducer_commitment,
            snapshot,
        )?;
        if record.encode()? != value {
            return Err(ProtectedFuseRegistrationErrorV2::Currentness);
        }
        Ok(record)
    }
}

fn snapshot_digest(snapshot: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SNAPSHOT_DOMAIN);
    digest.update(snapshot);
    digest.finalize().into()
}

fn record_digest(value_without_digest: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECORD_DOMAIN);
    digest.update(value_without_digest);
    digest.finalize().into()
}

fn transaction_id(
    record: &RegistrationRecordV2,
) -> Result<[u8; 16], ProtectedFuseRegistrationErrorV2> {
    let mut digest = Sha256::new();
    digest.update(TRANSACTION_DOMAIN);
    digest.update(record.generation.to_be_bytes());
    digest.update(record.previous_head);
    digest.update(record.head());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[..16]);
    if id == [0; 16] {
        return Err(ProtectedFuseRegistrationErrorV2::Currentness);
    }
    Ok(id)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ProtectedFuseRegistrationErrorV2> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ProtectedFuseRegistrationErrorV2> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ProtectedFuseRegistrationErrorV2> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProtectedFuseRegistrationErrorV2> {
    bytes
        .get(offset..offset + N)
        .ok_or(ProtectedFuseRegistrationErrorV2::Currentness)?
        .try_into()
        .map_err(|_| ProtectedFuseRegistrationErrorV2::Currentness)
}
