//! Bounded original-pair native observations, never canonical floor authority.
//!
//! The existing Journal parser alone supplies validated COMMIT transactions.
//! Captures retain bounded native transactions and boundaries, not full-map
//! prefixes, another materializer or a checkpoint/phase decoder. Fixed original
//! names and independent-offset reads bracket the actual held writer snapshot.
//! The later Security store must separately compare all eight sidecar limits
//! and its typed initialization/prepare/finalize history under genuine Origins.

use std::mem::size_of;
use std::path::Path;

use crate::runtime_deployment::{
    MAIN_DIRECTORY_V1, MAIN_LIMITS, NAMESPACE, SIDECAR_NAME,
    VerifiedDeploymentGenesisV1,
};

use super::runtime_deployment_history::ReadAtCursorV1;
use super::{
    FileIdentity, Journal, JournalError, JournalLimits, JournalRecord,
    JournalTransaction, ReplayState, replay_sidecar_observed,
};

/// Carries exact native transaction DATA captured under a genuine held pair.
///
/// Fields and construction stay private. A copied transaction or boundary is
/// historical DATA, never a floor, append permission or physical observation.
#[derive(Debug, Eq, PartialEq)]
pub struct RuntimeDeploymentNativeTransactionDataV1 {
    transaction: JournalTransaction,
    begin_sequence: u64,
    commit_sequence: u64,
    next_sequence: u64,
}

impl RuntimeDeploymentNativeTransactionDataV1 {
    /// Borrows the exact original UUID and ordered records as historical DATA.
    #[must_use]
    pub fn transaction(&self) -> &JournalTransaction {
        &self.transaction
    }

    /// Returns the original native BEGIN boundary, not an append token.
    #[must_use]
    pub const fn begin_sequence(&self) -> u64 {
        self.begin_sequence
    }

    /// Returns the validated original native COMMIT sequence.
    #[must_use]
    pub const fn commit_sequence(&self) -> u64 {
        self.commit_sequence
    }

    /// Returns the checked boundary immediately after that original COMMIT.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
}

/// Retains only bounded transactions delivered by the existing native parser.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RetainedDeploymentNativeHistoryV1 {
    transactions: Vec<RuntimeDeploymentNativeTransactionDataV1>,
    committed_records: usize,
    retained_bytes: usize,
    maximum_retained_bytes: usize,
    next_sequence: u64,
}

impl RetainedDeploymentNativeHistoryV1 {
    pub(in crate::journal) fn new(physical_length: u64) -> Result<Self, JournalError> {
        if physical_length > MAIN_LIMITS.maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }
        let maximum_retained_bytes = usize::try_from(physical_length)
            .map_err(|_| JournalError::JournalTooLarge)?;
        Ok(Self {
            transactions: Vec::new(),
            committed_records: 0,
            retained_bytes: 0,
            maximum_retained_bytes,
            next_sequence: 1,
        })
    }

    pub(crate) fn transactions(&self) -> &[RuntimeDeploymentNativeTransactionDataV1] {
        &self.transactions
    }

    pub(in crate::journal) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
    ) -> Result<(), JournalError> {
        let count = transaction.records().len();
        let commit_distance = u64::try_from(count)
            .ok()
            .and_then(|records| records.checked_add(1))
            .ok_or(JournalError::SequenceExhausted)?;
        let next_sequence = commit_sequence.checked_add(1)
            .filter(|next| *next != u64::MAX)
            .ok_or(JournalError::SequenceExhausted)?;
        if count == 0
            || begin_sequence != self.next_sequence
            || begin_sequence.checked_add(commit_distance) != Some(commit_sequence)
            || transaction.id() == &[0; 16]
            || &transaction.id()[8..] == b"compact1"
            || transaction.records().iter().any(|record| record.namespace() != NAMESPACE)
        {
            return Err(JournalError::ProtectedBoundary);
        }

        // Validate the complete retained allocation charge before the first
        // reservation/copy. Ordinary parser limits have already validated TXs.
        let transaction_bytes = retained_transaction_bytes(transaction)?;
        let retained_bytes = self.retained_bytes.checked_add(transaction_bytes)
            .filter(|bytes| *bytes <= self.maximum_retained_bytes)
            .ok_or(JournalError::LimitExceeded("deployment retained native bytes"))?;
        let committed_records = self.committed_records.checked_add(count)
            .ok_or(JournalError::LimitExceeded("deployment retained native records"))?;
        let transactions = self.transactions.len().checked_add(1)
            .ok_or(JournalError::LimitExceeded("deployment retained native transactions"))?;
        if transactions > self.maximum_retained_bytes {
            return Err(JournalError::LimitExceeded("deployment retained native transactions"));
        }

        self.transactions.try_reserve_exact(1)
            .map_err(|_| retention_allocation_error())?;
        let transaction = copy_transaction(transaction)?;
        self.transactions.push(RuntimeDeploymentNativeTransactionDataV1 {
            transaction,
            begin_sequence,
            commit_sequence,
            next_sequence,
        });
        self.committed_records = committed_records;
        self.retained_bytes = retained_bytes;
        self.next_sequence = next_sequence;
        Ok(())
    }

    pub(in crate::journal) fn finish(&self, replayed: &ReplayState) -> Result<(), JournalError> {
        if self.transactions.is_empty()
            || self.transactions.len() != replayed.committed_transactions
            || self.committed_records != replayed.committed_records
            || self.next_sequence != replayed.next_sequence
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

/// Captures mechanical sidecar observations without interpreting floor claims.
pub(super) struct SidecarHistoryAuditV1 {
    retained: RetainedDeploymentNativeHistoryV1,
}

impl SidecarHistoryAuditV1 {
    pub(super) fn new(physical_length: u64) -> Result<Self, JournalError> {
        Ok(Self {
            retained: RetainedDeploymentNativeHistoryV1::new(physical_length)?,
        })
    }

    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
    ) -> Result<(), JournalError> {
        self.retained.observe(transaction, begin_sequence, commit_sequence)
    }

    fn finish(self, replayed: &ReplayState) -> Result<RetainedDeploymentNativeHistoryV1, JournalError> {
        self.retained.finish(replayed)?;
        Ok(self.retained)
    }
}

impl Journal {
    /// Rereads this actual original fixed sidecar with the sole native parser.
    pub(crate) fn capture_runtime_deployment_sidecar_history_v1(
        &self,
        owner: &VerifiedDeploymentGenesisV1<'_>,
    ) -> Result<RetainedDeploymentNativeHistoryV1, JournalError> {
        owner.recheck().map_err(|_| JournalError::ProtectedBoundary)?;
        require_sidecar_capture_limits(self.limits)?;
        self.require_protected_named_location(
            Path::new(MAIN_DIRECTORY_V1), SIDECAR_NAME, 0, self.limits,
        )?;
        let witness = self.protected_writer_name_witness()?;
        let physical = FileIdentity::of(&self.file)?;
        if physical.size > MAIN_LIMITS.maximum_journal_bytes
            || physical.size > self.limits.maximum_journal_bytes
        {
            return Err(JournalError::JournalTooLarge);
        }

        let result = (|| {
            let mut history = SidecarHistoryAuditV1::new(physical.size)?;
            let mut reader = ReadAtCursorV1::new(&self.file, physical.size);
            let replayed = replay_sidecar_observed(&mut reader, self.limits, &mut history)?;
            let retained = history.finish(&replayed)?;
            self.require_deployment_pair_replayed_snapshot_v1(
                &replayed, physical.size,
            )?;
            Ok(retained)
        })();

        // These physical/origin bookends also run after a failed parse/copy.
        self.require_protected_named_location(
            Path::new(MAIN_DIRECTORY_V1), SIDECAR_NAME, 0, self.limits,
        )?;
        self.validate_protected_writer_name_witness(&witness)?;
        if FileIdentity::of(&self.file)? != physical {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        owner.recheck().map_err(|_| JournalError::ProtectedBoundary)?;
        result
    }

    pub(crate) fn require_deployment_pair_independence_v1(
        &self,
        sidecar: &Journal,
    ) -> Result<(), JournalError> {
        let main_names = self.protected_writer_physical_names_v1()?;
        let sidecar_names = sidecar.protected_writer_physical_names_v1()?;
        let names = [
            main_names.journal, main_names.lock,
            sidecar_names.journal, sidecar_names.lock,
        ];
        if main_names.directory != sidecar_names.directory
            || names.iter().enumerate().any(|(index, name)| {
                names[..index].contains(name)
            })
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Compares original replay fields shared by main and sidecar, not row counts.
    pub(in crate::journal) fn require_deployment_pair_replayed_snapshot_v1(
        &self,
        replayed: &ReplayState,
        physical_length: u64,
    ) -> Result<(), JournalError> {
        if replayed.durable_end != physical_length
            || replayed.next_sequence != self.next_sequence
            || replayed.committed_transactions != self.committed_transactions
            || replayed.transaction_ids != self.transaction_ids
            || replayed.committed_namespaces != self.committed_namespaces
            || replayed.state != self.state
            || replayed.materialized_bytes != self.materialized_bytes
            || replayed.idempotency != self.idempotency
            || replayed.committed_namespaces.iter().any(|namespace| *namespace != NAMESPACE)
            || !replayed.source_challenge_history.is_empty()
            || !self.source_challenge_history.is_empty()
            || replayed.source_original_replay.has_dependencies()
            || self.source_original_replay.has_dependencies()
            || replayed.source_history_compacted
            || self.source_history_compacted
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        // Namespace27 cannot populate Source challenge/original caches. Their
        // absent state above is required rather than granting cross-role DATA.
        Ok(())
    }
}

/// Bounds every original parser allocation as well as physical capture length.
///
/// These are mechanical resource ceilings, not the eight canonical sidecar
/// limits: the Security owner must derive/compare those through its one engine.
fn require_sidecar_capture_limits(limits: JournalLimits) -> Result<(), JournalError> {
    let maximum = usize::try_from(MAIN_LIMITS.maximum_journal_bytes)
        .map_err(|_| JournalError::JournalTooLarge)?;
    let maximum_record = maximum.checked_sub(7)
        .ok_or(JournalError::JournalTooLarge)?;
    if limits.maximum_journal_bytes == 0
        || limits.maximum_journal_bytes > MAIN_LIMITS.maximum_journal_bytes
        || limits.maximum_record_bytes == 0
        || limits.maximum_record_bytes > maximum_record
        || limits.maximum_records_per_transaction > maximum / size_of::<JournalRecord>()
        || limits.maximum_transactions > maximum / size_of::<RuntimeDeploymentNativeTransactionDataV1>()
        || limits.maximum_materialized_records > maximum / size_of::<JournalRecord>()
        || [
            limits.maximum_key_bytes,
            limits.maximum_records_per_transaction,
            limits.maximum_transaction_bytes,
            limits.maximum_transactions,
            limits.maximum_materialized_bytes,
            limits.maximum_materialized_records,
        ].into_iter().any(|limit| limit == 0 || limit > maximum)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn retained_transaction_bytes(transaction: &JournalTransaction) -> Result<usize, JournalError> {
    let mut bytes = size_of::<RuntimeDeploymentNativeTransactionDataV1>();
    for record in transaction.records() {
        bytes = bytes.checked_add(size_of::<JournalRecord>())
            .and_then(|bytes| bytes.checked_add(record.key().len()))
            .and_then(|bytes| bytes.checked_add(record.value().map_or(0, <[u8]>::len)))
            .ok_or(JournalError::LimitExceeded("deployment retained native bytes"))?;
    }
    Ok(bytes)
}

fn copy_transaction(transaction: &JournalTransaction) -> Result<JournalTransaction, JournalError> {
    let mut records = Vec::new();
    records.try_reserve_exact(transaction.records().len())
        .map_err(|_| retention_allocation_error())?;
    for record in transaction.records() {
        let key = copy_bytes(record.key())?;
        let record = match record.value() {
            Some(value) => JournalRecord::put(record.namespace(), key, copy_bytes(value)?),
            None => JournalRecord::delete(record.namespace(), key),
        };
        records.push(record);
    }
    JournalTransaction::new(*transaction.id(), records)
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, JournalError> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len())
        .map_err(|_| retention_allocation_error())?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

fn retention_allocation_error() -> JournalError {
    JournalError::LimitExceeded("deployment native retention allocation")
}

#[cfg(test)]
pub(crate) fn observed_native_fixture_v1(
    transactions: &[JournalTransaction],
    limits: JournalLimits,
) -> Result<RetainedDeploymentNativeHistoryV1, JournalError> {
    use std::io::{Seek as _, Write as _};

    // Inert same-codec test data, not a protected owner or production guard.
    let mut file = tempfile::tempfile()?;
    let mut sequence = 1_u64;
    for transaction in transactions {
        for frame in super::encode_transaction(transaction, sequence)? {
            file.write_all(&frame)?;
        }
        let frames = u64::try_from(transaction.records().len())
            .ok().and_then(|records| records.checked_add(2))
            .ok_or(JournalError::SequenceExhausted)?;
        sequence = sequence.checked_add(frames).ok_or(JournalError::SequenceExhausted)?;
    }
    let physical = FileIdentity::of(&file)?;
    let writer_position = file.stream_position()?;
    require_sidecar_capture_limits(limits)?;
    let mut audit = SidecarHistoryAuditV1::new(physical.size)?;
    let mut reader = ReadAtCursorV1::new(&file, physical.size);
    let replayed = replay_sidecar_observed(&mut reader, limits, &mut audit)?;
    drop(reader);
    if file.stream_position()? != writer_position {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    audit.finish(&replayed)
}

#[cfg(test)]
pub(crate) fn require_sidecar_capture_limits_for_test(
    limits: JournalLimits,
) -> Result<(), JournalError> {
    require_sidecar_capture_limits(limits)
}
