//! Immutable historical original Output archive transaction preparation.
//!
//! ```text
//! namespace ControllerStorageOutputReserveAttempt:
//! execution:16 -> AOSCST01
//! 'a' | execution:16 -> complete AOSCSA01
//! 'p' | chunk-index:1 | execution:16 -> complete AOSCSP01
//! ```
//!
//! This path does not sign, send, retry or admit Storage. The existing absent
//! method46 profile refuses before any Journal operation. A future successful
//! historical append still proves byte custody only, not six live source owners.

use std::path::Path;

use aos_sandbox_protocol::storage_output_reserve::authority_archive::{
    HistoricalStorageOutputArchiveErrorV1, HistoricalStorageOutputAuthorityArchiveV1,
    require_original_carrier_profile_v1,
};
use sha2::{Digest as _, Sha256};

use crate::{
    Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace, SignedBrokerPlan,
};

use super::publication_chunks::HistoricalOutputPublicationChunkV1;
use super::recovery::{
    HistoricalStorageOutputArchiveStateV1, load_historical_complete_storage_output_archive_v1,
};
use super::ControllerStorageOutputReserveAttemptV1;

const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-original-archive-tx.v1\0";
pub(super) const NAMESPACE: RecordNamespace = RecordNamespace::ControllerStorageOutputReserveAttempt;

/// Reports invalid, unavailable or uncertain historical Output byte retention.
#[derive(Debug, thiserror::Error)]
pub enum HistoricalStorageOutputRetentionErrorV1 {
    /// The complete original records or publication do not match.
    #[error("historical Storage output archive is invalid")]
    Invalid,
    /// Any prior original or related key already owns the execution.
    #[error("historical Storage output original already exists")]
    AlreadyIssued,
    /// The sole method46 profile is absent; no Journal mutation was attempted.
    #[error("Storage output archive carrier profile is unavailable")]
    UnsupportedCarrierProfile,
    /// A nested historical format failed validation.
    #[error(transparent)]
    Archive(#[from] HistoricalStorageOutputArchiveErrorV1),
    /// The actual protected writer or transaction preflight failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The exact original batch may be committed and must not be regenerated.
    #[error("historical Storage output archive commit/readback is uncertain")]
    OutcomeUnknown {
        /// Owns every exact original record byte across the uncertain outcome.
        original: Box<HistoricalPreparedStorageOutputArchiveV1>,
        /// Retains the actual failed operation without claiming not committed.
        #[source]
        cause: Box<HistoricalStorageOutputRetentionErrorV1>,
    },
}

/// Owns every original prepared archive byte without granting a writer or retry.
pub struct HistoricalPreparedStorageOutputArchiveV1 {
    transaction: JournalTransaction,
    companion: HistoricalStorageOutputAuthorityArchiveV1,
}

impl core::fmt::Debug for HistoricalPreparedStorageOutputArchiveV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HistoricalPreparedStorageOutputArchiveV1")
            .field("transaction_id", self.transaction.id())
            .field("record_count", &self.transaction.records().len())
            .finish_non_exhaustive()
    }
}

impl HistoricalPreparedStorageOutputArchiveV1 {
    /// Returns the deterministic original archive transaction identity.
    #[must_use]
    pub const fn transaction_id(&self) -> &[u8; 16] {
        self.transaction.id()
    }

    /// Borrows the unchanged complete original companion bytes.
    #[must_use]
    pub fn companion_bytes(&self) -> &[u8] {
        self.companion.canonical_bytes()
    }

    /// Borrows every original archive key/value preimage in transaction order.
    ///
    /// These bytes permit historical comparison, not a new writer or resend.
    pub fn records(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.transaction.records().iter().filter_map(|record| {
            record.value().map(|value| (record.key(), value))
        })
    }
}

/// Retains confirmed complete historical archive bytes, never live admission.
#[derive(Debug)]
pub struct HistoricalRetainedStorageOutputArchiveV1 {
    original: HistoricalPreparedStorageOutputArchiveV1,
}

impl HistoricalRetainedStorageOutputArchiveV1 {
    /// Borrows the sole exact original historical batch.
    #[must_use]
    pub const fn original(&self) -> &HistoricalPreparedStorageOutputArchiveV1 {
        &self.original
    }
}

/// Retains one complete original historical archive in one Controller transaction.
///
/// No production caller is installed. The exact existing method46 profile is
/// checked before any Journal access; it currently yields a typed refusal.
/// The batch may only initialize wholly absent related keys. A legacy original
/// is never upgraded, overwritten or filled with newly obtained signatures.
///
/// # Errors
///
/// Returns `UnsupportedCarrierProfile` before any write while method46 is
/// closed. Otherwise rejects incomplete/mismatched bytes, prior keys, changed
/// fixed-writer custody or actual preflight limits. Any commit or subsequent
/// readback failure returns `OutcomeUnknown` owning the complete original batch.
pub fn retain_historical_complete_storage_output_archive_v1(
    controller: &mut Journal,
    exact_original_body: &[u8],
    signed_plan: &SignedBrokerPlan,
    companion: &HistoricalStorageOutputAuthorityArchiveV1,
    exact_publication_bytes: &[u8],
) -> Result<HistoricalRetainedStorageOutputArchiveV1, HistoricalStorageOutputRetentionErrorV1> {
    require_supported_carrier()?;
    let carrier = companion.canonical_carrier()?;
    let (attempt, original_parts) = ControllerStorageOutputReserveAttemptV1::from_original_checked(
        exact_original_body,
        signed_plan.digest(),
    ).map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    let authorization = carrier.message().authorization.as_option()
        .ok_or(HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    if authorization.broker_plan != signed_plan.canonical_plan()
        || authorization.broker_plan_signature != signed_plan.canonical_signature()
    {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    super::recovery::validate_carrier_message_checked(
        &attempt,
        companion,
        carrier.message(),
        &original_parts,
    )?;
    super::recovery::validate_attempt_companion_checked(&attempt, companion, &original_parts)?;
    crate::publication::validate_historical_output_publication_v1(
        exact_publication_bytes,
        companion.publication_digest(),
        Some((
            &authorization.ownership_lease,
            &authorization.ownership_lease_signature,
        )),
    ).map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;

    // Parsing reuse ends before Journal custody, preflight and effects begin.
    drop(original_parts);
    require_fixed_controller_writer(controller)?;
    let state = load_historical_complete_storage_output_archive_v1(controller, attempt.execution())?;
    if !matches!(state, HistoricalStorageOutputArchiveStateV1::Absent) {
        return Err(HistoricalStorageOutputRetentionErrorV1::AlreadyIssued);
    }
    let original = prepare_batch(&attempt, companion, exact_publication_bytes)?;
    controller.preflight_transactions(std::slice::from_ref(&original.transaction))?;
    require_fixed_controller_writer(controller)?;

    if let Err(error) = controller.commit(&original.transaction) {
        return Err(unknown(
            original,
            HistoricalStorageOutputRetentionErrorV1::Journal(error),
        ));
    }
    // Journal commit exposes its projection only after sync succeeds. Compare
    // every complete retained record, bracketed by the SAME fixed writer names.
    if let Err(error) = readback_original(controller, &original) {
        return Err(unknown(original, error));
    }
    Ok(HistoricalRetainedStorageOutputArchiveV1 { original })
}

fn require_supported_carrier() -> Result<(), HistoricalStorageOutputRetentionErrorV1> {
    match require_original_carrier_profile_v1() {
        Ok(()) => Ok(()),
        Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedCarrierProfile) => {
            Err(HistoricalStorageOutputRetentionErrorV1::UnsupportedCarrierProfile)
        }
        Err(error) => Err(HistoricalStorageOutputRetentionErrorV1::Archive(error)),
    }
}

pub(super) fn require_fixed_controller_writer(controller: &Journal) -> Result<(), JournalError> {
    controller.require_protected_named_location(
        Path::new("/var/lib/aos/sandboxd"),
        "controller.journal",
        controller.protected_owner_uid()?,
        controller.configured_limits(),
    )
}

pub(super) fn companion_key(execution: aos_sandbox_core::ExecutionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'a');
    key.extend_from_slice(execution.as_bytes());
    key
}

fn prepare_batch(
    attempt: &ControllerStorageOutputReserveAttemptV1,
    companion: &HistoricalStorageOutputAuthorityArchiveV1,
    publication: &[u8],
) -> Result<HistoricalPreparedStorageOutputArchiveV1, HistoricalStorageOutputRetentionErrorV1> {
    let chunks = HistoricalOutputPublicationChunkV1::from_publication(
        attempt.execution,
        attempt.create_operation,
        companion.publication_digest(),
        publication,
    )?;
    let mut records = Vec::with_capacity(2 + chunks.len());
    records.push(JournalRecord::put(
        NAMESPACE,
        attempt.execution.as_bytes().to_vec(),
        attempt.encode(),
    ));
    records.push(JournalRecord::put(
        NAMESPACE,
        companion_key(attempt.execution),
        companion.canonical_bytes().to_vec(),
    ));
    for chunk in chunks {
        let (key, bytes) = chunk.into_record_parts();
        records.push(JournalRecord::put(NAMESPACE, key, bytes));
    }
    let transaction_digest: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(attempt.execution.as_bytes())
        .chain_update(attempt.create_operation.as_bytes())
        .chain_update(attempt.original_request_id())
        .chain_update(companion.digest())
        .finalize()
        .into();
    let transaction_id = transaction_digest[..16].try_into()
        .map_err(|_| HistoricalStorageOutputRetentionErrorV1::Invalid)?;
    Ok(HistoricalPreparedStorageOutputArchiveV1 {
        transaction: JournalTransaction::new(transaction_id, records)?,
        companion: companion.clone(),
    })
}

fn readback_original(
    controller: &Journal,
    original: &HistoricalPreparedStorageOutputArchiveV1,
) -> Result<(), HistoricalStorageOutputRetentionErrorV1> {
    require_fixed_controller_writer(controller)?;
    for record in original.transaction.records() {
        if controller.get(NAMESPACE, record.key()) != record.value() {
            return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
        }
    }
    let state = load_historical_complete_storage_output_archive_v1(
        controller, original.companion.original_coordinates().execution(),
    )?;
    let HistoricalStorageOutputArchiveStateV1::CompleteHistoricalArchive(loaded) = state else {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    };
    if loaded.companion().canonical_bytes() != original.companion.canonical_bytes() {
        return Err(HistoricalStorageOutputRetentionErrorV1::Invalid);
    }
    require_fixed_controller_writer(controller)?;
    Ok(())
}

fn unknown(
    original: HistoricalPreparedStorageOutputArchiveV1,
    cause: HistoricalStorageOutputRetentionErrorV1,
) -> HistoricalStorageOutputRetentionErrorV1 {
    HistoricalStorageOutputRetentionErrorV1::OutcomeUnknown {
        original: Box::new(original),
        cause: Box::new(cause),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_refusal_is_the_first_retention_step_and_needs_no_journal() {
        assert!(matches!(require_supported_carrier(),
            Err(HistoricalStorageOutputRetentionErrorV1::UnsupportedCarrierProfile)));
    }
}
