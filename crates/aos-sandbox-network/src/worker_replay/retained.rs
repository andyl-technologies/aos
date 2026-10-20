//! Retained fixed Prepare-worker replay opening and its one owned claim.
//!
//! The parent prepays this complete compiled source before creating the worker.
//! These destinations retain native prefixes and typed results; they provide
//! neither a child-local bank nor Network mutation permission. Lifecycle workers
//! continue to use their separate ordinary directory and replay rules.

use std::error::Error;
use std::mem::size_of;

use crate::journal::{
    JournalAppendReceivingDemandErrorV1,
    NetworkWorkerReplayCapturedJournalOpenV4, ProtectedJournalPreopenReplayExtentV1,
    protected_journal_preopen_replay_extent_for_prefix_v1,
};
use crate::journal::{CommitResult, JournalError, RecoveryReport};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;

use super::*;

const PREPARE_REPLAY_DIRECTORY: &str = "/var/lib/aos-sandbox-network-worker";

/// Retains the fixed root-owned replay opening, semantic rejection and report.
#[must_use = "retain the whole opening through worker diagnostics and native exit"]
pub struct NetworkWorkerReplayOpeningOriginalV4 {
    native: NetworkWorkerReplayCapturedJournalOpenV4,
    entry: Option<Result<(), NetworkWorkerProtocolError>>,
    replay_entered: bool,
    take_entered: bool,
    report: Option<RecoveryReport>,
    transfer: Option<Result<(), NetworkWorkerProtocolError>>,
    ledger: Option<NetworkWorkerReplayLedger>,
    validation: Option<Result<(), NetworkWorkerProtocolError>>,
    reentry: Option<NetworkWorkerProtocolError>,
}

impl NetworkWorkerReplayOpeningOriginalV4 {
    /// Creates an inert destination without allocating paths or entering I/O.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            native: NetworkWorkerReplayCapturedJournalOpenV4::new(),
            entry: None,
            replay_entered: false,
            take_entered: false,
            report: None,
            transfer: None,
            ledger: None,
            validation: None,
            reentry: None,
        }
    }

    /// Returns the compiled maximum number of admitted Prepare claims.
    #[must_use]
    pub const fn maximum_claims_v4() -> usize {
        MAXIMUM_CLAIMS
    }

    /// Returns the exact native limits shared with the ordinary replay engine.
    #[must_use]
    pub const fn journal_limits_v4() -> JournalLimits {
        journal_limits(MAXIMUM_CLAIMS)
    }

    /// Prices fixed opening custody before its first allocation or native call.
    ///
    /// This includes both the opening and transferred ledger carriers. Replay
    /// and claim representations are separately included by the complete-child
    /// supplier; no scalar returned here funds either operation.
    ///
    /// # Errors
    /// Preserves checked representation or accounting overflow.
    pub fn fixed_preparation_demand() -> Result<ResourceVector, JournalError> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<NetworkWorkerReplayLedger>()))
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?;
        NetworkWorkerReplayCapturedJournalOpenV4::fixed_preparation_demand()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(JournalError::ReceivingAccounting)
    }

    /// Prices replay at the unchanged compiled physical-history ceiling.
    ///
    /// # Errors
    /// Preserves the shared native/semantic geometry or accounting refusal.
    pub fn maximum_replay_receiving_demand_v4() -> Result<ResourceVector, JournalError> {
        let limits = Self::journal_limits_v4();
        let extent = protected_journal_preopen_replay_extent_for_prefix_v1(
            limits, limits.maximum_journal_bytes,
        )?;
        replay_demand(&extent)
    }

    /// Prices the fixed claim's maximum native history and retained maps.
    ///
    /// # Errors
    /// Preserves the shared typed append geometry and accounting refusal.
    pub fn maximum_claim_receiving_demand_v4()
        -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1>
    {
        let encoded = u64::try_from(ENCODED_CLAIM_TRANSACTION_BYTES)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let native = NetworkWorkerReplayCapturedJournalOpenV4::maximum_append_receiving_demand_v4(
            Self::journal_limits_v4(), encoded,
        )?;
        // The inline slot already owns its encoded array and Result carriers.
        // The actual one-record TX allocates this Vec element and exact slices.
        // Claim validation/encoding and the transaction ID also keep their
        // concrete fixed models and SHA-256 state on the same entered stack.
        let bytes = size_of::<WorkerClaimV1>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(size_of::<Sha256>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<JournalRecord>()))
            .and_then(|bytes| bytes.checked_add(MATERIALIZED_CLAIM_BYTES))
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?;
        Ok(native.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes).with(D::MetadataEntries, 1))?)
    }

    /// Prices the complete finite child source before the parent issues PID1.
    ///
    /// This is a conservative sum, including malformed full-width histories.
    /// It neither creates a child account nor guarantees configured resource fit.
    ///
    /// # Errors
    /// Preserves fixed, replay, append or checked aggregate refusal.
    pub fn complete_child_receiving_demand_v4()
        -> Result<ResourceVector, JournalAppendReceivingDemandErrorV1>
    {
        Ok(Self::fixed_preparation_demand()?
            .checked_add(Self::maximum_replay_receiving_demand_v4()?)?
            .checked_add(Self::maximum_claim_receiving_demand_v4()?)?)
    }

    /// Captures the installed Prepare directory once using the shared opener.
    ///
    /// A different configured path refuses before path allocation or native I/O.
    /// The lifecycle directory cannot be adopted by this fixed destination.
    pub fn prepare_once_v4(&mut self, directory: &Path) {
        if self.entry.is_some() || self.reentry.is_some() {
            self.reentry.get_or_insert(NetworkWorkerProtocolError::ReplayStore);
            return;
        }
        self.entry = Some(if directory == Path::new(PREPARE_REPLAY_DIRECTORY) {
            Ok(())
        } else {
            Err(NetworkWorkerProtocolError::ReplayStore)
        });
        if matches!(self.entry, Some(Ok(()))) {
            self.native.prepare_once(Self::journal_limits_v4());
        }
    }

    /// Borrows the actual captured prefix, never a reconstructed metadata proof.
    #[must_use]
    pub fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        self.native.captured_extent()
    }

    /// Replays the same captured original after the parent prepaid its source.
    pub fn replay_once(&mut self) {
        if !matches!(self.entry, Some(Ok(()))) || self.replay_entered || self.reentry.is_some() {
            self.reentry.get_or_insert(NetworkWorkerProtocolError::ReplayStore);
            return;
        }
        self.replay_entered = true;
        self.native.replay_once();
    }

    /// Moves the same ledger only after native posts and complete claim validation.
    ///
    /// A malformed claim leaves its entire actual Journal and report in this
    /// destination. Failed or ambiguous openings cannot be retried or adopted.
    #[must_use]
    pub fn take_completed_once_v4(&mut self) -> Option<NetworkWorkerReplayLedger> {
        if self.take_entered || self.reentry.is_some() || !self.replay_entered {
            self.reentry.get_or_insert(NetworkWorkerProtocolError::ReplayStore);
            return None;
        }
        self.take_entered = true;
        let Some((journal, report)) = self.native.take_opened() else {
            self.transfer = Some(Err(NetworkWorkerProtocolError::ReplayStore));
            return None;
        };
        self.transfer = Some(Ok(()));
        self.report = Some(report);
        self.ledger = Some(NetworkWorkerReplayLedger {
            journal,
            maximum_claims: MAXIMUM_CLAIMS,
            retained_native: true,
            claim_original: None,
        });
        self.validation = Some(match self.ledger.as_ref() {
            Some(ledger) => ledger.validate_claims_v4(),
            None => Err(NetworkWorkerProtocolError::ReplayStore),
        });
        if matches!(self.validation, Some(Ok(()))) {
            self.ledger.take()
        } else {
            None
        }
    }

    /// Borrows the actual earliest entry, native or semantic cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.entry)
            .or_else(|| self.native.failure())
            .or_else(|| error(&self.transfer))
            .or_else(|| error(&self.validation))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Default for NetworkWorkerReplayOpeningOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}

/// Owns one claim's actual forecast, encoder, transaction, commit and readback.
///
/// Only the same ledger constructs and enters this inline slot. It cannot be
/// supplied to another ledger or used to join a different native error source.
#[must_use = "retain the same ledger and its whole claim through worker exit"]
pub struct NetworkWorkerReplayClaimOriginalV4 {
    pub(super) entered: bool,
    pub(super) entry: Option<Result<(), NetworkWorkerProtocolError>>,
    pub(super) forecast: Option<Result<ResourceVector, JournalAppendReceivingDemandErrorV1>>,
    pub(super) encoded: Option<Result<[u8; CLAIM_BYTES], NetworkWorkerProtocolError>>,
    pub(super) transaction: Option<Result<JournalTransaction, JournalTransactionDataError>>,
    pub(super) commit: Option<Result<CommitResult, JournalError>>,
    pub(super) readback: Option<Result<(), NetworkWorkerProtocolError>>,
    pub(super) reentry: Option<NetworkWorkerProtocolError>,
}

impl NetworkWorkerReplayClaimOriginalV4 {
    pub(super) const fn new() -> Self {
        Self {
            entered: false,
            entry: None,
            forecast: None,
            encoded: None,
            transaction: None,
            commit: None,
            readback: None,
            reentry: None,
        }
    }

    /// Borrows the original first cause in actual claim order.
    ///
    /// Native commit errors retain their actual body and independent posts in
    /// the same Journal. Their typed diagnostic is preserved unchanged here;
    /// a later cleanup failure never replaces an earlier codec or forecast error.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.entry)
            .or_else(|| error(&self.forecast))
            .or_else(|| error(&self.encoded))
            .or_else(|| error(&self.transaction))
            .or_else(|| error(&self.commit))
            .or_else(|| error(&self.readback))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

fn replay_demand(extent: &ProtectedJournalPreopenReplayExtentV1) -> Result<ResourceVector, JournalError> {
    extent.dominant_native_receiving_demand_v1()?
        .checked_add(extent.dominant_semantic_receiving_demand_v1()?)
        .map_err(JournalError::ReceivingAccounting)
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_path_refuses_before_native_preparation_and_stays_owned() {
        let mut original = NetworkWorkerReplayOpeningOriginalV4::new();
        original.prepare_once_v4(Path::new("/var/lib/aos-sandbox-network-lifecycle-worker"));
        let first = original.failure().unwrap() as *const dyn Error;

        assert!(original.captured_extent().is_none());
        assert!(original.native.failure().is_none());
        original.prepare_once_v4(Path::new(PREPARE_REPLAY_DIRECTORY));
        original.replay_once();
        assert!(original.take_completed_once_v4().is_none());

        assert!(original.captured_extent().is_none());
        assert_eq!(original.failure().unwrap() as *const dyn Error, first);
        assert!(original.native.failure().is_none());
    }

    #[test]
    fn a_pure_encoder_failure_precedes_commit_and_survives_reentry() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = NetworkWorkerReplayLedger::open_for_test(directory.path()).unwrap();
        // Exercise the selected owned slot and real ordinary native forecast;
        // this test flag supplies no fixed-path native provenance or grant.
        ledger.retained_native = true;
        assert!(ledger.claim_retaining_v4([0; 16], ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32])).is_err());
        let first = ledger.failure_v4().unwrap() as *const dyn Error;
        let original = ledger.claim_original_v4().unwrap();

        assert!(matches!(original.forecast, Some(Ok(_))));
        assert!(matches!(original.encoded, Some(Err(_))));
        assert!(original.transaction.is_none());
        assert!(original.commit.is_none());
        assert!(ledger.journal.get(RecordNamespace::Effect, &[0; 16]).is_none());

        assert!(ledger.claim_retaining_v4([1; 16], ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32])).is_err());
        assert_eq!(ledger.failure_v4().unwrap() as *const dyn Error, first);
        assert!(ledger.claim_original_v4().unwrap().commit.is_none());
    }

    #[test]
    fn ordinary_ledger_cannot_adopt_the_fixed_retained_mode() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = NetworkWorkerReplayLedger::open_for_test(directory.path()).unwrap();
        assert!(ledger.claim_retaining_v4([1; 16], ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32])).is_err());
        let original = ledger.claim_original_v4().unwrap();

        assert!(matches!(original.entry, Some(Err(_))));
        assert!(original.forecast.is_none());
        assert!(original.commit.is_none());
        assert_eq!(ledger.journal.records(RecordNamespace::Effect).count(), 0);
    }

    #[test]
    fn selected_claim_keeps_actual_commit_position_and_exact_readback() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = NetworkWorkerReplayLedger::open_for_test(directory.path()).unwrap();
        ledger.retained_native = true;
        ledger.claim_retaining_v4([1; 16], ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32])).unwrap();
        let original = ledger.claim_original_v4().unwrap();
        let position = original.commit.as_ref().unwrap().as_ref().unwrap();
        let encoded = original.encoded.as_ref().unwrap().as_ref().unwrap();

        assert_eq!(position.durable_bytes, ENCODED_CLAIM_TRANSACTION_BYTES as u64);
        assert!(matches!(original.readback, Some(Ok(()))));
        assert_eq!(ledger.journal.get(RecordNamespace::Effect, &[1; 16]), Some(encoded.as_slice()));
        assert!(ledger.failure_v4().is_none());
        drop(ledger);

        let recovered = NetworkWorkerReplayLedger::open_for_test(directory.path()).unwrap();
        assert_eq!(recovered.journal.records(RecordNamespace::Effect).count(), 1);
        assert!(recovered.validate_claims_v4().is_ok());
    }

    #[test]
    fn compiled_maximum_covers_the_actual_forecast_at_growing_prefixes() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = NetworkWorkerReplayLedger::open_for_test(directory.path()).unwrap();
        let maximum = NetworkWorkerReplayOpeningOriginalV4::maximum_claim_receiving_demand_v4().unwrap();
        for id in [1, 2, 3] {
            let actual = ledger.claim_receiving_demand_v4().unwrap();
            for dimension in [D::MemoryBytes, D::MetadataEntries, D::StorageBytes, D::OpenFiles] {
                assert!(maximum.get(dimension) >= actual.get(dimension));
            }
            ledger.claim([id; 16], ObjectDigest::from_bytes([1; 32]),
                ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32])).unwrap();
        }
        assert_eq!(NetworkWorkerReplayOpeningOriginalV4::maximum_claims_v4(), MAXIMUM_CLAIMS);
        assert_eq!(NetworkWorkerReplayOpeningOriginalV4::journal_limits_v4(), journal_limits(MAXIMUM_CLAIMS));
    }
}
