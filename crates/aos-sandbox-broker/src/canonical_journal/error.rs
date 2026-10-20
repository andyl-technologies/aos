//! Classifies native journal failures without role authority or cause cloning.
//!
//! These are the existing flattened mechanical classes. Role errors remain in
//! their actual issuers. Conversions move the precise native IO source; they do
//! not reobserve metadata, reconstruct an error, admit an operation or restore
//! a failed owner. Selected failed stages remain in their genuine resident sink.

use std::io;

use aos_sandbox_journal::{
    framing::FrameError, record::RecordError, recovery::RecoveryTailError,
    replay::NativeReplayError,
};
use aos_sandbox_protocol::domain_ledger::{
    JournalTransactionDataError,
    readonly::IdempotencyRecordDataErrorV1,
};

use super::{NativeJournalDataErrorV1, append_stages::CanonicalAppendErrorV1};

/// Preserves the canonical mechanical error class and its original owned source.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalJournalMechanicalErrorV1 {
    /// Preserves the sole bank replay and durable baseline-precharge refusal.
    #[error(transparent)]
    ResourceBank(#[from] aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError),
    /// Preserves the sole provisioning companion or publication-link refusal.
    #[error(transparent)]
    ProvisioningResources(#[from] aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceLinkErrorV1),
    /// A filesystem operation failed.
    #[error("journal I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Another process owns the journal lock.
    #[error("journal is already owned by another process")]
    AlreadyLocked,
    /// The journal exceeds its configured replay byte bound.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// A frame uses an unsupported format version.
    #[error("unsupported journal format version {0}")]
    UnsupportedVersion(u16),
    /// A complete frame failed checksum validation.
    #[error("journal frame checksum mismatch at byte offset {0}")]
    ChecksumMismatch(u64),
    /// Frame sequence numbers are not exact and monotonic.
    #[error("journal sequence discontinuity at byte offset {0}")]
    SequenceDiscontinuity(u64),
    /// A frame violates transaction ordering or commit invariants.
    #[error("malformed journal transaction: {0}")]
    MalformedTransaction(&'static str),
    /// A record payload violates the closed binary schema.
    #[error("malformed journal record: {0}")]
    MalformedRecord(&'static str),
    /// A caller supplied an invalid transaction.
    #[error("transaction identity must be nonzero and records must be nonempty")]
    InvalidTransaction,
    /// A caller supplied an empty or oversized idempotency key.
    #[error("idempotency key must contain between 1 and 128 bytes")]
    InvalidIdempotencyKey,
    /// A configured size or count limit was exceeded.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A transaction changes the same logical key more than once.
    #[error("transaction contains duplicate logical record keys")]
    DuplicateRecordKey,
    /// A committed transaction identity was reused.
    #[error("transaction identity was already committed")]
    DuplicateTransaction,
    /// A committed idempotency key was rebound to another decision.
    #[error("idempotency key is already bound to another decision")]
    IdempotencyConflict,
    /// An earlier durability failure requires the journal to be reopened.
    #[error("journal handle is poisoned and must be reopened")]
    Poisoned,
    /// A protected path, owner, file type, or mode violates its boundary.
    #[error("protected journal storage boundary is invalid")]
    ProtectedBoundary,
    /// A dedicated authority journal contains a record in another namespace.
    #[error("protected authority journal contains a foreign namespace")]
    ForeignAuthorityNamespace,
    /// An authority token does not describe this journal's current snapshot.
    #[error("protected authority snapshot is stale or belongs to another journal")]
    StaleAuthoritySnapshot,
    /// A preflight token was presented for a different transaction sequence.
    #[error("protected authority preflight does not match the supplied transactions")]
    AuthorityPreflightMismatch,
    /// The kernel cannot enforce the protected opener's resolution policy.
    #[error("protected journal opening requires supported, permitted openat2 resolution")]
    UnsupportedProtectedOpen,
    /// Sequence space is exhausted and cannot safely wrap.
    #[error("journal sequence space is exhausted")]
    SequenceExhausted,
}

impl From<aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1>
    for CanonicalJournalMechanicalErrorV1
{
    fn from(error: aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1) -> Self {
        match error {
            aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1::Malformed => {
                Self::ProtectedBoundary
            }
        }
    }
}

impl From<aos_sandbox_core::journal_namespace::UnknownRecordNamespace> for CanonicalJournalMechanicalErrorV1 {
    fn from(_: aos_sandbox_core::journal_namespace::UnknownRecordNamespace) -> Self {
        Self::MalformedRecord("unknown record namespace")
    }
}

impl From<aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError>
    for CanonicalJournalMechanicalErrorV1
{
    fn from(
        error: aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError,
    ) -> Self {
        use aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError;

        match error {
            CapacityDataError::MalformedRecord(reason) => Self::MalformedRecord(reason),
            CapacityDataError::LimitExceeded(bound) => Self::LimitExceeded(bound),
            CapacityDataError::JournalTooLarge => Self::JournalTooLarge,
            CapacityDataError::InvalidTransaction => Self::InvalidTransaction,
            CapacityDataError::ForeignAuthorityNamespace => Self::ForeignAuthorityNamespace,
            CapacityDataError::ProtectedBoundary => Self::ProtectedBoundary,
            CapacityDataError::Transaction(error) => Self::from(error),
        }
    }
}

impl From<JournalTransactionDataError> for CanonicalJournalMechanicalErrorV1 {
    fn from(error: JournalTransactionDataError) -> Self {
        match error {
            JournalTransactionDataError::InvalidTransaction => Self::InvalidTransaction,
            JournalTransactionDataError::InvalidIdempotencyKey => Self::InvalidIdempotencyKey,
            JournalTransactionDataError::MalformedTransaction(reason) => {
                Self::MalformedTransaction(reason)
            }
            JournalTransactionDataError::MalformedRecord(reason) => Self::MalformedRecord(reason),
            JournalTransactionDataError::LimitExceeded(bound) => Self::LimitExceeded(bound),
            JournalTransactionDataError::DuplicateRecordKey => Self::DuplicateRecordKey,
            JournalTransactionDataError::JournalTooLarge => Self::JournalTooLarge,
            JournalTransactionDataError::Frame(error) => Self::from(error),
            JournalTransactionDataError::Record(error) => Self::from(error),
        }
    }
}

impl From<FrameError> for CanonicalJournalMechanicalErrorV1 {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::Io(error) => Self::Io(error),
            FrameError::JournalTooLarge => Self::JournalTooLarge,
            FrameError::UnsupportedVersion(version) => Self::UnsupportedVersion(version),
            FrameError::ChecksumMismatch(offset) => Self::ChecksumMismatch(offset),
            FrameError::MalformedTransaction(reason) => Self::MalformedTransaction(reason),
            FrameError::LimitExceeded(bound) => Self::LimitExceeded(bound),
            FrameError::MissingRetainedPayload => Self::ProtectedBoundary,
            FrameError::SequenceExhausted => Self::SequenceExhausted,
        }
    }
}

impl From<RecordError> for CanonicalJournalMechanicalErrorV1 {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::MalformedRecord(reason) => Self::MalformedRecord(reason),
            RecordError::LimitExceeded(bound) => Self::LimitExceeded(bound),
        }
    }
}

impl From<NativeReplayError> for CanonicalJournalMechanicalErrorV1 {
    fn from(error: NativeReplayError) -> Self {
        match error {
            NativeReplayError::SequenceDiscontinuity(offset) => Self::SequenceDiscontinuity(offset),
            NativeReplayError::SequenceExhausted => Self::SequenceExhausted,
            NativeReplayError::JournalTooLarge => Self::JournalTooLarge,
            NativeReplayError::DuplicateTransaction => Self::DuplicateTransaction,
            NativeReplayError::LimitExceeded(bound) => Self::LimitExceeded(bound),
        }
    }
}

impl From<RecoveryTailError> for CanonicalJournalMechanicalErrorV1 {
    fn from(error: RecoveryTailError) -> Self {
        match error {
            RecoveryTailError::Io(error) => Self::Io(error),
            RecoveryTailError::UncommittedTail => Self::MalformedTransaction(
                "read-only journal has an uncommitted tail",
            ),
            RecoveryTailError::RetainedNativeFailure => Self::ProtectedBoundary,
        }
    }
}

impl From<IdempotencyRecordDataErrorV1> for CanonicalJournalMechanicalErrorV1 {
    fn from(error: IdempotencyRecordDataErrorV1) -> Self {
        match error {
            IdempotencyRecordDataErrorV1::Conflict => Self::IdempotencyConflict,
            IdempotencyRecordDataErrorV1::MalformedRecord(reason) => Self::MalformedRecord(reason),
        }
    }
}

impl From<CanonicalAppendErrorV1> for CanonicalJournalMechanicalErrorV1 {
    fn from(error: CanonicalAppendErrorV1) -> Self {
        match error {
            CanonicalAppendErrorV1::Record(error) => Self::from(error),
            CanonicalAppendErrorV1::Frame(error) => Self::from(error),
            CanonicalAppendErrorV1::Idempotency(error) => Self::from(error),
            CanonicalAppendErrorV1::Closed(_) => Self::ProtectedBoundary,
        }
    }
}

impl aos_sandbox_journal::protected_storage::ProtectedFailure
    for CanonicalJournalMechanicalErrorV1
{
    const BOUNDARY: Self = Self::ProtectedBoundary;
    const UNSUPPORTED_OPEN: Self = Self::UnsupportedProtectedOpen;
    const STALE_NAME: Self = Self::StaleAuthoritySnapshot;
}

impl CanonicalJournalMechanicalErrorV1 {
    /// Consumes an ordinary native refusal after disposing its encoded frames.
    ///
    /// This is an explicitly consuming ordinary adapter. Selected callers must
    /// keep their whole original/stage/error owners resident and must not use it
    /// to erase a negative prefix. It issues no disposal or financial receipt.
    #[must_use]
    pub fn from_ordinary_native_v1(error: NativeJournalDataErrorV1) -> Self {
        match error {
            NativeJournalDataErrorV1::Io(error) => Self::Io(error),
            NativeJournalDataErrorV1::Frame(error) => Self::from(error),
            NativeJournalDataErrorV1::Transaction(error) => Self::from(error),
            NativeJournalDataErrorV1::ReplayCoordinate(error) => Self::from(error),
            NativeJournalDataErrorV1::Append(failure) => {
                Self::from_ordinary_native_v1((*failure).into_ordinary_cause_v1())
            }
            NativeJournalDataErrorV1::Poisoned => Self::Poisoned,
            NativeJournalDataErrorV1::ProtectedBoundary => Self::ProtectedBoundary,
            NativeJournalDataErrorV1::StaleAuthoritySnapshot => Self::StaleAuthoritySnapshot,
            NativeJournalDataErrorV1::UnsupportedProtectedOpen => Self::UnsupportedProtectedOpen,
            NativeJournalDataErrorV1::AlreadyLocked => Self::AlreadyLocked,
            NativeJournalDataErrorV1::DuplicateTransaction => Self::DuplicateTransaction,
            NativeJournalDataErrorV1::SequenceExhausted => Self::SequenceExhausted,
            NativeJournalDataErrorV1::JournalTooLarge => Self::JournalTooLarge,
            NativeJournalDataErrorV1::ForeignAuthorityNamespace => Self::ForeignAuthorityNamespace,
            NativeJournalDataErrorV1::LimitExceeded(bound) => Self::LimitExceeded(bound),
            NativeJournalDataErrorV1::MalformedTransaction(reason) => Self::MalformedTransaction(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::{BTreeMap, BTreeSet}, fs::File, path::PathBuf};
    use aos_sandbox_core::RecordNamespace;
    use aos_sandbox_journal::owner::NativeJournalState;
    use crate::canonical_journal::{CanonicalNativeJournalV1, JournalLimits, JournalRecord, JournalTransaction};

    fn empty_native(file: File) -> CanonicalNativeJournalV1 {
        CanonicalNativeJournalV1::from_owned_parts(
            PathBuf::new(), file, tempfile::tempfile().unwrap(), JournalLimits::default(),
            NativeJournalState::from_owned_parts(
                1, 0, BTreeSet::new(), BTreeSet::new(), BTreeMap::new(), 0,
            ),
        )
    }

    fn transaction(id: u8) -> JournalTransaction {
        JournalTransaction::new([id; 16], vec![JournalRecord::put(
            RecordNamespace::Operation, vec![id], vec![id + 1],
        )]).unwrap()
    }

    #[test]
    fn real_readonly_append_projects_io_without_restoring_poisoned_native_owner() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let mut native = empty_native(File::open(path.path()).unwrap());

        let refused = native.append_data(&transaction(1)).unwrap_err();
        assert!(matches!(&refused, NativeJournalDataErrorV1::Append(_)));
        let projected = CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(refused);

        assert!(matches!(projected, CanonicalJournalMechanicalErrorV1::Io(_)));
        assert!(native.native().is_poisoned());
        assert!(native.native().state().is_empty());
        assert_eq!(native.native().next_sequence(), 1);
        assert!(matches!(native.append_data(&transaction(2)),
            Err(NativeJournalDataErrorV1::Poisoned)));
    }

    #[test]
    fn real_duplicate_append_keeps_old_class_and_same_committed_prefix() {
        let mut native = empty_native(tempfile::tempfile().unwrap());
        let transaction = transaction(1);
        native.append_data(&transaction).unwrap();
        let sequence = native.native().next_sequence();
        let first_value = native.native().state().values().next().unwrap().as_ptr();

        let refused = native.append_data(&transaction).unwrap_err();
        let projected = CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(refused);

        assert!(matches!(projected, CanonicalJournalMechanicalErrorV1::DuplicateTransaction));
        assert_eq!(native.native().next_sequence(), sequence);
        assert_eq!(native.native().state().values().next().unwrap().as_ptr(), first_value);
        assert!(!native.native().is_poisoned());
    }

    #[test]
    fn ordinary_append_projection_moves_exact_nested_io_source() {
        let original = io::Error::other(io::Error::from_raw_os_error(9));
        let source = original.get_ref().unwrap() as *const _;
        let refusal = NativeJournalDataErrorV1::Append(Box::new(
            crate::canonical_journal::NativeAppendFailureV1 {
                frames: vec![vec![1, 2, 3]],
                cause: NativeJournalDataErrorV1::Transaction(
                    JournalTransactionDataError::Frame(FrameError::Io(original)),
                ),
            },
        ));

        let projected = CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(refusal);

        let CanonicalJournalMechanicalErrorV1::Io(actual) = projected else {
            panic!("ordinary classification must preserve the original IO class");
        };
        assert!(std::ptr::eq(source, actual.get_ref().unwrap() as *const _));
        assert_eq!(actual.get_ref().unwrap().downcast_ref::<io::Error>().unwrap().raw_os_error(), Some(9));
    }

    #[test]
    fn actual_invalid_transaction_and_index_conflict_keep_distinct_classes() {
        let invalid = JournalTransaction::new([0; 16], Vec::new()).unwrap_err();
        let projected = CanonicalJournalMechanicalErrorV1::from(invalid);
        let conflict = CanonicalJournalMechanicalErrorV1::from(IdempotencyRecordDataErrorV1::Conflict);

        assert!(matches!(projected, CanonicalJournalMechanicalErrorV1::InvalidTransaction));
        assert!(matches!(conflict, CanonicalJournalMechanicalErrorV1::IdempotencyConflict));
        assert!(matches!(CanonicalJournalMechanicalErrorV1::from(FrameError::MissingRetainedPayload),
            CanonicalJournalMechanicalErrorV1::ProtectedBoundary));
    }
}

impl From<super::CanonicalCompactionErrorV1> for CanonicalJournalMechanicalErrorV1 {
    fn from(error: super::CanonicalCompactionErrorV1) -> Self {
        use super::CanonicalCompactionErrorV1 as Error;
        match error {
            Error::Io(error) => Self::Io(error),
            Error::Frame(error) => Self::from(error),
            Error::Transaction(error) => Self::from(error),
            Error::LimitExceeded(message) => Self::LimitExceeded(message),
            Error::SequenceExhausted => Self::SequenceExhausted,
        }
    }
}
