//! Retains fixed Storage startup and Prepare Native results and independent posts.
//!
//! The preparation and fixed-prefix reservoirs stay inside the genuine Storage
//! receiver. Its State facade is nonauthorizing result DATA; each selected
//! domain pays actual work before entry. An ambiguous append retains the actual
//! first Result and cannot be settled or reused.

use aos_sandbox_broker::{BrokerAdmissionError, StoragePrepareNativeClockLoanV1};

use crate::journal::{ProtectedJournalCurrentnessOriginalsV1, StoragePrepareNativeClockCaptureV1};
use crate::{CommitResult, Journal, JournalError, JournalTransaction};

use crate::StorageReceivingClosedV1;

#[derive(Clone, Copy)]
enum Failure {
    Transaction,
    Preflight,
    Clock,
    Native,
    Readback,
    NamesHealth,
    Names,
    Closed,
}

pub(crate) struct StorageNativeCommitOriginalV1 {
    exact_transaction: Option<Result<(), JournalError>>,
    preflight: Option<Result<(), JournalError>>,
    clock: StoragePrepareNativeClockCaptureV1,
    native: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<(), JournalError>>,
    names_health: Option<Result<(), JournalError>>,
    names: Option<Result<(), JournalError>>,
    names_originals: ProtectedJournalCurrentnessOriginalsV1,
    first: Option<Failure>,
    entered: bool,
}

enum ActualCommitV1<'cut> {
    Preparation(Result<StoragePrepareNativeClockLoanV1<'cut>, BrokerAdmissionError>),
    OrdinaryStoragePrefix,
}

impl StorageNativeCommitOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            exact_transaction: None,
            preflight: None,
            clock: StoragePrepareNativeClockCaptureV1::new(),
            native: None,
            readback: None,
            names_health: None,
            names: None,
            names_originals: ProtectedJournalCurrentnessOriginalsV1::new(),
            first: None,
            entered: false,
        }
    }

    pub(crate) fn append_once(
        &mut self,
        journal: &mut Journal,
        transaction: &JournalTransaction,
        clock: Result<StoragePrepareNativeClockLoanV1<'_>, BrokerAdmissionError>,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.append_for(journal, transaction, ActualCommitV1::Preparation(clock), false)
    }

    pub(crate) fn append_ordinary_once(
        &mut self,
        journal: &mut Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), StorageReceivingClosedV1> {
        self.append_for(journal, transaction, ActualCommitV1::OrdinaryStoragePrefix, false)
    }

    fn append_for(
        &mut self,
        journal: &mut Journal,
        transaction: &JournalTransaction,
        actual: ActualCommitV1<'_>,
        retain_native_clock: bool,
    ) -> Result<(), StorageReceivingClosedV1> {
        if self.entered {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        self.entered = true;
        if retain_native_clock {
            self.clock.retain_native_source_v1();
        }
        let actual = match actual {
            ActualCommitV1::Preparation(Ok(clock)) => {
                self.exact_transaction = Some(if clock.transaction() == transaction {
                    Ok(())
                } else {
                    Err(JournalError::ProtectedBoundary)
                });
                if matches!(self.exact_transaction, Some(Err(_))) {
                    self.first = Some(Failure::Transaction);
                    // No commit or clock sample entered. The loan still holds
                    // its actual admission owners through this independent post.
                    self.observe_names_once_v1(journal);
                    return Err(StorageReceivingClosedV1);
                }
                ActualCommitV1::Preparation(Ok(clock))
            }
            ActualCommitV1::Preparation(Err(error)) => {
                self.native = Some(journal.commit_storage_prepare_with_clock_v1(
                    Err(error),
                    &mut self.clock,
                ));
                self.first = Some(Failure::Clock);
                self.observe_names_once_v1(journal);
                return Err(StorageReceivingClosedV1);
            }
            ActualCommitV1::OrdinaryStoragePrefix => ActualCommitV1::OrdinaryStoragePrefix,
        };
        self.preflight = Some(journal.preflight_transactions(std::slice::from_ref(transaction)));
        if matches!(self.preflight, Some(Err(_))) {
            self.first = Some(Failure::Preflight);
        } else {
            self.native = Some(match actual {
                ActualCommitV1::Preparation(clock) =>
                    journal.commit_storage_prepare_with_clock_v1(clock, &mut self.clock),
                ActualCommitV1::OrdinaryStoragePrefix => journal.commit(transaction),
            });
            if matches!(self.native, Some(Err(_))) {
                self.first = Some(if self.clock.failure().is_some() {
                    Failure::Clock
                } else {
                    Failure::Native
                });
            }
            self.readback = Some(if transaction.records().iter().all(|record| {
                journal.get(record.namespace(), record.key()) == record.value()
            }) {
                Ok(())
            } else {
                Err(JournalError::Poisoned)
            });
            if matches!(self.readback, Some(Err(_))) {
                self.first.get_or_insert(Failure::Readback);
            }
        }
        // This independent post runs even after a preflight or actual native
        // error. Its error never replaces the earlier native/clock cause.
        self.observe_names_once_v1(journal);
        if matches!(self.names_health, Some(Err(_))) {
            self.first.get_or_insert(Failure::NamesHealth);
        }
        if matches!(self.names, Some(Err(_))) {
            self.first.get_or_insert(Failure::Names);
        }
        self.require_complete()?;
        // Only this exact complete native/readback/immediate-name interval
        // may dispose its successful temporary name observations. The actual
        // Native Result stays on this original through its enclosing phase.
        self.names_originals.settle_positive_once_v1();
        Ok(())
    }

    fn observe_names_once_v1(&mut self, journal: &Journal) {
        // Preserve ordinary health admission as its own real Result while the
        // independent physical observation still runs on a poisoned writer.
        self.names_health = Some(journal.ensure_healthy());
        self.names = Some(journal.observe_held_names_post_retaining_v1(&mut self.names_originals));
    }

    pub(crate) fn require_complete(&self) -> Result<(), StorageReceivingClosedV1> {
        if self.first.is_some()
            || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.readback, Some(Ok(())))
            || !matches!(self.names_health, Some(Ok(())))
            || !matches!(self.names, Some(Ok(())))
        {
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }

    /// Reports the same completed native/readback/name interval as DATA.
    ///
    /// The native append recipe has returned and disposed its successful
    /// temporary maps/frames before this can become positive. Whole result
    /// slots remain on this actual original; a fresh/vacant or failed owner
    /// cannot justify reusing its predecessor's transient append peak.
    pub(crate) fn is_positive(&self) -> bool {
        self.entered && matches!(self.preflight, Some(Ok(())))
            && self.require_complete().is_ok()
    }

    pub(crate) fn native_result(&self) -> Option<&Result<CommitResult, JournalError>> {
        self.native.as_ref()
    }

    pub(crate) fn requires_reopen(&self) -> bool {
        matches!(self.native, Some(Err(_))) && self.clock.failure().is_none()
            || matches!(self.readback, Some(Err(_)))
            || matches!(self.names_health, Some(Err(_)))
            || matches!(self.names, Some(Err(_)))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            Failure::Transaction => self.exact_transaction.as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e as &dyn std::error::Error),
            Failure::Preflight => self.preflight.as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e as &dyn std::error::Error),
            Failure::Clock => self.clock.failure(),
            Failure::Native => self.native.as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e as &dyn std::error::Error),
            Failure::Readback => self.readback.as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e as &dyn std::error::Error),
            Failure::NamesHealth => self.names_health.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Names => self.names_originals.failure().or_else(|| self.names.as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e as &dyn std::error::Error)),
            Failure::Closed => None,
        };
        cause.or(Some(&StorageReceivingClosedV1))
    }
}

/// Retains one ordinary State append and all immediate independent posts.
///
/// This vacant DATA reservoir supplies no receiving payment or authority. It
/// invokes the same ordinary Journal commit, including every semantic guard.
/// A domain must admit its actual transaction work before entering it.
pub struct StorageStateNativeCommitAttemptV1 {
    original: StorageNativeCommitOriginalV1,
}

/// Reports refusal while the complete first cause remains on the attempt.
#[derive(Debug, thiserror::Error)]
#[error("ordinary Storage State native commit is closed")]
pub struct StorageStateNativeCommitClosedV1;

impl Default for StorageStateNativeCommitAttemptV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageStateNativeCommitAttemptV1 {
    /// Creates vacant nonauthorizing result custody without observing Native.
    #[must_use]
    pub const fn new() -> Self {
        Self { original: StorageNativeCommitOriginalV1::new() }
    }

    /// Appends once through the ordinary engine and retains its complete Result.
    ///
    /// # Errors
    /// Refuses repeated entry or any preflight, Native, exact readback or held
    /// name error. Every original Result remains on this same attempt.
    pub fn commit_once_v1(
        &mut self,
        journal: &mut Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), StorageStateNativeCommitClosedV1> {
        self.original.append_ordinary_once(journal, transaction)
            .map_err(|_| StorageStateNativeCommitClosedV1)
    }

    /// Returns the actual retained clock's additional native byte/FD shape.
    ///
    /// # Errors
    /// Returns overflow if the fixed bounded native reservoirs cannot be sized.
    pub fn preparation_clock_demand_v1()
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        StoragePrepareNativeClockCaptureV1::retaining_native_demand_v1()
    }

    /// Commits the exact admitted preparation with its native clock retained.
    ///
    /// This is result custody, not payment or effect authority. Its caller must
    /// hold the genuine paid stage; the real Broker loan remains mandatory.
    ///
    /// # Errors
    /// Retains actual clock, preflight, append, exact readback and names errors.
    pub fn commit_preparation_once_v1(
        &mut self,
        journal: &mut Journal,
        transaction: &JournalTransaction,
        clock: Result<StoragePrepareNativeClockLoanV1<'_>, BrokerAdmissionError>,
    ) -> Result<(), StorageStateNativeCommitClosedV1> {
        self.original.append_for(journal, transaction, ActualCommitV1::Preparation(clock), true)
            .map_err(|_| StorageStateNativeCommitClosedV1)
    }

    /// Disposes only a completely positive observation before peak reuse.
    ///
    /// # Errors
    /// Refuses a vacant, incomplete, failed or ambiguous attempt without
    /// changing any original Result or cause. Negative custody is never reset.
    pub fn settle_positive_once_v1(&mut self) -> Result<(), StorageStateNativeCommitClosedV1> {
        self.original.require_complete()
            .map_err(|_| StorageStateNativeCommitClosedV1)?;
        self.original = StorageNativeCommitOriginalV1::new();
        Ok(())
    }

    /// Borrows the actual ordinary Native commit Result without projecting it.
    #[must_use]
    pub fn native_result_v1(&self) -> Option<&Result<CommitResult, JournalError>> {
        self.original.native_result()
    }

    /// Borrows the earliest retained Native, readback or independent post cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JournalLimits, JournalRecord, RecordNamespace};
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-storage-state-native-{}-{}",
                std::process::id(),
                aos_sandbox_model::OperationId::new(),
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn open(&self) -> Journal {
            Journal::open_protected_at_uid(
                &self.0,
                "state.journal",
                JournalLimits::default(),
                fs::metadata(&self.0).unwrap().uid(),
            ).unwrap().0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn change(id: u8, namespace: RecordNamespace, value: &[u8]) -> JournalTransaction {
        JournalTransaction::new(
            [id; 16],
            vec![JournalRecord::put(namespace, b"current".to_vec(), value.to_vec())],
        ).unwrap()
    }

    fn replace_name(directory: &Path) {
        fs::rename(directory.join("state.journal"), directory.join("retained.journal")).unwrap();
        fs::write(directory.join("state.journal"), []).unwrap();
        fs::set_permissions(directory.join("state.journal"), fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn retained_preparation_refusal_keeps_exact_clock_cause_and_owed_names() {
        let directory = TestDirectory::new();
        let mut journal = directory.open();
        let transaction = change(44, RecordNamespace::DesiredState, b"never appended");
        let before = fs::read(directory.0.join("state.journal")).unwrap();
        let mut attempt = StorageStateNativeCommitAttemptV1::new();
        replace_name(&directory.0);

        assert!(attempt.commit_preparation_once_v1(
            &mut journal, &transaction, Err(BrokerAdmissionError::RequestMismatch),
        ).is_err());

        assert!(matches!(attempt.native_result_v1(), Some(Err(_))));
        assert!(matches!(attempt.original.names, Some(Err(_))));
        let actual = attempt.original.clock.failure().unwrap()
            .downcast_ref::<BrokerAdmissionError>().unwrap();
        let reported = attempt.failure().unwrap()
            .downcast_ref::<BrokerAdmissionError>().unwrap();
        assert_eq!(*actual, BrokerAdmissionError::RequestMismatch);
        assert!(std::ptr::eq(actual, reported));
        let first = reported as *const BrokerAdmissionError;
        assert!(attempt.settle_positive_once_v1().is_err());
        assert!(attempt.commit_preparation_once_v1(
            &mut journal, &transaction, Err(BrokerAdmissionError::FenceRejected),
        ).is_err());
        assert!(std::ptr::eq(first, attempt.failure().unwrap()
            .downcast_ref::<BrokerAdmissionError>().unwrap() as *const BrokerAdmissionError));
        assert_eq!(fs::read(directory.0.join("retained.journal")).unwrap(), before);
    }

    #[test]
    fn preparation_clock_shape_prices_the_actual_retained_native_reader() {
        use aos_sandbox_model::ResourceDimension as D;
        use crate::policy_compiler::RetainedKernelPairedClockAttemptV1 as Clock;

        let demand = StorageStateNativeCommitAttemptV1::preparation_clock_demand_v1().unwrap();

        assert_eq!(demand.get(D::OpenFiles), Clock::MAXIMUM_RETAINED_FILES_V1 as u64);
        assert!(demand.get(D::MemoryBytes) >= Clock::dominant_requested_bytes_v1().unwrap() as u64);
        assert_eq!(demand.get(D::MetadataEntries), 0);
    }

    #[test]
    fn poisoned_admission_keeps_health_refusal_but_performs_owed_names_observation() {
        let directory = TestDirectory::new();
        let mut journal = directory.open();
        let transaction = change(42, RecordNamespace::DesiredState, b"never appended");
        let before = fs::read(directory.0.join("state.journal")).unwrap();
        // This is an explicit Native fault-state fixture, not a manufactured
        // positive service/funding original or a recovered healthy journal.
        journal.native.poison();
        let mut attempt = StorageStateNativeCommitAttemptV1::new();

        assert!(attempt.commit_once_v1(&mut journal, &transaction).is_err());
        assert!(matches!(attempt.original.preflight, Some(Err(JournalError::Poisoned))));
        assert!(attempt.native_result_v1().is_none());
        assert!(matches!(attempt.original.names_health, Some(Err(JournalError::Poisoned))));
        assert!(attempt.original.requires_reopen());
        assert!(matches!(attempt.original.names, Some(Ok(()))));
        assert!(attempt.original.names_originals.is_complete());
        assert_eq!(attempt.original.names_originals.retained_file_count(), 2);
        assert!(matches!(attempt.failure().unwrap().downcast_ref::<JournalError>(),
            Some(JournalError::Poisoned)));
        assert!(matches!(journal.validate_held_protected_names(), Err(JournalError::Poisoned)));
        assert!(attempt.settle_positive_once_v1().is_err());
        assert!(journal.commit(&transaction).is_err());
        assert_eq!(fs::read(directory.0.join("state.journal")).unwrap(), before);
    }

    #[test]
    fn replaced_name_post_keeps_real_commit_and_actual_native_name_cause() {
        let directory = TestDirectory::new();
        let mut journal = directory.open();
        let mut attempt = StorageStateNativeCommitAttemptV1::new();
        let transaction = change(41, RecordNamespace::DesiredState, b"retained");
        replace_name(&directory.0);

        assert!(attempt.commit_once_v1(&mut journal, &transaction).is_err());
        let committed = attempt.native_result_v1().unwrap().as_ref().unwrap();
        assert_eq!(committed.durable_bytes,
            fs::metadata(directory.0.join("retained.journal")).unwrap().len());
        assert!(matches!(attempt.original.readback, Some(Ok(()))));
        assert!(matches!(attempt.original.names, Some(Err(_))));
        let cause = attempt.original.names_originals.failure().unwrap();
        assert!(std::ptr::eq(
            cause.downcast_ref::<JournalError>().unwrap(),
            attempt.failure().unwrap().downcast_ref::<JournalError>().unwrap(),
        ));
        assert!(!attempt.original.names_originals.is_complete());
        let bytes = fs::read(directory.0.join("retained.journal")).unwrap();

        assert!(attempt.commit_once_v1(&mut journal, &transaction).is_err());
        assert!(attempt.settle_positive_once_v1().is_err());
        assert_eq!(fs::read(directory.0.join("retained.journal")).unwrap(), bytes);
        assert!(attempt.native_result_v1().unwrap().is_ok());
    }

    #[test]
    fn ordinary_commit_keeps_real_position_and_posts_before_positive_reuse() {
        let directory = TestDirectory::new();
        let mut journal = directory.open();
        let mut attempt = StorageStateNativeCommitAttemptV1::new();
        let first = change(1, RecordNamespace::DesiredState, b"first");

        attempt.commit_once_v1(&mut journal, &first).unwrap();

        let committed = attempt.native_result_v1().unwrap().as_ref().unwrap();
        assert_eq!(committed.durable_bytes, fs::metadata(directory.0.join("state.journal")).unwrap().len());
        assert!(committed.commit_sequence > 0);
        assert!(matches!(attempt.original.readback, Some(Ok(()))));
        assert!(matches!(attempt.original.names, Some(Ok(()))));
        assert_eq!(journal.get(RecordNamespace::DesiredState, b"current"), Some(b"first".as_slice()));
        attempt.settle_positive_once_v1().unwrap();
        assert!(attempt.native_result_v1().is_none());

        let second = change(2, RecordNamespace::DesiredState, b"second");
        attempt.commit_once_v1(&mut journal, &second).unwrap();
        let second_position = *attempt.native_result_v1().unwrap().as_ref().unwrap();
        drop(journal);
        let reopened = directory.open();
        assert_eq!(reopened.get(RecordNamespace::DesiredState, b"current"), Some(b"second".as_slice()));
        assert_eq!(second_position.durable_bytes, fs::metadata(directory.0.join("state.journal")).unwrap().len());
    }

    #[test]
    fn denied_ordinary_scope_keeps_first_cause_and_file_bytes_on_retry() {
        let directory = TestDirectory::new();
        let mut journal = directory.open();
        let original_bytes = fs::read(directory.0.join("state.journal")).unwrap();
        // A namespace label alone does not select SourceOriginal authority.
        // CreateStorageHistory really requires its private original loan in
        // both ordinary preview and commit, regardless of the payload bytes.
        let forbidden = change(3, RecordNamespace::CreateStorageHistory, b"not-authority");
        let mut attempt = StorageStateNativeCommitAttemptV1::new();

        assert!(attempt.commit_once_v1(&mut journal, &forbidden).is_err());

        assert!(attempt.native_result_v1().is_none());
        assert!(matches!(
            attempt.original.preflight,
            Some(Err(JournalError::ProtectedBoundary)),
        ));
        assert!(matches!(attempt.original.names, Some(Ok(()))));
        let first = attempt.failure().unwrap()
            .downcast_ref::<JournalError>().unwrap() as *const JournalError;
        assert!(attempt.settle_positive_once_v1().is_err());
        assert!(attempt.commit_once_v1(&mut journal, &change(4, RecordNamespace::DesiredState, b"later")).is_err());
        assert!(std::ptr::eq(
            first,
            attempt.failure().unwrap().downcast_ref::<JournalError>().unwrap() as *const JournalError,
        ));
        assert_eq!(fs::read(directory.0.join("state.journal")).unwrap(), original_bytes);
    }

    #[test]
    fn actual_clock_refusal_precedes_independent_replaced_name_failure() {
        let directory = TestDirectory::new();
        let mut journal = directory.open();
        let transaction = change(5, RecordNamespace::DesiredState, b"unused");
        let mut original = StorageNativeCommitOriginalV1::new();
        replace_name(&directory.0);

        assert!(original.append_once(&mut journal, &transaction,
            Err(BrokerAdmissionError::RequestMismatch)).is_err());

        assert!(matches!(original.native, Some(Err(JournalError::ProtectedBoundary))));
        assert!(matches!(original.names, Some(Err(_))));
        assert!(original.failure().unwrap().downcast_ref::<BrokerAdmissionError>().is_some());
        let first = original.failure().unwrap()
            .downcast_ref::<BrokerAdmissionError>().unwrap() as *const BrokerAdmissionError;
        assert!(original.append_ordinary_once(&mut journal, &transaction).is_err());
        assert!(std::ptr::eq(
            first,
            original.failure().unwrap().downcast_ref::<BrokerAdmissionError>().unwrap() as *const BrokerAdmissionError,
        ));
        assert_eq!(fs::metadata(directory.0.join("retained.journal")).unwrap().len(), 0);
    }
}
