//! Prepaid State startup mutations with retained actual append results.
//!
//! This owner is installed only by the actual staged Runtime under its genuine
//! Storage loan. It forecasts the optional policy floor and every authenticated
//! Prepared retirement before their shared ordinary engines clone or encode.
//! Every native result remains resident through the enclosing independent posts.

use super::*;
use aos_sandbox::journal::{
    JournalAppendReceivingDemandErrorV1, StorageStateNativeCommitAttemptV1,
};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::RecordShape;

#[derive(Debug, thiserror::Error)]
enum DemandError {
    #[error(transparent)]
    Append(#[from] JournalAppendReceivingDemandErrorV1),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    State(#[from] StorageStateError),
}

#[derive(Clone, Copy)]
enum Failure {
    PostDemand,
    PostPayment,
    Demand,
    Payment,
    Allocation,
    Native,
    NamesHealth,
    Names,
    Current,
    Closed,
}

pub(super) struct StorageStartupMutationCaptureV1 {
    post_demand: Option<Result<ResourceVector, aos_sandbox::JournalError>>,
    post_payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
    demand: Option<Result<ResourceVector, DemandError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    native: crate::native_commit_batch::StorageNativeCommitBatchV1,
    names_health: Option<Result<(), aos_sandbox::JournalError>>,
    names: Option<Result<(), aos_sandbox::JournalError>>,
    current: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    first: Option<Failure>,
    active: bool,
    post_owed: bool,
}

impl StorageStartupMutationCaptureV1 {
    fn new() -> Self {
        Self {
            post_demand: None,
            post_payment: None,
            names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            demand: None,
            payment: None,
            native: crate::native_commit_batch::StorageNativeCommitBatchV1::new(),
            names_health: None,
            names: None,
            current: None,
            first: None,
            active: false,
            post_owed: false,
        }
    }

    pub(super) fn requires_capture_v1(&self) -> bool {
        self.active || self.first.is_some()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            Failure::PostDemand => self.post_demand.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::PostPayment => self.post_payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Demand => self.demand.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Payment => self.payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Allocation | Failure::Native => self.native.failure(),
            Failure::NamesHealth => self.names_health.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Names => self.names_originals.failure().or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)),
            Failure::Current => self.current.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Closed => None,
        };
        cause.or(Some(&aos_sandbox::StorageReceivingClosedV1))
    }

    fn primary_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.first, Some(Failure::NamesHealth | Failure::Names | Failure::Current)) {
            None
        } else {
            self.failure()
        }
    }

    fn post_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.first, Some(Failure::NamesHealth | Failure::Names | Failure::Current)) {
            self.failure()
        } else {
            None
        }
    }

    pub(super) fn commit_once_v1(
        &mut self,
        journal: &mut Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), StorageStateError> {
        if !self.active || self.first.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageStateError::Receiving);
        }
        if self.native.commit_once_v1(journal, transaction).is_err() {
            self.first = Some(Failure::Native);
            return Err(StorageStateError::Receiving);
        }
        Ok(())
    }
}

impl StorageTransactionStore {
    pub(crate) fn prepare_startup_mutations_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageStateError> {
        if self.startup_mutations.is_some() {
            return Err(StorageStateError::Receiving);
        }
        self.startup_mutations = Some(StorageStartupMutationCaptureV1::new());
        let capture = self.startup_mutations.as_mut().ok_or(StorageStateError::Receiving)?;
        capture.post_demand = Some(aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(
            "storage-state.journal",
        ));
        let Some(Ok(post_demand)) = capture.post_demand.as_ref() else {
            capture.first = Some(Failure::PostDemand);
            return Err(StorageStateError::Receiving);
        };
        capture.post_payment = Some(receiving.reserve_startup_retirement_posts_once_v1(*post_demand));
        if !matches!(capture.post_payment, Some(Ok(()))) {
            capture.first = Some(Failure::PostPayment);
            return Err(StorageStateError::Receiving);
        }
        capture.post_owed = true;
        let demand = startup_mutation_demand_v1(self);
        let capture = self.startup_mutations.as_mut().ok_or(StorageStateError::Receiving)?;
        capture.demand = Some(demand);
        let Some(Ok(demand)) = capture.demand.as_ref() else {
            capture.first = Some(Failure::Demand);
            return Err(StorageStateError::Receiving);
        };
        capture.payment = Some(receiving.reserve_startup_retirement_once_v1(*demand));
        if !matches!(capture.payment, Some(Ok(()))) {
            capture.first = Some(Failure::Payment);
            return Err(StorageStateError::Receiving);
        }
        // Payment precedes the actual result reservoir allocation. No future
        // result is reconstructed, and even an unused slot is fully reserved.
        let slots = self.records.values()
            .filter(|record| record.phase == DurableStoragePhase::Prepared).count()
            .checked_add(1).ok_or(StorageStateError::Receiving)?;
        if capture.native.prepare_once_v1(slots).is_err() {
            capture.first = Some(Failure::Allocation);
            return Err(StorageStateError::Receiving);
        }
        capture.active = true;
        Ok(())
    }

    pub(crate) fn finish_startup_mutations_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageStateError> {
        let capture = self.startup_mutations.as_mut().ok_or(StorageStateError::Receiving)?;
        if !capture.post_owed {
            capture.first.get_or_insert(Failure::Closed);
            return Err(StorageStateError::Receiving);
        }
        capture.post_owed = false;
        // Owed on demand, payment, allocation and domain errors too. Earlier real append errors keep priority.
        capture.names = Some(receiving.observe_startup_retirement_names_once_v1(
            &self.journal, &mut capture.names_originals, &mut capture.names_health,
        ));
        if matches!(capture.names_health, Some(Err(_))) {
            capture.first.get_or_insert(Failure::NamesHealth);
        }
        if !matches!(capture.names, Some(Ok(()))) {
            capture.first.get_or_insert(Failure::Names);
        }
        capture.current = Some(receiving.finish_startup_retirement_post_once_v1());
        if !matches!(capture.current, Some(Ok(()))) {
            capture.first.get_or_insert(Failure::Current);
        }
        if capture.first.is_some() {
            return Err(StorageStateError::Receiving);
        }
        capture.names_originals.settle_positive_once_v1();
        capture.active = false;
        Ok(())
    }

    pub(crate) fn startup_mutation_primary_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.startup_mutations.as_ref().and_then(StorageStartupMutationCaptureV1::primary_failure_v1)
    }

    pub(crate) fn startup_mutation_post_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.startup_mutations.as_ref().and_then(StorageStartupMutationCaptureV1::post_failure_v1)
    }

    pub(crate) fn startup_mutation_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.startup_mutations.as_ref().and_then(StorageStartupMutationCaptureV1::failure)
    }
}

/// A no-allocation one-or-two-record view of an actual typed publication.
struct StartupRecordShapesV1 {
    first: Option<RecordShape>,
    second: Option<RecordShape>,
}

impl Iterator for StartupRecordShapesV1 {
    type Item = RecordShape;

    fn next(&mut self) -> Option<Self::Item> {
        self.first.take().or_else(|| self.second.take())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = usize::from(self.first.is_some()) + usize::from(self.second.is_some());
        (count, Some(count))
    }
}

impl ExactSizeIterator for StartupRecordShapesV1 {}

fn startup_mutation_demand_v1(store: &StorageTransactionStore) -> Result<ResourceVector, DemandError> {
    use crate::receiving_demand::{add, count, multiply};

    let floor = StartupRecordShapesV1 {
        first: Some(RecordShape {
            key_bytes: RESOLVER_POLICY_FLOOR_KEY.len(),
            value_bytes: Some(RESOLVER_POLICY_FLOOR_BYTES),
        }),
        second: None,
    };
    let prepared = store.records.values()
        .filter(|record| record.phase == DurableStoragePhase::Prepared);
    let prepared_count = prepared.clone().count();
    for record in prepared.clone() {
        // Preserve the actual shared encoder-width cause before projecting
        // iterator geometry into Native's nonauthorizing forecast interface.
        let _ = encoded_record_capacity_v1(record)?;
    }
    let transactions = std::iter::once(Ok(floor)).chain(prepared.map(|record| {
        // Aborted retains the same canonical catalog and has no result. The
        // capacity function is shared with encode_record; no value is encoded.
        let value_bytes = encoded_record_capacity_v1(record)
            .map_err(|_| aos_sandbox::JournalError::ProtectedBoundary)?;
        Ok(StartupRecordShapesV1 {
            first: Some(RecordShape { key_bytes: 16, value_bytes: None }),
            second: Some(RecordShape { key_bytes: 16, value_bytes: Some(value_bytes) }),
        })
    }));
    let native = store.journal.append_sequence_receiving_demand_v1(transactions)?;
    let mut encoded = 0_u64;
    for (_, key, value) in store.journal.all_records() {
        encoded = add(encoded, add(count(key.len())?, count(value.len())?)?)?;
    }
    let slots = add(count(prepared_count)?, 1)?;
    let result_bytes = multiply(slots, count(std::mem::size_of::<StorageStateNativeCommitAttemptV1>())?)?;
    // The recovery engine decodes/authenticates real effect/catalog rows, and
    // retains its retirement list while the primary materialized maps remain.
    // Encoded copies and per-row fixed carriers are bounded separately.
    let models = add(multiply(encoded, 128)?, add(result_bytes,
        multiply(slots, count(std::mem::size_of::<DurableRecord>() +
            std::mem::size_of::<crate::broker::PreparedStorageRetirementV1>())?)?)?)?;
    Ok(native.checked_add(ResourceVector::ZERO
        .with(D::MemoryBytes, models)
        .with(D::MetadataEntries, add(multiply(encoded, 8)?, multiply(slots, 32)?)?))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn result_slots_retain_actual_native_success_and_refuse_an_extra_append() {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "aos-startup-native-slots-{}-{unique}", std::process::id(),
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let path = directory.0.join("state");
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = std::fs::metadata(&directory.0).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            &directory.0, "state", JournalLimits::default(), owner,
        ).unwrap();
        let transaction = |id| JournalTransaction::new([id; 16], vec![JournalRecord::put(
            RecordNamespace::Operation, b"key".to_vec(), vec![id],
        )]).unwrap();
        // This is result-reservoir mechanics DATA, not an installed receiving
        // original. Production installs slots only after the real loan's debit.
        let mut capture = StorageStartupMutationCaptureV1::new();
        capture.native.prepare_once_v1(1).unwrap();
        capture.active = true;

        capture.commit_once_v1(&mut journal, &transaction(1)).unwrap();
        let returned = capture.native.native_result_v1(0).unwrap().as_ref().unwrap();
        let returned_position = *returned;
        let durable = std::fs::read(&path).unwrap();
        assert!(capture.commit_once_v1(&mut journal, &transaction(2)).is_err());

        assert_eq!(capture.native.native_result_v1(0).unwrap().as_ref().unwrap(), &returned_position);
        assert_eq!(std::fs::read(&path).unwrap(), durable);
        assert_eq!(capture.native.attempted_count_v1(), 1);
        assert_eq!(capture.failure().unwrap().to_string(), "Storage startup append result slots are closed");
    }
}

#[cfg(test)]
mod names_health_tests {
    use super::*;

    #[test]
    fn earlier_health_cause_precedes_later_physical_names_projection() {
        let mut capture = StorageStartupMutationCaptureV1::new();
        capture.names_health = Some(Err(aos_sandbox::JournalError::Poisoned));
        capture.names = Some(Err(aos_sandbox::JournalError::ProtectedBoundary));
        capture.first = Some(Failure::NamesHealth);

        let original = capture.names_health.as_ref().unwrap().as_ref().unwrap_err();
        let cause = capture.failure().unwrap()
            .downcast_ref::<aos_sandbox::JournalError>().unwrap();
        assert!(std::ptr::eq(original, cause));
        assert!(capture.primary_failure_v1().is_none());
        assert!(capture.post_failure_v1().is_some());
    }
}
