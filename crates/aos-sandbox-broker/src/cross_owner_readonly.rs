//! Retains native observations around one exclusive cross-owner historical read.
//!
//! This mechanism verifies the same live native writer, protected location,
//! canonical prefix and resident idempotency index. It lends no copied map and
//! performs no semantic admission. Actual Runtime, Source and Cache adapters
//! retain their fixed-purpose originals, payment, independent profile posts
//! and private effect permissions above this native observation.

use std::collections::BTreeMap;

use aos_sandbox_core::{OperationId, RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::owner::NativeJournal;
use aos_sandbox_journal::protected_storage::ProtectedJournalLocation;
use aos_sandbox_protocol::domain_ledger::readonly::{
    HistoricalLedgerReadViewV1, IdempotencyDecisionV1,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

use crate::canonical_journal::{CanonicalReplayExtentDataV1, CanonicalReplayOriginalV1, NativeJournalDataErrorV1};
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

mod observation;

/// Retains both reached native checks and their first refusal without authority.
///
/// Empty construction performs no IO or allocation. The actual role adapter
/// must reserve the fixed and actual-prefix demand before entering, retain this
/// owner through its independent posts, and fence unfinished selected custody.
#[must_use]
pub struct CrossOwnerReadOriginalsV1 {
    before: observation::ReadObservation,
    after: observation::ReadObservation,
    entered: bool,
    reentered: bool,
    finished: bool,
    settlement: Option<Result<(), NativeJournalDataErrorV1>>,
}

impl CrossOwnerReadOriginalsV1 {
    /// Creates empty destinations without opening or admitting any owner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            before: observation::ReadObservation::new(),
            after: observation::ReadObservation::new(),
            entered: false,
            reentered: false,
            finished: false,
            settlement: None,
        }
    }

    /// Prices additional fixed custody before the first names or metadata IO.
    ///
    /// The parent separately pays its actual inline `Self`. This bound adds
    /// two simultaneous rooted/name observations, one actual construction
    /// temporary, the exclusive borrowed carrier, and fixed native outcomes.
    /// It excludes the borrowed original writer, location and resident index.
    ///
    /// # Errors
    /// Refuses an invalid directory/name or checked representation overflow.
    pub fn additional_fixed_receiving_demand_v1(
        directory: &std::path::Path,
        name: &str,
    ) -> Result<ResourceVector, NativeJournalDataErrorV1> {
        let invalid = || NativeJournalDataErrorV1::LimitExceeded("cross-owner read geometry");
        let names = WriterCurrentnessOriginalsV1::<NativeJournalDataErrorV1>
            ::fixed_demand_v1(directory, name)?;
        // The shared helper includes its inline owner once. Both of those
        // fields are already inside the parent's paid actual Self layout.
        let embedded_names = u64::try_from(std::mem::size_of::<
            WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
        >()).map_err(|_| invalid())?;
        let names = names.with(D::MemoryBytes,
            names.get(D::MemoryBytes).checked_sub(embedded_names).ok_or_else(invalid)?);
        let temporary = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<CrossOwnerProtectedReadBorrowV1<'_, '_, ()>>())
            .and_then(|bytes| bytes.checked_add(4 * 256)).ok_or_else(invalid)?;
        // Two sets of seven observation outcome/control fields; four parent
        // controls; four borrow fields; three old replay controls per child.
        // Named-native fields and canonical validator cells have own suppliers.
        let control = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(temporary).map_err(|_| invalid())?)
            .with(D::MetadataEntries, 2 * 7 + 4 + 4 + 2 * 3);
        names.checked_add(names).and_then(|demand| demand.checked_add(control))
            .map_err(|_| invalid())
    }

    /// Prices two possibly coexisting replays of this actual captured extent.
    ///
    /// # Errors
    /// Refuses native/semantic representation or complete-bound overflow. The
    /// actual role charges this beyond its fixed demand before parser growth.
    pub fn additional_captured_receiving_demand_v1(
        actual: CanonicalReplayExtentDataV1,
    ) -> Result<ResourceVector, NativeJournalDataErrorV1> {
        let invalid = || NativeJournalDataErrorV1::LimitExceeded("cross-owner replay geometry");
        let one = actual.dominant_native_receiving_demand_v1()?
            .checked_add(actual.dominant_semantic_receiving_demand_v1()?)
            .map_err(|_| invalid())?;
        one.checked_add(one).map_err(|_| invalid())
    }

    /// Borrows the actual native writer and its existing index exclusively.
    ///
    /// This starts the same native observation even when it will refuse. The
    /// returned owner keeps the exclusive writer borrow through the body and
    /// independent post. It supplies no role or effect authority on its own.
    #[must_use]
    pub fn borrow_once<'writer, 'observation, P>(
        &'observation mut self,
        native: &'writer mut NativeJournal<RecordNamespace, JournalLimits>,
        location: &'writer ProtectedJournalLocation<P>,
        idempotency: &'writer BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    ) -> CrossOwnerProtectedReadBorrowV1<'writer, 'observation, P> {
        if self.entered {
            self.reentered = true;
            native.poison();
        } else {
            self.entered = true;
            self.before.prepare_once(native, location);
        }
        CrossOwnerProtectedReadBorrowV1 { native, location, idempotency, originals: self }
    }

    /// Borrows the earliest actual native, canonical or index refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.failure().or_else(|| self.after.failure())
            .or_else(|| self.settlement.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| {
            if self.reentered {
                Some(&READ_CLOSED as &(dyn std::error::Error + 'static))
            } else {
                None
            }
        })
    }
}

impl Default for CrossOwnerReadOriginalsV1 {
    fn default() -> Self { Self::new() }
}

/// Holds the same exclusive native writer borrow through one complete read.
///
/// No public map, snapshot, path, descriptor or boolean constructs this object.
/// The borrow observes the real native owner and real location through the
/// shared retained engines. A private role proof must separately authenticate
/// its purpose, original association, semantic crosslinks and funding. The
/// historical view is unavailable after completion or any native refusal.
#[must_use]
pub struct CrossOwnerProtectedReadBorrowV1<'writer, 'observation, P> {
    native: &'writer mut NativeJournal<RecordNamespace, JournalLimits>,
    location: &'writer ProtectedJournalLocation<P>,
    idempotency: &'writer BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    originals: &'observation mut CrossOwnerReadOriginalsV1,
}

impl<P> CrossOwnerProtectedReadBorrowV1<'_, '_, P> {
    /// Describes the actual fixed-paid captured prefix before replay growth.
    ///
    /// Both reached replay destinations can coexist on a negative post. The
    /// actual role must admit this complete native/semantic demand through its
    /// genuine original before calling `replay_prepared_once`.
    ///
    /// # Errors
    /// Refuses failed preparation, absent actual metadata or configured overflow.
    pub fn prepared_extent(&self) -> Result<CanonicalReplayExtentDataV1, NativeJournalDataErrorV1> {
        if self.originals.reentered || self.originals.finished
            || self.originals.before.failure().is_some()
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let end = self.originals.before.captured_end()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        CanonicalReplayExtentDataV1::new(self.native.limits(), end)
    }

    /// Replays the same captured prefix after the role's actual admission.
    ///
    /// This method is native DATA mechanics, not a funding or effect port.
    /// Actual role adapters retain the whole same-original admission result.
    ///
    /// # Errors
    /// Retains canonical parser, full-native comparison or actual index refusal.
    pub fn replay_prepared_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.originals.finished || self.originals.reentered
            || self.originals.before.replay_was_attempted()
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        let end = self.originals.before.captured_end()
            .ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
        self.originals.before.replay_once(self.native, self.idempotency, end);
        if self.originals.before.is_complete() {
            Ok(())
        } else {
            Err(NativeJournalDataErrorV1::ProtectedBoundary)
        }
    }

    /// Borrows the same actual protected location during this native interval.
    ///
    /// This is native comparison DATA. It does not replace a role's admitted
    /// original or grant a fixed path, writer, operation or receiving purpose.
    #[must_use]
    pub fn protected_location(&self) -> Option<&ProtectedJournalLocation<P>> {
        if self.historical_view().is_some() { Some(self.location) } else { None }
    }

    /// Lends the same existing native/index DATA while the interval is active.
    ///
    /// This does not create or certify a Runtime/Source/Cache proof. The view's
    /// lifetime prevents completion while any borrowed row remains in use.
    #[must_use]
    pub fn historical_view(&self) -> Option<HistoricalLedgerReadViewV1<'_>> {
        if self.originals.finished || self.originals.reentered
            || self.originals.before.failure().is_some()
            || !self.originals.before.is_complete()
        {
            return None;
        }
        Some(HistoricalLedgerReadViewV1::new(self.native, self.idempotency))
    }

    /// Performs the owed native post independently of an upper body failure.
    ///
    /// The method accepts no body Result, success flag or callback. Positive
    /// completion disposes only these native observation scratch owners. Upper
    /// semantic completion and effect permissions remain with the actual role.
    ///
    /// # Errors
    /// Refuses a failed/changed native prefix, physical name, index or repeated
    /// completion, preserving every reached whole result in the same owner.
    pub fn finish_native_once(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.originals.finished || self.originals.reentered {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.originals.finished = true;
        self.originals.after.prepare_once(self.native, self.location);
        if self.originals.before.replay_was_attempted() {
            if let Some(end) = self.originals.before.captured_end() {
                // A changed physical length refuses before any post replay
                // allocation. Equal-length content changes still meet the same
                // captured bound and are checked by full canonical replay.
                self.originals.after.replay_once(self.native, self.idempotency, end);
            }
        }
        if self.originals.failure().is_some()
            || !self.originals.before.is_complete() || !self.originals.after.is_complete()
        {
            self.originals.settlement = Some(Err(NativeJournalDataErrorV1::ProtectedBoundary));
            self.native.poison();
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
        self.originals.settlement = Some((|| {
            self.originals.before.dispose_positive_once()?;
            self.originals.after.dispose_positive_once()
        })());
        if matches!(self.originals.settlement, Some(Ok(()))) {
            Ok(())
        } else {
            self.native.poison();
            Err(NativeJournalDataErrorV1::ProtectedBoundary)
        }
    }

    /// Borrows the exact retained observation's first cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.originals.failure()
    }
}

impl<P> Drop for CrossOwnerProtectedReadBorrowV1<'_, '_, P> {
    fn drop(&mut self) {
        if !matches!(self.originals.settlement, Some(Ok(()))) {
            // This native denial is not custody disposal. Selected role owners
            // still retain the observation originals and enforce their fence.
            self.native.poison();
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("native cross-owner read is closed")]
struct ReadClosed;

const READ_CLOSED: ReadClosed = ReadClosed;

fn require_native_index(
    native: &NativeJournal<RecordNamespace, JournalLimits>,
    idempotency: &BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
) -> Result<(), NativeJournalDataErrorV1> {
    let mut actual = native.state().range((RecordNamespace::Idempotency, Vec::new())..)
        .take_while(|((namespace, _), _)| *namespace == RecordNamespace::Idempotency);
    for (key, decision) in idempotency {
        let Some(((_, actual_key), value)) = actual.next() else {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        };
        if actual_key != key || value.len() != 48
            || value[..32] != decision.request_digest
            || value[32..] != *decision.operation_id.as_bytes()
            || decision.operation_id == OperationId::from_bytes([0; 16])
        {
            return Err(NativeJournalDataErrorV1::ProtectedBoundary);
        }
    }
    if actual.next().is_some() {
        return Err(NativeJournalDataErrorV1::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs::File;
    use std::os::unix::fs::MetadataExt as _;
    use aos_sandbox_journal::owner::NativeJournalState;

    #[test]
    fn failed_rooted_sample_keeps_both_actual_partial_sets_after_the_owed_post() {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let held_directory = File::open(directory.path()).unwrap();
        let uid = held_directory.metadata().unwrap().uid();
        let location = ProtectedJournalLocation::from_original_parts((
            held_directory, "journal".to_owned(), uid, (),
        ));
        let prefix = NativeJournalState::from_owned_parts(
            1, 0, BTreeSet::new(), BTreeSet::new(), BTreeMap::new(), 0,
        );
        let mut native = NativeJournal::from_owned_parts(
            directory.path().join("absent-parent").join("journal"),
            tempfile::tempfile().unwrap(), tempfile::tempfile().unwrap(),
            JournalLimits::default(), prefix,
        );
        let index = BTreeMap::new();
        let mut originals = CrossOwnerReadOriginalsV1::new();
        let mut borrowed = originals.borrow_once(&mut native, &location, &index);

        assert!(borrowed.prepared_extent().is_err());
        assert!(borrowed.historical_view().is_none());
        assert!(borrowed.originals.before.retained_file_count() > 0);
        let first_cause = borrowed.failure().unwrap() as *const dyn std::error::Error as *const ();
        assert!(borrowed.finish_native_once().is_err());
        assert_eq!(borrowed.failure().unwrap() as *const dyn std::error::Error as *const (), first_cause);
        assert!(borrowed.originals.before.retained_file_count() > 0);
        assert!(borrowed.originals.after.retained_file_count() > 0);
        assert!(!borrowed.originals.before.is_disposed());
        assert!(!borrowed.originals.after.is_disposed());
        drop(borrowed);

        assert!(native.is_poisoned());
        assert!(originals.failure().is_some());
        assert!(matches!(originals.settlement, Some(Err(_))));
    }

    #[test]
    fn index_comparison_requires_the_same_complete_native_rows_without_copying_them() {
        let key = vec![3, 4];
        let digest = [7; 32];
        let operation_id = OperationId::from_bytes([9; 16]);
        let mut value = digest.to_vec();
        value.extend_from_slice(operation_id.as_bytes());
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::Idempotency, key.clone()), value);
        let prefix = NativeJournalState::from_owned_parts(
            4, 1, BTreeSet::from([[1; 16]]),
            BTreeSet::from([RecordNamespace::Idempotency]), state, 50,
        );
        let native = NativeJournal::from_owned_parts(
            std::path::PathBuf::new(), tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(), JournalLimits::default(), prefix,
        );
        let mut index = BTreeMap::from([(key.clone(), IdempotencyDecisionV1 {
            request_digest: digest, operation_id,
        })]);
        let actual_row = native.state().get(&(RecordNamespace::Idempotency, key.clone())).unwrap().as_ptr();

        require_native_index(&native, &index).unwrap();
        index.get_mut(&key).unwrap().operation_id = OperationId::from_bytes([10; 16]);
        assert!(require_native_index(&native, &index).is_err());
        index.clear();
        assert!(require_native_index(&native, &index).is_err());
        assert_eq!(native.state().get(&(RecordNamespace::Idempotency, key)).unwrap().as_ptr(), actual_row);
    }
}
