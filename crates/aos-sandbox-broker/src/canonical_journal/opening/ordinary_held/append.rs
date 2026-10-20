//! Dispatches ordinary borrowed or captured DATA to the existing append stages.
//!
//! Each held-owner method borrows its private native/index fields only for one
//! mechanical step. The trusted role keeps the SAME owner, actual payment,
//! currentness, semantics and final crossings at every original frontier. The
//! lower head comparison is ordering DATA, not a new native identity or permit.
//! Captured observations and whole-primary intervals remain with their owners.

use std::error::Error;

use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

use super::CanonicalOrdinaryHeldJournalV1;
use crate::canonical_journal::append_stages::{
    CanonicalAppendClosedV1, CanonicalAppendErrorV1, CanonicalAppendPublishedDataV1,
    CanonicalAppendStagesV1,
};
use crate::canonical_journal::coordinator::retained_data::{
    RetainedAppendDataCustodyV1, RetainedAppendDataFailureV1, RetainedAppendDataStageV1,
};
use crate::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1, CanonicalCoordinatorReadV1,
    CanonicalWriterReadViewV1, sealed,
};

enum Disposition<'transaction> {
    Borrowed(Option<CanonicalAppendStagesV1<&'transaction JournalTransaction>>),
    Captured(Option<RetainedAppendDataStageV1>),
}

/// Retains the actual borrowed or captured mechanical append through upper gaps.
///
/// Only a held owner's preparation entries construct this carrier. It exposes
/// the existing readonly staged-DATA trait, without a native or mutable map
/// projection. Short held-method borrows leave the role's semantic and final
/// crossing checks at their actual positions. The role must keep selecting the
/// same held owner; this type adds no stronger affinity than the lower healthy
/// stage/current-head comparison.
///
/// Captured Drop parks the whole unfinished stage in its SAME prepaid sink.
/// Borrowed Drop keeps ordinary immediate disposal. Neither is positive role
/// completion, and neither creates funding or a selected writer brand.
#[must_use]
pub struct CanonicalOrdinaryAppendStageV1<'transaction> {
    disposition: Disposition<'transaction>,
}

// Both finite ownership cases call the sole existing mechanical body. No
// callback can replace a native step or cross an upper semantic frontier.
macro_rules! stage_call {
    ($stage:expr, $method:ident($($argument:expr),* $(,)?)) => {
        match &mut $stage.disposition {
            Disposition::Borrowed(Some(body)) => body.$method($($argument),*),
            Disposition::Captured(Some(original)) => match original.data_mut() {
                Some(body) => body.$method($($argument),*),
                None => Err(CanonicalAppendClosedV1),
            },
            _ => Err(CanonicalAppendClosedV1),
        }
    };
}

impl CanonicalOrdinaryAppendStageV1<'_> {
    /// Bounds fixed construction, return, residence and diagnostic carriers.
    ///
    /// Counts the actual local/returned stage headers, optional owner slot and
    /// typed return carriers with checked arithmetic. The same native encoder,
    /// retained sink, cloned transaction, frames, index and model backing have
    /// their separate suppliers. A matched caller replaces its old stage/control
    /// terms with this term before construction; it must not add both recipes.
    /// This passive byte supplier establishes no payment or namespace entries.
    /// Returns `None` on representation overflow.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<Self, CanonicalAppendClosedV1>>())?
            .checked_add(std::mem::size_of::<Option<Self>>())?
            .checked_add(std::mem::size_of::<
                Result<Option<CanonicalAppendErrorV1>, CanonicalAppendClosedV1>,
            >())?
            .checked_add(std::mem::size_of::<
                Result<RetainedAppendDataFailureV1, CanonicalAppendClosedV1>,
            >())
    }

    /// Moves only an ordinary temporary's actual typed error after its old drop.
    ///
    /// The lower extractor destroys encoder/frame/projection temporaries at the
    /// ordinary frontier. The role keeps its own semantic cause chronology.
    ///
    /// # Errors
    /// Refuses a captured or already extracted stage without consuming it. A
    /// captured original must use its separate whole-owner failure entry.
    pub fn take_ordinary_error_v1(
        &mut self,
    ) -> Result<Option<CanonicalAppendErrorV1>, CanonicalAppendClosedV1> {
        match &mut self.disposition {
            Disposition::Borrowed(stage) => stage
                .take()
                .map(CanonicalAppendStagesV1::into_ordinary_error)
                .ok_or(CanonicalAppendClosedV1),
            Disposition::Captured(_) => Err(CanonicalAppendClosedV1),
        }
    }

    /// Parks the SAME captured stage before exposing its owning diagnostic.
    ///
    /// Dropping the returned diagnostic cannot erase the permanent sink or its
    /// first reached failure. This entry cannot perform positive disposal.
    ///
    /// # Errors
    /// Refuses an ordinary or already extracted stage without consuming it.
    pub fn take_captured_failure_v1(
        &mut self,
    ) -> Result<RetainedAppendDataFailureV1, CanonicalAppendClosedV1> {
        match &mut self.disposition {
            Disposition::Captured(stage) => stage
                .take()
                .map(RetainedAppendDataStageV1::into_failure_original)
                .ok_or(CanonicalAppendClosedV1),
            Disposition::Borrowed(_) => Err(CanonicalAppendClosedV1),
        }
    }
}

impl sealed::AppendData for CanonicalOrdinaryAppendStageV1<'_> {}

impl CanonicalCoordinatorAppendDataV1 for CanonicalOrdinaryAppendStageV1<'_> {
    fn transaction(&self) -> Option<&JournalTransaction> {
        match &self.disposition {
            Disposition::Borrowed(stage) => Some(stage.as_ref()?.transaction()),
            Disposition::Captured(stage) => Some(stage.as_ref()?.data()?.transaction()),
        }
    }

    fn encoded_frames(&self) -> Option<&[Vec<u8>]> {
        match &self.disposition {
            Disposition::Borrowed(stage) => stage.as_ref()?.encoded_frames(),
            Disposition::Captured(stage) => stage.as_ref()?.data()?.encoded_frames(),
        }
    }

    fn projected_materialized_bytes(&self) -> Option<usize> {
        match &self.disposition {
            Disposition::Borrowed(stage) => stage.as_ref()?.projected_materialized_bytes(),
            Disposition::Captured(stage) => stage.as_ref()?.data()?.projected_materialized_bytes(),
        }
    }

    fn last_applied_record(&self) -> Option<&JournalRecord> {
        match &self.disposition {
            Disposition::Borrowed(stage) => stage.as_ref()?.last_applied_record(),
            Disposition::Captured(stage) => stage.as_ref()?.data()?.last_applied_record(),
        }
    }

    fn published_coordinates(&self) -> Option<CanonicalAppendPublishedDataV1> {
        match &self.disposition {
            Disposition::Borrowed(stage) => stage.as_ref()?.published_coordinates(),
            Disposition::Captured(stage) => stage.as_ref()?.data()?.published_coordinates(),
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match &self.disposition {
            Disposition::Borrowed(stage) => stage.as_ref()?.failure(),
            Disposition::Captured(stage) => stage.as_ref()?.data()?.failure(),
        }
    }
}

impl<P, I> CanonicalOrdinaryHeldJournalV1<P, I> {
    /// Copies, projects and encodes input in the actual already-paid sticky sink.
    ///
    /// The sink is mechanical DATA, not a payer or a native identity. The closed
    /// role selects its SAME owner/sink and keeps captured-before and any C17
    /// encoded-window debit before this copy. Reached body failures are returned
    /// in the complete stage, never consumed as an ordinary temporary.
    ///
    /// # Errors
    /// Refuses a closed or active sink before a stage exists. Its actual failed
    /// original remains retained. No new debit, observation or reset is used.
    pub fn prepare_captured_append_v1<'transaction>(
        &mut self,
        custody: &RetainedAppendDataCustodyV1,
        transaction: &'transaction JournalTransaction,
    ) -> Result<CanonicalOrdinaryAppendStageV1<'transaction>, CanonicalAppendClosedV1> {
        let mut stage = CanonicalOrdinaryAppendStageV1 {
            disposition: Disposition::Captured(Some(custody.prepare_owned_once(transaction)?)),
        };
        if stage_call!(stage, project_once(self.native.native())).is_ok() {
            let _ = stage_call!(stage, encode_once(self.native.native()));
        }
        Ok(stage)
    }
}

impl<P, I> sealed::ReadOwner for CanonicalOrdinaryHeldJournalV1<P, I> {}

impl<P, I> CanonicalCoordinatorReadV1<P> for CanonicalOrdinaryHeldJournalV1<P, I> {
    fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, P> {
        self.read_view_v1()
    }
}

impl<P, I> sealed::AppendOwner for CanonicalOrdinaryHeldJournalV1<P, I> {}

// This is the existing sealed short-step interface, not a selected role port.
// The upper coordinator keeps its SAME-owner choice, genuine admission and
// native currentness at every step. Its complete semantic/final-crossing gaps
// remain between these borrows; actual owned captures keep their original sink.
impl<P, I> CanonicalCoordinatorAppendV1<P> for CanonicalOrdinaryHeldJournalV1<P, I> {
    type Error = CanonicalAppendClosedV1;
    type Prepared<'transaction> = CanonicalOrdinaryAppendStageV1<'transaction>;

    fn poison(&mut self) {
        self.native.native_mut().poison();
    }

    fn prepare_append_once<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<Self::Prepared<'transaction>, Self::Error> {
        let mut stage = CanonicalOrdinaryAppendStageV1 {
            disposition: Disposition::Borrowed(Some(CanonicalAppendStagesV1::new(transaction))),
        };
        if stage_call!(stage, project_once(self.native.native())).is_ok() {
            let _ = stage_call!(stage, encode_once(self.native.native()));
        }
        // A reached lower failure remains in the complete actual stage, just
        // like the existing ordinary implementation of this same interface.
        Ok(stage)
    }

    fn append_coordinates_once(
        &self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<(u64, u64), Self::Error> {
        stage_call!(stage, coordinates_once())
    }

    fn expected_append_length_once(
        &self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<u64, Self::Error> {
        stage_call!(stage, expected_length_once(self.native.native()))
    }

    fn append_prepared_once(&mut self, stage: &mut Self::Prepared<'_>) -> Result<u64, Self::Error> {
        if self.is_read_only_v1() {
            return stage_call!(stage, refuse());
        }
        stage_call!(stage, append_once(self.native.native_mut()))
    }

    fn apply_next_record_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<bool, Self::Error> {
        stage_call!(
            stage,
            apply_next_record_once(self.native.native_mut(), &mut self.index)
        )
    }

    fn publish_append_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<CanonicalAppendPublishedDataV1, Self::Error> {
        stage_call!(stage, publish_once(self.native.native_mut()))
    }

    fn finish_append_after_posts_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<(), Self::Error> {
        match &mut stage.disposition {
            Disposition::Borrowed(Some(body))
                if body.is_published() && body.failure().is_none() =>
            {
                Ok(())
            }
            Disposition::Captured(Some(original)) => original.dispose_published_once(),
            _ => Err(CanonicalAppendClosedV1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_journal::JournalLimits;
    use crate::canonical_journal::opening::ordinary_held::{
        CanonicalOrdinaryOpeningOriginalsV1, tests as opening_tests,
    };
    use aos_sandbox_core::RecordNamespace;
    use aos_sandbox_journal::recovery::RecoveryTailMode;
    use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyRecordDataErrorV1;

    fn held() -> (tempfile::TempDir, CanonicalOrdinaryHeldJournalV1<()>) {
        let directory = opening_tests::protected_directory();
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        opening_tests::finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (held, _) = opening.take_held_without_instance_once_v1(()).unwrap();
        (directory, held)
    }

    fn malformed_decision() -> JournalTransaction {
        // Deliberately hostile lower DATA reaches the real post-write index
        // guard. A role's earlier canonical admission would reject this input.
        JournalTransaction::from_unvalidated_data(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::Idempotency,
                vec![1, 2],
                vec![3],
            )],
        )
    }

    fn fail_actual_index(
        held: &mut CanonicalOrdinaryHeldJournalV1<()>,
        stage: &mut CanonicalOrdinaryAppendStageV1<'_>,
    ) {
        held.append_coordinates_once(stage).unwrap();
        held.expected_append_length_once(stage).unwrap();
        assert!(held.append_prepared_once(stage).unwrap() > 0);
        assert!(held.apply_next_record_once(stage).is_err());
        assert!(matches!(
            stage
                .failure()
                .unwrap()
                .downcast_ref::<IdempotencyRecordDataErrorV1>(),
            Some(IdempotencyRecordDataErrorV1::MalformedRecord(_))
        ));
        assert!(stage.published_coordinates().is_none());
        assert!(held.publish_append_once(stage).is_err());
        assert!(held.finish_append_after_posts_once(stage).is_err());
        assert!(held.read_view_v1().idempotency_index().is_empty());
        assert!(
            held.read_view_v1()
                .state()
                .contains_key(&(RecordNamespace::Idempotency, vec![1, 2],))
        );
    }

    #[test]
    fn premature_borrowed_publication_keeps_frames_and_refuses_wrong_extraction() {
        let (directory, mut held) = held();
        let transaction = malformed_decision();
        let mut stage = held.prepare_append_once(&transaction).unwrap();
        let frames = stage.encoded_frames().unwrap().as_ptr();
        assert!(std::ptr::eq(stage.transaction().unwrap(), &transaction));

        assert!(stage.take_captured_failure_v1().is_err());
        assert_eq!(stage.encoded_frames().unwrap().as_ptr(), frames);
        assert!(held.publish_append_once(&mut stage).is_err());
        let first = stage.failure().unwrap() as *const dyn Error as *const ();
        assert!(held.append_coordinates_once(&mut stage).is_err());
        assert_eq!(
            stage.failure().unwrap() as *const dyn Error as *const (),
            first
        );
        assert_eq!(
            std::fs::metadata(directory.path().join("history"))
                .unwrap()
                .len(),
            0
        );

        assert!(matches!(
            stage.take_ordinary_error_v1().unwrap(),
            Some(CanonicalAppendErrorV1::Closed(_))
        ));
        assert!(stage.take_ordinary_error_v1().is_err());
        assert!(held.append_prepared_once(&mut stage).is_err());
    }

    #[test]
    fn borrowed_partial_index_failure_preserves_its_typed_cause_and_unpublished_native() {
        let (_directory, mut held) = held();
        let transaction = malformed_decision();
        let mut stage = held.prepare_append_once(&transaction).unwrap();
        fail_actual_index(&mut held, &mut stage);

        assert!(stage.take_captured_failure_v1().is_err());
        assert!(matches!(
            stage.take_ordinary_error_v1().unwrap(),
            Some(CanonicalAppendErrorV1::Idempotency(
                IdempotencyRecordDataErrorV1::MalformedRecord(_)
            ))
        ));
        held.poison();
        assert!(held.read_view_v1().is_poisoned());
        assert!(held.instance_data_v1().is_none());
    }

    #[test]
    fn captured_failure_parks_before_diagnostic_drop_and_cannot_reenter() {
        let (_directory, mut held) = held();
        let custody = RetainedAppendDataCustodyV1::new();
        let transaction = malformed_decision();
        let mut stage = held
            .prepare_captured_append_v1(&custody, &transaction)
            .unwrap();
        assert!(!std::ptr::eq(stage.transaction().unwrap(), &transaction));
        assert!(
            held.prepare_captured_append_v1(&custody, &transaction)
                .is_err()
        );
        let transaction_records = stage.transaction().unwrap().records().as_ptr();
        let frames = stage.encoded_frames().unwrap().as_ptr();
        let frame_backings: Vec<_> = stage
            .encoded_frames()
            .unwrap()
            .iter()
            .map(|frame| (frame.as_ptr(), frame.len()))
            .collect();
        fail_actual_index(&mut held, &mut stage);
        let cause_text = stage.failure().unwrap().to_string();

        // Ordinary extraction cannot consume captured failed backing.
        assert!(stage.take_ordinary_error_v1().is_err());
        assert_eq!(stage.failure().unwrap().to_string(), cause_text);
        let diagnostic = stage.take_captured_failure_v1().unwrap();
        let parked_cause = diagnostic.source().unwrap() as *const dyn Error as *const ();
        assert_eq!(diagnostic.source().unwrap().to_string(), cause_text);
        assert!(custody.is_closed());
        drop(diagnostic);
        drop(stage);

        let parked = custody.parked_data_for_test().unwrap();
        assert!(matches!(
            parked
                .failure()
                .unwrap()
                .downcast_ref::<IdempotencyRecordDataErrorV1>(),
            Some(IdempotencyRecordDataErrorV1::MalformedRecord(_))
        ));
        assert_eq!(parked.transaction().records().as_ptr(), transaction_records);
        let retained_frames = parked.retained_encoded_frames().unwrap();
        assert_eq!(retained_frames.as_ptr(), frames);
        assert_eq!(
            retained_frames
                .iter()
                .map(|frame| (frame.as_ptr(), frame.len()))
                .collect::<Vec<_>>(),
            frame_backings
        );
        assert_eq!(custody.failure().unwrap().to_string(), cause_text);
        assert_eq!(
            custody.failure().unwrap() as *const dyn Error as *const (),
            parked_cause
        );
        assert!(
            held.prepare_captured_append_v1(&custody, &transaction)
                .is_err()
        );
    }

    #[test]
    fn captured_unwind_keeps_the_actual_reached_cause_in_the_original_sink() {
        let (_directory, mut held) = held();
        let custody = RetainedAppendDataCustodyV1::new();
        let transaction = malformed_decision();
        let mut stage = held
            .prepare_captured_append_v1(&custody, &transaction)
            .unwrap();
        let transaction_records = stage.transaction().unwrap().records().as_ptr();
        let frames = stage.encoded_frames().unwrap().as_ptr();
        let frame_backings: Vec<_> = stage
            .encoded_frames()
            .unwrap()
            .iter()
            .map(|frame| (frame.as_ptr(), frame.len()))
            .collect();
        fail_actual_index(&mut held, &mut stage);
        let cause_text = stage.failure().unwrap().to_string();

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _entered = stage;
            panic!("leave the actual failed captured stage through unwind");
        }));
        assert!(unwind.is_err());
        assert!(custody.is_closed());
        let parked = custody.parked_data_for_test().unwrap();
        assert!(matches!(
            parked
                .failure()
                .unwrap()
                .downcast_ref::<IdempotencyRecordDataErrorV1>(),
            Some(IdempotencyRecordDataErrorV1::MalformedRecord(_))
        ));
        assert_eq!(parked.transaction().records().as_ptr(), transaction_records);
        let retained_frames = parked.retained_encoded_frames().unwrap();
        assert_eq!(retained_frames.as_ptr(), frames);
        assert_eq!(
            retained_frames
                .iter()
                .map(|frame| (frame.as_ptr(), frame.len()))
                .collect::<Vec<_>>(),
            frame_backings
        );
        assert_eq!(custody.failure().unwrap().to_string(), cause_text);
        let parked_cause = custody.failure().unwrap() as *const dyn Error as *const ();
        assert!(custody.prepare_owned_once(&transaction).is_err());
        assert_eq!(
            custody.failure().unwrap() as *const dyn Error as *const (),
            parked_cause
        );
        assert!(
            held.prepare_captured_append_v1(&custody, &transaction)
                .is_err()
        );
    }
}
