//! Replays the same held Root file through the sole full Q04 Cold observer.
//!
//! The resident journal retains every failed native capture. The lower observer
//! owns only borrowed recipe/history DATA; this module owns the actual cursor,
//! full-map comparison, financial admission and independent native bookends.

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1 as Mechanical,
    CanonicalOrdinaryRereadDataV1, CanonicalOrdinaryRereadOriginalV1, CanonicalReplayExtentDataV1,
    NativeJournalDataErrorV1,
};
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1;
use aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1;
use aos_sandbox_model::{ObjectDigest, RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1;
use aos_sandbox_ledger_replay::cold::{ColdReplayOriginalV1, ColdReplayRemainderDataV1};
use aos_sandbox_ledger_replay::q04_native_history::{
    Q04NativeHistoryDataErrorV1, Q04NativeRecipeAuditDataV1,
};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalTransaction, encode_record_fields};
use sha2::{Digest as _, Sha256};

use super::RootPolicyJournalV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;

/// Marks a failed readback whose actual cause remains in its resident journal.
#[derive(Debug)]
pub struct Q04ReadbackFailureV1;

impl fmt::Display for Q04ReadbackFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the resident Root Q04 readback failed")
    }
}

impl Error for Q04ReadbackFailureV1 {}

pub(super) struct Q04ReadbackCustodyV1 {
    working: Mutex<Option<Q04ReadbackOriginalV1>>,
    failed: OnceLock<Q04ReadbackOriginalV1>,
    refused: AtomicBool,
}

#[derive(Clone, Copy)]
struct Q04ReadbackDataV1 {
    names: ProtectedJournalNamesV1,
}

struct Q04ReadbackOriginalV1 {
    admission: Option<Result<(), NativeError>>,
    before: WriterWitnessOriginalsV1<Mechanical>,
    after: WriterWitnessOriginalsV1<Mechanical>,
    bank_names: WriterWitnessOriginalsV1<Mechanical>,
    named_result: Option<Result<(), Mechanical>>,
    bank_names_result: Option<Result<(), Mechanical>>,
    named: WriterCurrentnessOriginalsV1<Mechanical>,
    initial: Option<Result<(), Mechanical>>,
    bookend: Option<Result<(), Mechanical>>,
    reread: Option<CanonicalOrdinaryRereadOriginalV1>,
    cold: ColdReplayOriginalV1,
    replay: Option<CanonicalOrdinaryRereadDataV1>,
    remainder: Option<ColdReplayRemainderDataV1>,
    native: Option<NativeJournalDataErrorV1>,
    history: Option<Q04NativeHistoryDataErrorV1>,
    boundary: Option<Mechanical>,
    data: Option<Q04ReadbackDataV1>,
    secondary_panic: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

impl Q04ReadbackCustodyV1 {
    pub(super) fn new() -> Self {
        Self {
            working: Mutex::new(None),
            failed: OnceLock::new(),
            refused: AtomicBool::new(false),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failed.get().and_then(Q04ReadbackOriginalV1::failure)
    }

    fn observe_v1(
        &self,
        journal: &RootPolicyJournalV1,
        recipes: Option<(&[JournalTransaction], Option<u64>)>,
    ) -> Result<Q04ReadbackDataV1, NativeError> {
        if self.refused.load(Ordering::Acquire) || self.failed.get().is_some() {
            return Err(NativeError::Q04Current(Q04ReadbackFailureV1));
        }
        let mut working = match self.working.try_lock() {
            Ok(working) if working.is_none() => working,
            _ => {
                self.refused.store(true, Ordering::Release);
                return Err(NativeError::Q04Current(Q04ReadbackFailureV1));
            }
        };
        // All financial guards end before constructing the destination and
        // before any held-file sampler enters its real native invocation.
        journal.admit_role_observation_v1(Q04ReadbackOriginalV1::fixed_demand_v1(journal)?)?;
        *working = Some(Q04ReadbackOriginalV1::new());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let original = working.as_mut().ok_or(())?;
            original.observe_v1(journal, recipes)
        }));
        let Some(original) = working.take() else {
            self.refused.store(true, Ordering::Release);
            return Err(NativeError::Q04Current(Q04ReadbackFailureV1));
        };
        drop(working);
        match result {
            Ok(Ok(())) => original.data.ok_or_else(NativeError::boundary),
            failed => {
                self.refused.store(true, Ordering::Release);
                if let Err(_retained) = self.failed.set(original) {
                    std::process::abort();
                }
                match failed {
                    Err(payload) => std::panic::resume_unwind(payload),
                    _ => Err(NativeError::Q04Current(Q04ReadbackFailureV1)),
                }
            }
        }
    }
}

impl Q04ReadbackOriginalV1 {
    fn new() -> Self {
        Self {
            admission: None,
            before: WriterWitnessOriginalsV1::new(),
            after: WriterWitnessOriginalsV1::new(),
            bank_names: WriterWitnessOriginalsV1::new(),
            named_result: None,
            bank_names_result: None,
            named: WriterCurrentnessOriginalsV1::new(),
            initial: None,
            bookend: None,
            reread: Some(CanonicalOrdinaryRereadOriginalV1::new()),
            cold: ColdReplayOriginalV1::new(),
            replay: None,
            remainder: None,
            native: None,
            history: None,
            boundary: None,
            data: None,
            secondary_panic: Mutex::new(None),
        }
    }

    fn fixed_demand_v1(journal: &RootPolicyJournalV1) -> Result<ResourceVector, NativeError> {
        let overflow = NativeError::geometry;
        let witness = WriterWitnessOriginalsV1::<Mechanical>::receiving_footprint_v1()
            .ok_or_else(overflow)?;
        let headers = std::mem::size_of::<WriterWitnessOriginalsV1<Mechanical>>()
            .checked_mul(2)
            .ok_or_else(overflow)?;
        let backing = witness
            .memory_bytes
            .checked_sub(headers)
            .ok_or_else(overflow)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(backing.checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let named = WriterCurrentnessOriginalsV1::<Mechanical>::named_demand_v1(
            journal
                .read_view()
                .protected_name()
                .ok_or_else(NativeError::boundary)?,
        )?;
        let header = u64::try_from(std::mem::size_of::<WriterCurrentnessOriginalsV1<Mechanical>>())
            .map_err(|_| overflow())?;
        named
            .checked_sub(ResourceVector::ZERO.with(D::MemoryBytes, header))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(|_| overflow())
    }

    fn observe_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        recipes: Option<(&[JournalTransaction], Option<u64>)>,
    ) -> Result<(), ()> {
        self.admission = Some(journal.require_native_original());
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(());
        }
        if recipes.is_none() {
            self.initial = Some((|| {
                self.named.begin(true)?;
                let returned = journal.read_view().observe_names_into(&mut self.named);
                self.named.finish(returned)
            })());
            if !matches!(self.initial, Some(Ok(()))) {
                return Err(());
            }
        }
        self.initial = Some(
            journal
                .read_view()
                .writer_witness_retaining_v1(&mut self.before),
        );
        if !matches!(self.initial, Some(Ok(()))) {
            return Err(());
        }
        let Some(witness) = self.before.completed_witness() else {
            return self.stale_v1();
        };
        if recipes.is_none() {
            self.data = Some(Q04ReadbackDataV1 {
                names: names_v1(witness),
            });
            return Ok(());
        }
        let (recipes, original_next) = recipes.ok_or(())?;
        // A returned body failure or panic never cancels the original final
        // native name bookend. Park the complete result before entering it.
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.replay_v1(journal, recipes, original_next)
        }));
        let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let witness = self.before.completed_witness().ok_or(())?;
            self.bookend = Some(
                journal
                    .read_view()
                    .require_writer_witness_retaining_v1(witness, &mut self.after),
            );
            if matches!(self.bookend, Some(Ok(()))) {
                Ok(())
            } else {
                Err(())
            }
        }));
        match (body, post) {
            (Err(first), Err(second)) => {
                match self.secondary_panic.get_mut() {
                    Ok(destination) => *destination = Some(second),
                    Err(_) => std::process::abort(),
                }
                std::panic::resume_unwind(first)
            }
            (Err(first), _) => std::panic::resume_unwind(first),
            (_, Err(last)) => std::panic::resume_unwind(last),
            (Ok(Ok(())), Ok(Ok(()))) => Ok(()),
            _ => Err(()),
        }
    }

    fn replay_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
        recipes: &[JournalTransaction],
        original_next: Option<u64>,
    ) -> Result<(), ()> {
        let view = journal.read_view();
        let Some(witness) = self.before.completed_witness() else {
            return self.stale_v1();
        };
        let extent = CanonicalReplayExtentDataV1::new(view.limits(), witness.file().byte_len())
            .map_err(|cause| {
                self.native = Some(cause);
            })?;
        let bank =
            PhysicalHistory::additional_use_receiving_demand_v1(view.state()).map_err(|cause| {
                self.history = Some(Q04NativeHistoryDataErrorV1::Bank(cause));
            })?;
        let dynamic = (|| {
            let canonical = CanonicalOrdinaryRereadOriginalV1::receiving_demand_v1(extent)
                .map_err(|cause| {
                    NativeError::Mechanical(Mechanical::from_ordinary_native_v1(cause))
                })?;
            let semantic = ColdReplayOriginalV1::<CanonicalIndexedReplayErrorV1>::fixed_demand_with_q04_native_recipe_v1()?;
            canonical
                .checked_add(semantic)
                .and_then(|demand| demand.checked_add(bank))
                .map_err(|_| NativeError::geometry())
        })();
        self.admission = Some(dynamic.and_then(|demand| journal.admit_role_observation_v1(demand)));
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(());
        }
        // A stopped Controller terminal selects the old Controller-only gate.
        // This actual owner is fixed Root Authority or Policy, so that gate
        // refuses before constructing any substitute stopped model.
        if view
            .historical_view()
            .records(RecordNamespace::Effect)
            .any(|(_, value)| value.first() == Some(&6) && value.get(2) == Some(&3))
        {
            return self.stale_v1();
        }
        let mut audit = Q04NativeRecipeAuditDataV1::new(
            recipes,
            view.limits().maximum_transactions,
            original_next,
            PhysicalHistory::new(view.state()),
            None,
        )
        .map_err(|cause| {
            self.history = Some(cause);
        })?;
        let Some(reread) = self.reread.as_mut() else {
            return self.stale_v1();
        };
        let entered = reread.begin_coordinator_ordinary_once_v1(
            view.captured_reader(witness.file().byte_len()),
            view.limits(),
        );
        let (identity, mut cursor) = entered.map_err(|cause| {
            self.native = Some(cause);
        })?;
        let returned = self.cold.observe_indexed_with_q04_native_recipe_once_v1(
            &mut cursor,
            identity,
            view.limits(),
            &mut audit,
        );
        drop(cursor);
        if returned.is_err() {
            self.history = audit.into_ordinary_failure_v1();
            return Err(());
        }
        // Positive native scratch is retired in its original ordinary order.
        // A failed prefix never reaches any of these disposal calls.
        self.cold.dispose_ordinary_prospective_v1();
        reread.dispose_ordinary_current_once_v1().map_err(|cause| {
            self.native = Some(cause);
        })?;
        reread.dispose_ordinary_pending_once_v1().map_err(|cause| {
            self.native = Some(cause);
        })?;
        self.remainder = self.cold.take_remainder_once();
        let original = self.reread.take().ok_or(())?;
        self.replay = match original.into_completed_comparison_data_v1() {
            Ok(replay) => Some(replay),
            Err(original) => {
                self.reread = Some(original);
                return Err(());
            }
        };
        // The old bank finish samples actual physical names after replay.
        let names = if audit.requires_names_v1() {
            let returned = (|| {
                self.named.begin(true)?;
                let returned = view.observe_names_into(&mut self.named);
                self.named.finish(returned)
            })();
            self.named_result = Some(returned);
            if !matches!(self.named_result, Some(Ok(()))) {
                return Err(());
            }
            self.bank_names_result = Some(view.writer_witness_retaining_v1(&mut self.bank_names));
            if !matches!(self.bank_names_result, Some(Ok(()))) {
                return Err(());
            }
            Some(names_v1(self.bank_names.completed_witness().ok_or(())?))
        } else {
            None
        };
        let replay = self.replay.as_ref().ok_or(())?;
        let finished = audit.finish_after_replay_v1(
            replay.transaction_ids_data_v1(),
            names,
            witness.file().byte_len(),
            view.next_sequence(),
        );
        self.history = audit.into_ordinary_failure_v1();
        if finished.is_err() {
            return Err(());
        }
        let remainder = self.remainder.as_ref().ok_or(())?;
        let coordinates = replay.coordinates_data_v1();
        if coordinates.durable_end != witness.file().byte_len()
            || coordinates.durable_next_sequence != view.next_sequence()
            || coordinates.committed_transactions != view.committed_transactions()
            || replay.transaction_ids_data_v1() != view.transaction_ids()
            || replay.committed_namespaces_data_v1() != view.committed_namespaces()
            || replay.state_data_v1() != view.state()
            || replay.materialized_bytes_data_v1() != view.materialized_bytes()
            || replay.idempotency_data_v1() != view.idempotency_index()
            || !remainder.challenge_history.is_empty()
            || !journal.history.challenge_history.is_empty()
            || remainder.original_replay.has_dependencies()
            || journal.history.original_replay.has_dependencies()
            || remainder.history_compacted != journal.history.history_compacted
            || remainder.q04_lower_history_present != journal.history.q04_lower_history_present
        {
            return self.stale_v1();
        }
        self.data = Some(Q04ReadbackDataV1 {
            names: names_v1(witness),
        });
        Ok(())
    }

    fn stale_v1<T>(&mut self) -> Result<T, ()> {
        self.boundary
            .get_or_insert(Mechanical::StaleAuthoritySnapshot);
        Err(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.admission
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.before.failure())
            .or_else(|| {
                self.initial
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.named.failure())
            .or_else(|| {
                self.named_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.bank_names.failure())
            .or_else(|| {
                self.bank_names_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.native.as_ref().map(|cause| cause as _))
            .or_else(|| {
                if self.cold.q04_native_recipe_failure_is_selected_v1() {
                    self.history.as_ref().map(|cause| cause as _)
                } else {
                    None
                }
            })
            .or_else(|| {
                self.reread
                    .as_ref()
                    .and_then(CanonicalOrdinaryRereadOriginalV1::failure)
            })
            .or_else(|| self.cold.failure())
            .or_else(|| self.history.as_ref().map(|cause| cause as _))
            .or_else(|| self.boundary.as_ref().map(|cause| cause as _))
            .or_else(|| self.after.failure())
            .or_else(|| {
                self.bookend
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

fn names_v1(
    witness: &aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness,
) -> ProtectedJournalNamesV1 {
    ProtectedJournalNamesV1::from_historical_fields(
        witness.directory().physical_pair(),
        witness.file().physical_pair(),
        witness.lock().physical_pair(),
    )
}

impl RootPolicyJournalV1 {
    pub(in crate::native) fn q04_readback_failure_v1(&self)
        -> Option<&(dyn Error + 'static)>
    {
        self.q04_current.failure()
    }

    pub(in crate::native) fn require_q04_native_recipe_prefix_v1(
        &self,
        recipes: &[JournalTransaction],
        original_next: u64,
    ) -> Result<(), NativeError> {
        if original_next == 0 {
            return Err(NativeError::boundary());
        }
        self.q04_current
            .observe_v1(self, Some((recipes, Some(original_next))))
            .map(|_| ())
    }

    pub(in crate::native) fn q04_physical_names_v1(
        &self,
    ) -> Result<ProtectedJournalNamesV1, NativeError> {
        Ok(self.q04_current.observe_v1(self, None)?.names)
    }

    pub(in crate::native) fn q04_before_rows_v1(
        &self,
    ) -> Result<(u64, ProtectedJournalNamesV1, ObjectDigest), NativeError> {
        self.q04_current.observe_v1(self, Some((&[], None)))?;
        let names = self.q04_current.observe_v1(self, None)?.names;
        let sequence = self.next_sequence();
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.create-q04.root-before-rows.v1\0");
        digest.update(names.to_bytes());
        digest.update(sequence.to_be_bytes());
        for (namespace, key, value) in self.all_records() {
            digest.update(
                encode_record_fields(namespace, key, Some(value)).map_err(Mechanical::from)?,
            );
        }
        self.q04_current.observe_v1(self, Some((&[], None)))?;
        let final_names = self.q04_current.observe_v1(self, None)?.names;
        if self.next_sequence() != sequence || final_names != names {
            return Err(NativeError::Mechanical(Mechanical::StaleAuthoritySnapshot));
        }
        Ok((
            sequence,
            names,
            ObjectDigest::from_bytes(digest.finalize().into()),
        ))
    }
}
