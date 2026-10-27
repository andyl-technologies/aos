//! Owns the actual fixed Controller writer below its semantic coordinator.
//!
//! The constructor is private to the paired startup path. It moves the SAME
//! native journal, idempotency index and protected location, including its
//! opaque compaction owner. Role borrowers receive historical views and bounded
//! read cursors; neither the journal nor either original file can escape.

use std::collections::BTreeMap;
use std::fs::Metadata;
use std::io;
use std::sync::Arc;

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_journal::protected_storage::{
    ProtectedWriterNameWitness, WriterWitnessOriginalsV1,
};
use crate::canonical_journal::coordinator::{CanonicalCoordinatorReadCursorV1, CanonicalWriterReadViewV1};
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;
use aos_sandbox_protocol::domain_ledger::readonly::{
    HistoricalLedgerReadViewV1, IdempotencyDecisionV1,
};
use aos_sandbox_protocol::domain_ledger::runtime_authority_history::ledger_read::
    HistoricalRuntimeLedgerReadV1;

use crate::canonical_journal::{CanonicalOpenedWriterDataV1, CanonicalWriterCustodyDataV1};
use crate::controller_receiving::ControllerReceivingOriginalV1;
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

use super::identity::ControllerWriterIdentityV1;
use super::ControllerBankLaunchErrorV1;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Index = BTreeMap<Vec<u8>, IdempotencyDecisionV1>;

/// Retains the fixed writer and all three of its original physical owners.
///
/// Field order conserves native storage, resident index, then protected-location
/// disposal. `P` remains inside that actual location for its entire lifetime.
/// This type has no public constructor, file projection or generic append port.
pub struct ControllerFixedWriterOriginalV1<P> {
    pub(super) physical: CanonicalWriterCustodyDataV1<P>,
    pub(super) identity: Arc<ControllerWriterIdentityV1>,
    pub(super) fenced: bool,
    pub(super) append_custody: Arc<super::append::ControllerAppendCustodyV1>,
    pub(super) append_debit_failure: Option<ControllerBankLaunchErrorV1>,
    pub(super) borrow_debit_failure: Option<ControllerBankLaunchErrorV1>,
    pub(super) last_receipt: Option<Arc<super::append::ControllerDurableAppendReceiptV1>>,
    original: Arc<ControllerReceivingOriginalV1>,
    fixed_preparation: aos_sandbox_model::ResourceVector,
    durable_end: u64,
    initial_bank_preparation_entered: bool,
    pub(super) replacement_semantic_bytes: Option<usize>,
}

impl<P> ControllerFixedWriterOriginalV1<P> {
    // Only the fixed opening consumes the completed acquisition and its own
    // resident index. No public native tuple can enter this constructor.
    pub(super) fn from_fixed_opening(
        opened: CanonicalOpenedWriterDataV1,
        index: Index,
        compaction: P,
        original: Arc<ControllerReceivingOriginalV1>,
        fixed_preparation: aos_sandbox_model::ResourceVector,
        durable_end: u64,
    ) -> Self {
        let (physical, _report) = CanonicalWriterCustodyDataV1::from_opened_data_v1(opened, index, compaction);
        Self {
            physical,
            identity: Arc::new(ControllerWriterIdentityV1::from_original(Arc::clone(&original))),
            fenced: false,
            append_custody: Arc::new(super::append::ControllerAppendCustodyV1::new()),
            append_debit_failure: None,
            borrow_debit_failure: None,
            last_receipt: None,
            original,
            fixed_preparation,
            durable_end,
            initial_bank_preparation_entered: false,
            replacement_semantic_bytes: None,
        }
    }

    pub(super) fn has_original(&self, original: &Arc<ControllerReceivingOriginalV1>) -> bool {
        self.identity.has_original(original)
    }

    pub(super) fn identity(&self) -> &Arc<ControllerWriterIdentityV1> {
        &self.identity
    }

    pub(super) fn require_healthy(&self) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.fenced || self.physical.native.native().is_poisoned()
            || !self.append_custody.is_idle() || !self.physical.replacement_custody.is_idle()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn fence(&mut self) {
        self.fenced = true;
        self.physical.native.native_mut().poison();
    }

    pub(super) fn bank_state_v1(&self) -> Result<&State, ControllerBankLaunchErrorV1> {
        self.require_healthy()?;
        Ok(self.physical.native.native().state())
    }

    pub(super) fn contains_bank_transaction_v1(
        &self,
        transaction: &[u8; 16],
    ) -> Result<bool, ControllerBankLaunchErrorV1> {
        self.require_healthy()?;
        Ok(self.physical.native.native().transaction_ids().contains(transaction))
    }

    pub(super) fn historical_view(&self) -> HistoricalLedgerReadViewV1<'_> {
        self.physical.historical_view()
    }

    pub(super) fn runtime_history(&self) -> HistoricalRuntimeLedgerReadV1<'_, aos_sandbox_journal::protected_storage::ProtectedJournalLocation<P>> {
        self.physical.runtime_history()
    }

    pub(super) const fn limits(&self) -> JournalLimits {
        self.physical.limits()
    }

    pub(super) const fn next_sequence(&self) -> u64 {
        self.physical.next_sequence()
    }

    pub(super) const fn durable_prefix_end_data_v1(&self) -> u64 {
        self.durable_end
    }

    // Metadata is observed at the caller's original frontier. A sampled length
    // never replaces the physical/native/currentness checks on the loan.
    pub(super) fn metadata(&self) -> io::Result<Metadata> {
        self.physical.metadata()
    }

    pub(super) fn captured_reader(&self, length: u64) -> CanonicalCoordinatorReadCursorV1<'_> {
        CanonicalWriterReadViewV1::from_parts(
            self.physical.native.native(), &self.physical.index, Some(&self.physical.location),
        ).captured_reader(length)
    }

    pub(super) fn compaction_selection(&self) -> &P {
        self.physical.compaction_selection()
    }

    pub(super) fn require_append_representation(
        &self,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_append_interval_representation(transaction, 0)
    }

    pub(super) fn require_append_interval_representation(
        &self,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
        upper_interval_bytes: usize,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes;

        let invalid = || ControllerBankLaunchErrorV1::Conflict;
        let appended = encoded_transaction_append_bytes(transaction)
            .map_err(|cause| ControllerBankLaunchErrorV1::Native(cause.into()))?;
        let end = self.durable_end.checked_add(appended).ok_or_else(invalid)?;
        let extent = crate::canonical_journal::CanonicalReplayExtentDataV1::new(self.limits(), end)?;
        let stage_bytes = crate::canonical_journal::coordinator::selected_append::selected_append_stage_bytes_v1(
            transaction, appended,
            std::mem::size_of::<super::append::ControllerPreparedAppendV1>(),
            std::mem::size_of::<super::append::ControllerAppendFailureOriginalV1>(),
            std::mem::size_of::<super::append::ControllerAppendBodyV1>(),
            std::mem::size_of::<super::append::ControllerDurableAppendReceiptV1>(),
        ).ok_or_else(invalid)?;
        let stage = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(stage_bytes).map_err(|_| invalid())?);
        let upper_interval = ResourceVector::ZERO.with(
            D::MemoryBytes, u64::try_from(upper_interval_bytes).map_err(|_| invalid())?,
        );
        let native_post = super::native_post::ControllerNativePostOriginalV1::receiving_demand_v1()?;
        // Rust stage/guard/error headers are bytes, not namespace entries.
        // Actual resident map/index entries use the captured-prefix suppliers.
        let complete = self.fixed_preparation
            .checked_add(extent.dominant_native_receiving_demand_v1()?)?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(super::replay::ControllerReplayIndexOriginalV1::dynamic_demand_v1(extent)?)?
            .checked_add(stage)?
            .checked_add(native_post)?
            .checked_add(upper_interval)?;
        self.original.require_fixed_writer_complete(complete)?;
        Ok(())
    }

    pub(super) fn original(&self) -> &Arc<ControllerReceivingOriginalV1> {
        &self.original
    }

    // Only private, closed purpose suppliers pass this representation demand.
    // The same original ledger remains held, including permanent native/index
    // debt; the public loan accepts neither an amount nor an account.
    pub(super) fn require_role_borrow_representation(
        &mut self,
        additional: aos_sandbox_model::ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_healthy()?;
        if self.borrow_debit_failure.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let result = (|| {
            let extent = crate::canonical_journal::CanonicalReplayExtentDataV1::new(
                self.limits(), self.durable_end,
            )?;
            let complete = self.fixed_preparation
                .checked_add(extent.dominant_native_receiving_demand_v1()?)?
                .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
                .checked_add(super::replay::ControllerReplayIndexOriginalV1::dynamic_demand_v1(extent)?)?
                .checked_add(additional)?;
            self.original.require_fixed_writer_complete(complete)?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.borrow_debit_failure = Some(cause);
                self.fence();
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    pub(super) fn enter_initial_bank_preparation_once_v1(&mut self)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        self.require_healthy()?;
        if self.initial_bank_preparation_entered {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.initial_bank_preparation_entered = true;
        Ok(())
    }

    pub(super) fn retained_append_failure(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.append_custody.parked_body().and_then(super::append::ControllerAppendBodyV1::failure)
            .or_else(|| self.append_debit_failure.as_ref().map(|cause| cause as _))
            .or_else(|| self.borrow_debit_failure.as_ref().map(|cause| cause as _))
    }

    pub(super) fn retain_bank_preparation_bytes_v1(
        &mut self,
        additional: aos_sandbox_model::ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.fixed_preparation = self.fixed_preparation.checked_add(additional)?;
        Ok(())
    }

    pub(super) fn record_durable_end(&mut self, end: u64) {
        self.durable_end = end;
    }

    /// Enters one fresh names-only sample after its actual geometry is paid.
    ///
    /// Fresh entry retains the ordinary health gate. Once the sample has begun,
    /// its private owed completion still observes the held names after poison.
    pub(super) fn begin_name_sample(
        &self,
        sample: &mut ControllerWriterNameSampleV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if sample.entry.is_some() {
            sample.reentered = true;
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        sample.entry = Some(self.require_healthy());
        if !matches!(sample.entry, Some(Ok(()))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        sample.native.begin(true).map_err(ControllerBankLaunchErrorV1::from)
    }

    /// Pays an already-entered sample's name debt on the SAME actual files.
    ///
    /// No health re-entry runs here. The prearmed entry is required; failed names
    /// retain their lower partials and do not reach the dependent witness step.
    pub(super) fn finish_owed_name_sample(
        &self,
        sample: &mut ControllerWriterNameSampleV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !matches!(sample.entry, Some(Ok(()))) || sample.completion.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let result = self.physical.observe_names_into(&mut sample.native);
        sample.completion = Some(sample.native.finish(result));
        if !matches!(sample.completion, Some(Ok(()))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        sample.witness_result = Some(self.physical.writer_witness_retaining_v1(&mut sample.witness));
        if !matches!(sample.witness_result, Some(Ok(()))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }
}

impl<P> Drop for ControllerFixedWriterOriginalV1<P> {
    fn drop(&mut self) {
        if self.fenced || self.physical.native.native().is_poisoned()
            || !self.append_custody.is_idle() || !self.physical.replacement_custody.is_idle()
        {
            // An uncertain append/currentness owner cannot disappear through
            // normal field destruction while its actual C still exists.
            std::process::abort();
        }
    }
}

/// Retains every reached name sample until its WHOLE enclosing interval ends.
pub(super) struct ControllerWriterNameSampleV1 {
    entry: Option<Result<(), ControllerBankLaunchErrorV1>>,
    native: WriterCurrentnessOriginalsV1<crate::canonical_journal::NativeJournalDataErrorV1>,
    completion: Option<Result<(), crate::canonical_journal::NativeJournalDataErrorV1>>,
    witness: WriterWitnessOriginalsV1<crate::canonical_journal::NativeJournalDataErrorV1>,
    witness_result: Option<Result<(), crate::canonical_journal::NativeJournalDataErrorV1>>,
    reentered: bool,
    disposed: bool,
}

impl ControllerWriterNameSampleV1 {
    pub(super) const fn new() -> Self {
        Self {
            entry: None,
            native: WriterCurrentnessOriginalsV1::new(),
            completion: None,
            witness: WriterWitnessOriginalsV1::new(),
            witness_result: None,
            reentered: false,
            disposed: false,
        }
    }

    pub(super) fn fixed_demand_v1(
    ) -> Result<aos_sandbox_model::ResourceVector, ControllerBankLaunchErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let wrapper = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes)
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?);
        let witness = WriterWitnessOriginalsV1::<crate::canonical_journal::NativeJournalDataErrorV1>
            ::receiving_footprint_v1().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let witness_demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(witness.memory_bytes)
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?)
            .with(D::OpenFiles, u64::try_from(witness.open_files)
                .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?);
        Ok(wrapper.checked_add(
            WriterCurrentnessOriginalsV1::<crate::canonical_journal::NativeJournalDataErrorV1>
                ::named_demand_v1(super::recipe::NAME)?,
        )?.checked_add(witness_demand)?)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.entry.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.native.failure())
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.witness.failure())
            .or_else(|| self.witness_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.reentered.then_some(&NAME_REENTERED as &(dyn std::error::Error + 'static)))
    }

    pub(super) fn has_owed_native_post(&self) -> bool {
        matches!(self.entry, Some(Ok(()))) && self.completion.is_none()
    }

    pub(super) fn witness(&self) -> Option<&ProtectedWriterNameWitness> {
        if self.failure().is_some() {
            return None;
        }
        self.witness.completed_witness()
    }

    pub(super) fn has_disposed_complete_interval_v1(&self) -> bool {
        self.disposed && self.failure().is_none() && self.witness().is_some()
            && self.native.is_complete() && self.native.retained_file_count() == 0
    }

    // Only the positive complete conjunction calls this, after every launch,
    // native and profile post. A positive name check alone cannot dispose it.
    pub(super) fn dispose_after_complete_interval(&mut self) {
        if self.failure().is_none() && self.witness().is_some() && !self.disposed {
            if !self.witness.retire_positive_metadata_once_v1() {
                std::process::abort();
            }
            self.native.settle_positive_once_v1();
            self.disposed = true;
        }
    }
}

static NAME_REENTERED: ControllerBankLaunchErrorV1 = ControllerBankLaunchErrorV1::Conflict;
