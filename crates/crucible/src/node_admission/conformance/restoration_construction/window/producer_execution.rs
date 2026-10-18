//! Retains recurrent real scheduler grants before fallible Producer preparation.
//!
//! An inline pending owner precedes quotation and history allocation. Every
//! append is separately admitted under the complete owning census. Completion,
//! failure and caller Drop never recycle a slot or refund a retained future row.

use super::*;
use crate::node_adapters::cnp::CnpSemanticSource;
use crate::node_contract::{OriginalRestoredProducerPublicationConstructionData, WorldActivation};
use crate::node_scheduling::ExecutionAdmission;
use crucible_node_provider::reference_packet::service::native_startup::PacketRestoredProducerLifecycleStorageData;

/// Contains the Source-derived complete construction commitment for one attempt.
///
/// Private construction binds this DATA to the real Source and Controller.
/// Only the separately issued Runtime/Window claim can authorize a callback.
#[derive(Clone, Copy)]
pub struct OriginalRestoredProducerExecutionConstructionData {
    pub(crate) process: u32,
    pub(crate) thread: ThreadId,
    pub(crate) source: *const PacketCompleteSemanticSource,
    pub(crate) controller: *const crucible_node_provider::client::CnpController,
    pub(crate) read_owner: *const (),
    pub(crate) provider: PacketRestoredProducerLifecycleStorageData,
    pub(crate) retained: usize,
    pub(crate) transient: usize,
    pub(crate) scratch: usize,
    pub(crate) maximum: usize,
    pub(crate) runtime_work: (usize, usize, usize),
    pub(crate) complete_scratch: usize,
}

impl OriginalRestoredProducerExecutionConstructionData {
    /// Returns all independent simultaneous action construction axes.
    ///
    /// # Errors
    /// Refuses checked overflow or a complete demand above its original ceiling.
    pub fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        checked_sum(
            &[
                self.retained,
                self.transient,
                self.scratch,
                self.runtime_work.0,
                self.runtime_work.1,
                self.runtime_work.2,
            ],
            self.maximum,
        )
    }

    /// Returns the independent fixed defining counter demand.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.complete_scratch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProducerExecutionStage {
    Pending,
    Quoted,
    BeginStarted,
    Begun,
    PollStarted,
    Completed,
    PublicationStarted,
    Published,
    RetirementStarted,
    Retired,
    ObservationStarted,
    Verified,
    Failed,
}

pub(super) struct ProducerExecutionAttempt {
    grant: ExecutionAdmission,
    slot: usize,
    row: Option<OriginalRestoredProducerExecutionConstructionData>,
    stage: Cell<ProducerExecutionStage>,
}

pub(super) struct ProducerExecutionLedger {
    pending: Option<ProducerExecutionAttempt>,
    attempts: Vec<ProducerExecutionAttempt>,
}

impl ProducerExecutionLedger {
    pub(super) fn new() -> Self {
        Self {
            pending: None,
            attempts: Vec::new(),
        }
    }

    pub(super) fn require_available_data(&self) -> Result<(), RuntimeError> {
        if self.pending.is_some()
            || self
                .attempts
                .last()
                .is_some_and(|attempt| attempt.stage.get() != ProducerExecutionStage::Verified)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    // The caller retains or abandons this SAME grant if insertion refuses.
    // This function neither clones it nor replaces any prior owner.
    pub(super) fn retain_pending_data(
        &mut self,
        grant: ExecutionAdmission,
        slot: usize,
    ) -> Result<(), (RuntimeError, ExecutionAdmission)> {
        if let Err(error) = self.require_available_data() {
            return Err((error, grant));
        }
        if self
            .attempts
            .last()
            .is_some_and(|attempt| attempt.slot >= slot)
        {
            return Err((RuntimeError::DuplicateOperation, grant));
        }
        self.pending = Some(ProducerExecutionAttempt {
            grant,
            slot,
            row: None,
            stage: Cell::new(ProducerExecutionStage::Pending),
        });
        Ok(())
    }

    pub(super) fn pending_grant_data(&self) -> Result<&ExecutionAdmission, RuntimeError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if pending.stage.get() != ProducerExecutionStage::Pending {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(&pending.grant)
    }

    pub(super) fn retain_quote_data(
        &mut self,
        row: OriginalRestoredProducerExecutionConstructionData,
    ) -> Result<(), RuntimeError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if pending.stage.get() != ProducerExecutionStage::Pending || pending.row.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Retain the row before a checked demand can fail. Failure cannot make
        // the original grant or its future commitment disappear from census.
        pending.row = Some(row);
        pending.stage.set(ProducerExecutionStage::Failed);
        row.requested_bytes_data()?;
        pending.stage.set(ProducerExecutionStage::Quoted);
        Ok(())
    }

    pub(super) fn append_after_census_data(&mut self) -> Result<usize, RuntimeError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if pending.stage.get() != ProducerExecutionStage::Quoted || pending.row.is_none() {
            return Err(RuntimeError::OutstandingObligations);
        }
        pending.stage.set(ProducerExecutionStage::Failed);
        // The caller has already held and admitted the full requested new bank
        // beside the old capacity. Allocation failure keeps the inline owner.
        self.attempts
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let pending = self.pending.take().ok_or(RuntimeError::OwnerUnavailable)?;
        let slot = pending.slot;
        pending.stage.set(ProducerExecutionStage::Quoted);
        self.attempts.push(pending);
        Ok(slot)
    }

    pub(super) fn last_data(&self, slot: usize) -> Result<&ProducerExecutionAttempt, RuntimeError> {
        self.attempts
            .last()
            .filter(|attempt| attempt.slot == slot)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    pub(super) fn future_requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        let mut requested = 0usize;
        for attempt in self.attempts.iter().chain(self.pending.iter()) {
            if let Some(row) = &attempt.row {
                requested = requested
                    .checked_add(row.requested_bytes_data()?)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        Ok(requested)
    }

    pub(super) fn charge_original_storage_data(
        &self,
        runtime: crate::node_contract::ConformanceRuntimeObservation<'_>,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut requested = self
            .attempts
            .capacity()
            .checked_mul(size_of::<ProducerExecutionAttempt>())
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        for attempt in self.attempts.iter().chain(self.pending.iter()) {
            requested = checked_sum(
                &[
                    requested,
                    runtime.original_restored_producer_grant_requested_storage_data(
                        &attempt.grant,
                        maximum,
                    )?,
                ],
                maximum,
            )?;
        }
        Ok(requested)
    }

    pub(super) fn append_bank_requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        self.attempts
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(size_of::<ProducerExecutionAttempt>()))
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl ProducerExecutionAttempt {
    pub(super) fn grant_data(&self) -> &ExecutionAdmission {
        &self.grant
    }

    pub(super) fn row_data(
        &self,
    ) -> Result<&OriginalRestoredProducerExecutionConstructionData, RuntimeError> {
        self.row.as_ref().ok_or(RuntimeError::OwnerUnavailable)
    }

    // Callers must authenticate the corresponding sealed Source completion
    // before advancing. This private method cannot itself establish progress.
    pub(super) fn advance_data(
        &self,
        from: ProducerExecutionStage,
        to: ProducerExecutionStage,
    ) -> Result<(), RuntimeError> {
        let legal = matches!(
            (from, to),
            (
                ProducerExecutionStage::Quoted,
                ProducerExecutionStage::BeginStarted
            ) | (
                ProducerExecutionStage::BeginStarted,
                ProducerExecutionStage::Begun
            ) | (
                ProducerExecutionStage::Begun,
                ProducerExecutionStage::PollStarted
            ) | (
                ProducerExecutionStage::PollStarted,
                ProducerExecutionStage::Completed
            ) | (
                ProducerExecutionStage::Completed,
                ProducerExecutionStage::PublicationStarted
            ) | (
                ProducerExecutionStage::PublicationStarted,
                ProducerExecutionStage::Published
            ) | (
                ProducerExecutionStage::Published,
                ProducerExecutionStage::RetirementStarted
            ) | (
                ProducerExecutionStage::RetirementStarted,
                ProducerExecutionStage::Retired
            ) | (
                ProducerExecutionStage::Retired,
                ProducerExecutionStage::ObservationStarted
            ) | (
                ProducerExecutionStage::ObservationStarted,
                ProducerExecutionStage::Verified
            )
        );
        if !legal || self.stage.replace(ProducerExecutionStage::Failed) != from {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.stage.set(to);
        Ok(())
    }

    pub(super) fn fail_data(&self) {
        self.stage.set(ProducerExecutionStage::Failed);
    }
}

pub(super) struct ProducerPublicationIdentity {
    pub(super) publisher: *const (),
    pub(super) row: OriginalRestoredProducerPublicationConstructionData,
    selected: usize,
    construction_started: Cell<bool>,
    constructing: Cell<bool>,
    constructed: Cell<bool>,
}

pub(super) fn counter_scratch_data() -> usize {
    use std::cell::{BorrowError, BorrowMutError, Ref, RefMut};
    use std::iter::{Chain, Enumerate};
    use std::{option, slice};
    type Attempts = Chain<
        slice::Iter<'static, ProducerExecutionAttempt>,
        option::Iter<'static, ProducerExecutionAttempt>,
    >;

    NodeRuntime::original_restored_producer_grant_counter_scratch_data()
        + PacketCompleteSemanticSource::original_restored_producer_execution_counter_scratch_data()
        + crate::node_adapters::cnp::CnpSemanticNode::original_producer_execution_node_counter_scratch_data()
        + PacketCompleteSemanticSource::original_restored_producer_outcome_counter_scratch_data()
        + crate::node_contract::OriginalRestoredProducerPublicationScope::counter_scratch_data()
        + size_of::<ProducerExecutionLedger>()
        + size_of::<ProducerExecutionAttempt>()
        + size_of::<Option<ProducerExecutionAttempt>>()
        + size_of::<Vec<ProducerExecutionAttempt>>()
        + size_of::<ProducerPublicationIdentity>()
        + size_of::<OnceCell<ProducerPublicationIdentity>>()
        + size_of::<[RefCell<ProducerExecutionLedger>; 3]>()
        + size_of::<[Cell<Option<(usize, usize, usize)>>; 3]>()
        + size_of::<[Cell<bool>; 3]>()
        + size_of::<Option<(usize, usize, usize)>>()
        + size_of::<(usize, usize, usize)>()
        + size_of::<OriginalRestoredProducerExecutionConstructionData>()
        + size_of::<Option<OriginalRestoredProducerExecutionConstructionData>>()
        + size_of::<OriginalRestoredProducerPublisherConstructionScope<'static>>()
        + size_of::<&OriginalRestoredProducerPublisherConstructionScope<'static>>()
        + size_of::<PublisherConstructionGuard<'static>>()
        + size_of::<Option<(*const (), &'static OriginalRestoredProducerPublicationConstructionData)>>()
        + size_of::<Ref<'static, ProducerExecutionLedger>>()
        + size_of::<RefMut<'static, ProducerExecutionLedger>>()
        + size_of::<Result<Ref<'static, ProducerExecutionLedger>, BorrowError>>()
        + size_of::<Result<RefMut<'static, ProducerExecutionLedger>, BorrowMutError>>()
        + size_of::<Result<Ref<'static, ProducerExecutionLedger>, RuntimeError>>()
        + size_of::<Result<RefMut<'static, ProducerExecutionLedger>, RuntimeError>>()
        + size_of::<Result<(), (RuntimeError, ExecutionAdmission)>>()
        + size_of::<Result<&ExecutionAdmission, RuntimeError>>()
        + size_of::<Result<&ProducerExecutionAttempt, RuntimeError>>()
        + size_of::<Result<&OriginalRestoredProducerExecutionConstructionData, RuntimeError>>()
        + size_of::<Option<&ProducerExecutionAttempt>>()
        + size_of::<Option<&mut ProducerExecutionAttempt>>()
        + size_of::<Option<&ProducerPublicationIdentity>>()
        + size_of::<Result<&ProducerPublicationIdentity, RuntimeError>>()
        + size_of::<Attempts>()
        + size_of::<slice::Iter<'static, ProducerExecutionAttempt>>()
        + size_of::<option::Iter<'static, ProducerExecutionAttempt>>()
        + size_of::<slice::Iter<'static, RefCell<ProducerExecutionLedger>>>()
        + size_of::<Enumerate<slice::Iter<'static, Rc<PacketCompleteSemanticSource>>>>()
        + size_of::<slice::Iter<'static, OnceCell<CompleteOriginalRestorationTransactionTarget>>>()
        + size_of::<OriginalRestorationMemberScope<'static>>()
        + size_of::<ProducerExecutionStage>() * 2
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<[usize; 3]>()
        + size_of::<[usize; 2]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[usize]>()
        + size_of::<&usize>()
        + size_of::<Option<*const ()>>()
}

impl OriginalRestoredProducerExecutionConstructionData {
    pub(crate) fn authenticate_owner_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: *const crucible_node_provider::client::CnpController,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || self.controller != controller
            || self.read_owner.is_null()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.requested_bytes_data()?;
        Ok(())
    }
}

#[path = "producer_execution/claims.rs"]
mod claims;
#[path = "producer_execution/grant.rs"]
mod grant;
#[path = "producer_execution/publication.rs"]
mod publication;

pub(crate) use claims::ProducerExecutionPhase;
pub use claims::{
    OriginalRestoredProducerExecutionAdmission, OriginalRestoredProducerExecutionClaim,
};
pub use publication::OriginalRestoredProducerPublisherConstructionScope;
use publication::PublisherConstructionGuard;
