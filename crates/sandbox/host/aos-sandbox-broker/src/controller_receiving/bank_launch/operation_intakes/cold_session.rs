//! Lends one cold Host comparison Session from the actual held Execution Source.
//!
//! The shared initial receiver keeps this same consumed C18 flight. Its private
//! identity remains in both the cold capture and the final native Session; the
//! Source scope cannot retire while either native graph remains alive.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::controller_receiving::ControllerReceivingErrorV1;
use crate::controller_receiving::initial_session::ControllerInitialSessionReceivingOriginalV1;

pub(crate) struct ControllerExecutionColdSessionBudgetV2 {
    original: Arc<ControllerReceivingOriginalV1>,
    active: AtomicBool,
    native_retained: AtomicBool,
    pair: ([u8; 16], [u8; 16]),
    node: [u8; 16],
}

/// Keeps the actual cold financial identity inside its final native Session.
///
/// This non-cloneable owner supplies no permission, scalar capacity or refund.
/// The trusted cold engine moves it only into the genuine completed Session,
/// after whose other native fields it is physically dropped.
#[doc(hidden)]
#[must_use]
pub struct ControllerExecutionColdSessionRetentionV2 {
    _budget: Arc<ControllerExecutionColdSessionBudgetV2>,
}

impl ControllerExecutionColdSessionBudgetV2 {
    pub(crate) fn demand_v2() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<ControllerExecutionColdSessionRetentionV2>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(crate) fn require_current_v2(&self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if !self.active.load(Ordering::Acquire) || self.original.is_closed() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.original.operation_intakes.try_lock()
            .map_err(|_| ControllerReceivingErrorV1::Conflict)?
            .slot(OperationIntakePurposeV1::Execution).require_active()
    }

    pub(in crate::controller_receiving) fn raise_complete_v2(&self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.require_current_v2()?;
        self.original.operation_intakes.try_lock()
            .map_err(|_| ControllerReceivingErrorV1::Conflict)?
            .slot_mut(OperationIntakePurposeV1::Execution)
            .reserve_cold_session_complete_v2(complete)
    }

    pub(in crate::controller_receiving) fn pair_data_v2(&self)
        -> Result<([u8; 16], [u8; 16]), ControllerReceivingErrorV1>
    { self.require_current_v2()?; Ok(self.pair) }

    pub(in crate::controller_receiving) fn node_data_v2(&self)
        -> Result<[u8; 16], ControllerReceivingErrorV1>
    { self.require_current_v2()?; Ok(self.node) }

    pub(crate) fn end_primary_v2(&self) { self.active.store(false, Ordering::Release); }

    pub(crate) fn require_last_owner_v2(actual: &Arc<Self>)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        if Arc::strong_count(actual) != 1 || !actual.native_retained.load(Ordering::Acquire) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_receiving) fn retain_native_v2(actual: &Arc<Self>)
        -> Result<ControllerExecutionColdSessionRetentionV2, ControllerReceivingErrorV1>
    {
        actual.require_current_v2()?;
        actual.native_retained.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        Ok(ControllerExecutionColdSessionRetentionV2 { _budget: Arc::clone(actual) })
    }
}

impl ControllerOperationIntakeReceivingLoanV1<'_> {
    pub(crate) fn begin_execution_cold_session_v2<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, fixed: ResourceVector,
    ) -> Result<(Arc<ControllerExecutionColdSessionBudgetV2>, ControllerInitialSessionReceivingOriginalV1),
        ControllerBankLaunchErrorV1>
    {
        self.require_active_v1(writer, launch, profile)?;
        if self.owner.purpose != OperationIntakePurposeV1::Execution || !self.owner.whole_declared
            || !self.delete_source_scope_entered || !self.owner.delete_source_scope_open
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let complete = fixed.checked_add(ControllerExecutionColdSessionBudgetV2::demand_v2()?)?
            .checked_add(super::super::ControllerSessionRepresentationV3::demand_v1()?)?;
        self.owner.original.operation_intakes.try_lock()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .slot_mut(OperationIntakePurposeV1::Execution).begin_cold_session_v2(complete)?;
        let enrollment = self.owner.before_result.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let pair = (enrollment.identity.native_fields().boot,
            enrollment.identity.native_fields().invocation);
        let node = enrollment.identity.native_fields().node;
        let budget = Arc::new(ControllerExecutionColdSessionBudgetV2 {
            original: Arc::clone(&self.owner.original), active: AtomicBool::new(true),
            native_retained: AtomicBool::new(false), pair, node,
        });
        let representation = Arc::new(super::super::ControllerSessionRepresentationV3::from_execution_cold_v2(
            Arc::clone(&self.owner.original), Arc::clone(&budget), fixed,
        )?);
        let receiving = ControllerInitialSessionReceivingOriginalV1::from_recover_v1(
            Arc::clone(&self.owner.original), profile, representation,
        );
        Ok((budget, receiving))
    }
}
