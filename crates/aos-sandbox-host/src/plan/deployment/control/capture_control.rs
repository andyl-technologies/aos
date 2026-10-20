//! Retains a prearmed Capture liability on the same intrinsic Host original.
//!
//! The checked representation is priced before the first Guest issue and stays
//! tied to the occupied Launch and Accept operations. The actual disposition
//! owner determines its permitted behavior. This financial loan alone grants
//! no cancellation, kill, thaw, quiescence or physical-completion permission.

use std::sync::{Arc, Mutex};

use aos_sandbox_core::ResourceVector;

use super::execution_receiving::{CaptureNegativeReservationV3, Request};
use super::{HostComponentControlStartupV2, HostExecutionReceivingLoanV2};
use crate::{HostError, Result};

pub(crate) struct HostCaptureNegativeControlV3 {
    original: Arc<Mutex<HostComponentControlStartupV2>>,
    reservation: Option<CaptureNegativeReservationV3>,
    entered: bool,
}

/// Borrows only the independently prepaid retained disposition liability.
///
/// It exposes no amount, positive gate, native descriptor, deadline extension
/// or operation disposal. The real disposition owner and all reached errors
/// remain resident; a financial association cannot manufacture native scope.
pub(crate) struct HostCaptureNegativeLoanV3 {
    original: Arc<Mutex<HostComponentControlStartupV2>>,
    reservation: CaptureNegativeReservationV3,
}

fn refused() -> HostError {
    HostError::Fence("Host Capture negative continuation is not the same prearmed original")
}

impl HostComponentControlStartupV2 {
    pub(in crate::plan::deployment::control) fn prearm_capture_negative_v3(
        &mut self, launch: Request, accept: Request,
        source: aos_sandbox_core::ObjectDigest, execution: aos_sandbox_core::ExecutionId,
        requirement: ResourceVector,
    ) -> Result<CaptureNegativeReservationV3> {
        self.require_admitted_original()?;
        if self.armed || self.first.is_some() { return Err(refused()); }
        let result = self.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(refused)?.prearm_capture_negative_v3(launch, accept, source, execution, requirement);
        match result {
            Ok(reservation) => Ok(reservation),
            Err(_) => {
                self.first.get_or_insert(super::FirstCauseV2::ExecutionReceiving);
                Err(refused())
            }
        }
    }
}

impl HostExecutionReceivingLoanV2<'_> {
    pub(crate) fn prearm_execution_resident_negative_v5(
        &mut self,
        original: &Arc<Mutex<HostComponentControlStartupV2>>,
        launch: Request,
        source: aos_sandbox_core::ObjectDigest,
        execution: aos_sandbox_core::ExecutionId,
        native_requirement: ResourceVector,
    ) -> Result<HostCaptureNegativeControlV3> {
        self.require_capture_prearm_frontier_v3()?;
        let requirement = native_requirement.checked_add(
            HostCaptureNegativeControlV3::receiving_demand_v3()?)
            .map_err(|_| HostError::ResourceExhausted)?;
        let reservation = self.prearm_capture_reservation_v3(
            launch, source, execution, requirement)?;
        Ok(HostCaptureNegativeControlV3::from_prearmed_original_v3(
            Arc::clone(original), reservation,
        ))
    }
}

impl HostCaptureNegativeControlV3 {
    pub(crate) fn receiving_demand_v3() -> Result<ResourceVector> {
        use aos_sandbox_core::ResourceDimension as D;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<HostCaptureNegativeLoanV3>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .ok_or(HostError::ResourceExhausted)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?))
    }

    fn from_prearmed_original_v3(
        original: Arc<Mutex<HostComponentControlStartupV2>>,
        reservation: CaptureNegativeReservationV3,
    ) -> Self {
        Self { original, reservation: Some(reservation), entered: false }
    }

    pub(crate) fn enter_from_same_control_v4(
        &mut self,
        actual: &Arc<Mutex<HostComponentControlStartupV2>>,
        original: &mut HostComponentControlStartupV2,
    ) -> Result<HostCaptureNegativeLoanV3> {
        if self.entered { return Err(refused()); }
        self.entered = true;
        if !Arc::ptr_eq(actual, &self.original) { return Err(refused()); }
        // The caller already holds this actual control original before taking
        // the Stage lock. Do not invert that order by locking its Arc again.
        original.execution_receiving.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or_else(refused)?.enter_capture_negative_v3(self.reservation.as_ref().ok_or_else(refused)?)
            .map_err(|_| refused())?;
        Ok(HostCaptureNegativeLoanV3 {
            original: Arc::clone(&self.original),
            reservation: self.reservation.take().ok_or_else(refused)?,
        })
    }

}

impl HostCaptureNegativeLoanV3 {
    // This borrows the actual once-moved prearm identity. Only the new closed
    // Stop lender combines it with fresh signed permission; it is no grant.
    pub(in crate::plan::deployment::control) fn reservation_for_stop_v4(&self)
        -> &CaptureNegativeReservationV3 {
        &self.reservation
    }

    pub(crate) fn execution_v3(&self) -> aos_sandbox_core::ExecutionId {
        self.reservation.execution
    }

    pub(crate) fn source_digest_v3(&self) -> aos_sandbox_core::ObjectDigest {
        self.reservation.source
    }

    pub(crate) fn require_owed_v3(&self) -> Result<()> {
        let original = self.original.lock().map_err(|_| refused())?;
        original.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(refused)?.require_capture_negative_owed_v3(&self.reservation)
            .map_err(|_| refused())
    }
}
