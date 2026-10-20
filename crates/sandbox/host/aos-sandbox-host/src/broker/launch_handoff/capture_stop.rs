//! Binds fresh Stop containment to the actual failed resident execution.
//!
//! This private identity borrower grants no effect, financial capacity or
//! native operation. The actual Launch keeps the Stage strongly resident;
//! fresh authenticated Stop admission and its separate receiving loan remain
//! required before any disabling write or physical alias retirement.

use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::plan::HostExecutionRequestBindingV2;
use crate::{HostError, Result};
use super::super::argument_handoff::ArgumentStageOriginalV2;

#[derive(Clone)]
pub(crate) struct HostCaptureFailedStageV4 {
    stage: Weak<Mutex<ArgumentStageOriginalV2>>,
    unknown: Arc<AtomicBool>,
    accept: HostExecutionRequestBindingV2,
    execution: aos_sandbox_model::ExecutionId,
}

impl HostCaptureFailedStageV4 {
    pub(in crate::broker::launch_handoff) fn from_resident_v4(
        stage: &Arc<Mutex<ArgumentStageOriginalV2>>,
        unknown: &Arc<AtomicBool>,
        accept: HostExecutionRequestBindingV2,
        execution: aos_sandbox_model::ExecutionId,
    ) -> Result<Self> {
        let held = stage.lock().map_err(|_| refused())?;
        if !unknown.load(Ordering::Acquire)
            || (held.request.1, held.request.2, held.request.3)
                != (accept.id, accept.session, accept.signed)
            || held.accepted.is_none()
        {
            return Err(refused());
        }
        Ok(Self { stage: Arc::downgrade(stage), unknown: Arc::clone(unknown), accept, execution })
    }

    pub(crate) fn require_failed_resident_v4(&self) -> Result<()> {
        if !self.unknown.load(Ordering::Acquire) {
            return Err(refused());
        }
        // The factory checked the immutable Stage request while holding its
        // real mutex. The Launch retains that same Stage; checking this weak
        // binding avoids relocking it while the actual accepted owner is lent.
        self.stage.upgrade().ok_or_else(refused)?;
        Ok(())
    }

    pub(crate) fn execution_v4(&self) -> aos_sandbox_model::ExecutionId { self.execution }

    pub(crate) fn accept_v4(&self) -> HostExecutionRequestBindingV2 { self.accept }
}

fn refused() -> HostError {
    HostError::Fence("fresh Stop does not borrow the actual failed Capture Stage")
}
