//! Owns the accepted Start's read-only current signed-policy input exchange.
//!
//! The whole accepted Prelude, actual R flight and all native originals remain
//! resident through exact response, End and independent Root disposal. This
//! purpose issues no lease, assignment publication, broker plan or signature.

pub(crate) mod opening;
mod models;
mod receiving;
mod dispatch;

pub(crate) use dispatch::RootStartAssignmentInputsDispatchOriginalV2;

use std::error::Error;

use crate::journal::JournalError;
use crate::normal_root::NormalRootStartupErrorV1;
use crate::policy_compiler::{
    RootCurrentPolicyInputDataV1,
    root_policy_prelude::RootStartAssignmentInputsPreludeV2,
};
use opening::RootStartAssignmentInputsOpeningOriginalV2 as Opening;
use receiving::RootStartAssignmentInputsNativeOriginalV2 as Native;

/// Retains the actual read-only current-input flight through complete disposition.
#[must_use = "retain the whole native input flight until its disposition completes"]
pub struct RootStartAssignmentInputsReceivingV2<'flight, 'listener, 'startup> {
    prelude: RootStartAssignmentInputsPreludeV2<'flight, 'listener, 'startup>,
    opening: Opening,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    funding: Option<Result<(), JournalError>>,
    native: Option<Box<Native>>,
    result: Option<Result<(), JournalError>>,
    negative: Option<Result<(), NormalRootStartupErrorV1>>,
    negative_disposition: Option<Result<(), NormalRootStartupErrorV1>>,
    entry_original_selected: bool,
    closed: bool,
}

impl<'flight, 'listener, 'startup> RootStartAssignmentInputsReceivingV2<'flight, 'listener, 'startup> {
    pub(crate) fn from_prelude_v2(
        prelude: RootStartAssignmentInputsPreludeV2<'flight, 'listener, 'startup>,
    ) -> Self {
        Self {
            prelude,
            opening: Default::default(),
            peer: None,
            funding: None,
            native: None,
            result: None,
            negative: None,
            negative_disposition: None,
            entry_original_selected: false,
            closed: false,
        }
    }

    /// Verifies the current accepted Start and returns the held signed inputs.
    ///
    /// # Errors
    /// Retains altered C/Source/policy cuts, native and financial refusals,
    /// malformed request/EOF, or the unchanged original horizon's expiration.
    pub fn receive_once_v2(&mut self, inputs: &RootCurrentPolicyInputDataV1<'_>)
        -> Result<(), JournalError>
    {
        if self.peer.is_some() || self.closed {
            self.closed = true;
            self.finish_negative_once_v2();
            return Err(JournalError::ProtectedBoundary);
        }
        let root = &mut self.prelude.original;
        self.peer = Some(root.flight.admit_start_assignment_inputs_controller_peer_once_v2());
        if !matches!(self.peer, Some(Ok(()))) {
            self.entry_original_selected = root.flight.failure().is_some();
            self.finish_negative_once_v2();
            return Err(JournalError::ProtectedBoundary);
        }
        self.funding = Some((|| {
            let bytes = std::mem::size_of::<Self>().checked_add(std::mem::size_of::<Native>())
                .ok_or(JournalError::JournalTooLarge)?;
            self.opening.admit_query_once_v1(
                &mut root.flight.start_assignment_inputs_stage_receiving_v2()
                    .map_err(|_| JournalError::ProtectedBoundary)?, bytes,
            )?;
            Ok(())
        })());
        if !matches!(self.funding, Some(Ok(()))) {
            self.entry_original_selected = root.flight.failure().is_some();
            self.finish_negative_once_v2();
            return Err(JournalError::ProtectedBoundary);
        }
        self.native = Some(Box::new(Native::new()));
        self.result = Some(self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .run_once_v2(&mut self.opening, root, inputs));
        let _opening_post = self.prelude.original.native.finish_opening_if_owed_v1();
        if self.require_complete_v2().is_err() {
            self.finish_negative_once_v2();
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn require_complete_v2(&self) -> Result<(), JournalError> {
        if self.closed || self.negative_disposition.is_some() || self.failure().is_some()
            || !matches!(self.peer, Some(Ok(()))) || !matches!(self.funding, Some(Ok(())))
            || !matches!(self.result, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_disposed_complete_v2()
    }

    fn finish_negative_once_v2(&mut self) {
        if self.negative_disposition.is_some() { return; }
        let root = &mut self.prelude.original;
        let _opening_post = root.native.finish_opening_if_owed_v1();
        if let Some(native) = self.native.as_mut() {
            native.finish_posts_once_v2(&self.opening, root.flight);
        } else {
            self.negative = Some(root.flight.finish_start_assignment_inputs_controller_peer_posts_once_v2());
        }
        self.negative_disposition = Some(root.finish_negative_once_v1());
    }

    /// Finishes every reached negative socket/native debt without retrying.
    ///
    /// # Errors
    /// Returns refusal while preserving the original cause and all native owners.
    pub fn finish_negative_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.finish_negative_once_v2();
        self.negative_disposition.as_ref().and_then(|value| value.as_ref().ok())
            .map(|_| ()).ok_or(NormalRootStartupErrorV1::Service)
    }

    /// Transfers the whole completed work to the existing Root disposal engine.
    ///
    /// # Errors
    /// Retains actual End, independent Root post and financial-disposal failure.
    pub fn finish_positive_once(self) -> Result<(), NormalRootStartupErrorV1> {
        let (work, flight) = match self.into_completed_dispatch_v2() {
            Ok(completed) => completed,
            Err(mut original) => {
                let _owed = original.finish_negative_once();
                std::process::abort();
            }
        };
        flight.finish_start_assignment_inputs_dispatch_once_v2(work)
    }

    /// Borrows the selected original failure without IO or new admission.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let root = &self.prelude.original;
        root.native.failure_before_v1()
            .or_else(|| if self.entry_original_selected { root.flight.failure() } else { None })
            .or_else(|| cause(&self.peer))
            .or_else(|| self.opening.failure())
            .or_else(|| cause(&self.funding))
            .or_else(|| self.native.as_ref()?.failure(&self.opening, root.flight.failure()))
            .or_else(|| cause(&self.result))
            .or_else(|| root.native.failure_after_v1())
            .or_else(|| cause(&self.negative))
            .or_else(|| cause(&self.negative_disposition))
    }
}

fn cause<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

// The common query stage invokes this closed actual owner's extra clock/EOF
// supplier before allocating or entering its native body.
pub(in crate::policy_compiler) fn opening_additional_demand_v2()
    -> Result<aos_sandbox_core::ResourceVector, JournalError>
{
    Native::fixed_receiving_demand_v2()
}
