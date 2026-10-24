//! Borrows one pending dispatch from the actual Runtime admission ledger.
//!
//! The runtime creates this scope only after its combined operation/input limit,
//! duplicate identity, owner reservation, World and route checks. Its lifetime
//! borrows the real retained entry while the node callback runs. It cannot be
//! cloned, decoded or reconstructed from an OperationAdmission copy.

use super::*;
use std::{mem::size_of, thread::ThreadId};

/// Borrows the runtime's actual pending original during its first node dispatch.
///
/// This scope authenticates Runtime admission custody only. Source policy,
/// independently prepaid action storage, same-window restoration provenance and
/// current native proof remain separate prerequisites before any suffix effect.
/// No constructor, Clone or serialization implementation is provided.
pub struct OriginalRuntimeOperationDispatch<'a> {
    retained: &'a RetainedOperation,
    authority: &'a Rc<()>,
    world: &'a WorldActivation,
    activated: &'a bool,
    barrier: &'a ActivationBarrier,
    process: u32,
    thread: ThreadId,
}

impl<'a> OriginalRuntimeOperationDispatch<'a> {
    /// Identifies a refusal before the node accepts the retained Runtime scope.
    pub(crate) const NODE_IDENTITY_REFUSAL: &'static str =
        "pending dispatch does not match the actual runtime node";

    /// Identifies a refusal of the installed same-Window custody association.
    pub(crate) const SUFFIX_IDENTITY_REFUSAL: &'static str =
        "restored suffix pending dispatch identity refused";

    /// Identifies the deliberately unavailable current-proof action admission.
    pub(crate) const SUFFIX_ACTION_ROW_REFUSAL: &'static str =
        "restored suffix current-proof action row is not admitted";

    /// Bounds both independent reason backings per retained used operation.
    ///
    /// Runtime retains a cloned failure while returning the original refusal.
    /// Its actual combined operation/input ceiling bounds all such used IDs.
    /// This row funds these reasons only, not a later native action phase.
    ///
    /// # Errors
    /// Refuses arithmetic overflow without changing the installed limit.
    pub(crate) fn refused_reason_retained_bytes_data(
        maximum_operations: usize,
    ) -> Result<usize, RuntimeError> {
        let maximum_reason_bytes = Self::NODE_IDENTITY_REFUSAL
            .len()
            .max(Self::SUFFIX_IDENTITY_REFUSAL.len())
            .max(Self::SUFFIX_ACTION_ROW_REFUSAL.len());

        maximum_reason_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_mul(maximum_operations))
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Creates the synchronous loan after the runtime's actual insertion/reservation.
    ///
    /// # Errors
    /// Refuses any noninitial or inconsistent retained operation/World association.
    pub(super) fn from_retained(
        retained: &'a RetainedOperation,
        authority: &'a Rc<()>,
        world: &'a WorldActivation,
        activated: &'a bool,
        barrier: &'a ActivationBarrier,
    ) -> Result<Self, RuntimeError> {
        let scope = Self {
            retained,
            authority,
            world,
            activated,
            barrier,
            process: std::process::id(),
            thread: std::thread::current().id(),
        };
        scope.authenticate_original_data(
            &retained.admission,
            world,
            retained.admission.token().route(),
        )?;
        Ok(scope)
    }

    /// Borrows the exact original retained by the issuing runtime.
    pub fn admission_data(&self) -> &OperationAdmission {
        &self.retained.admission
    }

    /// Rechecks the same pending ledger entry, World, route and runtime authority.
    ///
    /// A copied admission with an equal genuine token is historical DATA, not
    /// this exclusive pending-dispatch loan. The immutable ledger borrow also
    /// prevents replacing its result or publication fields during this callback.
    ///
    /// # Errors
    /// Refuses another thread/process, admission allocation, runtime authority,
    /// World or route, an inactive runtime, and any noninitial pending phase.
    pub fn authenticate_original_data(
        &self,
        admission: &OperationAdmission,
        world: &WorldActivation,
        route: &NodeRoute,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !*self.activated
            || !std::ptr::eq(admission, &self.retained.admission)
            || !Rc::ptr_eq(self.authority, &admission.token().authority)
            || !Rc::ptr_eq(self.authority, &world.authority)
            || !self.world.same_authority(world)
            || !admission.activation().same_authority(world)
            || world.record() != self.barrier.record()
            || admission.token().route() != route
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if !matches!(self.retained.result, RetainedResult::Pending)
            || self.retained.close_submission.is_some()
            || self.retained.submission_effects.is_some()
            || self.retained.scheduling_commit.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    /// Names the new borrowed scope and complete fixed construction/result views.
    ///
    /// Selected suffix construction adds this term independently before Prepare;
    /// it is not an execution allowance or a substitute for current heap census.
    pub fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>() * 2
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<(
                &RetainedOperation,
                &Rc<()>,
                &WorldActivation,
                &bool,
                &ActivationBarrier,
            )>()
            + size_of::<(&Self, &OperationAdmission, &WorldActivation, &NodeRoute)>()
            + size_of::<&ActivationRecord>() * 2
            + size_of::<std::slice::Iter<'static, OwnerIdentity>>()
            + size_of::<&OwnerIdentity>() * 2
            + size_of::<&RetainedOperation>()
            + size_of::<&OperationAdmission>() * 2
            + size_of::<&Rc<()>>()
            + size_of::<&WorldActivation>() * 2
            + size_of::<&bool>()
            + size_of::<&ActivationBarrier>()
            + size_of::<&NodeRoute>()
            + size_of::<&OperationToken>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<super::super::Submission>()
            + size_of::<super::super::Refusal>()
            + size_of::<String>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<usize>() * 3
            + size_of::<&str>() * 3
            + size_of::<Option<&RetainedOperation>>()
            + size_of::<Result<&RetainedOperation, RuntimeError>>()
    }
}
