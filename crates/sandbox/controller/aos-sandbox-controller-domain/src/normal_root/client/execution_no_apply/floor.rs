//! Borrows the genuine retained Root floor across Cprepare and CAS bookends.

use super::*;

/// Borrows a completed actual Root floor and its continuously held native socket.
#[must_use = "finish every prepaid Root after observation before releasing the borrow"]
pub struct RootExecutionNoApplyClientFloorBorrowV2<'root> {
    pub(super) owner: &'root mut RootExecutionNoApplyClientOriginalV2,
    pub(super) profile: &'root ProductionControllerNormalRootProfileV1,
}

impl RootExecutionNoApplyClientFloorBorrowV2<'_> {
    /// Borrows literal attestation DATA only with its completed actual Root response.
    ///
    /// # Errors
    /// Refuses a failed original or an incomplete/malformed floor response.
    pub fn canonical_attestation_data_v2(
        &self,
    ) -> Result<&[u8], RootExecutionNoApplyClientClosedV2> {
        if self.owner.first.is_some() || self.owner.phase < 2 {
            return Err(RootExecutionNoApplyClientClosedV2);
        }
        let native = self.owner.native()?;
        ExecutionNoApplyFloorReplyDataV2::decode_v2(native.replies[1].received.bytes())
            .map(|reply| reply.attestation)
            .map_err(|_| RootExecutionNoApplyClientClosedV2)
    }

    /// Parks the paid independent Root post before entering genuine Cprepare.
    ///
    /// # Errors
    /// Refuses changed native C association, reentry or a failed Root bookend.
    pub fn begin_controller_prepare_once_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        self.owner.require_phase(2)?;
        if let Err(cause) = self.owner.require_owned_cut(loan) {
            return Err(self.owner.refuse_validation(cause));
        }
        self.owner.pending = Some(5);
        self.owner.observe_bookend(4, self.profile, false)
    }

    /// Runs the separately prepaid Root after even when Cprepare or Source refused.
    ///
    /// # Errors
    /// Retains the actual native after refusal without a fresh Source debit.
    pub fn finish_controller_prepare_owed_once_v2(
        &mut self,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        let result = self.owner.drain_owed(self.profile);
        if let Some(native) = self.owner.state.as_mut() {
            native.prepare_after = Some(result);
        }
        if result.is_ok() && self.owner.first.is_none() {
            self.owner.phase = 3;
        }
        result
    }

    /// Requires the actual Cprepare Root after observation to have completed.
    ///
    /// # Errors
    /// Refuses missing or failed posts, preserving the original native cause.
    pub fn require_controller_prepare_complete_v2(
        &self,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        if self.owner.first.is_none() && matches!(self.owner.native()?.prepare_after, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    /// Parks the paid independent Root post before entering the genuine CAS.
    ///
    /// # Errors
    /// Refuses reentry, a stale genuine prepared-floor owner or native Root refusal.
    pub fn begin_controller_cas_once_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        self.owner.require_phase(3)?;
        loan.require_prepared_root_floor_current_v2(self.canonical_attestation_data_v2()?)
            .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        self.owner.pending = Some(7);
        self.owner.observe_bookend(6, self.profile, false)
    }

    /// Runs the prepaid independent Root after even after CAS or Source refusal.
    ///
    /// # Errors
    /// Retains actual native refusal and never performs a new Source debit.
    pub fn finish_controller_cas_owed_once_v2(
        &mut self,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        let result = self.owner.drain_owed(self.profile);
        if let Some(native) = self.owner.state.as_mut() {
            native.cas_after = Some(result);
        }
        if result.is_ok() && self.owner.first.is_none() {
            self.owner.phase = 4;
        }
        result
    }

    /// Requires the actual CAS Root after observation to have completed.
    ///
    /// # Errors
    /// Refuses absent/failed native posts, preserving the same first cause.
    pub fn require_controller_cas_complete_v2(
        &self,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        if self.owner.first.is_none() && matches!(self.owner.native()?.cas_after, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }
}
impl Drop for RootExecutionNoApplyClientFloorBorrowV2<'_> {
    fn drop(&mut self) {
        if self.owner.pending.is_some() {
            self.owner
                .reentry
                .get_or_insert(RootExecutionNoApplyClientClosedV2);
            self.owner.first.get_or_insert(First::Unwind);
            let _ = self.owner.drain_owed(self.profile);
        }
    }
}
