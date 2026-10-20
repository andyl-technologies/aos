//! Limits the new paid Start interval to its canonical authorization/admission.
//!
//! Generic Journal mutation stays fenced. Only the existing floor encoder and
//! canonical Core admission assembly can supply these private recipes. The same
//! native append engine retains the original; no scope-presence waiver exists.

use std::sync::Arc;

use crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1;
use crate::controller_resource_reservation::StartNativeStateV1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::policy_compiler::create_q04::Q04CutIdentityV1;
use crate::{Journal, JournalError, JournalTransaction};

use super::OperationPlan;

mod host;
pub(crate) use host::StartHostCoreScopePhaseV2;

pub(crate) struct StartAdmissionScopeV1 {
    native: StartNativeStateV1,
    host: Option<host::StartHostScopeDataV2>,
    identity: Arc<()>,
    plan: Option<Arc<OperationPlan>>,
    floor_entered: bool,
    admission_entered: bool,
}

impl StartAdmissionScopeV1 {
    pub(crate) fn from_entry_v1(
        entry: &mut crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let identity = Arc::clone(entry.scope_identity_v1()?);
        let native = entry.take_native_state_v1(controller)?;
        Ok(Self { native, host: None, identity, plan: None, floor_entered: false, admission_entered: false })
    }

    pub(crate) fn into_native_v1(self) -> StartNativeStateV1 {
        self.native
    }

    pub(crate) fn require_entry_v1(&self, entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.host.is_some() || !Arc::ptr_eq(&self.identity, entry.scope_identity_v1()?) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.native.require_current_v1(controller)
    }

    pub(crate) fn bind_actual_plan_v1(&mut self,
        original: &crate::controller_resource_reservation::AcceptedStartPlanOriginalV1<'_>,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.host.is_some() || self.plan.is_some() || !self.floor_entered || self.admission_entered
            || !Arc::ptr_eq(&self.identity, original.scope_identity_v1()?) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.native.require_current_v1(controller)?;
        original.require_predecessor_v1(self.native.q04_v1()?)?;
        self.plan = Some(Arc::clone(original.plan_v1()?));
        Ok(())
    }

    pub(crate) fn require_current_v1(&self, controller: &Journal) -> Result<(), JournalError> {
        self.native.require_current_v1(controller).map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn matches_q04_v1(&self, expected: &Q04CutIdentityV1) -> bool {
        self.native.q04_v1().is_ok_and(|actual| actual == expected)
    }

    pub(crate) fn prepay_append_v1(&mut self, controller: &Journal,
        transaction: &JournalTransaction, index: usize,
    ) -> Result<(), JournalError> {
        if self.host.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.native.require_append_once_v1(controller, transaction, index)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn prepare_floor_v1(&mut self, transaction: &JournalTransaction,
        recipe: &PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        if self.host.is_some() || self.floor_entered || self.plan.is_some() || self.admission_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        recipe.require_exact_v1(transaction)?;
        self.floor_entered = true;
        Ok(())
    }

    pub(crate) fn require_floor_v1(&self, controller: &Journal,
        transaction: &JournalTransaction, recipe: &PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        if self.host.is_some() || !self.floor_entered || self.plan.is_some() || self.admission_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_current_v1(controller)?;
        recipe.require_exact_v1(transaction)
    }

    pub(crate) fn prepare_admission_v1(&mut self, plan: &OperationPlan) -> Result<(), JournalError> {
        if self.host.is_some() || !self.floor_entered || self.admission_entered
            || self.plan.as_deref() != Some(plan) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.admission_entered = true;
        Ok(())
    }

    pub(crate) fn require_admission_v1(&self, controller: &Journal,
        plan: &OperationPlan,
    ) -> Result<(), JournalError> {
        if self.host.is_some() || !self.floor_entered || !self.admission_entered || self.plan.as_deref() != Some(plan) {
            return Err(JournalError::ProtectedBoundary);
        }
        // The unchanged Core admission validator/encoder supplies the exact
        // complete row set from this SAME immutable plan. No parser is repeated.
        self.require_current_v1(controller)
    }
}
