//! Keeps the two actual location-only writer observations at their old slots.
//!
//! Location validates the held directory and health and returns unit. It never
//! reads physical names DATA or adds the distinct physical witness recipe.

use std::error::Error;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use crate::native::journal::{RootPolicyJournalV1, names::{
    RootFixedNameRoleV1 as Role, RootFixedNameRecipeV1 as Recipe,
    RootPolicyNameObservationOriginalV1 as Names,
}};
use crate::native::target::RootPolicyTargetOriginalV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;

use super::initial_open::RootInitialOpenErrorV1 as E;

pub(super) struct RootInitialLocationPairOriginalV1 {
    authority: Names,
    policy: Names,
    authority_result: Option<Result<(), E>>,
    policy_result: Option<Result<(), E>>,
    entered: bool,
    closed: bool,
}

impl RootInitialLocationPairOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            authority: Names::new(),
            policy: Names::new(),
            authority_result: None,
            policy_result: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn observe_once_v1(
        &mut self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
    ) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.authority_result = Some(self.authority
            .observe_once(authority, Role::Authority, Recipe::Location)
            .map_err(|()| E::Boundary));
        self.policy_result = Some(policy.observe_fixed_location_once_v1(&mut self.policy)
            .map_err(|()| E::Boundary));
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if self.entered && !self.closed
            && matches!(self.authority_result, Some(Ok(())))
            && matches!(self.policy_result, Some(Ok(())))
            && self.failure_v1().is_none()
        {
            Ok(())
        } else {
            Err(E::Boundary)
        }
    }

    pub(super) fn additional_native_demand_v1() -> Result<ResourceVector, NativeError> {
        let authority = Names::additional_demand_v1(Role::Authority, Recipe::Location)?;
        let policy = Names::additional_demand_v1(Role::Policy, Recipe::Location)?;
        let cells = Names::retained_control_cells_v1().checked_mul(2)
            .ok_or_else(NativeError::geometry)?;
        authority.checked_add(policy)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MetadataEntries, cells)))
            .map_err(|_| NativeError::geometry())
    }

    // Bundle verification's original arrays selected both native originals
    // before either returned marker. Trust retains its separate interleaved
    // selector below; these passive views preserve each actual caller's order.
    pub(super) fn native_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.authority.failure().or_else(|| self.policy.failure())
    }

    pub(super) fn returned_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.authority_result).or_else(|| cause(&self.policy_result))
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.authority.failure()
            .or_else(|| cause(&self.authority_result))
            .or_else(|| self.policy.failure())
            .or_else(|| cause(&self.policy_result))
    }
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
