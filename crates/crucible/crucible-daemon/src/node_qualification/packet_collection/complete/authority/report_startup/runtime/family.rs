//! Borrows the same retained proposal for original or fresh inactive construction.
//!
//! Family selection follows the holder's private purpose and actual lifecycle
//! owners. No manifest scalar, copied activation or optional DATA row selects it.

use super::super::{restoration::FreshLifecycleOwners, scene::OriginalSceneOwners};
use super::*;
use std::{cell::Ref, mem::size_of};

pub(super) enum RuntimeConstructionOwner<'a> {
    Original(Ref<'a, OriginalSceneOwners>),
    Fresh(Ref<'a, FreshLifecycleOwners>),
}

impl RuntimeConstructionOwner<'_> {
    pub(super) fn activation(
        &self,
    ) -> Result<&crucible_engine::node_contract::ActivationRecord, RuntimeError> {
        match self {
            Self::Original(owner) => Ok(&owner.inputs.activation),
            Self::Fresh(owner) => Ok(&owner
                .inputs
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .activation),
        }
    }

    pub(super) fn limits(
        &self,
    ) -> Result<crucible_engine::node_contract::RuntimeLimits, RuntimeError> {
        match self {
            Self::Original(owner) => Ok(owner.inputs.runtime_limits),
            Self::Fresh(owner) => Ok(owner
                .inputs
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .runtime_limits),
        }
    }

    pub(super) fn share_supervisor(
        &self,
        member: &CompleteOriginalRuntimeConstructionMember,
    ) -> Result<(), RuntimeError> {
        match self {
            Self::Original(owner) => owner.inputs.supervisor.share_original(member),
            Self::Fresh(owner) => owner
                .inputs
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .supervisor
                .share_original(member),
        }
    }

    pub(super) fn shared_supervisor(
        &self,
    ) -> Result<Ref<'_, Rc<PacketWorldHostSupervisor>>, RuntimeError> {
        match self {
            Self::Original(owner) => owner.inputs.supervisor.shared_data(),
            Self::Fresh(owner) => owner
                .inputs
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .supervisor
                .shared_data(),
        }
    }

    pub(super) fn runtime_slot(
        &self,
    ) -> Result<&dyn crucible_engine::node_contract::RuntimeCustodySlot, RuntimeError> {
        match self {
            Self::Original(owner) => owner
                .runtime_slot
                .as_deref()
                .ok_or(RuntimeError::OwnerUnavailable),
            Self::Fresh(owner) => owner
                .runtime_slot
                .as_deref()
                .ok_or(RuntimeError::OwnerUnavailable),
        }
    }

    pub(super) fn authenticate_completed_lifecycle(&self) -> Result<(), RuntimeError> {
        let valid = match self {
            Self::Original(owner) => {
                owner.staged
                    && owner.launched.get()
                    && owner.initial_completed.iter().all(Cell::get)
            }
            Self::Fresh(owner) => {
                owner.staged
                    && owner.launched.get()
                    && owner.initial_completed.iter().all(Cell::get)
                    && owner.host_completed.iter().all(Cell::get)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(RuntimeError::OutstandingObligations)
        }
    }
}

impl PacketCompleteReportStartupHolder {
    pub(super) fn runtime_construction_owner_data(
        &self,
    ) -> Result<RuntimeConstructionOwner<'_>, RuntimeError> {
        match &self.purpose {
            StartupHolderPurpose::OriginalScene => Ok(RuntimeConstructionOwner::Original(
                self.original_scene
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?,
            )),
            StartupHolderPurpose::FreshRestoration(_) => {
                self.authenticate_fresh_runtime_flight_data()?;
                Ok(RuntimeConstructionOwner::Fresh(
                    self.fresh_lifecycle
                        .get()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .try_borrow()
                        .map_err(|_| RuntimeError::OwnerBusy)?,
                ))
            }
        }
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<RuntimeConstructionOwner<'_>>()
        + size_of::<Result<RuntimeConstructionOwner<'_>, RuntimeError>>()
        + size_of::<Ref<'_, OriginalSceneOwners>>()
        + size_of::<Ref<'_, FreshLifecycleOwners>>()
        + size_of::<Result<Ref<'_, OriginalSceneOwners>, std::cell::BorrowError>>()
        + size_of::<Result<Ref<'_, OriginalSceneOwners>, RuntimeError>>()
        + size_of::<Result<Ref<'_, FreshLifecycleOwners>, std::cell::BorrowError>>()
        + size_of::<Result<Ref<'_, FreshLifecycleOwners>, RuntimeError>>()
        + size_of::<&crucible_engine::node_contract::ActivationRecord>()
        + size_of::<Result<&crucible_engine::node_contract::ActivationRecord, RuntimeError>>()
        + size_of::<crucible_engine::node_contract::RuntimeLimits>()
        + size_of::<Result<crucible_engine::node_contract::RuntimeLimits, RuntimeError>>()
        + size_of::<Option<&super::super::restoration::PacketCompleteFreshRestorationInputs>>()
        + size_of::<
            Result<&super::super::restoration::PacketCompleteFreshRestorationInputs, RuntimeError>,
        >()
        + size_of::<std::slice::Iter<'_, Cell<bool>>>()
        + size_of::<&Cell<bool>>()
        + size_of::<Ref<'_, Rc<PacketWorldHostSupervisor>>>()
        + size_of::<Result<Ref<'_, Rc<PacketWorldHostSupervisor>>, RuntimeError>>()
        + size_of::<&dyn crucible_engine::node_contract::RuntimeCustodySlot>()
        + size_of::<Option<&dyn crucible_engine::node_contract::RuntimeCustodySlot>>()
        + size_of::<Result<&dyn crucible_engine::node_contract::RuntimeCustodySlot, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
}
