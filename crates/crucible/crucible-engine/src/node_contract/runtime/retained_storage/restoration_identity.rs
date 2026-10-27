//! Checks the actual inactive runtime scheduler while its node loan is mutable.
//!
//! No cloned world, replacement scheduler, live runtime reference or arbitrary
//! callback is retained. These two weak original identities are DATA. Only the
//! separate installed whole restoration window may turn a successful resource
//! observation into its private phase claim; this owner issues no final context.

use super::super::scheduling_state::OriginalRestorationSchedulingFence;
use super::*;
use crucible_node_format::HashRef;

pub(crate) struct OriginalRestorationRuntimeMemberIdentity {
    runtime: OriginalRuntimeStorageIdentity,
    scheduler: OriginalRestorationSchedulingFence,
}

impl NodeRuntime {
    pub(crate) fn original_restoration_live_member_identity_data(
        &self,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<OriginalRestorationRuntimeMemberIdentity, RuntimeError> {
        self.authenticate_original_restoration_target_data(archive, plan, activation)?;
        let identity = OriginalRestorationRuntimeMemberIdentity {
            runtime: self.original_retained_storage_identity()?,
            scheduler: self
                .scheduler
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .restoration_member_fence_data(&self.authority, &activation.world_binding_hash)?,
        };
        identity.authenticate_current(&activation.world_binding_hash)?;
        self.authenticate_original_restoration_target_data(archive, plan, activation)?;
        Ok(identity)
    }
}

impl OriginalRestorationRuntimeMemberIdentity {
    pub(crate) fn authenticate_world_activation_data(
        &self,
        world: &crate::node_contract::WorldActivation,
        expected: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        if world.record() != expected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let authority = self
            .runtime
            .authority
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !std::rc::Rc::ptr_eq(&authority, &world.authority) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_current(&expected.world_binding_hash)
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &NodeRuntime,
        world: &HashRef,
    ) -> Result<(), RuntimeError> {
        self.runtime.authenticate(runtime)?;
        self.authenticate_current(world)
    }

    pub(crate) fn authenticate_current(&self, world: &HashRef) -> Result<(), RuntimeError> {
        if self.runtime.process != std::process::id()
            || self.runtime.thread != std::thread::current().id()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let authority = self
            .runtime
            .authority
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.scheduler.authenticate_current(&authority, world)
    }

    pub(crate) fn authenticate_original_transaction_member_data(
        &self,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        original: &OriginalRuntimeStorageIdentity,
        world: &HashRef,
    ) -> Result<(), RuntimeError> {
        if self.runtime.process != original.process
            || self.runtime.thread != original.thread
            || !std::rc::Weak::ptr_eq(&self.runtime.authority, &original.authority)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        {
            let authority = self
                .runtime
                .authority
                .upgrade()
                .ok_or(RuntimeError::ForeignAuthority)?;
            ticket.authenticate_original_restoration_transaction_data(&authority)?;
        }
        // The temporary strong view above is gone. The final real scheduler
        // check remains valid while the runtime/node and Source banks are lent.
        self.authenticate_current(world)
    }

    pub(crate) fn retained_backing_storage_data(
        &self,
        world: &HashRef,
    ) -> Result<usize, RuntimeError> {
        self.authenticate_current(world)?;
        let bytes = NodeRuntime::capture_shared_allocation_storage::<()>()
            .checked_add(self.scheduler.retained_backing_storage_data()?)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.authenticate_current(world)?;
        Ok(bytes)
    }

    pub(crate) fn counter_scratch_data() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<std::rc::Rc<()>>()
            + std::mem::size_of::<Option<std::rc::Rc<()>>>()
            + std::mem::size_of::<Result<std::rc::Rc<()>, RuntimeError>>()
            + OriginalRestorationSchedulingFence::counter_scratch_data()
            + std::mem::size_of::<Result<Self, RuntimeError>>()
            + std::mem::size_of::<Result<usize, RuntimeError>>()
            + std::mem::size_of::<std::cell::Ref<'static, Option<std::rc::Rc<()>>>>()
            + std::mem::size_of::<Option<[bool; 4]>>()
            + std::mem::size_of::<Result<(), RuntimeError>>()
    }
}
