//! Seals the Host arm of the same physical engine to its actual owning role.
//!
//! Broker and online floor facades have no Host constructor. Their empty slot
//! makes that invariant structural without transferring a Host startup borrow.

use super::RetainedHostPhysicalBindingV1;

mod sealed {
    pub trait Sealed {}
}

/// Borrows only the genuine binding from one of two sealed representations.
pub(in crate::tpm_nv_custody) trait PhysicalHostSlotV1<'owner, 'origin, 'startup>:
    sealed::Sealed
{
    fn host_ref_v1(&self) -> &RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup>;

    fn host_mut_v1(&mut self) -> &mut RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup>;
}

impl sealed::Sealed for RetainedHostPhysicalBindingV1<'_, '_, '_> {}

impl<'owner, 'origin, 'startup> PhysicalHostSlotV1<'owner, 'origin, 'startup>
    for RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup>
{
    fn host_ref_v1(&self) -> &RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup> {
        self
    }

    fn host_mut_v1(&mut self) -> &mut RetainedHostPhysicalBindingV1<'owner, 'origin, 'startup> {
        self
    }
}

/// Has no value and cannot admit a Host binding into a Broker owner.
pub(crate) enum BrokerOnlyHostPhysicalSlotV1 {}

impl sealed::Sealed for BrokerOnlyHostPhysicalSlotV1 {}

impl PhysicalHostSlotV1<'static, 'static, 'static> for BrokerOnlyHostPhysicalSlotV1 {
    fn host_ref_v1(&self) -> &RetainedHostPhysicalBindingV1<'static, 'static, 'static> {
        match *self {}
    }

    fn host_mut_v1(&mut self) -> &mut RetainedHostPhysicalBindingV1<'static, 'static, 'static> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn actual_broker_physical_owner_can_cross_the_controller_worker_boundary() {
        fn requires_send<T: Send>() {}

        requires_send::<super::super::RetainedBrokerPhysicalTpmOwnerV1>();
        requires_send::<crate::handshake::RetainedStorageColdOpenV1>();
    }
}
