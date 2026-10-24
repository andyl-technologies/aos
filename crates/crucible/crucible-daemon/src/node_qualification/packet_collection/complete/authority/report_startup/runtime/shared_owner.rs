//! Moves the same concrete linear input into one shared allocation after admission.

use super::*;
use std::cell::{Ref, RefMut};

struct OriginalOwnerSlots<T> {
    original: Option<T>,
    shared: Option<Rc<T>>,
}

pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) struct OriginalSharedOwner<
    T,
>(RefCell<OriginalOwnerSlots<T>>);

impl<T> OriginalSharedOwner<T> {
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn new(
        original: T,
    ) -> Self {
        Self(RefCell::new(OriginalOwnerSlots {
            original: Some(original),
            shared: None,
        }))
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_data(
        &self,
    ) -> Result<Ref<'_, T>, RuntimeError> {
        let slots = self.0.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        Ref::filter_map(slots, |slots| match (&slots.original, &slots.shared) {
            (Some(original), None) => Some(original),
            (None, Some(shared)) => Some(shared.as_ref()),
            _ => None,
        })
        .map_err(|_| RuntimeError::OutstandingObligations)
    }

    pub(super) fn shared_data(&self) -> Result<Ref<'_, Rc<T>>, RuntimeError> {
        let slots = self.0.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        Ref::filter_map(slots, |slots| {
            if slots.original.is_none() {
                slots.shared.as_ref()
            } else {
                None
            }
        })
        .map_err(|_| RuntimeError::OwnerUnavailable)
    }

    pub(super) fn share_original(
        &self,
        member: &CompleteOriginalRuntimeConstructionMember,
    ) -> Result<(), RuntimeError> {
        // The private InputOwners caller authenticates and retains this exact
        // opaque Core member before entering either actual Rc constructor.
        let _retained_member = member;
        let mut slots = self
            .0
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if slots.shared.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        let original = slots
            .original
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        slots.shared = Some(Rc::new(original));
        Ok(())
    }

    pub(super) fn charge_shared_root(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        let slots = self.0.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let OriginalOwnerSlots { original, shared } = &*slots;
        match (original, shared) {
            (Some(_), None) => Ok(()),
            (None, Some(shared)) => {
                counter.rc(shared).map_err(storage_error)?;
                Ok(())
            }
            _ => Err(RuntimeError::OutstandingObligations),
        }
    }

    pub(super) fn counter_scratch_data() -> usize {
        std::mem::size_of::<Ref<'_, OriginalOwnerSlots<T>>>()
            + std::mem::size_of::<RefMut<'_, OriginalOwnerSlots<T>>>()
            + std::mem::size_of::<Ref<'_, T>>()
            + std::mem::size_of::<Ref<'_, Rc<T>>>()
            + std::mem::size_of::<Result<Ref<'_, OriginalOwnerSlots<T>>, std::cell::BorrowError>>()
            + std::mem::size_of::<Result<Ref<'_, OriginalOwnerSlots<T>>, RuntimeError>>()
            + std::mem::size_of::<Result<Ref<'_, T>, Ref<'_, OriginalOwnerSlots<T>>>>()
            + std::mem::size_of::<Result<Ref<'_, T>, RuntimeError>>()
            + std::mem::size_of::<Result<Ref<'_, Rc<T>>, Ref<'_, OriginalOwnerSlots<T>>>>()
            + std::mem::size_of::<Result<Ref<'_, Rc<T>>, RuntimeError>>()
    }
}

/// Retains the exact original complete supervisor without allocating a new owner.
///
/// The actual scene action later moves this owner into an Rc and keeps the same
/// queue, wake descriptors, mailbox and previously reserved runtime slot.
pub struct PacketCompleteOriginalSceneSupervisor(OriginalSharedOwner<PacketWorldHostSupervisor>);
impl From<PacketWorldHostSupervisor> for PacketCompleteOriginalSceneSupervisor {
    fn from(original: PacketWorldHostSupervisor) -> Self {
        Self(OriginalSharedOwner::new(original))
    }
}

impl PacketCompleteOriginalSceneSupervisor {
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_data(
        &self,
    ) -> Result<Ref<'_, PacketWorldHostSupervisor>, RuntimeError> {
        self.0.original_data()
    }

    pub(super) fn shared_data(
        &self,
    ) -> Result<Ref<'_, Rc<PacketWorldHostSupervisor>>, RuntimeError> {
        self.0.shared_data()
    }

    pub(super) fn share_original(
        &self,
        member: &CompleteOriginalRuntimeConstructionMember,
    ) -> Result<(), RuntimeError> {
        self.0.share_original(member)
    }

    pub(super) fn charge_shared_root(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        self.0.charge_shared_root(counter)
    }
}
