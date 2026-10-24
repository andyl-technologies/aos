//! Separates the actual Runtime loan from the capsule's retained owner bank.
//!
//! A selected operation may hold the inner mutable Runtime while its genuine
//! Core whole-observation scope reborrows the outer capsule. That scope must
//! lend the identical Runtime address; a busy bank alone never authenticates it.

use super::*;
use crucible_engine::node_contract::RuntimeError;
use std::cell::{BorrowError, BorrowMutError, Ref, RefMut};
use std::mem::size_of;

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn runtime_data(
        &self,
    ) -> Result<Ref<'_, ConformanceRuntime>, RuntimeError> {
        self.runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn runtime_mut_loan_data(
        &self,
    ) -> Result<RefMut<'_, ConformanceRuntime>, RuntimeError> {
        self.runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn runtime_mut_data(
        &mut self,
    ) -> Result<&mut ConformanceRuntime, RuntimeError> {
        Ok(self
            .runtime
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .get_mut())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_runtime_owner_data(
        &self,
        runtime: &ConformanceRuntime,
    ) -> Result<(), RuntimeError> {
        let owner = self
            .runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !std::ptr::eq(owner.as_ptr().cast_const(), runtime) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn runtime_owner_counter_scratch_data()
    -> usize {
        size_of::<RefCell<ConformanceRuntime>>()
            + size_of::<&RefCell<ConformanceRuntime>>()
            + size_of::<Option<&RefCell<ConformanceRuntime>>>()
            + size_of::<&mut RefCell<ConformanceRuntime>>()
            + size_of::<Option<&mut RefCell<ConformanceRuntime>>>()
            + size_of::<Result<&mut RefCell<ConformanceRuntime>, RuntimeError>>()
            + size_of::<*const ConformanceRuntime>()
            + size_of::<*mut ConformanceRuntime>()
            + size_of::<Result<&RefCell<ConformanceRuntime>, RuntimeError>>()
            + size_of::<Ref<'static, ConformanceRuntime>>()
            + size_of::<RefMut<'static, ConformanceRuntime>>()
            + size_of::<Result<Ref<'static, ConformanceRuntime>, BorrowError>>()
            + size_of::<Result<RefMut<'static, ConformanceRuntime>, BorrowMutError>>()
            + size_of::<Result<Ref<'static, ConformanceRuntime>, RuntimeError>>()
            + size_of::<Result<RefMut<'static, ConformanceRuntime>, RuntimeError>>()
            + size_of::<&ConformanceRuntime>()
            + size_of::<&mut ConformanceRuntime>()
            + size_of::<Result<&mut ConformanceRuntime, RuntimeError>>()
            + size_of::<Result<Ref<'static, ConformanceRuntime>, StateError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
