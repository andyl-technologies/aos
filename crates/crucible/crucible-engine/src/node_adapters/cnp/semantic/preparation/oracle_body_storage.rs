//! Quotes actual Controller body construction before the preparation is moved.

use super::super::CnpSemanticSource;
use super::CnpSemanticPreparation;
use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_contract::RuntimeError;
use std::{mem::size_of, rc::Rc};

impl CnpSemanticPreparation {
    /// Quotes original Oracle body ownership from this preparation's Controller.
    ///
    /// Only creator and exact installed Source allocation are checked here. The
    /// actual witness consumer independently repeats its live currentness and
    /// semantic guards; these layout facts grant no graph or native permission.
    /// Schema/semantic validator allocations remain a separate caller window.
    ///
    /// # Errors
    /// Refuses foreign creator/Source, missing actual custody or Controller,
    /// malformed candidate framing, arithmetic overflow or the supplied bound.
    pub fn original_native_oracle_observation_construction_storage_data(
        &self,
        source: &Rc<PacketCompleteSemanticSource>,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.guard.preparation_storage_origin_precredit_data()?;
        let native = self
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let installed = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !std::ptr::eq(
            Rc::as_ptr(installed).cast::<()>(),
            Rc::as_ptr(source).cast::<()>(),
        ) || !std::ptr::eq(installed.installation(), source.installation())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let (retained, transient, source_scratch) = source
            .original_native_oracle_observation_construction_storage_data(controller, maximum)?;
        let scratch = source_scratch
            .checked_add(Self::original_native_oracle_preparation_counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        retained
            .checked_add(transient)
            .and_then(|n| n.checked_add(scratch))
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.guard.preparation_storage_origin_precredit_data()?;
        Ok((retained, transient, scratch))
    }

    /// Names actual origin, custody, Source, Controller and row-result views.
    pub fn original_native_oracle_preparation_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&Rc<PacketCompleteSemanticSource>>()
            + size_of::<&super::super::process::CnpSemanticProcessCustody>()
            + size_of::<&crucible_node_transport::client::CnpController>()
            + size_of::<&Rc<dyn CnpSemanticSource>>()
            + size_of::<Option<&Rc<dyn CnpSemanticSource>>>()
            + size_of::<Result<&Rc<dyn CnpSemanticSource>, RuntimeError>>()
            + size_of::<Option<&super::super::process::CnpSemanticProcessCustody>>()
            + size_of::<Result<&super::super::process::CnpSemanticProcessCustody, RuntimeError>>()
            + size_of::<Option<&crucible_node_transport::client::CnpController>>()
            + size_of::<Result<&crucible_node_transport::client::CnpController, RuntimeError>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }
}
