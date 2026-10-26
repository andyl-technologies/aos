//! Counts original native read capacities while preserving separate live fences.
//!
//! This DATA roster retains each real shared view independently. It performs no
//! process, executable-byte or registrar-currentness query and issues no rights.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts, records::PacketRuntimeMetadataRecordBank,
};
use std::mem::size_of;

impl CnpSemanticSourceRead {
    /// Reports actual retained read-owner, registrar and executable capacities.
    ///
    /// The enclosing inline handle is caller-owned. Earlier physical rows remain
    /// intact and repeated views receive no alias discount. Revocation alone
    /// leaves storage observable; in-flight owner calls still refuse. These
    /// facts neither authenticate current custody nor count whole-Source work.
    ///
    /// # Errors
    /// Refuses foreign creator processes or threads before bank mutation, busy
    /// owner calls, opaque executable lease-worker backing, exhausted rows,
    /// unavailable physical backing or checked metadata overflow.
    pub fn retained_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.capacity_origin_data()?;
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        self.record_capacity_data(&mut census)?;
        Ok(census.finish())
    }

    /// Names compiled read, executable, SDK and census observation controls.
    pub fn retained_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + CnpRegistrarRead::capacity_counter_scratch_data()
            + OriginalExecutable::capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<(
                &u32,
                &Rc<ReadOwner>,
                &CnpRegistrarRead,
                &KernelIdentity,
                &Rc<OriginalExecutable>,
            )>()
            + size_of::<(&U64, &Cell<bool>, &Cell<bool>)>()
            + size_of::<(&mut OriginalOwnerCapacityMetadataData<'_>,)>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<bool>()
    }

    /// Appends this defining read roster to the enclosing Source census.
    ///
    /// # Errors
    /// Refuses creator or busy-owner changes, unsupported worker backing,
    /// exhausted rows and checked geometry or physical-bank failures.
    pub(in crate::node_adapters::cnp::semantic) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.capacity_origin_data()?;
        let Self {
            process,
            owner,
            registration,
            kernel,
            executable,
        } = self;
        census.observe_inline_data(process);
        census.observe_inline_data(kernel);
        census.observe_shared_allocation_data(owner)?;
        let ReadOwner {
            identity,
            current,
            busy,
        } = owner.as_ref();
        census.observe_inline_data(identity);
        census.observe_inline_data(&current.get());
        census.observe_inline_data(&busy.get());
        census.observe_registrar_read_data(registration)?;
        census.observe_shared_allocation_data(executable)?;
        executable.record_capacity_data(census)?;
        self.capacity_origin_data()
    }

    fn capacity_origin_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.executable.storage_origin_precredit_data()?;
        self.owner.storage_precredit_data()
    }
}
