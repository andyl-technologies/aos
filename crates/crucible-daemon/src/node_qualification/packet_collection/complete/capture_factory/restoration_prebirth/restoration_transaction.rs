//! Lends the actual inactive restoration capsule to its installed transaction.
//!
//! Tickets, source, runtime and partials remain in the registered capsule until
//! the admitted fixed group takes the originals. No mutable runtime, controller
//! or preparation extractor is exposed to the caller.

use super::*;
use crucible::node_adapters::cnp::{PacketCompleteOriginalHostSdk, PacketCompleteSemanticSource};
use crucible::node_admission::{
    CompleteOriginalRestorationWindow, OriginalRestorationConstructionInputs,
};
use crucible::node_contract::{ActivationRecord, RuntimeError};
use crucible_node_contract::Id;
use crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch;

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn original_restoration_construction_inputs_data<
        'a,
    >(
        &'a self,
        runtime: &'a ConformanceRuntime,
        sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
        sdks: [&'a PacketCompleteOriginalHostSdk; 3],
        launches: &'a [PacketNative5SourceLaunch; 3],
        encoded_launches: [&'a [u8]; 3],
        plan: &'a InstalledConformancePlan,
        activation: &'a ActivationRecord,
        prepare_ids: &'a [Id; 3],
        commit_ids: &'a [Id; 3],
    ) -> Result<OriginalRestorationConstructionInputs<'a>, RuntimeError> {
        self.authenticate_runtime_owner_data(runtime)?;
        let archive = self
            .source
            .original_restoration_source_data(runtime, plan, activation)?;
        self.authenticate_restoration_target_storage_data(archive, runtime, plan, activation)?;
        let tickets = [
            self.native[0]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            self.native[1]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            self.native[2]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        ];
        let journals = [
            tickets[0].original_restoration_journal_reference_data()?,
            tickets[1].original_restoration_journal_reference_data()?,
            tickets[2].original_restoration_journal_reference_data()?,
        ];
        Ok(OriginalRestorationConstructionInputs {
            sources,
            sdks,
            launches,
            encoded_launches,
            tickets,
            selected: 0,
            prepare_ids,
            commit_ids,
            source: &sources[0],
            launch: &launches[0],
            encoded_launch: encoded_launches[0],
            archive,
            ticket: tickets[0],
            runtime: runtime.observation_data(),
            activation,
            journals,
            journal: journals[0],
            prepare_id: &prepare_ids[0],
            commit_id: &commit_ids[0],
        })
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retain_original_restoration_group(
        &mut self,
        window: &CompleteOriginalRestorationWindow,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
        prepare_ids: &mut Option<[Id; 3]>,
        commit_ids: &mut Option<[Id; 3]>,
    ) -> Result<(), RuntimeError> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        window.retain_original_transaction_group(
            plan,
            &runtime,
            activation,
            &mut self.native,
            prepare_ids,
            commit_ids,
        )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn bind_original_restoration_targets(
        &mut self,
        window: &CompleteOriginalRestorationWindow,
        plan: &InstalledConformancePlan,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .get_mut();
        for (selected, source) in sources.iter().enumerate() {
            window.bind_original_transaction_target(plan, source, runtime, activation, selected)?;
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn execute_original_restoration_prepare(
        &mut self,
        window: &CompleteOriginalRestorationWindow,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        window.execute_original_prepare_phase(plan, self.runtime_mut_data()?, activation)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn execute_original_restoration_inputs(
        &mut self,
        window: &CompleteOriginalRestorationWindow,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        window.execute_original_inputs_phase(plan, self.runtime_mut_data()?, activation)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn execute_original_restoration_commit(
        &mut self,
        window: &CompleteOriginalRestorationWindow,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        window.execute_original_commit_phase(plan, self.runtime_mut_data()?, activation)
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn recheck_original_restoration_inputs_data(
        &self,
        window: &CompleteOriginalRestorationWindow,
        plan: &InstalledConformancePlan,
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        encoded_launches: [&[u8]; 3],
        activation: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        window.recheck_original_transaction_inputs_data(
            plan,
            sdks,
            launches,
            encoded_launches,
            &*self.runtime_data()?,
            activation,
        )
    }
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn inspect_original_restoration_native_continuations(
        &self,
        window: &CompleteOriginalRestorationWindow,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        window.inspect_original_native_continuations(plan, &*self.runtime_data()?, activation)
    }
}
