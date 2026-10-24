//! Observes every actual inactive owner after its original phase moves.

use super::*;
use crucible_engine::{
    node_adapters::cnp::{CnpPreparationStorageScratch, PacketCompleteSemanticSource},
    node_contract::{NodeRuntime, SimulationNode},
};
use std::mem::{size_of, size_of_val};

pub(super) fn counter_scratch_data() -> Result<usize, RuntimeError> {
    let terms=[InstalledConformancePlan::original_runtime_construction_counter_scratch_data()?,
        super::content_limits::counter_scratch_data(),
        super::super::super::super::execution::schedule::bootstrap_counter_scratch_data(),
        super::family::counter_scratch_data(),
        super::inactive::counter_scratch_data(),
        super::fresh::counter_scratch_data()?,
        ConformanceRuntime::original_fixed_four_inactive_observer_counter_scratch_data()?,
        super::super::super::super::construction_diagnostics::Scope::requested_bytes(),
        // Fixed observer work: actual selected producer Bytes base64 bank,
        // one U64 decimal String, ryu formatter and stable-sort local workspace.
        44+20+132+4096+66*size_of::<(usize,usize)>(),
        3*PacketCompleteSemanticSource::original_collecting_validation_counter_scratch_data(),
        crucible_engine::node_adapters::cnp::CnpSemanticLaunchGuard::original_initial_lifecycle_storage_counter_scratch_data(),

        size_of::<Counter>(),size_of::<Counter>(),
        size_of::<std::cell::Ref<'_,OriginalRuntimeOwners>>(),
        size_of::<std::cell::RefMut<'_,OriginalRuntimeOwners>>(),
        size_of::<[&PacketCompleteOriginalHostSdk;3]>(),size_of::<[(usize,usize,usize);4]>(),
        OriginalSharedOwner::<PacketCompleteEffectReceiverReader>::counter_scratch_data(),
        OriginalSharedOwner::<PacketWorldHostSupervisor>::counter_scratch_data(),
        CnpPreparationStorageScratch::requested_bytes(),
        crucible_engine::node_admission::ConformanceGraph::original_fixed_four_construction_counter_scratch_data(),
        crucible_engine::node_adapters::cnp::CnpSemanticPreparation::original_conformance_node_construction_counter_scratch_data(),
        crucible_engine::node_contract::HostSchedulingSource::original_collection_node_construction_counter_scratch_data(),
        NodeRuntime::original_fixed_four_construction_counter_scratch_data(),
        CnpSemanticExactConformanceWorldProvider::original_construction_counter_scratch_data()?,
        InstalledConformancePlan::original_runtime_constructor_data_counter_scratch_data(),
        PacketCompleteNativeOracle::original_shared_construction_counter_scratch_data()?,
        PacketCompleteNativeOracle::original_initial_journal_counter_scratch_data()?,
        super::super::preparation::PreparationOwners::original_native_oracle_observation_counter_scratch_data(),
        3 * PacketCompleteSemanticSource::original_native_oracle_observation_counter_scratch_data(),
        3 * crucible_engine::node_adapters::cnp::CnpSemanticPreparation::original_native_oracle_preparation_counter_scratch_data(),
        PacketCompleteExecutionScene::original_construction_counter_scratch_data()?,
        PacketCompleteExecutionActor::original_construction_counter_scratch_data()?,
        super::initial_preparation::counter_scratch_data()?];
    terms
        .into_iter()
        .try_fold(0usize, |a, b| add(a, b, usize::MAX))
}

impl PacketCompleteReportStartupHolder {
    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn charge_original_runtime_storage_data(
        &self,
        c: &mut Counter,
    ) -> Result<(), RuntimeError> {
        self.receiver_reader.charge_shared_root(c)?;
        if let Some(scene) = self.original_scene.get() {
            scene
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .inputs
                .supervisor
                .charge_shared_root(c)?;
        }
        if let Some(fresh) = self.fresh_lifecycle.get() {
            if let Some(inputs) = &fresh
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .inputs
            {
                inputs.supervisor.charge_shared_root(c)?;
            }
        }
        let owners = self
            .runtime_owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        // An arbitrary unwind or unobserved failed constructor cannot be called
        // empty. Originals remain held for containment and terminal fit refuses.
        if owners.provider_failure.is_some()
            || owners.preparation_failure.is_some()
            || owners.attachment_failure.is_some()
            || owners.node_failures.iter().any(Option::is_some)
            || owners.unwinds.iter().any(Option::is_some)
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        for program in owners.programmes.iter().flatten() {
            c.charge(program).map_err(storage_error)?;
        }
        for path in owners.paths.iter().flatten() {
            c.charge(path).map_err(storage_error)?;
        }
        if let Some(schedule) = &owners.schedule {
            c.charge(schedule).map_err(storage_error)?;
        }
        if let Some(requirements) = &owners.requirements {
            c.charge(requirements).map_err(storage_error)?;
        }
        c.charge(&owners.descriptors).map_err(storage_error)?;
        c.charge(&owners.bindings).map_err(storage_error)?;
        c.charge(&owners.owners).map_err(storage_error)?;
        if let Some(oracle) = &owners.oracle {
            if c.rc(oracle).map_err(storage_error)? {
                if matches!(&self.purpose, StartupHolderPurpose::OriginalScene) {
                    oracle.charge_original_initial_construction_data(c)?;
                } else {
                    oracle.charge_dormant_original_construction_data(c)?;
                }
            }
        }
        if let Some(scene) = &owners.scene {
            c.rc(scene).map_err(storage_error)?;
        }
        if let Some(factory) = &owners.factory {
            c.rc(factory).map_err(storage_error)?;
        }
        if let Some(actor) = &owners.actor {
            c.add(
                actor.retained_runtime_construction_storage_precredit_data(
                    matches!(&self.purpose, StartupHolderPurpose::OriginalScene)
                        .then_some(&self.authority.roster.sources),
                    c.remaining(),
                )?,
            )
            .map_err(storage_error)?;
        }
        if let Some(graph) = &owners.graph {
            c.add(graph.original_retained_storage_precredit_data(c.remaining())?)
                .map_err(storage_error)?;
        }
        let scratch =
            CnpPreparationStorageScratch::new(CnpPreparationStorageScratch::requested_bytes())?;
        for node in owners
            .nodes
            .iter()
            .flatten()
            .chain(owners.node_vector.iter())
        {
            c.add(
                if matches!(&self.purpose, StartupHolderPurpose::OriginalScene) {
                    let source = self
                        .authority
                        .roster
                        .sources
                        .iter()
                        .find(|source| {
                            source.installation().descriptor.id
                                == node.original_conformance_route_data().node
                        })
                        .ok_or(RuntimeError::ForeignAuthority)?;
                    node.retained_original_initial_requested_storage_precredit_data(
                        source,
                        &scratch,
                        c.remaining(),
                    )?
                    .complete_requested_bytes_precredit_data()?
                } else {
                    node.retained_requested_storage_precredit_data(
                        &scratch,
                        None,
                        None,
                        c.remaining(),
                    )?
                    .complete_requested_bytes_precredit_data()?
                },
            )
            .map_err(storage_error)?;
        }
        c.add(
            owners
                .node_vector
                .capacity()
                .checked_mul(size_of::<CnpSemanticConformanceNode>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )
        .map_err(storage_error)?;
        c.add(
            owners
                .native
                .capacity()
                .checked_mul(size_of::<Box<dyn SimulationNode>>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )
        .map_err(storage_error)?;
        for node in &owners.native {
            c.add(size_of_val(node.as_ref())).map_err(storage_error)?;
            c.add(
                node.retained_requested_storage_precredit_data(c.remaining())?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )
            .map_err(storage_error)?;
        }
        if let Some(host) = &owners.host {
            c.add(
                host.retained_requested_storage_precredit_data(c.remaining())?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )
            .map_err(storage_error)?;
        }
        if let Some(provider) = &owners.provider {
            let bytes = if matches!(&self.purpose, StartupHolderPurpose::OriginalScene) {
                provider.retained_original_initial_requested_storage_precredit_data(
                    &self.authority.roster.sources,
                    c.remaining(),
                )?
            } else {
                provider.original_retained_storage_precredit_data(c.remaining())?
            };
            c.add(bytes).map_err(storage_error)?;
        }
        if let Some(runtime) = &owners.runtime {
            let bytes = if matches!(&self.purpose, StartupHolderPurpose::OriginalScene) {
                runtime.retained_original_initial_requested_storage_precredit_data(
                    &self.authority.roster.sources,
                    c.remaining(),
                )?
            } else {
                runtime.original_inactive_retained_storage_precredit_data(c.remaining())?
            };
            c.add(bytes).map_err(storage_error)?;
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::authority::report_startup) fn original_runtime_descriptor_views_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let owners = self
            .runtime_owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if owners.provider_failure.is_some()
            || owners.preparation_failure.is_some()
            || owners.attachment_failure.is_some()
            || owners.unwinds.iter().any(Option::is_some)
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut total = 0usize;
        for node in owners
            .nodes
            .iter()
            .flatten()
            .chain(owners.node_vector.iter())
        {
            total = add(
                total,
                node.retained_descriptor_views_precredit_data()?,
                usize::MAX,
            )?;
        }
        for node in &owners.native {
            total = add(
                total,
                node.retained_descriptor_views_precredit_data()?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
                usize::MAX,
            )?;
        }
        if let Some(provider) = &owners.provider {
            total = add(
                total,
                provider.original_retained_descriptor_views_precredit_data()?,
                usize::MAX,
            )?;
        }
        if let Some(runtime) = &owners.runtime {
            total = add(
                total,
                runtime.original_inactive_descriptor_views_precredit_data()?,
                usize::MAX,
            )?;
        }
        if let Some(actor) = &owners.actor {
            total = add(
                total,
                actor.original_inactive_descriptor_views_precredit_data()?,
                usize::MAX,
            )?;
        }
        Ok(total)
    }
}
