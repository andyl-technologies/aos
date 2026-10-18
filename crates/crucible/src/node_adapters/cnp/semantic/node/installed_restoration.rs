//! Retains installed restoration custody beside its actual native resource owner.
//!
//! The Core-created association borrows the same retained Window at every use.
//! Historical inputs and operations never acquire fabricated generic Begin,
//! Input or response records. The original protocol histories remain independent.

use std::{mem::size_of, rc::Rc};

use crate::{
    node_contract::{
        ActivationRecord, NodeRoute, OperationAdmission, OperationFailure,
        OriginalInstalledRestorationNodeAssociation, OriginalLineageRestoration,
        OriginalLineageRuntimeRecord, RuntimeError, WorldActivation,
    },
    node_scheduling::{NativeInputAcknowledgement, RuntimeInputBatch},
};

#[path = "installed_restoration/activation.rs"]
mod activation;
#[path = "installed_restoration/correspondence.rs"]
mod correspondence;
#[path = "installed_restoration/observation.rs"]
mod observation;
#[path = "installed_restoration/outcome.rs"]
mod outcome;
pub(super) use outcome::{
    historical_outcome_correspondence17_counter_scratch_data,
    historical_outcome_correspondence17_data,
};
#[path = "installed_restoration/raw_storage.rs"]
mod raw_storage;
#[path = "installed_restoration/runtime_dispatch.rs"]
mod runtime_dispatch;
#[path = "installed_restoration/storage.rs"]
mod storage;

/// Stays in the native capsule, including after refusal, unwind or node Drop.
pub(in crate::node_adapters::cnp::semantic) struct InstalledRestorationCustody {
    association: OriginalInstalledRestorationNodeAssociation,
    install_started: bool,
    installed: bool,
    activation: Option<WorldActivation>,
    operations: Vec<OperationAdmission>,
    inputs: Vec<Rc<RuntimeInputBatch>>,
    commands: [Option<crucible_node_provider::reference_packet::service::complete_restore::activation::PacketRestorationActivationCommand>; 2],
    completed: [Option<crucible_node_provider::bodies::ResponseBody>; 2],
    world_manifest: Option<crucible_node_contract::ActivationManifest>,
    world_value: Option<serde_json::Value>,
    world_bytes: Option<Vec<u8>>,
    observation_attempted: bool,
    observation_completed: Option<crucible_node_provider::bodies::ResponseBody>,
    observation: Option<crate::node_scheduling::NativeSchedulingObservation>,
    observation_return: Option<crate::node_scheduling::NativeSchedulingObservation>,
    current_observations: Vec<current_observation::CurrentNodeObservation>,
    producer_executions: producer_execution::ProducerNodeHistory,
}

/// Counts new selected-node custody copies before the restoration transaction.
///
/// This DATA has no public constructor or decoding implementation. The genuine
/// Window binds it to its actual Source, controller and node before allocating
/// Prepare. It cannot issue a context, admit Arm or release a physical gate.
#[derive(Clone, Copy)]
pub struct OriginalInstalledRestorationCustodyConstructionData {
    copies: usize,
    scratch: usize,
    operations: usize,
    inputs: usize,
    requested: usize,
    activation: crucible_node_provider::reference_packet::service::complete_restore::activation::OriginalInstalledRestorationActivationConstructionData,
    observation: Option<crucible_node_provider::reference_packet::service::complete_restore::restoration_observe::OriginalInstalledRestorationObservationConstructionData>,
}

impl OriginalInstalledRestorationCustodyConstructionData {
    /// Borrows the independent complete Provider/SDK/native activation DATA row.
    ///
    /// Neither this row nor an association's copied DATA issues a phase claim.
    pub fn activation_construction_data(&self) -> &crucible_node_provider::reference_packet::service::complete_restore::activation::OriginalInstalledRestorationActivationConstructionData{
        &self.activation
    }

    /// Borrows separately quoted first-observation DATA for explicit mechanism5.
    ///
    /// Older activation-only declarations have no observation constructor row.
    pub fn observation_construction_data(&self) -> Option<&crucible_node_provider::reference_packet::service::complete_restore::restoration_observe::OriginalInstalledRestorationObservationConstructionData>{
        self.observation.as_ref()
    }

    /// Returns the independent copied custody and fixed observer demand.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Returns the independently precharged fixed counter and borrowed views.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
}

impl super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn has_installed_restoration_data(&self) -> bool {
        self.preparation
            .guard
            .custody
            .as_ref()
            .and_then(|native| native.runtime.as_ref())
            .is_some_and(|runtime| runtime.installed_restoration.is_some())
    }

    pub(in crate::node_adapters::cnp::semantic) fn admit_installed_restoration(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        if !context.is_original_installed_restoration_data() {
            return Err(super::super::refused(
                "complete original-lineage restoration admission is unsupported",
            ));
        }
        let native = self
            .preparation
            .guard
            .custody()
            .map_err(super::super::unknown)?;
        let runtime = native.runtime.as_ref().ok_or_else(|| {
            super::super::refused("installed restoration common custody is absent")
        })?;
        if runtime.installed_restoration.is_some() {
            return Err(super::super::refused(
                "installed restoration admission is spent",
            ));
        }
        runtime
            .dormant_storage_data()
            .map_err(super::super::refused_display)?;
        let source = native.source.as_ref().ok_or_else(|| {
            super::super::refused("installed restoration original Source is absent")
        })?;
        let controller = native.controller().ok_or_else(|| {
            super::super::refused("installed restoration original Controller is absent")
        })?;
        let association = context
            .retain_original_installed_node_association(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
            )
            .map_err(super::super::refused_display)?;
        // The actual association precedes every adoption callback. This is not
        // a borrowed context cached beyond its lifetime, nor a decoded proof.
        self.state_mut()?.installed_restoration = Some(InstalledRestorationCustody {
            association,
            install_started: false,
            installed: false,
            activation: None,
            operations: Vec::new(),
            inputs: Vec::new(),
            commands: [None, None],
            completed: [None, None],
            world_manifest: None,
            world_value: None,
            world_bytes: None,
            observation_attempted: false,
            observation_completed: None,
            observation: None,
            observation_return: None,
            current_observations: Vec::new(),
            producer_executions: producer_execution::ProducerNodeHistory::new(),
        });
        self.authenticate_installed_restoration_current_data()
    }

    pub(in crate::node_adapters::cnp::semantic) fn authenticate_installed_restoration_current_data(
        &self,
    ) -> Result<(), OperationFailure> {
        let native = self
            .preparation
            .guard
            .custody()
            .map_err(super::super::unknown)?;
        let Some(selected) = native
            .runtime
            .as_ref()
            .and_then(|state| state.installed_restoration.as_ref())
        else {
            return Ok(());
        };
        let source = native.source.as_ref().ok_or_else(|| {
            super::super::refused("installed restoration original Source is absent")
        })?;
        selected
            .association
            .with_original_node_custody_data(
                source.as_ref(),
                native.controller().ok_or_else(|| {
                    super::super::refused("installed restoration original Controller is absent")
                })?,
                Rc::as_ptr(&native.read_owner).cast(),
                |_, _, _| Ok(()),
            )
            .map_err(super::super::refused_display)
    }

    pub(crate) fn original_installed_restoration_custody_construction_data(
        &self,
        record: &OriginalLineageRuntimeRecord,
        target: &ActivationRecord,
        view: &crate::node_admission::OriginalRestorationSigningConstructionInputs<'_>,
        coordinator: &crate::node_admission::OriginalRestorationCoordinatorConstructionData,
        maximum: usize,
    ) -> Result<OriginalInstalledRestorationCustodyConstructionData, RuntimeError> {
        self.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let runtime = native
            .runtime
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        runtime.dormant_storage_data()?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native.controller().ok_or(RuntimeError::OwnerUnavailable)?;
        if Rc::as_ptr(source).cast::<()>() != Rc::as_ptr(view.source).cast::<()>()
            || !std::ptr::eq(controller, view.controller)
            || view.activation != target
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if record.schema_version != 7
            || target.world_binding_hash != record.source_activation.world_binding_hash
            || self.route.owners.is_empty()
            || !self
                .route
                .owners
                .iter()
                .all(|owner| target.owners.contains(owner))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (operations, inputs) = storage::counts(record, &self.route)?;
        let copies = storage::sum(&[
            storage::prospective_copies(record, target, &self.route, maximum)?,
            crate::node_contract::NodeRuntime::original_runtime_constructor_serialization_storage_data(self.preparation.binding(), maximum)?,
        ], maximum)?;
        let scratch = custody_counter_scratch_data()?;
        use crucible_node_provider::reference_packet::service::complete_restore::{
            activation::PacketRestorationActivationCoordinatorConstructionInputs,
            transfer::PacketCompleteRestoreSelectedOwnerInputs,
        };
        let content = view.archive.content();
        let owner = view.ticket.owner()?;
        let owner_inputs = PacketCompleteRestoreSelectedOwnerInputs {
            owner_state: content
                .get(&owner.state)
                .ok_or(RuntimeError::UnsupportedFacet)?,
            journal: content
                .get(view.journal_reference)
                .ok_or(RuntimeError::UnsupportedFacet)?,
            control: content
                .get(&view.journal.native_control)
                .ok_or(RuntimeError::UnsupportedFacet)?,
            anchor: content
                .get(&view.journal.native_anchor)
                .ok_or(RuntimeError::UnsupportedFacet)?,
            maximum_input_bytes: view.maximum_record_bytes,
            maximum_before_bytes: usize::try_from(
                view.launch
                    .capture_profile
                    .native_before_bytes(&view.launch.storage)
                    .get(),
            )
            .map_err(|_| RuntimeError::ResourceLimit)?,
            maximum_requested_bytes: maximum,
        };
        let coordinator_inputs = PacketRestorationActivationCoordinatorConstructionInputs {
            source_runtime: content
                .get(&view.journal.runtime)
                .ok_or(RuntimeError::UnsupportedFacet)?,
            maximum_encoded_bytes: coordinator.maximum_encoded_bytes_data(),
            retained_requested_bytes: coordinator.retained_requested_bytes_data(),
            maximum_simultaneous_transient_bytes: coordinator
                .maximum_simultaneous_transient_bytes_data(),
            declared_counter_scratch_bytes: coordinator.counter_scratch_bytes_data(),
        };
        let activation = controller
            .quote_original_installed_restoration_activation_construction_data(
                view.launch,
                &owner_inputs,
                &coordinator_inputs,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let observation = if view
            .source
            .is_original_restoration_observation_declaration_data()?
        {
            Some(
                controller
                    .quote_original_installed_restoration_observation_construction_data(
                        view.launch,
                        &owner_inputs,
                    )
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )
        } else {
            None
        };
        let observation_requested = match observation.as_ref() {
            Some(data) => data.requested_bytes_data(),
            None => 0, // Explicit older declaration has no observation route.
        };
        // Node-owned command/result/Ready copies and manifest construction are
        // additional independent owners, never the SDK/Core rows reassigned.
        let node_activation = storage::node_activation_copies(&activation, coordinator, maximum)?;
        let requested = storage::sum(
            &[
                copies,
                node_activation,
                scratch,
                activation.requested_bytes_data(),
                observation_requested,
            ],
            maximum,
        )?;
        self.preparation
            .guard
            .preparation_storage_origin_precredit_data()?;
        Ok(OriginalInstalledRestorationCustodyConstructionData {
            copies,
            scratch,
            operations,
            inputs,
            requested,
            activation,
            observation,
        })
    }
}

pub(super) fn custody_counter_scratch_data() -> Result<usize, RuntimeError> {
    storage::sum(
        &[
            storage::counter_scratch_data(),
            activation::counter_scratch_data(),
            observation::counter_scratch_data(),
            outcome::counter_scratch_data(),
            runtime_dispatch::counter_scratch_data(),
            current_observation::counter_scratch_data(),
            producer_execution::counter_scratch_data(),
            raw_storage::counter_scratch_data(),
            OriginalInstalledRestorationNodeAssociation::counter_scratch_data(),
            size_of::<OriginalInstalledRestorationCustodyConstructionData>(),
            size_of::<Result<OriginalInstalledRestorationCustodyConstructionData, RuntimeError>>(),
            size_of::<Option<&OriginalLineageRuntimeRecord>>(),
            size_of::<Option<&crate::node_contract::OriginalLineageInputRecord>>(),
            size_of::<Result<&crate::node_contract::OriginalLineageInputRecord, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Option<&WorldActivation>>(),
            size_of::<&NodeRoute>(),
            size_of::<&[OperationAdmission]>(),
            size_of::<&[Rc<RuntimeInputBatch>]>(),
            crate::node_contract::opaque_owner_counter_scratch_data(),
            crucible_node_provider::reference_packet::service::complete_restore::activation::original_installed_restoration_activation_construction_counter_scratch_data(),
            size_of::<crucible_node_provider::reference_packet::service::complete_restore::activation::PacketRestorationActivationCoordinatorConstructionInputs<'static>>(),
            size_of::<crucible_node_provider::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreSelectedOwnerInputs<'static>>(),
        ],
        usize::MAX,
    )
}

impl InstalledRestorationCustody {
    pub(in crate::node_adapters::cnp::semantic) fn input_content_dependencies(
        &self,
    ) -> impl Clone + Iterator<Item = &crucible_node_contract::ContentRef> {
        self.inputs
            .iter()
            .flat_map(|batch| batch.payloads().iter().map(|payload| &payload.reference))
    }

    pub(in crate::node_adapters::cnp::semantic) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut requested = storage::sum(
            &[
                raw_storage::phase_owners(self, maximum)?,
                self.association
                    .retained_requested_storage_precredit_data(maximum)?,
                storage::retained_aliases(&self.operations, &self.inputs, maximum)?,
            ],
            maximum,
        )?;
        if let Some(activation) = &self.activation {
            let facts = activation.retained_requested_storage_data(maximum)?;
            requested = storage::sum(&[requested, facts.independent_bytes()], maximum)?;
            for owner in facts.shared_allocations() {
                requested = storage::sum(&[requested, owner.requested_bytes()], maximum)?;
            }
        }
        Ok(requested)
    }
}

impl super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn install_installed_restoration(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
        activation: &WorldActivation,
        operations: &[OperationAdmission],
        inputs: &[Rc<RuntimeInputBatch>],
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or_else(|| super::super::refused("installed custody absent"))?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| super::super::refused("installed Source absent"))?;
        let controller = native
            .controller
            .as_ref()
            .ok_or_else(|| super::super::refused("installed Controller absent"))?;
        let runtime = native
            .runtime
            .as_mut()
            .ok_or_else(|| super::super::refused("installed common state absent"))?;
        let selected = runtime
            .installed_restoration
            .as_mut()
            .ok_or_else(|| super::super::refused("genuine installed context association absent"))?;
        if selected.install_started {
            return Err(super::super::refused("installed custody adoption is spent"));
        }
        let admitted = *selected
            .association
            .admitted_node_custody_data()
            .map_err(super::super::refused_display)?;
        if operations.len() != admitted.operations || inputs.len() != admitted.inputs {
            return Err(super::super::refused(
                "complete installed custody roster changed",
            ));
        }
        selected.install_started = true;
        selected.activation = Some(activation.clone());
        let InstalledRestorationCustody {
            association,
            operations: retained_operations,
            inputs: retained_inputs,
            installed,
            ..
        } = selected;
        association
            .with_original_node_custody_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                |record, scope, content| {
                    association.authenticate_context_data(context)?;
                    if activation.record() != &scope.target {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    retained_operations
                        .try_reserve_exact(operations.len())
                        .map_err(|_| RuntimeError::ResourceLimit)?;
                    retained_inputs
                        .try_reserve_exact(inputs.len())
                        .map_err(|_| RuntimeError::ResourceLimit)?;
                    for operation in operations {
                        // Retain the genuine local admission before fallible matching.
                        retained_operations.push(operation.clone());
                        correspondence::operation(&self.route, activation, operation, record)?;
                        if retained_operations[..retained_operations.len() - 1]
                            .iter()
                            .any(|old| old.token().operation() == operation.token().operation())
                        {
                            return Err(RuntimeError::InvalidReceipt);
                        }
                    }
                    for batch in inputs {
                        retained_inputs.push(Rc::clone(batch));
                        let saved = correspondence::input(
                            &self.route,
                            activation,
                            batch,
                            record,
                            scope,
                            content,
                        )?;
                        let fresh = scope
                            .input_acknowledgements
                            .iter()
                            .find(|ack| {
                                ack.node == *batch.node()
                                    && ack.stage_operation == *batch.stage_operation()
                            })
                            .ok_or(RuntimeError::InvalidReceipt)?;
                        correspondence::acknowledgement(batch, saved, scope, fresh)?;
                        if retained_inputs[..retained_inputs.len() - 1]
                            .iter()
                            .any(|old| old.stage_operation() == batch.stage_operation())
                        {
                            return Err(RuntimeError::InvalidReceipt);
                        }
                    }
                    *installed = true;
                    Ok(())
                },
            )
            .map_err(super::super::refused_display)?;
        self.current()
    }

    pub(in crate::node_adapters::cnp::semantic) fn validate_installed_restoration_ack(
        &self,
        batch: &RuntimeInputBatch,
        acknowledgement: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        let native = self
            .preparation
            .guard
            .custody()
            .map_err(super::super::unknown)?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| super::super::refused("installed Source absent"))?;
        let controller = native
            .controller()
            .ok_or_else(|| super::super::refused("installed Controller absent"))?;
        let selected = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or_else(|| super::super::refused("installed association absent"))?;
        let activation = selected
            .activation
            .as_ref()
            .ok_or_else(|| super::super::refused("installed activation absent"))?;
        if !selected.installed
            || !selected
                .inputs
                .iter()
                .any(|original| std::ptr::eq(original.as_ref(), batch))
        {
            return Err(super::super::refused(
                "input batch is not actual retained installed custody",
            ));
        }
        selected
            .association
            .with_original_node_custody_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                |record, scope, content| {
                    let saved = correspondence::input(
                        &self.route,
                        activation,
                        batch,
                        record,
                        scope,
                        content,
                    )?;
                    correspondence::acknowledgement(batch, saved, scope, acknowledgement)
                },
            )
            .map_err(super::super::refused_display)
    }
}

#[path = "installed_restoration/current_observation.rs"]
mod current_observation;

#[path = "installed_restoration/producer_execution.rs"]
mod producer_execution;

pub(crate) use producer_execution::OriginalRestoredSettledNodeHistoryView;

pub(crate) use producer_execution::original_restored_settled_semantic_history_counter_scratch_data;
