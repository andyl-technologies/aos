//! Resolves original declaration roles through the signed parent's provenance.
//!
//! Caps come from the actual original qualification contracts body. The paired
//! descriptor/fixture roles bind tuple position to the exact archived raw5 node.
//! No fresh installation, Runtime resource request or per-Boot allowance replaces
//! the four original semantic ceilings.

use super::*;
use crate::node_state::{
    RestoredArchive17Initial15Work as TerminalWork, RestoredArchive17Initial15Role as TerminalRole,
    RestoredArchive17Initial15QualificationRole as QualificationRole,
};

use crucible_node_contract::{CaptureManifest, Repeatability, Validate};
use crucible_node_provider::protocol_snapshot::borrowed_json::BorrowedJsonFields as Fields;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Initial15Coordinator {
    pub(super) schema_version: u16,
    pub(super) runtime: ContentRef,
    pub(super) scheduler: ContentRef,
    pub(super) world_repeatability: Repeatability,
}

impl OriginalInitial15ArchivedGroup {
    pub(super) fn read_declarations_data(
        &mut self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        terminal: Option<&Initial15Terminal17<'_, '_>>,
    ) -> Result<(), OperationFailure> {
        let manifest = scope.manifest_data().map_err(unknown)?;
        self.parse_role_data(scope, &manifest.provenance_ref, 0, additional, terminal, 0)?;
        let provenance = self.values[0]
            .as_ref()
            .ok_or_else(|| refused("initial15 provenance absent"))?;
        let object = provenance
            .as_object()
            .ok_or_else(|| refused("initial15 provenance is not an object"))?;
        if object.len() != 6
            || object.get("schema_version").and_then(Value::as_u64) != Some(1)
            || !object.contains_key("source_activation")
            || !object.contains_key("cut")
            || !object.contains_key("ordinal")
        {
            return Err(refused("initial15 original provenance grammar differs"));
        }
        let archive = object
            .get("native_archive")
            .and_then(Value::as_object)
            .ok_or_else(|| refused("initial15 native archive role absent"))?;
        if archive.len() != 3
            || archive.get("schema_version").and_then(Value::as_u64) != Some(3)
            || archive.get("content_inventory").and_then(Value::as_u64) != Some(2)
            || !reference_matches_data(
                archive
                    .get("original_capture_journal")
                    .ok_or_else(|| refused("initial15 administrative role absent"))?,
                scope
                    .original_capture_journal_reference_data()
                    .map_err(unknown)?,
            )?
        {
            return Err(refused("initial15 native archive provenance differs"));
        }
        let collecting = object
            .get("collecting_capture")
            .ok_or_else(|| refused("initial15 collecting original scope absent"))?;
        self.begin_typed_terminal_data(
            terminal,
            TerminalWork::RoleTyped(TerminalRole::Provenance),
            collecting,
        )?;
        self.admit_typed_data(scope, additional, collecting)?;
        self.collecting = Some(
            crate::node_state::CollectingCompleteCaptureProvenance::deserialize(collecting)
                .map_err(unknown)?,
        );
        let collecting = self
            .collecting
            .as_ref()
            .ok_or_else(|| refused("initial15 collecting scope absent"))?;
        if collecting.schema != "source-owned.collecting-complete-capture/1"
            || collecting.ordinary_acceptance
            || collecting.world != manifest.world_binding_hash
            || collecting.sources.len() > 32
            || collecting.sources.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(refused("initial15 original collecting scope differs"));
        }
        let dependencies = scope
            .dependency_data(&manifest.provenance_ref)
            .map_err(unknown)?;
        for reference in std::iter::once(&collecting.plan)
            .chain(std::iter::once(&collecting.refused))
            .chain(&collecting.sources)
        {
            reference.validate().map_err(unknown)?;
            if !dependencies.contains(reference) {
                return Err(refused("initial15 provenance dependency absent"));
            }
            scope.body_data(reference).map_err(unknown)?;
        }
        let plan = collecting.plan.clone();
        let plan_copy = NodeRuntime::capture_reference_storage(&plan).map_err(unknown)?;
        if let Some(cursor) = terminal {
            cursor.finish_data(self, plan_copy)?;
        }
        self.parse_role_data(scope, &plan, 1, additional, terminal, plan_copy)?;
        drop(plan);
        for (key, slot) in [("descriptors", 2), ("contracts", 3), ("fixtures", 4)] {
            let unit = self.values[1]
                .as_ref()
                .and_then(|plan| plan.get("unit"))
                .and_then(Value::as_object)
                .ok_or_else(|| refused("initial15 original qualification unit absent"))?;
            if unit.len() != 9
                || [
                    "implementation",
                    "realization",
                    "descriptors",
                    "contracts",
                    "port_profiles",
                    "environment",
                    "harness",
                    "fixtures",
                    "specification",
                ]
                .iter()
                .any(|key| !unit.contains_key(*key))
            {
                return Err(refused(
                    "initial15 original qualification unit grammar differs",
                ));
            }
            let value = unit
                .get(key)
                .ok_or_else(|| refused("initial15 qualification role absent"))?;
            let role = match key {
                "descriptors" => QualificationRole::Descriptors,
                "contracts" => QualificationRole::Contracts,
                "fixtures" => QualificationRole::Fixtures,
                _ => return Err(refused("initial15 qualification role differs")),
            };
            self.begin_typed_terminal_data(
                terminal,
                TerminalWork::QualificationReference(role),
                value,
            )?;
            self.admit_typed_data(scope, additional, value)?;
            let reference = ContentRef::deserialize(value).map_err(unknown)?;
            let collecting = self
                .collecting
                .as_ref()
                .ok_or_else(|| refused("initial15 collecting scope absent"))?;
            if !collecting.sources.contains(&reference)
                || !scope
                    .dependency_data(&manifest.provenance_ref)
                    .map_err(unknown)?
                    .contains(&reference)
            {
                return Err(refused(
                    "initial15 qualification role is not an original immutable prerequisite",
                ));
            }
            let reference_copy =
                NodeRuntime::capture_reference_storage(&reference).map_err(unknown)?;
            if let Some(cursor) = terminal {
                cursor.finish_data(self, reference_copy)?;
            }
            self.parse_role_data(
                scope,
                &reference,
                slot,
                additional,
                terminal,
                reference_copy,
            )?;
        }
        self.parse_role_data(
            scope,
            &manifest.coordinator_state_ref,
            5,
            additional,
            terminal,
            0,
        )?;
        let coordinator = self.values[5]
            .as_ref()
            .ok_or_else(|| refused("initial15 coordinator absent"))?;
        self.begin_typed_terminal_data(
            terminal,
            TerminalWork::RoleTyped(TerminalRole::Coordinator),
            coordinator,
        )?;
        self.admit_typed_data(scope, additional, coordinator)?;
        self.coordinator = Some(Initial15Coordinator::deserialize(coordinator).map_err(unknown)?);
        let coordinator = self
            .coordinator
            .as_ref()
            .ok_or_else(|| refused("initial15 typed coordinator absent"))?;
        if coordinator.schema_version != 7
            || coordinator.runtime.media_type != crate::node_state::ORIGINAL_LINEAGE_RUNTIME_MEDIA
            || coordinator.scheduler.media_type != "application/json"
            || coordinator.world_repeatability == Repeatability::Qualified
        {
            return Err(refused("initial15 original coordinator grammar differs"));
        }
        let dependencies = scope
            .dependency_data(&manifest.coordinator_state_ref)
            .map_err(unknown)?;
        if dependencies.len() != 2
            || !dependencies.contains(&coordinator.runtime)
            || !dependencies.contains(&coordinator.scheduler)
        {
            return Err(refused("initial15 coordinator dependency roles differ"));
        }
        let runtime_ref = coordinator.runtime.clone();
        let scheduler_ref = coordinator.scheduler.clone();
        let coordinator_copies = checked_sum(
            [
                NodeRuntime::capture_reference_storage(&runtime_ref).map_err(unknown)?,
                NodeRuntime::capture_reference_storage(&scheduler_ref).map_err(unknown)?,
            ],
            self.maximum,
        )?;
        if let Some(cursor) = terminal {
            cursor.finish_data(self, coordinator_copies)?;
        }
        self.parse_role_data(
            scope,
            &runtime_ref,
            6,
            additional,
            terminal,
            coordinator_copies,
        )?;
        self.parse_role_data(
            scope,
            &scheduler_ref,
            7,
            additional,
            terminal,
            coordinator_copies,
        )?;
        drop(runtime_ref);
        drop(scheduler_ref);
        let runtime_value = self.values[6]
            .as_ref()
            .ok_or_else(|| refused("initial15 runtime DOM absent"))?;
        self.begin_typed_terminal_data(
            terminal,
            TerminalWork::RoleTyped(TerminalRole::Runtime),
            runtime_value,
        )?;
        self.admit_typed_data(scope, additional, runtime_value)?;
        self.runtime =
            Some(OriginalLineageRuntimeRecord::deserialize(runtime_value).map_err(unknown)?);
        if let Some(cursor) = terminal {
            cursor.finish_data(self, 0)?;
        }
        let scheduling_value = self.values[7]
            .as_ref()
            .ok_or_else(|| refused("initial15 scheduling DOM absent"))?;
        self.begin_typed_terminal_data(
            terminal,
            TerminalWork::RoleTyped(TerminalRole::Scheduling),
            scheduling_value,
        )?;
        self.admit_typed_data(scope, additional, scheduling_value)?;
        self.scheduling = Some(SchedulingSnapshot::deserialize(scheduling_value).map_err(unknown)?);
        if let Some(cursor) = terminal {
            cursor.finish_data(self, 0)?;
        }
        self.parse_role_data(
            scope,
            scope
                .original_capture_journal_reference_data()
                .map_err(unknown)?,
            8,
            additional,
            terminal,
            0,
        )?;
        let administrative = self.values[8]
            .as_ref()
            .ok_or_else(|| refused("initial15 administrative DOM absent"))?;
        self.begin_typed_terminal_data(
            terminal,
            TerminalWork::RoleTyped(TerminalRole::Administrative),
            administrative,
        )?;
        self.admit_typed_data(scope, additional, administrative)?;
        self.administrative =
            Some(RuntimeOriginalCaptureJournal::deserialize(administrative).map_err(unknown)?);
        if let Some(cursor) = terminal {
            cursor.finish_data(self, 0)?;
        }
        self.authenticate_runtime_roles_data(scope, additional, terminal)?;
        for index in 0..3 {
            self.read_original_launch_data(scope, index, additional, terminal)?;
            let launch = self.launches[index]
                .as_ref()
                .ok_or_else(|| refused("initial15 launch absent"))?;
            for previous in &self.launches[..index] {
                let previous = previous
                    .as_ref()
                    .ok_or_else(|| refused("initial15 previous launch absent"))?;
                if launch.selection.realize.requested_node_ids
                    == previous.selection.realize.requested_node_ids
                    || launch.selection.realization.owner_bindings[0].owner.id
                        == previous.selection.realization.owner_bindings[0].owner.id
                {
                    return Err(refused("initial15 original node or owner repeats"));
                }
            }
        }
        Ok(())
    }

    fn read_original_launch_data(
        &mut self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        index: usize,
        additional: usize,
        terminal: Option<&Initial15Terminal17<'_, '_>>,
    ) -> Result<(), OperationFailure> {
        let descriptors = tuple_data(
            self.values[2]
                .as_ref()
                .ok_or_else(|| refused("initial15 descriptor role absent"))?,
            2,
        )?;
        let contracts = tuple_data(
            self.values[3]
                .as_ref()
                .ok_or_else(|| refused("initial15 contracts role absent"))?,
            2,
        )?;
        let fixtures = tuple_data(
            self.values[4]
                .as_ref()
                .ok_or_else(|| refused("initial15 fixtures role absent"))?,
            5,
        )?;
        let nodes = tuple_data(&descriptors[0], 3)?;
        let rows = tuple_data(&contracts[0], 3)?;
        let launches = tuple_data(&fixtures[1], 3)?;
        let row = tuple_data(&rows[index], 7)?;
        let caps = OriginalSemanticCaps {
            operations: usize_data(&row[3])?,
            result: usize_data(&row[4])?,
            authorization: usize_data(&row[5])?,
            semantic: usize_data(&row[6])?,
        };
        if caps.operations == 0
            || caps.operations > 64
            || caps.result != 65_536
            || caps.authorization < 8192
            || caps.semantic == 0
            || caps.semantic > 256 * 1024 * 1024
            || caps.result > caps.semantic
            || caps.authorization > caps.semantic
        {
            return Err(refused("initial15 original semantic ceilings unsupported"));
        }
        let member =
            crate::node_state::RestoredArchive17SourceIndex::from_data(index).map_err(unknown)?;
        self.begin_typed_terminal_data(
            terminal,
            TerminalWork::LaunchDecode(member),
            &launches[index],
        )?;
        self.admit_typed_data(scope, additional, &launches[index])?;
        self.launches[index] =
            Some(PacketNative5SourceLaunch::deserialize(&launches[index]).map_err(unknown)?);
        if let Some(cursor) = terminal {
            cursor.finish_data(self, 0)?;
        }
        let launch = self.launches[index]
            .as_ref()
            .ok_or_else(|| refused("initial15 typed launch absent"))?;
        if let Some(cursor) = terminal {
            let (formatter, quote_scratch) = launch
                .validation_construction_projection_storage_data()
                .map_err(unknown)?;
            cursor.begin_with_scratch_data(
                TerminalWork::LaunchValidate(member),
                formatter,
                quote_scratch,
            )?;
            let (transient, scratch) = self.launch_terminal_transient_data(launch, &rows[index])?;
            cursor.construct_with_scratch_data(0, transient, scratch)?;
        }
        // The real raw5 validator checks all original selection/schema/model and
        // private declaration DATA; it creates no process, key or native marker.
        self.admit_serialization_data(scope, additional, launch)?;
        launch.validate().map_err(unknown)?;
        let [descriptor] = launch.selection.realization.descriptors.as_slice() else {
            return Err(refused("initial15 native descriptor roster differs"));
        };
        let [binding] = launch.selection.realization.bindings.as_slice() else {
            return Err(refused("initial15 native binding roster differs"));
        };
        let [owner] = launch.selection.realization.owner_bindings.as_slice() else {
            return Err(refused("initial15 native owner binding roster differs"));
        };
        if launch
            .selection
            .provider
            .implementation
            .implementation_id
            .as_str()
            != "source-owned.packet-native/5"
            || descriptor.roles.len() != 1
            || descriptor.roles[0].as_str() != "external_device"
            || binding.compatibility.configuration_ref != descriptor.model_ref
            || launch.selection.realize.configuration != descriptor.model_ref
            || launch.selection.realize.requested_node_ids.as_slice()
                != std::slice::from_ref(&descriptor.id)
            || binding.compatibility.node_id != descriptor.id
            || binding.compatibility.execution_owner != owner.owner
            || binding.compatibility.capture_owner != owner.owner
            || owner.owner.participant_ids.as_slice() != std::slice::from_ref(&descriptor.id)
            || launch.selection.world != scope.manifest_data().map_err(unknown)?.world_binding_hash
            || launch
                .selection
                .realize
                .resource_limits
                .maximum_operations
                .get()
                < caps.operations as u64
            || !matches!(
                launch.capture_profile,
                PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
            || launch.protocol_metadata_limits.is_none()
        {
            return Err(refused(
                "initial15 original source/owner/world selection differs",
            ));
        }
        self.admit_serialization_data(scope, additional, descriptor)?;
        if serde_json::to_value(descriptor).map_err(unknown)? != nodes[index] {
            return Err(refused(
                "initial15 descriptor order differs from archived launch",
            ));
        }
        self.admit_serialization_data(
            scope,
            additional,
            &binding.compatibility.operating_contract,
        )?;
        if serde_json::to_value(&binding.compatibility.operating_contract).map_err(unknown)?
            != row[0]
        {
            return Err(refused("initial15 original operating contract differs"));
        }
        {
            self.admit_typed_data(scope, additional, &rows[index])?;
            let receipt = SchemaRef::deserialize(&row[2]).map_err(unknown)?;
            receipt.validate().map_err(unknown)?;
            let facet = FacetSelection::deserialize(&row[1]).map_err(unknown)?;
            facet.validate().map_err(unknown)?;
            let facets = &binding.compatibility.operating_contract.facets;
            if facet.id.as_str() != "source-owned.packet-exact/5"
                || facet.version != 5
                || facet.configuration_ref != binding.compatibility.configuration_ref
                || facet.guarantees_ref != binding.compatibility.guarantees_ref
                || !facet.extensions.is_empty()
                || facets.len() != 2
                || !facets.contains(&facet)
                || facets.iter().any(|selected| {
                    selected.version != 5
                        || selected.configuration_ref != binding.compatibility.configuration_ref
                        || selected.guarantees_ref != binding.compatibility.guarantees_ref
                        || !selected.extensions.is_empty()
                        || !matches!(
                            selected.id.as_str(),
                            "source-owned.packet-exact/5"
                                | "source-owned.packet-complete-original-lineage/5"
                        )
                })
                || facets[0].id == facets[1].id
                || receipt.id.as_str() != "source-owned.packet-receipt/5"
                || receipt.version != 5
                || !receipt.extensions.is_empty()
                || !launch
                    .selection
                    .provider
                    .implementation
                    .formats
                    .contains(&receipt)
                || !binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&receipt)
            {
                return Err(refused(
                    "initial15 original facet or receipt schema differs",
                ));
            }
            let temporary = declaration_comparison_storage_data(&receipt, &facet, self.maximum)?;
            let compiled = crucible_node_provider::reference_packet::continuation_contracts::complete_packet_contract_history_data();
            self.admit_serialization_data(
                scope,
                checked_sum([additional, temporary], self.maximum)?,
                &compiled,
            )?;
            let value = serde_json::to_value(&compiled).map_err(unknown)?;
            let value_storage =
                NodeRuntime::capture_initial15_json_storage_data(&value, self.maximum)
                    .map_err(unknown)?;
            self.admit_serialization_data(
                scope,
                checked_sum([additional, temporary, value_storage], self.maximum)?,
                &value,
            )?;
            let bytes = canonical::canonical_json(&value).map_err(unknown)?;
            receipt.definition.verify(&bytes).map_err(unknown)?;
            if receipt.definition.media_type != "application/json"
                || scope.body_data(&receipt.definition).map_err(unknown)? != bytes.as_slice()
            {
                return Err(refused(
                    "initial15 receipt definition differs from the compiled complete contract",
                ));
            }
        }
        let owner = scope
            .selected_initial15_owner_data(
                &descriptor.id,
                &launch.selection.provider.implementation.implementation_id,
            )
            .map_err(unknown)?;
        if owner.owner != launch.selection.realization.owner_bindings[0].owner.id {
            return Err(refused("initial15 native owner/schema differs"));
        }
        // Compare the same full compiled schema without allocating its definition
        // and reference merely to perform equality against the archived key.
        crucible_node_provider::reference_packet::service::native_snapshot::authenticate_native_owned14_snapshot_schema_data(&owner.key.schema)
            .map_err(unknown)?;
        self.admit_serialization_data(scope, additional, &launch.program)?;
        let program = match &launch.program {
            PacketConnectedSourceProgram::Producer { program } => {
                serde_json::to_value(program).map_err(unknown)?
            }
            PacketConnectedSourceProgram::Reactive { program } => {
                serde_json::to_value(program).map_err(unknown)?
            }
        };
        let program_storage =
            NodeRuntime::capture_initial15_json_storage_data(&program, self.maximum)
                .map_err(unknown)?;
        self.admit_serialization_data(
            scope,
            checked_sum([additional, program_storage], self.maximum)?,
            &program,
        )?;
        let program_bytes = canonical::canonical_json(&program).map_err(unknown)?;
        descriptor
            .model_ref
            .verify(&program_bytes)
            .map_err(unknown)?;
        if descriptor.model_ref.media_type != "application/json"
            || scope.body_data(&descriptor.model_ref).map_err(unknown)? != program_bytes.as_slice()
        {
            return Err(refused("initial15 original native program body differs"));
        }
        self.storage[index] = Some(PacketNative5StorageSelection {
            storage: launch.storage.clone(),
            limits: launch.limits.clone(),
        });
        self.caps[index] = Some(caps);
        drop(program_bytes);
        drop(program);
        self.admit_data(scope, additional, 0)?;
        if let Some(cursor) = terminal {
            cursor.finish_data(self, 0)?;
        }
        Ok(())
    }

    fn authenticate_runtime_roles_data(
        &self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        terminal: Option<&Initial15Terminal17<'_, '_>>,
    ) -> Result<(), OperationFailure> {
        if let Some(cursor) = terminal {
            let reference = &self
                .coordinator
                .as_ref()
                .ok_or_else(|| refused("initial15 coordinator absent"))?
                .runtime;
            // Any temporary Bytes formatter reconstructs a string decoded from
            // this exact closed Runtime input. Its backing cannot exceed the
            // literal body extent. This prices only the quote's formatter, not
            // a parser, result heap or reusable semantic allowance.
            let formatter = scope
                .body_data(reference)
                .map_err(unknown)?
                .len()
                .checked_add(20)
                .ok_or_else(|| refused("initial15 Runtime formatter extent overflow"))?;
            cursor.begin_data(
                crate::node_state::RestoredArchive17Initial15Work::RuntimeJoin,
                formatter,
            )?;
            let transient = self.runtime_join_terminal_transient_data(scope)?;
            cursor.construct_data(0, transient)?;
        }
        self.authenticate_runtime_roles_inner_data(scope, additional)?;
        if let Some(cursor) = terminal {
            cursor.finish_data(self, 0)?;
        }
        Ok(())
    }

    fn authenticate_runtime_roles_inner_data(
        &self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
    ) -> Result<(), OperationFailure> {
        let manifest = scope.manifest_data().map_err(unknown)?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| refused("initial15 Runtime7 absent"))?;
        let scheduling = self
            .scheduling
            .as_ref()
            .ok_or_else(|| refused("initial15 Scheduler1 absent"))?;
        let coordinator = self
            .coordinator
            .as_ref()
            .ok_or_else(|| refused("initial15 coordinator absent"))?;
        let administrative = self
            .administrative
            .as_ref()
            .ok_or_else(|| refused("initial15 administrative absent"))?;
        let nodes = administrative
            .attempts
            .len()
            .checked_add(5)
            .and_then(|n| n.checked_mul(NodeRuntime::capture_map_node_storage::<&Id, ()>()))
            .ok_or_else(|| refused("initial15 administrative counter overflow"))?;
        self.admit_data(scope, additional, nodes)?;
        scope
            .authenticate_initial15_administrative_data(
                administrative,
                &coordinator.runtime,
                &coordinator.scheduler,
            )
            .map_err(unknown)?;
        let [attempt] = administrative.attempts.as_slice() else {
            return Err(refused("initial15 administrative attempt differs"));
        };
        let source = &runtime.source_activation;
        if runtime.capture_cut != manifest.cut
            || runtime.capture_ordinal != manifest.event_ordinal
            || source.world_binding_hash != manifest.world_binding_hash
            || source != &attempt.source_activation
            || runtime.capture_cut != scheduling.capture_cut
            || runtime.capture_ordinal != scheduling.capture_ordinal
            || source.activation_id != scheduling.source_activation_id
            || source.generation != scheduling.source_generation
            || source.boundary != scheduling.source_boundary
            || source.world_binding_hash != scheduling.world_binding_hash
            || source.owners.len() != scheduling.source_owners.len()
            || source
                .owners
                .iter()
                .zip(&scheduling.source_owners)
                .any(|(owner, saved)| {
                    owner.owner != saved.owner
                        || owner.incarnation != saved.incarnation
                        || owner.generation != saved.generation
                })
            || scheduling.schema_version != 1
            || scheduling.original_epochs.is_some()
            || !scheduling.external_closed_prefixes.is_empty()
        {
            return Err(refused(
                "initial15 original Runtime7/Scheduler1 scope differs",
            ));
        }
        let provenance = self.values[0]
            .as_ref()
            .ok_or_else(|| refused("initial15 provenance absent"))?;
        self.admit_serialization_data(scope, additional, source)?;
        if provenance.get("source_activation")
            != Some(&serde_json::to_value(source).map_err(unknown)?)
            || provenance.get("cut")
                != Some(&serde_json::to_value(runtime.capture_cut).map_err(unknown)?)
            || provenance.get("ordinal")
                != Some(&serde_json::to_value(runtime.capture_ordinal).map_err(unknown)?)
        {
            return Err(refused("initial15 original provenance frontier differs"));
        }
        self.admit_data(
            scope,
            additional,
            NodeRuntime::capture_future_decode_storage(runtime, self.maximum).map_err(unknown)?,
        )?;
        runtime
            .validate_initial15_parent_bodies_data(
                scope,
                scope
                    .limits_data()
                    .map_err(unknown)?
                    .state
                    .maximum_record_bytes,
            )
            .map_err(unknown)
    }
}

pub(super) fn settlement_reference_data<'a>(
    administrative: &'a RuntimeOriginalCaptureJournal,
    owner: &Id,
) -> Result<&'a ContentRef, OperationFailure> {
    let [attempt] = administrative.attempts.as_slice() else {
        return Err(refused("initial15 administrative attempt differs"));
    };
    let saved = attempt
        .owners
        .iter()
        .find(|one| &one.owner.owner == owner)
        .ok_or_else(|| refused("initial15 owner settlement absent"))?;
    match &saved.state {
        OriginalCaptureOwnerState::Settled { journal, .. } => Ok(journal),
        _ => Err(refused("initial15 owner not settled")),
    }
}

pub(super) fn metadata_rows_data(bytes: &[u8], maximum: usize) -> Result<usize, OperationFailure> {
    let mut outer = Fields::array(bytes).map_err(unknown)?;
    if outer.next().map_err(unknown)? != Some(b"\"source-private.cnp-protocol/11\"".as_slice()) {
        return Err(refused("initial15 protocol outer class differs"));
    }
    outer
        .next()
        .map_err(unknown)?
        .ok_or_else(|| refused("initial15 protocol payload absent"))?;
    let records = outer
        .next()
        .map_err(unknown)?
        .ok_or_else(|| refused("initial15 metadata roster absent"))?;
    outer
        .next()
        .map_err(unknown)?
        .ok_or_else(|| refused("initial15 alias roster absent"))?;
    outer.finish().map_err(unknown)?;
    let records =
        crucible_node_provider::retained_metadata::records::ValidatedMetadataRecords::validate(
            records, 131072, maximum,
        )
        .map_err(unknown)?;
    let rows = records.row_count();
    if rows == 0 {
        return Err(refused("initial15 metadata rows empty"));
    }
    Ok(rows)
}

fn declaration_comparison_storage_data(
    receipt: &SchemaRef,
    facet: &FacetSelection,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    use super::super::super::archive_semantics::decoded_storage::Census;
    let SchemaRef {
        id,
        version,
        definition,
        extensions,
    } = receipt;
    let mut census = Census::new(maximum);
    census.charge(id).map_err(unknown)?;
    census.charge(definition).map_err(unknown)?;
    census.charge(extensions).map_err(unknown)?;
    let _: &u16 = version;
    let FacetSelection {
        id,
        version,
        configuration_ref,
        guarantees_ref,
        extensions,
    } = facet;
    census.charge(id).map_err(unknown)?;
    census.charge(configuration_ref).map_err(unknown)?;
    census.charge(guarantees_ref).map_err(unknown)?;
    census.charge(extensions).map_err(unknown)?;
    let _: &u16 = version;
    Ok(census.bytes())
}

fn tuple_data(value: &Value, length: usize) -> Result<&[Value], OperationFailure> {
    value
        .as_array()
        .filter(|values| values.len() == length)
        .map(Vec::as_slice)
        .ok_or_else(|| refused("initial15 original declaration tuple differs"))
}

fn usize_data(value: &Value) -> Result<usize, OperationFailure> {
    usize::try_from(
        value
            .as_u64()
            .ok_or_else(|| refused("initial15 original cap is not an integer"))?,
    )
    .map_err(unknown)
}

fn reference_matches_data(value: &Value, reference: &ContentRef) -> Result<bool, OperationFailure> {
    let fields = value
        .as_object()
        .ok_or_else(|| refused("initial15 reference is not an object"))?;
    let hash = fields
        .get("hash")
        .and_then(Value::as_object)
        .ok_or_else(|| refused("initial15 reference hash absent"))?;
    let length = fields
        .get("length")
        .and_then(Value::as_str)
        .ok_or_else(|| refused("initial15 reference length absent"))?;
    if length.is_empty()
        || (length.len() > 1 && length.starts_with('0'))
        || !length.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(refused("initial15 reference length grammar differs"));
    }
    Ok(fields.len() == 3
        && hash.len() == 3
        && hash.get("algorithm").and_then(Value::as_str) == Some(reference.hash.algorithm.as_str())
        && hash.get("domain").and_then(Value::as_str) == Some(reference.hash.domain.as_str())
        && hash.get("digest").and_then(Value::as_str) == Some(reference.hash.digest.as_str())
        && fields.get("media_type").and_then(Value::as_str) == Some(reference.media_type.as_str())
        && length.parse::<u64>().ok() == Some(reference.length.get()))
}

pub(super) fn authenticate_original_native_selection_data(
    selection: &OriginalInitial15ArchivedSelection<'_>,
    protocol: &Initial15DecodedOwner,
) -> Result<(), OperationFailure> {
    selection.authenticate_origin_data()?;
    let expected = serde_json::to_value(selection.launch).map_err(unknown)?;
    for sealed in [
        protocol.native_before_data()?,
        protocol.native_after_data()?,
    ] {
        let native = sealed.historical().map_err(unknown)?;
        let wrapper = native
            .service
            .bootstrap
            .launch_value
            .as_object()
            .ok_or_else(|| refused("initial15 original invocation launch absent"))?;
        if wrapper.len() != 3
            || wrapper.get("schema_version").and_then(Value::as_u64) != Some(6)
            || wrapper.get("launch") != Some(&expected)
            || !wrapper.contains_key("invocation")
            || native.connection.policy.selection != selection.launch.selection
            || native.connection.policy.capture_profile != selection.launch.capture_profile
            || native.connection.policy.protocol_metadata_limits
                != selection.launch.protocol_metadata_limits
        {
            return Err(refused(
                "initial15 native private launch differs from immutable fixtures",
            ));
        }
    }
    selection.authenticate_origin_data()
}

pub(super) fn authenticate_original_caps_data(
    semantics: &PacketCompleteArchivedSemantics,
    caps: OriginalSemanticCaps,
) -> Result<(), OperationFailure> {
    let common = semantics.source_common_data();
    let associations = common
        .operations
        .len()
        .checked_add(common.inputs.len())
        .ok_or_else(|| refused("initial15 generic association count overflow"))?;
    if associations > caps.operations || common.retained_credit > caps.semantic {
        return Err(refused(
            "initial15 common semantic lifetime credit exceeds original declaration",
        ));
    }
    for operation in common.operations.values() {
        if let Some(outcome) = &operation.outcome {
            super::super::super::super::budget::serialized_size(outcome, caps.result)?;
        }
        if let Some(payload) = &operation.retirement {
            super::super::super::super::budget::serialized_size(payload, caps.authorization)?;
        }
    }
    for input in common.inputs.values() {
        if let Some(ack) = &input.acknowledgement {
            super::super::super::super::budget::serialized_size(ack, caps.result)?;
        }
    }
    if let Some(ready) = &common.ready {
        super::super::super::super::budget::serialized_size(ready, caps.result)?;
    }
    if let Some(prepared) = &common.prepared_owner {
        super::super::super::super::budget::serialized_size(prepared, caps.result)?;
    }
    if let Some((_, observation)) = &common.observation {
        super::super::super::super::budget::serialized_size(observation, caps.result)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn row_geometry_uses_the_actual_closed_capacity_records() {
        // This framing fragment prices DATA only; it is not an owned11 state.
        let bytes =
            br#"["source-private.cnp-protocol/11",null,[["string",8,1,1],["vector",2,8,8]],[]]"#;

        assert_eq!(metadata_rows_data(bytes, 24).unwrap(), 2);
        assert!(metadata_rows_data(bytes, 23).is_err());
        assert!(
            metadata_rows_data(br#"["source-private.cnp-protocol/11",null,[],[]]"#, 24).is_err()
        );
    }

    #[test]
    fn original_usize_caps_cannot_be_reinterpreted_from_decimal_strings() {
        assert_eq!(usize_data(&json!(64)).unwrap(), 64);
        assert!(usize_data(&json!("64")).is_err());
        assert!(usize_data(&json!(64.5)).is_err());
    }

    #[test]
    fn original_role_comparison_preserves_full_media_and_canonical_length() {
        let reference = canonical::content_ref(b"original DATA", "application/json").unwrap();
        let mut value = serde_json::to_value(&reference).unwrap();
        assert!(reference_matches_data(&value, &reference).unwrap());

        value["media_type"] = json!("application/octet-stream");
        assert!(!reference_matches_data(&value, &reference).unwrap());

        value["media_type"] = json!(reference.media_type);
        value["length"] = json!(format!("0{}", reference.length.get()));
        assert!(reference_matches_data(&value, &reference).is_err());
    }
}

impl OriginalInitial15ArchivedGroup {
    fn begin_typed_terminal_data(
        &self,
        terminal: Option<&Initial15Terminal17<'_, '_>>,
        work: TerminalWork,
        value: &Value,
    ) -> Result<(), OperationFailure> {
        if let Some(cursor) = terminal {
            cursor.begin_data(work, 0)?;
            let extent = NodeRuntime::capture_future_decode_storage(value, self.maximum)
                .map_err(unknown)?
                .checked_mul(3)
                .ok_or_else(|| refused("initial15 terminal typed row overflow"))?;
            // Same defining complete typed+serde construction as local admission.
            // Both columns conservatively cover overlap with transient decoders.
            cursor.construct_data(extent, extent)?;
        }
        Ok(())
    }
}
