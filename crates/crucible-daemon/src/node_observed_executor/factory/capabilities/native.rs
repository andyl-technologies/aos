//! Authenticates the actual complete Clock model beneath selected metadata.

use std::rc::Rc;

use crucible::{
    node_adapters::{HostModelResources, host_clock_initial_bytes},
    node_admission::AdmittedGraph,
    node_contract::{ActivationRecord, RuntimeSnapshot},
    node_scheduling::SchedulingSnapshot,
    node_state::{
        AuthenticatedNativeSource, NativeArchiveLimits, NativeArchiveRecord, NativeRestoreStaging,
        NativeWorldFactory, RestoreReservations, StateError, VerifiedStateContent,
    },
};
use crucible_node_contract::CapturedOwner;

use super::{ResolvedCapabilityWorld, staging::CapabilityClockStaging, state_error};

/// Authenticates one installed closed capability-bearing Clock native archive.
///
/// Instances are created by the measured installation catalog. The factory
/// accepts only its complete immutable original selection and unchanged native
/// Clock codec, and allocates fresh native state under owned restore custody.
pub struct InstalledCapabilityClockFactory {
    pub(super) resolved: Rc<ResolvedCapabilityWorld>,
    pub(super) installed: Rc<super::super::InstalledHostStateFactory>,
}

pub(super) fn resources() -> HostModelResources {
    HostModelResources {
        maximum_capture_bytes: 64 * 1024 * 1024,
        maximum_operations: 65_536,
    }
}

impl NativeWorldFactory for InstalledCapabilityClockFactory {
    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_selection(graph)?;
        if owner.participant_ids.as_slice()
            != std::slice::from_ref(&self.resolved.scenario.descriptors[0].id)
            || owner.capture_owner_id != source.owner().owner
            || source.owner().cut != source.runtime().capture_cut
            || source.runtime().schema_version != 1
        {
            return Err(state_error(
                "capability original owner, runtime codec or cut differs",
            ));
        }
        let inventory = super::super::native_state::host::authenticate_clock_source(
            graph,
            &owner.participant_ids[0],
            source,
            resources(),
        )?;
        if inventory.native_model.bytes
            != host_clock_initial_bytes(source.runtime().capture_cut.time_ps.get())
            || !source.runtime().inputs.is_empty()
            || source
                .runtime()
                .operations
                .iter()
                .any(|operation| operation.route.node != owner.participant_ids[0])
        {
            return Err(state_error(
                "capability original native integer state or ingress differs",
            ));
        }
        Ok(())
    }

    fn authenticate_coordinator(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        self.authenticate_selection(graph)?;
        if runtime.schema_version != 1
            || scheduler.schema_version != 1
            || runtime.source_activation.world_binding_hash != *graph.world_binding_hash()
            || scheduler.world_binding_hash != *graph.world_binding_hash()
            || runtime.capture_cut != scheduler.capture_cut
            || runtime.capture_ordinal != scheduler.capture_ordinal
            || !runtime.inputs.is_empty()
            || !scheduler.external_closed_prefixes.is_empty()
            || !graph.world().connections.is_empty()
            || graph.ownership_policy().capture_owners.len() != 1
            || graph.ownership_policy().capture_owners.iter().any(|owner| {
                !owner.complete_model
                    || !owner.unchanged_cut
                    || !owner.exact_continuation
                    || !owner.durable_restart
                    || !owner.dependencies.is_empty()
            })
        {
            return Err(state_error(
                "capability coordinator original complete closure differs",
            ));
        }
        crucible::node_scheduling::validate_saved_source(graph, scheduler).map_err(state_error)?;
        if content.get(&self.resolved.scenario.descriptors[0].initialization_ref)
            != Some(host_clock_initial_bytes(0).as_slice())
        {
            return Err(state_error(
                "installed capability Clock initialization is missing",
            ));
        }
        Ok(())
    }

    fn reservation(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
        limits: NativeArchiveLimits,
    ) -> Result<RestoreReservations, StateError> {
        self.authenticate_source(graph, owner, source)?;
        let bytes = source
            .owner()
            .evidence
            .iter()
            .try_fold(source.owner().state.length.get(), |total, object| {
                total.checked_add(object.length.get())
            })
            .ok_or_else(|| state_error("capability native memory reservation overflow"))?;
        if bytes > limits.state.maximum_native_memory_bytes {
            return Err(state_error(
                "capability native memory credit is unavailable",
            ));
        }
        Ok(RestoreReservations {
            memory_bytes: bytes,
            writable_bytes: 0,
            processes: 0,
            descriptors: 0,
        })
    }

    fn empty_staging(
        &self,
        graph: Rc<AdmittedGraph>,
        archive: NativeArchiveRecord,
        target: &ActivationRecord,
        reservations: RestoreReservations,
        _: NativeArchiveLimits,
    ) -> Result<Box<dyn NativeRestoreStaging>, StateError> {
        self.authenticate_selection(&graph)?;
        if target.world_binding_hash != *graph.world_binding_hash()
            || target.boundary != archive.manifest().cut
            || target.owners.len() != 1
        {
            return Err(state_error(
                "capability fresh complete capsule scope differs",
            ));
        }
        Ok(Box::new(CapabilityClockStaging::empty(
            graph,
            archive,
            target.clone(),
            reservations,
            self.installed.clone(),
        )))
    }
}

impl InstalledCapabilityClockFactory {
    pub(super) fn authenticate_selection(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        let expected = &self.resolved.scenario;
        let actual = graph
            .capability_selection()
            .ok_or_else(|| state_error("original authored capability selection is absent"))?;
        if graph.world() != &expected.world
            || !graph.selected_extensions().is_empty()
            || expected.descriptors.len() != 1
            || !super::policy::standalone_clock(&self.resolved.candidate.selections)
            || crucible_node_contract::canonical::json_hash(
                "crucible.capability-demand.v1",
                actual.requirements(),
            )
            .map_err(state_error)?
                != crucible_node_contract::canonical::json_hash(
                    "crucible.capability-demand.v1",
                    &self.resolved.requirements,
                )
                .map_err(state_error)?
            || graph.descriptor(&expected.descriptors[0].id) != Some(&expected.descriptors[0])
            || graph
                .binding(&expected.descriptors[0].id)
                .is_none_or(|binding| {
                    expected.compatibility.as_slice()
                        != std::slice::from_ref(&binding.compatibility)
                })
            || actual.objects().any(|(reference, bytes)| {
                expected
                    .content
                    .iter()
                    .find(|object| &object.reference == reference)
                    .is_none_or(|object| object.bytes != bytes)
            })
        {
            return Err(state_error(
                "complete installed capability Clock source selection differs",
            ));
        }
        self.installed
            .check_model(
                &crucible::node_adapters::HostModel::Clock(
                    crucible_device::clock::VirtualClock::new(),
                ),
                &expected.descriptors[0],
                graph
                    .binding(&expected.descriptors[0].id)
                    .ok_or_else(|| state_error("actual Clock binding absent"))?,
            )
            .map_err(|error| state_error(error.reason))?;
        super::policy::matches(
            &self.resolved.candidate.selections,
            expected,
            &self.resolved.requirements,
        )
        .map_err(state_error)
    }
}

impl crucible::node_state::CaptureEvidence for InstalledCapabilityClockFactory {
    fn content(
        &self,
        reference: &crucible_node_contract::ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, StateError> {
        if let Some(object) = self
            .resolved
            .scenario
            .content
            .iter()
            .find(|object| &object.reference == reference)
        {
            if object.bytes.len() > maximum {
                return Err(state_error(
                    "installed capability object exceeds finite read allowance",
                ));
            }
            reference.verify(&object.bytes).map_err(state_error)?;
            return Ok(object.bytes.clone());
        }
        self.installed.content(reference, maximum)
    }

    fn dependencies(
        &self,
        reference: &crucible_node_contract::ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<crucible_node_contract::ContentRef>, StateError> {
        let body = self
            .resolved
            .scenario
            .content
            .iter()
            .find(|object| object.reference == self.resolved.scenario.world.scenario_ref)
            .ok_or_else(|| state_error("selected capability wrapper absent"))?;
        let selection: crucible::node_admission::CapabilitySelection =
            serde_json::from_slice(&body.bytes).map_err(state_error)?;
        if reference == &self.resolved.scenario.world.scenario_ref
            || reference == &selection.requirements_ref
        {
            let actual = self
                .resolved
                .scenario
                .content
                .iter()
                .find(|object| &object.reference == reference)
                .ok_or_else(|| state_error("capability body absent"))?;
            if actual.bytes != bytes {
                return Err(state_error("original capability policy bytes changed"));
            }
            let mut dependencies = Vec::new();
            let capacity = if reference == &self.resolved.scenario.world.scenario_ref {
                2
            } else {
                self.resolved
                    .requirements
                    .nodes
                    .iter()
                    .try_fold(0usize, |total, node| {
                        node.operations
                            .len()
                            .checked_mul(2)
                            .and_then(|count| count.checked_add(1))
                            .and_then(|count| count.checked_add(total))
                    })
                    .ok_or_else(|| state_error("capability dependency credit overflow"))?
            };
            if capacity > maximum {
                return Err(state_error(
                    "complete capability dependency credit unavailable",
                ));
            }
            dependencies
                .try_reserve_exact(capacity)
                .map_err(state_error)?;
            if reference == &self.resolved.scenario.world.scenario_ref {
                dependencies.push(selection.base_scenario_ref);
                dependencies.push(selection.requirements_ref);
            } else {
                for node in &self.resolved.requirements.nodes {
                    dependencies.push(node.timing.policy_ref.clone());
                    for operation in &node.operations {
                        dependencies.push(operation.facet.configuration_ref.clone());
                        dependencies.push(operation.facet.guarantees_ref.clone());
                    }
                }
            }
            dependencies.sort();
            dependencies.dedup();
            return Ok(dependencies);
        }
        self.installed.dependencies(reference, bytes, maximum)
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &crucible_node_contract::CaptureManifest,
        _: &CapturedOwner,
        _: &crucible::node_state::StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<crucible::node_state::NativeOwnerCaptureProof, StateError> {
        Err(state_error(
            "immutable capability policy cannot issue native source capture authority",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &crucible_node_contract::CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<crucible::node_state::NativeCoordinatorCaptureProof, StateError> {
        Err(state_error(
            "immutable capability policy cannot issue coordinator source authority",
        ))
    }
}
