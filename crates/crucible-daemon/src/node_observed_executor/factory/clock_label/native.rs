//! Authenticates the actual complete Clock model beneath selected metadata.

use std::rc::Rc;

use crucible::{
    node_adapters::{HostModelResources, host_clock_initial_bytes},
    node_admission::AdmittedGraph,
    node_contract::{ActivationRecord, RuntimeSnapshot},
    node_scheduling::SchedulingSnapshot,
    node_state::{
        AuthenticatedNativeSource, NativeArchiveLimits, NativeArchiveRecord,
        NativeExtensionPreservationPolicy, NativeRestoreStaging, NativeWorldFactory,
        RestoreReservations, StateError, VerifiedStateContent,
    },
};
use crucible_node_contract::CapturedOwner;

use super::{ClockLabelPolicy, staging::ClockLabelStaging, state_error};

/// Authenticates one installed closed metadata-label Clock native archive.
///
/// Instances are created by the measured installation catalog. The factory
/// accepts only its complete immutable original selection and unchanged native
/// Clock codec, and allocates fresh native state under owned restore custody.
pub struct InstalledClockLabelFactory {
    pub(super) profile: Rc<ClockLabelPolicy>,
    pub(super) installed: Rc<super::super::InstalledHostStateFactory>,
}

pub(super) fn resources() -> HostModelResources {
    HostModelResources {
        maximum_capture_bytes: 64 * 1024 * 1024,
        maximum_operations: 65_536,
    }
}

impl NativeWorldFactory for InstalledClockLabelFactory {
    fn extension_preservation_policy(&self) -> Option<&dyn NativeExtensionPreservationPolicy> {
        Some(self.profile.as_ref())
    }

    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError> {
        self.profile.authenticate_selection(graph)?;
        if owner.participant_ids.as_slice()
            != std::slice::from_ref(&self.profile.labeled.descriptors[0].id)
            || owner.capture_owner_id != source.owner().owner
            || source.owner().cut != source.runtime().capture_cut
            || source.runtime().schema_version != 1
        {
            return Err(state_error(
                "label original owner, runtime codec or cut differs",
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
                "label original native integer state or ingress differs",
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
        self.profile.authenticate_selection(graph)?;
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
                "label coordinator original complete closure differs",
            ));
        }
        crucible::node_scheduling::validate_saved_source(graph, scheduler).map_err(state_error)?;
        if content.get(&self.profile.labeled.descriptors[0].initialization_ref)
            != Some(host_clock_initial_bytes(0).as_slice())
        {
            return Err(state_error(
                "installed label Clock initialization is missing",
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
            .ok_or_else(|| state_error("label native memory reservation overflow"))?;
        if bytes > limits.state.maximum_native_memory_bytes {
            return Err(state_error("label native memory credit is unavailable"));
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
        self.profile.authenticate_selection(&graph)?;
        if target.world_binding_hash != *graph.world_binding_hash()
            || target.boundary != archive.manifest().cut
            || target.owners.len() != 1
        {
            return Err(state_error("label fresh complete capsule scope differs"));
        }
        Ok(Box::new(ClockLabelStaging::empty(
            graph,
            archive,
            target.clone(),
            reservations,
            self.installed.clone(),
        )))
    }
}
