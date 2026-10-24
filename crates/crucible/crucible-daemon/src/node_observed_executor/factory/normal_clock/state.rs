//! Uses the existing typed native archive and public Clock continuation owner.
//!
//! Immutable source lookup supplies no provenance: the Core archive's signed
//! native owner/coordinator reader invokes this concrete source factory on the
//! actual captured public preparation and the complete native Clock ledger.

use std::rc::Rc;

use crucible_engine::{
    node_adapters::{
        HostModel, HostModelQualification, HostModelResources, host_clock_initial_bytes,
        validate_public_clock_continuation,
    },
    node_contract::{ActivationRecord, OperationFailure, RuntimeSnapshot},
    node_scheduling::SchedulingSnapshot,
    node_state::{
        AuthenticatedNativeSource, CaptureEvidence, NativeArchiveLimits, NativeArchiveRecord,
        NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, NativeRestoreStaging,
        NativeWorldFactory, RestoreReservations, StateError, StateErrorCode, StateRequirements,
        VerifiedStateContent,
    },
};
use crucible_node_format::{CaptureManifest, CapturedOwner, NodeBinding, NodeDescriptor};

use super::*;

/// Authenticates the actual public Clock state under its current source profile.
///
/// Only the measured catalog constructs this owner. Old generic/label codecs
/// are not substituted for the selected preparation-bearing source. Durable
/// source authentication grants no activation or mutable original runtime loan.
#[derive(Clone)]
pub struct InstalledNormalClockStateFactory {
    profile: InstalledNormalClockProfile,
    baseline: Rc<super::super::InstalledHostStateFactory>,
    origin: ClockOrigin,
}

impl InstalledNodeCatalog {
    /// Resolves complete native state support for the exact public Clock profile.
    ///
    /// # Errors
    /// Refuses a changed profile or missing current source/native implementation.
    pub fn installed_normal_clock_state_factory(
        &self,
        profile: &InstalledNormalClockProfile,
    ) -> Result<Rc<InstalledNormalClockStateFactory>, NodeObservedError> {
        let current = self.installed_normal_clock()?;
        if profile.scenario.canonical_bytes()? != current.scenario.canonical_bytes()? {
            return Err(refused(
                "normal Clock state profile differs from current source",
            ));
        }
        let baseline =
            self.host_state_factory(std::slice::from_ref(&profile.selection), &profile.baseline)?;
        Ok(Rc::new(InstalledNormalClockStateFactory {
            profile: current,
            baseline,
            origin: ClockOrigin {
                source: self.host_identity.clone(),
                source_path: self.host_executable.clone(),
                process: std::process::id(),
                thread: std::thread::current().id(),
            },
        }))
    }
}

pub(super) fn resources() -> HostModelResources {
    HostModelResources::default()
}

pub(super) fn state_error(reason: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "normal public Clock state",
        reason.to_string(),
    )
}

impl InstalledNormalClockStateFactory {
    pub(super) fn authenticate_graph(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        self.origin.current().map_err(state_error)?;
        let expected = &self.profile.scenario;
        if graph.world() != &expected.world
            || graph.node_ids().count() != 1
            || graph.owners().count() != 1
            || graph.descriptor(&expected.descriptors[0].id) != Some(&expected.descriptors[0])
            || graph
                .binding(&expected.descriptors[0].id)
                .is_none_or(|binding| binding.compatibility != expected.compatibility[0])
            || graph.owners().ne(expected.owners.iter())
            || !graph.selected_extensions().is_empty()
            || canonical::json_hash("cnp.admission-requirements.v1", graph.requirements())
                .map_err(state_error)?
                != canonical::json_hash("cnp.admission-requirements.v1", &expected.requirements)
                    .map_err(state_error)?
        {
            return Err(state_error("normal Clock complete source graph changed"));
        }
        Ok(())
    }
}

impl HostModelQualification for InstalledNormalClockStateFactory {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        self.origin.current().map_err(|error| OperationFailure {
            effects: crucible_engine::node_contract::EffectKnowledge::None,
            reason: error.to_string(),
        })?;
        if descriptor != &self.profile.scenario.descriptors[0]
            || binding.compatibility != self.profile.scenario.compatibility[0]
            || !matches!(model, HostModel::Clock(_))
        {
            return Err(OperationFailure {
                effects: crucible_engine::node_contract::EffectKnowledge::None,
                reason: "normal Clock actual constructor differs from exact public source".into(),
            });
        }
        // The public profile changes preparation records, never the native
        // initial model/implementation. Reuse the original concrete constructor
        // check only after authenticating the complete new public selection.
        let mut original = binding.clone();
        original.compatibility = self.profile.baseline.compatibility[0].clone();
        self.baseline
            .check_model(model, &self.profile.baseline.descriptors[0], &original)
    }
}

impl NativeWorldFactory for InstalledNormalClockStateFactory {
    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_graph(graph)?;
        let node = &self.profile.selection.node;
        if owner.participant_ids.as_slice() != std::slice::from_ref(node)
            || owner.capture_owner_id != source.owner().owner
            || source.owner().cut != source.runtime().capture_cut
            || source.runtime().schema_version != 1
            || !source.runtime().inputs.is_empty()
            || source
                .runtime()
                .operations
                .iter()
                .any(|operation| operation.route.node != *node)
        {
            return Err(state_error("normal Clock signed owner/runtime/cut differs"));
        }
        let inventory = validate_public_clock_continuation(source, graph, node, resources())
            .map_err(|error| state_error(error.reason))?;
        if inventory.native_model.bytes
            != host_clock_initial_bytes(source.runtime().capture_cut.time_ps.get())
        {
            return Err(state_error(
                "normal Clock captured native integer differs from actual cut",
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
        self.authenticate_graph(graph)?;
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
            || content.get(&self.profile.scenario.descriptors[0].initialization_ref)
                != Some(host_clock_initial_bytes(0).as_slice())
        {
            return Err(state_error(
                "normal Clock full coordinator scope or initial native body differs",
            ));
        }
        crucible_engine::node_scheduling::validate_saved_source(graph, scheduler)
            .map_err(state_error)
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
            .try_fold(source.owner().state.length.get(), |sum, row| {
                sum.checked_add(row.length.get())
            })
            .ok_or_else(|| state_error("normal Clock record reservation overflow"))?;
        if bytes > limits.state.maximum_native_memory_bytes {
            return Err(state_error("normal Clock native record credit exhausted"));
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
        self.authenticate_graph(&graph)?;
        if target.world_binding_hash != *graph.world_binding_hash()
            || target.boundary != archive.manifest().cut
            || target.owners.len() != 1
        {
            return Err(state_error(
                "normal Clock fresh source/target scope differs",
            ));
        }
        // The Core driver stores this empty nonautonomous capsule in its actual
        // reserved supervisor before prepare_owner constructs any model.
        Ok(Box::new(super::state_staging::NormalClockStaging::empty(
            graph,
            archive,
            target.clone(),
            reservations,
            self.clone(),
        )))
    }
}

impl CaptureEvidence for InstalledNormalClockStateFactory {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        self.origin.current().map_err(state_error)?;
        if let Some(object) = self
            .profile
            .scenario
            .content
            .iter()
            .find(|row| &row.reference == reference)
        {
            if object.bytes.len() > maximum {
                return Err(state_error("normal Clock immutable byte credit exhausted"));
            }
            reference.verify(&object.bytes).map_err(state_error)?;
            return Ok(object.bytes.clone());
        }
        self.baseline.content(reference, maximum)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        self.origin.current().map_err(state_error)?;
        let Some(object) = self
            .profile
            .scenario
            .content
            .iter()
            .find(|row| &row.reference == reference)
        else {
            return self.baseline.dependencies(reference, bytes, maximum);
        };
        if object.bytes != bytes {
            return Err(state_error("normal Clock original immutable body changed"));
        }
        if reference.media_type != "application/json" {
            return Ok(Vec::new());
        }
        let value = canonical::parse_json(bytes, crate::node_scenario::MAX_NODE_SCENARIO_BYTES)
            .map_err(state_error)?;
        let mut stack = vec![&value];
        let mut children = Vec::new();
        while let Some(value) = stack.pop() {
            match value {
                serde_json::Value::Object(row)
                    if row.contains_key("hash")
                        && row.contains_key("length")
                        && row.contains_key("media_type") =>
                {
                    if children.len() >= maximum {
                        return Err(state_error("normal Clock dependency credit exhausted"));
                    }
                    let child: ContentRef =
                        serde_json::from_value(value.clone()).map_err(state_error)?;
                    if child != self.origin.source
                        && !self
                            .profile
                            .scenario
                            .content
                            .iter()
                            .any(|known| known.reference == child)
                    {
                        return Err(state_error(
                            "normal Clock immutable dependency has no original source",
                        ));
                    }
                    children.push(child);
                }
                serde_json::Value::Object(row) => stack.extend(row.values()),
                serde_json::Value::Array(rows) => stack.extend(rows),
                _ => {}
            }
        }
        children.sort();
        children.dedup();
        Ok(children)
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(state_error(
            "immutable Clock source lookup cannot issue native owner provenance",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(state_error(
            "immutable Clock source lookup cannot issue coordinator provenance",
        ))
    }
}

impl crate::node_qualification::RetainedMetadataOwned for InstalledNormalClockStateFactory {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            profile,
            baseline,
            origin,
        } = self;
        counter.charge(origin)?;
        counter.charge(profile)?;
        if counter.rc(baseline)? {
            counter.charge(baseline.as_ref())?;
        }
        Ok(())
    }
}
