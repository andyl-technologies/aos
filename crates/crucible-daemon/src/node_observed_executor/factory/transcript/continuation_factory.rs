//! Installed original-source validation for complete conditional replay archives.
//!
//! This private qualification accepts the actual source-enrolled reference pair
//! and the compiled replay implementation. Capture remains conditional and
//! nondeterministic in origin; no physical provider state is reconstructed.

use std::rc::Rc;

use crucible::{
    node_adapters::transcript::authenticate_replay_continuation,
    node_admission::AdmissionEvidence,
    node_contract::{RuntimeSnapshot, SavedRuntimeResult},
    node_scheduling::{SchedulingSnapshot, validate_saved_source},
    node_state::{
        AuthenticatedNativeSource, CaptureEvidence, NativeArchiveLimits, NativeArchiveRecord,
        NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, NativeRestoreStaging,
        NativeWorldFactory, RestoreReservations, StateError, StateErrorCode, StateRequirements,
        VerifiedStateContent,
    },
};
use crucible_node_contract::{CaptureManifest, CapturedOwner};

use super::*;

pub(super) struct ReplayArchiveFactory {
    pub(super) allocation: Rc<cursor_allocation::CursorAllocation>,
}

pub(super) fn state_error(error: impl ToString) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed original replay",
        error.to_string(),
    )
}

impl ReplayArchiveFactory {
    fn check_graph(&self, graph: &AdmittedGraph) -> Result<(), StateError> {
        self.allocation.check_scope().map_err(state_error)?;
        if graph.world() != &self.allocation.profile().scenario.world
            || graph.node_ids().count() != 2
            || self.allocation.profile().bindings.iter().any(|binding| {
                graph
                    .binding(&binding.compatibility.node_id)
                    .is_none_or(|actual| actual.compatibility != binding.compatibility)
            })
        {
            return Err(state_error("complete installed replay world differs"));
        }
        Ok(())
    }
}

impl CaptureEvidence for ReplayArchiveFactory {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        AdmissionEvidence::content(self.allocation.as_ref(), reference, maximum)
            .map_err(state_error)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        reference.verify(bytes).map_err(state_error)?;
        if self.allocation.installed_asset(reference).is_some() {
            return Ok(Vec::new());
        }
        let original = self
            .allocation
            .profile()
            .scenario
            .content
            .iter()
            .find(|object| &object.reference == reference)
            .ok_or_else(|| state_error("immutable object has no original installed source"))?;
        if original.bytes != bytes {
            return Err(state_error("immutable original object bytes differ"));
        }
        // The typed transcript codec embeds its complete original raw objects;
        // source enrollment has already verified that self-contained envelope.
        // Other opaque original bodies are accepted only by exact typed identity.
        if reference.media_type != "application/json" {
            return Ok(Vec::new());
        }
        let value = canonical::parse_json(bytes, 16 * 1024 * 1024).map_err(state_error)?;
        let mut pending = vec![(&value, 0usize)];
        let mut visited = 0usize;
        let mut dependencies = BTreeMap::new();
        while let Some((value, depth)) = pending.pop() {
            visited += 1;
            if depth > 64 || visited > 262_144 {
                return Err(state_error(
                    "installed immutable dependency traversal exceeds finite credit",
                ));
            }
            match value {
                serde_json::Value::Object(object)
                    if object.contains_key("hash")
                        && object.contains_key("length")
                        && object.contains_key("media_type") =>
                {
                    let dependency: ContentRef =
                        serde_json::from_value(value.clone()).map_err(state_error)?;
                    if self.allocation.installed_asset(&dependency).is_none()
                        && !self
                            .allocation
                            .profile()
                            .scenario
                            .content
                            .iter()
                            .any(|object| object.reference == dependency)
                    {
                        return Err(state_error(format!(
                            "installed original dependency is absent: {} {} under {}",
                            dependency.media_type, dependency.hash.digest, reference.hash.digest
                        )));
                    }
                    if !dependencies.contains_key(&dependency) && dependencies.len() >= maximum {
                        return Err(state_error(
                            "installed immutable dependencies exceed credit",
                        ));
                    }
                    dependencies.insert(dependency, ());
                }
                serde_json::Value::Object(object) => {
                    if pending
                        .len()
                        .checked_add(object.len())
                        .is_none_or(|count| count > 262_144)
                    {
                        return Err(state_error(
                            "installed immutable traversal queue exceeds credit",
                        ));
                    }
                    pending.extend(object.values().map(|value| (value, depth + 1)));
                }
                serde_json::Value::Array(array) => {
                    if pending
                        .len()
                        .checked_add(array.len())
                        .is_none_or(|count| count > 262_144)
                    {
                        return Err(state_error(
                            "installed immutable traversal queue exceeds credit",
                        ));
                    }
                    pending.extend(array.iter().map(|value| (value, depth + 1)));
                }
                _ => {}
            }
        }
        Ok(dependencies.into_keys().collect())
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
            "immutable registry does not issue native source provenance",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(state_error(
            "immutable registry does not issue coordinator provenance",
        ))
    }
}

impl NativeWorldFactory for ReplayArchiveFactory {
    fn authenticate_source(
        &self,
        graph: &AdmittedGraph,
        owner: &CapturedOwner,
        source: &AuthenticatedNativeSource<'_>,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        let [node] = owner.participant_ids.as_slice() else {
            return Err(state_error("replay source owner is not exclusive"));
        };
        let actual = authenticate_replay_continuation(source, node)
            .map_err(|error| state_error(error.reason))?;
        let accepted = self
            .allocation
            .source_for(node)
            .ok_or_else(|| state_error("replay source has no enrolled physical origin"))?;
        if actual.transcript().reference() != accepted.reference()
            || actual.transcript().bytes() != accepted.bytes()
            || graph
                .binding(node)
                .is_none_or(|binding| binding.compatibility != actual.binding().compatibility)
            || actual.route().owners.len() != 1
            || actual.route().owners[0].owner != owner.capture_owner_id
            || actual.runtime() != source.runtime()
        {
            return Err(state_error(
                "complete replay source lineage or custody differs",
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
        self.check_graph(graph)?;
        validate_saved_source(graph, scheduler).map_err(state_error)?;
        let owners = scheduler
            .source_owners
            .iter()
            .map(|owner| OwnerIdentity {
                owner: owner.owner.clone(),
                incarnation: owner.incarnation.clone(),
                generation: owner.generation,
            })
            .collect::<Vec<_>>();
        if runtime.source_activation.world_binding_hash != *graph.world_binding_hash()
            || runtime.source_activation.owners != owners
            || runtime.source_activation.generation != scheduler.source_generation
            || runtime.source_activation.activation_id != scheduler.source_activation_id
            || runtime.source_activation.boundary != scheduler.source_boundary
            || runtime.capture_cut != scheduler.capture_cut
            || runtime.capture_ordinal != scheduler.capture_ordinal
        {
            return Err(state_error(
                "complete original runtime and coordinator scope differ",
            ));
        }
        for payload in &scheduler.payload_objects {
            if content.get(&payload.reference) != Some(payload.bytes.as_slice()) {
                return Err(state_error("original retained delivery payload is absent"));
            }
        }
        for operation in &runtime.operations {
            if graph.binding(&operation.route.node).is_none()
                || matches!(operation.result, SavedRuntimeResult::Failed(_))
            {
                return Err(state_error("unsupported original replay operation custody"));
            }
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
        let memory = source
            .owner()
            .state
            .length
            .get()
            .checked_mul(8)
            .ok_or_else(|| state_error("replay reserve overflow"))?;
        if memory > limits.state.maximum_native_memory_bytes {
            return Err(state_error(
                "complete replay state exceeds native memory credit",
            ));
        }
        Ok(RestoreReservations {
            memory_bytes: memory,
            ..RestoreReservations::default()
        })
    }

    fn empty_staging(
        &self,
        _: Rc<AdmittedGraph>,
        _: NativeArchiveRecord,
        _: &ActivationRecord,
        _: RestoreReservations,
        _: NativeArchiveLimits,
    ) -> Result<Box<dyn NativeRestoreStaging>, StateError> {
        Err(state_error(
            "replay restoration consumes preauthenticated owned cursor seals instead of lazy archive paths",
        ))
    }
}
