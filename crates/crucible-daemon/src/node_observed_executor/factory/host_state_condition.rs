//! Installed whole-world original stopped-condition source authentication.
//!
//! The independently regenerated catalog owns the model program and immutable
//! storage/script inputs. Signed native and coordinator bodies remain original
//! historical facts; only actual isolated reconstruction supplies fresh owners.

use super::*;
use crucible::node_contract::{ConditionPublicationState, SavedConditionStop, SavedRuntimeResult};

#[path = "host_state_condition_inputs.rs"]
mod inputs;

impl InstalledHostStateFactory {
    pub(super) fn condition_world(&self) -> bool {
        self.selections
            .values()
            .filter(|selected| {
                matches!(
                    selected.kind,
                    InstalledNodeKind::HostConditionDebugPreserving { .. }
                )
            })
            .count()
            == 1
            && self.selections.values().all(|selected| {
                matches!(
                    selected.kind,
                    InstalledNodeKind::HostConditionDebugPreserving { .. }
                        | InstalledNodeKind::HostClock
                        | InstalledNodeKind::HostScripted { .. }
                        | InstalledNodeKind::HostIo {
                            profile: super::super::io::InstalledHostIoProfile::Block { .. }
                        }
                )
            })
    }

    pub(super) fn authenticate_condition_scope(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: Option<&VerifiedStateContent>,
    ) -> Result<SavedConditionStop, StateError> {
        self.check_graph(graph)?;
        let saved = runtime
            .condition_stop
            .as_ref()
            .ok_or_else(|| refusal("condition original Stop context absent"))?;
        if !self.condition_world()
            || runtime.schema_version != 6
            || scheduler.schema_version != 4
            || scheduler.original_epochs.is_some()
            || runtime.terminal.is_some()
            || !scheduler.reservations.is_empty()
            || !scheduler.external_closed_prefixes.is_empty()
            || saved.record.source != runtime.source_activation
            || saved.record.cut != runtime.capture_cut
            || scheduler.capture_cut != runtime.capture_cut
            || scheduler.capture_ordinal != runtime.capture_ordinal
            || !saved.submitted
            || !saved.acknowledged
            || saved.resumed
            || saved.resume_operation.is_some()
            || saved.resume_receipt.is_some()
            || saved.resume_publication.is_some()
            || saved.publication != Some(ConditionPublicationState::Committed)
            || !matches!(
                self.selection(&saved.record.node)?.kind,
                InstalledNodeKind::HostConditionDebugPreserving { .. }
            )
        {
            return Err(refusal(
                "condition original complete acknowledged stopped scope differs",
            ));
        }
        crucible::node_scheduling::validate_saved_source(graph, scheduler).map_err(state_error)?;
        let mut marker = serde_json::to_value(scheduler).map_err(state_error)?;
        let fields = marker
            .as_object_mut()
            .ok_or_else(|| refusal("condition scheduler is not an object"))?;
        fields.remove("capture_ordinal");
        fields.remove("schema_version");
        fields.insert(
            "format".into(),
            "crucible.condition-stop-coordinator".into(),
        );
        fields.insert("version".into(), 1.into());
        if canonical::canonical_json(&marker).map_err(state_error)?
            != saved.record.scheduler.as_slice()
        {
            return Err(refusal(
                "condition original scheduled payload or FIFO context changed",
            ));
        }
        let nodes: Vec<_> = graph.node_ids().cloned().collect();
        if saved
            .record
            .native
            .iter()
            .map(|inventory| inventory.node.clone())
            .collect::<Vec<_>>()
            != nodes
            || saved.record.native.iter().any(|inventory| {
                inventory.boundary != runtime.capture_cut
                    || inventory.owners.is_empty()
                    || inventory
                        .owners
                        .iter()
                        .any(|owner| !runtime.source_activation.owners.contains(owner))
            })
        {
            return Err(refusal("condition original whole native roster changed"));
        }
        let original = runtime
            .operations
            .iter()
            .find(|operation| operation.operation == saved.record.operation)
            .ok_or_else(|| refusal("condition original native Stop operation absent"))?;
        if !matches!(original.result, SavedRuntimeResult::Acknowledged(_))
            || original.route.node != saved.record.node
        {
            return Err(refusal("condition original native Stop ACK differs"));
        }
        if let Some(content) = content {
            for object in saved.record.dependency_objects() {
                let bytes = content.get(&object.reference).ok_or_else(|| {
                    refusal("condition original stopped native body missing from signed closure")
                })?;
                object.reference.verify(bytes).map_err(state_error)?;
                if !object.bytes.is_empty() && bytes != object.bytes.as_slice() {
                    return Err(refusal(
                        "condition original stopped native body missing from signed closure",
                    ));
                }
            }
            let report = saved
                .report
                .as_ref()
                .ok_or_else(|| refusal("condition original report absent"))?;
            if content.get(&report.reference) != Some(report.bytes.as_slice()) {
                return Err(refusal("condition original report body changed"));
            }
        }
        Ok(saved.clone())
    }
}

#[cfg(test)]
pub(super) fn verify_required_input_key(body: &[u8]) -> Result<(), StateError> {
    inputs::verify_required_input_key(body)
}
