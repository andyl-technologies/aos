//! Installed controller-scope and original applied native receipt authentication.
//!
//! The independently regenerated selected model owns each controller table and
//! journal. Native records remain historical after a cold branch; only fresh
//! runtime permissions are rebound by the authenticated archive owner.

use super::*;
use crucible::node_contract::{OperationRequest, ProgressEvidence, SavedRuntimeResult};

impl InstalledHostStateFactory {
    pub(super) fn authenticate_fault_scope(
        &self,
        graph: &AdmittedGraph,
        runtime: &RuntimeSnapshot,
        scheduler: &SchedulingSnapshot,
        content: Option<&VerifiedStateContent>,
    ) -> Result<(), StateError> {
        self.check_graph(graph)?;
        if runtime.schema_version != 4
            || runtime.terminal.is_some()
            || !matches!(scheduler.schema_version, 1 | 3)
            || runtime.source_activation.world_binding_hash != *graph.world_binding_hash()
            || runtime.capture_cut != scheduler.capture_cut
            || runtime.capture_ordinal != scheduler.capture_ordinal
            || !self.selections.values().any(|selected| {
                matches!(
                    selected.kind,
                    InstalledNodeKind::HostControlledFaultLink { .. }
                )
            })
        {
            return Err(refusal(
                "selected fault scope lacks complete unchanged coordinator custody",
            ));
        }
        for selected in self.selections.values() {
            if let InstalledNodeKind::HostControlledFaultLink { profile } = &selected.kind {
                let (reference, bytes) = self
                    .objects
                    .get(&profile.program.hash.digest)
                    .filter(|(reference, _)| reference == &profile.program)
                    .ok_or_else(|| refusal("independently installed controller missing"))?;
                reference.verify(bytes).map_err(state_error)?;
                if content.is_some_and(|content| content.get(reference) != Some(bytes.as_slice())) {
                    return Err(refusal(
                        "signed immutable controller differs from installation",
                    ));
                }
                let program: crucible::node_adapters::ControlledFaultProgram =
                    serde_json::from_slice(bytes).map_err(state_error)?;
                program.validate().map_err(|error| refusal(error.reason))?;
            } else if matches!(selected.kind, InstalledNodeKind::HostSemantics { .. }) {
                return Err(refusal(
                    "terminal and fault-controller preservation are distinct editions",
                ));
            }
        }
        for operation in &runtime.operations {
            if let OperationRequest::FaultInjectionV1(request) = &operation.request {
                let selected = self.selection(&operation.route.node)?;
                let InstalledNodeKind::HostControlledFaultLink { profile } = &selected.kind else {
                    return Err(refusal(
                        "original fault operation names a different native owner",
                    ));
                };
                if request.program != profile.program
                    || request.facet_profile.as_str()
                        != crucible::node_adapters::HOST_FAULT_INJECTION_PROFILE
                    || operation.input_batch.is_some()
                {
                    return Err(refusal(
                        "original fault permission differs from installed controller",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn authenticate_fault_journal(
        &self,
        node: &Id,
        controller: &crucible::node_adapters::ControlledFaultLink,
        source: &RuntimeSnapshot,
        content: &VerifiedStateContent,
    ) -> Result<(), StateError> {
        for record in controller.mutation_records() {
            let operation = source
                .operations
                .iter()
                .find(|operation| {
                    operation.operation == record.operation && &operation.route.node == node
                })
                .ok_or_else(|| refusal("applied native mutation lacks original runtime custody"))?;
            let outcome = match &operation.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => outcome,
                _ => {
                    return Err(refusal(
                        "applied native mutation lacks exact completed receipt",
                    ));
                }
            };
            let bytes =
                canonical::canonical_json(&serde_json::to_value(record).map_err(state_error)?)
                    .map_err(state_error)?;
            let reference =
                canonical::content_ref(&bytes, "application/json").map_err(state_error)?;
            if operation.request
                != OperationRequest::FaultInjectionV1(Box::new(record.request.clone()))
                || record.source.world_binding_hash != source.source_activation.world_binding_hash
                || record.node != *node
                || content.get(&reference) != Some(bytes.as_slice())
                || !matches!(&outcome.progress, ProgressEvidence::FaultMutationApplied {
                    reached, receipt, program, decision,
                } if *reached == record.request.at && receipt == &reference
                    && program == &record.request.program && *decision == record.request.decision)
                || !outcome.retained_outputs.is_empty()
                || outcome.scheduling.as_ref().is_none_or(|observation| {
                    observation.proof_ref != reference
                        || observation.reached != record.request.at
                        || !observation.publications.is_empty()
                        || observation.input_progress.is_some()
                })
            {
                return Err(refusal("applied original mutation/context/receipt differs"));
            }
        }
        let recorded: std::collections::BTreeSet<_> = controller
            .mutation_records()
            .iter()
            .map(|record| &record.operation)
            .collect();
        if source.operations.iter().any(|operation| {
            &operation.route.node == node
                && matches!(operation.request, OperationRequest::FaultInjectionV1(_))
                && matches!(
                    operation.result,
                    SavedRuntimeResult::Complete(_) | SavedRuntimeResult::Acknowledged(_)
                )
                && !recorded.contains(&operation.operation)
        }) {
            return Err(refusal(
                "runtime claims a mutation absent from actual native journal",
            ));
        }
        Ok(())
    }
}
