//! Exact original-to-allocated-replay policy for the closed native reference pair.
//!
//! This policy checks its already accepted signed sources and actual allocated
//! fresh graph. The complete original byte context remains unchanged; only the
//! explicitly selected implementation and operational roster are substituted.

use crucible::{
    node_adapters::transcript::{
        AuthenticatedTranscript, InstalledReplayPolicy, ReplayQualification, TranscriptAction,
        TranscriptError, context_commitment,
    },
    node_admission::AdmittedGraph,
    node_contract::NodeRoute,
};

use super::*;

impl InstalledReplayPolicy for cursor_allocation::CursorAllocation {
    fn qualify(
        &self,
        source: &AuthenticatedTranscript,
        target: &AdmittedGraph,
        route: &NodeRoute,
        context: &[InputPayload],
    ) -> Result<ReplayQualification, TranscriptError> {
        let refuse = |error: NodeObservedError| TranscriptError::Unqualified(error.to_string());
        self.check_scope().map_err(refuse)?;
        // This installed profile executes only the completed quantized native
        // reference trajectory. Other recorded controls remain authentic source
        // data, but must be refused before any fresh readiness or response.
        for record in &source.transcript().records {
            let metadata = record.request.request_metadata()?;
            let response: serde_json::Value = serde_json::from_slice(&record.response_bytes)
                .map_err(|error| TranscriptError::Unqualified(error.to_string()))?;
            let supported = match metadata.action {
                TranscriptAction::Begin => {
                    matches!(
                        metadata.operation,
                        Some(crucible::node_contract::OperationRequest::QuantumBegin { .. })
                    ) && response["kind"] == "submission"
                        && response["value"] == "Accepted"
                }
                // Close retains the original Begin permission, not a newly
                // minted closing grant or changed window.
                TranscriptAction::CloseWindow => {
                    matches!(
                        metadata.operation,
                        Some(crucible::node_contract::OperationRequest::QuantumBegin { .. })
                    ) && response["kind"] == "submission"
                        && serde_json::from_value::<crucible::node_contract::Submission>(
                            response["value"].clone(),
                        )
                        .is_ok_and(|submission| {
                            matches!(
                                submission,
                                crucible::node_contract::Submission::Accepted
                                    | crucible::node_contract::Submission::Refused(_)
                            )
                        })
                }
                TranscriptAction::Complete => response["kind"] == "outcome",
                TranscriptAction::Observe => response["kind"] == "observation",
                TranscriptAction::StageInput => response["kind"] == "input",
                TranscriptAction::Acknowledge => response["kind"] == "acknowledged",
                TranscriptAction::Cancel => false,
            };
            if !supported {
                return Err(TranscriptError::Unqualified(format!(
                    "original control trajectory {:?} response {:?} is unsupported by this installed replay profile",
                    metadata.action, response["kind"]
                )));
            }
        }

        let original = self.source_for(&route.node).ok_or_else(|| {
            TranscriptError::Unqualified("replay node has no accepted original source".into())
        })?;
        let binding = self
            .profile()
            .bindings
            .iter()
            .find(|binding| binding.compatibility.node_id == route.node)
            .ok_or_else(|| {
                TranscriptError::Unqualified("allocated replay binding absent".into())
            })?;
        let owners = self
            .profile()
            .record
            .owners
            .iter()
            .filter(|owner| owner.owner == binding.compatibility.execution_owner.id)
            .cloned()
            .collect::<Vec<_>>();
        if source.reference() != original.reference()
            || source.bytes() != original.bytes()
            || context != original.transcript().origin.context
            || route.owners != owners
            || target.binding(&route.node) != Some(binding)
            || target.world() != &self.profile().scenario.world
            || target.node_ids().count() != self.source().sources.len()
            || self
                .profile()
                .bindings
                .iter()
                .any(|binding| target.binding(&binding.compatibility.node_id) != Some(binding))
        {
            return Err(TranscriptError::Unqualified(
                "changed source, context, peer, clock, horizon or allocated replay owner".into(),
            ));
        }
        let target_binding = canonical::content_ref(
            &canonical::canonical_json(
                &serde_json::to_value(binding)
                    .map_err(|error| TranscriptError::Unqualified(error.to_string()))?,
            )
            .map_err(|error| TranscriptError::Unqualified(error.to_string()))?,
            "application/json",
        )
        .map_err(|error| TranscriptError::Unqualified(error.to_string()))?;
        let source_context = context_commitment(&source.transcript().origin)?;
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.installed-original-replay-association.v1",
            "source":source.reference(), "context":source_context,
            "original_attempt":source.transcript().origin.attempt,
            "original_activation":source.transcript().origin.activation,
            "target_world":target.world_binding_hash(), "target_binding":target_binding,
            "target_route":route,"host":self.host_identity(),
            "applicability":"unchanged full original requests, input bodies, FIFO order and time assignments only",
            "taint":source.transcript().origin.repeatability,
        })).map_err(|error| TranscriptError::Unqualified(error.to_string()))?;
        Ok(ReplayQualification {
            proof: InputPayload {
                reference: canonical::content_ref(&bytes, "application/json")
                    .map_err(|error| TranscriptError::Unqualified(error.to_string()))?,
                bytes,
            },
            source_context,
            target_world: target.world_binding_hash().clone(),
            target_binding,
            target_route: route.clone(),
        })
    }
}
