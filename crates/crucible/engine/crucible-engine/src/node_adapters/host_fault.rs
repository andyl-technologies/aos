//! Original native coefficient mutation preparation, application and receipt custody.
//!
//! The actual admitted controller fixes timing and topology. Complete native
//! journal and result storage are allocated before changing coefficients. A
//! cached outcome is valid only if the original native journal proves that
//! exact operation was applied; an interrupted preparation is not completion.

use std::collections::BTreeSet;

use super::*;
use crate::node_scheduling::{NativeProducerBound, NativeSchedulingObservation};

impl HostModelNode {
    pub(super) fn begin_fault_mutation(&mut self, original: &OperationAdmission) -> Submission {
        let prepared = self.prepare_fault_mutation(original);
        let (change, completed) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return Submission::Refused(Refusal {
                    reason: error.reason,
                });
            }
        };
        let operation = original.token().operation().clone();
        // Reserve the complete map entry before the setter. Original lookup
        // separately verifies the actual native journal, so this preparatory
        // object cannot become positive completion evidence after an unwind.
        self.completed.insert(operation.clone(), completed);
        let committed = match self.model.as_mut() {
            Some(HostModel::ControlledFaultLink(controller)) => controller.commit_mutation(change),
            _ => Err(failure(
                "prepared native controller disappeared before mutation",
            )),
        };
        match committed {
            Ok(()) => {
                self.activation_authority = Some(Rc::clone(&original.activation.authority));
                Submission::Accepted
            }
            Err(error) => {
                self.completed.remove(&operation);
                Submission::Refused(Refusal {
                    reason: error.reason,
                })
            }
        }
    }

    fn prepare_fault_mutation(
        &mut self,
        original: &OperationAdmission,
    ) -> Result<
        (
            super::super::faulted_link::controlled::PreparedFaultMutation,
            Completed,
        ),
        OperationFailure,
    > {
        let OperationRequest::FaultInjectionV1(request) = original.request() else {
            return Err(failure(
                "native fault mutation requires explicit operation edition",
            ));
        };
        if self.quarantined
            || !self.same_world(original.activation())
            || original.token().route() != &self.route
            || !self.facets.contains(&FacetKind::FaultInjection)
            || request.at != self.boundary
            || original.inputs().is_some()
            || self.completed.len() >= self.limits.maximum_operations
            || self.completed.contains_key(original.token().operation())
            || self.failed.contains_key(original.token().operation())
            || self
                .staged
                .as_ref()
                .is_some_and(|staged| staged.consumed != staged.original.deliveries().len())
        {
            return Err(failure(
                "fault mutation lacks unchanged current owner/input custody",
            ));
        }
        let change = match self.model.as_mut() {
            Some(HostModel::ControlledFaultLink(controller)) => {
                controller.prepare_mutation(original)?
            }
            _ => {
                return Err(failure(
                    "selected native model does not admit controller mutations",
                ));
            }
        };
        let prepared_bytes = change
            .tables
            .iter()
            .try_fold(change.body.bytes.len(), |bytes, object| {
                bytes.checked_add(object.bytes.len())
            })
            .ok_or_else(|| failure("original fault proof byte accounting overflow"))?;
        let retained_bytes = self
            .completed
            .values()
            .flat_map(|completed| &completed.evidence)
            .try_fold(prepared_bytes, |bytes, object| {
                bytes.checked_add(object.bytes.len())
            });
        if retained_bytes.is_none_or(|bytes| bytes > self.limits.maximum_capture_bytes) {
            return Err(failure(
                "original fault receipt lacks complete native byte credits",
            ));
        }
        let proof = change.body.reference.clone();
        let outcome = OperationOutcome {
            operation: original.token().operation().clone(),
            node: self.route.node.clone(),
            owners: self.route.owners.clone(),
            progress: ProgressEvidence::FaultMutationApplied {
                reached: self.boundary,
                receipt: proof.clone(),
                program: request.program.clone(),
                decision: request.decision,
            },
            retained_outputs: Vec::new(),
            scheduling: Some(NativeSchedulingObservation {
                node: self.route.node.clone(),
                owners: self.route.owners.clone(),
                reached: self.boundary,
                closed_prefix: self.boundary,
                bounds: vec![NativeProducerBound {
                    producer: self.route.node.clone(),
                    bound: self.output_bound(),
                    proof_ref: proof.clone(),
                }],
                publications: Vec::new(),
                input_progress: None,
                external_inputs: Vec::new(),
                proof_ref: proof,
            }),
        };
        let mut evidence = Vec::new();
        evidence
            .try_reserve_exact(change.tables.len() + 1)
            .map_err(|_| failure("complete original fault proof credit unavailable"))?;
        evidence.push(change.body.clone());
        evidence.extend(change.tables.iter().cloned());
        let completed = Completed {
            original: original.clone(),
            outcome,
            capture: None,
            acknowledged: false,
            evidence,
        };
        Ok((change, completed))
    }

    pub(super) fn validate_original_fault_result(
        &self,
        completed: &Completed,
    ) -> Result<(), OperationFailure> {
        let OperationRequest::FaultInjectionV1(request) = completed.original.request() else {
            return Ok(());
        };
        let Some(HostModel::ControlledFaultLink(controller)) = self.model.as_ref() else {
            return Err(unknown_fault_result());
        };
        let record = controller
            .original_mutation(completed.original.token().operation())
            .ok_or_else(unknown_fault_result)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(record).map_err(|_| unknown_fault_result())?,
        )
        .map_err(|_| unknown_fault_result())?;
        let proof = canonical::content_ref(&bytes, "application/json")
            .map_err(|_| unknown_fault_result())?;
        // Fresh handles retain the authenticated original native context. Only
        // the local admission/owner scaffold is rebound by unchanged restore;
        // source activation and native receipt bytes are never rewritten.
        if record.request != **request
            || record.source.world_binding_hash != self.world_hash
            || record.node != self.route.node
            || record
                .owners
                .iter()
                .map(|owner| &owner.owner)
                .collect::<BTreeSet<_>>()
                != self
                    .route
                    .owners
                    .iter()
                    .map(|owner| &owner.owner)
                    .collect::<BTreeSet<_>>()
            || !matches!(&completed.outcome.progress, ProgressEvidence::FaultMutationApplied { receipt, .. } if receipt == &proof)
            || !completed
                .evidence
                .iter()
                .any(|object| object.reference == proof && object.bytes == bytes)
        {
            return Err(unknown_fault_result());
        }
        Ok(())
    }
}

fn unknown_fault_result() -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: "original fault result lacks actual applied native journal custody".into(),
    }
}
