//! Authenticated bounded byte retrieval for original completed operation evidence.

use std::collections::BTreeSet;

use crucible_node_contract::{ContentRef, U64, Validate};

use super::*;
use crate::{node_contract::ProgressEvidence, node_scheduling::InputPayload};

impl NodeRuntime {
    /// Reads original immutable native evidence before or after its output ACK.
    ///
    /// Every requested object must belong to the original validated completion.
    /// Supporting providers retain the same bytes under their native capture
    /// and supervision contract; successful read confers no execution authority.
    /// Empty requests return no objects without invoking a native evidence hook.
    ///
    /// # Errors
    /// Refuses foreign tokens, outstanding or failed operations, changed routes,
    /// unrelated or repeated references, count or aggregate byte overruns,
    /// unsupported native retrieval and unauthenticated or corrupt original bytes.
    pub fn operation_evidence(
        &mut self,
        token: &OperationToken,
        references: &[ContentRef],
        maximum_bytes: U64,
    ) -> Result<Vec<InputPayload>, RuntimePollFailure> {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        self.checked_route(&token.route.node)
            .map_err(RuntimePollFailure::Admission)?;
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        let outcome = match &entry.result {
            RetainedResult::Complete(outcome) | RetainedResult::Acknowledged(outcome) => outcome,
            _ => {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ));
            }
        };

        let allowed = outcome_references(outcome);
        let unique: BTreeSet<_> = references.iter().collect();
        if references.len() > self.limits.maximum_retained_outputs
            || unique.len() != references.len()
            || references
                .iter()
                .any(|reference| !allowed.contains(reference))
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        let mut total_bytes = 0_u64;
        for reference in references {
            reference
                .validate()
                .map_err(|_| RuntimePollFailure::Admission(RuntimeError::InvalidReceipt))?;
            total_bytes = total_bytes
                .checked_add(reference.length.get())
                .ok_or(RuntimePollFailure::Admission(RuntimeError::ResourceLimit))?;
        }
        if total_bytes > maximum_bytes.get() || usize::try_from(total_bytes).is_err() {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }
        if references.is_empty() {
            return Ok(Vec::new());
        }

        let admission = entry.admission.clone();
        let handle = self
            .nodes
            .get(&token.route.node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let objects = match handle.read_operation_evidence(&admission, references) {
            Ok(objects) => objects,
            Err(failure) => {
                if failure.effects != EffectKnowledge::None {
                    self.contain_roster(token.route());
                }
                return Err(RuntimePollFailure::Native(failure));
            }
        };
        let valid = objects.len() == references.len()
            && objects.iter().zip(references).all(|(object, requested)| {
                &object.reference == requested && requested.verify(&object.bytes).is_ok()
            })
            && handle
                .validate_operation_evidence(&admission, references, &objects)
                .is_ok();
        if !valid {
            self.contain_roster(token.route());
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        Ok(objects)
    }
}

fn outcome_references(outcome: &OperationOutcome) -> BTreeSet<&ContentRef> {
    let mut references = BTreeSet::new();
    match &outcome.progress {
        ProgressEvidence::Quantized { closure, .. } => {
            references.extend([
                &closure.close_receipt,
                &closure.output_inventory,
                &closure.pending_inventory,
                &closure.clock_evidence,
            ]);
        }
        ProgressEvidence::Paused { stop_receipt, .. } => {
            references.insert(stop_receipt);
        }
        ProgressEvidence::AssertionsFinalized {
            barrier, report, ..
        } => {
            references.extend([barrier, report]);
        }
        ProgressEvidence::Exact { .. } | ProgressEvidence::Administrative => {}
    }
    if let Some(observation) = &outcome.scheduling {
        references.insert(&observation.proof_ref);
        references.extend(observation.bounds.iter().map(|bound| &bound.proof_ref));
        references.extend(
            observation
                .publications
                .iter()
                .map(|publication| &publication.payload),
        );
        if let Some(progress) = &observation.input_progress {
            references.insert(&progress.proof_ref);
        }
        for inventory in &observation.external_inputs {
            references.insert(&inventory.proof_ref);
            for input in &inventory.inputs {
                references.extend([&input.payload, &input.provenance_ref]);
            }
        }
    }
    references
}
