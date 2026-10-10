//! Once-owned original condition bodies and per-operation custody indexes.
//!
//! Each original operation retains its exact evidence-reference inventory.
//! Bodies live once under the native node's ownership until authentic cleanup;
//! a historical reference cannot retrieve evidence from another operation.

use super::*;
use crate::node_scheduling::InputPayload;

impl HostModelNode {
    pub(super) fn pooled_condition_objects(&self) -> bool {
        matches!(self.model.as_ref(), Some(HostModel::ConditionObserver(_)))
    }

    pub(super) fn check_condition_object_credit(
        &self,
        evidence: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        let mut bodies: BTreeMap<_, _> = self
            .condition_objects
            .iter()
            .map(|(reference, object)| (reference, object.bytes.as_slice()))
            .collect();
        for object in evidence {
            object
                .reference
                .verify(&object.bytes)
                .map_err(|error| failure(&error.to_string()))?;
            if let Some(original) = bodies.insert(&object.reference, &object.bytes)
                && original != object.bytes.as_slice()
            {
                return Err(failure("condition original pooled body changed"));
            }
        }
        let bytes = bodies
            .values()
            .try_fold(0usize, |count, body| count.checked_add(body.len()))
            .ok_or_else(|| failure("condition original pooled body size overflow"))?;
        let maximum_objects = condition_state::maximum_objects(self.limits.maximum_operations)?;
        let mut hashes = std::collections::BTreeSet::new();
        if bodies.len() > maximum_objects
            || bytes > self.limits.maximum_capture_bytes
            || bodies
                .keys()
                .any(|reference| !hashes.insert(&reference.hash))
        {
            return Err(failure("condition original pooled body credit exhausted"));
        }
        Ok(())
    }

    pub(super) fn retain_condition_objects(
        &mut self,
        operation: &Id,
        evidence: Vec<InputPayload>,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        if !self.pooled_condition_objects() {
            return Ok(evidence);
        }
        if self.condition_operation_objects.contains_key(operation)
            || self.condition_operation_objects.len() >= self.limits.maximum_operations
        {
            return Err(failure(
                "condition original operation object inventory reused or exhausted",
            ));
        }
        self.check_condition_object_credit(&evidence)?;
        let mut references = Vec::new();
        for object in evidence {
            references.push(object.reference.clone());
            // Move first ownership into the store; later identical bodies are
            // released rather than retained in every operation's envelope.
            self.condition_objects
                .entry(object.reference.clone())
                .or_insert(object);
        }
        self.condition_operation_objects
            .insert(operation.clone(), references);
        Ok(Vec::new())
    }

    pub(super) fn original_condition_objects<'a>(
        &'a self,
        operation: &Id,
        completed: &'a Completed,
    ) -> Result<Vec<&'a InputPayload>, OperationFailure> {
        if !self.pooled_condition_objects() {
            return Ok(completed.evidence.iter().collect());
        }
        let references = self
            .condition_operation_objects
            .get(operation)
            .ok_or_else(|| failure("condition original operation object association omitted"))?;
        references
            .iter()
            .map(|reference| {
                self.condition_objects
                    .get(reference)
                    .ok_or_else(|| failure("condition original owned evidence body omitted"))
            })
            .collect()
    }
}
