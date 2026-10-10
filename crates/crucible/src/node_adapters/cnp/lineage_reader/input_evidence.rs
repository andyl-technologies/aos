//! Borrows the actual retained Stage ACK closure before any owned evidence copy.
//!
//! Registered source codec rows select every reachable body. A missing row is
//! refusal, including for apparent leaves; hashing does not install a codec.

use super::{
    control::ReaderState,
    readiness::{refused, unknown},
};
use crate::node_contract::{
    OperationAdmission, OperationFailure, OriginalInputEvidence, OriginalInputLineageLimits,
    OriginalLineageRow, OriginalStagedInput,
};
use crate::node_scheduling::InputPayload;
use crucible_node_contract::ContentRef;
use std::collections::BTreeMap;

impl ReaderState {
    fn validate_staged_scope(
        &self,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
    ) -> Result<(), OperationFailure> {
        self.verify_native_custody().map_err(unknown)?;
        self.validate_evidence_world(original.activation())?;
        let input = self
            .input
            .as_ref()
            .ok_or_else(|| refused("original staged custody unavailable"))?;
        let batch = staged.batch();
        let admitted = original
            .inputs()
            .ok_or_else(|| refused("original completion has no admitted input"))?;
        if !admitted.activation().same_authority(batch.activation())
            || admitted.node() != batch.node()
            || admitted.owners() != batch.owners()
            || admitted.stage_operation() != batch.stage_operation()
            || admitted.batch() != batch.batch()
            || admitted.inventory() != batch.inventory()
            || admitted.cutoff() != batch.cutoff()
            || admitted.deliveries() != batch.deliveries()
            || admitted.payloads() != batch.payloads()
        {
            return Err(refused("original completion input cut differs"));
        }
        let expected = &input.original;
        if !expected.activation().same_authority(batch.activation())
            || !batch.activation().same_authority(original.activation())
            || expected.node() != batch.node()
            || expected.owners() != batch.owners()
            || expected.stage_operation() != batch.stage_operation()
            || expected.batch() != batch.batch()
            || expected.inventory() != batch.inventory()
            || expected.cutoff() != batch.cutoff()
            || expected.deliveries() != batch.deliveries()
            || expected.payloads() != batch.payloads()
            || input.acknowledgement.as_ref() != Some(staged.acknowledgement())
        {
            return Err(refused(
                "original Stage ACK belongs to another retained input",
            ));
        }
        if !batch.deliveries().is_empty() {
            let source = input
                .provenance
                .as_ref()
                .ok_or_else(|| refused("original producer bodies unavailable"))?;
            let supplied = staged
                .provenance()
                .ok_or_else(|| refused("runtime producer bodies unavailable"))?;
            let lineage = self
                .input_lineages
                .get(batch.stage_operation())
                .ok_or_else(|| refused("original producer associations unavailable"))?;
            let supplied_lineage = staged
                .lineage()
                .ok_or_else(|| refused("runtime producer associations unavailable"))?;
            if !source.activation().same_authority(supplied.activation())
                || source.node() != supplied.node()
                || source.stage_operation() != supplied.stage_operation()
                || source.batch() != supplied.batch()
                || source.inventory() != supplied.inventory()
                || source.roots() != supplied.roots()
                || source.objects() != supplied.objects()
                || lineage.publications() != supplied_lineage.publications()
            {
                return Err(refused("original producer proof custody changed"));
            }
        }
        Ok(())
    }

    pub(super) fn read_staged_evidence(
        &self,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalInputEvidence, OperationFailure> {
        self.validate_staged_scope(original, staged)?;
        let root = &staged.acknowledgement().proof_ref;
        let evidence = copy_closure(
            &self.boundary_evidence,
            &self.boundary_dependencies,
            root,
            limits,
        )?;
        self.validate_staged_scope(original, staged)?;
        Ok(evidence)
    }

    pub(super) fn validate_staged_evidence(
        &self,
        original: &OperationAdmission,
        staged: &OriginalStagedInput<'_>,
        evidence: &OriginalInputEvidence,
    ) -> Result<(), OperationFailure> {
        self.validate_staged_scope(original, staged)?;
        let selected = borrowed_closure(
            &self.boundary_evidence,
            &self.boundary_dependencies,
            &staged.acknowledgement().proof_ref,
            OriginalInputLineageLimits::default(),
        )?;
        if evidence.root != staged.acknowledgement().proof_ref
            || selected.len() != evidence.objects.len()
            || selected.len() != evidence.rows.len()
            || selected
                .iter()
                .zip(&evidence.objects)
                .any(|(reference, body)| self.boundary_evidence.get(*reference) != Some(body))
            || selected.iter().zip(&evidence.rows).any(|(reference, row)| {
                *reference != &row.object
                    || self.boundary_dependencies.get(*reference) != Some(&row.dependencies)
            })
        {
            return Err(refused("original Stage ACK closure changed"));
        }
        self.validate_staged_scope(original, staged)
    }
}

fn copy_closure(
    source_objects: &BTreeMap<ContentRef, InputPayload>,
    source_rows: &BTreeMap<ContentRef, Vec<ContentRef>>,
    root: &ContentRef,
    limits: OriginalInputLineageLimits,
) -> Result<OriginalInputEvidence, OperationFailure> {
    let selected = borrowed_closure(source_objects, source_rows, root, limits)?;
    let mut objects = Vec::new();
    let mut rows = Vec::new();
    objects
        .try_reserve_exact(selected.len())
        .map_err(|_| refused("original evidence object reservation"))?;
    rows.try_reserve_exact(selected.len())
        .map_err(|_| refused("original evidence row reservation"))?;
    for reference in selected {
        let source = source_objects
            .get(reference)
            .ok_or_else(|| refused("original evidence body lost"))?;
        let direct = source_rows
            .get(reference)
            .ok_or_else(|| refused("original evidence row lost"))?;
        let mut bytes = Vec::new();
        let mut dependencies = Vec::new();
        bytes
            .try_reserve_exact(source.bytes.len())
            .map_err(|_| refused("original body reservation"))?;
        dependencies
            .try_reserve_exact(direct.len())
            .map_err(|_| refused("original direct-row reservation"))?;
        mark_copy();
        bytes.extend_from_slice(&source.bytes);
        dependencies.extend(direct.iter().cloned());
        objects.push(InputPayload {
            reference: reference.clone(),
            bytes,
        });
        rows.push(OriginalLineageRow {
            object: reference.clone(),
            dependencies,
        });
    }
    Ok(OriginalInputEvidence {
        root: root.clone(),
        objects,
        rows,
    })
}

/// Walks only registered rows using bounded borrowed workspaces. The complete
/// body/edge credit and acyclicity check precede every body or ContentRef copy.
fn borrowed_closure<'a>(
    objects: &'a BTreeMap<ContentRef, InputPayload>,
    rows: &'a BTreeMap<ContentRef, Vec<ContentRef>>,
    root: &'a ContentRef,
    limits: OriginalInputLineageLimits,
) -> Result<Vec<&'a ContentRef>, OperationFailure> {
    let cap = OriginalInputLineageLimits::default();
    if limits.maximum_objects == 0
        || limits.maximum_objects > cap.maximum_objects
        || limits.maximum_bytes == 0
        || limits.maximum_bytes > cap.maximum_bytes
        || limits.maximum_edges > cap.maximum_edges
    {
        return Err(refused("original input evidence credit invalid"));
    }
    let mut done = Vec::new();
    let mut stack = Vec::new();
    done.try_reserve_exact(limits.maximum_objects)
        .map_err(|_| refused("original closure reservation"))?;
    stack
        .try_reserve_exact(limits.maximum_objects)
        .map_err(|_| refused("original closure traversal reservation"))?;
    let mut bytes = 0usize;
    let mut edges = 0usize;
    stack.push((root, 0usize));
    while let Some((reference, index)) = stack.last().copied() {
        let body = objects
            .get(reference)
            .ok_or_else(|| refused("original ACK closure lacks registered body"))?;
        let direct = rows
            .get(reference)
            .ok_or_else(|| refused("original ACK closure lacks registered codec row"))?;
        if index == 0 {
            if body.reference != *reference
                || reference.verify(&body.bytes).is_err()
                || direct.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(refused("original ACK body or direct row invalid"));
            }
            bytes = bytes
                .checked_add(body.bytes.len())
                .filter(|total| *total <= limits.maximum_bytes)
                .ok_or_else(|| refused("original ACK closure body credit exhausted"))?;
            edges = edges
                .checked_add(direct.len())
                .filter(|total| *total <= limits.maximum_edges)
                .ok_or_else(|| refused("original ACK closure edge credit exhausted"))?;
        }
        if let Some(next) = direct.get(index) {
            if let Some(frame) = stack.last_mut() {
                frame.1 += 1;
            }
            if done.contains(&next) {
                continue;
            }
            if stack.iter().any(|(active, _)| *active == next) {
                return Err(refused("original ACK closure is cyclic"));
            }
            if done.len() + stack.len() >= limits.maximum_objects {
                return Err(refused("original ACK closure object credit exhausted"));
            }
            stack.push((next, 0));
        } else {
            stack.pop();
            done.push(reference);
        }
    }
    done.sort_unstable();
    Ok(done)
}

#[cfg(test)]
thread_local! { static COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

fn mark_copy() {
    #[cfg(test)]
    COPIES.with(|copies| copies.set(copies.get() + 1));
}

#[cfg(test)]
#[path = "input_evidence_tests.rs"]
mod tests;
