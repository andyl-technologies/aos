//! Reads the exact stopped receipt closure of a closed locally owned Clock.
//!
//! Only the Clock's existing receipt codec declares these two children. Staged
//! input inventories and other host models need their own complete provenance
//! codecs; this reader supplies no fallback for those dependencies.

use super::*;
use crate::node_scheduling::InputPayload;

impl HostModelNode {
    fn closed_clock_objects(
        &self,
        activation: &WorldActivation,
    ) -> Result<[InputPayload; 3], OperationFailure> {
        if !self.same_world(activation)
            || self.quarantined
            || !matches!(self.model, Some(HostModel::Clock(_)))
            || self.staged.is_some()
            || !self.input_history.is_empty()
            || !self.pending_causes.is_empty()
        {
            return Err(failure("closed Clock original proof custody unavailable"));
        }
        state::state_receipt_objects(self)
    }

    pub(super) fn read_closed_clock_evidence(
        &self,
        activation: &WorldActivation,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        if references.len() > 3
            || references
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != references.len()
        {
            return Err(failure("closed Clock proof roster differs"));
        }
        let originals = self.closed_clock_objects(activation)?;
        let mut total = 0usize;
        for reference in references {
            let object = originals
                .iter()
                .find(|object| &object.reference == reference)
                .ok_or_else(|| failure("closed Clock original proof body absent or changed"))?;
            total = total
                .checked_add(object.bytes.len())
                .ok_or_else(|| failure("closed Clock proof geometry overflowed"))?;
        }
        if total > maximum_bytes {
            return Err(failure("closed Clock proof byte credit exhausted"));
        }

        // Reserve all selected roles before copying any original body.
        let mut output = Vec::new();
        output
            .try_reserve_exact(references.len())
            .map_err(|_| failure("closed Clock proof role credit unavailable"))?;
        for reference in references {
            let object = originals
                .iter()
                .find(|object| &object.reference == reference)
                .ok_or_else(|| failure("closed Clock original proof role changed"))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(object.bytes.len())
                .map_err(|_| failure("closed Clock proof byte reservation unavailable"))?;
            bytes.extend_from_slice(&object.bytes);
            output.push(InputPayload {
                reference: object.reference.clone(),
                bytes,
            });
        }
        Ok(output)
    }

    pub(super) fn closed_clock_dependencies(
        &self,
        activation: &WorldActivation,
        root: &ContentRef,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        let originals = self.closed_clock_objects(activation)?;
        let total = originals
            .iter()
            .try_fold(0usize, |total, object| {
                total.checked_add(object.bytes.len())
            })
            .ok_or_else(|| failure("closed Clock complete proof geometry overflowed"))?;
        if root != &originals[0].reference
            || limits.maximum_objects < originals.len()
            || limits.maximum_bytes < total
        {
            return Err(failure(
                "closed Clock original root or complete proof credit differs",
            ));
        }
        Ok(originals[1..]
            .iter()
            .map(|object| object.reference.clone())
            .collect())
    }
}
