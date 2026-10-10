//! Borrows complete original staged inputs beneath actual completion custody.
//!
//! This projection contains no deserialization or caller-issued permission. The
//! owning runtime selects it through the original completed operation, retaining
//! the actual stage ACK and producer lineage independently of payload equality.

use super::*;
use crate::node_scheduling::{InputCustodyCommit, NativeInputAcknowledgement, RuntimeInputBatch};
use crucible_node_contract::Validate;

/// Borrows source-authenticated original producer and native staging custody.
///
/// A borrow does not stage, consume, acknowledge or retire native work. The
/// original runtime owns every referenced body for the lifetime of this view.
pub struct OriginalStagedInput<'a> {
    batch: &'a RuntimeInputBatch,
    provenance: Option<&'a InputProvenanceClosure>,
    lineage: Option<&'a OriginalInputLineage>,
    acknowledgement: &'a NativeInputAcknowledgement,
    coordinator_commit: Option<&'a InputCustodyCommit>,
    committed: bool,
}

impl OriginalStagedInput<'_> {
    /// Borrows the complete original frozen input cut.
    pub fn batch(&self) -> &RuntimeInputBatch {
        self.batch
    }

    /// Borrows authenticated roots and complete original producer proof bodies.
    pub fn provenance(&self) -> Option<&InputProvenanceClosure> {
        self.provenance
    }

    /// Borrows each ordered source-original publication association and body row.
    pub fn lineage(&self) -> Option<&OriginalInputLineage> {
        self.lineage
    }

    /// Borrows the actual original native staging acknowledgement.
    pub fn acknowledgement(&self) -> &NativeInputAcknowledgement {
        self.acknowledgement
    }

    /// Borrows the coordinator's original staging commitment, when retained.
    pub fn coordinator_commit(&self) -> Option<&InputCustodyCommit> {
        self.coordinator_commit
    }

    /// Reports whether staging locks were released under that original commit.
    ///
    /// This is buffer-transfer custody, separate from modeled input consumption.
    pub fn committed(&self) -> bool {
        self.committed
    }
}

impl NodeRuntime {
    pub(super) fn observe_original_staged_input(
        &self,
        admission: &OperationAdmission,
    ) -> Result<Option<OriginalStagedInput<'_>>, RuntimeError> {
        let Some(input) = admission.inputs() else {
            return Ok(None);
        };
        let retained = self
            .input_batches
            .get(input.stage_operation())
            .ok_or(RuntimeError::ForeignAuthority)?;
        let original = &retained.batch;
        if !original.activation().same_authority(admission.activation())
            || !original.activation().same_authority(input.activation())
            || original.node() != &admission.token().route().node
            || original.owners() != admission.token().route().owners
            || !same_batch(original, input)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if retained.failure.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let acknowledgement = retained
            .acknowledgement
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?;
        if acknowledgement.node != *original.node()
            || acknowledgement.stage_operation != *original.stage_operation()
            || acknowledgement.batch != *original.batch()
            || acknowledgement.owners != original.owners()
            || acknowledgement.cutoff != original.cutoff()
            || acknowledgement.inventory != *original.inventory()
            || acknowledgement.proof_ref.validate().is_err()
            || acknowledgement.proof_ref.length.get() == 0
        {
            return Err(RuntimeError::InvalidReceipt);
        }

        // Nonempty delivery cannot be certified by payload equality or a proof
        // root alone. Both original authenticated body inventories must survive.
        if !original.deliveries().is_empty() {
            let provenance = retained
                .provenance
                .as_ref()
                .ok_or(RuntimeError::UnsupportedFacet)?;
            let lineage = retained
                .lineage
                .as_ref()
                .ok_or(RuntimeError::UnsupportedFacet)?;
            if !provenance
                .activation()
                .same_authority(original.activation())
                || provenance.node() != original.node()
                || provenance.stage_operation() != original.stage_operation()
                || provenance.batch() != original.batch()
                || provenance.inventory() != original.inventory()
                || !same_batch(lineage.original(), original)
                || lineage.publications().len() != original.deliveries().len()
                || provenance.roots().is_empty()
                || provenance.objects().is_empty()
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        if let Some(commit) = &retained.commit {
            if !commit.activation().same_authority(original.activation())
                || commit.node() != original.node()
                || commit.stage_operation() != original.stage_operation()
                || commit.batch() != original.batch()
                || commit.inventory() != original.inventory()
                || commit.cutoff() != original.cutoff()
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        } else if retained.committed {
            return Err(RuntimeError::InvalidReceipt);
        }

        Ok(Some(OriginalStagedInput {
            batch: original,
            provenance: retained.provenance.as_ref(),
            lineage: retained.lineage.as_ref(),
            acknowledgement,
            coordinator_commit: retained.commit.as_ref(),
            committed: retained.committed,
        }))
    }
}

fn same_batch(left: &RuntimeInputBatch, right: &RuntimeInputBatch) -> bool {
    left.activation().same_authority(right.activation())
        && left.node() == right.node()
        && left.stage_operation() == right.stage_operation()
        && left.batch() == right.batch()
        && left.owners() == right.owners()
        && left.cutoff() == right.cutoff()
        && left.inventory() == right.inventory()
        && left.deliveries() == right.deliveries()
        && left.payloads() == right.payloads()
}
