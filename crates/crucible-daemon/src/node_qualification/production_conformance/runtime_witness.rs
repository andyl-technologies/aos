//! Borrows privately constructed original runtime observations for installed sinks.
//!
//! No decoder, cloning or public constructor can turn report metadata into this
//! witness. The fresh runtime completion and exact retained native input closure
//! stay borrowed while installed independent source/oracle policy inspects them.

use crucible::node_contract::{OriginalCompletedOperation, OriginalInputEvidence};
use crucible_node_contract::{ContentRef, canonical};

use super::{
    ExactCompletionObservation, QualificationError, QuantizedCompletionObservation,
    exact::InputView, protocol, staging,
};

/// Borrows the actual source timing family's complete retained observation.
pub enum OriginalCompletionObservation<'a> {
    /// Retains a whole exact completion without staged input assumptions.
    Exact(&'a ExactCompletionObservation),
    /// Retains a whole quantized completion and source-selected native input closure.
    Quantized(&'a QuantizedCompletionObservation),
}

/// Borrows an original completion and report under its same actual runtime custody.
///
/// Only the runner constructs this view. It supplies no execution, publication,
/// ACK, accepted class, ordinary graph or mutable runtime access.
pub struct OriginalCompletionWitness<'a, 'runtime> {
    original: &'a OriginalCompletedOperation<'runtime>,
    observation: OriginalCompletionObservation<'a>,
    native_input: Option<&'a OriginalInputEvidence>,
    reference: &'a ContentRef,
    bytes: &'a [u8],
}

impl<'a, 'runtime> OriginalCompletionWitness<'a, 'runtime> {
    pub(super) fn exact(
        original: &'a OriginalCompletedOperation<'runtime>,
        observation: &'a ExactCompletionObservation,
        reference: &'a ContentRef,
        bytes: &'a [u8],
    ) -> Result<Self, QualificationError> {
        verify_fresh(
            original,
            false,
            None,
            &observation.snapshot_ref,
            &observation.snapshot,
            reference,
            bytes,
        )?;
        Ok(Self {
            original,
            observation: OriginalCompletionObservation::Exact(observation),
            native_input: None,
            reference,
            bytes,
        })
    }

    pub(super) fn quantized(
        original: &'a OriginalCompletedOperation<'runtime>,
        observation: &'a QuantizedCompletionObservation,
        native_input: Option<&'a OriginalInputEvidence>,
        reference: &'a ContentRef,
        bytes: &'a [u8],
    ) -> Result<Self, QualificationError> {
        verify_fresh(
            original,
            true,
            native_input,
            &observation.snapshot_ref,
            &observation.snapshot,
            reference,
            bytes,
        )?;
        if original
            .staged_inputs()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?
            .is_some()
            != native_input.is_some()
        {
            return Err(QualificationError::Refused(
                "changed original input evidence disposition",
            ));
        }
        Ok(Self {
            original,
            observation: OriginalCompletionObservation::Quantized(observation),
            native_input,
            reference,
            bytes,
        })
    }

    /// Borrows the fresh same-token completed admission, outcome and ACK disposition.
    pub fn original(&self) -> &OriginalCompletedOperation<'runtime> {
        self.original
    }

    /// Borrows the complete original observation without copying its bodies.
    pub fn observation(&self) -> &OriginalCompletionObservation<'a> {
        &self.observation
    }

    /// Borrows the same full native input evidence used in the quantized snapshot.
    pub fn native_input(&self) -> Option<&OriginalInputEvidence> {
        self.native_input
    }

    /// Borrows the canonical complete report identity retained for result authentication.
    pub fn reference(&self) -> &ContentRef {
        self.reference
    }

    /// Borrows original canonical report bytes without an exported decoder.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

fn verify_fresh(
    original: &OriginalCompletedOperation<'_>,
    quantized: bool,
    native_input: Option<&OriginalInputEvidence>,
    snapshot_reference: &ContentRef,
    snapshot: &crucible_node_contract::Bytes,
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), QualificationError> {
    snapshot_reference.verify(snapshot.as_slice())?;
    reference.verify(bytes)?;
    let admission = original.admission();
    let input = admission.inputs().map(InputView::from);
    let limit = snapshot.as_slice().len();
    let fresh = if quantized {
        let staged = original
            .staged_inputs()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        let staging = match (staged, native_input) {
            (Some(staged), Some(evidence)) => Some(staging::StagedView::new(staged, evidence)),
            (None, None) => None,
            _ => {
                return Err(QualificationError::Refused(
                    "changed original staging custody",
                ));
            }
        };
        let value = (
            "crucible.original-quantized-completion.v1",
            admission.request(),
            staging::activation_view(admission.activation()),
            input,
            staging,
            original.outcome(),
            original.acknowledged(),
        );
        current_snapshot(&value, limit)?
    } else {
        let value = (
            "crucible.original-exact-completion.v1",
            admission.request(),
            staging::activation_view(admission.activation()),
            input,
            original.outcome(),
            original.acknowledged(),
        );
        current_snapshot(&value, limit)?
    };
    // Count the complete fresh borrowed snapshot before allocation. Matching
    // every byte binds current activation, original batch, native Stage/ACK,
    // producer lineage, permission, outcome and output ACK to this observation.
    if fresh != snapshot.as_slice() {
        return Err(QualificationError::Refused(
            "fresh original completion changed",
        ));
    }
    Ok(())
}

fn current_snapshot(
    value: &impl serde::Serialize,
    limit: usize,
) -> Result<Vec<u8>, QualificationError> {
    protocol::precharge(value, limit)?;
    canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )
    .map_err(Into::into)
}

#[cfg(test)]
#[path = "runtime_witness/tests.rs"]
mod tests;
