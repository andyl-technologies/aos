//! Retains Bootstrap18 proof attachment, full DOM and canonical request bytes.
//!
//! ```text
//! assigned unsigned original + typed proof -> proof Value -> same sealed original
//! same sealed original -> full Envelope DOM -> retained canonical literal
//! ```
//!
//! These are DATA transformations. The defining Source must independently fund
//! the complete holder and authenticate its private signing purpose. No MAC,
//! SDK assignment, original deadline or transport effect is authenticated here.

use super::*;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use serde_json::Value;
use std::{io::Write, mem::size_of};

/// Names the last entered sealed-request materialization operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketNativeImport18BootstrapSealingStep {
    /// Serializes the typed proof into its separately retained Value.
    ProofValue,
    /// Attaches that Value to the same retained unsigned original.
    Attach,
    /// Serializes the complete sealed original into an independently owned DOM.
    EnvelopeValue,
    /// Writes canonical bytes into the retained literal bank.
    Literal,
}

/// Preserves the refused constructor without allocating diagnostic text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketNativeImport18BootstrapSealingFailure {
    /// Reports failure of the typed proof's Value serializer.
    ProofValue,
    /// Reports failure of the complete Envelope's Value serializer.
    EnvelopeValue,
    /// Reports failure of the authoritative canonical writer.
    Literal,
}

/// Retains independently derived request materialization demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeImport18BootstrapSealingRowData {
    axes: [usize; 3],
}

impl PacketNativeImport18BootstrapSealingRowData {
    /// Returns retained, simultaneous transient and fixed-control requested bytes.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }
}

/// Owns moved inputs and every initialized materialization prefix after refusal.
pub struct PacketNativeImport18BootstrapSealingData {
    row: PacketNativeImport18BootstrapSealingRowData,
    assignment: Option<PacketNativeImport18BootstrapAssignmentData>,
    proof: Option<PacketNativeImport18BootstrapAckProof>,
    proof_value: Option<Value>,
    envelope_value: Option<Value>,
    literal: Option<Vec<u8>>,
    step: Option<PacketNativeImport18BootstrapSealingStep>,
    failure: Option<PacketNativeImport18BootstrapSealingFailure>,
    sealed: bool,
    failed: bool,
}

/// Borrows actual request construction banks without lending protocol authority.
pub struct PacketNativeImport18BootstrapSealingHistoryData<'a> {
    /// Preserves the exact independently admitted materialization row.
    pub requested_storage: [usize; 3],
    /// Borrows the same moved assignment, including its original Envelope.
    pub assignment: Option<PacketNativeImport18BootstrapAssignmentHistoryData<'a>>,
    /// Borrows the moved typed proof, including its actual spare capacities.
    pub proof: Option<&'a PacketNativeImport18BootstrapAckProof>,
    /// Borrows the proof Value, or its retained null root after attachment.
    pub proof_value: Option<&'a Value>,
    /// Borrows the separately owned complete sealed Envelope DOM.
    pub envelope_value: Option<&'a Value>,
    /// Borrows the actual canonical bank, including any failed write prefix.
    pub literal: Option<&'a Vec<u8>>,
    /// Reports the last entered operation independently of its outcome.
    pub step: Option<PacketNativeImport18BootstrapSealingStep>,
    /// Preserves a fixed serializer/writer refusal without diagnostic allocation.
    pub failure: Option<PacketNativeImport18BootstrapSealingFailure>,
    /// Reports structural materialization, without authenticating the proof MAC.
    pub sealed: bool,
    /// Reports a spent/refused attempt independently of retained banks.
    pub failed: bool,
}

impl PacketNativeImport18BootstrapSealingData {
    /// Borrows every actual moved input and partial output without cloning them.
    pub fn borrowed_history_data(&self) -> PacketNativeImport18BootstrapSealingHistoryData<'_> {
        PacketNativeImport18BootstrapSealingHistoryData {
            requested_storage: self.row.axes,
            assignment: self
                .assignment
                .as_ref()
                .map(PacketNativeImport18BootstrapAssignmentData::borrowed_history_data),
            proof: self.proof.as_ref(),
            proof_value: self.proof_value.as_ref(),
            envelope_value: self.envelope_value.as_ref(),
            literal: self.literal.as_ref(),
            step: self.step,
            failure: self.failure,
            sealed: self.sealed,
            failed: self.failed,
        }
    }

    /// Counts the moved assignment and every surviving bank's actual capacity.
    ///
    /// # Errors
    /// Refuses checked metadata exhaustion or unsupported backing layouts.
    pub fn retained_requested_bytes_data(&self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_retained_into_data(&mut observer)?;
        sum(&[
            size_of::<Self>(),
            requested_metadata_backing_storage_data(&observer.finish())?,
        ])
    }

    pub(crate) fn observe_retained_into_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            row: _,
            assignment,
            proof,
            proof_value,
            envelope_value,
            literal,
            step: _,
            failure: _,
            sealed: _,
            failed: _,
        } = self;
        if let Some(assignment) = assignment {
            assignment.observe_retained_into_data(observer)?;
        }
        if let Some(proof) = proof {
            observe_proof(proof, observer)?;
        }
        observer.observe(proof_value)?;
        observer.observe(envelope_value)?;
        observer.observe(literal)?;
        Ok(())
    }
}

/// Quotes actual moved inputs and independently owned closed serialization banks.
///
/// This row includes the moved assignment; its old retained component must not
/// also be counted as a surviving separate owner. The typed proof is charged at
/// its actual capacities, independently of its extension Value, Envelope DOM and
/// literal. SDK cloning, publication and Source completion remain separate work.
/// `maximum` restricts the derived demand and supplies no allocation allowance.
///
/// # Errors
/// Refuses an incomplete/nonempty assignment, malformed proof, checked layout
/// overflow or derived demand exceeding the restriction.
pub fn native_import18_bootstrap_sealing_quote_data(
    assignment: &PacketNativeImport18BootstrapAssignmentData,
    proof: &PacketNativeImport18BootstrapAckProof,
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapSealingRowData, ProviderError> {
    let history = assignment.borrowed_history_data();
    if !history.assigned
        || history.failed
        || !history.original.ok_or_else(invalid)?.extensions.is_empty()
    {
        return Err(invalid());
    }
    proof.validate_data()?;
    let projection = native_import18_bootstrap_envelope_projection_data(maximum)?;
    let request = projection.serialization_requested_bytes_data()[0];
    let proof_shape = native_import18_bootstrap_ack_projection_data(maximum)?;
    let proof_work = proof_shape.serialization_requested_bytes_data()[1];
    let mut observer = MetadataObserver::new();
    assignment.observe_retained_into_data(&mut observer)?;
    observe_proof(proof, &mut observer)?;
    let retained = sum(&[
        size_of::<PacketNativeImport18BootstrapSealingData>(),
        requested_metadata_backing_storage_data(&observer.finish())?,
        // One bank bounds the extension added to the original; a second bank
        // independently bounds the entire retained Envelope DOM. This also
        // covers the proof Value before it moves into that extension.
        projection.retained_value_backing_bytes_data()[0],
        projection.retained_value_backing_bytes_data()[0],
        request[2],
    ])?;
    let transient = sum(&[
        request[0],
        proof_work[0],
        proof_shape.bytes_formatter_temporary_data(),
        size_of::<PacketNativeImport18BootstrapSealingData>(),
        size_of::<Option<PacketNativeImport18BootstrapSealingData>>(),
        size_of::<PacketNativeImport18BootstrapAssignmentData>(),
        size_of::<Option<PacketNativeImport18BootstrapAssignmentData>>(),
        size_of::<PacketNativeImport18BootstrapAckProof>(),
        size_of::<Option<PacketNativeImport18BootstrapAckProof>>(),
        size_of::<Value>(),
        size_of::<Option<Value>>(),
        size_of::<Result<Value, serde_json::Error>>(),
        size_of::<Vec<u8>>(),
        size_of::<Option<Vec<u8>>>(),
        // Neither transient serde error is formatted into an owned String.
        crate::reference_packet::continuation_models::serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
        canonical::CANONICAL_JSON_INVALID_REASON_BYTES_DATA,
    ])?;
    let axes = [
        retained,
        transient,
        native_import18_bootstrap_sealing_counter_scratch_data(),
    ];
    if sum(&axes)? > maximum {
        return Err(exhausted());
    }
    Ok(PacketNativeImport18BootstrapSealingRowData { axes })
}

/// Moves both inputs into the same retained attempt before fallible validation.
///
/// Occupied output or absent input refuses without moving either input. Once
/// installed, the output preserves the assignment, typed proof, original
/// extension and all serializer/writer prefixes after either outcome. Structural
/// sealing supplies no proof verification, Source credit or publishing right.
///
/// # Errors
/// Refuses occupied/absent inputs, changed component row, malformed proof,
/// serializer/writer failure or actual retained demand exceeding the quote.
pub fn native_import18_bootstrap_sealing_into_data(
    assignment: &mut Option<PacketNativeImport18BootstrapAssignmentData>,
    proof: &mut Option<PacketNativeImport18BootstrapAckProof>,
    row: &PacketNativeImport18BootstrapSealingRowData,
    maximum: usize,
    output: &mut Option<PacketNativeImport18BootstrapSealingData>,
) -> Result<(), ProviderError> {
    if output.is_some() || assignment.is_none() || proof.is_none() {
        return Err(invalid());
    }
    *output = Some(PacketNativeImport18BootstrapSealingData {
        row: *row,
        assignment: assignment.take(),
        proof: proof.take(),
        proof_value: None,
        envelope_value: None,
        literal: None,
        step: None,
        failure: None,
        sealed: false,
        failed: true,
    });
    let owner = output.as_mut().ok_or_else(invalid)?;
    let result = construct(owner, maximum);
    let retained = owner.retained_requested_bytes_data();
    result?;
    if retained? > owner.row.axes[0] {
        return Err(exhausted());
    }
    owner.sealed = true;
    owner.failed = false;
    Ok(())
}

fn construct(
    owner: &mut PacketNativeImport18BootstrapSealingData,
    maximum: usize,
) -> Result<(), ProviderError> {
    if owner.row
        != native_import18_bootstrap_sealing_quote_data(
            owner.assignment.as_ref().ok_or_else(invalid)?,
            owner.proof.as_ref().ok_or_else(invalid)?,
            maximum,
        )?
    {
        return Err(invalid());
    }
    owner.step = Some(PacketNativeImport18BootstrapSealingStep::ProofValue);
    match serde_json::to_value(owner.proof.as_ref().ok_or_else(invalid)?) {
        Ok(value) => owner.proof_value = Some(value),
        Err(_) => {
            owner.failure = Some(PacketNativeImport18BootstrapSealingFailure::ProofValue);
            return Err(invalid());
        }
    }

    owner.step = Some(PacketNativeImport18BootstrapSealingStep::Attach);
    let original = owner
        .assignment
        .as_mut()
        .ok_or_else(invalid)?
        .original_mut_data()?;
    let proof_value = owner.proof_value.as_mut().ok_or_else(invalid)?;
    original.extensions.insert(
        NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        std::mem::take(proof_value),
    );

    owner.step = Some(PacketNativeImport18BootstrapSealingStep::EnvelopeValue);
    match serde_json::to_value(&*original) {
        Ok(value) => owner.envelope_value = Some(value),
        Err(_) => {
            owner.failure = Some(PacketNativeImport18BootstrapSealingFailure::EnvelopeValue);
            return Err(invalid());
        }
    }
    let bound = native_import18_bootstrap_envelope_projection_data(maximum)?
        .maximum_encoded_bytes_data()[0];
    write_literal(owner, bound)
}

fn write_literal(
    owner: &mut PacketNativeImport18BootstrapSealingData,
    maximum: usize,
) -> Result<(), ProviderError> {
    owner.step = Some(PacketNativeImport18BootstrapSealingStep::Literal);
    owner.literal = Some(Vec::new());
    let mut writer = LiteralWriter {
        output: owner.literal.as_mut().ok_or_else(invalid)?,
        maximum,
    };
    if canonical::canonical_json_to_writer(
        owner.envelope_value.as_ref().ok_or_else(invalid)?,
        &mut writer,
    )
    .is_err()
    {
        owner.failure = Some(PacketNativeImport18BootstrapSealingFailure::Literal);
        return Err(invalid());
    }
    Ok(())
}

struct LiteralWriter<'a> {
    output: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for LiteralWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .output
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.maximum)
        {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn observe_proof(
    proof: &PacketNativeImport18BootstrapAckProof,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let PacketNativeImport18BootstrapAckProof {
        schema,
        algorithm,
        context_digest,
        mac,
    } = proof;
    observer.observe(schema)?;
    observer.observe(algorithm)?;
    observer.observe(context_digest)?;
    observer.observe(mac)?;
    Ok(())
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(exhausted)
    })
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("bootstrap request materialization storage")
}

/// Names concrete quote, move, serializer, canonical writer and census controls.
pub fn native_import18_bootstrap_sealing_counter_scratch_data() -> usize {
    native_import18_bootstrap_assignment_counter_scratch_data()
        + native_import18_bootstrap_ack_counter_scratch_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + size_of::<PacketNativeImport18BootstrapSealingRowData>() * 2
        + size_of::<Result<PacketNativeImport18BootstrapSealingRowData, ProviderError>>()
        + size_of::<PacketNativeImport18BootstrapSealingHistoryData<'static>>()
        + size_of::<PacketNativeImport18BootstrapAssignmentHistoryData<'static>>()
        + size_of::<&mut PacketNativeImport18BootstrapSealingData>()
        + size_of::<&mut Option<PacketNativeImport18BootstrapSealingData>>()
        + size_of::<&mut Option<PacketNativeImport18BootstrapAssignmentData>>()
        + size_of::<&mut Option<PacketNativeImport18BootstrapAckProof>>()
        + size_of::<&PacketNativeImport18BootstrapAckProof>()
        + size_of::<&mut Envelope>()
        + size_of::<&Value>()
        + size_of::<&mut Value>()
        + size_of::<LiteralWriter<'static>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<[usize; 20]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<Result<(), ProviderError>>() * 2
        + size_of::<std::io::Result<usize>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + MetadataObserver::native_import18_json_metadata_frame_counter_scratch_data() * 8
}

#[cfg(test)]
#[path = "sealing/tests.rs"]
mod tests;
