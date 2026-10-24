//! Projects the actual fixed stage crypto grammar before allocating its DATA.
//!
//! Context, proof, complete receipt and unsigned receipt input have separate
//! shapes. Original bindings, Envelopes, typed decoders, diagnostics and live
//! Source/native/SDK constructors remain independently funded obligations.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape,
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};
use std::mem::size_of;

/// Retains defining serialization shapes without allocating a positive DTO.
pub struct PacketNativeImport17StageCryptoProjectionData {
    shapes: [Shape; 4],
}

impl PacketNativeImport17StageCryptoProjectionData {
    /// Returns maximum context, proof, receipt and unsigned-receipt encoded sizes.
    pub fn maximum_encoded_bytes_data(&self) -> [usize; 4] {
        self.shapes
            .each_ref()
            .map(|shape| shape.maximum_encoded_bytes)
    }

    /// Returns separate DOM/JCS, parser and output banks for each defining shape.
    ///
    /// Shape order is context, proof, receipt and unsigned receipt input. Parser
    /// banks cover JSON Value construction only; concrete typed partials and
    /// retained failures need their actual decoder's separate accounting.
    pub fn serialization_requested_bytes_data(&self) -> [[usize; 3]; 4] {
        self.shapes.each_ref().map(|shape| {
            [
                shape.dom_and_canonical_scratch_bytes,
                shape.projected_parser_requested_bytes,
                shape.canonical_output_requested_bytes,
            ]
        })
    }
}

/// Projects all four defining crypto shapes for one distinct stage.
///
/// The fixed digests use their actual unpadded base64 width without running the
/// allocating Bytes formatter. This walk constructs no Context, proof, receipt,
/// Source grant, native phase permission or independently admitted caller row.
///
/// # Errors
/// Refuses checked shape overflow or an independently short restriction.
pub fn native_import17_stage_crypto_projection_data(
    phase: PacketNativeImport17Stage,
    maximum: usize,
) -> Result<PacketNativeImport17StageCryptoProjectionData, ProviderError> {
    let mut context = Projection::new(maximum)?;
    object(
        &mut context,
        &[
            "schema",
            "algorithm",
            "phase",
            "birth_context_digest",
            "stage_binding_digest",
            "assigned_original_digest",
        ],
    )?;
    context.add_string("source-owned.packet-native-import-stage-context/17")?;
    context.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    context.add_string(phase_name(phase))?;
    for _ in 0..3 {
        digest(&mut context)?;
    }
    let context = context.finish(maximum)?;

    let mut proof = Projection::new(maximum)?;
    object(
        &mut proof,
        &["schema", "algorithm", "context_digest", "mac"],
    )?;
    proof.add_string(phase.proof_extension())?;
    proof.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    for _ in 0..2 {
        digest(&mut proof)?;
    }
    let proof = proof.finish(maximum)?;

    let receipt = receipt_shape(phase, true, maximum)?;
    let input = receipt_shape(phase, false, maximum)?;
    Ok(PacketNativeImport17StageCryptoProjectionData {
        shapes: [context, proof, receipt, input],
    })
}

/// Quotes retained crypto outputs and their actual simultaneous canonical work.
///
/// Retained backing covers one valid Context, proof and receipt, excluding their
/// enclosing field slots. Temporary work includes the context output Vec that
/// remains live while receipt-input DOM/JCS is constructed, plus the actual
/// sequential 32-byte Bytes formatter. The caller separately funds original
/// binding/Envelope construction, typed decoders, allocation admission, callback
/// and asynchronous frames, live phases and publication. This is no phase row.
///
/// # Errors
/// Refuses checked accumulation overflow or a restriction below the complete
/// component's retained/transient/counter sum. A larger restriction adds no credit.
pub fn native_import17_stage_crypto_construction_data(
    phase: PacketNativeImport17Stage,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let projected = native_import17_stage_crypto_projection_data(phase, maximum)?;
    let [context, _, _, input] = &projected.shapes;
    let retained = "source-owned.packet-native-import-stage-context/17".len()
        + phase.proof_extension().len()
        + phase.receipt_extension().len()
        + PACKET_COMPLETE_RESTORE_ALGORITHM.len() * 3
        + 32 * 8;
    let canonical = canonical_work(context)?.max(
        context
            .canonical_output_requested_bytes
            .checked_add(canonical_work(input)?)
            .ok_or_else(invalid)?,
    );
    let transient = canonical
        .checked_add(43)
        .and_then(|n| n.checked_add(constructor_headers()))
        .ok_or_else(invalid)?;
    let scratch = native_import17_stage_crypto_counter_scratch_data();
    let row = [retained, transient, scratch];
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|n| n > maximum)
    {
        return Err(invalid());
    }
    Ok(row)
}

/// Names fixed projection, canonical/MAC, validation and borrowed receipt controls.
///
/// Dynamic JSON, output and formatter backing are separate. This does not claim
/// compiler frame size, allocator-rounded residency or enclosing caller controls.
pub fn native_import17_stage_crypto_counter_scratch_data() -> usize {
    original_serialization_counter_scratch_data()
        + crate::connection::original_serialized_credit_counter_scratch_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + size_of::<Projection>()
        + size_of::<PacketNativeImport17StageCryptoProjectionData>()
        + size_of::<Result<PacketNativeImport17StageCryptoProjectionData, ProviderError>>()
        + size_of::<[Shape; 4]>()
        + size_of::<Result<Shape, ProviderError>>()
        + size_of::<&mut Projection>()
        + size_of::<&Shape>() * 4
        + size_of::<&[&str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<&&str>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<PacketNativeImport17Stage>() * 2
        + size_of::<&PacketNativeImport17StageContext>() * 3
        + size_of::<&PacketNativeImport17StageProof>()
        + size_of::<&PacketNativeImport17StageReceipt>() * 2
        + size_of::<crypto::ReceiptInput<'static>>()
        + size_of::<[&crucible_node_format::Bytes; 3]>()
        + size_of::<std::array::IntoIter<&'static crucible_node_format::Bytes, 3>>()
        + size_of::<&[u8; 32]>() * 2
        + size_of::<&[u8]>() * 2
        + size_of::<[u8; 32]>() * 2
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>() * 2
        + size_of::<Vec<u8>>() * 3
        + size_of::<Result<Vec<u8>, ProviderError>>() * 2
        + size_of::<[usize; 3]>() * 2
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<usize>() * 5
        + size_of::<bool>()
}

fn constructor_headers() -> usize {
    size_of::<PacketNativeImport17StageContext>() * 2
        + size_of::<PacketNativeImport17StageProof>() * 2
        + size_of::<Result<PacketNativeImport17StageProof, ProviderError>>()
        + size_of::<PacketNativeImport17StageReceipt>() * 2
        + size_of::<Result<PacketNativeImport17StageReceipt, ProviderError>>()
}

fn receipt_shape(
    phase: PacketNativeImport17Stage,
    complete: bool,
    maximum: usize,
) -> Result<Shape, ProviderError> {
    let mut receipt = Projection::new(maximum)?;
    object(
        &mut receipt,
        &[
            "schema",
            "algorithm",
            "phase",
            "context_digest",
            "assigned_response",
            "physical_gate_held",
        ],
    )?;
    receipt.add_string(phase.receipt_extension())?;
    receipt.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    receipt.add_string(phase_name(phase))?;
    for _ in 0..2 {
        digest(&mut receipt)?;
    }
    receipt.add_value(&(phase == PacketNativeImport17Stage::Arm))?;
    if complete {
        receipt.add_field("mac")?;
        digest(&mut receipt)?;
    }
    receipt.finish(maximum)
}

fn canonical_work(shape: &Shape) -> Result<usize, ProviderError> {
    [
        shape.dom_and_canonical_scratch_bytes,
        shape.canonical_output_requested_bytes,
        shape.serializer_temporary_requested_bytes,
    ]
    .into_iter()
    .try_fold(0usize, |sum, field| {
        sum.checked_add(field).ok_or_else(invalid)
    })
}

fn object(projection: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    projection.add_object()?;
    for field in fields {
        projection.add_field(field)?;
    }
    Ok(())
}

fn digest(projection: &mut Projection) -> Result<(), ProviderError> {
    projection.add_unescaped_ascii_extent(43)
}

fn phase_name(phase: PacketNativeImport17Stage) -> &'static str {
    match phase {
        PacketNativeImport17Stage::Arm => "arm",
        PacketNativeImport17Stage::World => "world",
        PacketNativeImport17Stage::FirstObserve => "first_observe",
    }
}

#[cfg(test)]
mod tests;
