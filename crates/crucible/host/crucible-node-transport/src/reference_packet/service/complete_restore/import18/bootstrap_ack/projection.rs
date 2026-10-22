//! Projects exact ACK18 DATA fields without manufacturing a bootstrap occurrence.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape,
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};
use std::mem::size_of;

/// Retains independent serialization/parser shapes for the three new ACK DTOs.
///
/// These are component facts, not a whole initial row. Actual original/response
/// Envelopes, raw receive ownership, expanded serde diagnostics, native identity,
/// Source callbacks and every enclosing partial owner remain separate terms.
pub struct PacketNativeImport18BootstrapAckProjectionData {
    context: Shape,
    proof: Shape,
    receipt: Shape,
}

impl PacketNativeImport18BootstrapAckProjectionData {
    /// Borrows the exact component shapes for the defining materialization quote.
    ///
    /// These private DATA facts do not authenticate operands or supply funding.
    pub(super) fn shapes_data(&self) -> [&Shape; 3] {
        [&self.context, &self.proof, &self.receipt]
    }

    /// Returns exact maximum encoded context, proof and receipt bytes in that order.
    pub fn maximum_encoded_bytes_data(&self) -> [usize; 3] {
        [
            self.context.maximum_encoded_bytes,
            self.proof.maximum_encoded_bytes,
            self.receipt.maximum_encoded_bytes,
        ]
    }

    /// Returns separately projected DOM/JCS, parser and output banks per DTO.
    ///
    /// Each row is `[DOM-and-JCS, parser, output]`, in context/proof/receipt order.
    /// The caller classifies actual surviving banks versus sequential temporary
    /// work from its real constructor. No maximum is itself an allowance.
    pub fn serialization_requested_bytes_data(&self) -> [[usize; 3]; 3] {
        let row = |value: &Shape| {
            [
                value.dom_and_canonical_scratch_bytes,
                value.projected_parser_requested_bytes,
                value.canonical_output_requested_bytes,
            ]
        };
        [row(&self.context), row(&self.proof), row(&self.receipt)]
    }

    /// Reports the actual sequential Bytes formatter's requested temporary bytes.
    pub const fn bytes_formatter_temporary_data(&self) -> usize {
        // Every validated digest is exactly32 bytes, unpadded base64 width43.
        43
    }
}

/// Projects every defining DTO field, including maximum decimal initial-row widths.
///
/// This allocation-free DATA walk does not invoke Bytes serialization, build a
/// DTO, call a signer, parse a body or accept a caller ceiling as demand.
///
/// # Errors
/// Refuses checked layout overflow or a component exceeding the restriction.
pub fn native_import18_bootstrap_ack_projection_data(
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapAckProjectionData, ProviderError> {
    let mut context = Projection::new(maximum)?;
    object(
        &mut context,
        &[
            "schema",
            "algorithm",
            "source_birth",
            "kernel_binding",
            "policy_binding",
            "host_registration",
            "native_registration",
            "hello_request",
            "hello_response",
            "assigned_request",
            "recipe_identity",
            "initial_funding",
        ],
    )?;
    context.add_string(NATIVE_IMPORT18_BOOTSTRAP_ACK_CONTEXT)?;
    context.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    for _ in 0..9 {
        digest(&mut context)?;
    }
    object(
        &mut context,
        &[
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    for _ in 0..3 {
        context.add_unescaped_ascii_extent(20)?;
    }
    let context = context.finish(maximum)?;

    let mut proof = Projection::new(maximum)?;
    object(
        &mut proof,
        &["schema", "algorithm", "context_digest", "mac"],
    )?;
    proof.add_string(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)?;
    proof.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    digest(&mut proof)?;
    digest(&mut proof)?;
    let proof = proof.finish(maximum)?;

    let mut receipt = Projection::new(maximum)?;
    object(
        &mut receipt,
        &[
            "schema",
            "algorithm",
            "state",
            "context_digest",
            "assigned_response",
            "mac",
        ],
    )?;
    receipt.add_string(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT)?;
    receipt.add_string(PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    receipt.add_string("bootstrap_only")?;
    for _ in 0..3 {
        digest(&mut receipt)?;
    }
    let receipt = receipt.finish(maximum)?;
    Ok(PacketNativeImport18BootstrapAckProjectionData {
        context,
        proof,
        receipt,
    })
}

fn object(out: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    out.add_object()?;
    for field in fields {
        out.add_field(field)?;
    }
    Ok(())
}

fn digest(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_unescaped_ascii_extent(43)
}

/// Names direct DATA quote, crypto and borrowed assignment controls.
///
/// Actual constructor outputs are separately transient headers below. Full
/// Envelope/body codec, expanded serde diagnostics, clone backing and generic
/// caller/callback controls remain independent defining obligations.
pub fn native_import18_bootstrap_ack_counter_scratch_data() -> usize {
    size_of::<Projection>()
        + size_of::<Shape>() * 3
        + size_of::<PacketNativeImport18BootstrapAckProjectionData>()
        + size_of::<Result<PacketNativeImport18BootstrapAckProjectionData, ProviderError>>()
        + size_of::<&mut Projection>()
        + size_of::<&[&str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<&&str>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<[&Bytes; 9]>()
        + size_of::<std::array::IntoIter<&'static Bytes, 9>>()
        + size_of::<&PacketNativeImport18BootstrapAckContext>()
        + size_of::<&PacketNativeImport18BootstrapAckProof>()
        + size_of::<&PacketNativeImport18BootstrapAckReceipt>()
        + size_of::<&Envelope>() * 2
        + size_of::<&[u8; 32]>() * 2
        + size_of::<&[u8]>() * 2
        + size_of::<[u8; 32]>() * 3
        + size_of::<[u8; 64]>()
        + size_of::<[u8; 20]>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>() * 2
        + size_of::<Vec<u8>>()
        + size_of::<serde_json::Value>()
        + size_of::<Option<&mut serde_json::Value>>()
        + size_of::<Option<&mut serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Option<serde_json::Value>>()
        + size_of::<serde_json::map::Keys<'static>>()
        + size_of::<&String>()
        + size_of::<usize>() * 2
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + original_serialization_counter_scratch_data()
        + crate::connection::original_serialized_credit_counter_scratch_data()
        + canonical::canonical_json_counter_scratch_bytes_data()
        + super::crypto::context_counter_scratch_data()
}

/// Names concrete typed return/Some installation windows for the three ACK DTOs.
///
/// Their retained field slots are charged by the real containing owner. This
/// does not estimate host compiler frames or fund parser/serializer work.
pub fn native_import18_bootstrap_ack_constructor_transient_data() -> usize {
    size_of::<PacketNativeImport18BootstrapAckContext>()
        + size_of::<Option<PacketNativeImport18BootstrapAckContext>>()
        + size_of::<PacketNativeImport18BootstrapAckProof>()
        + size_of::<Result<PacketNativeImport18BootstrapAckProof, ProviderError>>()
        + size_of::<Option<PacketNativeImport18BootstrapAckProof>>()
        + size_of::<PacketNativeImport18BootstrapAckReceipt>()
        + size_of::<Result<PacketNativeImport18BootstrapAckReceipt, ProviderError>>()
        + size_of::<Option<PacketNativeImport18BootstrapAckReceipt>>()
}

// Exhaustive defining DTO patterns keep this closed projection tied to the
// actual serializer field roster, without constructing positive authority DATA.
const _: fn(&PacketNativeImport18BootstrapAckContext) = |value| {
    let PacketNativeImport18BootstrapAckContext {
        schema: _,
        algorithm: _,
        source_birth: _,
        kernel_binding: _,
        policy_binding: _,
        host_registration: _,
        native_registration: _,
        hello_request: _,
        hello_response: _,
        assigned_request: _,
        recipe_identity: _,
        initial_funding: _,
    } = value;
};
const _: fn(&PacketNativeImport18BootstrapAckProof) = |value| {
    let PacketNativeImport18BootstrapAckProof {
        schema: _,
        algorithm: _,
        context_digest: _,
        mac: _,
    } = value;
};
const _: fn(&PacketNativeImport18BootstrapAckReceipt) = |value| {
    let PacketNativeImport18BootstrapAckReceipt {
        schema: _,
        algorithm: _,
        state: _,
        context_digest: _,
        assigned_response: _,
        mac: _,
    } = value;
};
