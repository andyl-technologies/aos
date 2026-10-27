//! Borrows the ACK policy preimage directly from original decoded native DATA.
//!
//! Its normalized wire grammar matches the existing retained-Value Source view.
//! No intermediate Source-binding DOM or owned recipe Bytes is constructed.
//! The enclosing bootstrap proves actual policy/SDK custody before this view.

use super::*;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18SourceBindingWireData;
use crate::reference_packet::service::complete_restore::import18::startup_wire::{
    native_import18_source_binding_wire_formatter_requested_data,
    native_import18_source_binding_wire_projection_counter_scratch_data,
    native_import18_source_binding_wire_projection_data,
};
use serde::Serializer;

/// Borrows the complete typed native policy using the same normalized five fields.
#[derive(Serialize)]
pub(in crate::reference_packet) struct PacketNativeImport18BootstrapTypedPolicyView<'a> {
    schema: &'static str,
    source_binding: &'a PacketNativeImport18SourceBindingWireData,
    #[serde(serialize_with = "serialize_digest")]
    recipe_identity: &'a [u8; 32],
    definitions: PacketNativeImport18BootstrapDefinitionsView<'a>,
    negotiated: PacketNativeImport18BootstrapNegotiatedView<'a>,
}

fn serialize_digest<S: Serializer>(digest: &&[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    Bytes::borrowed_serialization_data(digest.as_slice()).serialize(serializer)
}

/// Borrows the original typed Source binding, full definitions and current SDK DATA.
///
/// Full compiled definitions, immutable launch and actual Source/kernel/Birth
/// provenance remain independent original guards. A valid view issues no ACK.
///
/// # Errors
/// Refuses a different recipe, schema edition, revoked SDK or absent negotiation.
pub(in crate::reference_packet) fn native_import18_bootstrap_typed_policy_wire_data<'a>(
    source_binding: &'a PacketNativeImport18SourceBindingWireData,
    recipe_identity: &'a [u8; 32],
    import: &'a SchemaRef,
    stage: &'a SchemaRef,
    record: &'a SchemaRef,
    authority: &'a ConnectionAuthority,
) -> Result<PacketNativeImport18BootstrapTypedPolicyView<'a>, ProviderError> {
    authority.ensure_live()?;
    if source_binding
        .announced_recipe_data()
        .announced_identity_data()
        != recipe_identity
    {
        return Err(invalid());
    }
    for (reference, expected) in [
        (import, "source-owned.packet-native-import/18"),
        (stage, "source-owned.packet-native-import-stage/18"),
        (record, "source-owned.packet-restored-native/18"),
    ] {
        if reference.id.as_str() != expected || reference.version != 18 {
            return Err(invalid());
        }
    }
    Ok(PacketNativeImport18BootstrapTypedPolicyView {
        schema: "source-owned.packet-native-import-bootstrap-policy-binding/18",
        source_binding,
        recipe_identity,
        definitions: PacketNativeImport18BootstrapDefinitionsView {
            mechanism: PacketNativeImport18Selection::SourceSignedImport18,
            import,
            stage,
            record,
        },
        negotiated: PacketNativeImport18BootstrapNegotiatedView {
            limits: authority.limits(),
            features: authority.selected_features(),
            extensions: authority.selected_extensions().ok_or_else(invalid)?,
            envelope_extensions: authority.envelope_extensions(),
        },
    })
}

impl PacketNativeImport18BootstrapTypedPolicyView<'_> {
    /// Borrows the same original decoded Source wrapper without copying its graph.
    pub(in crate::reference_packet) fn source_binding_data(
        &self,
    ) -> &PacketNativeImport18SourceBindingWireData {
        self.source_binding
    }

    /// Projects the actual complete normalized policy before its allocating serializer.
    ///
    /// Both base64 formatters are sequential: the original Source bank and the
    /// fixed recipe digest each retain their defining temporary String only for
    /// their own leaf. Parser/output banks remain separate from that formatter.
    ///
    /// # Errors
    /// Refuses checked projection overflow or the complete shape above the restriction.
    pub(in crate::reference_packet) fn serialization_data(
        &self,
        maximum: usize,
    ) -> Result<OriginalSerializationStorageData, ProviderError> {
        let Self {
            schema,
            source_binding,
            recipe_identity: _,
            definitions,
            negotiated,
        } = self;
        let mut out = Projection::new(maximum)?;
        object(
            &mut out,
            &[
                "schema",
                "source_binding",
                "recipe_identity",
                "definitions",
                "negotiated",
            ],
        )?;
        out.add_string(schema)?;
        native_import18_source_binding_wire_projection_data(&mut out, source_binding)?;
        out.add_unescaped_ascii_extent(43)?;
        out.add_value(definitions)?;
        out.add_value(negotiated)?;
        let mut shape = out.finish(maximum)?;
        shape.serializer_temporary_requested_bytes =
            shape.serializer_temporary_requested_bytes.max(
                native_import18_source_binding_wire_formatter_requested_data(source_binding)?
                    .max(43),
            );
        if shape.requested_total()? > maximum {
            return Err(invalid());
        }
        Ok(shape)
    }

    /// Names the actual typed view, checked constructor and projection controls.
    ///
    /// Recursive serialization/JCS and the caller's currentness/admission frames
    /// remain independently priced. This does not constitute an initial or phase row.
    pub(in crate::reference_packet) fn counter_scratch_data() -> usize {
        native_import18_bootstrap_operands_counter_scratch_data()
            + native_import18_source_binding_wire_projection_counter_scratch_data()
            + Bytes::borrowed_serialization_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&PacketNativeImport18SourceBindingWireData>()
            + size_of::<&[u8; 32]>() * 2
            + size_of::<&[u8]>()
            + size_of::<Result<(), ProviderError>>()
    }
}
