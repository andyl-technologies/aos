//! Borrows the bootstrap birth preimage from the original decoded private body.
//!
//! The complete typed Source wrapper stays in its original owner. No private key
//! enters this serializer, and no intermediate Source DOM is needed. Original
//! Source/Birth, kernel and SDK provenance remain the enclosing caller's guards.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};

/// Borrows all six normalized birth-association fields from the private body.
#[derive(Serialize)]
pub(in crate::reference_packet) struct PacketNativeImport18BootstrapTypedBirthView<'a> {
    schema: &'static str,
    birth_id: &'a Bytes,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
    source_binding: &'a PacketNativeImport18SourceBindingWireData,
    expected_host_registration: &'a Value,
}

impl PacketNativeImport18PrivateBootWireData {
    /// Borrows complete birth-association DATA without exporting the private key.
    ///
    /// Matching these fields creates no Birth or ACK. The original enclosing
    /// bootstrap separately authenticates all private operands and their custody.
    ///
    /// # Errors
    /// Refuses a birth identifier outside its defining 32-byte grammar.
    pub(in crate::reference_packet) fn bootstrap_birth_wire_data(
        &self,
    ) -> Result<PacketNativeImport18BootstrapTypedBirthView<'_>, ProviderError> {
        let Self {
            schema: BootSchema::Import18,
            private_key: _,
            birth_id,
            source_birth,
            expected_host_registration,
            private_launch,
            host_executable,
        } = self;
        digest32(birth_id)?;
        Ok(PacketNativeImport18BootstrapTypedBirthView {
            schema: "source-owned.packet-native-import-bootstrap-birth-association/18",
            birth_id,
            private_launch,
            host_executable,
            source_binding: source_birth,
            expected_host_registration,
        })
    }
}

impl PacketNativeImport18BootstrapTypedBirthView<'_> {
    /// Borrows the original fixed birth identifier without copying its bank.
    pub(in crate::reference_packet) fn birth_id_data(&self) -> &Bytes {
        self.birth_id
    }

    /// Borrows the complete original decoded Source binding.
    pub(in crate::reference_packet) fn source_binding_data(
        &self,
    ) -> &PacketNativeImport18SourceBindingWireData {
        self.source_binding
    }

    /// Projects every normalized field before invoking either Bytes formatter.
    ///
    /// Birth and original Source-bank formatters run sequentially. Their peak
    /// String is separate from the parser, DOM/JCS and canonical output banks.
    ///
    /// # Errors
    /// Refuses checked projection overflow or a complete shape above the restriction.
    pub(in crate::reference_packet) fn serialization_data(
        &self,
        maximum: usize,
    ) -> Result<OriginalSerializationStorageData, ProviderError> {
        let Self {
            schema,
            birth_id: _,
            private_launch,
            host_executable,
            source_binding,
            expected_host_registration,
        } = self;
        let mut out = Projection::new(maximum)?;
        out.add_object()?;
        for name in [
            "schema",
            "birth_id",
            "private_launch",
            "host_executable",
            "source_binding",
            "expected_host_registration",
        ] {
            out.add_field(name)?;
        }
        out.add_string(schema)?;
        out.add_unescaped_ascii_extent(43)?;
        out.add_value(private_launch)?;
        out.add_value(host_executable)?;
        native_import18_source_binding_wire_projection_data(&mut out, source_binding)?;
        out.add_value(expected_host_registration)?;

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

    /// Names the actual constructor, borrowed views and projection controls.
    ///
    /// Original custody checks and dynamic callback/serializer construction are
    /// separate. This quote provides no initial allowance or phase funding.
    pub(in crate::reference_packet) fn counter_scratch_data() -> usize {
        native_import18_source_binding_wire_projection_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<&PacketNativeImport18PrivateBootWireData>()
            + size_of::<&PacketNativeImport18SourceBindingWireData>()
            + size_of::<&Value>()
            + size_of::<&Bytes>()
            + size_of::<&[u8]>()
            + size_of::<&[u8; 32]>()
            + size_of::<Result<&[u8; 32], ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<&Id>()
            + size_of::<&ContentRef>()
            + size_of::<[&str; 6]>()
            + size_of::<std::array::IntoIter<&'static str, 6>>()
            + size_of::<usize>()
            + size_of::<Result<(), ProviderError>>()
    }
}
