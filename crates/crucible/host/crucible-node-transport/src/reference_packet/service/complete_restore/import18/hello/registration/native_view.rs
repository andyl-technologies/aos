//! Projects the actual native registration without constructing a normalized DOM.
//!
//! The existing nine-field serializer remains the wire definition. Native-only
//! projection requires the original profile's connection and empty typed roster;
//! actual Source/Hello/SDK provenance stays with the enclosing bootstrap loan.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};

impl PacketNativeImport18CurrentRegistrationView<'_> {
    /// Projects every native registration field before allocating normalization.
    ///
    /// The actual profile has no typed extensions or Bytes leaves. Its five U64
    /// limits format into their fixed decimal stack banks; Id and String rosters
    /// are borrowed. A changed field roster requires an explicit projection review.
    ///
    /// # Errors
    /// Refuses a controller/foreign connection, nonempty typed roster, checked
    /// projection overflow or a complete shape above the independent restriction.
    pub(in crate::reference_packet) fn native_serialization_data(
        &self,
        maximum: usize,
    ) -> Result<OriginalSerializationStorageData, ProviderError> {
        let Self {
            schema: _,
            role,
            connection_id,
            session_id: _,
            incarnation_id: _,
            limits,
            features: _,
            extensions,
            envelope_extensions: _,
        } = self;
        let Limits {
            frame_bytes: _,
            nesting: _,
            requests: _,
            journal_entries: _,
            blob_chunk_bytes: _,
        } = limits;
        if *role != "native"
            || connection_id.as_str() != NATIVE_IMPORT18_CONNECTION_ID
            || !extensions.is_empty()
        {
            return Err(refused());
        }
        let mut out = Projection::new(maximum)?;
        out.add_value(self)?;
        out.finish(maximum)
    }

    /// Names the real native view, projection and shared constructor controls.
    ///
    /// Dynamic DOM/JCS, parser/output and original caller guards remain separate.
    pub(in crate::reference_packet) fn native_counter_scratch_data() -> usize {
        native_import18_registration_counter_scratch_data()
            + original_serialization_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&Limits>()
            + size_of::<Projection>()
            + size_of::<OriginalSerializationStorageData>()
            + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
            + size_of::<usize>()
            + size_of::<Result<(), ProviderError>>()
    }
}
