//! Borrows complete actual input allocation geometry without restoring tokens.

use super::*;
use serde::{Serializer, ser::SerializeStruct};

struct InputQuoteHistory<'a>(&'a NativeRestoreInputAllocationQuote);

impl NativeRestoreInputAllocationQuote {
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.actor_current()?;
        Ok(InputQuoteHistory(self))
    }
}

impl Serialize for InputQuoteHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeRestoreInputAllocationQuote {
            actor,
            codec: _,
            request_digest,
            input_lengths,
            maximum_metadata_rows,
            maximum_nodes,
            raw_input_bytes,
            historical_backing_bytes,
            reconstruction_lookup_bytes,
            requested_geometry_bytes,
            declared_scratch_and_owner_bytes,
            custody_layout_bytes,
            held_proof,
            sdk_requested_bytes,
        } = self.0;
        actor.ensure_current().map_err(serde::ser::Error::custom)?;
        let mut fields = serializer.serialize_struct("NativeInputQuoteHistory17", 15)?;
        fields.serialize_field("schema", "source-private.native-input-allocation-quote/17")?;
        fields.serialize_field("actor_role", "native-connection-actor")?;
        fields.serialize_field("codec_role", "native-connection-codec")?;
        fields.serialize_field("request_digest", request_digest.as_bytes())?;
        fields.serialize_field("input_lengths", input_lengths)?;
        fields.serialize_field("maximum_metadata_rows", maximum_metadata_rows)?;
        fields.serialize_field("maximum_nodes", maximum_nodes)?;
        fields.serialize_field("raw_input_bytes", raw_input_bytes)?;
        fields.serialize_field("historical_backing_bytes", historical_backing_bytes)?;
        fields.serialize_field("reconstruction_lookup_bytes", reconstruction_lookup_bytes)?;
        fields.serialize_field("requested_geometry_bytes", requested_geometry_bytes)?;
        fields.serialize_field(
            "declared_scratch_and_owner_bytes",
            declared_scratch_and_owner_bytes,
        )?;
        fields.serialize_field("custody_layout_bytes", custody_layout_bytes)?;
        fields.serialize_field(
            "held_proof",
            &held_proof
                .borrowed_settled_history_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("sdk_requested_bytes", sdk_requested_bytes)?;
        fields.end()
    }
}
