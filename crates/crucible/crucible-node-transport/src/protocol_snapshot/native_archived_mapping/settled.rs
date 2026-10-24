//! Binds the current installed mapping to its verified immutable imported body.
//!
//! The live imported decoder remains retained in the actual mapping. This
//! portable logical view does not recursively copy that immutable Rust heap,
//! evict it during Capture, revive old keys or reinterpret an old11 owner as17.
//! The strict17 consumer must obtain and validate the named immutable body from
//! its bounded authenticated DAG, plus the same current actor/authority/codec.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct MappingHistory<'a>(&'a PreparedArchivedNativeProtocolMapping);

impl PreparedArchivedNativeProtocolMapping {
    pub(crate) fn borrowed_restored_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        self.historical()?.authenticate_capture_correspondence()?;
        Ok(MappingHistory(self))
    }
}

impl Serialize for MappingHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PreparedArchivedNativeProtocolMapping {
            class,
            actor,
            authority,
            codec: _,
            reference,
            nonce,
            normalization,
            historical,
        } = self.0;
        actor.ensure_current().map_err(serde::ser::Error::custom)?;
        authority.ensure_live().map_err(serde::ser::Error::custom)?;
        let historical = historical
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native imported mapping absent"))?;
        historical
            .historical()
            .and_then(|state| state.authenticate_capture_correspondence())
            .map_err(serde::ser::Error::custom)?;
        let mut fields = serializer.serialize_struct("NativeImportedMapping17", 9)?;
        fields.serialize_field("schema", "source-private.native-imported-mapping/17")?;
        fields.serialize_field("class", class.normalization_format())?;
        fields.serialize_field("actor_role", "native-connection-actor")?;
        fields.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        fields.serialize_field("codec_role", "native-connection-codec")?;
        fields.serialize_field("reference", reference)?;
        fields.serialize_field("nonce", nonce)?;
        fields.serialize_field("normalization", &BorrowedCompactBytes::new(normalization))?;
        fields.serialize_field("imported_protocol", historical.body_reference())?;
        fields.end()
    }
}
