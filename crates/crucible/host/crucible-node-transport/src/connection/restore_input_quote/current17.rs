//! Encodes every actual restore-input quote field and its original role edges.

use super::*;
use crate::retained_metadata::aliases::MetadataSharedKind;
use serde::{Serializer, ser::SerializeStruct};

struct CurrentInputQuote17<'a>(&'a NativeRestoreInputAllocationQuote);

impl NativeRestoreInputAllocationQuote {
    /// Borrows the complete retained quote without granting its original credit.
    ///
    /// # Errors
    /// Refuses a foreign originating actor; no deadline or token is recreated.
    pub(crate) fn borrowed_current17_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.actor_current()?;
        Ok(CurrentInputQuote17(self))
    }

    /// Derives exact original quote commitments from the concrete Prepare DATA.
    ///
    /// # Errors
    /// Refuses malformed request geometry, checked extents or serialization.
    pub(crate) fn current17_request_facts_data(
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<([u8; 32], [usize; 6], usize, usize), ProviderError> {
        request.validate_data()?;
        Ok((
            *request_digest(request)?.as_bytes(),
            input_lengths(request)?,
            selected(request.allocation.maximum_metadata_rows.get())?,
            selected(request.allocation.maximum_nodes.get())?,
        ))
    }

    /// Names exact borrowed quote and pure request-fact result headers.
    pub(crate) fn current17_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<CurrentInputQuote17<'static>>()
            + size_of::<Result<CurrentInputQuote17<'static>, ProviderError>>()
            + size_of::<([u8; 32], [usize; 6], usize, usize)>()
            + size_of::<Result<([u8; 32], [usize; 6], usize, usize), ProviderError>>()
            + super::super::restore_proof_quote::OriginalRestoreHeldProofAllocationQuote::settled_history_counter_scratch_data()
    }

    /// Observes every retained quote field in the defining serialization order.
    ///
    /// # Errors
    /// Refuses foreign roots, exhausted metadata or checked layout overflow.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.actor_current()?;
        let Self {
            actor,
            codec,
            request_digest: _,
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
        } = self;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        observer.shared_original(MetadataSharedKind::Codec, codec.as_ref())?;
        observer.observe(input_lengths)?;
        observer.observe(maximum_metadata_rows)?;
        observer.observe(maximum_nodes)?;
        observer.observe(raw_input_bytes)?;
        observer.observe(historical_backing_bytes)?;
        observer.observe(reconstruction_lookup_bytes)?;
        observer.observe(requested_geometry_bytes)?;
        observer.observe(declared_scratch_and_owner_bytes)?;
        observer.observe(custody_layout_bytes)?;
        held_proof.observe_settled_history_metadata_data(observer)?;
        observer.observe(sdk_requested_bytes)
    }
}

impl Serialize for CurrentInputQuote17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.actor_current().map_err(serde::ser::Error::custom)?;
        let NativeRestoreInputAllocationQuote {
            actor: _,
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
        let mut fields = serializer.serialize_struct("NativeInputQuoteCurrent17", 15)?;
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
