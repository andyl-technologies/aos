//! Moves actual original encoded storage without duplicating its archive payload.
//!
//! The opaque correspondence owner comes only from consuming a source-issued
//! snapshot. It retains original actor, codec, cut, capacity and literal history;
//! neither this transfer nor a matching body grants installation authority.

use super::*;

/// Retains the actual source-issued owner after its encoded bytes move once.
///
/// The source still joins exact signed archive/target context and native semantic
/// settlement. This type has no public constructor, Clone or Deserialize.
pub struct OriginalProtocolPayloadOwner {
    compact: bool,
    maximum: usize,
    encoded_length: usize,
    encoded_capacity: usize,
    body: blake3::Hash,
    authority: ConnectionAuthority,
    owner: Rc<ProtocolCaptureOwner>,
    cut: ProtocolCaptureCut,
    deadline: crate::operational_time::OperationalDeadline,
    literal: Option<crate::transport::original_frames::OriginalFrameReservation>,
    codec: Option<Rc<crate::connection::Native5CodecOwner>>,
}

impl OriginalProtocolSnapshot {
    /// Moves the same encoded vector once while retaining its original associations.
    ///
    /// This infallible data ownership transfer invokes no callback or I/O. It
    /// does not authenticate currentness or grant rights: every later use of the
    /// opaque owner rechecks its original process/thread, and source restoration
    /// separately authenticates live target/semantic/signed-context authority.
    pub fn into_original_payload(self) -> (OriginalProtocolPayloadOwner, Vec<u8>) {
        let original = OriginalProtocolPayloadOwner {
            compact: self.compact,
            maximum: self.maximum,
            encoded_length: self.bytes.len(),
            encoded_capacity: self.bytes.capacity(),
            body: blake3::hash(&self.bytes),
            authority: self.authority,
            owner: self.owner,
            cut: self.cut,
            deadline: self.deadline,
            literal: self.literal,
            codec: self.codec,
        };
        (original, self.bytes)
    }
}

impl OriginalProtocolPayloadOwner {
    /// Reports immutable issuance allocation facts after the encoded vector moves.
    ///
    /// These describe the original snapshot, not the archive's current buffer.
    /// The archive must charge its actual retained Vec length/capacity separately:
    /// a copied, grown or reallocated buffer cannot earn original storage credit
    /// merely because its bytes still match this owner's digest.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn original_allocation_facts(
        &self,
    ) -> Result<ProtocolSnapshotAllocationFacts, ProviderError> {
        self.owner.ensure_current()?;
        Ok(ProtocolSnapshotAllocationFacts {
            maximum_encoded_bytes: self.maximum,
            encoded_capacity: self.encoded_capacity,
            encoded_length: self.encoded_length,
            literal: self
                .literal
                .as_ref()
                .map(|literal| literal.snapshot_allocation_facts()),
            allocated_bytes: self.encoded_capacity
                + self
                    .literal
                    .as_ref()
                    .map_or(0, |literal| literal.allocated_bytes()),
        })
    }

    /// Authenticates exact original body correspondence without granting installation.
    ///
    /// This checks original byte correspondence, not allocation identity,
    /// current archive capacity, interpretation or a decoded caller's claim.
    /// Registration/source/target and native settlement authentication remain
    /// separate mandatory gates.
    ///
    /// # Errors
    /// Refuses changed process/thread, body length or original digest.
    pub fn validate_original_payload(&self, bytes: &[u8]) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if bytes.len() != self.encoded_length || blake3::hash(bytes) != self.body {
            return Err(ProviderError::Correlation(
                "original protocol payload changed",
            ));
        }
        Ok(())
    }
}

impl OriginalProtocolPayloadOwner {
    /// Borrows retained source association data after the encoded payload moves.
    ///
    /// This is correspondence data only. Opaque original Rc associations remain
    /// retained privately; serialized labels never replace source/target checks.
    /// The physical deadline remains an original local cut rather than portable
    /// guest time, and its current exhaustion is observed separately.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn original_association_view(&self) -> Result<impl serde::Serialize + '_, ProviderError> {
        self.owner.ensure_current()?;
        Ok((
            "source-private.original-protocol-payload/7",
            self.compact,
            self.authority.session_id(),
            self.authority.incarnation_id(),
            self.authority.connection_id(),
            self.authority.epoch(),
            match self.cut {
                ProtocolCaptureCut::HostSettled => "host-settled",
                ProtocolCaptureCut::NativeIncomingCapture => "native-incoming-capture",
            },
            self.codec.as_ref().map(|codec| codec.protocol_view()),
        ))
    }

    /// Observes expiration of the retained original local physical cut.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn original_physical_cut_expired(&self) -> Result<bool, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.deadline.is_expired())
    }
}
