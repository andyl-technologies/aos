//! Moves actual original encoded storage without duplicating its archive payload.
//!
//! The opaque correspondence owner comes only from consuming a source-issued
//! snapshot. It retains original actor, codec, cut, capacity and literal history;
//! neither this transfer nor a matching body grants installation authority.

use super::*;

mod capacities;

/// Retains the actual source-issued owner after its encoded bytes move once.
///
/// The source still joins exact signed archive/target context and native semantic
/// settlement. This type has no public constructor, Clone or Deserialize.
pub struct OriginalProtocolPayloadOwner {
    compact: bool,
    owned11_records: Option<MetadataRecordBank>,
    owned11_aliases: Option<MetadataAliasBank>,
    original_assigned_cut: Option<crate::operational_time::OperationalDeadline>,
    original_restore_cut: Option<crate::operational_time::OperationalDeadline>,
    original_hello:
        Option<Rc<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>>,
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
            owned11_records: self.owned11_records,
            owned11_aliases: self.owned11_aliases,
            original_assigned_cut: self.original_assigned_cut,
            original_restore_cut: self.original_restore_cut,
            original_hello: self.original_hello,
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
    /// Reads actual historical row and temporary lookup capacities after payload transfer.
    ///
    /// # Errors
    /// Refuses another original process or thread.
    pub fn original_alias_allocation_facts(
        &self,
    ) -> Result<Option<MetadataAliasAllocationFacts>, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self
            .owned11_aliases
            .as_ref()
            .map(MetadataAliasBank::allocation_facts))
    }

    /// Reports the actual record bank still retained after the bytes move once.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn original_metadata_record_allocation_facts(
        &self,
    ) -> Result<Option<MetadataRecordAllocationFacts>, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.owned11_records.as_ref().map(metadata_record_facts))
    }

    /// Authenticates original Hello allocation identity after payload transfer.
    ///
    /// # Errors
    /// Refuses a changed original process/thread, missing or incomplete Hello,
    /// or another actual journal. Equal body digests grant no allocation credit.
    pub fn authenticate_original_hello(
        &self,
        journal: &crate::client::OriginalHelloJournal,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        journal.original_literal_frame_digests()?;
        let bank = self
            .original_hello
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "owned protocol retained Hello absent",
            ))?;
        journal.authenticate_original_literal_bank(bank)
    }

    /// Reports retention of the original restore physical cut.
    ///
    /// This provenance observation cannot renew a deadline or create cut authority.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn retains_original_restore_cut(&self) -> Result<bool, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.original_restore_cut.is_some())
    }

    /// Reports retention of the original assigned physical cut.
    ///
    /// This provenance observation cannot renew a deadline or create cut authority.
    ///
    /// # Errors
    /// Refuses a different original process or thread.
    pub fn retains_original_assigned_cut(&self) -> Result<bool, ProviderError> {
        self.owner.ensure_current()?;
        Ok(self.original_assigned_cut.is_some())
    }

    /// Observes actual retained metadata capacities after the payload moves.
    ///
    /// This performs no serialization, allocation, callback or I/O. It counts
    /// shared backing conservatively per retained view, independently of the
    /// archive Vec's current storage and the snapshot's issuance byte facts.
    /// The caller separately admits tree/control-block layout and traversal
    /// stack terms; these facts cannot restore metadata omitted by edition7.
    ///
    /// # Errors
    /// Refuses a different original process/thread, extent overflow or traversal
    /// beyond the fixed node/depth allowance.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<super::RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            compact: _,
            owned11_records: _,
            owned11_aliases: _,
            original_assigned_cut: _,
            original_restore_cut: _,
            original_hello,
            maximum: _,
            encoded_length: _,
            encoded_capacity: _,
            body: _,
            authority,
            owner,
            cut: _,
            deadline: _,
            literal: _,
            codec,
        } = self;
        original_association_metadata(owner, authority, codec.as_ref(), original_hello.as_ref())
    }

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
                    .owned11_aliases
                    .as_ref()
                    .map_or(0, MetadataAliasBank::allocated_bytes)
                + self
                    .owned11_records
                    .as_ref()
                    .map_or(0, MetadataRecordBank::allocated_bytes)
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
            self.codec
                .as_ref()
                .map(|codec| crate::connection::ProtocolCodecView {
                    codec,
                    compact: self.compact,
                }),
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
