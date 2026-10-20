//! Borrows the installed input edge without duplicating its native payload.
//!
//! The actual Boot Prepare owns the same custody allocation and encodes that
//! payload once. This Connection component validates the real token/custody
//! relation and records the edge; it cannot install a decoded token or owner.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct InstalledInputHistory<'a>(&'a InstalledCompleteRestoreInputs);

impl OriginalCompleteRestoreInputCustody {
    /// Checks the same actual quote and originating owner for a retained Prepare.
    ///
    /// # Errors
    /// Refuses a foreign process/thread/actor or a changed complete Prepare row.
    pub(crate) fn authenticate_settled_history_prepare_data(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_prepare_data(request)
    }
}

impl InstalledCompleteRestoreInputs {
    /// Borrows the complete installed input token and its actual shared edge.
    ///
    /// # Errors
    /// Refuses borrowed/foreign native owners, a changed Prepare quote or a
    /// different custody allocation. This issues no installation/Capture rights.
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.token
            .authenticate_settled_history_custody_data(&self.custody)?;
        Ok(InstalledInputHistory(self))
    }

    /// Appends the actual token and custody edge without payload recursion.
    ///
    /// # Errors
    /// Refuses changed token/custody relations, exhausted metadata or overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.token
            .authenticate_settled_history_custody_data(&self.custody)?;
        self.token.observe_settled_history_metadata_data(observer)?;
        observer.shared_original(
            MetadataSharedKind::NativeRestoreInputCustody,
            self.custody.as_ref(),
        )
    }

    /// Names the defining wrapper, exact field loans and relation-check headers.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<InstalledInputHistory<'static>>()
            + size_of::<Result<InstalledInputHistory<'static>, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + VerifiedCompleteRestorePrepare::settled_history_counter_scratch_data()
            + field_view_bytes(|value: &'static Self| {
                let Self { token, custody } = value;
                (token, custody)
            })
    }
}

impl Serialize for InstalledInputHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .token
            .authenticate_settled_history_custody_data(&self.0.custody)
            .map_err(serde::ser::Error::custom)?;
        let InstalledCompleteRestoreInputs { token, custody: _ } = self.0;
        let token = token
            .borrowed_settled_history_data()
            .map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("InstalledRestoreInputHistory17", 3)?;
        state.serialize_field(
            "schema",
            "source-private.installed-restore-input-history/17",
        )?;
        state.serialize_field("token", &token)?;
        state.serialize_field("custody_role", "native-restore-input-custody")?;
        state.end()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}

struct CustodyHistory<'a>(&'a OriginalCompleteRestoreInputCustody);
struct InputBanksHistory<'a>(&'a [InputBank; 6]);
struct InputChunksHistory<'a>(&'a [OriginalRestoreInputChunk]);

impl OriginalCompleteRestoreInputCustody {
    /// Borrows complete installed input banks once the decoder has moved to mapping.
    ///
    /// Pending/failed reconstruction is never omitted: this settled Capture
    /// branch refuses it and leaves every owner untouched. Immutable imported
    /// state is bound by the same mapping's full protocol reference separately.
    pub(crate) fn borrowed_restored_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_settled_capture_boundary_data()?;
        Ok(CustodyHistory(self))
    }

    fn authenticate_settled_capture_boundary_data(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.phase != CustodyPhase::Complete
            || self.next_input != self.banks.len()
            || self.native_encoded.is_some()
            || self.native_owner.is_some()
            || self.mapping_attempt.is_some()
            || self
                .banks
                .iter()
                .zip(self.quote.input_lengths())
                .any(|(bank, length)| !bank.begun || !bank.finished || bank.bytes.len() != length)
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl Serialize for InputBanksHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(6))?;
        for InputBank {
            bytes,
            transfer,
            transfer_length,
            begun,
            finished,
        } in self.0
        {
            let transfer = transfer
                .get(..*transfer_length)
                .ok_or_else(|| serde::ser::Error::custom("native input transfer extent"))?;
            seq.serialize_element(&(
                crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(bytes),
                bytes.capacity(),
                crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(transfer),
                begun,
                finished,
            ))?;
        }
        seq.end()
    }
}

impl Serialize for InputChunksHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for OriginalRestoreInputChunk {
            input,
            offset,
            length,
        } in self.0
        {
            seq.serialize_element(&(input, offset, length))?;
        }
        seq.end()
    }
}

impl Serialize for CustodyHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_settled_capture_boundary_data()
            .map_err(serde::ser::Error::custom)?;
        let OriginalCompleteRestoreInputCustody {
            creator,
            thread: _,
            quote,
            banks,
            chunks,
            summaries,
            native_encoded: _,
            native_owner: _,
            mapping_attempt: _,
            held_proof_quote_taken,
            next_input,
            phase: _,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeInstalledInputCustody17", 11)?;
        fields.serialize_field("schema", "source-private.native-installed-input-custody/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field(
            "quote",
            &quote
                .borrowed_settled_history_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("banks", &InputBanksHistory(banks))?;
        fields.serialize_field("chunks", &InputChunksHistory(chunks))?;
        fields.serialize_field("chunk_capacity", &chunks.capacity())?;
        // These alias summaries are completed decoder scratch, not live graph
        // owners. The paired reader recomputes them from the immutable imported
        // protocol with the exact retained finite count; no old pointer survives.
        fields.serialize_field("decoder_summary_capacity", &summaries.capacity())?;
        fields.serialize_field("held_proof_quote_taken", held_proof_quote_taken)?;
        fields.serialize_field("next_input", next_input)?;
        fields.serialize_field("phase", "complete-mapping-transferred")?;
        fields.end()
    }
}
