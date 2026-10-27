//! Borrows complete native Connection child history without reviving rights.
//!
//! Actual shared payloads are encoded once by the enclosing native17 graph.
//! This view preserves all raw/typed/partial fields and records their real alias
//! edges. Deadline labels are historical roles; host clock coordinates are
//! deliberately unencoded and no fresh deadline or issuer is reconstructed.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct ChildHistory<'a>(&'a CompletedHeldProof);

impl CompletedHeldProof {
    /// Borrows every actual field under its original native owner relation.
    ///
    /// # Errors
    /// Refuses foreign originating roots, borrowed token relations or a changed
    /// installed mapping. This grants no Capture, continuation or installation.
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.actor.ensure_current()?;
        Ok(ChildHistory(self))
    }

    /// Appends complete actual child capacities and shared edges without reset.
    ///
    /// # Errors
    /// Refuses foreign/borrowed roots, exhausted admitted banks or checked overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        let Self {
            actor,
            bank,
            prefix_slots,
            prefix_digest,
            commit_sequence,
            next_received,
            next_sent,
        } = self;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        observer.shared_original(MetadataSharedKind::FrameBank, bank.as_ref())?;
        observer.observe(prefix_slots)?;
        observer.observe(prefix_digest.as_bytes())?;
        observer.observe(commit_sequence)?;
        observer.observe(next_received)?;
        observer.observe(next_sent)?;
        Ok(())
    }

    /// Names the defining borrowed field, serializer, option and error headers.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<ChildHistory<'static>>()
            + size_of::<Result<ChildHistory<'static>, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<&[u8; 32]>()
            + field_view_bytes(|value: &'static CompletedHeldProof| {
                let CompletedHeldProof {
                    actor,
                    bank,
                    prefix_slots,
                    prefix_digest,
                    commit_sequence,
                    next_received,
                    next_sent,
                } = value;
                (
                    actor,
                    bank,
                    prefix_slots,
                    prefix_digest,
                    commit_sequence,
                    next_received,
                    next_sent,
                )
            })
    }
}

impl Serialize for ChildHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .actor
            .ensure_current()
            .map_err(serde::ser::Error::custom)?;
        let CompletedHeldProof {
            actor,
            bank,
            prefix_slots,
            prefix_digest,
            commit_sequence,
            next_received,
            next_sent,
        } = self.0;
        let mut state = serializer.serialize_struct("NativeConnectionChildHistory17", 8)?;
        state.serialize_field("schema", "source-private.restore-held-proof-history/17")?;
        let _ = actor;
        state.serialize_field("actor_role", "native-connection-actor")?;
        let _ = bank;
        state.serialize_field("bank_role", "native-connection-frames")?;
        state.serialize_field("prefix_slots", prefix_slots)?;
        state.serialize_field("prefix_digest", prefix_digest.as_bytes())?;
        state.serialize_field("commit_sequence", commit_sequence)?;
        state.serialize_field("next_received", next_received)?;
        state.serialize_field("next_sent", next_sent)?;
        state.end()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}
