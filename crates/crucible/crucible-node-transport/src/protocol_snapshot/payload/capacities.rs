//! Observes post-move custody without charging historical encoded capacity again.

use super::*;
use crate::protocol_snapshot::capacities::{inline, observe_association, observe_banks};
use crate::retained_metadata::MetadataObserver;

impl OriginalProtocolPayloadOwner {
    pub(crate) fn check_capacity_creator_data(&self) -> Result<(), ProviderError> {
        self.owner.ensure_current()
    }

    pub(crate) fn observe_capacity_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            compact,
            owned11_records,
            owned11_aliases,
            original_assigned_cut,
            original_restore_cut,
            original_hello,
            maximum,
            encoded_length,
            encoded_capacity,
            body,
            authority,
            owner,
            cut,
            deadline,
            literal,
            codec,
        } = self;
        inline(compact);
        inline(original_assigned_cut);
        inline(original_restore_cut);
        inline(maximum);
        inline(encoded_length);
        inline(encoded_capacity);
        inline(body);
        inline(cut);
        inline(deadline);

        observe_banks(
            owned11_records.as_ref(),
            owned11_aliases.as_ref(),
            literal.as_ref(),
            observer,
        )?;
        observe_association(
            owner,
            authority,
            codec.as_ref(),
            original_hello.as_ref(),
            observer,
        )
    }
}
