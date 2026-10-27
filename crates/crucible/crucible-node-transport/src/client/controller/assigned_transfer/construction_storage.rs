//! Quotes private SDK assignment, cache and returned-response owners as DATA.
//!
//! Source supplies independent closed envelope/DTO/normalization projections.
//! This child names the actual private assignment/correlation/cache layouts and
//! the full negotiated receive/error graphs whose future bytes are unknown.
//! It creates no request, operation cut, mapping, emitter or publication right.

use super::*;
use crate::retained_metadata::requested_storage::tree_storage_data;
use std::mem::{align_of, size_of};

impl CnpController {
    /// Returns the independent two-phase assignment and response DATA axes.
    ///
    /// Caller rows must separately include all original-envelope backing,
    /// concrete DTO construction, canonical work, mapping clones and input/held
    /// Blob prefixes. Raw literal banks already owned by this controller are
    /// checked for room here; they are not new backing funded by this row.
    ///
    /// # Errors
    /// Refuses a foreign/revoked actor or codec, another selection, an already
    /// populated transfer slot, insufficient actual journal credit or overflow.
    pub fn original_selected_restore_assignment_storage_data(
        &self,
    ) -> Result<(usize, usize, usize), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.session.authenticate_native5_source_codec()?;

        if self.original_native5_complete_restore_selection()?
            != Some(
                crate::reference_packet::service::complete_restore::
                    PacketNative5CompleteRestoreSelection::SourceSignedTransfer12
            )
            || self.original_native5_fresh_restore_allocation_selection()?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || self.original_complete_restore.is_some()
            || self.original_complete_restore_prepare.is_some()
            || self.original_complete_restore_commit.is_some()
        {
            return Err(refused());
        }

        let frame = self.maximum_frame()?;
        let pair = frame.checked_add(frame).ok_or_else(credit)?;
        let both_pairs = pair.checked_add(pair).ok_or_else(credit)?;
        self.preflight_source_reply(2, 0, both_pairs, 0, 0)?;
        let raw = crate::connection::original_host_initial_raw_receive_storage_data(frame)?;
        let cache = self.custody.fresh_query_cache_requested_layout_data(2)?;
        let pending = tree_storage_data(
            1,
            1,
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<Id>().max(align_of::<Envelope>()),
        )?;

        // The two private bytes Vecs are real independently reserved banks.
        // Cached response, assigned response and caller ResponseBody are three
        // independent graphs after decode. At an error only a prefix exists;
        // pricing all three keeps that partially returned custody conservative.
        let retained = sum(&[pair, cache, pending, raw, raw, raw])?;

        // receive returns a temporary frame before moving its envelope into
        // the assigned slot. envelope_bytes and decode_response each construct
        // additional temporary DOM/typed work while retained caches stay live.
        let transient = sum(&[raw, raw, raw])?;

        Ok((
            retained,
            transient,
            Self::original_selected_restore_assignment_counter_scratch_data(),
        ))
    }

    /// Returns exact fixed private assignment and returned-response view layouts.
    pub fn original_selected_restore_assignment_counter_scratch_data() -> usize {
        size_of::<TransferPreparation>()
            + size_of::<TransferExtensions>()
            + size_of::<AssignedOriginalCompleteRestore>()
            + size_of::<PreparedOriginalCompleteRestoreTransfer<'static>>()
            + size_of::<CompletedOriginalCompleteRestoreTransfer<'static>>()
            + size_of::<crate::client::ClientOriginal>()
            + size_of::<crate::connection::ReceivedFrame>()
            + size_of::<crate::connection::ReceivedBody>()
            + size_of::<crate::connection::CompleteRestoreTransferProjection<'static>>()
            + size_of::<
                Result<
                    crate::connection::CompleteRestoreTransferProjection<'static>,
                    ProviderError,
                >,
            >()
            + size_of::<RequestBody>()
            + size_of::<ResponseBody>()
            + size_of::<Option<ResponseBody>>()
            + size_of::<Option<Envelope>>()
            + size_of::<Option<&'static mut ResponseBody>>()
            + size_of::<Result<PreparedOriginalCompleteRestoreTransfer<'static>, ProviderError>>()
            + size_of::<Result<CompletedOriginalCompleteRestoreTransfer<'static>, ProviderError>>()
            + size_of::<Result<RequestBody, ProviderError>>()
            + size_of::<Result<ResponseBody, ProviderError>>()
            + size_of::<(&Envelope, &Value, &Id, &ContentRef)>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), ProviderError>>()
            + size_of::<[usize; 6]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + complete_restore_fresh_prepare_digest_counter_scratch_data()
            + 20
            + 44
    }
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms
        .iter()
        .try_fold(0usize, |sum, one| sum.checked_add(*one).ok_or_else(credit))
}
