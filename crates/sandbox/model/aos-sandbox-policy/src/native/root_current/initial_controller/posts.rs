//! Finishes Initial Controller's independently owed native and clock posts.
//!
//! Body refusal never suppresses writer names, archived reader names, mount,
//! Storage or metadata. The actual prearmed peer is observed afterwards; its
//! positive original drops before the same distinct late clock is sampled.

use super::super::initial_source_exchange::RootInitialSourceExchangeOriginalV1;
use super::super::owned::RootCurrentAcceptedOriginalsV1;
use super::super::writers::RootCurrentWritersOriginalV1;
use super::*;
use super::purpose::RootControllerPostPurposeBorrowV1;

impl RootInitialControllerReadonlyOriginalV1 {
    pub(in crate::native::root_current) fn observe_native_posts_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        self.observe_native_posts_for_purpose_once_v1(
            writers,
            open,
            RootControllerPurposeBorrowV1::Initial.post_v1(),
        );
    }

    pub(in crate::native::root_current) fn observe_reserved_native_posts_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &super::super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        received: &super::super::use_tail::reserved::RootUseReservedReceivedOriginalV1,
    ) {
        self.observe_native_posts_for_purpose_once_v1(
            writers,
            open,
            RootControllerPurposeBorrowV1::Reserved {
                authorization,
                received,
            }.post_v1(),
        );
    }

    fn observe_native_posts_for_purpose_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        purpose: RootControllerPostPurposeBorrowV1<'_>,
    ) {
        if !self.body.body_entered || self.body.after_readback.is_some() {
            return;
        }
        if let Ok((authority, policy)) = writers.opened_pair_view_v1() {
            self.body.after.observe_once_v1(authority, policy);
            self.body.after_readback = Some(purpose.readback_v1(open, authority, policy));
        } else {
            self.body.after_readback = Some(Err(RootInitialOpenErrorV1::Boundary));
        }
        self.body
            .reader
            .observe_current_names_after_once_v1(&mut self.body.model);
        self.body.reader.observe_current_mount_after_once_v1();
        self.body.storage_inventory.finish_post_once();
        self.body.after_metadata = self
            .body
            .reader
            .observe_current_file_metadata_v1(&self.body.model);
        self.body.after_length = Some((|| {
            let metadata =
                positive(&self.body.after_metadata).map_err(|_| ReadError::ProtectedBoundary)?;
            let lane = open
                .body_v1()
                .map_err(|_| ReadError::ProtectedBoundary)?
                .open
                .lane;
            let receipt = InputsReadyNativeReceiptDataV1::decode(&self.receipt, lane)
                .map_err(|_| ReadError::ProtectedBoundary)?;
            if metadata.len()
                != purpose
                    .after_end_v1(lane, receipt, &self.body)
                    .map_err(|_| ReadError::ProtectedBoundary)?
            {
                return Err(ReadError::ProtectedBoundary);
            }
            Ok(())
        })());
    }

    pub(in crate::native::root_current) fn observe_peer_and_clock_once_v1(
        &mut self,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
    ) {
        if !self.body.body_entered || self.body.after_readback.is_none() || self.body.peer.is_some()
        {
            return;
        }
        self.body.peer = Some(match &mut self.body.peer_original {
            Some(history) => match history.borrow_accepted_v1(&originals.peer, &originals.stream) {
                Ok(mut accepted) => accepted.observe_shared_once_v1(),
                Err(error) => Err(error),
            },
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.body.peer, Some(Ok(()))) {
            drop(self.body.peer_original.take());
        }
        self.body.after_sample = Some(self.body.after_clock.observe_once(None));
        self.body.after_cutoff = Some(super::super::initial_cache::require_clock(
            open,
            source,
            &self.body.after_sample,
        ));
        if let Some(Ok(sample)) = &self.body.after_sample {
            if self.body.storage_inventory.failure().is_none() && self.body.storage_width.is_some()
            {
                self.body.storage_liveness =
                    Some(self.body.storage_inventory.require_live_at_v1(*sample));
            }
        }
        if self.body.compiled.require_complete().is_ok() {
            self.body.compiler_liveness = Some(
                positive(&self.body.after_sample)
                    .map_err(|_| ReadError::ProtectedBoundary)
                    .and_then(|sample| self.body.compiled.require_live_at_v1(*sample)),
            );
        }
        if let (Some(Ok(before)), Some(Ok(after))) =
            (&self.body.before_sample, &self.body.after_sample)
        {
            self.body.interval = Some(before.validate_later_sample(*after));
        }
    }

    pub(in crate::native::root_current) fn require_complete_v1(&self) -> Result<(), E> {
        let state = &self.body;
        state.fixed.require_complete_v1()?;
        state.native.require_complete_v1()?;
        state.semantic.require_complete_v1()?;
        if !state.body_entered || state.closed {
            return Err(E::Incomplete);
        }
        positive(&state.primary)?;
        state.after.require_complete_v1()?;
        positive(&state.after_readback)?;
        positive(&state.after_length)?;
        positive(&state.peer)?;
        positive(&state.after_cutoff)?;
        positive(&state.compiler_liveness)?;
        positive(&state.storage_liveness)?;
        state
            .storage_inventory
            .require_complete()
            .map_err(|_| E::Incomplete)?;
        positive(&state.interval)?;
        if !state.suffix_progress.is_complete()
            || !state.previous_progress[..state.suffix_segments - 1]
                .iter()
                .all(|progress| progress.is_complete())
            || state.suffix_active != state.suffix_segments - 1
            || self.failure_v1().is_some()
        {
            return Err(E::Incomplete);
        }
        Ok(())
    }

    pub(in crate::native::root_current) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        self.body.semantic.require_complete_v1().map_err(E::from)
    }

    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.body.failure_v1()
    }
}

impl RootInitialControllerReadonlyBodyV1 {
    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let state = self;
        state.predecessor.as_ref().map(|error| error as _)
            .or_else(|| cause(&state.fixed_quote))
            .or_else(|| state.fixed.failure_v1())
            .or_else(|| cause(&state.tail_preparation))
            .or_else(|| state.signed_suffix.failure())
            .or_else(|| cause(&state.receipt_copy))
            .or_else(|| cause(&state.receipt_decoding))
            .or_else(|| cause(&state.expected))
            .or_else(|| cause(&state.coordinates))
            .or_else(|| cause(&state.storage_width))
            .or_else(|| cause(&state.compiler_root_width))
            .or_else(|| cause(&state.history_geometry))
            .or_else(|| state.before.native_failure_v1())
            .or_else(|| state.before.returned_failure_v1())
            .or_else(|| cause(&state.before_readback))
            .or_else(|| state.before_clock.failure())
            .or_else(|| cause(&state.before_sample))
            .or_else(|| cause(&state.before_cutoff))
            .or_else(|| state.receiving.named_failure_v1())
            .or_else(|| {
                let context_failed = state.receiving.captured_failure_v1().is_some()
                    || state.accepted_native.failure().is_some()
                    || state.suffix_progress.failure().is_some()
                    || state.previous_progress.iter().any(|progress| progress.failure().is_some());
                if context_failed {
                    None
                } else {
                    state.reader.current_primary_failure_v1()
                        .or_else(|| state.model.current_primary_failure_v1())
                }
            })
            .or_else(|| cause(&state.captured_binding))
            .or_else(|| state.native_predecessor.as_ref().map(|error| error as _))
            .or_else(|| cause(&state.tail_native))
            .or_else(|| cause(&state.native_quote))
            .or_else(|| state.native.failure_v1())
            .or_else(|| state.previous_expected.iter().find_map(cause))
            .or_else(|| state.reader.current_audit_original_v1().failure())
            .or_else(|| cause(&state.bank_use_geometry))
            .or_else(|| state.semantic_predecessor.as_ref().map(|error| error as _))
            .or_else(|| state.outcome_suffix.failure())
            .or_else(|| state.closed_suffix.failure())
            .or_else(|| cause(&state.tail_semantic))
            .or_else(|| cause(&state.semantic_quote))
            .or_else(|| state.semantic.failure_v1())
            .or_else(|| state.accepted_native.failure())
            .or_else(|| state.previous_progress.iter().find_map(|progress| progress.failure()).map(|cause| cause as _))
            .or_else(|| state.suffix_progress.failure().map(|cause| cause as _))
            .or_else(|| cause(&state.suffix_construction))
            .or_else(|| state.receiving.captured_failure_v1())
            .or_else(|| state.reader.current_primary_failure_v1())
            .or_else(|| state.model.current_primary_failure_v1())
            .or_else(|| cause(&state.native_binding))
            .or_else(|| cause(&state.history_binding))
            .or_else(|| state.accepted_create.failure())
            .or_else(|| state.root_parent.failure())
            .or_else(|| cause(&state.root_parent_result))
            .or_else(|| state.compiled.failure())
            .or_else(|| state.storage_inventory.failure())
            .or_else(|| cause(&state.primary))
            .or_else(|| state.after.native_failure_v1())
            .or_else(|| state.after.returned_failure_v1())
            .or_else(|| cause(&state.after_readback))
            .or_else(|| state.reader.failure())
            .or_else(|| state.model.failure())
            .or_else(|| state.reader.post_failure())
            .or_else(|| state.storage_inventory.post_failure())
            .or_else(|| cause(&state.after_metadata))
            .or_else(|| cause(&state.after_length))
            .or_else(|| state.peer_original.as_ref().and_then(|original| original.failure_v1()))
            .or_else(|| cause(&state.peer_arm))
            .or_else(|| cause(&state.peer))
            .or_else(|| state.after_clock.failure())
            .or_else(|| cause(&state.after_sample))
            .or_else(|| cause(&state.after_cutoff))
            .or_else(|| cause(&state.storage_liveness))
            .or_else(|| cause(&state.compiler_liveness))
            .or_else(|| cause(&state.interval))
            .or_else(|| state.closed.then_some(&CLOSED as &(dyn Error + 'static)))
    }
}

const CLOSED: ReadError = ReadError::ProtectedBoundary;

impl RootInitialControllerReadonlyOriginalV1 {
    pub(in crate::native::root_current) fn receiving_fixed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.body.fixed.require_complete_v1().map_err(E::from)
    }

    pub(in crate::native::root_current) fn same_receiving_fixed_financial_v1(
        &self, financial: &RootJournalFinancialOriginalV1,
    ) -> bool {
        self.body.fixed.financial.as_ref().is_some_and(|same| same.same_original_data_v1(financial))
    }

    // This is the SAME protected-built Inventory on the completed C9 purpose;
    // it is borrowed for the later independent Session terminal comparison.
    pub(in crate::native::root_current) fn storage_inventory_v1(&self)
        -> Result<&super::super::storage_inventory::RootCurrentStorageInventoryV1, E>
    {
        self.require_complete_v1()?;
        Ok(&self.body.storage_inventory)
    }

    pub(in crate::native::root_current) fn completed_sample_v1(&self) -> Result<RawPairedClockSample, E> {
        self.require_complete_v1()?;
        positive(&self.body.after_sample).copied()
    }

    pub(in crate::native::root_current) fn outcome_suffix_v1(&self)
        -> Result<&tail_data::RootControllerOutcomeSuffixDataV1, E>
    {
        self.require_complete_v1()?;
        if self.body.suffix_segments != 10 { return Err(E::Incomplete); }
        self.body.outcome_suffix.require_complete_v1()?;
        Ok(&self.body.outcome_suffix)
    }

    pub(in crate::native::root_current) fn closed_suffix_v1(&self)
        -> Result<&tail_data::RootControllerClosedSuffixDataV1, E>
    {
        self.require_complete_v1()?;
        if self.body.suffix_segments != 12 { return Err(E::Incomplete); }
        self.body.closed_suffix.require_complete_v1()?;
        Ok(&self.body.closed_suffix)
    }

    pub(in crate::native::root_current) fn require_closed_original_v1(
        &self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &purpose::RootInitialUseAuthorizedOriginalV1,
        reserved: &purpose::RootUseReservedOriginalV1,
        signed: &purpose::RootSignedBoundOriginalV1,
        outcome: &purpose::RootUseOutcomeOriginalV1,
        input: &purpose::RootReleaseInputOriginalV1,
    ) -> Result<(), E> {
        self.require_complete_v1()?;
        let body = open.body_v1()?;
        if self.body.suffix_segments != 12 || self.body.purpose_root_nonce != Some(body.root_nonce) {
            return Err(E::Incomplete);
        }
        let financial = self.body.semantic.financial.as_ref().ok_or(E::Incomplete)?;
        if !authorization.same_financial_v1(financial) || !reserved.same_financial_v1(financial)
            || !signed.same_financial_v1(financial) || !outcome.same_financial_v1(financial)
        { return Err(E::Incomplete); }
        // This compares against the private expected handoff already observed
        // by THIS actual 12-segment native replay, not a supplied phase flag.
        let expected = self.body.closed_suffix.expected_v1()?;
        let receipt = input.controller_receipt_v1(body.open.lane).map_err(|_| E::Incomplete)?;
        let [record, head] = expected[1].records() else { return Err(E::Incomplete); };
        if record.value() != Some(receipt.record) || head.value() != Some(receipt.latest_head.as_slice()) {
            return Err(E::Incomplete);
        }
        Ok(())
    }
    pub(in crate::native::root_current) fn observe_signed_native_posts_once_v1(
        &mut self, writers: &RootCurrentWritersOriginalV1, open: &RootInitialOpenPreparedOriginalV1,
        _authorization: &purpose::RootInitialUseAuthorizedOriginalV1,
        _reserved: &purpose::RootUseReservedOriginalV1,
        admitted: &purpose::RootUseAdmittedOriginalV1,
        _input: &purpose::RootSignedInputOriginalV1,
    ) {
        self.observe_native_posts_for_purpose_once_v1(writers, open,
            RootControllerPostPurposeBorrowV1::Signed { admitted });
    }

    pub(in crate::native::root_current) fn observe_outcome_native_posts_once_v1(
        &mut self, writers: &RootCurrentWritersOriginalV1, open: &RootInitialOpenPreparedOriginalV1,
        _authorization: &purpose::RootInitialUseAuthorizedOriginalV1,
        _reserved: &purpose::RootUseReservedOriginalV1,
        _admitted: &purpose::RootUseAdmittedOriginalV1,
        signed: &purpose::RootSignedBoundOriginalV1,
        input: &purpose::RootOutcomeInputOriginalV1,
    ) {
        self.observe_native_posts_for_purpose_once_v1(writers, open,
            RootControllerPostPurposeBorrowV1::Outcome { signed, input });
    }

    pub(in crate::native::root_current) fn observe_closed_native_posts_once_v1(
        &mut self, writers: &RootCurrentWritersOriginalV1, open: &RootInitialOpenPreparedOriginalV1,
        _authorization: &purpose::RootInitialUseAuthorizedOriginalV1,
        _reserved: &purpose::RootUseReservedOriginalV1,
        _signed: &purpose::RootSignedBoundOriginalV1,
        outcome: &purpose::RootUseOutcomeOriginalV1,
        input: &purpose::RootReleaseInputOriginalV1,
    ) {
        self.observe_native_posts_for_purpose_once_v1(writers, open,
            RootControllerPostPurposeBorrowV1::Closed { outcome, input });
    }

}
