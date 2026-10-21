//! Runs the actual local Root Stage, append and independent write bookends.

use super::*;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use aos_sandbox_broker::receiving::{RootInitialReceivingOriginalV1,
    RootJournalFinancialOriginalV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    root_open::RootHelloDataV1,
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameKindV1},
};
use crate::native::startup::RootCurrentWritersPredecessorV1;
use super::super::{
    initial_controller::RootInitialControllerReadonlyOriginalV1,
    initial_open::RootInitialOpenPreparedOriginalV1,
    initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    initial_cache::RootInitialCacheProofOriginalV1,
    initial_ready::RootInitialReadyOriginalV1,
    owned::RootCurrentAcceptedOriginalsV1,
    writers::RootCurrentWritersOriginalV1,
};

impl RootInitialUseAuthorizedOriginalV1 {
    pub(in crate::native::root_current) fn begin_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        readonly: &RootInitialControllerReadonlyOriginalV1,
        writers: &RootCurrentWritersOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if self.fixed.permit.is_some() || !self.fixed.entered || self.closed {
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.fixed.financial = Some(financial.clone());
        self.fixed.permit = Some(self.local_permit(initial, open, readonly, writers,
            financial, startup, exclusion));
        self.fixed.finish_v1(initial, startup, exclusion)
    }

    fn local_permit(
        &mut self,
        initial: &RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        readonly: &RootInitialControllerReadonlyOriginalV1,
        writers: &RootCurrentWritersOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        let invalid = PolicyNativeJournalErrorV1::boundary;
        super::super::initial_controller::require_same_initial(initial, open, financial, startup)?;
        readonly.require_complete_v1().map_err(|_| invalid())?;
        if !readonly.same_financial_v1(financial) {
            return Err(invalid());
        }
        let inputs = writers.initial_open_receiving_data_v1().map_err(|_| invalid())?;
        if !inputs.financial.same_original_data_v1(financial) {
            return Err(invalid());
        }
        let base = readonly.completed_prefix_v1().map_err(|_| invalid())?;
        self.fixed_quote = Some(super::super::initial_geometry::use_authorized_append_demand_v1(
            inputs.held, inputs.supplement,
        ));
        let additional = *positive(&self.fixed_quote).map_err(|_| invalid())?;
        let complete = base.checked_add(additional).map_err(|_| PolicyNativeJournalErrorV1::geometry())?;
        if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, complete).is_err() {
            return Err(PolicyNativeJournalErrorV1::Financial(financial.clone()));
        }
        Ok(complete)
    }

    pub(in crate::native::root_current) fn append_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        readonly: &RootInitialControllerReadonlyOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        original: &UnixStream,
    ) -> Result<(), E> {
        positive(&self.primary)?;
        let result = match writers.opened_pair_v1() {
            Ok(pair) => match pair.authority_and_policy_v1() {
                Ok((authority, policy)) => self.pair.append_use_authorized_once_v1(
                    authority, policy, open, readonly, source, cache, originals, original.as_fd(),
                ).map_err(E::from),
                Err(error) => Err(E::Root(error)),
            },
            Err(error) => Err(E::Root(error)),
        };
        self.primary = Some(result);
        positive(&self.primary).map(|_| ())
    }

    pub(in crate::native::root_current) fn observe_append_posts_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        readonly: &RootInitialControllerReadonlyOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
    ) {
        // The old Use programme returns before entering its body if this arm
        // failed. Its successful arm owes all posts after any attempted body.
        if !matches!(self.append_arm, Some(Ok(()))) {
            return;
        }
        self.append_posts.observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.append_live = Some(match self.append_posts.require_complete_v1() {
            Ok(()) => match self.append_posts.sample_v1() {
                Ok(sample) => require_live_v1(open, source, readonly, sample),
                Err(error) => Err(E::Open(error)),
            },
            Err(error) => Err(E::Open(error)),
        });
    }

    pub(in crate::native::root_current) fn frame_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
    ) -> Result<(), E> {
        positive(&self.primary)?;
        positive(&self.append_live)?;
        if self.framing.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.framing = Some(self.make_frame(open, ready, cache));
        positive(&self.framing).map(|_| ())
    }

    fn make_frame(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
    ) -> Result<(), HistoryErrorV1> {
        ready.original_hello_frame_v1(open, &mut self.hello)?;
        let body = open.body_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        let hello = RootHelloDataV1::decode(&self.hello, body.open)?;
        let receipt = self.receipt_data_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        receipt.require_originals(&hello, cache.controller_receipt_v1(open, ready)
            .map_err(|_| HistoryErrorV1::Correlation)?)?;
        let encoded = receipt.encode(body.open.lane)?;
        let sequence = u64::from(ready.original_transfer_index_v1()
            .map_err(|_| HistoryErrorV1::Correlation)?.count())
            .checked_add(5).ok_or(HistoryErrorV1::Extent)?;
        let header = FrameCoordinatesV1 {
            kind: FrameKindV1::UseAuthorized,
            lane: body.open.lane,
            sequence,
            root_nonce: body.root_nonce,
            controller_nonce: body.open.controller_nonce,
        }.encode_header(&encoded)?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        self.frame[FRAME_HEADER_BYTES..].copy_from_slice(&encoded);
        Ok(())
    }

    pub(in crate::native::root_current) fn send_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        readonly: &RootInitialControllerReadonlyOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        original: &UnixStream,
    ) -> Result<(), E> {
        positive(&self.framing)?;
        positive(&self.send_arm)?;
        if self.sent.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        let cutoff = source.original_cutoff_v1().map_err(|_| E::Incomplete)?;
        self.sent = Some(self.send.run_once(&mut &*original, &mut self.frame,
            cutoff, DeadlineStreamDirectionV1::Write));
        self.send_posts.observe_once_v1(writers, open, &originals.peer, &originals.stream);
        match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => {
                self.send_readback = Some(self.pair.readback_pair_v1(authority, policy));
                self.send_native_end = Some(authority.read_view().metadata());
            }
            Err(error) => self.send_readback = Some(Err(RootInitialOpenErrorV1::Root(error))),
        }
        self.send_live = Some(self.require_send_live(open, readonly, source));
        self.complete = self.send.completed_exact() && self.failure_v1().is_none()
            && matches!(self.send_live, Some(Ok(())));
        self.require_complete_v1()
    }

    fn require_send_live(
        &self,
        open: &RootInitialOpenPreparedOriginalV1,
        readonly: &RootInitialControllerReadonlyOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
    ) -> Result<(), E> {
        self.send_posts.require_complete_v1()?;
        require_live_v1(open, source, readonly, self.send_posts.sample_v1()?)?;
        positive(&self.send_readback)?;
        self.pair.require_end_v1(&self.send_native_end).map_err(E::from)
    }
}

pub(super) fn control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    type State = RootInitialUseAuthorizedOriginalV1;
    let entry = size_of::<(&mut State, &RootInitialOpenPreparedOriginalV1,
        &RootInitialControllerReadonlyOriginalV1, &RootCurrentWritersOriginalV1,
        RootCurrentWritersPredecessorV1<'_, '_, '_>, &RootSelectedStartupBorrowV1<'_>,
        &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?;
    let permit = size_of::<(&mut State, &RootInitialReceivingOriginalV1,
        &RootInitialOpenPreparedOriginalV1, &RootInitialControllerReadonlyOriginalV1,
        &RootCurrentWritersOriginalV1, &RootJournalFinancialOriginalV1,
        &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?;
    let cuts = size_of::<(&mut State, &RootInitialOpenPreparedOriginalV1,
        &RootInitialControllerReadonlyOriginalV1, &RootInitialSourceExchangeOriginalV1,
        &RootInitialCacheProofOriginalV1, &mut RootCurrentWritersOriginalV1,
        &RootCurrentAcceptedOriginalsV1<'_>, &UnixStream)>().checked_mul(9)?;
    let frames = size_of::<(&mut State, &RootInitialOpenPreparedOriginalV1,
        &RootInitialReadyOriginalV1, &RootInitialCacheProofOriginalV1)>().checked_mul(6)?;
    let live = size_of::<(&RootInitialOpenPreparedOriginalV1,
        &RootInitialSourceExchangeOriginalV1, &RootInitialControllerReadonlyOriginalV1,
        RawPairedClockSample)>().checked_mul(9)?;
    let results = size_of::<Result<(), E>>().checked_mul(33)?
        .checked_add(size_of::<Result<(), HistoryErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>().checked_mul(9)?)?
        .checked_add(size_of::<ResourceVector>().checked_mul(12)?)?
        .checked_add(size_of::<Option<RootObservationErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<bool>().checked_mul(3)?)?;
    entry.checked_add(permit)?.checked_add(cuts)?.checked_add(frames)?.checked_add(live)?.checked_add(results)
}
