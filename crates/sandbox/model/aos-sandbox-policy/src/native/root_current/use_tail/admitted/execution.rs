//! Executes Root3 using actual refreshed predecessors and the sole native gate.
//!
//! Local fixed admission and every financial arm use transient same-Initial
//! loans. Native work, append and standard-library writes remain outside L/U;
//! each entered append/send body still owes its original independent bookends.

use super::super::super::{
    initial_cache::RootInitialCacheProofOriginalV1,
    initial_open::RootInitialOpenPreparedOriginalV1,
    initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
    owned::RootCurrentAcceptedOriginalsV1, writers::RootCurrentWritersOriginalV1,
};
use super::super::reserved::RootUseReservedOriginalV1;
use super::*;
use crate::native::startup::RootCurrentWritersPredecessorV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FRAME_HEADER_BYTES;
use std::mem::size_of;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

impl RootUseAdmittedOriginalV1 {
    pub(in crate::native::root_current) fn begin_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        writers: &RootCurrentWritersOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if !self.fixed.entered || self.fixed.permit.is_some() || self.closed {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.fixed.financial = Some(financial.clone());
        self.fixed.permit = Some(self.permit(
            initial,
            open,
            authorization,
            reserved,
            source,
            cache,
            writers,
            financial,
            startup,
            exclusion,
        ));
        self.fixed.finish_v1(initial, startup, exclusion)
    }

    fn permit(
        &mut self,
        initial: &RootInitialReceivingOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        writers: &RootCurrentWritersOriginalV1,
        financial: &RootJournalFinancialOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<ResourceVector, NativeError> {
        let invalid = NativeError::boundary;
        super::super::super::initial_controller::require_same_initial(
            initial, open, financial, startup,
        )?;
        reserved.require_complete_v1().map_err(|_| invalid())?;
        source
            .require_use_complete_for_v1(open, authorization, reserved)
            .map_err(|_| invalid())?;
        cache
            .require_use_complete_for_v1(open, authorization, reserved)
            .map_err(|_| invalid())?;
        if !reserved.same_financial_v1(financial)
            || !source.same_financial_v1(financial)
            || !cache.same_financial_v1(financial)
        {
            return Err(invalid());
        }
        let inputs = writers
            .initial_open_receiving_data_v1()
            .map_err(|_| invalid())?;
        if !inputs.financial.same_original_data_v1(financial) {
            return Err(invalid());
        }
        let base = cache.completed_prefix_v1().map_err(|_| invalid())?;
        self.quote = Some(Self::receiving_demand_v1(
            inputs.held,
            inputs.supplement,
            authorization,
            reserved,
        ));
        let additional = *positive(&self.quote).map_err(|_| invalid())?;
        let complete = base
            .checked_add(additional)
            .map_err(|_| NativeError::geometry())?;
        if financial
            .require_receiving_demand_under_upper_exclusion_v1(exclusion, complete)
            .is_err()
        {
            return Err(NativeError::Financial(financial.clone()));
        }
        Ok(complete)
    }

    fn receiving_demand_v1(
        held: &super::super::super::preopen_geometry::ProtectedJournalPreopenReplayExtentV1,
        supplement: ResourceVector,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
    ) -> Result<ResourceVector, NativeError> {
        let invalid = NativeError::geometry;
        let receipt = authorization
            .completed_receipt_v1()
            .map_err(|_| invalid())?;
        let extent=super::super::super::preopen_geometry::protected_authority_preopen_replay_extent_for_prefix_v1(
            held.limits_v1(),receipt.after_end).map_err(NativeError::Mechanical)?;
        let plan = reserved
            .completed_controller_v1()
            .map_err(|_| invalid())?
            .prospective_use_plan_v1()
            .map_err(|_| invalid())?
            .preparation_data_v1();
        let frame = FRAME_HEADER_BYTES
            .checked_add(20 + USE_ADMITTED_RECEIPT_BYTES_V1)
            .and_then(|bytes| bytes.checked_add(plan.canonical_plan().len()))
            .and_then(|bytes| bytes.checked_add(plan.signing_request().canonical_statement().len()))
            .ok_or_else(invalid)?;
        let owner = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(frame.checked_mul(2)?))
            .ok_or_else(invalid)?;
        super::super::super::initial_geometry::continuation_append_demand_v1(
            &extent,
            supplement,
            USE_ADMITTED_BODY_BYTES_V1,
            frame,
            owner,
        )
    }

    pub(in crate::native::root_current) fn append_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        original: &UnixStream,
    ) -> Result<(), E> {
        positive(&self.primary)?;
        let result = match writers.opened_pair_v1() {
            Ok(pair) => match pair.authority_and_policy_v1() {
                Ok((authority, policy)) => self
                    .pair
                    .append_use_admitted_once_v1(
                        authority,
                        policy,
                        open,
                        authorization,
                        reserved,
                        source,
                        cache,
                        originals,
                        original.as_fd(),
                    )
                    .map_err(E::from),
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
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
    ) {
        if !matches!(self.append_arm, Some(Ok(()))) {
            return;
        }
        self.append_posts
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.append_live = Some(
            self.append_posts
                .require_complete_v1()
                .map_err(E::from)
                .and_then(|()| {
                    require_live(open, reserved, source, self.append_posts.sample_v1()?)
                }),
        );
    }

    pub(in crate::native::root_current) fn send_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
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
        self.sent = Some(self.send.run_once(
            &mut &*original,
            &mut self.frame,
            source.original_cutoff_v1()?,
            DeadlineStreamDirectionV1::Write,
        ));
        self.send_posts
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => {
                self.send_readback = Some(self.pair.readback_pair_v1(authority, policy));
                self.send_metadata = Some(authority.read_view().metadata());
            }
            Err(error) => self.send_readback = Some(Err(RootInitialOpenErrorV1::Root(error))),
        }
        self.send_live = Some((|| {
            self.send_posts.require_complete_v1()?;
            require_live(open, reserved, source, self.send_posts.sample_v1()?)?;
            positive(&self.send_readback)?;
            self.pair.require_end_v1(&self.send_metadata)?;
            Ok(())
        })());
        self.complete = self.send.completed_exact()
            && self.failure_v1().is_none()
            && matches!(self.send_live, Some(Ok(())));
        self.require_complete_v1()
    }
}

fn require_live(
    open: &RootInitialOpenPreparedOriginalV1,
    reserved: &RootUseReservedOriginalV1,
    source: &RootInitialSourceExchangeOriginalV1,
    sample: RawPairedClockSample,
) -> Result<(), E> {
    let body = open.body_v1()?;
    open.clock_original_v1()
        .require_current_v1(sample, body.cutoff)
        .map_err(RootInitialOpenErrorV1::from)?;
    reserved
        .completed_controller_v1()?
        .require_live_at_v1(sample)?;
    if sample.boottime_nanoseconds() >= source.original_cutoff_v1()? {
        return Err(E::Incomplete);
    }
    Ok(())
}
