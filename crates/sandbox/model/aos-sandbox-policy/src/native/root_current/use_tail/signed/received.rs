//! Owns Signed's real input bookends, variable stage and verification.
//!
//! Fixed/index and variable/chunk loans are disjoint short operations. The
//! surrounding caller always reaches the after bookend once this body entered.

use super::super::super::{
    initial_bundle::RootInitialBundleOwnershipOriginalV1,
    initial_ready::RootInitialReadyOriginalV1,
    initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    owned::RootCurrentAcceptedOriginalsV1, writers::RootCurrentWritersOriginalV1,
};
use super::super::signed_input::RootSignedInputBorrowV1;
use super::*;
use crate::native::startup::RootCurrentWritersPredecessorV1;
use aos_sandbox_broker::receiving::{RootSelectedStartupBorrowV1, RootUpperMutationGuardV1};

pub(in crate::native::root_current) struct RootSignedReceivedOriginalV1 {
    pub(in crate::native::root_current) input: RootSignedInputOriginalV1,
    pub(in crate::native::root_current) variable: RootInitialStageOriginalV1,
    pub(in crate::native::root_current) verification: RootSignedVerificationV1,
    pub(in crate::native::root_current) before: RootInitialOpenPostsOriginalV1,
    pub(in crate::native::root_current) after: RootInitialOpenPostsOriginalV1,
    pub(in crate::native::root_current) before_arm: Slot<(), RootObservationErrorV1>,
    pub(in crate::native::root_current) after_arm: Slot<(), RootObservationErrorV1>,
    before_readback: Slot<(), RootInitialOpenErrorV1>,
    before_live: Slot<()>,
    variable_quote: Slot<ResourceVector, super::super::signed_input::RootSignedInputErrorV1>,
    pub(in crate::native::root_current) variable_predecessor: Option<RootObservationErrorV1>,
    result: Slot<()>,
    after_readback: Slot<(), RootInitialOpenErrorV1>,
    after_live: Slot<()>,
    interval: Slot<(), aos_sandbox_model::OwnershipLeaseVerificationError>,
    entered: bool,
    closed: bool,
}

impl RootSignedReceivedOriginalV1 {
    pub(in crate::native::root_current) fn new() -> Self {
        Self {
            input: RootSignedInputOriginalV1::new(),
            variable: RootInitialStageOriginalV1::new(),
            verification: Default::default(),
            before: RootInitialOpenPostsOriginalV1::new(),
            after: RootInitialOpenPostsOriginalV1::new(),
            before_arm: None,
            after_arm: None,
            before_readback: None,
            before_live: None,
            variable_quote: None,
            variable_predecessor: None,
            result: None,
            after_readback: None,
            after_live: None,
            interval: None,
            entered: false,
            closed: false,
        }
    }

    pub(in crate::native::root_current) fn begin_once_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
        admitted: &RootUseAdmittedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        ownership: &RootInitialBundleOwnershipOriginalV1,
    ) -> Result<(), E> {
        positive(&self.before_arm)?;
        positive(&self.after_arm)?;
        if self.entered || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.entered = true;
        // Prior phase guards belonged before the first observation in the old body.
        admitted.require_complete_v1()?;
        ownership.require_complete_v1()?;
        self.before
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.before_readback = Some(match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => admitted.readback_current_v1(authority, policy).map(|_| ()),
            Err(error) => Err(RootInitialOpenErrorV1::Root(error)),
        });
        self.before_live = Some((|| {
            self.before.require_complete_v1()?;
            positive(&self.before_readback)?;
            require_live(open, reserved, source, self.before.sample_v1()?)
        })());
        positive(&self.before_live).map(|_| ())
    }

    pub(in crate::native::root_current) fn borrow_index_v1<'cut, 'startup>(
        &'cut mut self,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        admitted: &'cut RootUseAdmittedOriginalV1,
        reserved: &'cut RootUseReservedOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
        fixed: &'cut RootInitialStageOriginalV1,
    ) -> Result<RootSignedInputBorrowV1<'cut, 'startup>, E> {
        positive(&self.before_live)?;
        self.input
            .borrow_fixed_v1(originals, open, ready, admitted, reserved, source, fixed)
            .map_err(E::from)
    }

    pub(in crate::native::root_current) fn begin_variable_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        admitted: &RootUseAdmittedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        fixed: &RootInitialStageOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if self.variable.entered || self.closed {
            self.closed = true;
            initial.latch_root_refusal_v1();
            return Err(RootObservationErrorV1::Service);
        }
        self.variable.entered = true;
        self.variable.financial = Some(financial.clone());
        self.variable.permit = Some((|| {
            super::super::super::initial_controller::require_same_initial(
                initial, open, financial, startup,
            )?;
            admitted
                .require_complete_v1()
                .map_err(|_| NativeError::boundary())?;
            reserved
                .require_complete_v1()
                .map_err(|_| NativeError::boundary())?;
            if !admitted.same_financial_v1(financial)
                || !reserved.same_financial_v1(financial)
                || !fixed
                    .financial
                    .as_ref()
                    .is_some_and(|same| same.same_original_data_v1(financial))
            {
                return Err(NativeError::boundary());
            }
            let base = fixed
                .require_complete_v1()
                .map_err(|_| NativeError::boundary())?;
            self.variable_quote = Some(self.input.additional_received_demand_v1(reserved));
            let complete = base
                .checked_add(*positive(&self.variable_quote).map_err(|_| NativeError::geometry())?)
                .map_err(|_| NativeError::geometry())?;
            if financial
                .require_receiving_demand_under_upper_exclusion_v1(exclusion, complete)
                .is_err()
            {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(complete)
        })());
        self.variable.finish_v1(initial, startup, exclusion)
    }

    pub(in crate::native::root_current) fn borrow_chunks_v1<'cut, 'startup>(
        &'cut mut self,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        ready: &'cut RootInitialReadyOriginalV1,
        admitted: &'cut RootUseAdmittedOriginalV1,
        reserved: &'cut RootUseReservedOriginalV1,
        source: &'cut RootInitialSourceExchangeOriginalV1,
    ) -> Result<RootSignedInputBorrowV1<'cut, 'startup>, E> {
        self.input
            .borrow_variable_v1(
                originals,
                open,
                ready,
                admitted,
                reserved,
                source,
                &self.variable,
            )
            .map_err(E::from)
    }

    pub(in crate::native::root_current) fn verify_once_v1(
        &mut self,
        reserved: &RootUseReservedOriginalV1,
        ownership: &RootInitialBundleOwnershipOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
    ) -> Result<(), E> {
        if self.result.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.result = Some((|| {
            let bundle = self.input.received_bundle_v1()?;
            self.verification.verify_once(
                bundle,
                reserved,
                ownership,
                self.before.sample_v1()?,
                source.original_cutoff_v1()?,
            )
        })());
        positive(&self.result).map(|_| ())
    }

    pub(in crate::native::root_current) fn observe_after_once_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
        admitted: &RootUseAdmittedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
    ) {
        if !self.entered {
            return;
        }
        self.after
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.after_readback = Some(match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => admitted.readback_current_v1(authority, policy).map(|_| ()),
            Err(error) => Err(RootInitialOpenErrorV1::Root(error)),
        });
        self.after_live = Some((|| {
            self.after.require_complete_v1()?;
            positive(&self.after_readback)?;
            require_live(open, reserved, source, self.after.sample_v1()?)
        })());
        if let (Ok(before), Ok(after)) = (self.before.sample_v1(), self.after.sample_v1()) {
            self.interval = Some(before.validate_later_sample(after));
        }
    }

    pub(in crate::native::root_current) fn require_complete_v1(&self) -> Result<(), E> {
        if !self.entered || self.closed {
            return Err(E::Incomplete);
        }
        self.variable.require_complete_v1()?;
        self.input.require_received_v1()?;
        self.verification.require_complete_v1()?;
        positive(&self.result)?;
        positive(&self.after_live)?;
        positive(&self.interval)?;
        if self.failure_v1().is_none() {
            Ok(())
        } else {
            Err(E::Incomplete)
        }
    }

    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.input
            .geometry_failure_v1()
            .or_else(|| cause(&self.before_arm))
            .or_else(|| cause(&self.after_arm))
            .or_else(|| self.before.failure_v1())
            .or_else(|| cause(&self.before_readback))
            .or_else(|| cause(&self.before_live))
            .or_else(|| self.input.before_variable_failure_v1())
            .or_else(|| self.variable_predecessor.as_ref().map(|cause| cause as _))
            .or_else(|| cause(&self.variable_quote))
            .or_else(|| self.variable.failure_v1())
            .or_else(|| self.input.after_variable_failure_v1())
            .or_else(|| self.verification.failure())
            .or_else(|| cause(&self.result))
            .or_else(|| self.after.failure_v1())
            .or_else(|| cause(&self.after_readback))
            .or_else(|| cause(&self.after_live))
            .or_else(|| cause(&self.interval))
    }
}

pub(super) fn require_live(
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
