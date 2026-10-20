//! Owns the fresh Root Storage Apply connection through its final disposition.
//!
//! The accepted socket, same R loan and native observations remain resident
//! while Controller signs and applies the independently normalized plan. The
//! unsigned reply does not complete this owner. Durable Applied evidence, the
//! real Completing Source model and final acknowledgement complete this Root
//! purpose; the client still needs its post-ACK terminal CAS for public success.

mod opening;
mod receiving;
mod unsigned;
mod final_readonly;
pub(in crate::policy_compiler) mod session;
mod lifecycle;
mod controller;
mod final_exchange;
mod dispatch;
pub(crate) use dispatch::RootStorageApplyDispatchOriginalV1;
pub(crate) use opening::RootStorageApplyOpeningOriginalV1;

use std::error::Error;
use crate::normal_root::NormalRootStartupErrorV1;
use crate::policy_compiler::root_policy_prelude::RootApplyPreludeV1;
use crate::policy_compiler::RootCurrentPolicyInputDataV1;
use receiving::RootStorageApplyNativeOriginalV1;
pub(super) use receiving::PhaseV1;

// This selects an existing owned error before independent posts may fill an
// earlier-empty child slot. It carries no reference or authority.
#[derive(Clone, Copy)]
pub(super) enum UnsignedFailureSourceV1 { Opening, OpeningPost, Phase(PhaseV1), Clock, Financial, Body }

impl UnsignedFailureSourceV1 {
    pub(super) fn select_v1(phase: PhaseV1, opening: bool, child: bool, clock: bool) -> Self {
        if opening { Self::Opening }
        else if child { Self::Phase(phase) }
        else if clock { Self::Clock }
        else { Self::Body }
    }

    pub(super) fn resolve_v1<'cause>(self, opening: Option<&'cause (dyn Error + 'static)>,
        opening_post: Option<&'cause (dyn Error + 'static)>,
        child: Option<&'cause (dyn Error + 'static)>,
        clock: Option<&'cause (dyn Error + 'static)>,
        financial: Option<&'cause (dyn Error + 'static)>,
        body: Option<&'cause (dyn Error + 'static)>) -> Option<&'cause (dyn Error + 'static)>
    {
        match self { Self::Opening => opening, Self::OpeningPost => opening_post, Self::Phase(_) => child,
            Self::Clock => clock, Self::Financial => financial, Self::Body => body }
    }
}

/// Retains one actual Apply purpose without adopting old Prepare authority.
pub struct RootStorageApplyReceivingV1<'flight, 'listener, 'startup> {
    prelude: RootApplyPreludeV1<'flight, 'listener, 'startup>,
    opening: RootStorageApplyOpeningOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<RootStorageApplyNativeOriginalV1>>,
    unsigned: Option<Result<(), Box<dyn Error>>>,
    unsigned_failure: Option<UnsignedFailureSourceV1>,
    negative: Option<Result<(), NormalRootStartupErrorV1>>,
    negative_disposition: Option<Result<(), NormalRootStartupErrorV1>>,
    closed: bool,
}

impl<'flight, 'listener, 'startup> RootStorageApplyReceivingV1<'flight, 'listener, 'startup> {
    pub(crate) fn from_prelude_v1(prelude: RootApplyPreludeV1<'flight, 'listener, 'startup>) -> Self {
        Self { prelude, opening: Default::default(), peer: None, native: None,
            unsigned: None, unsigned_failure: None, negative: None, negative_disposition: None, closed: false }
    }

    /// Receives actual original inputs and sends one independently rebuilt plan.
    ///
    /// The same connection remains exclusively borrowed after this stage. A
    /// failure retains all reached native owners and executes their owed posts.
    ///
    /// # Errors
    /// Refuses an unavailable original, changed native/current policy input or
    /// exhausted original horizon while retaining the first actual cause.
    pub fn receive_unsigned_once_v1(&mut self, policy: &RootCurrentPolicyInputDataV1<'_>)
        -> Result<(), super::create_storage_current::RootCreateStorageCurrentErrorV1>
    {
        use super::create_storage_current::RootCreateStorageCurrentErrorV1 as Stop;
        if self.peer.is_some() || self.closed {
            self.closed = true;
            self.finish_negative_once_v1();
            return Err(Stop::Ready);
        }
        let root = &mut self.prelude.original;
        self.peer = Some(root.flight.admit_apply_controller_peer_once_v1());
        if !matches!(self.peer, Some(Ok(()))) {
            self.finish_negative_once_v1();
            return Err(Stop::Ready);
        }
        let funded = (|| {
            let mut stage = root.flight.apply_stage_receiving_v1()?;
            self.opening.admit_query_once_v1(&mut stage,
                std::mem::size_of::<RootStorageApplyNativeOriginalV1>())?;
            Ok::<_, Box<dyn Error>>(())
        })();
        if let Err(cause) = funded {
            self.unsigned = Some(Err(cause));
            self.select_unsigned_failure_before_posts_v1();
            self.finish_negative_once_v1();
            return Err(Stop::Ready);
        }
        self.native = Some(Box::new(RootStorageApplyNativeOriginalV1::new()));
        let native = self.native.as_mut().ok_or(Stop::Ready)?;
        self.unsigned = Some(unsigned::receive_once_v1(
            &mut self.opening, native, root, policy));
        self.select_unsigned_failure_before_posts_v1();
        // The opening's independent paired post is owed even after a partial
        // remainder or decoder failure. No successful stage refreshes it.
        let _opening_post = self.prelude.original.native.finish_opening_if_owed_v1();
        if !matches!(self.unsigned, Some(Ok(()))) || self.failure().is_some() {
            self.finish_negative_once_v1();
            return Err(Stop::Ready);
        }
        Ok(())
    }

    /// Verifies real preterminal Applied evidence and sends its final acknowledgement.
    ///
    /// The accepted socket and all originals remain borrowed until a separate
    /// positive-disposal consumer retires this completed purpose. A failed
    /// acknowledgement preserves durable completion and ambiguous custody.
    ///
    /// # Errors
    /// Refuses incomplete originals, expired or changed native cuts, a failed
    /// same-payer admission or any missing applied/Source/publication/workspace join.
    pub fn receive_final_once_v1(&mut self, policy: &RootCurrentPolicyInputDataV1<'_>)
        -> Result<(), super::create_storage_current::RootCreateStorageCurrentErrorV1>
    {
        use super::create_storage_current::RootCreateStorageCurrentErrorV1 as Stop;
        if self.closed || !matches!(self.unsigned, Some(Ok(()))) || self.failure().is_some()
            || self.native.as_ref().is_none_or(|native| native.final_geometry.is_some())
        {
            self.closed = true;
            self.finish_negative_once_v1();
            return Err(Stop::Ready);
        }
        let root = &mut self.prelude.original;
        let native = self.native.as_mut().ok_or(Stop::Ready)?;
        native.phase = PhaseV1::Final;
        native.final_geometry = Some(final_exchange::RootApplyFinalExchangeOriginalV1::fixed_demand_v1(root.flight));
        let primary: Result<(), Box<dyn Error>> = (|| {
            let demand = native.final_geometry.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(crate::journal::JournalError::JournalTooLarge)?;
            native.final_funding = Some(root.flight.apply_stage_receiving_v1()?
                .admit_apply_final_proof_once_v1(crate::controller_resource_reservation::RootContinuationDemandV1::from_demand_v1(demand)));
            if !matches!(native.final_funding, Some(Ok(()))) { return Err(crate::journal::JournalError::ProtectedBoundary.into()); }
            let mut final_exchange = Box::new(final_exchange::RootApplyFinalExchangeOriginalV1::new(&self.opening)?);
            // Park the whole reached owner even when its actual body refuses.
            let returned = final_exchange.run_once_v1(&self.opening, native, root, policy);
            native.final_exchange = Some(final_exchange);
            returned?;
            Ok(())
        })();
        native.final_entry = Some(primary);
        if !matches!(native.final_entry, Some(Ok(()))) || self.failure().is_some() {
            self.finish_negative_once_v1();
            return Err(Stop::Ready);
        }
        Ok(())
    }

    pub(crate) fn require_final_complete_v1(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.closed || self.failure().is_some() || !matches!(self.unsigned, Some(Ok(())))
            || self.prelude.original.negative_disposition_entered_v1()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.native.as_ref().and_then(|native| native.final_exchange.as_ref())
            .ok_or(NormalRootStartupErrorV1::Service)?.require_complete_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    /// Finishes the actual negative socket and independently owed Root posts.
    ///
    /// # Errors
    /// Retains the original body/native failure and every later owed refusal.
    /// No failed owner is disposed, refunded or admitted for another purpose.
    pub fn finish_negative_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.finish_negative_once_v1();
        self.negative_disposition.as_ref().and_then(|returned| returned.as_ref().ok())
            .map(|_| ()).ok_or(NormalRootStartupErrorV1::Service)
    }

    /// Transfers the whole positive Apply work to the same-purpose finisher.
    ///
    /// # Errors
    /// The accepted flight retains the whole offered work through any native
    /// End, independent Root post or financial-disposal refusal. Calling this
    /// before actual complete final acknowledgement aborts with custody held.
    pub fn finish_positive_once(self) -> Result<(), NormalRootStartupErrorV1> {
        let (work, flight) = match self.into_completed_dispatch_v1() {
            Ok(completed) => completed,
            Err(mut original) => {
                let _owed = original.finish_negative_once();
                std::process::abort();
            }
        };
        flight.finish_storage_apply_dispatch_once_v1(work)
    }

    fn select_unsigned_failure_before_posts_v1(&mut self) {
        if self.unsigned_failure.is_some() || !matches!(self.unsigned, Some(Err(_))) { return; }
        let native = self.native.as_deref();
        let phase = native.map_or(PhaseV1::Opening, |native| native.phase);
        let source = if self.prelude.original.native.failure_after_v1().is_some() {
            UnsignedFailureSourceV1::OpeningPost
        } else if self.opening.funding_failed_v1()
            && self.prelude.original.flight.failure().is_some()
        {
            // Only this exact reached funding origin selects same-R debt.
            UnsignedFailureSourceV1::Financial
        } else {
            UnsignedFailureSourceV1::select_v1(phase, self.opening.failure().is_some(),
                native.and_then(|native| native.phase_failure_v1(phase)).is_some(),
                native.and_then(|native| native.clock_failure_v1()).is_some())
        };
        self.unsigned_failure = Some(source);
    }

    fn selected_unsigned_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let source = self.unsigned_failure?;
        let native = self.native.as_deref();
        let child = match source {
            UnsignedFailureSourceV1::Phase(phase) => native.and_then(|native| native.phase_failure_v1(phase)),
            _ => None,
        };
        source.resolve_v1(self.opening.failure(), self.prelude.original.native.failure_after_v1(), child,
            native.and_then(|native| native.clock_failure_v1()),
            self.prelude.original.flight.failure(),
            self.unsigned.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
    }

    fn finish_negative_once_v1(&mut self) {
        if self.negative_disposition.is_some() { return; }
        let root = &mut self.prelude.original;
        let _opening_post = root.native.finish_opening_if_owed_v1();
        if let Some(native) = self.native.as_mut() {
            native.finish_initial_posts_once_v1(root.flight);
        }
        // This is the real already-armed purpose peer, available after debt.
        let peer_already_posted = self.native.as_ref()
            .and_then(|native| native.final_exchange.as_ref())
            .is_some_and(|exchange| exchange.peer_post_entered_v1());
        if !peer_already_posted {
            self.negative = Some(root.flight.finish_apply_controller_peer_posts_once_v1());
        }
        // The original same-socket End/shutdown and independent policy-flight
        // Root post are still owed; purpose peer posts alone cannot finish them.
        self.negative_disposition = Some(root.finish_negative_once_v1());
    }

    /// Borrows the retained original failure without observing or retrying.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let root = &self.prelude.original;
        root.native.failure_before_v1()
            .or_else(|| self.peer.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.selected_unsigned_failure_v1())
            .or_else(|| {
                let native = self.native.as_ref()?;
                if matches!(native.final_funding, Some(Err(_)))
                    || native.final_exchange.as_ref().is_some_and(|exchange| exchange.selects_flight_failure_v1())
                { root.flight.failure() } else { None }
            })
            .or_else(|| self.opening.failure())
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| self.unsigned.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| root.native.failure_after_v1())
            .or_else(|| self.negative.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.negative_disposition.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| root.flight.failure())
    }
}
