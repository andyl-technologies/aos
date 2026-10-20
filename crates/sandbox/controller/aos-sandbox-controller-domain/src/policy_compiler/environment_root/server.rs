//! Serves the one genuine Root Environment stream through authenticated End.
//!
//! One original prelude moves here. The fixed request, all native body owners,
//! provisional response, actual EOF and final closed response remain resident
//! through the independent peer/Root posts and same-R positive disposition.
//! EOF reports only stream completion; Source lease success remains C18-owned.

use std::error::Error;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

use aos_sandbox_model::{OperationId, ResourceDimension as D, ResourceVector};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::environment::deployment::{RootEnvironmentResponseOriginalV1, transport::{
    EnvironmentRootOpenDataV1, EnvironmentRootClosedDataV1, EnvironmentRootWireErrorV1,
    OPEN_BYTES, RESPONSE_BYTES, CLOSED_BYTES,
}};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RootCurrentPolicyInputDataV1;
use super::business::{RootEnvironmentBusinessOriginalV1, EnvironmentExecutionHorizonDataV1};
use super::super::bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1, SliceDeadlineStreamIoV1};
use super::super::root_policy_prelude::{RootPolicyPreludeOriginalV1, RootPolicyPurposeV1,
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1};

type Cause = Box<dyn Error>;

/// Reports a stopped original Environment exchange while its real cause stays held.
#[derive(Debug, thiserror::Error)]
#[error("the original Root Environment exchange is unavailable")]
pub struct RootEnvironmentExchangeErrorV1;

#[derive(Clone, Copy)]
enum First { Peer, Funding, Remainder, Decode, Business, Response, Header, Body, Eof, Claim, PeerAfter, Closed }

pub(crate) struct RootEnvironmentDispatchOriginalV1 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    bytes: [u8; OPEN_BYTES],
    remainder: [u8; OPEN_BYTES - 32],
    remainder_io: FixedDeadlineStreamIoV1<{ OPEN_BYTES - 32 }>,
    open: Option<Result<EnvironmentRootOpenDataV1, EnvironmentRootWireErrorV1>>,
    business: Option<Result<RootEnvironmentBusinessOriginalV1, crate::journal::JournalError>>,
    response: RootEnvironmentResponseOriginalV1,
    header_io: FixedDeadlineStreamIoV1<RESPONSE_BYTES>,
    body_io: SliceDeadlineStreamIoV1,
    eof_io: FixedDeadlineStreamIoV1<1>,
    eof_byte: [u8; 1],
    closed: [u8; CLOSED_BYTES],
    closed_io: FixedDeadlineStreamIoV1<CLOSED_BYTES>,
    opening_clock_after: Option<Result<(), super::super::root_policy_prelude::RootPolicyPreludeErrorV1>>,
    peer_after: Option<Result<(), NormalRootStartupErrorV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    primary: Option<Result<(), Cause>>,
    first: Option<First>,
}

impl RootEnvironmentDispatchOriginalV1 {
    fn business_mut(&mut self) -> Result<&mut RootEnvironmentBusinessOriginalV1, RootEnvironmentExchangeErrorV1> {
        self.business.as_mut().and_then(|value| value.as_mut().ok()).ok_or(RootEnvironmentExchangeErrorV1)
    }

    fn open_data(&self) -> Result<EnvironmentRootOpenDataV1, RootEnvironmentExchangeErrorV1> {
        self.open.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(RootEnvironmentExchangeErrorV1)
    }

    fn serve_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        inputs: &RootCurrentPolicyInputDataV1<'_>) -> Result<(), Cause>
    {
        self.first = Some(First::Peer);
        self.peer = Some(flight.admit_environment_controller_peer_once_v1());
        if !matches!(self.peer, Some(Ok(()))) { return Err(RootEnvironmentExchangeErrorV1.into()); }
        // The serving Root6 pair must really exist before any new business
        // frontier. This comparison grants neither an Environment nor a lease.
        let _same_pair = flight.environment_policy_receiving_demand_v1()?;
        self.first = Some(First::Funding);
        let fixed = RootEnvironmentBusinessOriginalV1::fixed_receiving_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(std::mem::size_of::<Self>().checked_mul(3)
                    .ok_or(crate::journal::JournalError::JournalTooLarge)?)?))?;
        self.funding = Some(flight.environment_stage_receiving_v1()?
            .admit_environment_request_once_v1(RootContinuationDemandV1::from_demand_v1(fixed)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(RootEnvironmentExchangeErrorV1.into()); }
        let cutoff = self.prelude.cutoff_v1()?;
        self.bytes[..32].copy_from_slice(self.prelude.prefix_bytes_v1());
        self.first = Some(First::Remainder);
        self.remainder_io.run_once(&mut self.original, &mut self.remainder, cutoff, DeadlineStreamDirectionV1::Read)?;
        self.bytes[32..].copy_from_slice(&self.remainder);
        self.first = Some(First::Decode);
        self.open = Some(EnvironmentRootOpenDataV1::decode(&self.bytes));
        let open = self.open_data()?;
        self.opening_clock_after = Some(self.prelude.finish_opening_once_v1());
        if !matches!(self.opening_clock_after, Some(Ok(()))) { return Err(RootEnvironmentExchangeErrorV1.into()); }
        self.first = Some(First::Business);
        self.business = Some(RootEnvironmentBusinessOriginalV1::new(EnvironmentExecutionHorizonDataV1 {
            original: open.original, absolute_cutoff: open.cutoff, expires: open.expires,
        }));
        self.business_mut()?.observe_once_v1(flight, inputs, OperationId::from_bytes(open.operation))?;
        self.business_mut()?.before_response_native_once_v1()?;
        self.first = Some(First::Response);
        let business = self.business.as_ref().and_then(|value| value.as_ref().ok()).ok_or(RootEnvironmentExchangeErrorV1)?;
        self.response.prepare_once_v1(&mut flight.environment_stage_receiving_v1()?, business, open)?;
        self.business_mut()?.before_response_native_once_v1()?;
        let (header, body) = self.response.wire_mut_v1()?;
        self.first = Some(First::Header);
        self.header_io.run_once(&mut self.original, header, open.cutoff, DeadlineStreamDirectionV1::Write)?;
        self.first = Some(First::Body);
        self.body_io.run_once(&mut self.original, body, open.cutoff, DeadlineStreamDirectionV1::Write)?;
        // The Controller may now publish its real Source generation and exact
        // execution lease. Root holds its own actual authority and artifact;
        // it never demands that Source NEXT remain unchanged across that work.
        self.first = Some(First::Eof);
        self.eof_io.run_once(&mut self.original, &mut self.eof_byte, open.cutoff, DeadlineStreamDirectionV1::Eof)?;
        self.first = Some(First::Claim);
        self.business_mut()?.finish_claim_once_v1(flight);
        self.business_mut()?.require_complete_v1()?;
        self.first = Some(First::PeerAfter);
        self.peer_after = Some(flight.finish_environment_controller_peer_posts_once_v1());
        if !matches!(self.peer_after, Some(Ok(()))) { return Err(RootEnvironmentExchangeErrorV1.into()); }
        self.first = Some(First::Closed);
        let observed = self.business_mut()?.final_clock_v1()?;
        self.closed = EnvironmentRootClosedDataV1 { operation: open.operation,
            response: self.response.complete_digest_v1()?, observed }.encode()?;
        self.closed_io.run_once(&mut self.original, &mut self.closed, open.cutoff, DeadlineStreamDirectionV1::Write)?;
        self.settlement = Some(flight.settle_environment_controller_peer_positive_once_v1());
        if !matches!(self.settlement, Some(Ok(()))) { return Err(RootEnvironmentExchangeErrorV1.into()); }
        self.first = None;
        Ok(())
    }

    fn finish_available_negative_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.opening_clock_after.is_none() {
            self.opening_clock_after = Some(self.prelude.finish_opening_once_v1());
        }
        if let Some(Ok(business)) = &mut self.business { business.finish_claim_once_v1(flight); }
        if self.peer_after.is_none() && self.peer.is_some() {
            self.peer_after = Some(flight.finish_environment_controller_peer_posts_once_v1());
        }
    }

    pub(crate) fn require_same_complete_v1(&self,
        native: &aos_sandbox_linux::unix_stream::RetainedUnixStream) -> Result<(), NormalRootStartupErrorV1>
    {
        if !matches!(self.primary, Some(Ok(()))) || self.failure().is_some()
            || !self.header_io.completed_exact() || !self.body_io.completed_exact()
            || !self.eof_io.completed_exact() || !self.closed_io.completed_exact()
            || !matches!(self.settlement, Some(Ok(())))
        { return Err(NormalRootStartupErrorV1::Service); }
        native.require_same_endpoint_v1(self.original.as_fd()).map_err(|_| NormalRootStartupErrorV1::Service)
    }

    // Only the actual Root financial disposal path calls this after the same
    // socket End, Root post and fallible same-original token preparation.
    pub(crate) fn complete_upper_disposal_v1(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(First::Peer) => cause(&self.peer),
            Some(First::Funding) => cause(&self.funding),
            Some(First::Remainder) => self.remainder_io.failure(),
            Some(First::Decode) => cause(&self.open),
            Some(First::Business | First::Claim) => self.business.as_ref().and_then(|value| value.as_ref().ok())
                .and_then(|business| business.failure()).or_else(|| cause(&self.business)),
            Some(First::Response) => self.response.failure(),
            Some(First::Header) => self.header_io.failure(),
            Some(First::Body) => self.body_io.failure(),
            Some(First::Eof) => self.eof_io.failure(),
            Some(First::PeerAfter) => cause(&self.peer_after),
            Some(First::Closed) => self.closed_io.failure().or_else(|| cause(&self.settlement)),
            None => None,
        };
        self.prelude.failure_before_v1().or(selected)
            .or_else(|| self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.prelude.failure_after_v1()).or_else(|| self.response.failure())
            .or_else(|| self.business.as_ref()?.as_ref().ok()?.failure()).or_else(|| cause(&self.peer_after))
    }
}

/// Retains the actual Environment stream beside its exclusively borrowed Root flight.
#[must_use]
pub struct RootEnvironmentPolicyAttemptV1<'flight, 'listener, 'startup> {
    work: RootEnvironmentDispatchOriginalV1,
    flight: &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
}

impl<'flight, 'listener, 'startup> RootEnvironmentPolicyAttemptV1<'flight, 'listener, 'startup> {
    pub(in crate::policy_compiler) fn from_prelude_v1(prelude: RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup>) -> Self {
        if prelude.purpose_v1() != Some(RootPolicyPurposeV1::Environment) { std::process::abort(); }
        let RootPolicyPreludeOriginalV1 { disposition, original, flight, native, .. } = prelude;
        Self { flight, work: RootEnvironmentDispatchOriginalV1 { disposition, original, prelude: native,
            peer: None, funding: None, bytes: [0; OPEN_BYTES], remainder: [0; OPEN_BYTES - 32],
            remainder_io: Default::default(), open: None, business: None,
            response: RootEnvironmentResponseOriginalV1::new(), header_io: Default::default(),
            body_io: Default::default(), eof_io: Default::default(), eof_byte: [0; 1],
            closed: [0; CLOSED_BYTES], closed_io: Default::default(), opening_clock_after: None,
            peer_after: None, settlement: None, primary: None, first: None } }
    }

    /// Serves real evidence and retains the same interval through peer End.
    ///
    /// # Errors
    /// Preserves every reached original and always finishes entered native
    /// policy/artifact/peer posts before returning a coarse stopped marker.
    pub fn serve_once(&mut self, inputs: &RootCurrentPolicyInputDataV1<'_>) -> Result<(), RootEnvironmentExchangeErrorV1> {
        if self.work.primary.is_some() { return Err(RootEnvironmentExchangeErrorV1); }
        self.work.disposition.entered = true;
        self.work.primary = Some(self.work.serve_inner(self.flight, inputs));
        if !matches!(self.work.primary, Some(Ok(()))) {
            self.work.finish_available_negative_once(self.flight);
            return Err(RootEnvironmentExchangeErrorV1);
        }
        Ok(())
    }

    /// Finishes the real socket and independent Root post on failure.
    ///
    /// # Errors
    /// The failed work remains resident; no negative original is disposed or rearmed.
    pub fn finish_negative_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.work.finish_available_negative_once(self.flight);
        self.flight.finish_dispatch_once(Err(Box::new(RootEnvironmentExchangeErrorV1)))
    }

    /// Moves the whole native-positive work to same-R financial disposition.
    ///
    /// # Errors
    /// The receiving flight retains the whole offer through native or financial refusal.
    pub fn finish_positive_once(self) -> Result<(), NormalRootStartupErrorV1> {
        self.flight.finish_environment_dispatch_once_v1(self.work)
    }

    /// Borrows the real body/native cause without any new observation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.work.failure().or_else(|| self.flight.failure())
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
