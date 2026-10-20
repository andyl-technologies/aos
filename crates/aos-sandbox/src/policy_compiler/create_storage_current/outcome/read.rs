//! Owns both independently captured native readers and authenticated acceptance.

use std::error::Error as StdError;
use std::os::unix::net::UnixStream;
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector,
    BrokerPlanExpectation, DecodeLimits, VerifiedBrokerPlan, BrokerPlanVerificationError,
    verify_broker_plan};
use aos_sandbox_core::format::{CanonicalCborError, decode_signature};
use aos_sandbox_core::model::Signature;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HistoryErrorV1,
    ready::ReadyBundleDataV1, continuation::ContinuationKindV1};
use crate::journal::JournalError;
use crate::normal_root::{RootPolicyAcceptedFlightV1, NormalRootStartupErrorV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::input::RootOutcomeInputV1;
use super::super::{RootCreateStorageCurrentErrorV1 as Error,
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    cache_current::RootCurrentCacheProofStateV1,
    controller_readonly::{RootCurrentControllerReadonlyStateV1,
        native_read::RootFixedNativeReadOriginalsV1,
        storage_inventory::RootVerifiedSessionTerminalV1},
    policy_inputs::RootCurrentPolicyInputDataV1,
    ready::RootCurrentReadyStateV1,
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1},
    signed_bound::RootCurrentSignedBoundStateV1,
    source_current::RootCurrentSourceExchangeStateV1,
    use_admitted::RootCurrentUseAdmittedStateV1,
    use_authorized::RootCurrentUseAuthorizedStateV1,
    use_reserved::RootCurrentUseReservedStateV1};

pub(crate) struct RootCurrentOutcomeReadV1 {
    pub(super) input: RootOutcomeInputV1,
    controller: RootCurrentControllerReadonlyStateV1,
    session: RootFixedNativeReadOriginalsV1,
    session_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    signature: Option<Result<Signature, CanonicalCborError>>,
    verified_plan: Option<Result<VerifiedBrokerPlan, BrokerPlanVerificationError>>,
    terminal: Option<Result<RootVerifiedSessionTerminalV1, Box<dyn StdError>>>,
    before_sample: Option<RawPairedClockSample>,
    interval: Option<Result<(), aos_sandbox_core::OwnershipLeaseVerificationError>>,
    primary: Option<Result<(), Error>>,
    after: RootCurrentHistoryPostsV1,
    after_readback: Option<Result<(), JournalError>>,
    after_live: Option<Result<(), JournalError>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentOutcomeReadV1 {
    pub(super) fn new() -> Self {
        Self { input: RootOutcomeInputV1::new(), controller: RootCurrentControllerReadonlyStateV1::new(),
            session: Default::default(), session_funding: None, signature: None, verified_plan: None,
            terminal: None, before_sample: None, interval: None, primary: None, after: Default::default(), after_readback: None,
            after_live: None, complete: false, closed: false }
    }

    pub(crate) fn additional_session_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        let native = self.session.replay_demand_v1()?;
        let extent = self.session.captured_extent_v1()?;
        let schema = crate::journal::broker_session_receiving::schema_demand(extent)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let p = self.controller.prospective_use_plan_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        // Reverify the same actual signed plan against this turn's freshly
        // captured fixed trust. Core's bounded decoder and collection backstop
        // bound each live model by the actual plan/policy bytes, not wire maxima.
        let raw = p.preparation_data_v1().canonical_plan().len()
            .checked_add(p.trust_policy_length_v1()).ok_or(JournalError::JournalTooLarge)?;
        let cell = [std::mem::size_of::<aos_sandbox_core::BrokerGrant>(),
            std::mem::size_of::<aos_sandbox_core::model::KeyReference>(),
            std::mem::size_of::<aos_sandbox_core::model::SignatureStatement>()]
            .into_iter().max().ok_or(JournalError::JournalTooLarge)?;
        let trust = raw.checked_mul(cell).and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        native.checked_add(schema).and_then(|value| value.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, trust))).map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn observe_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, signed: &RootCurrentSignedBoundStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.after.arm_once(flight)?;
        self.primary = Some(self.observe_inner(flight, writers, original, root, ready, cache,
            source, ownership, policy, authorization, reserved, admitted, signed));
        // Native name/time/profile posts are independently owed even after a
        // captured-prefix, payment, replay, signature or terminal refusal.
        self.session.finish_post_once();
        let body = root.completed_body().ok();
        let origin = root.original_clock_origin_v1().ok();
        self.after.observe_once(flight, writers, body.as_ref(), origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        self.after_readback = Some(match writers.authority_and_policy() {
            Ok((authority, policy)) => signed.readback_current_v1(authority, policy).map(|_| ()),
            Err(cause) => Err(cause),
        });
        self.after_live = Some((|| {
            self.after.require_complete()?;
            positive(&self.after_readback)?;
            self.session.terminal_native_v1()?;
            self.require_live_at_v1(root, reserved, source, self.after.sample()?)
        })());
        if let (Some(before), Ok(after)) = (self.before_sample, self.after.sample()) {
            self.interval = Some(before.validate_later_sample(after));
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && matches!(self.after_live, Some(Ok(())))
            && matches!(self.interval, Some(Ok(())))
            && self.failure_with_original(flight).is_none();
        self.require_complete_v1()
    }

    fn observe_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, signed: &RootCurrentSignedBoundStateV1,
    ) -> Result<(), Error> {
        self.input.receive_once(flight, writers, original, root, ready, signed, reserved, source)?;
        self.controller.capture_outcome_once(flight, writers, root, ready, cache, source,
            ownership, policy, authorization, reserved, admitted, signed, &self.input)?;
        self.before_sample = Some(self.controller.completed_sample_v1()?);
        let body = root.completed_body()?;
        self.session.capture_once(body.controller_uid);
        self.session.require_captured_v1().map_err(|_| Error::History)?;
        self.session_funding = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_outcome_session_once(root, signed, self));
        positive(&self.session_funding).map_err(|_| Error::History)?;
        let suffix = self.controller.outcome_suffix_v1()?;
        let request_recorded = suffix.session_v1()?;
        self.session.replay_marked_once_v1((request_recorded.after_next, request_recorded.after_end));
        let native = self.session.replay_native_v1().map_err(|_| Error::History)?;
        let sample = self.controller.completed_sample_v1()?;
        let signed_bundle = signed.completed_bundle_v1()?;
        let prospective = self.controller.prospective_use_plan_v1()?;
        self.signature = Some(decode_signature(signed_bundle.signature, DecodeLimits::default()));
        let expected = prospective.plan_data_v1();
        self.verified_plan = Some(verify_broker_plan(signed_bundle.plan,
            positive(&self.signature).map_err(|_| Error::History)?, prospective.anchor_v1(),
            BrokerPlanExpectation { audience: expected.audience(), protocol: expected.protocol(),
                protocol_version: expected.protocol_version(), assignment: expected.assignment(),
                node: expected.node(), now_seconds: sample.wall_seconds() }, DecodeLimits::default()));
        if positive(&self.verified_plan).map_err(|_| Error::History)?.plan_digest()
            != signed.verified_plan_v1()?.plan_digest() { return Err(Error::History); }
        let original = ReadyBundleDataV1::borrow_field_framing_data_v1(ready.raw_ready_bytes()?)
            .map_err(|_| Error::History)?;
        self.terminal = Some(self.controller.storage_inventory_v1()?.verify_prepare_terminal_v1(
            native, self.input.completed_bundle_v1()?, signed_bundle, signed.completed_request_id_v1()?, source.original_cutoff_v1()?, original,
            sample, aos_sandbox_protocol::PeerCredentials { uid: body.controller_uid, gid: body.controller_gid,
                pid: Some(body.controller_pid) }, suffix.outcome_v1()?, request_recorded));
        positive(&self.terminal).map(|_| ()).map_err(|_| Error::History)
    }

    pub(super) fn failed_financial_entry_v1(&self) -> Option<super::OutcomeFinancialStageV1> {
        if self.input.failed_financial_entry_v1() { return Some(super::OutcomeFinancialStageV1::Bytes); }
        self.controller.failed_outcome_financial_entry_v1().or_else(||
            matches!(self.session_funding, Some(Err(_))).then_some(super::OutcomeFinancialStageV1::Session))
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed { self.controller.require_complete_v1() }
        else { Err(Error::History) }
    }

    pub(crate) fn require_live_at_v1(&self, root: &RootCurrentOpenStateV1,
        reserved: &RootCurrentUseReservedStateV1, source: &RootCurrentSourceExchangeStateV1,
        sample: RawPairedClockSample) -> Result<(), JournalError>
    {
        root.require_clock(sample)?;
        reserved.completed_readonly_v1().map_err(|_| JournalError::ProtectedBoundary)?.require_live_at_v1(sample)?;
        self.controller.require_live_at_v1(sample)?;
        positive(&self.terminal)?.require_live_at_v1(sample)?;
        let plan = positive(&self.verified_plan)?;
        if sample.wall_seconds() >= plan.plan().expires_seconds()
            || sample.boottime_nanoseconds() >= source.original_cutoff_v1().map_err(|_| JournalError::ProtectedBoundary)?
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(crate) fn controller_v1(&self) -> Result<&RootCurrentControllerReadonlyStateV1, Error> {
        self.require_complete_v1()?;
        Ok(&self.controller)
    }

    pub(crate) fn terminal_v1(&self) -> Result<&RootVerifiedSessionTerminalV1, Error> {
        self.require_complete_v1()?;
        positive(&self.terminal).map_err(|_| Error::History)
    }

    pub(crate) fn failure_with_original<'a>(&'a self, flight: &'a RootPolicyAcceptedFlightV1<'_, '_>)
        -> Option<&'a (dyn StdError + 'static)> {
        self.input.failure_with_original(flight)
            .or_else(|| self.controller.failure_with_original(flight))
            .or_else(|| self.session.failure())
            .or_else(|| if matches!(self.session_funding, Some(Err(_))) { flight.failure() } else { None })
            .or_else(|| cause(&self.session_funding)).or_else(|| cause(&self.signature))
            .or_else(|| cause(&self.verified_plan))
            .or_else(|| self.terminal.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| cause(&self.primary)).or_else(|| self.session.post_failure())
            .or_else(|| self.after.failure()).or_else(|| cause(&self.after_readback))
            .or_else(|| cause(&self.after_live)).or_else(|| cause(&self.interval))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
