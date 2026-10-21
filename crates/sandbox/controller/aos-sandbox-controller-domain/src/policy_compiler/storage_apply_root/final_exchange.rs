//! Compares durable Applied evidence before the preterminal Root reply.
//!
//! These are distinct final readers and a new actual Root policy interval.
//! The complete Lifecycle/C selector invoice is admitted from actual captured
//! rows before candidate recovery, schema replay, selection or comparison.
//! The public parent remains Applying/REQUESTED until the client completes
//! this acknowledgement and its prearmed terminal CAS. Failure preserves the
//! durable Applied prefix; this response cannot publish STOPPED itself.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::{PeerCredentials, domain_ledger::{
    create_storage_history::{ready::ReadyBundleDataV1,
        continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1}},
    effect_history::{decode_lifecycle_effect_receipt_v1, LifecycleEffectReceiptDataV1},
    provisioning_root::storage_apply::{StorageApplyFinalDataV1, StorageApplyClosedDataV1,
        StorageApplySubjectDataV1, FINAL_BYTES_V1, CLOSED_BYTES_V1},
}};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{RootCurrentPolicyInputDataV1, RetainedKernelPairedClockAttemptV1};
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use crate::policy_compiler::continuation_policy::RootApplyPolicyOriginalV1;
use crate::policy_compiler::provisioning_current::{RootContinuationClockGateV1,
    current_compiler_complete_receiving_demand_v1};
use crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1;
use crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1;
use crate::cold_launch_publication::completion::{create_stopped_controller_receiving_demand_v1,
    create_stopped_comparison_receiving_demand_v1};
use super::{RootStorageApplyOpeningOriginalV1, receiving::RootStorageApplyNativeOriginalV1,
    final_readonly::{RootApplyFinalReadonlyOriginalV1, NativeCutDataV1},
    session::RootApplyFinalSessionOriginalV1, lifecycle::RootApplyFinalLifecycleOriginalV1,
    controller::RootApplyFinalControllerOriginalV1};

type Cause = Box<dyn Error>;

#[derive(Clone, Copy)]
enum Phase { Policy, Read, Eof, Proof, Readonly, Session, Funding, Lifecycle, Controller, Compare, Posts, Peer, Send, Settlement }

#[derive(Clone, Copy)]
enum First { Child(Phase), Clock, Body }

pub(super) struct RootApplyFinalExchangeOriginalV1 {
    bytes: [u8; FINAL_BYTES_V1],
    read: FixedDeadlineStreamIoV1<FINAL_BYTES_V1>,
    eof_byte: [u8; 1],
    eof: FixedDeadlineStreamIoV1<1>,
    clock: RootContinuationClockGateV1,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), Cause>>,
    readers: RootApplyFinalReadonlyOriginalV1,
    session: Option<Box<RootApplyFinalSessionOriginalV1>>,
    lifecycle: Option<Box<RootApplyFinalLifecycleOriginalV1>>,
    controller: Option<Box<RootApplyFinalControllerOriginalV1>>,
    policy: RootApplyPolicyOriginalV1,
    policy_begun: bool,
    phase: Phase,
    first: Option<First>,
    primary: Option<Result<(), Cause>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    posts_done: bool,
    peer_after: Option<Result<(), NormalRootStartupErrorV1>>,
    closed: [u8; CLOSED_BYTES_V1],
    send: FixedDeadlineStreamIoV1<CLOSED_BYTES_V1>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    returned: Option<Result<(), Cause>>,
}

impl RootApplyFinalExchangeOriginalV1 {
    pub(super) fn fixed_demand_v1(flight: &RootPolicyAcceptedFlightV1<'_, '_>) -> Result<ResourceVector, Cause> {
        let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(clock))
            .and_then(|bytes| bytes.checked_add(crate::policy_compiler::provisioning_current::create_finality::controller::CreateFinalityControllerOriginalV1::observation_control_bytes_v2()?))
            .and_then(|bytes| bytes.checked_add(RootApplyFinalReadonlyOriginalV1::observation_control_bytes_v2()?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        Ok(flight.apply_policy_receiving_demand_v1()?.checked_add(
            RootContinuationClockGateV1::receiving_demand_v1()?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                .with(D::OpenFiles, RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
                .with(D::NetworkBytes, FINAL_BYTES_V1 as u64)))
            .map_err(JournalError::ReceivingAccounting)?)
    }

    pub(super) fn new(opening: &RootStorageApplyOpeningOriginalV1) -> Result<Self, JournalError> {
        Ok(Self { bytes: [0; FINAL_BYTES_V1], read: Default::default(), eof_byte: [0; 1], eof: Default::default(),
            clock: RootContinuationClockGateV1::new(opening.horizon_v1()?),
            after_clock: Default::default(), after_sample: None, after_binding: None,
            readers: RootApplyFinalReadonlyOriginalV1::new(), session: None, lifecycle: None,
            controller: None, policy: Default::default(), policy_begun: false,
            phase: Phase::Policy, first: None, primary: None, funding: None, posts_done: false,
            peer_after: None, closed: [0; CLOSED_BYTES_V1], send: Default::default(),
            settlement: None, returned: None })
    }

    pub(super) fn run_once_v1(&mut self, opening: &RootStorageApplyOpeningOriginalV1,
        initial: &RootStorageApplyNativeOriginalV1, root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), JournalError> {
        if self.returned.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.primary = Some(self.compare_inner_v1(opening, initial, root, policy));
        if matches!(self.primary, Some(Err(_))) {
            self.first = Some(if self.child_failure_v1(self.phase).is_some() {
                First::Child(self.phase)
            } else if self.clock.failure().is_some() { First::Clock } else { First::Body });
        }
        // Every independent native post remains reachable after body/debit
        // refusal. A separate pre-funded sampler is never suppressed by the
        // sequential gate's failed current sample.
        self.finish_claim_once_v1(opening, initial, root.flight);
        self.returned = Some((|| {
            if !matches!(self.primary, Some(Ok(()))) || self.failure().is_some() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.readers.require_complete_v1()?;
            self.policy.require_complete_v1()?;
            let sample = self.after_sample.as_ref().and_then(|sample| sample.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            self.phase = Phase::Peer;
            self.peer_after = Some(root.flight.finish_apply_controller_peer_posts_once_v1());
            if !matches!(self.peer_after, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
            let subject = StorageApplySubjectDataV1::decode_v1(initial.subject.bytes())?;
            let lane = ReadyBundleDataV1::decode(subject.ready)?.lane;
            let proof = StorageApplyFinalDataV1::decode_v1(&self.bytes, lane)?;
            let query = opening.query_v1()?;
            self.closed = StorageApplyClosedDataV1 { root_nonce: opening.root_nonce_v1()?,
                controller_nonce: query.controller_nonce, query_digest: query.digest_v1()?,
                reply_digest: initial.reply_digest.ok_or(JournalError::ProtectedBoundary)?,
                final_digest: proof.digest_v1(lane)?, observed_wall_seconds: sample.wall_seconds(),
                observed_boottime_ns: sample.boottime_nanoseconds(), cutoff_ns: opening.current_cutoff_v1()? }.encode_v1()?;
            self.phase = Phase::Send;
            self.send.run_once(&mut root.original, &mut self.closed,
                opening.current_cutoff_v1()?, DeadlineStreamDirectionV1::Write)?;
            self.phase = Phase::Settlement;
            self.settlement = Some(root.flight.settle_apply_controller_peer_positive_once_v1());
            if !matches!(self.settlement, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
            Ok(())
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    fn compare_inner_v1(&mut self, opening: &RootStorageApplyOpeningOriginalV1,
        initial: &RootStorageApplyNativeOriginalV1, root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Cause> {
        self.phase = Phase::Policy;
        self.policy_begun = true;
        root.flight.begin_apply_policy_once_v1(&mut self.policy)?;
        let plan_expires = initial.plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.preparation_data_v1()
            .signing_request().statement().expires_seconds().ok_or(JournalError::ProtectedBoundary)?;
        self.clock.narrow_wall_expiry_data_v1(plan_expires);
        self.clock.check_next_once_v1()?;
        self.phase = Phase::Read;
        self.read.run_once(&mut root.original, &mut self.bytes,
            opening.current_cutoff_v1()?, DeadlineStreamDirectionV1::Read)?;
        self.phase = Phase::Eof;
        self.eof.run_once(&mut root.original, &mut self.eof_byte,
            opening.current_cutoff_v1()?, DeadlineStreamDirectionV1::Eof)?;
        self.phase = Phase::Proof;
        let subject = StorageApplySubjectDataV1::decode_v1(initial.subject.bytes())?;
        let lane = ReadyBundleDataV1::decode(subject.ready)?.lane;
        let proof = StorageApplyFinalDataV1::decode_v1(&self.bytes, lane)?;
        let query = opening.query_v1()?;
        if proof.root_nonce != opening.root_nonce_v1()? || proof.controller_nonce != query.controller_nonce
            || proof.query_digest != query.digest_v1()?
            || Some(proof.reply_digest) != initial.reply_digest
        { return Err(JournalError::ProtectedBoundary.into()); }
        self.phase = Phase::Policy;
        let sample = self.clock.check_next_once_v1()?;
        root.flight.verify_apply_policy_sources_once_v1(&mut self.policy, policy, sample)?;
        let current = self.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
        let original = initial.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
        if current.0.head() != original.0.head() || current.1.packet_digest() != original.1.packet_digest() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::Readonly;
        self.readers.observe_once_v1(&mut root.flight.apply_stage_receiving_v1()?, &mut self.clock)?;
        let (controller_cut, source_cut) = self.readers.cuts_v1()?;
        if !native_cut_matches_v1(controller_cut, proof.controller_native)
            || !native_cut_matches_v1(source_cut, proof.source_native)
        { return Err(JournalError::ProtectedBoundary.into()); }
        self.phase = Phase::Session;
        self.session = Some(Box::new(RootApplyFinalSessionOriginalV1::new()));
        let credentials = root.flight.current_cut_native()?.peer().credentials();
        let controller = PeerCredentials { uid: credentials.uid(), gid: credentials.gid(),
            pid: Some(credentials.pid().get()) };
        let issued = initial.plan.as_ref().and_then(|plan| plan.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.session.as_mut().ok_or(JournalError::ProtectedBoundary)?.observe_once_v1(
            self.readers.session_v1()?, &initial.inputs, issued, controller,
            self.clock.check_next_once_v1()?, opening.current_cutoff_v1()?)?;
        self.phase = Phase::Funding;
        let (controller, source) = self.readers.models_v1()?;
        let c_state = controller.state_v1();
        let width = c_state.iter().try_fold(0_u64, |total, ((_, key), value)| {
            total.checked_add(u64::try_from(key.len().checked_add(value.len())?).ok()?)
        }).ok_or(JournalError::JournalTooLarge)?;
        let fixed = size_of::<RootApplyFinalLifecycleOriginalV1>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(3 * size_of::<RootApplyFinalControllerOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(RootApplyFinalLifecycleOriginalV1::observe_rows_interface_control_bytes_v2()?))

            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let demand = retained_lifecycle_replay_receiving_demand_v1(source.all_records())
            .ok_or(JournalError::JournalTooLarge)?
            .checked_add(create_stopped_controller_receiving_demand_v1(c_state).ok_or(JournalError::JournalTooLarge)?)?
            .checked_add(create_stopped_comparison_receiving_demand_v1().ok_or(JournalError::JournalTooLarge)?)?
            .checked_add(current_compiler_complete_receiving_demand_v1(width, c_state, current)?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                aos_sandbox_protocol::public_api::projection::geometry::sandbox_source_receiving_bytes_v1(controller.rows_data_v2())
                    .ok_or(JournalError::JournalTooLarge)?))?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed)
                .with(D::NetworkBytes, CLOSED_BYTES_V1 as u64).with(D::OutputBytes, CLOSED_BYTES_V1 as u64))?;
        self.funding = Some(root.flight.apply_stage_receiving_v1()?.admit_apply_final_response_once_v1(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        self.clock.check_next_once_v1()?;
        let parent = initial.inputs.proposed_v1()?.operation_id();
        self.phase = Phase::Lifecycle;
        self.lifecycle = Some(Box::new(RootApplyFinalLifecycleOriginalV1::new()));
        self.lifecycle.as_mut().ok_or(JournalError::ProtectedBoundary)?.observe_once_v1(source.rows_data_v2(), parent)?;
        self.clock.check_next_once_v1()?;
        let LifecycleEffectReceiptDataV1::CreateStopped(receipt) =
            decode_lifecycle_effect_receipt_v1(proof.lifecycle_receipt, lane)?
        else { return Err(JournalError::ProtectedBoundary.into()); };
        self.phase = Phase::Controller;
        self.controller = Some(Box::new(RootApplyFinalControllerOriginalV1::new()));
        self.controller.as_mut().ok_or(JournalError::ProtectedBoundary)?.observe_once_v1(
            controller, receipt, parent, proof.lifecycle_receipt)?;
        self.phase = Phase::Compare;
        let root_receipt = ContinuationNativeReceiptDataV1::decode(subject.root_closed,
            lane, ContinuationKindV1::Closed)?;
        self.controller.as_ref().ok_or(JournalError::ProtectedBoundary)?.compare_once_v1(controller,
            self.lifecycle.as_ref().ok_or(JournalError::ProtectedBoundary)?,
            self.session.as_ref().ok_or(JournalError::ProtectedBoundary)?, receipt, root_receipt,
            issued.preparation_data_v1().canonical_plan(), lane)?;
        Ok(())
    }

    fn finish_claim_once_v1(&mut self, opening: &RootStorageApplyOpeningOriginalV1,
        initial: &RootStorageApplyNativeOriginalV1, flight: &RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.posts_done { return; }
        self.posts_done = true;
        self.readers.finish_posts_once_v1();
        if self.policy_begun { let _owed = flight.finish_apply_policy_once_v1(&mut self.policy); }
        self.after_sample = Some(self.after_clock.observe_once(opening.root_sample_v1().ok()));
        self.after_binding = Some((|| {
            let sample = self.after_sample.as_ref().and_then(|sample| sample.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            self.clock.require_final_sample_v1(sample)?;
            opening.require_current_clock_v1(sample)?;
            if sample.wall_seconds() >= initial.compiler.expires_at_v1()?
                || sample.wall_seconds() >= initial.inputs.lease_v1()?.authority_expires_seconds()
            { return Err(JournalError::ProtectedBoundary.into()); }
            Ok(())
        })());
    }

    fn child_failure_v1(&self, phase: Phase) -> Option<&(dyn Error + 'static)> {
        match phase {
            Phase::Policy => self.policy.failure(), Phase::Read => self.read.failure(), Phase::Eof => self.eof.failure(),
            Phase::Readonly => self.readers.failure(), Phase::Session => self.session.as_ref()?.failure(),
            Phase::Lifecycle => self.lifecycle.as_ref()?.failure(), Phase::Controller => self.controller.as_ref()?.failure(),
            Phase::Send => self.send.failure(),
            _ => None,
        }
    }

    pub(super) fn selects_flight_failure_v1(&self) -> bool {
        (matches!(self.phase, Phase::Funding) && matches!(self.funding, Some(Err(_))))
            || (matches!(self.first, Some(First::Child(Phase::Readonly)))
                && self.readers.selected_funding_failed_v1())
            || (matches!(self.primary, Some(Ok(())))
                && (matches!(self.peer_after, Some(Err(_))) || matches!(self.settlement, Some(Err(_)))))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let primary = match self.first {
            Some(First::Child(phase)) => self.child_failure_v1(phase),
            Some(First::Clock) => self.clock.failure(),
            Some(First::Body) => self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
            None => None,
        };
        primary.or_else(|| self.readers.failure()).or_else(|| self.policy.failure())
            .or_else(|| self.after_clock.failure())
            .or_else(|| self.after_sample.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.after_binding.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.child_failure_v1(self.phase))
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
    }

    pub(super) fn peer_post_entered_v1(&self) -> bool { self.peer_after.is_some() }

    pub(super) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if matches!(self.returned, Some(Ok(()))) && self.failure().is_none()
            && self.read.completed_exact() && self.eof.completed_exact() && self.send.completed_exact()
            && matches!(self.settlement, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }
}

fn native_cut_matches_v1(actual: NativeCutDataV1, encoded: &[u8]) -> bool {
    encoded.len() == 64 && actual.names.to_bytes().as_slice() == &encoded[..48]
        && actual.next.to_be_bytes().as_slice() == &encoded[48..56]
        && actual.end.to_be_bytes().as_slice() == &encoded[56..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

    #[test]
    fn final_cut_requires_exact_names_next_and_end_without_monotone_fallback() {
        let actual = NativeCutDataV1 { names: ProtectedJournalNamesV1::from_historical_fields(
            (1, 2), (3, 4), (5, 6)), next: 42, end: 4096 };
        let mut bytes = [0; 64];
        bytes[..48].copy_from_slice(&actual.names.to_bytes());
        bytes[48..56].copy_from_slice(&actual.next.to_be_bytes());
        bytes[56..].copy_from_slice(&actual.end.to_be_bytes());
        assert!(native_cut_matches_v1(actual, &bytes));

        bytes[48..56].copy_from_slice(&(actual.next + 1).to_be_bytes());
        assert!(!native_cut_matches_v1(actual, &bytes));
        bytes[48..56].copy_from_slice(&actual.next.to_be_bytes());
        bytes[56..].copy_from_slice(&(actual.end + 1).to_be_bytes());
        assert!(!native_cut_matches_v1(actual, &bytes));
        bytes[56..].copy_from_slice(&actual.end.to_be_bytes());
        bytes[31] ^= 1;
        assert!(!native_cut_matches_v1(actual, &bytes));
        assert!(!native_cut_matches_v1(actual, &bytes[..63]));
    }
}
