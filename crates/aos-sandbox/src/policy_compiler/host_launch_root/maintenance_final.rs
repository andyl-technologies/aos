//! Closes actual Maintenance31 after fresh native cuts and all independent posts.
//!
//! The original Root opening remains held through exact31/fresh18 comparison,
//! current C/Source/model rebuilding, strict EOF and final same-socket response.
//! The common native readers and Session decoders retain every failed prefix.

use super::maintenance_native::RootMaintenanceNativeOriginalV3;
use super::maintenance_opening::RootMaintenanceStorageOpeningOriginalV2;
use super::maintenance_final_models::RootMaintenanceFinalModelsOriginalV3;
use super::session::RootStartResourceFinalSessionOriginalV2;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{RootCurrentPolicyInputDataV1, RetainedKernelPairedClockAttemptV1,
    bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1, SliceDeadlineStreamIoV1},
    continuation_policy::RootMaintenanceStoragePolicyOriginalV2,
    provisioning_current::{RootContinuationClockGateV1,
        finality_readonly::{NativeCutDataV1, RootCreateFinalityReadonlyOriginalV1}},
    root_policy_prelude::RootPolicyPreludeOriginalV1};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::provisioning_root::{
    maintenance_storage::MaintenanceStorageSubjectDataV2,
    host_launch::completion::{RESOURCE_CLOSED_BYTES_V2, RESOURCE_PROOF_HEADER_BYTES_V2,
        ResourceCompletionBindingDataV2, ResourceCompletionPurposeDataV3,
        ResourceCompletionProofDataV2, ResourceCompletionClosedDataV2},
};

type Cause = Box<dyn std::error::Error>;

#[derive(Clone, Copy)]
enum Phase { Read, Eof, Binding, Policy, Readonly, Session, Models, Posts, Peer, Send, Settlement }

#[derive(Clone, Copy)]
enum First { Child(Phase), Clock, Body }

pub(super) struct RootMaintenanceFinalExchangeOriginalV3 {
    bytes: Vec<u8>, read: SliceDeadlineStreamIoV1,
    eof_byte: [u8; 1], eof: FixedDeadlineStreamIoV1<1>,
    clock: RootContinuationClockGateV1,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), Cause>>,
    policy: RootMaintenanceStoragePolicyOriginalV2,
    policy_begun: bool,
    readers: RootCreateFinalityReadonlyOriginalV1,
    session: Option<Box<RootStartResourceFinalSessionOriginalV2>>,
    models: RootMaintenanceFinalModelsOriginalV3,
    phase: Phase, first: Option<First>, primary: Option<Result<(), Cause>>,
    returned: Option<Result<(), Cause>>, posts: bool, repeated: bool,
    response_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_after: Option<Result<(), NormalRootStartupErrorV1>>,
    local_cutoff: Option<u64>, ack: [u8; RESOURCE_CLOSED_BYTES_V2],
    sent: FixedDeadlineStreamIoV1<RESOURCE_CLOSED_BYTES_V2>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootMaintenanceFinalExchangeOriginalV3 {
    pub(super) fn receiving_demand_v3(flight: &RootPolicyAcceptedFlightV1<'_, '_>, announced: usize)
        -> Result<ResourceVector, Cause> {
        let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(announced))
            .and_then(|bytes| bytes.checked_add(clock))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let traffic = announced.checked_sub(RESOURCE_PROOF_HEADER_BYTES_V2)
            .and_then(|bytes| bytes.checked_add(1)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(flight.maintenance_storage_policy_receiving_demand_v2()?
            .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::NetworkBytes, traffic)
                .with(D::OpenFiles, RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))?)
    }

    pub(super) fn new(opening: &RootMaintenanceStorageOpeningOriginalV2) -> Result<Self, JournalError> {
        Ok(Self { bytes: Vec::new(), read: Default::default(), eof_byte: [0; 1], eof: Default::default(),
            clock: RootContinuationClockGateV1::new(opening.horizon_v2()?), after_clock: Default::default(),
            after_sample: None, after_binding: None, policy: Default::default(), policy_begun: false,
            readers: RootCreateFinalityReadonlyOriginalV1::new(), session: None,
            models: RootMaintenanceFinalModelsOriginalV3::new(), phase: Phase::Read, first: None,
            primary: None, returned: None, posts: false, repeated: false, response_funding: None,
            peer_after: None, local_cutoff: None, ack: [0; RESOURCE_CLOSED_BYTES_V2],
            sent: Default::default(), settlement: None })
    }

    pub(super) fn run_once_v3(&mut self, opening: &RootMaintenanceStorageOpeningOriginalV2,
        initial: &RootMaintenanceNativeOriginalV3, announced: usize,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>, policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), JournalError> {
        if self.primary.is_some() { self.repeated = true; return Err(JournalError::ProtectedBoundary); }
        self.primary = Some(self.compare_once_v3(opening, initial, announced, root, policy));
        if matches!(self.primary, Some(Err(_))) {
            self.first = Some(if self.child_failure(self.phase).is_some() { First::Child(self.phase) }
                else if self.clock.failure().is_some() { First::Clock } else { First::Body });
        }
        self.finish_posts_once_v3(opening, root.flight);
        self.returned = Some((|| -> Result<(), Cause> {
            if !matches!(self.primary, Some(Ok(()))) || self.failure().is_some() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.readers.require_complete_v1()?;
            self.policy.require_complete_v1()?;
            self.models.require_complete_v3()?;
            self.phase = Phase::Peer;
            self.peer_after = Some(root.flight.finish_maintenance_storage_controller_peer_posts_once_v2());
            if !matches!(self.peer_after, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
            let sample = self.clock.check_next_once_v1()?;
            opening.require_current_clock_v1(sample)?;
            let proof = ResourceCompletionProofDataV2::decode_v2(&self.bytes)?;
            self.ack = ResourceCompletionClosedDataV2 { binding: proof.binding, proof_digest: proof.digest_v2()?,
                observed_wall_seconds: sample.wall_seconds(), observed_boottime_ns: sample.boottime_nanoseconds(),
                cutoff_ns: opening.current_cutoff_v1()? }.encode_v2()?;
            self.phase = Phase::Send;
            self.sent.run_once(&mut root.original, &mut self.ack,
                self.local_cutoff.ok_or(JournalError::ProtectedBoundary)?, DeadlineStreamDirectionV1::Write)?;
            self.phase = Phase::Settlement;
            self.settlement = Some(root.flight.settle_maintenance_storage_controller_peer_positive_once_v2());
            if !matches!(self.settlement, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
            Ok(())
        })());
        self.require_complete_v3()
    }

    fn compare_once_v3(&mut self, opening: &RootMaintenanceStorageOpeningOriginalV2,
        initial: &RootMaintenanceNativeOriginalV3, announced: usize,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>, policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Cause> {
        initial.require_posts_v3()?;
        initial.assignment.require_compiled_v2()?;
        initial.request.require_typed_v2()?;
        self.clock.narrow_wall_expiry_data_v1(initial.plan.preparation_v2()?.plan_data_v1().expires_seconds());
        self.clock.check_next_once_v1()?;
        self.bytes.try_reserve_exact(announced)?;
        self.bytes.resize(announced, 0);
        self.bytes[..RESOURCE_PROOF_HEADER_BYTES_V2].copy_from_slice(&initial.final_header);
        self.read.run_once(&mut root.original, &mut self.bytes[RESOURCE_PROOF_HEADER_BYTES_V2..],
            opening.current_cutoff_v1()?, DeadlineStreamDirectionV1::Read)?;
        self.phase = Phase::Eof;
        self.eof.run_once(&mut root.original, &mut self.eof_byte,
            opening.current_cutoff_v1()?, DeadlineStreamDirectionV1::Eof)?;
        self.phase = Phase::Binding;
        let proof = ResourceCompletionProofDataV2::decode_v2(&self.bytes)?;
        let query = opening.query_v2()?;
        if proof.binding != (ResourceCompletionBindingDataV2 {
            purpose: ResourceCompletionPurposeDataV3::MaintenanceStorage,
            root_nonce: opening.root_nonce_v2()?, controller_nonce: query.controller_nonce,
            query_digest: query.digest_v2()?, reply_digest: initial.reply_digest.ok_or(JournalError::ProtectedBoundary)?,
        }) { return Err(JournalError::ProtectedBoundary.into()); }
        self.phase = Phase::Policy;
        self.policy_begun = true;
        root.flight.begin_maintenance_storage_policy_once_v2(&mut self.policy)?;
        let sample = self.clock.check_next_once_v1()?;
        opening.require_current_clock_v1(sample)?;
        root.flight.verify_maintenance_storage_policy_sources_once_v2(&mut self.policy, policy, sample)?;
        let current = self.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
        let original = initial.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
        if current.0.head() != original.0.head() || current.1.packet_digest() != original.1.packet_digest() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::Readonly;
        self.readers.observe_maintenance_storage_final_once_v2(
            &mut root.flight.maintenance_storage_stage_receiving_v2()?, &mut self.clock)?;
        let (controller, source) = self.readers.cuts_v1()?;
        let session = self.readers.session_v1()?;
        if !controller.matches_encoded_data_v3(proof.controller_native)
            || !source.matches_encoded_data_v3(proof.source_native)
            || !(NativeCutDataV1 { names: session.names, next: session.next, end: session.end })
                .matches_encoded_data_v3(proof.session_native) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::Session;
        self.session = Some(Box::new(RootStartResourceFinalSessionOriginalV2::new()));
        let observed = self.clock.check_next_once_v1()?;
        opening.require_current_clock_v1(observed)?;
        let model = self.session.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        model.observe_maintenance_storage_final_once_v3(session, initial.inputs.storage_manifest_v2()?,
            &initial.assignment, &initial.request, &initial.plan, initial.inputs.maintenance_lease_v2()?,
            proof, observed, opening.current_cutoff_v1()?)?;
        let local_cutoff = model.local_cutoff_v2()?.min(opening.current_cutoff_v1()?);
        self.local_cutoff = Some(local_cutoff);
        self.clock.narrow_horizon_data_v1(crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1::
            from_original_data_v1(opening.root_sample_v2()?, local_cutoff)?)?;
        self.phase = Phase::Models;
        let subject = MaintenanceStorageSubjectDataV2::decode_v2(initial.subject.bytes())?;
        let sample = self.clock.check_next_once_v1()?;
        opening.require_current_clock_v1(sample)?;
        self.models.observe_once_v3(&mut root.flight.maintenance_storage_stage_receiving_v2()?,
            &self.readers, &initial.assignment, &initial.views, &initial.request, &initial.inputs,
            &self.policy, subject.reservation, model.current_storage_inventory_v2()?, sample, local_cutoff)?;
        self.response_funding = Some(root.flight.maintenance_storage_stage_receiving_v2()?
            .admit_maintenance_final_response_once_v2(RootContinuationDemandV1::from_demand_v1(
                ResourceVector::ZERO.with(D::NetworkBytes, RESOURCE_CLOSED_BYTES_V2 as u64)
                    .with(D::OutputBytes, RESOURCE_CLOSED_BYTES_V2 as u64))));
        if !matches!(self.response_funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        Ok(())
    }

    fn finish_posts_once_v3(&mut self, opening: &RootMaintenanceStorageOpeningOriginalV2,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.posts { return; }
        self.posts = true;
        self.readers.finish_posts_once_v1();
        if self.policy_begun { let _owed = flight.finish_maintenance_storage_policy_once_v2(&mut self.policy); }
        self.after_sample = Some(self.after_clock.observe_once(None));
        self.after_binding = Some((|| -> Result<(), Cause> {
            let sample = *self.after_sample.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            opening.require_current_clock_v1(sample)?;
            self.clock.require_final_sample_v1(sample)?;
            Ok(())
        })());
    }

    pub(super) fn peer_post_entered_v3(&self) -> bool { self.peer_after.is_some() }

    pub(super) fn require_complete_v3(&self) -> Result<(), JournalError> {
        if self.repeated || !matches!(self.primary, Some(Ok(()))) || !matches!(self.returned, Some(Ok(())))
            || !matches!(self.peer_after, Some(Ok(()))) || !matches!(self.settlement, Some(Ok(())))
            || self.failure().is_some() { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    fn child_failure(&self, phase: Phase) -> Option<&(dyn std::error::Error + 'static)> {
        match phase {
            Phase::Read => self.read.failure(), Phase::Eof => self.eof.failure(), Phase::Binding => None,
            Phase::Policy => self.policy.failure(), Phase::Readonly => self.readers.failure(),
            Phase::Session => self.session.as_ref().and_then(|model| model.failure()),
            Phase::Models => self.models.failure().or_else(|| self.response_funding.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Phase::Posts => self.readers.failure().or_else(|| self.policy.failure()),
            Phase::Peer => self.peer_after.as_ref()?.as_ref().err().map(|cause| cause as _),
            Phase::Send => self.sent.failure(),
            Phase::Settlement => self.settlement.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let original = match self.first {
            Some(First::Child(phase)) => self.child_failure(phase),
            Some(First::Clock) => self.clock.failure(),
            Some(First::Body) => self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
            None => None,
        };
        original.or_else(|| self.child_failure(self.phase)).or_else(|| self.clock.failure())
            .or_else(|| self.readers.failure()).or_else(|| self.policy.failure())
            .or_else(|| self.after_clock.failure())
            .or_else(|| self.after_sample.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.after_binding.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.repeated.then_some(&JournalError::ProtectedBoundary as _))
    }
}
