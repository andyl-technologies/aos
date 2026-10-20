//! Retains the actual paid Root inputs, general-plan comparison and final cut.

use std::{error::Error, mem::size_of};

use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamOriginalCurrentnessV1};
use aos_sandbox_protocol::authorization_artifact::{
    host_stop_cleanup_plan::{
        StopCleanupPlanPreparationDataV1, host_stop_cleanup_request_body_data_v1,
        prepare_host_stop_cleanup_plan_v1,
    },
    start_resource_plan::host_stop_cleanup_unsigned_receiving_demand_v1,
};
use aos_sandbox_protocol::root_policy_completion::{
    StopCleanupObservationDataV1, stop_cleanup_observation_decision_digest_v1,
};

use crate::{
    controller_resource_reservation::{RootContinuationDemandV1, RootStopCleanupStageV1 as Stage},
    journal::JournalError,
    normal_root::{NormalRootStartupErrorV1, RootStopCleanupStageReceivingV1},
    policy_compiler::{
        RetainedKernelPairedClockAttemptV1, RootCurrentPolicyInputDataV1,
        continuation_policy::RootStopCleanupPolicyOriginalV1,
        create_storage_current::pins::RootCurrentPinsStateV1,
        execution_no_apply_root::HostHistoryOriginalV2,
        provisioning_current::{
            RootContinuationClockGateV1,
            finality_readonly::{
                RootCreateFinalityReadStageV1, RootCreateFinalityReadonlyOriginalV1,
                RootStopCleanupFinalHostOriginalV1,
            },
        },
        root_current_writers::RootCreateStorageCurrentWritersV1,
    },
};

use super::{
    SelectionData,
    inventory::{self, Completed, Selection},
    models::Models,
    trust::Trust,
};

type Cause = Box<dyn Error>;

/// Owns every reached native prefix; no public DATA can construct completion.
pub(crate) struct RootStopCleanupNativeOriginalV1 {
    demand: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    repeated: Option<JournalError>,
}

#[derive(Clone, Copy)]
enum Phase {
    Connection(usize),
    Clock,
    Policy,
    Trust,
    Readonly,
    Models,
    Funding,
    Plan,
    Signature,
    FinalHost,
    FinalModels,
    Posts,
    After,
}

struct Native {
    selection: SelectionData,
    policy: RootStopCleanupPolicyOriginalV1,
    trust: Trust,
    readonly: RootCreateFinalityReadonlyOriginalV1,
    models: Models,
    final_host: RootStopCleanupFinalHostOriginalV1,
    final_history: Option<Box<HostHistoryOriginalV2>>,
    plan: Option<Result<StopCleanupPlanPreparationDataV1, Cause>>,
    plan_sample: Option<RawPairedClockSample>,
    effective_cutoff: Option<u64>,
    canonical_signature: Option<Vec<u8>>,
    signature_receiving: Option<usize>,
    signature: Option<
        Result<aos_sandbox_core::model::Signature, aos_sandbox_core::format::CanonicalCborError>,
    >,
    verified: Option<
        Result<aos_sandbox_core::VerifiedBrokerPlan, aos_sandbox_core::BrokerPlanVerificationError>,
    >,
    connection: [UnixStreamOriginalCurrentnessV1; 3],
    connection_result: [Option<aos_sandbox_linux::Result<()>>; 3],
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<
        Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>,
    >,
    after_binding: Option<Result<(), JournalError>>,
    funding: [Option<Result<(), NormalRootStartupErrorV1>>; 4],
    next_funding: usize,
    initial: Option<Result<(), Cause>>,
    signed: Option<Result<(), Cause>>,
    final_result: Option<Result<(), Cause>>,
    terminal_digest: Option<[u8; 32]>,
    phase: Phase,
    first: Option<Phase>,
    posts: bool,
}

impl RootStopCleanupNativeOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            demand: None,
            funding: None,
            native: None,
            repeated: None,
        }
    }

    /// Reads and normalizes only through the actual selected Stop Root stage.
    /// The caller keeps the same accepted connection and primary Root pair
    /// through signature comparison, Host child and final inventory.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_inputs_once_v1(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &RootCurrentPolicyInputDataV1<'_>,
        clock: &mut RootContinuationClockGateV1,
        selection: SelectionData,
    ) -> Result<(), JournalError> {
        if self.demand.is_some() {
            self.repeated.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.demand = Some(initial_demand(writers));
        self.funding = Some(stage.admit_stop_cleanup_once_v1(
            Stage::Trust,
            RootContinuationDemandV1::from_demand_v1(*positive(&self.demand)?),
        ));
        positive(&self.funding)?;
        self.native = Some(Box::new(Native::new(selection)));
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        native.initial = Some(native.observe_inputs(stage, original, writers, pins, policy, clock));
        native.latch(clock, native.initial.as_ref().is_some_and(Result::is_err));
        if matches!(native.initial, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    /// Borrows the exact unsigned effect plan, or an observation-only decision.
    pub(crate) fn unsigned_plan_v1(
        &self,
    ) -> Result<Option<&StopCleanupPlanPreparationDataV1>, JournalError> {
        let native = self.initial_native()?;
        match native.models.selected()?.0 {
            Selection::Effect(_) => positive(&native.plan).map(Some),
            Selection::Complete(_) => Ok(None),
        }
    }

    pub(crate) fn decision_digest_v1(&self) -> Result<[u8; 32], JournalError> {
        match self.initial_native()?.models.selected()?.0 {
            Selection::Effect(subject) => Ok(subject.digest_data_v1()),
            Selection::Complete(Completed::Historical(row)) => {
                stop_cleanup_observation_decision_digest_v1(
                    StopCleanupObservationDataV1::Historical(row),
                )
                .map_err(|_| JournalError::ProtectedBoundary)
            }
            Selection::Complete(Completed::Cleanup(row)) => {
                stop_cleanup_observation_decision_digest_v1(StopCleanupObservationDataV1::Cleanup(
                    row,
                ))
                .map_err(|_| JournalError::ProtectedBoundary)
            }
        }
    }

    /// Compares a genuine ordinary Controller signature on the exact plan.
    /// Observation-only completion accepts no signature or new effect plan.
    pub(crate) fn observe_signature_once_v1(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
        signature: Option<&[u8]>,
    ) -> Result<(), JournalError> {
        self.initial_native()?;
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        if native.signed.is_some() {
            self.repeated.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        native.signed = Some(native.observe_signature(stage, clock, signature));
        native.latch(clock, native.signed.as_ref().is_some_and(Result::is_err));
        if matches!(native.signed, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn observed_decision_v1(&self) -> Result<Option<StopCleanupObservationDataV1>, JournalError> {
        Ok(match self.initial_native()?.models.selected()?.0 {
            Selection::Effect(_) => None,
            Selection::Complete(Completed::Historical(row)) => Some(StopCleanupObservationDataV1::Historical(row)),
            Selection::Complete(Completed::Cleanup(row)) => Some(StopCleanupObservationDataV1::Cleanup(row)),
        })
    }

    /// Borrows the already checked subject without another request decode.
    pub(crate) fn issued_subject_v1(&self) -> Result<Option<aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1>, JournalError> {
        Ok(match self.initial_native()?.models.selected()?.0 {
            Selection::Effect(subject) => Some(subject),
            Selection::Complete(_) => None,
        })
    }

    /// Prepays the actual announced frame and typed signature before growth.
    /// The no-effect branch enters no signature decoder or verifier programme.
    pub(crate) fn admit_child_decision_receiving_once_v1(&mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        frame_bytes: usize, signature_bytes: usize,
    ) -> Result<(), JournalError> {
        self.initial_native()?;
        let native = self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if native.signature_receiving.is_some() || native.signed.is_some() {
            self.repeated.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        native.signature_receiving = Some(signature_bytes);
        let result = (|| {
            let mut bytes = frame_bytes.checked_mul(3).ok_or(JournalError::JournalTooLarge)?;
            let header = match native.models.selected()?.0 {
                Selection::Effect(_) => {
                    let signature = aos_sandbox_core::format::authorization_capture::SignatureDecodeCaptureV1::receiving_dynamic_bytes_v1(signature_bytes)
                        .ok_or(JournalError::JournalTooLarge)?;
                    let verification = native.trust.broker()?.anchor.verification_receiving_bytes_v1(
                        positive(&native.plan)?.preparation.canonical_plan().len()).ok_or(JournalError::JournalTooLarge)?;
                    bytes = bytes.checked_add(signature).and_then(|value| value.checked_add(verification))
                        .ok_or(JournalError::JournalTooLarge)?;
                    20
                }
                Selection::Complete(_) if signature_bytes == 0 => 16,
                _ => return Err(JournalError::ProtectedBoundary),
            };
            let wire = frame_bytes.checked_sub(header).ok_or(JournalError::ProtectedBoundary)?;
            native.admit(stage, Stage::ChildDecision, ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?)
                .with(D::NetworkBytes, u64::try_from(wire).map_err(|_| JournalError::JournalTooLarge)?))
        })();
        if result.is_err() { native.first.get_or_insert(Phase::Funding); }
        result
    }

    /// Completes the independent final Host read after the held child exchange.
    /// Every reached reader, fixed credential, Root policy and clock post drains
    /// even when final comparison or funding refuses. This is not D disposal.
    pub(crate) fn observe_final_once_v1(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        clock: &mut RootContinuationClockGateV1,
        query: ([u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    ) -> Result<(), JournalError> {
        self.initial_native()?;
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        if native.final_result.is_some() || !matches!(native.signed, Some(Ok(()))) {
            self.repeated.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        native.final_result = Some(native.observe_final(stage, original, clock, query));
        native.latch(
            clock,
            native.final_result.as_ref().is_some_and(Result::is_err),
        );
        native.finish_posts(original, writers, pins, clock);
        self.require_complete_v1()
    }

    /// Drains the same reached originals on a refused or truncated exchange.
    pub(crate) fn finish_negative_once_v1(
        &mut self,
        original: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        clock: &RootContinuationClockGateV1,
    ) {
        if let Some(native) = self.native.as_mut() {
            native.finish_posts(original, writers, pins, clock);
        }
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        let native = self.initial_native()?;
        if !matches!(native.signed, Some(Ok(())))
            || !matches!(native.final_result, Some(Ok(())))
            || !native.posts
            || native.failure().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        native.readonly.require_complete_v1()?;
        native.final_host.require_complete_v1()?;
        native.trust.require_complete()?;
        native
            .policy
            .require_complete_v1()
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    /// Returns comparison inputs only after the actual complete programme.
    pub(crate) fn completion_data_v1(
        &self,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32], u64), JournalError> {
        self.require_complete_v1()?;
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok((
            native.selection.query_digest,
            self.decision_digest_v1()?,
            native
                .terminal_digest
                .ok_or(JournalError::ProtectedBoundary)?,
            native.effective_cutoff.ok_or(JournalError::ProtectedBoundary)?,
        ))
    }

    fn initial_native(&self) -> Result<&Native, JournalError> {
        if self.repeated.is_some() || !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if !matches!(native.initial, Some(Ok(())))
            || native.first.is_some()
            || native.failure().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(native)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.demand)
            .or_else(|| error(&self.funding))
            .or_else(|| self.native.as_deref()?.failure())
            .or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn plan_sample_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.initial_native()?
            .plan_sample
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn policy_expiry_v1(&self) -> Result<i64, JournalError> {
        let native = self.initial_native()?;
        let policy = native
            .policy
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(policy
            .0
            .head()
            .expires_at()
            .min(policy.1.expires_at())
            .min(native.selection.admission.wall_expiry)
            .min(native.models.lease()?.authority_expires_seconds()))
    }

    pub(crate) fn cutoff_v1(&self) -> Result<u64, JournalError> {
        self.initial_native()?.effective_cutoff.ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn external_clock_is_first_v1(&self, clock: &RootContinuationClockGateV1) -> bool {
        self.native
            .as_deref()
            .is_some_and(|native| matches!(native.first, Some(Phase::Clock)))
            && clock.failure().is_some()
    }
}

impl Native {
    fn new(selection: SelectionData) -> Self {
        Self {
            selection,
            policy: Default::default(),
            trust: Trust::new(),
            readonly: RootCreateFinalityReadonlyOriginalV1::new(),
            models: Models::new(),
            final_host: RootStopCleanupFinalHostOriginalV1::new(),
            final_history: None,
            plan: None,
            plan_sample: None,
            effective_cutoff: None,
            canonical_signature: None,
            signature_receiving: None,
            signature: None,
            verified: None,
            connection: std::array::from_fn(|_| Default::default()),
            connection_result: std::array::from_fn(|_| None),
            after_clock: Default::default(),
            after_sample: None,
            after_binding: None,
            funding: std::array::from_fn(|_| None),
            next_funding: 0,
            initial: None,
            signed: None,
            final_result: None,
            terminal_digest: None,
            phase: Phase::Connection(0),
            first: None,
            posts: false,
        }
    }

    fn admit(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        phase: Stage,
        demand: ResourceVector,
    ) -> Result<(), JournalError> {
        self.phase = Phase::Funding;
        let slot = self
            .funding
            .get_mut(self.next_funding)
            .ok_or(JournalError::ProtectedBoundary)?;
        if slot.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.next_funding += 1;
        *slot =
            Some(stage.admit_stop_cleanup_once_v1(
                phase,
                RootContinuationDemandV1::from_demand_v1(demand),
            ));
        positive(slot).map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_inputs(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &RootCurrentPolicyInputDataV1<'_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), Cause> {
        self.connection_result[0] =
            Some(original.revalidate_original_retaining_v1(&mut self.connection[0]));
        positive(&self.connection_result[0])?;
        self.phase = Phase::Clock;
        clock.require_opening_cutoff_data_v2(self.selection.first, self.selection.cutoff)?;
        clock.narrow_original_cutoff_data_v2(self.selection.cutoff)?;
        if self.selection.cutoff > self.selection.admission.cutoff
            || self.selection.first.host_boot_id()
                != self.selection.admission.original.host_boot_id()
            || self.selection.first.boottime_nanoseconds()
                < self.selection.admission.original.boottime_nanoseconds()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        clock.narrow_wall_expiry_data_v1(self.selection.admission.wall_expiry);
        let sample = clock.check_next_once_v1()?;
        self.phase = Phase::Policy;
        self.policy.begin_for_actual_pair_once_v1(writers, pins)?;
        self.policy
            .verify_current_sources_once_v1(writers, policy, sample)?;
        let signed = self
            .policy
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        clock.narrow_wall_expiry_data_v1(signed.0.head().expires_at().min(signed.1.expires_at()));
        self.phase = Phase::Trust;
        self.trust.capture_once(clock)?;
        self.trust.decode_once(stage.enrolled_node_v1()?)?;
        self.phase = Phase::Readonly;
        self.readonly.observe_once_v1(
            &mut RootCreateFinalityReadStageV1::StopCleanup(stage),
            clock,
        )?;
        let demand = Models::receiving_demand(
            &mut self.readonly,
            &self.trust,
            &self.policy,
            self.selection,
        )?;
        self.admit(stage, Stage::Models, demand)?;
        self.phase = Phase::Models;
        let sample = clock.check_next_once_v1()?;
        self.models.observe_once(
            &mut self.readonly,
            &self.trust,
            self.selection,
            sample,
            stage.enrolled_node_v1()?,
            stage.controller_identity_v1(),
            stage.controller_baseline_partition_v1()?,
        )?;
        if self.models.project_v1()?
            != self
                .policy
                .verified_v1()
                .ok_or(JournalError::ProtectedBoundary)?
                .0
                .head()
                .project()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        clock.narrow_wall_expiry_data_v1(self.models.lease()?.authority_expires_seconds());
        self.readonly.finish_stop_initial_host_posts_once_v1()?;
        self.phase = Phase::Plan;
        self.prepare_plan(stage, clock)?;
        Ok(())
    }

    fn prepare_plan(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), Cause> {
        let public = self.trust.broker()?;
        let lease = self.models.lease()?;
        let body_bound = aos_sandbox_protocol::host_stop_cleanup::MAXIMUM_CANONICAL_HOST_STOP_CLEANUP_BODY_BYTES_V1;
        let demand = match self.models.selected()?.0 {
            Selection::Effect(_) => host_stop_cleanup_unsigned_receiving_demand_v1(
                body_bound, lease, &public.authority).ok_or(JournalError::JournalTooLarge)?,
            // The decision clock is prepaid with the enclosing native gate.
            // An already complete observation constructs no unsigned plan.
            Selection::Complete(_) => ResourceVector::ZERO,
        };
        self.admit(stage, Stage::Plan, demand)?;
        let sample = clock.check_next_once_v1()?;
        self.plan_sample = Some(sample);
        let signed = self.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
        let expiry = signed.0.head().expires_at().min(signed.1.expires_at())
            .min(self.selection.admission.wall_expiry)
            .min(self.models.lease()?.authority_expires_seconds());
        let opening = clock.original_sample_data_v1();
        // The body and every reply use one intersection computed at the same
        // retained Root opening origin. The Source22 D remains immutable history.
        let effective = self.selection.cutoff
            .min(crate::dispatch::conservative_lease_deadline(self.models.lease()?, opening)?)
            .min(opening.conservative_expiry_deadline_data_v1(expiry)
                .ok_or(JournalError::ProtectedBoundary)?);
        clock.narrow_wall_expiry_data_v1(expiry);
        clock.narrow_original_cutoff_data_v2(effective)?;
        self.effective_cutoff = Some(effective);
        let Selection::Effect(subject) = self.models.selected()?.0 else {
            return Ok(());
        };
        let assignment = self.models.assignment()?;
        let manifest = assignment.binding.manifest();
        let public = self.trust.broker()?;
        let lease = self.models.lease()?;
        clock.narrow_wall_expiry_data_v1(lease.authority_expires_seconds());
        let body = host_stop_cleanup_request_body_data_v1(
            manifest,
            self.models.desired_generation()?,
            subject,
        ).map_err(|cause| -> Cause { cause })?;
        if body.len() > body_bound {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let signed = self
            .policy
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.plan = Some(
            prepare_host_stop_cleanup_plan_v1(
                &body,
                manifest,
                self.models.desired_generation()?,
                subject,
                manifest.manifest().policy().digest(),
                lease,
                sample,
                effective,
                signed.0.head().expires_at().min(signed.1.expires_at()),
                self.selection.admission.wall_expiry,
                public.authority.clone(),
                public.revocation_scope,
            )
            .map_err(|cause| cause as Cause),
        );
        positive(&self.plan)?;
        Ok(())
    }

    fn observe_signature(
        &mut self,
        _stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
        signature: Option<&[u8]>,
    ) -> Result<(), Cause> {
        let width = signature.map_or(0, <[u8]>::len);
        if self.signature_receiving != Some(width) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::Signature;
        let sample = clock.check_next_once_v1()?;
        match self.models.selected()?.0 {
            Selection::Complete(_) if signature.is_none() => Ok(()),
            Selection::Effect(_) => {
                let signature = signature.ok_or(JournalError::ProtectedBoundary)?;
                self.canonical_signature = Some(signature.to_vec());
                self.signature = Some(aos_sandbox_core::format::decode_signature(
                    signature,
                    aos_sandbox_core::DecodeLimits::default(),
                ));
                let signature = positive(&self.signature)?;
                let plan = &positive(&self.plan)?.preparation;
                if signature.statement() != plan.signing_request().statement() {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                let expected = plan.plan_data_v1();
                self.verified = Some(aos_sandbox_core::verify_broker_plan(
                    plan.canonical_plan(),
                    signature,
                    &self.trust.broker()?.anchor,
                    aos_sandbox_core::BrokerPlanExpectation {
                        audience: expected.audience(),
                        protocol: expected.protocol(),
                        protocol_version: expected.protocol_version(),
                        assignment: expected.assignment(),
                        node: expected.node(),
                        now_seconds: sample.wall_seconds(),
                    },
                    aos_sandbox_core::DecodeLimits::default(),
                ));
                positive(&self.verified)?;
                Ok(())
            }
            _ => Err(JournalError::ProtectedBoundary.into()),
        }
    }

    fn observe_final(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
        original: &RetainedUnixStream,
        clock: &mut RootContinuationClockGateV1,
        query: ([u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    ) -> Result<(), Cause> {
        self.phase = Phase::Connection(1);
        self.connection_result[1] =
            Some(original.revalidate_original_retaining_v1(&mut self.connection[1]));
        positive(&self.connection_result[1])?;
        if !self.connection[0].matches_observed_endpoint_data_v2(&self.connection[1]) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::FinalHost;
        self.final_host.observe_once_v1(stage, clock)?;
        let native = self.final_host.session_v1()?;
        let demand = HostHistoryOriginalV2::receiving_demand(
            usize::try_from(native.end)?,
            native.state.len(),
        )?;
        self.admit(stage, Stage::FinalModels, demand)?;
        self.phase = Phase::FinalModels;
        self.final_history = Some(Box::new(HostHistoryOriginalV2::new()));
        let history = self
            .final_history
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        history.observe_once(
            &self.final_host.session_v1()?,
            self.trust.manifest()?,
            stage.controller_identity_v1(),
        )?;
        let sample = clock.check_next_once_v1()?;
        let (outcome, inventory, boot) = history.stop_cleanup_inventory_v1()?;
        let request = outcome.request();
        use sha2::Digest as _;
        let aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
            else { return Err(JournalError::ProtectedBoundary.into()); };
        if (
            request.request_id(),
            request.session_binding(),
            <[u8; 32]>::from(sha2::Sha256::digest(request.canonical_packet())),
            <[u8; 32]>::from(sha2::Sha256::digest(outcome.canonical_packet())),
            <[u8; 32]>::from(sha2::Sha256::digest(exact_body)),
        ) != query
            || query.0 == self.selection.host_query
            || query.1 != self.selection.host_session
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let selected = self.models.selected()?;
        let source = self.models.dispatch_v1()?;
        let (final_selection, _) = inventory::select(
            inventory,
            inventory::QueryData {
                request: query.0,
                boot,
                recipient: Some(selected.1),
                first: self.selection.first.boottime_nanoseconds(),
                cutoff: request.deadline_boottime_nanoseconds(),
                observed: sample,
            },
            self.models.recovery_v1()?,
            self.models.assignment()?.binding.manifest(),
            self.models.desired_generation()?,
            source.sdk_request_data_v1(),
        )?;
        let Selection::Complete(completed) = final_selection else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        match selected.0 {
            Selection::Effect(subject) => {
                let Completed::Cleanup(row) = completed else {
                    return Err(JournalError::ProtectedBoundary.into());
                };
                if row.subject_v1() != &subject {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                history.observe_stop_cleanup_child_once_v1(subject)?;
                let child = history.stop_cleanup_child_v1()?;
                let actual = child.request();
                let auth = actual
                    .authorization()
                    .ok_or(JournalError::ProtectedBoundary)?;
                let prepared = positive(&self.plan)?;
                if row.child_v1() != (actual.request_id(), actual.session_binding(), actual.signed_request_digest())
                    || actual.exact_body() != prepared.request_body
                    || auth.broker_plan() != prepared.preparation.canonical_plan()
                    || Some(auth.broker_plan_signature()) != self.canonical_signature.as_deref()
                    || auth.ownership_lease() != self.models.lease()?.canonical_lease()
                    || auth.ownership_lease_signature() != self.models.lease()?.canonical_signature()
                    || !matches!(child.result(), aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { .. }) {
                    return Err(JournalError::ProtectedBoundary.into());
                }
            }
            Selection::Complete(previous) if previous.scope() == completed.scope() => {}
            _ => return Err(JournalError::ProtectedBoundary.into()),
        }
        self.terminal_digest = Some(query.3);
        Ok(())
    }

    fn finish_posts(
        &mut self,
        original: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        clock: &RootContinuationClockGateV1,
    ) {
        if self.posts {
            return;
        }
        self.posts = true;
        self.readonly.finish_posts_once_v1();
        self.final_host.finish_posts_once_v1();
        self.trust.finish_posts();
        let _ = self.policy.finish_actual_pair_once_v1(writers, pins);
        self.connection_result[2] =
            Some(original.revalidate_original_retaining_v1(&mut self.connection[2]));
        self.after_sample = Some(self.after_clock.observe_once(None));
        self.after_binding = Some((|| {
            let sample = *positive(&self.after_sample)?;
            clock.require_final_sample_v1(sample)?;
            if !self.connection[0].matches_observed_endpoint_data_v2(&self.connection[2]) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
    }

    fn latch(&mut self, clock: &RootContinuationClockGateV1, failed: bool) {
        if failed && self.first.is_none() {
            self.first = Some(if clock.failure().is_some() {
                Phase::Clock
            } else {
                self.phase
            });
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            None => None,
            Some(Phase::Connection(index)) => self.connection[index].failure(),
            Some(Phase::Policy) => self.policy.failure(),
            Some(Phase::Trust) => self.trust.failure(),
            Some(Phase::Readonly) => self.readonly.failure(),
            Some(Phase::Models) => self.models.failure(),
            Some(Phase::Funding) => self.funding.iter().find_map(error),
            Some(Phase::Plan) => error_box(&self.plan),
            Some(Phase::Signature) => error(&self.signature).or_else(|| error(&self.verified)),
            Some(Phase::FinalHost) => self.final_host.failure(),
            Some(Phase::FinalModels) => self
                .final_history
                .as_ref()
                .and_then(|value| value.failure()),
            Some(Phase::Clock | Phase::Posts | Phase::After) => None,
        };
        selected
            .or_else(|| error_box(&self.initial))
            .or_else(|| error_box(&self.signed))
            .or_else(|| error_box(&self.final_result))
            .or_else(|| self.readonly.failure())
            .or_else(|| self.final_host.failure())
            .or_else(|| self.trust.failure())
            .or_else(|| self.policy.failure())
            .or_else(|| self.connection[2].failure())
            .or_else(|| self.after_clock.failure())
            .or_else(|| error(&self.after_binding))
    }
}

fn initial_demand(
    writers: &RootCreateStorageCurrentWritersV1,
) -> Result<ResourceVector, JournalError> {
    let stream = UnixStreamOriginalCurrentnessV1::receiving_demand_v1()
        .ok_or(JournalError::JournalTooLarge)?;
    let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
        .ok_or(JournalError::JournalTooLarge)?;
    let bytes = size_of::<Native>()
        .checked_mul(3)
        .and_then(|value| value.checked_add(size_of::<RootStopCleanupNativeOriginalV1>() * 3))
        .and_then(|value| value.checked_add(stream.0.checked_mul(3)?))
        .and_then(|value| value.checked_add(clock))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    Trust::fixed_demand()?
        .checked_add(RootStopCleanupPolicyOriginalV1::receiving_demand_v1(
            writers,
        )?)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(
            D::OpenFiles,
            RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
        ))
        .map_err(JournalError::ReceivingAccounting)
}

fn positive<T, E>(result: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    result
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn error_box<T>(result: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}
