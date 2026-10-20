//! Finishes one Start resource after fresh protected cuts and all owed posts.

use super::{
    RootHostLaunchOpeningOriginalV2, native::RootStartResourceNativeOriginalV2,
    session::RootStartResourceFinalSessionOriginalV2,
};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::lifecycle::{
    LifecycleHistoricalReadOriginalV1, retained_lifecycle_replay_receiving_demand_v1,
};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{
    RetainedKernelPairedClockAttemptV1, RootCurrentPolicyInputDataV1,
    bounded_stream_io::{
        DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1, SliceDeadlineStreamIoV1,
    },
    continuation_policy::RootHostLaunchPolicyOriginalV1,
    provisioning_current::{
        RootContinuationClockGateV1, current_compiler_complete_receiving_demand_v1,
        current_manifest::{
            CurrentProtectedAssignmentDataV2, current_protected_assignment_data_v2,
        },
        finality_readonly::{
            NativeCutDataV1, RootCreateFinalityReadStageV1, RootCreateFinalityReadonlyOriginalV1,
        },
        StartAssignmentCompilationDataV2, compile_root_start_assignment_v2,
    },
    root_policy_prelude::RootPolicyPreludeOriginalV1,
};
use aos_sandbox_model::{OperationId, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::{
    HostLaunchSubjectDataV1, HostResourcePurposeDataV1,
    completion::{
        RESOURCE_CLOSED_BYTES_V2, RESOURCE_PROOF_HEADER_BYTES_V2, ResourceCompletionBindingDataV2,
        ResourceCompletionClosedDataV2, ResourceCompletionProofDataV2,
    },
};

type Cause = Box<dyn std::error::Error>;

#[derive(Clone, Copy)]
enum Phase {
    Read,
    Eof,
    Binding,
    Policy,
    Readonly,
    Session,
    Models,
    Compare,
    Posts,
    Peer,
    Send,
    Settlement,
}

#[derive(Clone, Copy)]
enum First {
    Child(Phase),
    Clock,
    Body,
}

pub(super) struct RootStartResourceFinalExchangeOriginalV2 {
    bytes: Vec<u8>,
    read: SliceDeadlineStreamIoV1,
    eof_byte: [u8; 1],
    eof: FixedDeadlineStreamIoV1<1>,
    clock: RootContinuationClockGateV1,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<
        Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>,
    >,
    after_binding: Option<Result<(), Cause>>,
    policy: RootHostLaunchPolicyOriginalV1,
    policy_begun: bool,
    readers: RootCreateFinalityReadonlyOriginalV1,
    session: Option<Box<RootStartResourceFinalSessionOriginalV2>>,
    source: LifecycleHistoricalReadOriginalV1,
    previous: Option<CurrentProtectedAssignmentDataV2>,
    compiled: Option<StartAssignmentCompilationDataV2>,
    models_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    host_models: Option<Result<ResourceVector, JournalError>>,
    host_completed: Option<Result<(), crate::ReconcilerError>>,
    response_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    local_cutoff: Option<u64>,
    phase: Phase,
    first: Option<First>,
    primary: Option<Result<(), Cause>>,
    returned: Option<Result<(), Cause>>,
    posts: bool,
    peer_after: Option<Result<(), NormalRootStartupErrorV1>>,
    ack: [u8; RESOURCE_CLOSED_BYTES_V2],
    sent: FixedDeadlineStreamIoV1<RESOURCE_CLOSED_BYTES_V2>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootStartResourceFinalExchangeOriginalV2 {
    pub(super) fn receiving_demand_v2(
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        announced: usize,
    ) -> Result<ResourceVector, Cause> {
        let clocks = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(announced))
            .and_then(|bytes| bytes.checked_add(clocks))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(flight
            .host_launch_policy_receiving_demand_v1()?
            .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(
                        D::NetworkBytes,
                        u64::try_from(
                            announced
                                .checked_sub(RESOURCE_PROOF_HEADER_BYTES_V2)
                                .and_then(|bytes| bytes.checked_add(1))
                                .ok_or(JournalError::JournalTooLarge)?,
                        )
                        .map_err(|_| JournalError::JournalTooLarge)?,
                    )
                    .with(
                        D::OpenFiles,
                        RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
                    ),
            )
            .map_err(JournalError::ReceivingAccounting)?)
    }

    pub(super) fn new(opening: &RootHostLaunchOpeningOriginalV2) -> Result<Self, JournalError> {
        Ok(Self {
            bytes: Vec::new(),
            read: Default::default(),
            eof_byte: [0; 1],
            eof: Default::default(),
            clock: RootContinuationClockGateV1::new(opening.horizon_v1()?),
            after_clock: Default::default(),
            after_sample: None,
            after_binding: None,
            policy: Default::default(),
            policy_begun: false,
            readers: RootCreateFinalityReadonlyOriginalV1::new(),
            session: None,
            source: LifecycleHistoricalReadOriginalV1::new(),
            previous: None,
            compiled: None,
            models_funding: None,
            host_models: None,
            host_completed: None,
            response_funding: None,
            local_cutoff: None,
            phase: Phase::Read,
            first: None,
            primary: None,
            returned: None,
            posts: false,
            peer_after: None,
            ack: [0; RESOURCE_CLOSED_BYTES_V2],
            sent: Default::default(),
            settlement: None,
        })
    }

    pub(super) fn run_once_v2(
        &mut self,
        opening: &RootHostLaunchOpeningOriginalV2,
        initial: &RootStartResourceNativeOriginalV2,
        announced: usize,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), JournalError> {
        if self.primary.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.primary = Some(self.compare_once_v2(opening, initial, announced, root, policy));
        if matches!(self.primary, Some(Err(_))) {
            self.first = Some(if self.child_failure(self.phase).is_some() {
                First::Child(self.phase)
            } else if self.clock.failure().is_some() {
                First::Clock
            } else {
                First::Body
            });
        }
        self.finish_posts_once_v2(opening, initial, root.flight);
        self.returned = Some((|| {
            if !matches!(self.primary, Some(Ok(()))) || self.failure().is_some() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.readers.require_complete_v1()?;
            self.policy.require_complete_v1()?;
            self.phase = Phase::Peer;
            self.peer_after = Some(
                root.flight
                    .finish_host_launch_controller_peer_posts_once_v1(),
            );
            if !matches!(self.peer_after, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let sample = self.clock.check_next_once_v1()?;
            opening.require_current_clock_v1(sample)?;
            let proof = ResourceCompletionProofDataV2::decode_v2(&self.bytes)?;
            self.ack = ResourceCompletionClosedDataV2 {
                binding: proof.binding,
                proof_digest: proof.digest_v2()?,
                observed_wall_seconds: sample.wall_seconds(),
                observed_boottime_ns: sample.boottime_nanoseconds(),
                cutoff_ns: opening.current_cutoff_v1()?,
            }
            .encode_v2()?;
            self.phase = Phase::Send;
            self.sent.run_once(
                &mut root.original,
                &mut self.ack,
                self.local_cutoff.ok_or(JournalError::ProtectedBoundary)?,
                DeadlineStreamDirectionV1::Write,
            )?;
            self.phase = Phase::Settlement;
            self.settlement = Some(
                root.flight
                    .settle_host_launch_controller_peer_positive_once_v1(),
            );
            if !matches!(self.settlement, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
        self.require_complete_v2()
    }

    fn compare_once_v2(
        &mut self,
        opening: &RootHostLaunchOpeningOriginalV2,
        initial: &RootStartResourceNativeOriginalV2,
        announced: usize,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Cause> {
        self.clock.narrow_wall_expiry_data_v1(
            initial
                .plan
                .preparation_v2()?
                .plan_data_v1()
                .expires_seconds(),
        );
        if initial.kind == Some(super::kind::ResourceKindV2::Mount) {
            initial.mount_before.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v2()?;
            initial.mount_inventory.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v2()?;
            if !matches!(initial.mount_before_result, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            initial
                .current_storage
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .require_complete_v2()?;
        }
        if initial.kind == Some(super::kind::ResourceKindV2::Host) {
            initial.host_catalog.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v2()?;
            initial.current_storage.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v2()?;
        }
        self.clock.check_next_once_v1()?;
        self.bytes.try_reserve_exact(announced)?;
        self.bytes.resize(announced, 0);
        self.bytes[..RESOURCE_PROOF_HEADER_BYTES_V2].copy_from_slice(&initial.final_header);
        self.read.run_once(
            &mut root.original,
            &mut self.bytes[RESOURCE_PROOF_HEADER_BYTES_V2..],
            opening.current_cutoff_v1()?,
            DeadlineStreamDirectionV1::Read,
        )?;
        self.phase = Phase::Eof;
        self.eof.run_once(
            &mut root.original,
            &mut self.eof_byte,
            opening.current_cutoff_v1()?,
            DeadlineStreamDirectionV1::Eof,
        )?;
        self.phase = Phase::Binding;
        let proof = ResourceCompletionProofDataV2::decode_v2(&self.bytes)?;
        let query = opening.query_v1()?;
        if proof.binding
            != (ResourceCompletionBindingDataV2 {
                purpose: initial
                    .kind
                    .ok_or(JournalError::ProtectedBoundary)?
                    .purpose_v2().into(),
                root_nonce: opening.root_nonce_v1()?,
                controller_nonce: query.controller_nonce,
                query_digest: query.digest_v1()?,
                reply_digest: initial
                    .reply_digest
                    .ok_or(JournalError::ProtectedBoundary)?,
            })
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::Policy;
        self.policy_begun = true;
        root.flight
            .begin_host_launch_policy_once_v1(&mut self.policy)?;
        let sample = self.clock.check_next_once_v1()?;
        root.flight
            .verify_host_launch_policy_sources_once_v1(&mut self.policy, policy, sample)?;
        let current = self
            .policy
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        let original = initial
            .policy
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        if current.0.head() != original.0.head()
            || current.1.packet_digest() != original.1.packet_digest()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::Readonly;
        self.readers.observe_once_v1(
            &mut RootCreateFinalityReadStageV1::HostResource(
                &mut root.flight.host_launch_stage_receiving_v1()?,
                initial.kind.ok_or(JournalError::ProtectedBoundary)?,
            ),
            &mut self.clock,
        )?;
        let (controller_cut, source_cut) = self.readers.cuts_v1()?;
        let session = self.readers.session_v1()?;
        if !native_cut_matches(controller_cut, proof.controller_native)
            || !native_cut_matches(source_cut, proof.source_native)
            || !native_cut_matches(
                NativeCutDataV1 {
                    names: session.names,
                    next: session.next,
                    end: session.end,
                },
                proof.session_native,
            )
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::Session;
        self.session = Some(Box::new(RootStartResourceFinalSessionOriginalV2::new()));
        self.session
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .observe_once_v2(
                session,
                initial.kind.ok_or(JournalError::ProtectedBoundary)?,
                initial.inputs.resource_manifest_v2()?,
                &initial.compiler,
                &initial.plan,
                &initial.historical,
                initial.inputs.lease_v2()?,
                proof,
                self.clock.check_next_once_v1()?,
                opening.current_cutoff_v1()?,
            )?;
        let local_cutoff = self
            .session
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .local_cutoff_v2()?
            .min(opening.current_cutoff_v1()?);
        self.local_cutoff = Some(local_cutoff);
        self.clock.narrow_horizon_data_v1(crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1::
            from_original_data_v1(opening.root_sample_v1()?, local_cutoff)?)?;
        self.phase = Phase::Models;
        let (controller, source) = self.readers.journals_v1()?;
        let state = controller.historical_read_view_v1().materialized_state_v1();
        let width = state
            .iter()
            .try_fold(0u64, |sum, ((_, key), value)| {
                sum.checked_add(u64::try_from(key.len().checked_add(value.len())?).ok()?)
            })
            .ok_or(JournalError::JournalTooLarge)?;
        let mut demand = current_compiler_complete_receiving_demand_v1(width, state, current)?
            .checked_add(
                retained_lifecycle_replay_receiving_demand_v1(source.all_records())
                    .ok_or(JournalError::JournalTooLarge)?,
            )?;
        if initial.kind == Some(super::kind::ResourceKindV2::Host) {
            self.host_models = Some(crate::reconciler::completed_start_host_publication_receiving_demand_v2(controller));
            demand = demand.checked_add(*self.host_models.as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?)?;
        }
        self.models_funding = Some(
            root.flight
                .host_launch_stage_receiving_v1()?
                .admit_host_final_models_once_v1(RootContinuationDemandV1::from_demand_v1(demand)),
        );
        if !matches!(self.models_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.phase = Phase::Compare;
        let subject = HostLaunchSubjectDataV1::decode_v1(initial.subject.bytes())?;
        let operation = OperationId::from_bytes(
            subject
                .start_operation
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?,
        );
        let original = initial.compiler.compiled_v2()?;
        self.source.observe_once_v1(source, operation)?;
        self.previous = Some(current_protected_assignment_data_v2(
            controller,
            original.source_v2().sandbox_v2(),
        )?);
        let previous = self
            .previous
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if initial.kind == Some(super::kind::ResourceKindV2::Host) {
            // Core4/6/5 already activated publication2 before actual Host1.
            // Its currentness is checked against the held initial compilation;
            // it must never be substituted as the predecessor to derive3.
            if previous.manifest_v2().canonical_bytes() != original.manifest_v2().canonical_bytes()
                || previous.publication_v2().lease().canonical_lease()
                    != initial.inputs.lease_v2()?.canonical_lease()
                || previous.publication_v2().lease().canonical_signature()
                    != initial.inputs.lease_v2()?.canonical_signature() {
                return Err(JournalError::ProtectedBoundary.into());
            }
        } else {
            if previous.manifest_v2().canonical_bytes()
                != initial
                    .compiler
                    .previous_v2()?
                    .manifest_v2()
                    .canonical_bytes()
                || previous.publication_v2().digest()
                    != initial.compiler.previous_v2()?.publication_v2().digest()
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
        self.compiled = Some(compile_root_start_assignment_v2(
            controller,
            operation,
            &self.source,
            if initial.kind == Some(super::kind::ResourceKindV2::Host) {
                initial.compiler.previous_v2()?.manifest_v2()
            } else {
                previous.manifest_v2()
            },
            initial.compiler.specification_v2()?,
            current,
            initial.views.tree_data_v1()?.head,
            self.clock.check_next_once_v1()?,
        ).map_err(|cause| cause as Cause)?);
        let compiled = self
            .compiled
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if compiled.manifest_v2().canonical_bytes() != original.manifest_v2().canonical_bytes()
            || compiled.source_v2().native_origin_data_v2()
                != original.source_v2().native_origin_data_v2()
            || compiled.source_v2().projection_revision_v2()
                != original.source_v2().projection_revision_v2()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        if initial.kind == Some(super::kind::ResourceKindV2::Host) {
            let (host_plan, host_signature, live_body, receipt) = self.session.as_ref()
                .ok_or(JournalError::ProtectedBoundary)?.completed_host_comparison_data_v2()?;
            self.host_completed = Some(crate::reconciler::require_completed_start_host_publication_data_v2(
                controller, self.previous.as_ref().ok_or(JournalError::ProtectedBoundary)?,
                operation, initial.reply_digest.ok_or(JournalError::ProtectedBoundary)?,
                original.manifest_v2(), initial.inputs.lease_v2()?, host_plan, host_signature,
                initial.plan.request_body_v2()?, live_body, receipt,
            ));
            if !matches!(self.host_completed, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
        self.response_funding = Some(
            root.flight
                .host_launch_stage_receiving_v1()?
                .admit_host_final_response_once_v1(RootContinuationDemandV1::from_demand_v1(
                    ResourceVector::ZERO
                        .with(D::NetworkBytes, RESOURCE_CLOSED_BYTES_V2 as u64)
                        .with(D::OutputBytes, RESOURCE_CLOSED_BYTES_V2 as u64),
                )),
        );
        if !matches!(self.response_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn finish_posts_once_v2(
        &mut self,
        opening: &RootHostLaunchOpeningOriginalV2,
        initial: &RootStartResourceNativeOriginalV2,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
    ) {
        if self.posts {
            return;
        }
        self.posts = true;
        self.phase = Phase::Posts;
        self.readers.finish_posts_once_v1();
        if self.policy_begun {
            let _owed = flight.finish_host_launch_policy_once_v1(&mut self.policy);
        }
        self.after_sample = Some(self.after_clock.observe_once(None));
        self.after_binding = Some((|| {
            let sample = self
                .after_sample
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(JournalError::ProtectedBoundary)?;
            self.clock.require_final_sample_v1(sample)?;
            opening.require_current_clock_v1(sample)?;
            if sample.wall_seconds() >= initial.compiler.expires_v2(&initial.policy)?
                || sample.wall_seconds() >= initial.inputs.lease_v2()?.authority_expires_seconds()
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
    }

    fn child_failure(&self, phase: Phase) -> Option<&(dyn std::error::Error + 'static)> {
        match phase {
            Phase::Read => self.read.failure(),
            Phase::Eof => self.eof.failure(),
            Phase::Policy => self.policy.failure(),
            Phase::Readonly => self.readers.failure(),
            Phase::Session => self.session.as_ref()?.failure(),
            Phase::Models => self.host_models.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as _).or_else(|| self.models_funding.as_ref()
                    .and_then(|value| value.as_ref().err()).map(|cause| cause as _)),
            Phase::Compare => self.source.failure().or_else(|| self.host_completed.as_ref()
                .and_then(|value| value.as_ref().err()).map(|cause| cause as _)),
            Phase::Send => self.sent.failure(),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let primary = match self.first {
            Some(First::Child(phase)) => self.child_failure(phase),
            Some(First::Clock) => self.clock.failure(),
            Some(First::Body) => self
                .primary
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            None => None,
        };
        primary
            .or_else(|| self.readers.failure())
            .or_else(|| self.policy.failure())
            .or_else(|| self.after_clock.failure())
            .or_else(|| {
                self.after_sample
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.after_binding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.child_failure(self.phase))
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
    }

    pub(super) fn peer_post_entered_v2(&self) -> bool {
        self.peer_after.is_some()
    }

    pub(super) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if matches!(self.returned, Some(Ok(())))
            && self.failure().is_none()
            && self.read.completed_exact()
            && self.eof.completed_exact()
            && self.sent.completed_exact()
            && matches!(self.settlement, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }
}

fn native_cut_matches(actual: NativeCutDataV1, encoded: &[u8]) -> bool {
    actual.matches_encoded_data_v3(encoded)
}
