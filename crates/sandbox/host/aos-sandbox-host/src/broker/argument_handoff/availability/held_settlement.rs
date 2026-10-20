//! Retains the actual four-writer NoApply owner through the finite42/43 turns.
//!
//! The enclosing active19 or fresh current-Control programme pays construction
//! and every original post. History cannot reconstruct either native owner.

use super::root_trust::HostNoApplyRootTrustOriginalV2;
use super::*;
use aos_sandbox_broker::bounded_entropy::RetainedKernelNonceOriginalV1;
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2;
use aos_sandbox_protocol::host_execution_no_apply::{
    ClosedHostTerminalArchiveDataV2, HostExecutionNoApplyRecordV2,
    closed_controller::ClosedCreateFailurePrepareDataV2,
    current_lease::{
        CurrentHostNoApplyLeaseDataV2, CurrentHostNoApplyLeaseFieldsV2, HostNoApplyLeaseScopeV2,
    },
    held_settlement_transport::HostNoApplyHeldCommandV2,
    recovery_acquisition::RootNoApplyRecoveryAcquisitionFieldsV2,
    root_attestation::RootExecutionNoApplyAttestationDataV2,
};
use sha2::{Digest as _, Sha256};
use std::error::Error;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Initial,
    PreliminaryNative,
    PreliminarySent,
    QueryNative,
    QuerySent,
    SealNative,
    SealSent,
    AckNative,
    AckSent,
}

/// Compares immutable terminal history; actual custody remains on the stage.
#[derive(Clone, Copy)]
pub(super) struct RetainedTerminalIdentityV2 {
    pub marker: aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2,
    pub archive_head: aos_sandbox_model::ObjectDigest,
    pub signed_terminal_outcome: aos_sandbox_model::ObjectDigest,
}

impl From<ClosedHostTerminalArchiveDataV2> for RetainedTerminalIdentityV2 {
    fn from(actual: ClosedHostTerminalArchiveDataV2) -> Self {
        Self {
            marker: actual.marker(),
            archive_head: actual.archive_head(),
            signed_terminal_outcome: actual.signed_terminal_outcome(),
        }
    }
}

impl RetainedTerminalIdentityV2 {
    fn marker(
        self,
    ) -> aos_sandbox_protocol::host_execution_no_apply::ClosedBeforeArgumentNoApplyRecordV2 {
        self.marker
    }

    fn archive_head(self) -> aos_sandbox_model::ObjectDigest {
        self.archive_head
    }

    fn signed_terminal_outcome(self) -> aos_sandbox_model::ObjectDigest {
        self.signed_terminal_outcome
    }
}

pub(super) struct HeldNoApplyOriginalV2 {
    trust: HostNoApplyRootTrustOriginalV2,
    entropy: [RetainedKernelNonceOriginalV1; 2],
    phase: Phase,
    challenge: Option<[u8; 32]>,
    comparison: Option<CurrentHostNoApplyLeaseDataV2>,
    root_nonce: Option<[u8; 32]>,
    signed_query_outcome: Option<[u8; 32]>,
    prepare: Option<ClosedCreateFailurePrepareDataV2>,
    controller_cut: Option<RootExecutionNoApplyControllerCutDataV2>,
    recovery: Option<RootNoApplyRecoveryAcquisitionFieldsV2>,
}

pub(super) struct HeldNoApplyNativeTurnV2<'turn, 'claim> {
    pub request: &'turn AuthenticatedBrokerMethodRequestV1,
    pub claim: &'turn mut aos_sandbox_controller_domain::runtime_execution::DormantRuntimeExecutionClaimV1<'claim>,
    pub clock: &'turn mut ArgumentClockV2,
    pub effective_deadline: u64,
    pub original_first_clock: u64,
    pub original_cutoff: u64,
    pub availability: HostExecutionAvailabilityObservationV2,
    pub archive: RetainedTerminalIdentityV2,
    pub host_state_cut: [u8; 32],
}

enum NoApplyNativeDisposalV2<'original> {
    Active(crate::plan::HostTerminalStageDisposalV3<'original>),
    Cleanup(crate::plan::HostControlCleanupDisposalV1<'original>),
}

impl NoApplyNativeDisposalV2<'_> {
    fn complete_after_native_drop_v2(self) -> Result<()> {
        match self {
            Self::Active(original) => {
                original.complete_after_disposal_v3();
                Ok(())
            }
            Self::Cleanup(original) => original.complete_after_native_drop_v1(),
        }
    }
}

impl HeldNoApplyOriginalV2 {
    pub(super) fn new() -> Self {
        Self::with_trust(HostNoApplyRootTrustOriginalV2::new(), None)
    }

    fn with_trust(
        trust: HostNoApplyRootTrustOriginalV2,
        recovery: Option<RootNoApplyRecoveryAcquisitionFieldsV2>,
    ) -> Self {
        Self {
            trust,
            entropy: std::array::from_fn(|_| RetainedKernelNonceOriginalV1::new()),
            phase: Phase::Initial,
            challenge: None,
            comparison: None,
            root_nonce: None,
            signed_query_outcome: None,
            prepare: None,
            controller_cut: None,
            recovery,
        }
    }

    pub(super) fn new_cleanup_v2(
        trust: HostNoApplyRootTrustOriginalV2,
        recovery: RootNoApplyRecoveryAcquisitionFieldsV2,
    ) -> Self {
        Self::with_trust(trust, Some(recovery))
    }

    pub(super) fn verify_acquisition_before_open_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        node: [u8; 16],
        clock: &mut ArgumentClockV2,
        deadline: u64,
    ) -> std::result::Result<(), ArgumentStageErrorV2> {
        let Some(HostNoApplyHeldCommandV2::RecoveryPreliminary {
            canonical_root_acquisition,
        }) = request
            .host_held_no_apply_settlement_data_v2()
            .map(|value| value.command_v2())
        else {
            return Err(HostError::Fence("Host cleanup acquisition context is absent").into());
        };
        self.trust
            .observe_before_once_v2()
            .map_err(|_| HostError::Fence("Host cleanup Root public pin is unavailable"))?;
        let sample = clock.sample()?;
        let actual = self
            .trust
            .verify_acquisition_once_v2(
                canonical_root_acquisition,
                super::root_trust::HostNoApplyRecoveryRecipientV2 {
                    node,
                    boot: clock.protected_boot_data_v4(),
                    session: request.session_binding(),
                    request: request.request_id(),
                    deadline,
                    clock: sample,
                },
            )
            .map_err(|_| HostError::Fence("Host cleanup Root acquisition verification failed"))?;
        if Some(actual) != self.recovery {
            return Err(HostError::Fence("Host cleanup acquisition source changed").into());
        }
        Ok(())
    }

    pub(super) fn receiving_demand_v2() -> Option<ResourceVector> {
        let native = std::mem::size_of::<HostNoApplyRootTrustOriginalV2>()
            .checked_add(2 * std::mem::size_of::<RetainedKernelNonceOriginalV1>())?;
        let memory = std::mem::size_of::<Self>().checked_sub(native)?.checked_mul(3)?
            .checked_add(2 * RetainedKernelNonceOriginalV1::construction_bytes_v1()?)?
            .checked_add(2 * std::mem::size_of::<HeldNoApplyNativeTurnV2<'static, 'static>>())?
            .checked_add(2 * std::mem::size_of::<NoApplyNativeDisposalV2<'static>>())?;
        HostNoApplyRootTrustOriginalV2::receiving_demand_v2()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?))
            .ok()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.trust
            .failure()
            .or_else(|| self.entropy.iter().find_map(|nonce| nonce.failure()))
    }

    pub(super) fn has_comparison_v2(&self) -> bool {
        self.comparison.is_some()
    }

    pub(super) fn has_sent_phase_v2(&self, request: &AuthenticatedBrokerMethodRequestV1) -> bool {
        let expected = match request
            .host_held_no_apply_settlement_data_v2()
            .map(|value| value.command_v2())
        {
            Some(HostNoApplyHeldCommandV2::Preliminary { .. }
                | HostNoApplyHeldCommandV2::RecoveryPreliminary { .. }) => Phase::PreliminarySent,
            Some(HostNoApplyHeldCommandV2::FloorSeal { .. }) => Phase::SealSent,
            Some(HostNoApplyHeldCommandV2::Acknowledge { .. }) => Phase::AckSent,
            None if request
                .host_no_apply_current_lease_query_data_v2()
                .is_some() =>
            {
                Phase::QuerySent
            }
            None => return false,
        };
        self.phase == expected
            && self.comparison.is_some_and(|comparison| {
                let fields = comparison.fields();
                fields.current_request == request.request_id()
                    && fields.current_session == request.session_binding()
                    && fields.signed_current_request == request.signed_request_digest()
            })
    }

    pub(super) fn execute_once_v2(
        &mut self,
        turn: HeldNoApplyNativeTurnV2<'_, '_>,
    ) -> std::result::Result<Vec<u8>, ArgumentStageErrorV2> {
        let HeldNoApplyNativeTurnV2 {
            request,
            claim,
            clock,
            effective_deadline,
            original_first_clock,
            original_cutoff,
            availability,
            archive,
            host_state_cut,
        } = turn;
        let command = request
            .host_held_no_apply_settlement_data_v2()
            .map(|value| value.command_v2());
        let turn = match (
            self.phase,
            command,
            request.host_no_apply_current_lease_query_data_v2(),
        ) {
            (
                Phase::Initial,
                Some(HostNoApplyHeldCommandV2::Preliminary {
                    marker,
                    archive_head,
                    signed_terminal_outcome,
                }),
                None,
            ) if self.recovery.is_none() && *marker == archive.marker()
                && *archive_head == archive.archive_head()
                && *signed_terminal_outcome == archive.signed_terminal_outcome() =>
            {
                0
            }
            (
                Phase::Initial,
                Some(HostNoApplyHeldCommandV2::RecoveryPreliminary { canonical_root_acquisition }),
                None,
            ) if self.recovery.is_some_and(|expected| {
                aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(
                    canonical_root_acquisition,
                ).is_ok_and(|actual| actual.fields_v2() == expected)
            }) => 0,
            (Phase::PreliminarySent, None, Some(_)) => 1,
            (Phase::QuerySent, Some(HostNoApplyHeldCommandV2::FloorSeal { .. }), None) => 2,
            (Phase::SealSent, Some(HostNoApplyHeldCommandV2::Acknowledge { .. }), None) => 3,
            _ => {
                return Err(HostError::Fence("Host held NoApply phase or terminal differs").into());
            }
        };
        if self.failure().is_some()
            || self.recovery.is_some() && self.trust.completed_acquisition_v2() != self.recovery
        {
            return Err(HostError::Fence("Host held NoApply retains its original failure").into());
        }
        if turn == 0 && self.recovery.is_none() {
            self.trust
                .observe_before_once_v2()
                .map_err(|_| HostError::Fence("Host Root floor public pin is unavailable"))?;
        }
        let before = match turn {
            0 => self.trust.preliminary_before_once_v2(),
            1 => self.trust.nonce_before_once_v2(),
            2 => self.trust.floor_before_once_v2(),
            _ => self.trust.ack_before_once_v2(),
        };
        let primary =
            (|| -> std::result::Result<CurrentHostNoApplyLeaseDataV2, ArgumentStageErrorV2> {
                before.map_err(|_| HostError::Fence("Host Root public pin before check failed"))?;
                if self.recovery.is_some() {
                    claim.require_held_closed_no_apply_history_v2(archive.marker())?;
                } else {
                    claim.require_held_active_closed_no_apply_v2(archive.marker())?;
                }
                let cut = claim.protected_host_settlement_cut_v1()?;
                let observed = clock.sample()?.boottime_nanoseconds();
                if observed >= effective_deadline {
                    return Err(
                        HostError::Fence("Host held NoApply original deadline expired").into(),
                    );
                }
                if turn == 0 {
                    let first = self.entropy[0].observe_once().map_err(|_| {
                        HostError::Fence("Host settlement challenge entropy failed")
                    })?;
                    let second = self.entropy[1].observe_once().map_err(|_| {
                        HostError::Fence("Host settlement challenge entropy failed")
                    })?;
                    let mut challenge = [0; 32];
                    challenge[..16].copy_from_slice(&first);
                    challenge[16..].copy_from_slice(&second);
                    self.challenge = Some(challenge);
                    let lease_head = Sha256::new()
                        .chain_update(b"aos.sandbox.host.held-no-apply-native-head.v2\0")
                        .chain_update(archive.marker().encode_canonical())
                        .chain_update(archive.archive_head().as_bytes())
                        .chain_update(archive.signed_terminal_outcome().as_bytes())
                        .chain_update(host_state_cut)
                        .chain_update(cut.digest().as_bytes())
                        .chain_update(cut.epoch().to_be_bytes())
                        .chain_update(challenge)
                        .chain_update(request.session_binding())
                        .finalize()
                        .into();
                    let comparison =
                        CurrentHostNoApplyLeaseDataV2::new(CurrentHostNoApplyLeaseFieldsV2 {
                            scope: if self.recovery.is_some() {
                                HostNoApplyLeaseScopeV2::RecoveryCleanup
                            } else {
                                HostNoApplyLeaseScopeV2::Active
                            },
                            native_first_clock: original_first_clock,
                            native_cutoff: original_cutoff,
                            native_boot: claim.host_verifier().boot_id(),
                            availability,
                            accepted_source: archive.marker().fields().source,
                            marker: HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(
                                archive.marker(),
                            ),
                            signed_terminal_outcome: *archive.signed_terminal_outcome().as_bytes(),
                            terminal_archive_head: *archive.archive_head().as_bytes(),
                            protected_host_state_cut: host_state_cut,
                            protected_execution_cut: *cut.digest().as_bytes(),
                            lease_head,
                            challenge,
                            current_session: request.session_binding(),
                            signed_current_request: request.signed_request_digest(),
                            lease_epoch: cut.epoch(),
                            observed_clock: observed,
                            current_request: request.request_id(),
                        })?;
                    self.comparison = Some(comparison);
                }
                let expected = self
                    .comparison
                    .ok_or(HostError::Fence("Host native NoApply lease is absent"))?;
                let expected_fields = expected.fields();
                if expected_fields.protected_host_state_cut != host_state_cut
                    || expected_fields.protected_execution_cut != *cut.digest().as_bytes()
                    || expected_fields.lease_epoch != cut.epoch()
                {
                    return Err(
                        HostError::Fence("Host native NoApply protected cut changed").into(),
                    );
                }
                match command {
                    Some(HostNoApplyHeldCommandV2::FloorSeal {
                        comparison,
                        canonical_root_attestation,
                        controller_prepare,
                    }) => {
                        if *comparison != expected {
                            return Err(HostError::Fence(
                                "Host Root floor changed its actual current43",
                            )
                            .into());
                        }
                        self.trust
                            .verify_once_v2(
                                canonical_root_attestation,
                                self.challenge
                                    .ok_or(HostError::Fence("Host challenge is absent"))?,
                                expected,
                                self.signed_query_outcome
                                    .ok_or(HostError::Fence("Host signed43 is absent"))?,
                                self.root_nonce
                                    .ok_or(HostError::Fence("Host Root read nonce is absent"))?,
                                *controller_prepare,
                            )
                            .map_err(|_| {
                                HostError::Fence("Host Root floor signature or native joins differ")
                            })?;
                        let artifact = RootExecutionNoApplyAttestationDataV2::decode_canonical(
                            canonical_root_attestation,
                        )?;
                        self.prepare = Some(*controller_prepare);
                        self.controller_cut =
                            Some(artifact.floor_data_v2().fields().controller_cut);
                    }
                    Some(HostNoApplyHeldCommandV2::Acknowledge { comparison, ack }) => {
                        require_same_lease_v2(*comparison, expected)?;
                        let prepare = self
                            .prepare
                            .ok_or(HostError::Fence("Host sealed prepare is absent"))?;
                        let baseline = self
                            .controller_cut
                            .ok_or(HostError::Fence("Host sealed Controller cut is absent"))?;
                        use aos_sandbox_protocol::host_execution_no_apply::{
                            closed_controller::ControllerCreateFailureAckPhaseV2 as AckPhase,
                            recovery_acquisition::RootNoApplyRecoveryPhaseV2 as RecoveryPhase,
                        };
                        let expected_phase = match self.recovery.map(|value| value.phase) {
                            None => AckPhase::Active,
                            Some(RecoveryPhase::BeforeFloor) => AckPhase::RecoveryBeforeFloor,
                            Some(RecoveryPhase::FloorAnchored) => AckPhase::RecoveryFloorAnchored,
                            Some(RecoveryPhase::Prepared) => AckPhase::RecoveryPrepared,
                            Some(RecoveryPhase::Settled) => AckPhase::RecoverySettled,
                        };
                        if ack.phase != expected_phase
                            || ack.operation != prepare.operation
                            || ack.root_floor != prepare.root_floor
                            || ack.root_sequence != prepare.root_sequence
                            || ack.controller_prepare != prepare.digest()
                            || ack.settled_cas != prepare.settled_cas_digest()
                            || ack.controller_cut.names() != baseline.names()
                            || baseline.next().checked_add(expected_phase.controller_advance_data_v2())
                                != Some(ack.controller_cut.next())
                            || ack.controller_cut.end() <= baseline.end()
                        {
                            return Err(HostError::Fence(
                                "Host ACK differs from its exact sealed CAS",
                            )
                            .into());
                        }
                    }
                    None => {
                        let query = request
                            .host_no_apply_current_lease_query_data_v2()
                            .ok_or(HostError::Fence("Host current query is absent"))?;
                        require_same_lease_v2(query.comparison_v2(), expected)?;
                        self.root_nonce = Some(query.read_nonce_v2());
                    }
                    _ => {}
                }
                claim.revalidate()?;
                if claim.protected_host_settlement_cut_v1()? != cut {
                    return Err(
                        HostError::Fence("Host native NoApply execution cut changed").into(),
                    );
                }
                let observed = clock.sample()?.boottime_nanoseconds();
                if observed >= effective_deadline {
                    return Err(
                        HostError::Fence("Host held NoApply original deadline expired").into(),
                    );
                }
                let comparison =
                    CurrentHostNoApplyLeaseDataV2::new(CurrentHostNoApplyLeaseFieldsV2 {
                        current_session: request.session_binding(),
                        signed_current_request: request.signed_request_digest(),
                        current_request: request.request_id(),
                        observed_clock: observed,
                        ..expected_fields
                    })?;
                Ok(comparison)
            })();
        // A reached before always owes its actual independent after, including
        // entropy, signature, native-currentness and primary refusals.
        let after = match turn {
            0 => self.trust.preliminary_after_once_v2(),
            1 => self.trust.nonce_after_once_v2(),
            2 => self.trust.floor_after_once_v2(),
            _ => self.trust.ack_after_once_v2(),
        };
        let comparison = primary?;
        after.map_err(|_| HostError::Fence("Host Root public pin owed after failed"))?;
        self.comparison = Some(comparison);
        self.phase = match turn {
            0 => Phase::PreliminaryNative,
            1 => Phase::QueryNative,
            2 => Phase::SealNative,
            _ => Phase::AckNative,
        };
        Ok(comparison.encode_canonical())
    }

    pub(super) fn retain_sent_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<()> {
        let expected = self
            .comparison
            .ok_or(HostError::Fence("Host native NoApply comparison is absent"))?;
        let aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
        else { return Err(HostError::Fence("Host held NoApply Sent is not positive")); };
        if outcome.request().canonical_packet() != request.canonical_packet()
            || expected.encode_canonical() != *exact_body
        {
            return Err(HostError::Fence(
                "Host held NoApply Sent changed its actual response",
            ));
        }
        self.phase = match self.phase {
            Phase::PreliminaryNative => Phase::PreliminarySent,
            Phase::QueryNative => {
                self.signed_query_outcome = Some(Sha256::digest(outcome.canonical_packet()).into());
                Phase::QuerySent
            }
            Phase::SealNative => Phase::SealSent,
            Phase::AckNative => Phase::AckSent,
            _ => return Err(HostError::Fence("Host held NoApply Sent phase differs")),
        };
        Ok(())
    }
}

fn require_same_lease_v2(
    actual: CurrentHostNoApplyLeaseDataV2,
    expected: CurrentHostNoApplyLeaseDataV2,
) -> Result<()> {
    let mut retained = actual.fields();
    let expected = expected.fields();
    retained.current_session = expected.current_session;
    retained.signed_current_request = expected.signed_current_request;
    retained.current_request = expected.current_request;
    retained.observed_clock = expected.observed_clock;
    if retained != expected {
        return Err(HostError::Fence(
            "Host comparison differs from its actual held lease",
        ));
    }
    Ok(())
}

impl<C: crate::plan::HostCatalog, S: HostStateStore, W: crate::worker::HostWorker>
    super::super::super::HostBroker<C, S, W>
{
    pub(in crate::broker) fn dispose_acknowledged_no_apply_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        if !matches!(
            request
                .host_held_no_apply_settlement_data_v2()
                .map(|original| original.command_v2()),
            Some(HostNoApplyHeldCommandV2::Acknowledge { .. })
        ) {
            return Ok(());
        }
        if !self.no_apply_settlement_frozen_v2
            || self.argument_stages[1].is_some()
            || self.active_argument_writes.is_some()
            || self.active_launch_writes.is_some()
        {
            return Err(HostError::Fence(
                "Host NoApply native custody cannot dispose",
            ));
        }
        let stage = self.argument_stages[0]
            .as_ref()
            .ok_or(HostError::Fence("Host NoApply terminal stage is absent"))?;
        if Arc::strong_count(stage) != 1 {
            return Err(HostError::Fence("Host NoApply terminal stage is aliased"));
        }
        let capture = stage
            .lock()
            .map_err(|_| HostError::Fence("Host NoApply stage is poisoned"))?;
        let available = capture
            .availability
            .as_ref()
            .ok_or(HostError::Fence("Host NoApply availability is absent"))?;
        let original = available
            .settlement
            .as_ref()
            .ok_or(HostError::Fence("Host NoApply settlement is absent"))?;
        if !capture.authenticated
            || capture.first.is_some()
            || capture.primary.is_some()
            || capture.owner.is_none()
            || capture.argument.is_some()
            || capture.accepted.is_some()
            || available.prepared.is_some()
            || available.accept.is_some()
            || available.failure().is_some()
            || original.phase != Phase::AckSent
            || !original.has_sent_phase_v2(request)
            || !original.trust.completed_comparison_v2()
            || available
                .intervals
                .iter()
                .any(|interval| !interval.authenticated)
            || !matches!(capture.before, Some(Ok(())))
            || !matches!(capture.after, Some(Ok(())))
            || !matches!(capture.native_finish, Some(Ok(())))
            || Arc::strong_count(&capture.writes) != 1
        {
            return Err(HostError::Fence(
                "Host NoApply terminal retains unresolved original debt",
            ));
        }
        capture
            .writes
            .lock()
            .map_err(|_| HostError::Fence("Host terminal State prefix is poisoned"))?
            .require_positive_disposal_v2()?;
        if let Some(output) = available.output_writes.as_ref() {
            if Arc::strong_count(output) != 1 {
                return Err(HostError::Fence("Host NoApply output prefix is aliased"));
            }
            output
                .lock()
                .map_err(|_| HostError::Fence("Host output prefix is poisoned"))?
                .require_positive_disposal_v2()?;
        }
        let posts = HostNoApplyTerminalPositiveV2 {
            stage: &capture,
            prepare: available.original,
            ack: request_identity(request),
        };
        let mut component = self
            .component_control
            .as_ref()
            .ok_or(HostError::Fence(
                "Host NoApply financial original is absent",
            ))?
            .lock()
            .map_err(|_| HostError::Fence("Host NoApply financial original is poisoned"))?;
        let disposal = match &available.origin {
            HostAvailabilityOriginV2::Active(_) => NoApplyNativeDisposalV2::Active(
                component.prepare_no_apply_terminal_disposal_v2(&posts)?,
            ),
            HostAvailabilityOriginV2::Cleanup { token: Some(token) } => {
                NoApplyNativeDisposalV2::Cleanup(
                    component.prepare_no_apply_cleanup_disposal_v1(token, &posts)?,
                )
            }
            HostAvailabilityOriginV2::Cleanup { token: None } => {
                return Err(HostError::Fence(
                    "Host NoApply cleanup native owner lost its current-Control original",
                ));
            }
        };
        drop(capture);
        let stage = self.argument_stages[0].take().ok_or(HostError::Fence(
            "Host NoApply original disappeared before disposition",
        ))?;
        let mut native = match Arc::try_unwrap(stage) {
            Ok(native) => native,
            Err(stage) => {
                self.argument_stages[0] = Some(stage);
                return Err(HostError::Fence(
                    "Host NoApply last native owner remains aliased",
                ));
            }
        };
        if native.get_mut().is_err() {
            self.argument_stages[0] = Some(Arc::new(native));
            return Err(HostError::Fence(
                "Host NoApply last native owner is poisoned",
            ));
        }
        // The actual last four writers, Root pin and every retained prefix die
        // before its actual active19 or fresh-Control payer ends liability.
        drop(native);
        disposal.complete_after_native_drop_v2()?;
        self.no_apply_settlement_frozen_v2 = false;
        Ok(())
    }
}
