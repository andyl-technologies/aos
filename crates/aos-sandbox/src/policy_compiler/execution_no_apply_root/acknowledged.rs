//! Certifies Root serving succession from independently read native ACK evidence.
//!
//! A completed floor alone cannot refresh Root6. This owner independently
//! captures final C, Host Session and Source through the shared final reader,
//! authenticates actual signed42 Acknowledge and checks the exact terminal
//! rows/global cut. Same Root/Policy writers and financial owners remain held.
//! No decoded ACK or scalar sequence can construct a completed native owner.

use std::error::Error;
use std::fs::Metadata;
use std::mem::size_of;

use aos_sandbox_broker::receiving::RootWriterPostOriginalV1;
use aos_sandbox_broker::systemd_credentials::RootCurrentHostManifestCustodyV2;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableHistoryV1, BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1,
    BrokerSessionTrafficStateV1, HistoricalTrafficReplayCaptureV1,
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    manifest::{BrokerSessionManifestAudienceV1, BrokerSessionManifestV1},
};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use aos_sandbox_protocol::authenticated_session::{
    historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    historical_method::HistoricalStartResourceMethodCaptureV2,
    stored_history::{
        StoredBrokerSessionHistoryDecodeCaptureV1, StoredBrokerSessionHistoryV1,
        canonical_protocol_key_v1,
    },
};
use aos_sandbox_protocol::host_execution_no_apply::{
    closed_controller::{
        ClosedCreateFailurePrepareDataV2, ControllerCreateFailureAckDataV2,
        ControllerCreateFailureAckPhaseV2,
    },
    current_lease::{CurrentHostNoApplyLeaseDataV2, HostNoApplyLeaseScopeV2},
    held_settlement_transport::HostNoApplyHeldCommandV2,
    root_attestation::RootExecutionNoApplyAttestationDataV2,
};

use crate::controller_resource_reservation::{
    RootContinuationDemandV1, service_interval::ObserverLifetime,
};
use crate::journal::{JournalError, root_construction::RootJournalServingIdentityV1};
use crate::normal_root::{
    NormalRootStartupErrorV1, RootControllerPeerCurrentSampleV1, RootPolicyAcceptedFlightV1,
};
use crate::policy_compiler::{
    continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
    create_storage_current::{
        closed::RootCurrentTerminalCompletionV1,
        controller_readonly::storage_inventory::verify_execution_host_history_retaining_v2,
        pins::RootCurrentPinsStateV1,
    },
    provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1,
    root_current_writers::{RootCreateStorageCurrentWritersV1, RootCurrentWriterRoleV1},
};
use crate::reconciler::ClosedCreateFailurePlanDataV2;

use super::{
    RootExecutionNoApplyFloorOriginalV2, RootExecutionNoApplyHostLeaseOriginalV2,
    RootExecutionNoApplyHostTrustOriginalV2,
    current_host_lease::host_history::HostHistoryOriginalV2,
};

type Cause = Box<dyn Error>;

// A recovery purpose is selected only by the retained native issuer original.
enum AckOriginV2<'held> {
    Active,
    Recovery(&'held mut super::RootExecutionNoApplyAcquisitionOriginalV2),
}

impl AckOriginV2<'_> {
    fn require_sample_v2(
        &self,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        sample: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), JournalError> {
        match self {
            Self::Active => Ok(()),
            Self::Recovery(acquisition) => acquisition.require_cleanup_sample_v2(policy, sample),
        }
    }

    fn require_floor_v2(
        &self,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        floor: &RootExecutionNoApplyFloorOriginalV2,
    ) -> Result<ControllerCreateFailureAckPhaseV2, JournalError> {
        match self {
            Self::Active => {
                if floor.floor_data_v2()?.fields().host_lease.fields().scope
                    != HostNoApplyLeaseScopeV2::Active
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                Ok(ControllerCreateFailureAckPhaseV2::Active)
            }
            Self::Recovery(acquisition) => {
                acquisition.acknowledgement_phase_v2(writers, pins, floor)
            }
        }
    }
}
type Session = (
    ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1,
    BrokerSessionTrafficStateV1,
);

#[derive(Clone, Copy)]
enum First {
    Arm,
    Before,
    Peer,
    Capture,
    Manifest,
    Body,
    CredentialPost,
    ReaderPost,
    RootPost,
    Final,
}

pub(crate) struct RootExecutionNoApplyAckOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    reentry: Option<JournalError>,
}

struct Native {
    first: Option<First>,
    posts: [Option<Result<RootWriterPostOriginalV1, JournalError>>; 4],
    posted: [Option<Result<(), JournalError>>; 4],
    peer: RootControllerPeerCurrentSampleV1,
    peer_result: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<[RootJournalServingIdentityV1; 2], JournalError>>,
    after: Option<Result<[RootJournalServingIdentityV1; 2], JournalError>>,
    end: [Option<std::io::Result<Metadata>>; 2],
    files: RootCurrentHostManifestCustodyV2,
    captured: Option<Result<(), ()>>,
    credential_post: Option<Result<(), ()>>,
    manifest: Option<Result<BrokerSessionManifestV1, Cause>>,
    roster: HostHistoryOriginalV2,
    stored: StoredBrokerSessionHistoryDecodeCaptureV1,
    checkpoint: HistoricalSessionCheckpointVerifyCaptureV1,
    traffic: HistoricalTrafficReplayCaptureV1,
    verified: Option<Result<Session, Cause>>,
    method: HistoricalStartResourceMethodCaptureV2,
    plan: Option<Result<ClosedCreateFailurePlanDataV2, super::RootExecutionNoApplyModelsErrorV2>>,
    ack: Option<ControllerCreateFailureAckDataV2>,
    body: Option<Result<(), Cause>>,
    reader_post: Option<Result<(), JournalError>>,
    final_binding: Option<Result<(), Cause>>,
    external_trust: bool,
    external_readers: bool,
}

impl RootExecutionNoApplyAckOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            native: None,
            reentry: None,
        }
    }

    /// Enters the finite actual275 verifier after independent final266..274 reads.
    /// Native posts run after every entered refusal before any receipt escapes.
    pub(crate) fn observe_active_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        stream: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        terminal: &RootCurrentTerminalCompletionV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        floor: &RootExecutionNoApplyFloorOriginalV2,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
    ) -> Result<(), JournalError> {
        self.observe_programme_once_v2(
            flight,
            stream,
            writers,
            pins,
            terminal,
            policy,
            floor,
            readonly,
            trust,
            AckOriginV2::Active,
        )
    }

    /// Verifies recovery only against the retained genuine acquisition owner.
    pub(crate) fn observe_recovery_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        stream: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        terminal: &RootCurrentTerminalCompletionV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        floor: &RootExecutionNoApplyFloorOriginalV2,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        acquisition: &mut super::RootExecutionNoApplyAcquisitionOriginalV2,
    ) -> Result<(), JournalError> {
        self.observe_programme_once_v2(
            flight,
            stream,
            writers,
            pins,
            terminal,
            policy,
            floor,
            readonly,
            trust,
            AckOriginV2::Recovery(acquisition),
        )
    }

    fn observe_programme_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        stream: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        terminal: &RootCurrentTerminalCompletionV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        floor: &RootExecutionNoApplyFloorOriginalV2,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        mut origin: AckOriginV2<'_>,
    ) -> Result<(), JournalError> {
        let returned = (|| {
            if self.geometry.is_some() {
                self.reentry.get_or_insert(JournalError::ProtectedBoundary);
                return Err(JournalError::ProtectedBoundary);
            }
            if let AckOriginV2::Recovery(acquisition) = &mut origin {
                acquisition.require_ack_connection_once_v2(stream)?;
            }
            self.geometry = Some((|| {
                readonly.require_execution_no_apply_final_v2()?;
                let data = readonly.execution_no_apply_current_data_v2()?;
                let carriers = u64::try_from(
                    size_of::<Self>()
                        .checked_mul(3)
                        .and_then(|n| n.checked_add(size_of::<Native>().checked_mul(3)?))
                        .and_then(|n| n.checked_add(size_of::<AckOriginV2<'_>>().checked_mul(2)?))
                        .ok_or(JournalError::JournalTooLarge)?,
                )
                .map_err(|_| JournalError::JournalTooLarge)?;
                let mut demand = data
                    .host_current_lease_demand_data_v2()?
                    .checked_add(
                        data.planning_demand_v2()
                            .map_err(|_| JournalError::ProtectedBoundary)?,
                    )?
                    .checked_add(
                        RootCurrentHostManifestCustodyV2::dominant_demand()
                            .ok_or(JournalError::JournalTooLarge)?,
                    )?
                    .checked_add(RootJournalServingIdentityV1::pair_demand_v1()?)?
                    .checked_add(RootJournalServingIdentityV1::pair_demand_v1()?)?
                    .checked_add(
                        RootControllerPeerCurrentSampleV1::demand_v1()
                            .map_err(|_| JournalError::ProtectedBoundary)?,
                    )?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carriers))?;
                for role in RootCurrentWriterRoleV1::ALL {
                    let one = writers
                        .serving_policy_interval_journal_v1(role)?
                        .root_names_post_demand_v1()?;
                    demand = demand.checked_add(one)?.checked_add(one)?;
                }
                Ok(demand)
            })());
            let demand = *positive(&self.geometry)?;
            self.funding = Some(flight.execution_no_apply_stage_receiving_v2().and_then(
                |mut stage| {
                    stage.admit_execution_no_apply_ack_once_v2(
                        RootContinuationDemandV1::from_demand_v1(demand),
                    )
                },
            ));
            positive(&self.funding)?;
            self.native = Some(Box::new(Native::new()));
            let native = self
                .native
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            native.body = Some(native.observe_body(
                flight, stream, writers, pins, terminal, policy, floor, readonly, trust, &origin,
            ));
            if matches!(native.body, Some(Err(_))) {
                native.first.get_or_insert(First::Body);
            }
            native.external_trust = trust.failure().is_some();
            native.finish_posts(writers, readonly);
            native.final_binding = Some((|| {
                positive(&native.body)?;
                positive(&native.before)?;
                for index in 0..2 {
                    let actual = writers.serving_identities_v1()?;
                    positive(&native.before)?[index]
                        .require_same_captured_cut_v2(&actual[index])?;
                }
                terminal.require_execution_floor_successor_v2(writers, pins, floor)?;
                policy.require_complete_v1()?;
                native.end[1] = Some(
                    writers
                        .serving_policy_interval_journal_v1(RootCurrentWriterRoleV1::Authority)?
                        .held_native_receiving_metadata_v1()
                        .0,
                );
                let packet = RootExecutionNoApplyAttestationDataV2::decode_canonical(
                    floor.attestation_bytes_v2()?,
                )?;
                if positive(&native.end[0])?.len() != packet.authority_end_v2()
                    || positive(&native.end[1])?.len() != packet.authority_end_v2()
                {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                let sample = trust.next_sample_v2()?;
                origin.require_sample_v2(policy, sample)?;
                require_policy_live(policy, sample.wall_seconds())?;
                readonly.require_complete_v1()?;
                positive(&native.credential_post)?;
                for post in &native.posted {
                    positive(post)?;
                }
                native.after = Some(writers.serving_identities_v1());
                positive(&native.after)?;
                Ok(())
            })());
            native.external_trust |= trust.failure().is_some();
            if matches!(native.final_binding, Some(Err(_))) {
                native.first.get_or_insert(First::Final);
            }
            self.require_complete_v2()
        })();
        // Earlier native final reads owe their own posts even if275 cannot be
        // admitted or constructed. A later failure never erases an earlier one.
        readonly.finish_posts_once_v1();
        returned
    }

    pub(crate) fn require_complete_v2(&self) -> Result<(), JournalError> {
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.reentry.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || native.first.is_some()
            || !matches!(native.body, Some(Ok(())))
            || !matches!(native.final_binding, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        native
            .ack
            .ok_or(JournalError::ProtectedBoundary)
            .map(|_| ())
    }

    /// Joins this actual completed native owner to the retained Root6 identities.
    pub(crate) fn require_serving_successor_v2(
        &self,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        floor: &RootExecutionNoApplyFloorOriginalV2,
        before: &[RootJournalServingIdentityV1; 2],
    ) -> Result<(), JournalError> {
        self.require_complete_v2()?;
        floor.require_policy_successor_v2(writers, pins, before)?;
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        writers.require_serving_identities_v1(positive(&native.after)?)?;
        Ok(())
    }

    /// Borrows the exact ACK only after all genuine final native consumers finish.
    pub(crate) fn acknowledgement_data_v2(
        &self,
    ) -> Result<ControllerCreateFailureAckDataV2, JournalError> {
        self.require_complete_v2()?;
        self.native
            .as_deref()
            .and_then(|native| native.ack)
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Selects the separately owned original when its first native failure won.
    pub(crate) fn external_failure_v2(&self) -> (bool, bool) {
        let Some(native) = self.native.as_deref() else {
            return (false, false);
        };
        (
            matches!(native.first, Some(First::Body | First::Final)) && native.external_trust,
            matches!(native.first, Some(First::ReaderPost)) && native.external_readers,
        )
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause as _)
            .or_else(|| {
                self.funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.native.as_deref()?.failure())
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Native {
    fn new() -> Self {
        Self {
            first: None,
            posts: std::array::from_fn(|_| None),
            posted: std::array::from_fn(|_| None),
            peer: RootControllerPeerCurrentSampleV1::new(ObserverLifetime::begin()),
            peer_result: None,
            peer_settlement: None,
            before: None,
            after: None,
            end: std::array::from_fn(|_| None),
            files: RootCurrentHostManifestCustodyV2::new(),
            captured: None,
            credential_post: None,
            manifest: None,
            roster: HostHistoryOriginalV2::new(),
            stored: Default::default(),
            checkpoint: Default::default(),
            traffic: Default::default(),
            verified: None,
            method: Default::default(),
            plan: None,
            ack: None,
            body: None,
            reader_post: None,
            final_binding: None,
            external_trust: false,
            external_readers: false,
        }
    }

    fn observe_body(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        stream: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        terminal: &RootCurrentTerminalCompletionV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        floor: &RootExecutionNoApplyFloorOriginalV2,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        origin: &AckOriginV2<'_>,
    ) -> Result<(), Cause> {
        for index in 0..4 {
            self.posts[index] = Some(
                writers
                    .serving_policy_interval_journal_v1(RootCurrentWriterRoleV1::ALL[index % 2])?
                    .arm_root_names_post_once_v1(),
            );
            if !matches!(self.posts[index], Some(Ok(_))) {
                self.first.get_or_insert(First::Arm);
            }
        }
        for post in &self.posts {
            positive(post)?;
        }
        for index in 0..2 {
            self.post(writers, index);
            positive(&self.posted[index])?;
        }
        self.before = Some(writers.serving_identities_v1());
        positive(&self.before)?;
        terminal.require_execution_floor_successor_v2(writers, pins, floor)?;
        policy.require_complete_v1()?;
        let sample = trust.next_sample_v2()?;
        origin.require_sample_v2(policy, sample)?;
        require_policy_live(policy, sample.wall_seconds())?;
        self.peer_result =
            Some(flight.observe_execution_no_apply_floor_peer_once_v2(stream, &mut self.peer));
        self.peer_settlement = Some(self.peer.settle_after_root_post_once_v1());
        if !matches!(self.peer_result, Some(Ok(())))
            || !matches!(self.peer_settlement, Some(Ok(())))
        {
            self.first.get_or_insert(First::Peer);
        }
        positive(&self.peer_result)?;
        positive(&self.peer_settlement)?;
        let saved = floor.floor_data_v2()?;
        let fields = saved.fields();
        let expected_phase = origin.require_floor_v2(writers, pins, floor)?;
        self.end[0] = Some(
            writers
                .serving_policy_interval_journal_v1(RootCurrentWriterRoleV1::Authority)?
                .held_native_receiving_metadata_v1()
                .0,
        );
        positive(&self.end[0])?;
        self.captured = Some(self.files.capture_once());
        if !matches!(self.captured, Some(Ok(()))) {
            self.first.get_or_insert(First::Capture);
        }
        positive(&self.captured)?;
        self.manifest = Some((|| {
            let manifest = BrokerSessionManifestV1::decode(
                self.files.bytes().ok_or(JournalError::ProtectedBoundary)?,
            )?;
            manifest.require_all_active()?;
            if manifest.protocol() != BrokerSessionProtocolV1::Host
                || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
                || manifest.node_id() != fields.host_lease.fields().accepted_source.fields().node
                || manifest.node_id()
                    != flight
                        .execution_no_apply_stage_receiving_v2()?
                        .enrolled_node_v1()?
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(manifest)
        })());
        if !matches!(self.manifest, Some(Ok(_))) {
            self.first.get_or_insert(First::Manifest);
        }
        let manifest = positive(&self.manifest)?;
        let data = readonly.execution_no_apply_current_data_v2()?;
        let native = readonly.session_v1()?;
        let controller = flight
            .execution_no_apply_stage_receiving_v2()?
            .controller_identity_v1();
        self.roster.observe_once(&native, manifest, controller)?;
        let key = match fields.host_lease.fields().scope {
            HostNoApplyLeaseScopeV2::Active => canonical_protocol_key_v1(BrokerSessionProtocolV1::Host),
            HostNoApplyLeaseScopeV2::RecoveryCleanup => aos_sandbox_protocol::authenticated_session::
                stored_history::canonical_host_no_apply_cleanup_key_v1(),
        };
        let bytes = native
            .state
            .get(&(
                crate::journal::RecordNamespace::BrokerSessionTraffic,
                key.clone(),
            ))
            .ok_or(JournalError::ProtectedBoundary)?;
        StoredBrokerSessionHistoryV1::decode_retaining(&key, bytes, &mut self.stored)?;
        let stored = self
            .stored
            .stored()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.verified = Some(verify_execution_host_history_retaining_v2(
            manifest,
            stored,
            manifest.node_id(),
            sample.host_boot_id(),
            &mut self.checkpoint,
            &mut self.traffic,
        ));
        let (_, transcript, history, traffic) = positive(&self.verified)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let head = history.head()?;
        if head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || traffic.has_outstanding_request()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let last = history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(JournalError::ProtectedBoundary)?;
        self.method.observe_host_held_no_apply_ack_once_v2(
            history.records(),
            last,
            checkpoint,
            transcript,
        )?;
        let request = self
            .method
            .request_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let command = request
            .host_held_no_apply_settlement_data_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let HostNoApplyHeldCommandV2::Acknowledge { comparison, ack } = command.command_v2() else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        require_same_immutable_lease(fields.host_lease, *comparison)?;
        if request.session_binding() != fields.host_lease.fields().current_session
            || request.deadline_boottime_nanoseconds() > fields.host_lease.fields().native_cutoff
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let received = self
            .method
            .outcome_v2()
            .ok_or(JournalError::ProtectedBoundary)?
            .recorded_host_held_no_apply_lease_v2()?
            .ok_or(JournalError::ProtectedBoundary)?;
        require_same_immutable_lease(fields.host_lease, received)?;
        if received.fields().native_boot != sample.host_boot_id()
            || received.fields().observed_clock > trust.next_sample_v2()?.boottime_nanoseconds()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let prepare = ClosedCreateFailurePrepareDataV2::from_root_floor_data_v2(saved)?;
        let cut = data.global_controller_cut_data_v2()?;
        if ack.phase != expected_phase
            || ack.operation != prepare.operation
            || ack.root_floor != prepare.root_floor
            || ack.root_sequence != prepare.root_sequence
            || ack.controller_prepare != prepare.digest()
            || ack.settled_cas != prepare.settled_cas_digest()
            || ack.controller_cut != cut
            || cut.names() != fields.controller_cut.names()
            || fields
                .controller_cut
                .next()
                .checked_add(expected_phase.controller_advance_data_v2())
                != Some(cut.next())
            || cut.end() <= fields.controller_cut.end()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.plan = Some(data.plan_rows_data_v2(
            prepare.identity.marker,
            prepare.identity.terminal_archive,
            prepare.identity.signed_terminal,
            prepare.wall_seconds,
        ));
        let plan = positive(&self.plan)?;
        if !plan.settled_data_v2()
            || plan.prepared_data_v2() != Some(prepare)
            || plan.row_digests_data_v2() != (fields.predecessor_rows, fields.successor_rows)
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.ack = Some(*ack);
        Ok(())
    }

    fn post(&mut self, writers: &RootCreateStorageCurrentWritersV1, index: usize) {
        if self.posted[index].is_some() {
            return;
        }
        if let Some(Ok(post)) = &mut self.posts[index] {
            self.posted[index] = Some(
                writers
                    .owed_policy_interval_journal_v1(RootCurrentWriterRoleV1::ALL[index % 2])
                    .and_then(|journal| journal.finish_root_names_post_once_v1(post)),
            );
            if !matches!(self.posted[index], Some(Ok(()))) {
                self.first.get_or_insert(if index < 2 {
                    First::Before
                } else {
                    First::RootPost
                });
            }
        }
    }

    fn finish_posts(
        &mut self,
        writers: &RootCreateStorageCurrentWritersV1,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
    ) {
        if self.captured.is_some() {
            self.credential_post = Some(self.files.recheck_once());
            if !matches!(self.credential_post, Some(Ok(()))) {
                self.first.get_or_insert(First::CredentialPost);
            }
        }
        readonly.finish_posts_once_v1();
        self.reader_post = Some(readonly.require_complete_v1());
        self.external_readers = readonly.failure().is_some();
        if !matches!(self.reader_post, Some(Ok(()))) {
            self.first.get_or_insert(First::ReaderPost);
        }
        for index in 0..4 {
            self.post(writers, index);
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Arm | First::Before | First::RootPost => {
                self.posts.iter().enumerate().find_map(|(index, post)| {
                    post.as_ref()
                        .and_then(|value| match value {
                            Ok(original) => original.failure(),
                            Err(cause) => Some(cause as _),
                        })
                        .or_else(|| {
                            self.posted[index]
                                .as_ref()?
                                .as_ref()
                                .err()
                                .map(|cause| cause as _)
                        })
                })
            }
            First::Peer => self
                .peer
                .failure()
                .or_else(|| {
                    self.peer_result
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.peer_settlement
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Capture => self.files.capture_failure().map(|cause| cause as _),
            First::Manifest => self
                .manifest
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            First::CredentialPost => self.files.failure().map(|cause| cause as _),
            First::ReaderPost if self.external_readers => None,
            First::ReaderPost => self
                .reader_post
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Body if self.external_trust => None,
            First::Body => self
                .before
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| self.end[0].as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.roster.failure())
                .or_else(|| self.stored.failure().map(|cause| cause as _))
                .or_else(|| self.checkpoint.failure().map(|cause| cause as _))
                .or_else(|| self.traffic.cause())
                .or_else(|| {
                    self.verified
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref())
                })
                .or_else(|| self.method.failure_v2())
                .or_else(|| self.plan.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| {
                    self.body
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref())
                }),
            First::Final if self.external_trust => None,
            First::Final => self.end[1]
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.final_binding
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref())
                }),
        }
    }
}

fn require_policy_live(
    policy: &RootExecutionNoApplyPolicyOriginalV2,
    wall: i64,
) -> Result<(), JournalError> {
    let sources = policy
        .verified_v1()
        .ok_or(JournalError::ProtectedBoundary)?;
    if wall >= sources.0.head().expires_at().min(sources.1.expires_at()) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn require_same_immutable_lease(
    original: CurrentHostNoApplyLeaseDataV2,
    observed: CurrentHostNoApplyLeaseDataV2,
) -> Result<(), JournalError> {
    let mut expected = original.fields();
    let actual = observed.fields();
    // Only current signed request/response observation coordinates advance.
    // Native scope/D/boot, original Session, cuts, head, epoch, challenge and
    // every terminal/source field remain identical through actual ACK.
    expected.signed_current_request = actual.signed_current_request;
    expected.current_request = actual.current_request;
    expected.observed_clock = actual.observed_clock;
    if expected != actual || actual.observed_clock < original.fields().observed_clock {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
