//! Issues fresh cleanup-read acquisition from the actual Root/native interval.
//!
//! The original drives the existing nine paid C/Host/Source readers, current
//! Recover capability/four-row checker and full Host/Root history classifiers.
//! It signs only after its native posts complete. The same Root connection,
//! writers, primary policy interval and this whole prefix remain held through
//! fresh43, floor, Controller settlement and ACK; acquisition appends no78 row.

use super::{
    current_host_lease::host_history::HostHistoryOriginalV2,
    floor::{loan::Crossing, signer::RootFloorSignerV2},
};
use crate::{
    Journal,
    controller_resource_reservation::RootContinuationDemandV1,
    journal::{JournalError, root_construction::RootJournalServingIdentityV1},
    normal_root::{
        NormalRootStartupErrorV1, RootControllerPeerCurrentSampleV1, RootPolicyAcceptedFlightV1,
    },
    policy_compiler::{
        continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
        create_storage_current::pins::RootCurrentPinsStateV1,
        provisioning_current::{
            RootContinuationClockGateV1,
            create_finality::authorization::{
                CreateFinalityAuthorizationOriginalV1 as Authorization,
                RootRecoveryAdmissionReferenceDataV2,
            },
            finality_readonly::RootCreateFinalityReadonlyOriginalV1,
        },
        root_current_writers::RootCreateStorageCurrentWritersV1,
    },
};
use aos_sandbox_broker::systemd_credentials::RootCurrentHostManifestCustodyV2;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1,
    manifest::{BrokerSessionManifestAudienceV1, BrokerSessionManifestV1},
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use aos_sandbox_protocol::{
    host_execution_availability::observation::HostExecutionAvailabilityObservationV2,
    host_execution_no_apply::{
        BeforeArgumentNoApplySourceDataV2, ClosedBeforeArgumentNoApplyRecordV2,
        recovery_acquisition::RootNoApplyRecoveryAcquisitionFieldsV2,
    },
};
use std::{error::Error, mem::size_of};

mod classification;

type Cause = Box<dyn Error>;

/// Supplies only untrusted references; no phase or current Root/C cut is input.
#[derive(Clone, Copy)]
pub(crate) struct RootNoApplyAcquisitionSelectionDataV2 {
    pub(crate) admission: RootRecoveryAdmissionReferenceDataV2,
    pub(crate) controller_nonce: [u8; 32],
    pub(crate) controller_first: RawPairedClockSample,
    pub(crate) cleanup_cutoff: u64,
    pub(crate) host_session: [u8; 32],
    pub(crate) historical_availability: HostExecutionAvailabilityObservationV2,
    pub(crate) accepted_source: BeforeArgumentNoApplySourceDataV2,
    pub(crate) marker: ClosedBeforeArgumentNoApplyRecordV2,
    pub(crate) terminal_archive: [u8; 32],
    pub(crate) signed_terminal: [u8; 32],
}

/// Retains all reached native originals and exact refusal causes until last Drop.
pub(crate) struct RootExecutionNoApplyAcquisitionOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    reentry: Option<JournalError>,
}

struct Native {
    phase: Phase,
    selection: RootNoApplyAcquisitionSelectionDataV2,
    files: RootCurrentHostManifestCustodyV2,
    capture: Option<Result<(), ()>>,
    manifest: Option<Result<BrokerSessionManifestV1, Cause>>,
    credential_post: Option<Result<(), ()>>,
    before: Option<Result<[RootJournalServingIdentityV1; 2], JournalError>>,
    crossing: Crossing,
    arm: Option<Result<(), JournalError>>,
    authorization: Authorization,
    host: HostHistoryOriginalV2,
    classified: Option<Result<classification::Classified, Cause>>,
    models_geometry: Option<Result<ResourceVector, Cause>>,
    models_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    body: Option<Result<(), Cause>>,
    reader_post: Option<Result<(), JournalError>>,
    crossing_result: Option<Result<(), JournalError>>,
    signer: RootFloorSignerV2,
    signer_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    signer_result: Option<Result<(), JournalError>>,
    controller_cut: Option<aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2>,
    readonly: RootCreateFinalityReadonlyOriginalV1,
    connection: [aos_sandbox_linux::unix_stream::UnixStreamOriginalCurrentnessV1; 3],
    connection_result: [Option<Result<(), aos_sandbox_linux::Error>>; 3],
}

#[derive(Clone, Copy)]
enum Phase {
    Connection,
    Clock,
    RootNames,
    Arm,
    Capture,
    Readonly,
    Manifest,
    ModelsGeometry,
    ModelsFunding,
    Authorization,
    HostHistory,
    Classification,
}

impl RootExecutionNoApplyAcquisitionOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            native: None,
            reentry: None,
        }
    }

    /// Runs the actual acquisition programme on the existing Execution Root R.
    ///
    /// The caller retains its paid clock, primary policy interval, actual pair
    /// and connection through the later floor/ACK programme. Independent owed
    /// posts drain even if a reader, model, fee or signing frontier refuses.
    pub(crate) fn observe_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        clock: &mut RootContinuationClockGateV1,
        selection: RootNoApplyAcquisitionSelectionDataV2,
    ) -> Result<(), JournalError> {
        if self.geometry.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.geometry = Some(trust_demand(writers));
        let demand = positive(&self.geometry).copied()?;
        self.funding = Some(
            flight
                .execution_no_apply_stage_receiving_v2()
                .and_then(|mut stage| stage.admit_execution_no_apply_acquisition_trust_once_v2(
                    RootContinuationDemandV1::from_demand_v1(demand))),
        );
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native = Some(Box::new(Native {
            phase: Phase::Connection,
            selection,
            files: RootCurrentHostManifestCustodyV2::new(),
            capture: None,
            manifest: None,
            credential_post: None,
            before: None,
            crossing: Crossing::new(),
            arm: None,
            authorization: Authorization::new_execution_no_apply_v2(),
            host: HostHistoryOriginalV2::new(),
            classified: None,
            models_geometry: None,
            models_funding: None,
            body: None,
            reader_post: None,
            crossing_result: None,
            signer: RootFloorSignerV2::new(),
            signer_funding: None,
            signer_result: None,
            controller_cut: None,
            readonly: RootCreateFinalityReadonlyOriginalV1::new(),
            connection: std::array::from_fn(|_| Default::default()),
            connection_result: std::array::from_fn(|_| None),
        }));
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        native.connection_result[0] =
            Some(original.revalidate_original_retaining_v1(&mut native.connection[0]));
        native.body = Some((|| {
            positive(&native.connection_result[0])?;
            native.observe_body(flight, writers, pins, policy, clock)
        })());
        native.finish_native_posts(writers);
        if matches!(native.body, Some(Ok(()))) && native.failure_before_signing().is_none() {
            native.crossing_result = Some((|| {
                let (authority, policy_journal) = held_pair(writers)?;
                let models = CompletedAcquisitionModelsLoanV2 {
                    authority,
                    policy_journal,
                    pins,
                    policy,
                    readonly: &native.readonly,
                    authorization: &native.authorization,
                    host: &native.host,
                    before: positive(&native.before)?,
                    classified: positive(&native.classified)?,
                    selection: native.selection,
                    controller_cut: native
                        .controller_cut
                        .ok_or(JournalError::ProtectedBoundary)?,
                };
                native
                    .crossing
                    .complete_acquisition_read_once_v2(flight, original, writers, &models, clock)
            })());
            if matches!(native.crossing_result, Some(Ok(()))) {
                native.signer_result = Some((|| {
                    let demand = RootFloorSignerV2::receiving_demand_v2()?;
                    native.signer_funding = Some(
                        flight.execution_no_apply_stage_receiving_v2().and_then(|mut stage|
                            stage.admit_execution_no_apply_acquisition_sign_once_v2(
                                RootContinuationDemandV1::from_demand_v1(demand))));
                    positive(&native.signer_funding)?;
                    native.sign_completed(writers, pins, policy, clock)
                })());
            }
        }
        native.signer.finish_posts_once_v2();
        self.acquisition_bytes_v2().map(|_| ())
    }

    pub(crate) fn acquisition_bytes_v2(&self) -> Result<&[u8], JournalError> {
        if self.reentry.is_some() || !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if native.failure_before_signing().is_some()
            || !matches!(native.crossing_result, Some(Ok(())))
            || !matches!(native.signer_funding, Some(Ok(())))
            || !matches!(native.signer_result, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        native.crossing.require_complete()?;
        native.signer.packet_bytes_v2()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.geometry)
            .or_else(|| error(&self.funding))
            .or_else(|| self.native.as_deref()?.failure())
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    /// Identifies an actual earliest borrowed clock refusal for the owner view.
    /// The caller retains the clock original and borrows its concrete cause.
    pub(crate) fn external_clock_is_first_v2(&self, clock: &RootContinuationClockGateV1) -> bool {
        // Pure horizon or capability comparisons also use the Clock frontier.
        // Only an actual retained native/clock-comparison cause selects the
        // caller's clock owner; otherwise the retained body cause stays first.
        if clock.failure().is_none() {
            return false;
        }
        let Some(native) = self.native.as_deref() else {
            return false;
        };
        if matches!(native.body, Some(Err(_))) {
            return matches!(native.phase, Phase::Clock)
                || matches!(native.phase, Phase::Readonly) && native.readonly.failure().is_none();
        }
        native.crossing.external_trust_failed() || native.signer.external_trust_is_first_v2()
    }

    /// Rejoins the retained original before the genuine future floor frontier.
    pub(crate) fn require_floor_connection_once_v2(
        &mut self,
        original: &RetainedUnixStream,
    ) -> Result<(), JournalError> {
        self.require_connection_once_v2(original, 1)
    }

    /// Rejoins the same original before the genuine final ACK reader frontier.
    pub(crate) fn require_ack_connection_once_v2(
        &mut self,
        original: &RetainedUnixStream,
    ) -> Result<(), JournalError> {
        self.require_connection_once_v2(original, 2)
    }

    /// Rechecks the actual unchanged Root/C originals before the new floor.
    pub(super) fn require_floor_inputs_v2(
        &self,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        models: &super::RootExecutionNoApplyModelsOriginalV2,
        host: &super::RootExecutionNoApplyHostLeaseOriginalV2,
    ) -> Result<(), JournalError> {
        self.acquisition_bytes_v2()?;
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        positive(&native.connection_result[1])?;
        writers.require_serving_identities_v1(positive(&native.before)?)?;
        let (authority, policy_journal) = held_pair(writers)?;
        policy.require_prepared_floor_pair_v2(authority, policy_journal, pins)?;
        readonly.require_complete_v1()?;
        let cut = readonly
            .execution_no_apply_current_data_v2()?
            .global_controller_cut_data_v2()?;
        let old = positive(&native.classified)?;
        let plan = models.plan_data_v2()?;
        if Some(cut) != native.controller_cut
            || plan.operation_data_v2() != old.plan.operation_data_v2()
            || plan.prepared_data_v2() != old.plan.prepared_data_v2()
            || plan.settled_data_v2() != old.plan.settled_data_v2()
            || plan.row_digests_data_v2() != old.plan.row_digests_data_v2()
            || plan.wall_seconds_data_v2() != old.plan.wall_seconds_data_v2()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let lease = host.lease_data_v2()?.fields();
        let selection = native.selection;
        if lease.scope != aos_sandbox_protocol::host_execution_no_apply::current_lease::HostNoApplyLeaseScopeV2::RecoveryCleanup
            || lease.native_boot != selection.controller_first.host_boot_id()
            || lease.current_session != selection.host_session
            || lease.native_first_clock < selection.controller_first.boottime_nanoseconds()
            || lease.native_cutoff > selection.cleanup_cutoff
            || lease.availability != selection.historical_availability
            || lease.accepted_source != selection.accepted_source
            || lease.marker != aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(selection.marker)
            || lease.terminal_archive_head != selection.terminal_archive
            || lease.signed_terminal_outcome != selection.signed_terminal
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    /// Lends the actual verified cap bound only after native acquisition signing.
    pub(crate) fn acquisition_wall_expiry_v2(&self) -> Result<i64, JournalError> {
        self.acquisition_bytes_v2()?;
        let native = self.native.as_deref().ok_or(JournalError::ProtectedBoundary)?;
        Ok(native.selection.admission.wall_expiry)
    }

    /// Lends that bound to Trust only after the same-stream floor crossing.
    pub(super) fn recover_wall_expiry_v2(&self) -> Result<i64, JournalError> {
        let expires = self.acquisition_wall_expiry_v2()?;
        let native = self.native.as_deref().ok_or(JournalError::ProtectedBoundary)?;
        positive(&native.connection_result[1])?;
        Ok(expires)
    }

    /// Keeps every later cleanup frontier inside the same current cap horizon.
    pub(super) fn require_cleanup_sample_v2(
        &self,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        sample: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.acquisition_bytes_v2()?;
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        require_live(native.selection, policy, sample)
    }

    /// Checks the proposed new record against this genuine acquisition history.
    pub(super) fn require_proposed_floor_v2(
        &self,
        floor: aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyFloorRecordDataV2,
    ) -> Result<(), JournalError> {
        use aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionDataV2;
        self.acquisition_bytes_v2()?;
        let packet =
            RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(self.acquisition_bytes_v2()?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        let acquired = packet.fields_v2();
        let fields = floor.fields();
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let classified = positive(&native.classified)?;
        let (revision, predecessor) = acquired.history.map_or(Ok((1, [0; 32])), |history| {
            history
                .current_revision
                .checked_add(1)
                .map(|revision| (revision, history.current_floor))
                .ok_or(JournalError::SequenceExhausted)
        })?;
        if acquired.root_instance.is_some_and(|instance| fields.root_instance != instance)
            || fields.authority_next != acquired.authority_next
            || fields.controller_cut != acquired.controller_cut
            || fields.policy_commitment != acquired.policy_commitment
            || fields.revision != revision || fields.predecessor_floor != predecessor
            || fields.operation != acquired.accepted_source.fields().create_operation
            || fields.host_lease.fields().scope != aos_sandbox_protocol::host_execution_no_apply::current_lease::HostNoApplyLeaseScopeV2::RecoveryCleanup
            || fields.host_lease.fields().availability != acquired.historical_availability
            || fields.host_lease.fields().accepted_source != acquired.accepted_source
            || fields.host_lease.fields().marker != aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(acquired.marker)
            || fields.host_lease.fields().terminal_archive_head != acquired.terminal_archive
            || fields.host_lease.fields().signed_terminal_outcome != acquired.signed_terminal
            || fields.host_lease.fields().current_session != acquired.host_session
            || fields.host_lease.fields().native_boot != acquired.host_boot
            || fields.host_lease.fields().native_first_clock < acquired.first_clock
            || fields.host_lease.fields().native_cutoff > acquired.cutoff
            || (fields.predecessor_rows, fields.successor_rows) != classified.plan.row_digests_data_v2()
            || fields.terminal_wall_seconds != classified.plan.wall_seconds_data_v2()
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    /// Derives the final phase only from this issuer and the actual new floor.
    pub(super) fn acknowledgement_phase_v2(
        &self, writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        floor: &super::RootExecutionNoApplyFloorOriginalV2,
    ) -> Result<aos_sandbox_protocol::host_execution_no_apply::closed_controller::ControllerCreateFailureAckPhaseV2, JournalError>{
        use aos_sandbox_protocol::host_execution_no_apply::{
            closed_controller::ControllerCreateFailureAckPhaseV2 as Ack,
            recovery_acquisition::RootNoApplyRecoveryPhaseV2 as Phase,
        };
        self.acquisition_bytes_v2()?;
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        positive(&native.connection_result[2])?;
        floor.require_policy_successor_v2(writers, pins, positive(&native.before)?)?;
        self.require_proposed_floor_v2(floor.floor_data_v2()?)?;
        Ok(match positive(&native.classified)?.phase {
            Phase::BeforeFloor => Ack::RecoveryBeforeFloor,
            Phase::FloorAnchored => Ack::RecoveryFloorAnchored,
            Phase::Prepared => Ack::RecoveryPrepared,
            Phase::Settled => Ack::RecoverySettled,
        })
    }

    fn require_connection_once_v2(
        &mut self,
        original: &RetainedUnixStream,
        index: usize,
    ) -> Result<(), JournalError> {
        self.acquisition_bytes_v2()?;
        let native = self
            .native
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        if native.connection_result[index].is_some()
            || index == 2 && !matches!(native.connection_result[1], Some(Ok(())))
        {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        native.connection_result[index] =
            Some(original.revalidate_original_retaining_v1(&mut native.connection[index]));
        positive(&native.connection_result[index])?;
        if !native.connection[0].matches_observed_endpoint_data_v2(&native.connection[index]) {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl Native {
    fn observe_body(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), Cause> {
        self.phase = Phase::Clock;
        clock.require_opening_cutoff_data_v2(
            self.selection.controller_first,
            self.selection.cleanup_cutoff,
        )?;
        require_live(self.selection, policy, clock.check_next_once_v1()?)?;
        self.phase = Phase::RootNames;
        self.before = Some(writers.serving_identities_v1());
        let (authority, policy_journal) = held_pair(writers)?;
        policy.require_prepared_floor_pair_v2(authority, policy_journal, pins)?;
        self.phase = Phase::Arm;
        self.arm = Some(self.crossing.arm_once(authority, policy_journal));
        positive(&self.arm)?;
        self.phase = Phase::Capture;
        self.capture = Some(self.files.capture_once());
        positive(&self.capture)?;
        self.phase = Phase::Readonly;
        let (node, partition, controller) = {
            let mut stage = flight.execution_no_apply_stage_receiving_v2()?;
            let coordinates = (
                stage.enrolled_node_v1()?,
                stage.controller_baseline_partition_v1()?,
                stage.controller_identity_v1(),
            );
            self.readonly
                .observe_execution_no_apply_acquisition_once_v2(&mut stage, clock)?;
            coordinates
        };
        self.readonly.require_execution_no_apply_acquisition_v2()?;
        self.phase = Phase::Manifest;
        self.manifest = Some((|| {
            let manifest = BrokerSessionManifestV1::decode(
                self.files.bytes().ok_or(JournalError::ProtectedBoundary)?,
            )?;
            manifest.require_all_active()?;
            if manifest.protocol() != BrokerSessionProtocolV1::Host
                || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
                || manifest.node_id() != node
                || self.selection.accepted_source.fields().node != node
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(manifest)
        })());
        positive(&self.manifest)?;
        self.phase = Phase::ModelsGeometry;
        self.models_geometry = Some((|| {
            let c = self.readonly.controller_v1()?;
            let authorization =
                Authorization::receiving_recovery_demand_v2(c, self.selection.admission)?;
            let rows =
                crate::reconciler::ClosedCreateFailurePlanDataV2::receiving_demand_data_v2(c)?;
            let native = self.readonly.session_v1()?;
            let prefix = usize::try_from(native.end).map_err(|_| JournalError::JournalTooLarge)?;
            let entries = native
                .state
                .keys()
                .filter(|(namespace, _)| *namespace == crate::RecordNamespace::BrokerSessionTraffic)
                .count();
            let group = aos_sandbox_protocol::host_execution_no_apply::closed_host_terminal_archive_receiving_bytes_v2(prefix)
                .and_then(|n| u64::try_from(n).ok()).ok_or(JournalError::JournalTooLarge)?;
            let history_carriers = size_of::<aos_sandbox_protocol::host_execution_no_apply::root_attestation::RootExecutionNoApplyAttestationDataV2<'_>>()
                .checked_mul(2)
                .and_then(|n| n.checked_add(size_of::<aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyFloorRecordDataV2>().checked_mul(3)?))
                .and_then(|n| n.checked_add(aos_sandbox_protocol::host_execution_no_apply::closed_controller::CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2.checked_mul(3)?))
                .and_then(|n| u64::try_from(n).ok()).ok_or(JournalError::JournalTooLarge)?;
            Ok(authorization
                .checked_add(rows)?
                .checked_add(HostHistoryOriginalV2::receiving_demand(prefix, entries)?)?
                .checked_add(
                    ResourceVector::ZERO.with(
                        D::MemoryBytes,
                        group
                            .checked_add(history_carriers)
                            .ok_or(JournalError::JournalTooLarge)?,
                    ),
                )?)
        })());
        let demand = *positive(&self.models_geometry)?;
        self.phase = Phase::Clock;
        require_live(self.selection, policy, clock.check_next_once_v1()?)?;
        self.phase = Phase::ModelsFunding;
        self.models_funding = Some(
            flight
                .execution_no_apply_stage_receiving_v2()?
                .admit_execution_no_apply_acquisition_models_once_v2(
                    RootContinuationDemandV1::from_demand_v1(demand),
                ),
        );
        positive(&self.models_funding)?;
        self.phase = Phase::Authorization;
        self.authorization.observe_execution_no_apply_once_v2(
            self.readonly.controller_v1()?,
            self.selection.admission,
            node,
            partition,
        )?;
        self.phase = Phase::HostHistory;
        self.host.observe_once(
            &self.readonly.session_v1()?,
            positive(&self.manifest)?,
            controller,
        )?;
        self.phase = Phase::Clock;
        let sample = clock.check_next_once_v1()?;
        require_live(self.selection, policy, sample)?;
        self.phase = Phase::Classification;
        self.classified = Some(classification::classify(
            authority,
            self.readonly.controller_v1()?,
            &self.authorization,
            &self.host,
            &self.selection,
            sample,
        ));
        positive(&self.classified)?;
        self.controller_cut = Some(
            self.readonly
                .execution_no_apply_current_data_v2()?
                .global_controller_cut_data_v2()?,
        );
        Ok(())
    }

    fn finish_native_posts(&mut self, writers: &RootCreateStorageCurrentWritersV1) {
        self.readonly.finish_posts_once_v1();
        self.reader_post = Some(self.readonly.require_complete_v1());
        if self.capture.is_some() && self.credential_post.is_none() {
            self.credential_post = Some(self.files.recheck_once());
        }
        self.crossing.finish_after_once(writers);
    }

    fn sign_completed(
        &mut self,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &RootExecutionNoApplyPolicyOriginalV2,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.signer.prepare_once_v2()?;
        let (authority, policy_journal) = held_pair(writers)?;
        let models = CompletedAcquisitionModelsLoanV2 {
            authority,
            policy_journal,
            pins,
            policy,
            readonly: &self.readonly,
            authorization: &self.authorization,
            host: &self.host,
            before: positive(&self.before)?,
            classified: positive(&self.classified)?,
            selection: self.selection,
            controller_cut: self.controller_cut.ok_or(JournalError::ProtectedBoundary)?,
        };
        let loan = CompletedAcquisitionSigningLoanV2 {
            models,
            crossing: &self.crossing,
        };
        self.signer.sign_acquisition_once_v2(&loan, clock);
        self.signer.packet_bytes_v2().map(|_| ())
    }

    fn failure_before_signing(&self) -> Option<&(dyn Error + 'static)> {
        if matches!(self.body, Some(Err(_))) {
            let primary: Option<&(dyn Error + 'static)> = match self.phase {
                Phase::Connection => self.connection[0]
                    .failure()
                    .or_else(|| error(&self.connection_result[0])),
                Phase::Clock => None,
                Phase::RootNames => error(&self.before),
                Phase::Arm => self.crossing.failure().or_else(|| error(&self.arm)),
                Phase::Capture => self.files.capture_failure().map(|cause| cause as _),
                Phase::Readonly => self.readonly.failure(),
                Phase::Manifest => boxed_error(&self.manifest),
                Phase::ModelsGeometry => boxed_error(&self.models_geometry),
                Phase::ModelsFunding => error(&self.models_funding),
                Phase::Authorization => self.authorization.failure(),
                Phase::HostHistory => self.host.failure(),
                Phase::Classification => boxed_error(&self.classified),
            };
            return primary.or_else(|| boxed_error(&self.body));
        }
        // Owed after work follows the primary body in this fixed order. A
        // secondary failure cannot replace an earlier financial/model cause.
        if matches!(self.reader_post, Some(Err(_))) {
            return self.readonly.failure().or_else(|| error(&self.reader_post));
        }
        if matches!(self.credential_post, Some(Err(()))) {
            return self.files.post_failure().map(|cause| cause as _);
        }
        self.crossing
            .failure()
            .or_else(|| {
                self.connection
                    .iter()
                    .find_map(|original| original.failure())
            })
            .or_else(|| self.connection_result.iter().find_map(error))
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failure_before_signing()
            .or_else(|| error(&self.crossing_result))
            .or_else(|| error(&self.signer_funding))
            .or_else(|| self.signer.failure())
            .or_else(|| error(&self.signer_result))
    }
}

/// Borrows only the genuine paid reader/model owner; no DATA factory is exposed.
pub(in crate::policy_compiler::execution_no_apply_root) struct CompletedAcquisitionModelsLoanV2<'held> {
    authority: &'held Journal,
    policy_journal: &'held Journal,
    pins: &'held RootCurrentPinsStateV1,
    policy: &'held RootExecutionNoApplyPolicyOriginalV2,
    readonly: &'held RootCreateFinalityReadonlyOriginalV1,
    authorization: &'held Authorization,
    host: &'held HostHistoryOriginalV2,
    before: &'held [RootJournalServingIdentityV1; 2],
    classified: &'held classification::Classified,
    selection: RootNoApplyAcquisitionSelectionDataV2,
    controller_cut: aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2,
}

impl CompletedAcquisitionModelsLoanV2<'_> {
    pub(in crate::policy_compiler::execution_no_apply_root) fn require_current_at_v2(
        &self,
        sample: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        require_live(self.selection, self.policy, sample)?;
        self.require_current_v2()
    }

    fn require_current_v2(&self) -> Result<(), JournalError> {
        self.authority
            .require_root_serving_identity_v1(&self.before[0])?;
        self.policy_journal
            .require_root_serving_identity_v1(&self.before[1])?;
        self.policy.require_prepared_floor_pair_v2(
            self.authority,
            self.policy_journal,
            self.pins,
        )?;
        self.readonly.require_execution_no_apply_acquisition_v2()?;
        self.readonly.require_complete_v1()?;
        if self
            .authorization
            .execution_no_apply_request_v2()?
            .execution_no_apply_target_v1()
            .is_none()
            || self.host.failure().is_some()
            || self
                .readonly
                .execution_no_apply_current_data_v2()?
                .global_controller_cut_data_v2()?
                != self.controller_cut
            || self.authorization.target_v1()? != self.classified.plan.operation_data_v2()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

/// Only this completed private crossing can enter the distinct signing domain.
pub(in crate::policy_compiler::execution_no_apply_root) struct CompletedAcquisitionSigningLoanV2<
    'held,
> {
    models: CompletedAcquisitionModelsLoanV2<'held>,
    crossing: &'held Crossing,
}

impl CompletedAcquisitionSigningLoanV2<'_> {
    pub(in crate::policy_compiler::execution_no_apply_root) fn authority_v2(&self) -> &Journal {
        self.models.authority
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn require_current_at_v2(
        &self,
        sample: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.crossing.require_complete()?;
        self.models.require_current_at_v2(sample)
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn require_current_v2(
        &self,
    ) -> Result<(), JournalError> {
        self.crossing.require_complete()?;
        self.models.require_current_v2()
    }

    pub(in crate::policy_compiler::execution_no_apply_root) fn fields_data_v2(
        &self,
        names: crate::journal::ProtectedJournalNamesV1,
        end: u64,
        public: aos_sandbox_protocol::host_execution_no_apply::root_attestation::RootNoApplyPublicPinDataV2,
    ) -> Result<RootNoApplyRecoveryAcquisitionFieldsV2, JournalError> {
        let model = &self.models;
        let sources = model
            .policy
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        let selection = model.selection;
        Ok(RootNoApplyRecoveryAcquisitionFieldsV2 {
            generation: public.generation_v2(),
            key_commitment: public.key_commitment_v2(),
            authority_names: names,
            authority_next: model.authority.snapshot_sequence(),
            authority_end: end,
            policy_commitment: *sources.0.head().packet_digest().as_bytes(),
            policy_expires_at: sources
                .0
                .head()
                .expires_at()
                .min(sources.1.expires_at())
                .min(selection.admission.wall_expiry),
            controller_cut: model.controller_cut,
            controller_nonce: selection.controller_nonce,
            host_node: selection.accepted_source.fields().node,
            host_boot: selection.controller_first.host_boot_id(),
            host_session: selection.host_session,
            first_clock: selection.controller_first.boottime_nanoseconds(),
            cutoff: selection.cleanup_cutoff,
            historical_availability: selection.historical_availability,
            accepted_source: selection.accepted_source,
            marker: selection.marker,
            terminal_archive: selection.terminal_archive,
            signed_terminal: selection.signed_terminal,
            root_instance: model
                .classified
                .history
                .instance
                .map(|instance| instance.instance()),
            phase: model.classified.phase,
            history: model.classified.recovery,
        })
    }
}

fn require_live(
    selection: RootNoApplyAcquisitionSelectionDataV2,
    policy: &RootExecutionNoApplyPolicyOriginalV2,
    sample: RawPairedClockSample,
) -> Result<(), JournalError> {
    let original = selection.admission.original;
    let first = selection.controller_first;
    let sources = policy
        .verified_v1()
        .ok_or(JournalError::ProtectedBoundary)?;
    if selection.controller_nonce[..16] == [0; 16]
        || selection.host_session == [0; 32]
        || first.host_boot_id() != original.host_boot_id()
        || sample.provenance() != first.provenance()
        || sample.host_boot_id() != original.host_boot_id()
        || first.boottime_nanoseconds() < original.boottime_nanoseconds()
        || first.wall_seconds() < original.wall_seconds()
        || sample.boottime_nanoseconds() < first.boottime_nanoseconds()
        || selection.cleanup_cutoff <= first.boottime_nanoseconds()
        || selection.cleanup_cutoff > selection.admission.cutoff
        || sample.boottime_nanoseconds() >= selection.cleanup_cutoff
        || sample.wall_seconds() >= selection.admission.wall_expiry
        || sample.wall_seconds() >= sources.0.head().expires_at().min(sources.1.expires_at())
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn trust_demand(
    writers: &RootCreateStorageCurrentWritersV1,
) -> Result<ResourceVector, JournalError> {
    let carriers = size_of::<Native>()
        .checked_mul(3)
        .and_then(|n| {
            n.checked_add(size_of::<RootExecutionNoApplyAcquisitionOriginalV2>().checked_mul(3)?)
        })
        .and_then(|n| n.checked_add(size_of::<classification::Classified>().checked_mul(3)?))
        .and_then(|n| {
            n.checked_add(size_of::<CompletedAcquisitionModelsLoanV2<'_>>().checked_mul(2)?)
        })
        .and_then(|n| {
            n.checked_add(size_of::<CompletedAcquisitionSigningLoanV2<'_>>().checked_mul(2)?)
        })
        .and_then(|n| {
            n.checked_add(size_of::<RootNoApplyAcquisitionSelectionDataV2>().checked_mul(2)?)
        })
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    let (stream_bytes, stream_names, stream_files) =
        aos_sandbox_linux::unix_stream::UnixStreamOriginalCurrentnessV1::receiving_demand_v1()
            .ok_or(JournalError::JournalTooLarge)?;
    let one_stream = ResourceVector::ZERO
        .with(
            D::MemoryBytes,
            u64::try_from(stream_bytes).map_err(|_| JournalError::JournalTooLarge)?,
        )
        .with(
            D::MetadataEntries,
            u64::try_from(stream_names).map_err(|_| JournalError::JournalTooLarge)?,
        )
        .with(
            D::OpenFiles,
            u64::try_from(stream_files).map_err(|_| JournalError::JournalTooLarge)?,
        );
    let mut demand = RootCurrentHostManifestCustodyV2::dominant_demand()
        .ok_or(JournalError::JournalTooLarge)?
        .checked_add(RootJournalServingIdentityV1::pair_demand_v1()?)?
        .checked_add(
            RootControllerPeerCurrentSampleV1::demand_v1()
                .map_err(|_| JournalError::ProtectedBoundary)?,
        )?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carriers))?
        .checked_add(one_stream)?
        .checked_add(one_stream)?
        .checked_add(one_stream)?;
    let (authority, policy) = held_pair(writers)?;
    for journal in [authority, policy] {
        let one = journal.root_names_post_demand_v1()?;
        demand = demand.checked_add(one)?.checked_add(one)?;
    }
    Ok(demand)
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn held_pair(
    writers: &RootCreateStorageCurrentWritersV1,
) -> Result<(&Journal, &Journal), JournalError> {
    use crate::policy_compiler::root_current_writers::RootCurrentWriterRoleV1 as Role;
    Ok((
        writers.serving_policy_interval_journal_v1(Role::Authority)?,
        writers.serving_policy_interval_journal_v1(Role::Policy)?,
    ))
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn boxed_error<T>(value: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}
