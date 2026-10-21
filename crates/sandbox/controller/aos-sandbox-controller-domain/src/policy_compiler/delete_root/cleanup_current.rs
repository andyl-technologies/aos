//! Joins real completed9 and fresh Host3 through the existing native/history engines.
//!
//! Eight independent actual prepay frontiers retain both fixed captures, native
//! prefixes, full method models, framed receipts and final same-D comparison.
//! This owner creates no Root62 signature or physical Mount acknowledgement.

use aos_sandbox_policy::native::{RootFinalityReadOriginalV1 as Target, RootFinalityReadKindV1 as Kind};
use crate::journal::historical_observation::root_readonly_error_v1 as project_read;
use super::body::message::RootDeleteMessageReceivingV2;
use super::controller::sessions::model::{
    DeleteCleanupTerminalPurposeV4, DeleteSessionModelsOriginalV2,
};
use super::*;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::journal::JournalError;
use crate::policy_compiler::{
    RetainedKernelPairedClockAttemptV1,

};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::{
    domain_ledger::delete_root::cleanup_current::{
        DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4, DeleteRootCleanupCurrentDataV4,
        DeleteRootCleanupCurrentErrorV4, cleanup_approval_commitment_data_v4,
    },
    host_stopped_namespace::HostStoppedNamespaceDataV4,
    host_recovered_namespace::{HostRecoveredNamespaceDataV7, HostRecoveryStopPhaseDataV7},
};

type Cause = Box<dyn StdError>;
const CLOCKS: usize = 10;

/// Names actual reader and comparison frontiers on the same retained Delete original.
#[derive(Clone, Copy)]
pub(crate) enum RootDeleteCleanupCurrentPhaseV4 {
    NetworkFixed,
    NetworkNative,
    NetworkModels,
    HostFixed,
    HostNative,
    HostModels,
    Frame,
    Comparison,
}

impl RootDeleteCleanupCurrentPhaseV4 {
    pub(crate) const fn index_v4(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy)]
enum First {
    Geometry(usize),
    Funding(usize),
    Arm,
    Before,
    Clock(usize),
    Frame,
    Decode,
    Native(usize),
    Models(usize),
    Comparison,
    Primary,
    After,
    Reentry,
}

pub(crate) struct RootDeleteCleanupCurrentOriginalV4 {
    phase: Option<RootDeleteCleanupCurrentPhaseV4>,
    demands: [Option<Result<ResourceVector, Cause>>; 8],
    permits: [Option<Result<(), ResourceReservationErrorV1>>; 8],
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; CLOCKS],
    samples: [Option<
        Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>,
    >; CLOCKS],
    times: [Option<Result<(), Cause>>; CLOCKS],
    latest: Option<RawPairedClockSample>,
    frame: RootDeleteMessageReceivingV2,
    received: Option<Result<(), RootDeleteErrorV1>>,
    decoded: Option<Result<DeleteRootCleanupCurrentDataV4, DeleteRootCleanupCurrentErrorV4>>,
    readers: [Target; 2],
    native: [Option<Result<(), JournalError>>; 2],
    models: [DeleteSessionModelsOriginalV2; 2],
    model_results: [Option<Result<(), JournalError>>; 2],
    completed_stop: Option<crate::lifecycle::completed_stop::CompletedStopHistoryOriginalV1>,
    compared: Option<Result<HostStoppedNamespaceDataV4, Cause>>,
    primary: Option<Result<(), Cause>>,
    network_completed: bool,
    entered: bool,
    native_entered: bool,
    complete: bool,
    first: Option<First>,
}

impl Default for RootDeleteCleanupCurrentOriginalV4 {
    fn default() -> Self {
        Self {
            phase: None,
            demands: std::array::from_fn(|_| None),
            permits: std::array::from_fn(|_| None),
            posts: Default::default(),
            arm: None,
            before: None,
            after: None,
            clocks: std::array::from_fn(|_| Default::default()),
            samples: std::array::from_fn(|_| None),
            times: std::array::from_fn(|_| None),
            latest: None,
            frame: Default::default(),
            received: None,
            decoded: None,
            readers: [
                Target::new(Kind::NetworkSession),
                Target::new(Kind::HostSession),
            ],
            native: std::array::from_fn(|_| None),
            models: std::array::from_fn(|_| Default::default()),
            model_results: std::array::from_fn(|_| None),
            completed_stop: None,
            compared: None,
            primary: None,
            network_completed: false,
            entered: false,
            native_entered: false,
            complete: false,
            first: None,
        }
    }
}

pub(super) struct CleanupCurrentInputsV4<'held> {
    pub(super) challenge: &'held RootDeleteChallengeOriginalsV1,
    pub(super) current: &'held RootDeletePreparationCurrentOriginalV3,
    pub(super) network: &'held apply_issuer::RootDeleteApplyIssuerOriginalV3,
    pub(super) controller: &'held RootDeleteControllerCurrentOriginalV1,
    pub(super) graph: &'held RootDeleteGraphComparisonOriginalV2,
}

impl RootDeleteCleanupCurrentOriginalV4 {
    pub(crate) fn admission_phase_v4(
        &self,
    ) -> Result<RootDeleteCleanupCurrentPhaseV4, ResourceReservationErrorV1> {
        let phase = self.phase.ok_or(ResourceReservationErrorV1::Conflict)?;
        let index = phase.index_v4();
        if !self.entered
            || !self.network_completed
            || self.first.is_some()
            || self.permits[index].is_some()
            || !matches!(self.demands[index], Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(phase)
    }

    pub(crate) fn receiving_demand_v4(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.demands[self.admission_phase_v4()?.index_v4()]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn observe_once_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        inputs: CleanupCurrentInputsV4<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.primary = Some(self.observe_inner_v4(flight, original, &inputs));
        if self.primary.as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(First::Primary);
        }
        // Retain the primary before every independently owed native/Root/clock
        // post. A failure in one file does not suppress the other's reached debt.
        for (index, reader) in self.readers.iter_mut().enumerate() {
            reader.finish_post_once();
            if reader.post_failure().is_some() {
                self.first.get_or_insert(First::Native(index));
            }
        }
        if self.native_entered {
            self.after = Some(self.posts.observe_after_once_v1(flight, inputs.challenge));
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
            self.sample_once_v4(9, &inputs);
        }
        self.complete = self.first.is_none()
            && matches!(self.primary, Some(Ok(())))
            && matches!(self.compared, Some(Ok(_)))
            && self.failure().is_none();
        self.require_completed_v4()
    }

    fn observe_inner_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        inputs: &CleanupCurrentInputsV4<'_>,
    ) -> Result<(), Cause> {
        use RootDeleteCleanupCurrentPhaseV4 as P;
        inputs.current.require_completed_v3()?;
        inputs.network.cleanup_network_approval_v4()?;
        self.network_completed = true;
        self.admit_v4(flight, P::Frame, Self::fixed_demand_v4())?;
        self.native_entered = true;
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(inputs.challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(First::Arm);
        }
        self.sample_once_v4(0, inputs);
        self.before = Some(self.posts.observe_before_once_v1(flight, inputs.challenge));
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(First::Before);
        }
        self.require_primary_v4()?;
        self.received = Some(self.frame.receive_continuation_once_v2(
            flight,
            original,
            inputs.challenge,
            DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4,
        ));
        if !matches!(self.received, Some(Ok(()))) {
            self.first = Some(First::Frame);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.decoded = Some(DeleteRootCleanupCurrentDataV4::decode_v4(
            self.frame.bytes_v2()?,
        ));
        if !matches!(self.decoded, Some(Ok(_))) {
            self.first = Some(First::Decode);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.sample_once_v4(1, inputs);
        self.require_primary_v4()?;
        let frame = *positive(&self.decoded)?;
        let current = inputs.current.completed_frame_data_v3()?;
        let approved = inputs.network.cleanup_network_approval_v4()?;
        if frame.challenge != current.challenge
            || frame.opening != current.opening
            || frame.opening != approved.open
            || frame.approved9 != cleanup_approval_commitment_data_v4(approved)?
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        let query = inputs.challenge.source_query_v1()?;
        let uid = flight
            .delete_cut_startup_v1()?
            .native_startup_original_v1()
            .fields()
            .profile
            .identities[0];
        for index in 0..2 {
            let (fixed, native, models, purpose, demand) = if index == 0 {
                (
                    P::NetworkFixed,
                    P::NetworkNative,
                    P::NetworkModels,
                    DeleteCleanupTerminalPurposeV4::NetworkDestroy9,
                    super::reader::fixed_demand_v1(Kind::NetworkSession),
                )
            } else {
                (
                    P::HostFixed,
                    P::HostNative,
                    P::HostModels,
                    DeleteCleanupTerminalPurposeV4::HostInventory3,
                    super::reader::fixed_demand_v1(Kind::HostSession),
                )
            };
            self.admit_v4(flight, fixed, demand.map_err(|cause| cause.into()))?;
            self.sample_once_v4(2 + index * 3, inputs);
            self.require_primary_v4()?;
            let proof = if index == 0 {
                frame.network
            } else {
                frame.host
            };
            self.readers[index].construct_reader_once_v1().map_err(project_read)?;
            self.readers[index].prepare_delete_cleanup_session_observation_v4(proof.native).map_err(project_read)?;
            self.readers[index].capture_once(uid);
            if self.readers[index].require_captured_v1().map_err(project_read).is_err() {
                self.first = Some(First::Native(index));
                return Err(RootDeleteErrorV1::Opening.into());
            }
            let demand = self.readers[index]
                .replay_demand_v1().map_err(project_read)
                .map_err(|cause| cause.into());
            self.admit_v4(flight, native, demand)?;
            self.sample_once_v4(3 + index * 3, inputs);
            self.require_primary_v4()?;
            self.readers[index].replay_once();
            self.readers[index].finish_post_once();
            self.native[index] = Some(
                self.readers[index]
                    .delete_preparation_native_data_v3().map_err(project_read)
                    .map(|_| ()),
            );
            if !matches!(self.native[index], Some(Ok(()))) {
                self.first = Some(First::Native(index));
                return Err(RootDeleteErrorV1::Opening.into());
            }
            let bytes = usize::try_from(self.readers[index].terminal_native_v1().map_err(project_read)?.end)
                .map_err(|_| JournalError::JournalTooLarge)?;
            let demand = DeleteSessionModelsOriginalV2::cleanup_packet_demand_v4(bytes, purpose)
                .map_err(|cause| cause.into());
            self.admit_v4(flight, models, demand)?;
            self.sample_once_v4(4 + index * 3, inputs);
            self.require_primary_v4()?;
            let manifests = inputs.controller.broker_manifests_v2()?;
            self.model_results[index] = Some(self.models[index].observe_cleanup_packets_once_v4(
                self.readers[index].terminal_native_v1().map_err(project_read)?,
                self.readers[index].completed_delete_cleanup_history_rows_v4().map_err(project_read)?,
                if index == 0 { manifests.3 } else { manifests.0 },
                query.cutoff,
                query.boot,
                purpose,
            ));
            if !matches!(self.model_results[index], Some(Ok(()))) {
                self.first = Some(First::Models(index));
                return Err(RootDeleteErrorV1::Opening.into());
            }
        }
        let history = if self.models[1].completed_host_inventory_v4()?.cleanup_lineages_v1.is_empty() {
            ResourceVector::ZERO
        } else {
            let (source_rows, _) = inputs.current.completed_stop_source_data_v5()?;
            crate::lifecycle::completed_stop::CompletedStopHistoryOriginalV1::receiving_demand_v1(
                inputs.current.current_assignment_rows_v3()?, source_rows,
            ).ok_or(JournalError::JournalTooLarge)?
        };
        self.admit_v4(flight, P::Comparison, Ok(history))?;
        self.sample_once_v4(8, inputs);
        self.require_primary_v4()?;
        self.compared = Some(self.compare_once_v4(inputs));
        if !matches!(self.compared, Some(Ok(_))) {
            self.first = Some(First::Comparison);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        Ok(())
    }

    fn compare_once_v4(
        &mut self,
        inputs: &CleanupCurrentInputsV4<'_>,
    ) -> Result<HostStoppedNamespaceDataV4, Cause> {
        let frame = *positive(&self.decoded)?;
        let query = inputs.challenge.source_query_v1()?;
        inputs.current.require_completed_v3()?;
        let network = self.models[0].completed_cleanup_outcome_v4()?;
        inputs
            .network
            .compare_cleanup_network_outcome_v4(network, frame.network, query.cutoff)?;
        let host = self.models[1].completed_cleanup_outcome_v4()?;
        inputs
            .controller
            .require_cleanup_host_successor_v4(host, frame.host.native)?;
        let nonce = host.request().request_id();
        // The genuine Host query may narrow D further to its signed9 horizon
        // or existing five-second local query bound. Never widen that narrower
        // deadline, and require this actual Root observation inside both cuts.
        require_host_deadline_v4(
            host.request().deadline_boottime_nanoseconds(),
            query.cutoff,
            self.latest.ok_or(JournalError::ProtectedBoundary)?.boottime_nanoseconds(),
        )?;
        if host.request().authorization().is_some()
            || host.request().signed_request_digest() != frame.host.request
            || blake3::hash(host.canonical_packet()).as_bytes() != &frame.host.outcome
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        let inventory = self.models[1].completed_host_inventory_v4()?;
        use aos_sandbox_protocol::host_stopped_namespace::HostStoppedInventoryDataV1;
        let evidence = HostStoppedInventoryDataV1::from_inventory_v1(inventory)?
            .ok_or(JournalError::StaleAuthoritySnapshot)?;
        if let HostStoppedInventoryDataV1::Cleanup(lineage) = &evidence {
            let (source_rows, source) = inputs.current.completed_stop_source_data_v5()?;
            let _ = source_rows;
            let controller = inputs.current.current_assignment_rows_v3()?;
            self.completed_stop = Some(crate::lifecycle::completed_stop::CompletedStopHistoryOriginalV1::new());
            let history = self.completed_stop.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            history.observe_once_v1(controller, source)?;
            history.require_same_v1(controller, source)?;
            let completed = history.require_scope_v1(evidence.historical_scope_v1())?;
            completed.require_cleanup_v1(lineage)?;
            if completed.project_v1().as_bytes() != &query.project {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
        }
        let scope = cleanup_stopped_scope_v4(inventory, nonce, query.boot,
            inputs.network.cleanup_network_approval_v4()?.clock.boottime_nanoseconds(),
            self.latest.ok_or(JournalError::ProtectedBoundary)?.boottime_nanoseconds(),
            host.request().deadline_boottime_nanoseconds())?;
        let graph = inputs.graph.selection_data_v2()?;
        if !inventory.runtimes.is_empty()
            || scope.fence_v4().sandbox_id() != graph.root.as_bytes()
            || nonce == scope.launch_v4().0
            || nonce == scope.stop_v4().0
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        Ok(scope)
    }

    fn fixed_demand_v4() -> Result<ResourceVector, Cause> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4.checked_mul(3)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?
                        .checked_mul(CLOCKS)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<sha2::Sha256>()))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<blake3::Hasher>()))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<aos_sandbox_protocol::host_stopped_namespace::HostStoppedInventoryDataV1>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(CLOCKS))
            .and_then(|names| u64::try_from(names).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(RootDeleteChunkPostsV1::fixed_demand_v1()?
            .checked_add(crate::policy_compiler::root_subject_chunk::RootSubjectChunkReceivingV1::delete_receiving_demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::MetadataEntries, names)
                .with(D::OpenFiles, 1 + CLOCKS as u64 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
                .with(D::NetworkBytes, (DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4 + 1) as u64)
                .with(D::OutputBytes, (DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4 + 1) as u64))?)
    }

    fn admit_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        phase: RootDeleteCleanupCurrentPhaseV4,
        demand: Result<ResourceVector, Cause>,
    ) -> Result<(), Cause> {
        let index = phase.index_v4();
        self.phase = Some(phase);
        self.demands[index] = Some(demand);
        if !matches!(self.demands[index], Some(Ok(_))) {
            self.first.get_or_insert(First::Geometry(index));
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.permits[index] = Some(flight.admit_delete_cleanup_current_once_v4(self));
        if !matches!(self.permits[index], Some(Ok(()))) {
            self.first.get_or_insert(First::Funding(index));
            return Err(RootDeleteErrorV1::Opening.into());
        }
        Ok(())
    }

    fn sample_once_v4(&mut self, index: usize, inputs: &CleanupCurrentInputsV4<'_>) {
        self.samples[index] = Some(self.clocks[index].observe_once(None));
        self.times[index] = Some((|| {
            let sample = *positive(&self.samples[index])?;
            if let Some(prior) = self.latest {
                prior.validate_later_sample(sample)?;
            }
            self.latest = Some(sample);
            inputs.challenge.require_current_clock_v1(sample)?;
            inputs.network.require_cleanup_sample_v4(sample)?;
            Ok(())
        })());
        if !matches!(self.times[index], Some(Ok(()))) {
            self.first.get_or_insert(First::Clock(index));
        }
    }

    fn require_primary_v4(&self) -> Result<(), Cause> {
        if self.first.is_some() {
            Err(RootDeleteErrorV1::Opening.into())
        } else {
            Ok(())
        }
    }

    pub(crate) fn require_completed_v4(&self) -> Result<(), RootDeleteErrorV1> {
        if self.complete
            && self.first.is_none()
            && matches!(self.compared, Some(Ok(_)))
            && self.failure().is_none()
        {
            Ok(())
        } else {
            Err(RootDeleteErrorV1::Original)
        }
    }

    pub(super) fn stopped_scope_v4(&self) -> Result<HostStoppedNamespaceDataV4, RootDeleteErrorV1> {
        self.require_completed_v4()?;
        positive(&self.compared)
            .copied()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn completed_frame_v4(
        &self,
    ) -> Result<DeleteRootCleanupCurrentDataV4, RootDeleteErrorV1> {
        self.require_completed_v4()?;
        positive(&self.decoded)
            .copied()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn completed_clock_v4(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.require_completed_v4()?;
        positive(&self.samples[9])
            .copied()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(crate) fn property_failure_view_v4(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(First::Arm | First::Before | First::After)) {
            self.posts.property_failure_view_v1(self.failure()?)
        } else {
            None
        }
    }

    pub(crate) fn funding_failed_v4(&self) -> bool {
        matches!(self.first, Some(First::Funding(_)))
            || matches!(self.first, Some(First::Arm | First::Before | First::After))
                && self.posts.funding_failed_v1()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match self.first? {
            First::Geometry(index) => self.demands[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            First::Funding(index) => cause(&self.permits[index]),
            First::Arm | First::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.arm))
                .or_else(|| cause(&self.before)),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::Clock(index) => self.clocks[index]
                .failure()
                .or_else(|| cause(&self.samples[index]))
                .or_else(|| {
                    self.times[index]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref())
                }),
            First::Frame => self.frame.failure().or_else(|| cause(&self.received)),
            First::Decode => cause(&self.decoded),
            First::Native(index) => self.readers[index]
                .failure()
                .or_else(|| cause(&self.native[index])),
            First::Models(index) => self.models[index]
                .failure()
                .or_else(|| cause(&self.model_results[index])),
            First::Comparison => self.completed_stop.as_ref().and_then(|history| history.failure())
                .or_else(|| self.compared.as_ref()?.as_ref().err().map(|cause| cause.as_ref())),
            First::Primary => self
                .primary
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            First::Reentry => None,
        }
    }
}

fn cleanup_stopped_scope_v4(
    inventory: &aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse,
    request_id: [u8; 16],
    boot: [u8; 16],
    not_before: u64,
    observed: u64,
    deadline: u64,
) -> Result<HostStoppedNamespaceDataV4, Cause> {
    if !inventory.runtimes.is_empty() || !inventory.native_absence_v5.is_empty() {
        return Err(JournalError::StaleAuthoritySnapshot.into());
    }
    let evidence = aos_sandbox_protocol::host_stopped_namespace::HostStoppedInventoryDataV1::from_inventory_v1(inventory)?
        .ok_or(JournalError::StaleAuthoritySnapshot)?;
    Ok(*evidence.require_completed_v1(request_id, boot, not_before, observed, deadline)?)
}

fn require_host_deadline_v4(
    deadline: u64,
    original_cutoff: u64,
    observed: u64,
) -> Result<(), JournalError> {
    if deadline > original_cutoff || observed >= deadline {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[test]
    fn narrower_actual_query_deadline_never_renews_original_root_horizon() {
        assert!(require_host_deadline_v4(8, 10, 7).is_ok());
        assert!(require_host_deadline_v4(10, 10, 9).is_ok());
        assert!(require_host_deadline_v4(11, 10, 7).is_err());
        assert!(require_host_deadline_v4(8, 10, 8).is_err());
        assert!(require_host_deadline_v4(8, 10, 9).is_err());
        assert!(require_host_deadline_v4(0, 10, 0).is_err());
    }

    #[test]
    fn canonical_recovery_projection_keeps_issued_and_cross_boot_permission_closed() {
        use aos_sandbox_protocol::host_inventory_absence::HostInventoryAbsenceDataV5;
        use aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse;

        // These are passive canonical DATA fixtures only. They construct no
        // authenticated Session, completed reader, Stop or Root permission.
        let mut old = [1; 328];
        old[..8].copy_from_slice(b"AOSHNS04");
        old[56..64].copy_from_slice(&1_u64.to_le_bytes());
        old[64..72].copy_from_slice(&1_u64.to_le_bytes());
        old[136..168].copy_from_slice(&aos_sandbox_protocol::semantics::host::runtime_handle_v1(
            &[1; 16], 1, &[1; 32]));
        old[248..264].copy_from_slice(&[2; 16]);
        old[296..328].copy_from_slice(&[3; 32]);
        let scope = HostStoppedNamespaceDataV4::decode_v4(&old).unwrap();
        let observation = HostInventoryAbsenceDataV5::from_data_v5(
            [4; 16], [1; 16], [5; 16], 10, 12).unwrap();
        let inventory = |phase, observation| InventoryRuntimeResponse {
            recovered_namespaces_v7: vec![HostRecoveredNamespaceDataV7::from_data_v7(
                scope, observation, phase).encode_v7().to_vec()],
            ..Default::default()
        };
        let complete = inventory(HostRecoveryStopPhaseDataV7::Complete, observation);
        assert_eq!(cleanup_stopped_scope_v4(&complete, [4; 16], [1; 16], 9, 13, 14)
            .unwrap().encode_v4(), old);
        for phase in [HostRecoveryStopPhaseDataV7::PayloadPending,
            HostRecoveryStopPhaseDataV7::GuardianPending,
            HostRecoveryStopPhaseDataV7::PayloadAwaitingAbsence,
            HostRecoveryStopPhaseDataV7::GuardianAwaitingAbsence] {
            assert!(cleanup_stopped_scope_v4(&inventory(phase, observation),
                [4; 16], [1; 16], 9, 13, 14).is_err());
        }
        let cross_boot = HostInventoryAbsenceDataV5::from_data_v5(
            [4; 16], [6; 16], [5; 16], 10, 12).unwrap();
        assert!(cleanup_stopped_scope_v4(&inventory(HostRecoveryStopPhaseDataV7::Complete, cross_boot),
            [4; 16], [6; 16], 9, 13, 14).is_err());
        assert!(cleanup_stopped_scope_v4(&complete, [7; 16], [1; 16], 9, 13, 14).is_err());
        assert!(cleanup_stopped_scope_v4(&complete, [4; 16], [1; 16], 11, 13, 14).is_err());
        assert!(cleanup_stopped_scope_v4(&complete, [4; 16], [1; 16], 9, 11, 14).is_err());
        assert!(cleanup_stopped_scope_v4(&complete, [4; 16], [1; 16], 9, 13, 12).is_err());
        let mut mixed = complete;
        mixed.stopped_namespaces_v4.push(old.to_vec());
        assert!(cleanup_stopped_scope_v4(&mixed, [4; 16], [1; 16], 9, 13, 14).is_err());
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
