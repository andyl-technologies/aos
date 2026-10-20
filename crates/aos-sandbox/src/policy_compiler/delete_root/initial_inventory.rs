//! Compares the real initial six prefixes before acknowledging fresh queries.
//!
//! Historical full preimages supply only the original planning correlation.
//! Every Session, Cache, Source predecessor, Controller, namespace and public
//! trust comparison comes from this same Root's own paid native owners. The
//! whole flight remains pending after ACK; no floor or lifecycle guard lifts.

use super::*;
use crate::controller_resource_reservation::{
    ResourceReservationErrorV1, RootContinuationDemandV1, RootDeleteChunkPostsV1,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    delete_root::{
        initial_inventory::{
            DELETE_ROOT_INITIAL_ACK_BYTES_V3, DELETE_ROOT_INITIAL_FRAME_BYTES_V3,
            DeleteRootInitialAckDataV3, DeleteRootInitialDataErrorV3, DeleteRootInitialFrameDataV3,
        },
        inventory_cuts::{initial_six_cut_data_v2, transfer_planning_cut_data_v2},
        transport::DeleteRootChallengeDataV2,
    },
    lifecycle_model::LifecycleModelError,
};

#[derive(Debug, thiserror::Error)]
enum ComparisonError {
    #[error(transparent)]
    Original(#[from] RootDeleteErrorV1),
    #[error(transparent)]
    Initial(#[from] DeleteRootInitialDataErrorV3),
    #[error(transparent)]
    Wire(#[from] DeleteRootWireErrorV2),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Planning(
        #[from]
        aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningDataErrorV3,
    ),
    #[error(transparent)]
    Lifecycle(#[from] LifecycleModelError),
    #[error(transparent)]
    Cache(#[from] super::cache::RowsError),
    #[error("Root's independently observed complete initial six preimages changed")]
    Changed,
}

#[derive(Clone, Copy)]
enum InitialFirst {
    Permit,
    Arm,
    BeforeClock,
    Before,
    Frame,
    Decode,
    Transfer,
    Compare,
    After,
    ComparisonClock,
    Ack,
    Send,
    SendClock,
    Reentry,
}

pub(super) struct RootDeleteInitialInventoryOriginalV2 {
    permit: Option<Result<(), NormalRootStartupErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; 3],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 3],
    horizons: [Option<Result<(), JournalError>>; 3],
    message: body::message::RootDeleteMessageReceivingV2,
    received: Option<Result<(), RootDeleteErrorV1>>,
    frame: Option<Result<DeleteRootInitialFrameDataV3, DeleteRootInitialDataErrorV3>>,
    transfer_after: Option<Result<(), RootDeleteErrorV1>>,
    compared: Option<Result<[u8; 32], ComparisonError>>,
    ack: Option<Result<[u8; DELETE_ROOT_INITIAL_ACK_BYTES_V3], ComparisonError>>,
    response: [u8; DELETE_ROOT_INITIAL_ACK_BYTES_V3],
    sent: FixedDeadlineStreamIoV1<DELETE_ROOT_INITIAL_ACK_BYTES_V3>,
    send: Option<Result<(), RootDeleteErrorV1>>,
    entered: bool,
    complete: bool,
    first: Option<InitialFirst>,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteInitialInventoryOriginalV2 {
    fn default() -> Self {
        Self {
            permit: None,
            posts: Default::default(),
            arm: None,
            before: None,
            after: None,
            clocks: std::array::from_fn(|_| Default::default()),
            samples: std::array::from_fn(|_| None),
            horizons: std::array::from_fn(|_| None),
            message: Default::default(),
            received: None,
            frame: None,
            transfer_after: None,
            compared: None,
            ack: None,
            response: [0; DELETE_ROOT_INITIAL_ACK_BYTES_V3],
            sent: Default::default(),
            send: None,
            entered: false,
            complete: false,
            first: None,
            closed: None,
        }
    }
}

impl RootDeleteInitialInventoryOriginalV2 {
    pub(super) fn completed_ack_bytes_v2(&self)
        -> Result<&[u8; DELETE_ROOT_INITIAL_ACK_BYTES_V3], RootDeleteErrorV1>
    {
        if !self.complete || self.first.is_some() || self.failure().is_some()
            || !matches!(self.send, Some(Ok(()))) || !self.sent.completed_exact()
        {
            return Err(RootDeleteErrorV1::Original);
        }
        Ok(&self.response)
    }

    fn demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(clock.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(DELETE_ROOT_INITIAL_FRAME_BYTES_V3.checked_mul(3)?))
            .and_then(|bytes| {
                bytes.checked_add(aos_sandbox_protocol::domain_ledger::delete_root::
                initial_inventory::initial_comparison_decoding_bytes_v3()?)
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let network = DELETE_ROOT_INITIAL_FRAME_BYTES_V3
            .checked_add(DELETE_ROOT_INITIAL_ACK_BYTES_V3)
            .and_then(|bytes| bytes.checked_add(1))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let files = RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(3)
            .and_then(|files| u64::try_from(files).ok())
            .ok_or_else(invalid)?;
        RootDeleteChunkPostsV1::fixed_demand_v1()?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::OpenFiles, files)
                    .with(D::NetworkBytes, network)
                    .with(D::OutputBytes, DELETE_ROOT_INITIAL_ACK_BYTES_V3 as u64),
            )
            .map_err(Into::into)
    }

    fn sample_once_v2(&mut self, index: usize, challenge: &RootDeleteChallengeOriginalsV1) {
        self.samples[index] = Some(self.clocks[index].observe_once(None));
        self.horizons[index] = Some((|| {
            let sample = *positive(&self.samples[index])?;
            challenge.require_current_clock_v1(sample)?;
            if index > 0 {
                positive(&self.samples[index - 1])?
                    .validate_later_sample(sample)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
            }
            Ok(())
        })());
    }

    pub(super) fn observe_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream,
        open: DeleteRootOpenDataV2,
        challenge: &RootDeleteChallengeOriginalsV1,
        batch: &body::RootDeleteBatchReceivingV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        floor: &RootDeleteFloorOriginalV1,
        transfer: &mut RootDeleteTransferNamespaceOriginalV1,
        cache: &cache::RootDeleteCacheCurrentOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(InitialFirst::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.permit = Some((|| {
            let mut receiving = flight
                .delete_cache_stage_receiving_v2(challenge, controller, source, floor, transfer)?;
            receiving.admit_delete_initial_inventory_once_v2(
                RootContinuationDemandV1::from_demand_v1(
                    Self::demand_v2().map_err(|_| NormalRootStartupErrorV1::Service)?,
                ),
            )
        })());
        if !matches!(self.permit, Some(Ok(()))) {
            self.first = Some(InitialFirst::Permit);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(InitialFirst::Arm);
        } else {
            self.sample_once_v2(0, challenge);
            self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
            if !matches!(self.horizons[0], Some(Ok(()))) {
                self.first = Some(InitialFirst::BeforeClock);
            }
            if !matches!(self.before, Some(Ok(()))) {
                self.first.get_or_insert(InitialFirst::Before);
            }
            if self.first.is_none() {
                self.received = Some(self.message.receive_continuation_once_v2(
                    flight,
                    original,
                    challenge,
                    DELETE_ROOT_INITIAL_FRAME_BYTES_V3,
                ));
                if !matches!(self.received, Some(Ok(()))) {
                    self.first = Some(InitialFirst::Frame);
                } else {
                    self.frame = Some((|| {
                        Ok(DeleteRootInitialFrameDataV3::decode_v3(
                            self.message
                                .bytes_v2()
                                .map_err(|_| DeleteRootWireErrorV2::Association)?,
                        )?)
                    })());
                    if !matches!(self.frame, Some(Ok(_))) {
                        self.first = Some(InitialFirst::Decode);
                    }
                }
            }
        }
        // The namespace/bootstrap and active Ownership afters were armed by
        // their actual earlier entry. A hostile frame cannot suppress them.
        self.transfer_after = Some(transfer.finish_if_owed_v1(flight, challenge));
        if !matches!(self.transfer_after, Some(Ok(()))) {
            self.first.get_or_insert(InitialFirst::Transfer);
        }
        if self.first.is_none() {
            self.compared = Some((|| {
                Self::compare_v2(
                    *positive(&self.frame)?,
                    open,
                    challenge,
                    batch,
                    controller,
                    source,
                    transfer,
                    cache,
                )
            })());
            if !matches!(self.compared, Some(Ok(_))) {
                self.first = Some(InitialFirst::Compare);
            }
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(InitialFirst::After);
        }
        self.sample_once_v2(1, challenge);
        if !matches!(self.horizons[1], Some(Ok(()))) {
            self.first.get_or_insert(InitialFirst::ComparisonClock);
        }
        if self.first.is_none() {
            self.ack = Some((|| {
                let held = DeleteRootChallengeDataV2::decode_v2(
                    challenge
                        .challenge_bytes_v1()
                        .map_err(|_| RootDeleteErrorV1::Original)?,
                )?;
                let frame = *positive(&self.frame)?;
                let ack = DeleteRootInitialAckDataV3 {
                    open: open.digest_v2()?,
                    challenge: held.digest_v2()?,
                    frame: frame.digest_v3()?,
                    initial_six: *positive(&self.compared)?,
                    clock: *positive(&self.samples[1])?,
                };
                ack.require_exchange_v3(frame, open, held, *positive(&self.compared)?)?;
                Ok(ack.encode_v3()?)
            })());
            if let Some(Ok(bytes)) = self.ack.as_ref() {
                self.response = *bytes;
                self.send = Some((|| {
                    let cutoff = challenge
                        .source_query_v1()
                        .map_err(|_| RootDeleteErrorV1::Original)?
                        .cutoff;
                    self.sent
                        .run_once(
                            original,
                            &mut self.response,
                            cutoff,
                            DeadlineStreamDirectionV1::Write,
                        )
                        .map_err(|_| RootDeleteErrorV1::Opening)
                })());
                if !matches!(self.send, Some(Ok(()))) {
                    self.first = Some(InitialFirst::Send);
                }
            } else {
                self.first = Some(InitialFirst::Ack);
            }
        }
        // This third original is independently owed even after send refusal.
        self.sample_once_v2(2, challenge);
        if !matches!(self.horizons[2], Some(Ok(()))) {
            self.first.get_or_insert(InitialFirst::SendClock);
        }
        if self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.complete = true;
        Ok(())
    }

    fn compare_v2(
        frame: DeleteRootInitialFrameDataV3,
        open: DeleteRootOpenDataV2,
        challenge: &RootDeleteChallengeOriginalsV1,
        batch: &body::RootDeleteBatchReceivingV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        transfer: &RootDeleteTransferNamespaceOriginalV1,
        cache: &cache::RootDeleteCacheCurrentOriginalV2,
    ) -> Result<[u8; 32], ComparisonError> {
        let held = DeleteRootChallengeDataV2::decode_v2(
            challenge
                .challenge_bytes_v1()
                .map_err(|_| RootDeleteErrorV1::Original)?,
        )?;
        frame.require_exchange_v3(open, held)?;
        let (planning, planning_challenge, observation) = frame.planning_v3()?;
        let (claim, next, end, caller, input) = controller.verified_planning_predecessor_v2()?;
        let predecessor = source.verified_source_predecessor_v2()?;
        let (namespace, ownership, trust) = transfer.completed_namespace_comparison_v2()?;
        if planning.funding != claim
            || planning.controller_next != next
            || planning.controller_end != end
            || planning.caller != caller
            || planning.input != input
            || (planning.source_next, planning.source_end) != predecessor.prior_native
            || batch.source_predecessor_next_sequence_v2()? != predecessor.prior_native.0
            || observation.native.namespace != namespace
            || observation.native.ownership != ownership
            || observation.trust != trust
        {
            return Err(ComparisonError::Changed);
        }
        let sessions = controller.initial_session_cuts_v2()?;
        let cache = cache.initial_cut_v2(frame.cache_nonce, frame.cache_cutoff)?;
        let transfer = transfer_planning_cut_data_v2(
            &planning,
            &planning_challenge,
            &frame.planning_observation,
        )?;
        let cuts = [
            sessions[0],
            sessions[1],
            sessions[2],
            sessions[3],
            cache,
            transfer,
        ];
        if cuts != batch.inventory_cuts_v2()? {
            return Err(ComparisonError::Changed);
        }
        let aggregate = initial_six_cut_data_v2(&cuts)?;
        if aggregate != batch.named_cuts_v2()?.initial_six {
            return Err(ComparisonError::Changed);
        }
        Ok(aggregate)
    }

    pub(super) fn transfer_failure_selected(&self) -> bool {
        matches!(self.first, Some(InitialFirst::Transfer))
    }

    pub(super) fn funding_failed(&self) -> bool {
        matches!(self.first, Some(InitialFirst::Permit))
            || matches!(self.first, Some(InitialFirst::Arm)) && self.posts.funding_failed_v1()
            || matches!(self.first, Some(InitialFirst::Frame))
                && self.message.financial_failure_is_selected_v1()
    }

    pub(super) fn property_failure_view(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            InitialFirst::Before | InitialFirst::After => {
                self.posts.property_failure_view_v1(self.failure()?)
            }
            InitialFirst::Frame => self.message.property_failure_view_v1(),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match self.first? {
            InitialFirst::Permit => cause(&self.permit),
            InitialFirst::Arm => self.posts.before_failure_v1().or_else(|| cause(&self.arm)),
            InitialFirst::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.before)),
            InitialFirst::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            InitialFirst::BeforeClock => self.clocks[0]
                .failure()
                .or_else(|| cause(&self.samples[0]))
                .or_else(|| cause(&self.horizons[0])),
            InitialFirst::ComparisonClock => self.clocks[1]
                .failure()
                .or_else(|| cause(&self.samples[1]))
                .or_else(|| cause(&self.horizons[1])),
            InitialFirst::SendClock => self.clocks[2]
                .failure()
                .or_else(|| cause(&self.samples[2]))
                .or_else(|| cause(&self.horizons[2])),
            InitialFirst::Frame => self.message.failure().or_else(|| cause(&self.received)),
            InitialFirst::Decode => cause(&self.frame),
            InitialFirst::Transfer => cause(&self.transfer_after),
            InitialFirst::Compare => cause(&self.compared),
            InitialFirst::Ack => cause(&self.ack),
            InitialFirst::Send => self.sent.failure().or_else(|| cause(&self.send)),
            InitialFirst::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
