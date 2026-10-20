//! Retains the post-ACK fresh frame and separate current Controller/Sessions.
//!
//! The same D flight first sends its actual fresh namespace/Ownership preimages
//! and then reads the Controller's six descriptors. Separate current Controller,
//! signed Sessions, Source and Cache readers independently reconstruct every
//! descriptor before the sole complete graph comparison. No decoded frame
//! approves or accepts Delete.

use super::*;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_root::{
    final_inventory::{DELETE_ROOT_FRESH_FRAME_BYTES_V2, DeleteRootFreshFrameDataV2,
        DELETE_ROOT_FRESH_TRANSFER_BYTES_V2, DeleteRootFreshTransferDataV2, initial_ack_commitment_data_v2},
    planning::{DeleteRootPlanningObservationDataV2, DeleteRootPlanningNativeDataV2, DeleteRootPlanningDataErrorV3},
    inventory_cuts::fresh_six_cut_data_v2,
    initial_inventory::DeleteRootInitialAckDataV3,
    transport::DeleteRootChallengeDataV2,
};

#[derive(Debug, thiserror::Error)]
enum ComparisonError {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Wire(#[from] DeleteRootWireErrorV2),
    #[error(transparent)]
    Original(#[from] RootDeleteErrorV1),
    #[error(transparent)]
    Planning(#[from] DeleteRootPlanningDataErrorV3),
    #[error(transparent)]
    Cache(#[from] super::cache::RowsError),
    #[error("fresh Root Controller frame differs from the exact final input")]
    Controller,
}

#[derive(Clone, Copy)]
enum FreshFirst {
    Arm,
    BeforeClock,
    Before,
    Transfer,
    TransferData,
    TransferPermit,
    TransferSend,
    TransferSendClock,
    Frame,
    Decode,
    Controller,
    Association,
    Sessions,
    Source,
    Cache,
    Six,
    After,
    AfterClock,
    Reentry,
}

pub(crate) struct RootDeleteFreshInventoryOriginalV2 {
    transfer: RootDeleteTransferNamespaceOriginalV1,
    transfer_begin: Option<Result<(), RootDeleteErrorV1>>,
    transfer_after: Option<Result<(), RootDeleteErrorV1>>,
    transfer_data: Option<Result<DeleteRootFreshTransferDataV2, ComparisonError>>,
    transfer_bytes: [u8; DELETE_ROOT_FRESH_TRANSFER_BYTES_V2],
    transfer_io: FixedDeadlineStreamIoV1<DELETE_ROOT_FRESH_TRANSFER_BYTES_V2>,
    transfer_permit: Option<Result<(), ResourceReservationErrorV1>>,
    transfer_send: Option<Result<(), RootDeleteErrorV1>>,
    six: Option<Result<[u8; 32], ComparisonError>>,
    message: body::message::RootDeleteMessageReceivingV2,
    received: Option<Result<(), RootDeleteErrorV1>>,
    frame: Option<Result<DeleteRootFreshFrameDataV2, DeleteRootWireErrorV2>>,
    pub(super) controller: RootDeleteControllerCurrentOriginalV1,
    controller_result: Option<Result<(), RootDeleteErrorV1>>,
    association: Option<Result<(), ComparisonError>>,
    sessions_result: Option<Result<(), RootDeleteErrorV1>>,
    pub(super) source: RootDeleteSourceCurrentOriginalV1,
    source_result: Option<Result<(), RootDeleteErrorV1>>,
    pub(super) cache: RootDeleteCacheCurrentOriginalV2,
    cache_result: Option<Result<(), RootDeleteErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; 3],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 3],
    horizons: [Option<Result<(), JournalError>>; 3],
    entered: bool,
    complete: bool,
    first: Option<FreshFirst>,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteFreshInventoryOriginalV2 {
    fn default() -> Self {
        Self {
            transfer: Default::default(), transfer_begin: None, transfer_after: None,
            transfer_data: None, transfer_bytes: [0; DELETE_ROOT_FRESH_TRANSFER_BYTES_V2],
            transfer_io: Default::default(), transfer_permit: None, transfer_send: None, six: None,
            message: Default::default(), received: None, frame: None,
            controller: Default::default(), controller_result: None,
            association: None, sessions_result: None,
            source: Default::default(), source_result: None,
            cache: Default::default(), cache_result: None,
            posts: Default::default(), arm: None, before: None, after: None,
            clocks: std::array::from_fn(|_| Default::default()),
            samples: std::array::from_fn(|_| None),
            horizons: std::array::from_fn(|_| None),
            entered: false, complete: false, first: None, closed: None,
        }
    }
}

impl RootDeleteFreshInventoryOriginalV2 {
    pub(super) fn fixed_receiving_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::Conflict;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(DELETE_ROOT_FRESH_FRAME_BYTES_V2.checked_mul(3)?)
                .and_then(|bytes| bytes.checked_add(DELETE_ROOT_FRESH_TRANSFER_BYTES_V2.checked_mul(3)?)))
            .and_then(|bytes| bytes.checked_add(pair.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(6)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DeleteRootInitialAckDataV3>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let files = u64::try_from(RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
            .map_err(|_| invalid())?.checked_mul(3).ok_or_else(invalid)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|n| n.checked_mul(3)).and_then(|n| u64::try_from(n).ok()).ok_or_else(invalid)?;
        RootDeleteChunkPostsV1::fixed_demand_v1()?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, files)
                .with(D::MetadataEntries, names).with(D::NetworkBytes, DELETE_ROOT_FRESH_FRAME_BYTES_V2 as u64),
        ).map_err(Into::into)
    }

    fn sample_once_v2(&mut self, index: usize, challenge: &RootDeleteChallengeOriginalsV1) {
        self.samples[index] = Some(self.clocks[index].observe_once(None));
        self.horizons[index] = Some((|| {
            let actual = *positive(&self.samples[index])?;
            challenge.require_current_clock_v1(actual)?;
            if index > 0 {
                positive(&self.samples[index - 1])?.validate_later_sample(actual)
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
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        floor: &RootDeleteFloorOriginalV1,
        transfer: &RootDeleteTransferNamespaceOriginalV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(FreshFirst::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(FreshFirst::Arm);
            return Err(RootDeleteErrorV1::Opening);
        }
        let primary = self.observe_inner_v2(flight, original, open, challenge, initial,
            controller, source, floor, transfer);
        // Both independently prearmed posts remain owed after every reached
        // frame, native reader, model, financial or comparison refusal.
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(FreshFirst::After);
        }
        self.sample_once_v2(2, challenge);
        if !matches!(self.horizons[2], Some(Ok(()))) {
            self.first.get_or_insert(FreshFirst::AfterClock);
        }
        if primary.is_err() || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.complete = true;
        Ok(())
    }

    fn observe_inner_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream,
        open: DeleteRootOpenDataV2,
        challenge: &RootDeleteChallengeOriginalsV1,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        floor: &RootDeleteFloorOriginalV1,
        transfer: &RootDeleteTransferNamespaceOriginalV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.sample_once_v2(0, challenge);
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        if !matches!(self.horizons[0], Some(Ok(()))) {
            self.first = Some(FreshFirst::BeforeClock);
        }
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(FreshFirst::Before);
        }
        if self.first.is_some() { return Err(RootDeleteErrorV1::Opening); }
        self.observe_transfer_once_v2(flight, original, open, challenge, initial,
            controller, source, floor)?;
        self.received = Some(self.message.receive_continuation_once_v2(
            flight, original, challenge, DELETE_ROOT_FRESH_FRAME_BYTES_V2,
        ));
        if !matches!(self.received, Some(Ok(()))) {
            self.first = Some(FreshFirst::Frame);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.frame = Some(self.message.bytes_v2().map_err(|_| DeleteRootWireErrorV2::Format)
            .and_then(DeleteRootFreshFrameDataV2::decode_v2));
        if !matches!(self.frame, Some(Ok(_))) {
            self.first = Some(FreshFirst::Decode);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.controller_result = Some(self.controller.observe_fresh_controller_once_v2(
            flight, original, challenge, controller,
        ));
        if !matches!(self.controller_result, Some(Ok(()))) {
            self.first = Some(FreshFirst::Controller);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.association = Some((|| {
            let initial = DeleteRootInitialAckDataV3::decode_v3(initial.completed_ack_bytes_v2()?)?;
            let held = DeleteRootChallengeDataV2::decode_v2(challenge.challenge_bytes_v1()
                .map_err(|_| RootDeleteErrorV1::Original)?)?;
            let fresh_c = self.controller.current_frame_data_v2()?;
            positive(&self.frame)?.require_exchange_v2(open, held, initial, fresh_c)?;
            Ok(())
        })());
        if !matches!(self.association, Some(Ok(()))) {
            self.first = Some(FreshFirst::Association);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.sessions_result = Some(self.controller.observe_fresh_sessions_once_v2(
            flight, challenge, controller,
        ));
        if !matches!(self.sessions_result, Some(Ok(()))) {
            self.first = Some(FreshFirst::Sessions);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.source_result = Some(self.source.observe_final_once_v2(flight, challenge,
            &mut self.controller, controller, source, open));
        if !matches!(self.source_result, Some(Ok(()))) {
            self.first = Some(FreshFirst::Source);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.cache_result = Some(self.cache.observe_once_v2(flight, challenge,
            &self.controller, &self.source, floor, &self.transfer));
        if !matches!(self.cache_result, Some(Ok(()))) {
            self.first = Some(FreshFirst::Cache);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.six = Some((|| {
            let frame = *positive(&self.frame)?;
            let sessions = self.controller.initial_session_cuts_v2()?;
            let cache = self.cache.initial_cut_v2(frame.cache_nonce, frame.cache_cutoff)?;
            let transfer = positive(&self.transfer_data)?.owner_cut_data_v2()?;
            let actual = [sessions[0], sessions[1], sessions[2], sessions[3], cache, transfer];
            if frame.owners != actual { return Err(ComparisonError::Controller); }
            Ok(fresh_six_cut_data_v2(&actual).map_err(DeleteRootWireErrorV2::from)?)
        })());
        if !matches!(self.six, Some(Ok(_))) {
            self.first = Some(FreshFirst::Six);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    fn observe_transfer_once_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, open: DeleteRootOpenDataV2,
        challenge: &RootDeleteChallengeOriginalsV1,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1, floor: &RootDeleteFloorOriginalV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.transfer_begin = Some(self.transfer.begin_final_once_v2(
            flight, challenge, controller, source, floor, initial,
        ));
        if !matches!(self.transfer_begin, Some(Ok(()))) {
            self.first = Some(FreshFirst::Transfer);
        }
        // This always returns the same entered native original, including the
        // independent namespace, Ownership, bootstrap file and Root/C posts.
        self.transfer_after = Some(self.transfer.finish_if_owed_v1(flight, challenge));
        if !matches!(self.transfer_after, Some(Ok(()))) {
            self.first.get_or_insert(FreshFirst::Transfer);
        }
        if self.first.is_none() {
            self.transfer_data = Some((|| {
                let held = DeleteRootChallengeDataV2::decode_v2(challenge.challenge_bytes_v1()
                    .map_err(|_| RootDeleteErrorV1::Original)?)?;
                let ack_bytes = initial.completed_ack_bytes_v2()?;
                let ack = DeleteRootInitialAckDataV3::decode_v3(ack_bytes)?;
                let (namespace, ownership, trust) = self.transfer.completed_namespace_comparison_v2()?;
                let data = DeleteRootFreshTransferDataV2 {
                    open: open.digest_v2()?, challenge: held.digest_v2()?,
                    initial_ack: initial_ack_commitment_data_v2(ack_bytes),
                    observation: DeleteRootPlanningObservationDataV2 {
                        native: DeleteRootPlanningNativeDataV2 {
                            open: open.digest_v2()?, challenge: held.digest_v2()?,
                            clock: self.transfer.completed_clock_v2()?, namespace, ownership,
                        }, trust,
                    },
                };
                data.require_exchange_v2(open, held, ack)?;
                self.transfer_bytes = data.encode_v2()?;
                Ok(data)
            })());
            if !matches!(self.transfer_data, Some(Ok(_))) {
                self.first = Some(FreshFirst::TransferData);
            }
        }
        if self.first.is_none() {
            self.transfer_permit = Some(flight.admit_delete_fresh_transfer_observation_once_v2(self));
            if !matches!(self.transfer_permit, Some(Ok(()))) {
                self.first = Some(FreshFirst::TransferPermit);
            } else {
                self.transfer_send = Some((|| {
                    let cutoff = challenge.current_cutoff_v1().map_err(|_| RootDeleteErrorV1::Original)?;
                    self.transfer_io.run_once(original, &mut self.transfer_bytes, cutoff,
                        DeadlineStreamDirectionV1::Write).map_err(|_| RootDeleteErrorV1::Opening)
                })());
                if !matches!(self.transfer_send, Some(Ok(()))) {
                    self.first = Some(FreshFirst::TransferSend);
                }
            }
        }
        // This independently paid sample remains reached after every entered
        // transfer/send refusal; it never renews the original D deadline.
        self.sample_once_v2(1, challenge);
        if !matches!(self.horizons[1], Some(Ok(()))) {
            self.first.get_or_insert(FreshFirst::TransferSendClock);
        }
        if self.first.is_some() { Err(RootDeleteErrorV1::Opening) } else { Ok(()) }
    }

    pub(crate) fn transfer_observation_receiving_demand_v2(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        if self.first.is_some() || !matches!(self.transfer_data, Some(Ok(_)))
            || self.transfer_permit.is_some() || self.transfer_send.is_some()
            || self.transfer.completed_namespace_comparison_v2().is_err()
        { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(ResourceVector::ZERO
            .with(D::NetworkBytes, DELETE_ROOT_FRESH_TRANSFER_BYTES_V2 as u64)
            .with(D::OutputBytes, DELETE_ROOT_FRESH_TRANSFER_BYTES_V2 as u64))
    }

    pub(super) fn inputs_complete_v2(&self) -> bool {
        self.complete && self.first.is_none() && self.failure().is_none()
            && matches!(self.controller_result, Some(Ok(())))
            && matches!(self.sessions_result, Some(Ok(())))
            && matches!(self.source_result, Some(Ok(())))
            && matches!(self.cache_result, Some(Ok(())))
            && matches!(self.transfer_send, Some(Ok(()))) && matches!(self.six, Some(Ok(_)))
    }

    pub(crate) fn require_inputs_complete_v2(&self) -> Result<(), RootDeleteErrorV1> {
        if self.inputs_complete_v2() { Ok(()) } else { Err(RootDeleteErrorV1::Original) }
    }

    pub(super) fn completed_frame_data_v2(&self) -> Result<DeleteRootFreshFrameDataV2, RootDeleteErrorV1> {
        self.require_inputs_complete_v2()?;
        self.frame.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn funding_failed_v2(&self) -> bool {
        matches!(self.first, Some(FreshFirst::TransferPermit))
            || matches!(self.first, Some(FreshFirst::Transfer)) && self.transfer.financial_failure_is_selected_v1()
            || matches!(self.first, Some(FreshFirst::Arm)) && self.posts.funding_failed_v1()
            || matches!(self.first, Some(FreshFirst::Frame)) && self.message.financial_failure_is_selected_v1()
            || matches!(self.first, Some(FreshFirst::Controller | FreshFirst::Sessions))
                && self.controller.financial_failure_is_selected_v1()
            || matches!(self.first, Some(FreshFirst::Source))
                && self.source.financial_failure_is_selected_v1()
            || matches!(self.first, Some(FreshFirst::Cache)) && self.cache.funding_failed()
    }

    pub(super) fn property_failure_view_v2(&self)
        -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>>
    {
        match self.first? {
            FreshFirst::Arm | FreshFirst::Before | FreshFirst::After =>
                self.posts.property_failure_view_v1(self.failure()?),
            FreshFirst::Frame => self.message.property_failure_view_v1(),
            FreshFirst::Controller | FreshFirst::Sessions => self.controller.property_failure_view_v1(),
            FreshFirst::Source => self.source.property_failure_view_v1(),
            FreshFirst::Cache => self.cache.property_failure_view(),
            FreshFirst::Transfer => self.transfer.property_failure_view_v1(),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match self.first? {
            FreshFirst::Arm | FreshFirst::Before => self.posts.before_failure_v1()
                .or_else(|| cause(&self.arm)).or_else(|| cause(&self.before)),
            FreshFirst::BeforeClock => self.clocks[0].failure()
                .or_else(|| cause(&self.samples[0])).or_else(|| cause(&self.horizons[0])),
            FreshFirst::Transfer => self.transfer.failure()
                .or_else(|| cause(&self.transfer_begin)).or_else(|| cause(&self.transfer_after)),
            FreshFirst::TransferData => cause(&self.transfer_data),
            FreshFirst::TransferPermit => cause(&self.transfer_permit),
            FreshFirst::TransferSend => self.transfer_io.failure().or_else(|| cause(&self.transfer_send)),
            FreshFirst::TransferSendClock => self.clocks[1].failure()
                .or_else(|| cause(&self.samples[1])).or_else(|| cause(&self.horizons[1])),
            FreshFirst::Six => cause(&self.six),
            FreshFirst::Frame => self.message.failure().or_else(|| cause(&self.received)),
            FreshFirst::Decode => cause(&self.frame),
            FreshFirst::Controller | FreshFirst::Sessions => self.controller.failure()
                .or_else(|| cause(&self.controller_result)).or_else(|| cause(&self.sessions_result)),
            FreshFirst::Source => self.source.failure().or_else(|| cause(&self.source_result)),
            FreshFirst::Cache => self.cache.failure().or_else(|| cause(&self.cache_result)),
            FreshFirst::Association => cause(&self.association),
            FreshFirst::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            FreshFirst::AfterClock => self.clocks[2].failure()
                .or_else(|| cause(&self.samples[2])).or_else(|| cause(&self.horizons[2])),
            FreshFirst::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}


impl<'flight, 'listener, 'startup> RootDeletePendingReceivingV1<'flight, 'listener, 'startup> {
    /// Reads the post-ACK input and independently replays current C and Sessions.
    ///
    /// Success completes only this paid prefix. Fresh Source, Cache and the
    /// default-local namespace conjunction remain required before approval.
    ///
    /// # Errors
    /// Retains the entire reached original and every independently owed post.
    pub(crate) fn verify_post_ack_inventory_once_v2(&mut self,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some()
            || self.initial_inventory.completed_ack_bytes_v2().is_err()
            || self.fresh_admission.is_some() || self.fresh_inventory.is_some()
        {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.fresh_admission = Some(flight.admit_delete_fresh_frame_once_v2(self));
        if matches!(self.fresh_admission, Some(Ok(()))) {
            self.fresh_inventory = Some(Box::new(final_inventory::RootDeleteFreshInventoryOriginalV2::default()));
            self.fresh_result = Some((|| {
                let open = self.decoded.as_ref().and_then(|value| value.as_ref().ok())
                    .copied().ok_or(RootDeleteErrorV1::Original)?;
                self.fresh_inventory.as_mut().ok_or(RootDeleteErrorV1::Original)?
                    .observe_once_v2(flight, &mut self.original, open, &self.challenge,
                        &self.initial_inventory, &self.controller, &self.source,
                        &self.floor, &self.transfer_namespace)
            })());
            if !matches!(self.fresh_result, Some(Ok(()))) {
                self.first.get_or_insert(First::FreshController);
            }
        } else {
            self.first.get_or_insert(First::FreshAdmission);
        }
        if self.first.is_none() {
            self.fresh_floor_result = Some((|| {
                let fresh = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
                self.fresh_floor.select_final_read_once_v2(&self.initial_inventory, fresh)?;
                flight.observe_delete_saved_floor_once_v1(&mut self.fresh_floor,
                    &self.challenge, &fresh.controller, &fresh.source)
            })());
            if !matches!(self.fresh_floor_result, Some(Ok(()))) {
                self.first.get_or_insert(First::FreshFloor);
            }
        }
        self.flight = Some(flight);
        if self.first.is_some() {
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        self.verify_complete_graph_once_v2()?;
        self.observe_resource_policy_once_v2(policy)?;
        self.observe_cleanup_inputs_once_v2()?;
        self.select_resource_preparation_once_v2()?;
        self.prepare_resource_plan_once_v2()?;
        self.send_resource_draft_once_v2()?;
        self.receive_resource_signature_once_v2()?;
        self.confirm_resource_policy_once_v2(policy)?;
        self.send_preparatory_approval_once_v3(policy)
    }

    fn observe_resource_policy_once_v2(&mut self,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.resource_policy_result.is_some()
            || self.graph_comparison.require_completed_v2().is_err() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.resource_policy_result = Some(self.resource_policy.observe_once_v2(flight,
            &self.challenge, &self.graph_objects, &self.graph_comparison, policy));
        self.flight = Some(flight);
        if !matches!(self.resource_policy_result, Some(Ok(()))) {
            self.first.get_or_insert(First::ResourcePolicy);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // A verified current policy is an input to the still-required resource
        // issuer. It neither sends final approval nor releases D disposition.
        Ok(())
    }

    fn observe_cleanup_inputs_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.cleanup_inputs_result.is_some()
            || self.resource_policy.verified_sources_v2().is_err() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.cleanup_inputs_result = Some((|| {
            let current = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            current.require_inputs_complete_v2()?;
            self.cleanup_inputs.observe_once_v2(flight, &self.challenge,
                &self.resource_policy, &current.controller, &self.graph_comparison)
        })());
        self.flight = Some(flight);
        if !matches!(self.cleanup_inputs_result, Some(Ok(()))) {
            self.first.get_or_insert(First::CleanupInputs);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // The actual current assignment and live lease are retained inputs.
        // Concrete signed plans and destructive/finalization posts remain owed.
        Ok(())
    }

    fn select_resource_preparation_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.resource_selection_result.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.resource_selection_result = Some((|| {
            let current = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            current.require_inputs_complete_v2()?;
            self.resource_selection.select_once_v2(&self.challenge, &self.cleanup_inputs,
                &current.controller, &self.graph_comparison)
        })());
        if !matches!(self.resource_selection_result, Some(Ok(()))) {
            self.first.get_or_insert(First::ResourceSelection);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // The inline Copy selection was covered by the whole pending-owner
        // constructor fee. No wire approval, catalog or signing authority is
        // created until its separate actual resource-plan interval completes.
        Ok(())
    }

    fn prepare_resource_plan_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.resource_preparation_result.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.resource_preparation_result = Some(self.resource_preparation.prepare_once_v2(flight,
            &self.challenge, &self.resource_policy, &self.cleanup_inputs, &self.resource_selection));
        self.flight = Some(flight);
        if !matches!(self.resource_preparation_result, Some(Ok(()))) {
            self.first.get_or_insert(First::ResourcePreparation);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // The exact26 plan and statement are now retained under this SAME D.
        // The actual Controller signer/Root comparison and accepted cleanup
        // debt still precede any catalog request or destructive permission.
        Ok(())
    }

    fn send_resource_draft_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.resource_draft_result.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.resource_draft_result = Some((|| {
            let fresh = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            self.resource_draft.send_once_v2(flight, &mut self.original, &self.challenge,
                &self.resource_policy, &self.cleanup_inputs, &self.resource_preparation, fresh)
        })());
        self.flight = Some(flight);
        if !matches!(self.resource_draft_result, Some(Ok(()))) {
            self.first.get_or_insert(First::ResourceDraft);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // Sending an unsigned draft creates neither acceptance nor effect
        // authority. This exact socket/D owner still owes the signed-result
        // comparison, concrete preparatory acceptance and final disposition.
        Ok(())
    }

    fn receive_resource_signature_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.resource_signature_result.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.resource_signature_result = Some(self.resource_signature.receive_once_v2(flight,
            &self.original, &self.challenge, &mut self.resource_policy, &self.cleanup_inputs,
            &self.resource_preparation, &self.resource_draft));
        self.flight = Some(flight);
        if !matches!(self.resource_signature_result, Some(Ok(()))) {
            self.first.get_or_insert(First::ResourceSignature);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // Signature verification is still before actual current-policy165 and
        // bounded preparatory acceptance. It does not end the original D.
        Ok(())
    }

    fn confirm_resource_policy_once_v2(&mut self,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.resource_policy_confirmation_result.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.resource_policy_confirmation_result = Some(self.resource_policy_confirmation.confirm_once_v2(flight,
            &self.challenge, &self.graph_objects, &self.graph_comparison, policy,
            &self.resource_signature, &self.resource_policy));
        self.flight = Some(flight);
        if !matches!(self.resource_policy_confirmation_result, Some(Ok(()))) {
            self.first.get_or_insert(First::ResourcePolicyConfirmation);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // The genuine signature and current-policy conjunction is retained for
        // the subsequent public desired-state acceptance and cleanup debt.
        Ok(())
    }

    fn send_preparatory_approval_once_v3(&mut self,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.preparatory_approval_result.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.preparatory_approval_result = Some((|| {
            let fresh = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            self.preparatory_approval.send_once_v3(flight, &mut self.original, &self.challenge,
                &self.initial_inventory, fresh, &self.cleanup_inputs, &self.resource_preparation,
                &self.resource_draft, &self.resource_signature, &self.resource_policy_confirmation)
        })());
        self.flight = Some(flight);
        if !matches!(self.preparatory_approval_result, Some(Ok(()))) {
            self.first.get_or_insert(First::PreparatoryApproval);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // This accepts only the concrete preparatory plan and cleanup debt.
        // The same socket/D/native disposition remains occupied for effects.
        self.verify_preparation_current_once_v3(policy)
    }

    fn verify_preparation_current_once_v3(&mut self,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.preparation_current_result.is_some()
            || !matches!(self.preparatory_approval_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Reentry); self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(opening) = self.decoded.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            return Err(RootDeleteErrorV1::Original);
        };
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.preparation_current_result = Some(self.preparation_current.observe_once_v3(flight, &self.original,
            preparation_current::CurrentInputsV3 { challenge: &self.challenge, batch: &self.body,
                controller: &self.controller, source: &self.source, approval: &self.preparatory_approval,
                policy: &self.resource_policy_confirmation, inputs: &self.cleanup_inputs,
                preparation: &self.resource_preparation, draft: &self.resource_draft,
                signature: &self.resource_signature, opening }));
        self.flight = Some(flight);
        if !matches!(self.preparation_current_result, Some(Ok(()))) {
            self.first.get_or_insert(First::PreparationCurrent); self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        self.issue_apply_once_v3(policy)
    }

    fn issue_apply_once_v3(&mut self,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.apply_issuer_result.is_some()
            || self.preparation_current.require_completed_v3().is_err() {
            self.first.get_or_insert(First::Reentry); self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.apply_issuer_result = Some((|| {
            let fresh = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            self.apply_issuer.issue_once_v3(flight, &mut self.original, &self.challenge, policy,
                &self.graph_objects, &self.graph_comparison, &self.initial_inventory, fresh,
                &self.resource_selection, &self.preparation_current, &self.resource_policy_confirmation)
        })());
        self.flight = Some(flight);
        if !matches!(self.apply_issuer_result, Some(Ok(()))) {
            self.first.get_or_insert(First::ApplyIssuer); self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        self.issue_network_once_v4(policy)
    }

    fn issue_network_once_v4(&mut self,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.network_issuer_result.is_some()
            || self.apply_issuer.require_completed_v3().is_err() {
            self.first.get_or_insert(First::Reentry); self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.network_issuer_result = Some((|| {
            let fresh = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            self.network_issuer.issue_network_once_v4(flight, &mut self.original, &self.challenge,
                policy, &self.graph_objects, &self.graph_comparison, &self.initial_inventory,
                fresh, &self.resource_selection, &self.preparation_current, &self.apply_issuer)
        })());
        self.flight = Some(flight);
        if !matches!(self.network_issuer_result, Some(Ok(()))) {
            self.first.get_or_insert(First::NetworkIssuer); self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // Neither approval is a physical acknowledgement or terminal release.
        // Root now independently receives the actual completed9/fresh3 native
        // receipts before any later namespace Reap issuer can enter.
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.cleanup_current_result = Some((|| {
            let fresh = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            fresh.require_inputs_complete_v2()?;
            self.cleanup_current.observe_once_v4(flight, &self.original,
                super::cleanup_current::CleanupCurrentInputsV4 { challenge: &self.challenge,
                    current: &self.preparation_current, network: &self.network_issuer,
                    controller: &fresh.controller, graph: &self.graph_comparison })
        })());
        self.flight = Some(flight);
        if !matches!(self.cleanup_current_result, Some(Ok(()))) {
            self.first.get_or_insert(First::CleanupCurrent); self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        let Some(flight) = self.flight.take() else { return Err(RootDeleteErrorV1::Original); };
        self.mount_issuer_result = Some((|| {
            let fresh = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            self.mount_issuer.issue_mount_once_v4(flight, &mut self.original, &self.challenge,
                policy, &self.graph_objects, &self.graph_comparison, &self.initial_inventory,
                fresh, &self.resource_selection, &self.preparation_current, &self.network_issuer,
                &self.cleanup_current)
        })());
        self.flight = Some(flight);
        if !matches!(self.mount_issuer_result, Some(Ok(()))) {
            self.first.get_or_insert(First::MountIssuer); self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // The same D stays occupied until actual physical acknowledgements and
        // the new terminal Source COMMIT pass independent native verification.
        self.receive_final_source_current_once_v4()
    }

    fn receive_final_source_current_once_v4(&mut self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_some() || self.closed.is_some() || self.completion_result.is_some()
            || self.mount_issuer.require_completed_v3().is_err() {
            self.first.get_or_insert(First::Reentry);
            return Err(RootDeleteErrorV1::Original);
        }
        let flight = self.flight.take().ok_or(RootDeleteErrorV1::Original)?;
        self.completion_result = Some((|| {
            let fresh = self.fresh_inventory.as_ref().ok_or(RootDeleteErrorV1::Original)?;
            self.completion.observe_once_v4(flight, &self.original,
                super::completion_current::CompletionInputsV4 { challenge: &self.challenge,
                    current: &self.preparation_current, cleanup: &self.cleanup_current,
                    mount: &self.mount_issuer, storage: &self.apply_issuer,
                    controller: &fresh.controller, batch: &self.body })
        })());
        self.flight = Some(flight);
        if !matches!(self.completion_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Completion);
            self.finish_negative_once_v1();
            return Err(RootDeleteErrorV1::Opening);
        }
        // ACK bytes alone are insufficient. The private Root listener bridge
        // still owns whole final posts, actual D settlement and positive EOF.
        Ok(())
    }

    pub(crate) fn fresh_frame_receiving_demand_v2(&self)
        -> Result<aos_sandbox_core::ResourceVector, crate::controller_resource_reservation::ResourceReservationErrorV1>
    {
        use crate::controller_resource_reservation::ResourceReservationErrorV1 as Error;
        if self.first.is_some() || self.closed.is_some() || self.fresh_admission.is_some()
            || self.fresh_inventory.is_some() || self.fresh_result.is_some()
            || self.initial_inventory.completed_ack_bytes_v2().is_err()
        {
            return Err(Error::Conflict);
        }
        final_inventory::RootDeleteFreshInventoryOriginalV2::fixed_receiving_demand_v2()
    }

}
