//! Completes actual signed31/fresh18 on the original Maintenance Root socket.
//!
//! The genuine M borrower checks both protected terminal/native stages before
//! lending the four immutable SDK packets. This owner uses the same framed
//! proof, bounded native subject transport, exact ACK and hostile EOF engines.
//! Independent final peer/paired-clock posts run after every entered failure.

use super::*;
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::{
    RESOURCE_CLOSED_BYTES_V2, ResourceCompletionBindingDataV2, ResourceCompletionClosedDataV2,
    ResourceCompletionProofDataV2, ResourceCompletionPurposeDataV3,
};
use std::os::fd::AsFd as _;

#[derive(Clone, Copy)]
enum FinalFirst {
    BeforeClock,
    BeforePeer,
    Positions,
    Proof,
    Funding,
    Send,
    RequestEnd,
    Receive,
    Reply,
    Eof,
    AfterPeer,
    AfterClock,
    Temporal,
    Settlement,
}

pub(super) struct FinalAcknowledgement {
    positions: crate::journal::StartResourceNativePositionsOriginalV2,
    positions_result: Option<Result<(), ResourceReservationErrorV1>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_time: Option<Result<(), HistoryErrorV1>>,
    peer_before: Box<PeerSampleV1>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    binding: Option<Result<ResourceCompletionBindingDataV2, HistoryErrorV1>>,
    proof_digest: Option<Result<[u8; 32], HistoryErrorV1>>,
    sender: FixedDeadlineStreamIoV1<4096>,
    sent: Option<Result<(), HistoryErrorV1>>,
    scratch: [u8; 4096],
    data_failure: Option<ApplyRootDataErrorV1>,
    request_end: Option<Result<(), rustix::io::Errno>>,
    received: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    extension: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    reply: Option<Result<ResourceCompletionClosedDataV2, HistoryErrorV1>>,
    eof: FixedDeadlineStreamIoV1<1>,
    eof_byte: [u8; 1],
    ended: Option<Result<(), HistoryErrorV1>>,
    peer_after: Box<PeerSampleV1>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    temporal: Option<Result<(), Cause>>,
    settlement: Option<Result<(), Cause>>,
    first: Option<FinalFirst>,
    retired: bool,
}

impl FinalAcknowledgement {
    pub(super) fn settlement_failed_v3(&self) -> bool {
        matches!(self.first, Some(FinalFirst::Settlement))
    }

    fn new() -> Self {
        Self {
            positions: crate::journal::StartResourceNativePositionsOriginalV2::new(),
            positions_result: None,
            before_clock: Default::default(),
            before_sample: None,
            before_time: None,
            peer_before: Box::new(PeerSampleV1::new()),
            before: None,
            binding: None,
            proof_digest: None,
            sender: Default::default(),
            sent: None,
            scratch: [0; 4096],
            data_failure: None,
            request_end: None,
            received: Default::default(),
            preparation: None,
            extension: None,
            chunk: None,
            reply: None,
            eof: Default::default(),
            eof_byte: [0],
            ended: None,
            peer_after: Box::new(PeerSampleV1::new()),
            after: None,
            after_clock: Default::default(),
            after_sample: None,
            temporal: None,
            settlement: None,
            first: None,
            retired: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FinalFirst::BeforeClock => self
                .before_clock
                .failure()
                .or_else(|| cause(&self.before_sample))
                .or_else(|| cause(&self.before_time)),
            FinalFirst::BeforePeer => self.peer_before.failure().or_else(|| cause(&self.before)),
            FinalFirst::Positions => self
                .positions
                .failure()
                .or_else(|| cause(&self.positions_result)),
            FinalFirst::Proof => cause(&self.binding).or_else(|| cause(&self.proof_digest)),
            FinalFirst::Funding => None,
            FinalFirst::Send => self.sender.failure().or_else(|| cause(&self.sent)),
            FinalFirst::RequestEnd => cause(&self.request_end),
            FinalFirst::Receive => self
                .chunk
                .as_ref()
                .and_then(|chunk| chunk.failure(&self.received))
                .or_else(|| self.received.failure())
                .or_else(|| cause(&self.preparation))
                .or_else(|| cause(&self.extension)),
            FinalFirst::Reply => cause(&self.reply),
            FinalFirst::Eof => self.eof.failure().or_else(|| cause(&self.ended)),
            FinalFirst::AfterPeer => self.peer_after.failure().or_else(|| cause(&self.after)),
            FinalFirst::AfterClock => self
                .after_clock
                .failure()
                .or_else(|| cause(&self.after_sample)),
            FinalFirst::Temporal => boxed_cause(&self.temporal),
            FinalFirst::Settlement => self
                .peer_before
                .failure()
                .or_else(|| self.peer_after.failure())
                .or_else(|| self.positions.failure())
                .or_else(|| boxed_cause(&self.settlement)),
        }
        .or_else(|| self.data_failure.as_ref().map(|cause| cause as _))
    }
}

impl RootMaintenanceStorageClientOriginalV3 {
    pub(crate) fn complete_final_ack_once_v3(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
        prepared: &crate::ControllerMaintenanceStorageRequestOriginalV3,
        packets: [&[u8]; 4],
        session_native: &[u8; 64],
    ) -> Result<(), RootMaintenanceStorageClientClosedV3> {
        self.require_transferred_request_v3(prepared)?;
        if self.final_entry.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        self.final_entry = Some((|| -> Result<(), Cause> {
            loan.require_current_v3(controller)?;
            let opening = self
                .state
                .as_ref()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let native =
                CreateStorageRootPeerReceivingOriginalsV1::provisioning_turn_native_peak_v1(
                    &opening.profile,
                )
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let memory = size_of::<FinalAcknowledgement>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(2 * size_of::<RootStrictChunkOriginalV1>()))
                .and_then(|bytes| {
                    bytes.checked_add(
                        RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?
                            .checked_mul(2)?,
                    )
                })
                .and_then(|bytes| bytes.checked_add(self.received_bound.checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let files = RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1
                .checked_mul(2)
                .and_then(|files| u64::try_from(files).ok())
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let metadata = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
                .and_then(|cells| cells.checked_mul(2))
                .and_then(|cells| u64::try_from(cells).ok())
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            let demand = native
                .checked_add(loan.completion_positions_demand_v3(controller)?)?
                .checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, memory)
                        .with(D::OpenFiles, files)
                        .with(D::MetadataEntries, metadata),
                )?;
            // The old reply remains resident. Move its already charged buffer
            // plane into the base before selecting the distinct ACK buffer;
            // no smaller receive bound refunds earlier retained custody.
            self.received_bound = RESOURCE_CLOSED_BYTES_V2;
            self.add_receiving_demand_v3(loan, controller, demand, 2)?;
            self.final_ack = Some(Box::new(FinalAcknowledgement::new()));
            Ok(())
        })());
        if !matches!(self.final_entry, Some(Ok(()))) {
            self.first = Some(First::Final);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        if let Err(first) = self.final_body(loan, controller, packets, session_native) {
            if let Some(final_ack) = self.final_ack.as_mut() {
                final_ack.first.get_or_insert(first);
            }
        }
        self.finish_final_posts(loan, controller);
        if self
            .final_ack
            .as_ref()
            .is_none_or(|state| state.first.is_some())
        {
            self.first.get_or_insert(First::Final);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        Ok(())
    }

    fn final_body(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
        packets: [&[u8]; 4],
        session_native: &[u8; 64],
    ) -> Result<(), FinalFirst> {
        let opening = self.state.as_mut().ok_or(FinalFirst::Proof)?;
        let final_ack = self.final_ack.as_mut().ok_or(FinalFirst::Proof)?;
        let previous = self
            .construction
            .as_ref()
            .ok_or(FinalFirst::BeforeClock)?
            .completed_after_clock_data_v3()
            .map_err(|_| FinalFirst::BeforeClock)?;
        final_ack.before_sample = Some(final_ack.before_clock.observe_once(Some(opening.origin)));
        final_ack.before_time = Some((|| {
            let before = *positive(&final_ack.before_sample)?;
            previous
                .validate_later_sample(before)
                .map_err(|_| HistoryErrorV1::Malformed)?;
            require_original_sample(opening.origin, opening.cutoff, before)
        })());
        positive(&final_ack.before_time).map_err(|_| FinalFirst::BeforeClock)?;
        final_ack.before = Some((|| {
            final_ack
                .peer_before
                .observe_against_sample_with_cutoff_once_v1(
                    &opening.profile,
                    opening
                        .connection
                        .stream()
                        .map_err(|_| NormalRootStartupErrorV1::Service)?,
                    opening
                        .peer_before
                        .as_deref()
                        .ok_or(NormalRootStartupErrorV1::Service)?,
                    None,
                    false,
                    opening.cutoff,
                )
        })());
        positive(&final_ack.before).map_err(|_| FinalFirst::BeforePeer)?;
        final_ack.positions_result =
            Some(loan.observe_completion_positions_once_v3(controller, &mut final_ack.positions));
        positive(&final_ack.positions_result).map_err(|_| FinalFirst::Positions)?;
        final_ack.binding = Some((|| {
            let admission = positive(&opening.reply)?;
            Ok(ResourceCompletionBindingDataV2 {
                purpose: ResourceCompletionPurposeDataV3::MaintenanceStorage,
                root_nonce: admission.root_nonce,
                controller_nonce: admission.controller_nonce,
                query_digest: admission.query_digest,
                reply_digest: MaintenanceStorageReplyDataV2::decode_v2(opening.received.bytes())?
                    .digest_v2()?,
            })
        })());
        let (controller_native, source_native) = final_ack
            .positions
            .data_v2()
            .map_err(|_| FinalFirst::Positions)?;
        let proof = ResourceCompletionProofDataV2 {
            binding: *positive(&final_ack.binding).map_err(|_| FinalFirst::Proof)?,
            controller_native,
            source_native,
            session_native,
            resource_request: packets[0],
            resource_outcome: packets[1],
            inventory_request: packets[2],
            inventory_outcome: packets[3],
        };
        final_ack.proof_digest = Some(proof.digest_v2());
        positive(&final_ack.proof_digest).map_err(|_| FinalFirst::Proof)?;
        let bytes = proof.encoded_bytes_v2().map_err(|_| FinalFirst::Proof)?;
        let mut funding = RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        let mut borrowed = RootClientLoanV1::MaintenanceStorage(loan);
        funding
            .charge(&mut borrowed, controller, 0, bytes, bytes)
            .map_err(|_| FinalFirst::Funding)?;
        resource_stream::send_subject_v1(
            RootSubjectDataV1::ResourceCompletion(proof),
            &mut opening.connection,
            &mut final_ack.sender,
            &mut final_ack.sent,
            &mut final_ack.scratch,
            &mut final_ack.data_failure,
            opening.cutoff,
        )
        .map_err(|_| FinalFirst::Send)?;
        final_ack.request_end = Some(rustix::net::shutdown(
            opening
                .connection
                .stream()
                .map_err(|_| FinalFirst::RequestEnd)?
                .as_fd(),
            rustix::net::Shutdown::Write,
        ));
        positive(&final_ack.request_end).map_err(|_| FinalFirst::RequestEnd)?;
        RootReplyReceiveV1 {
            connection: &mut opening.connection,
            received: &mut final_ack.received,
            preparation: &mut final_ack.preparation,
            extension: &mut final_ack.extension,
            chunk: &mut final_ack.chunk,
            data_failure: &mut final_ack.data_failure,
            peer_before: &final_ack.peer_before,
            profile: &opening.profile,
            cutoff: opening.cutoff,
        }
        .receive_fixed_reply_v2(
            RESOURCE_CLOSED_BYTES_V2,
            &mut borrowed,
            controller,
            &mut funding,
        )
        .map_err(|_| FinalFirst::Receive)?;
        final_ack.reply = Some((|| {
            let reply = ResourceCompletionClosedDataV2::decode_v2(final_ack.received.bytes())?;
            if reply.binding != *positive(&final_ack.binding)?
                || reply.proof_digest != *positive(&final_ack.proof_digest)?
                || reply.cutoff_ns != positive(&opening.reply)?.cutoff_ns
            {
                return Err(HistoryErrorV1::Correlation);
            }
            Ok(reply)
        })());
        positive(&final_ack.reply).map_err(|_| FinalFirst::Reply)?;
        final_ack.ended = Some(
            final_ack.eof.run_once(
                opening
                    .connection
                    .stream_mut()
                    .map_err(|_| FinalFirst::Eof)?,
                &mut final_ack.eof_byte,
                opening.cutoff,
                DeadlineStreamDirectionV1::Eof,
            ),
        );
        if !matches!(final_ack.ended, Some(Ok(()))) || !final_ack.eof.completed_exact() {
            return Err(FinalFirst::Eof);
        }
        Ok(())
    }

    fn finish_final_posts(
        &mut self,
        loan: &mut ControllerCatalogMaintenanceRootLoanV3<'_, '_>,
        controller: &Journal,
    ) {
        let (Some(opening), Some(final_ack)) = (self.state.as_ref(), self.final_ack.as_mut())
        else {
            return;
        };
        final_ack.after = Some((|| {
            final_ack
                .peer_after
                .observe_against_sample_with_cutoff_once_v1(
                    &opening.profile,
                    opening
                        .connection
                        .stream()
                        .map_err(|_| NormalRootStartupErrorV1::Service)?,
                    opening
                        .peer_before
                        .as_deref()
                        .ok_or(NormalRootStartupErrorV1::Service)?,
                    None,
                    true,
                    opening.cutoff,
                )
        })());
        if !matches!(final_ack.after, Some(Ok(()))) {
            final_ack.first.get_or_insert(FinalFirst::AfterPeer);
        }
        final_ack.after_sample = Some(final_ack.after_clock.observe_once(Some(opening.origin)));
        if !matches!(final_ack.after_sample, Some(Ok(_))) {
            final_ack.first.get_or_insert(FinalFirst::AfterClock);
        }
        if final_ack.first.is_some() {
            return;
        }
        final_ack.temporal = Some((|| -> Result<(), Cause> {
            loan.require_current_v3(controller)?;
            let before = *positive(&final_ack.before_sample)?;
            let after = *positive(&final_ack.after_sample)?;
            let closed = positive(&final_ack.reply)?;
            let observed = RawPairedClockSample::new_untrusted(
                opening.origin.provenance(),
                opening.origin.host_boot_id(),
                closed.observed_wall_seconds,
                closed.observed_boottime_ns,
            )?;
            before.validate_later_sample(observed)?;
            observed.validate_later_sample(after)?;
            require_original_sample(opening.origin, opening.cutoff, after)?;
            let admission = positive(&opening.reply)?;
            if after.wall_seconds() >= admission.policy_expires_seconds
                || after.wall_seconds() >= admission.lease_expires_seconds
            {
                return Err(RootMaintenanceStorageClientClosedV3.into());
            }
            Ok(())
        })());
        if !matches!(final_ack.temporal, Some(Ok(()))) {
            final_ack.first = Some(FinalFirst::Temporal);
        }
    }

    pub(crate) fn final_ack_completed_v3(&self) -> bool {
        self.first.is_none()
            && self.final_ack.as_ref().is_some_and(|state| {
                state.first.is_none()
                    && matches!(state.reply, Some(Ok(_)))
                    && matches!(state.ended, Some(Ok(())))
                    && state.eof.completed_exact()
                    && matches!(state.after, Some(Ok(())))
                    && matches!(state.temporal, Some(Ok(())))
            })
    }

    pub(crate) fn retire_positive_native_once_v3(
        &mut self,
    ) -> Result<(), RootMaintenanceStorageClientClosedV3> {
        if !self.final_ack_completed_v3() {
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        let final_ack = self
            .final_ack
            .as_mut()
            .ok_or(RootMaintenanceStorageClientClosedV3)?;
        if final_ack.retired {
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        final_ack.settlement = Some((|| -> Result<(), Cause> {
            let opening = self
                .state
                .as_mut()
                .ok_or(RootMaintenanceStorageClientClosedV3)?;
            opening
                .peer_before
                .as_mut()
                .ok_or(RootMaintenanceStorageClientClosedV3)?
                .settle_positive_once()?;
            opening
                .peer_after
                .as_mut()
                .ok_or(RootMaintenanceStorageClientClosedV3)?
                .settle_positive_once()?;
            self.construction
                .as_mut()
                .ok_or(RootMaintenanceStorageClientClosedV3)?
                .retire_positive_peers_once_v3()?;
            final_ack.peer_before.settle_positive_once()?;
            final_ack.peer_after.settle_positive_once()?;
            final_ack.positions.retire_positive_once_v2()?;
            Ok(())
        })());
        if !matches!(final_ack.settlement, Some(Ok(()))) {
            final_ack.first = Some(FinalFirst::Settlement);
            self.first.get_or_insert(First::Final);
            return Err(RootMaintenanceStorageClientClosedV3);
        }
        final_ack.retired = true;
        Ok(())
    }
}

fn boxed_cause(value: &Option<Result<(), Cause>>) -> Option<&(dyn Error + 'static)> {
    value
        .as_ref()?
        .as_ref()
        .err()
        .map(|cause| cause.as_ref() as &(dyn Error + 'static))
}
