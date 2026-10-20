//! Retains opening-local native custody through independently owed Root/C posts.

use std::collections::TryReserveError;
use super::super::strict_chunk::RootStrictChunkOriginalV1 as ChunkV1;
use std::error::Error;

use super::{
    ControllerBankLaunchOriginalV1, First, NormalRootStartupErrorV1, PeerSampleV1,
    RootDeleteClientClosedV1 as Closed, RootDeleteClientOriginalV1, cause,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{Journal, SourceDeletePendingFenceV1};
use crate::policy_compiler::bounded_stream_io::{
    FixedDeadlineStreamIoV1, SliceDeadlineStreamIoV1,
};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1};
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::HistoryErrorV1,
    delete_root::transport::{
        DELETE_ROOT_OPEN_BYTES_V2, DeleteRootChallengeDataV2, DeleteRootOpenDataV2,
        DeleteRootWireErrorV2,
    },
};

use aos_sandbox_protocol::domain_ledger::delete_root::controller_cut::{
    DELETE_ROOT_CONTROLLER_CUT_BYTES_V3, DeleteRootControllerCutDataV3,
    DeleteRootControllerCutErrorV3,
};

pub(super) struct RootDeleteClientOpeningV1 {
    origin_original: RetainedKernelPairedClockAttemptV1,
    origin: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    clock_post: Option<Result<(), DeleteRootWireErrorV2>>,
    deadline: Option<Result<u64, DeleteRootWireErrorV2>>,
    encoding: Option<Result<(), DeleteRootWireErrorV2>>,
    pub(super) encoded_open: [u8; DELETE_ROOT_OPEN_BYTES_V2],
    pub(super) connected: Option<Result<(), HistoryErrorV1>>,
    pub(super) peer_before: PeerSampleV1,
    pub(super) peer_before_result: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) peer_after: PeerSampleV1,
    pub(super) peer_after_result: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    pub(super) sent_open: FixedDeadlineStreamIoV1<DELETE_ROOT_OPEN_BYTES_V2>,
    pub(super) sent_open_result: Option<Result<(), HistoryErrorV1>>,
    pub(super) received: RetainedSubjectStreamReadV1,
    prepared: Option<Result<(), SubjectStreamReadErrorV1>>,
    chunk: Option<Box<ChunkV1>>,
    pub(super) batch: Vec<u8>,
    reservation: Option<Result<(), TryReserveError>>,
    pub(super) sent_batch: SliceDeadlineStreamIoV1,
    pub(super) sent_batch_result: Option<Result<(), HistoryErrorV1>>,
    controller_cut_encoding: Option<Result<(), DeleteRootControllerCutErrorV3>>,
    controller_cut_bytes: [u8; DELETE_ROOT_CONTROLLER_CUT_BYTES_V3],
    controller_cut_io: FixedDeadlineStreamIoV1<DELETE_ROOT_CONTROLLER_CUT_BYTES_V3>,
    controller_cut_sent: Option<Result<(), HistoryErrorV1>>,
    authorization_fields: Option<Result<aos_sandbox_protocol::domain_ledger::delete_root::authorization::DeleteRootAuthorizationFieldsV2, DeleteRootWireErrorV2>>,
    authorization_encoding: Option<Result<(), DeleteRootWireErrorV2>>,
    authorization_reservation: Option<Result<(), TryReserveError>>,
    authorization_bytes: Vec<u8>,
    authorization_io: SliceDeadlineStreamIoV1,
    authorization_sent: Option<Result<(), HistoryErrorV1>>,
    pub(super) settlement: Option<Result<(), NormalRootStartupErrorV1>>,
}


impl RootDeleteClientOpeningV1 {
    pub(super) fn new() -> Self {
        Self {
            origin_original: Default::default(),
            origin: None,
            after_original: Default::default(),
            after: None,
            clock_post: None,
            deadline: None,
            encoding: None,
            encoded_open: [0; DELETE_ROOT_OPEN_BYTES_V2],
            connected: None,
            peer_before: PeerSampleV1::new(),
            peer_before_result: None,
            peer_after: PeerSampleV1::new(),
            peer_after_result: None,
            reporting: None,
            sent_open: Default::default(),
            sent_open_result: None,
            received: Default::default(),
            prepared: None,
            chunk: None,
            batch: Vec::new(),
            reservation: None,
            sent_batch: Default::default(),
            sent_batch_result: None,
            controller_cut_encoding: None,
            controller_cut_bytes: [0; DELETE_ROOT_CONTROLLER_CUT_BYTES_V3],
            controller_cut_io: Default::default(),
            controller_cut_sent: None,
            authorization_fields: None,
            authorization_encoding: None,
            authorization_reservation: None,
            authorization_bytes: Vec::new(),
            authorization_io: Default::default(),
            authorization_sent: None,
            settlement: None,
        }
    }

    pub(super) fn begin_clock_once(&mut self) -> Result<(), Closed> {
        if self.origin.is_some() {
            return Err(Closed);
        }
        self.origin = Some(self.origin_original.observe_once(None));
        if matches!(self.origin, Some(Ok(_))) {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn prepare_open_once(&mut self, open: DeleteRootOpenDataV2) -> Result<(), Closed> {
        if self.encoding.is_some() {
            return Err(Closed);
        }
        self.encoding = Some(open.encode_v2().map(|bytes| self.encoded_open = bytes));
        self.deadline = Some((|| {
            let before = *self
                .origin
                .as_ref()
                .and_then(|sample| sample.as_ref().ok())
                .ok_or(DeleteRootWireErrorV2::Clock)?;
            let local = before
                .boottime_nanoseconds()
                .checked_add(5_000_000_000)
                .ok_or(DeleteRootWireErrorV2::Clock)?;
            Ok(local.min(open.cutoff_for_root_sample_v1(before)?))
        })());
        if self.open_failure().is_none() {
            self.cutoff().map(|_| ())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn cutoff(&self) -> Result<u64, Closed> {
        self.deadline
            .as_ref()
            .and_then(|deadline| deadline.as_ref().ok())
            .copied()
            .ok_or(Closed)
    }

    pub(super) fn copy_batch_once(&mut self, batch: &[u8]) -> Result<(), Closed> {
        if self.reservation.is_some() {
            return Err(Closed);
        }
        self.reservation = Some(self.batch.try_reserve_exact(batch.len()));
        if !matches!(self.reservation, Some(Ok(()))) {
            return Err(Closed);
        }
        self.batch.extend_from_slice(batch);
        Ok(())
    }

    pub(super) fn send_controller_cut_once(
        &mut self,
        stream: &mut aos_sandbox_linux::unix_stream::RetainedUnixStream,
        challenge: DeleteRootChallengeDataV2,
        funding: &[u8],
        next: u64,
        end: u64,
        cutoff: u64,
    ) -> Result<(), First> {
        if self.controller_cut_encoding.is_some() {
            return Err(First::ControllerCut);
        }
        self.controller_cut_encoding = Some((|| {
            let cut = DeleteRootControllerCutDataV3 {
                challenge: challenge.digest_v2()?,
                funding: aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1::decode_v1(funding)?,
                next,
                end,
            };
            self.controller_cut_bytes = cut.encode_v3()?;
            Ok(())
        })());
        if !matches!(self.controller_cut_encoding, Some(Ok(()))) {
            return Err(First::ControllerCut);
        }
        self.controller_cut_sent = Some(self.controller_cut_io.run_once(
            stream,
            &mut self.controller_cut_bytes,
            cutoff,
            crate::policy_compiler::bounded_stream_io::DeadlineStreamDirectionV1::Write,
        ));
        if matches!(self.controller_cut_sent, Some(Ok(()))) {
            Ok(())
        } else {
            Err(First::SendControllerCut)
        }
    }

    pub(super) fn send_authorization_once(
        &mut self,
        stream: &mut aos_sandbox_linux::unix_stream::RetainedUnixStream,
        fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        open: DeleteRootOpenDataV2,
        challenge: DeleteRootChallengeDataV2,
        cutoff: u64,
    ) -> Result<(), First> {
        use aos_sandbox_protocol::domain_ledger::delete_root::authorization::{
            DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2,
            DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2,
            authorization_witness_checksum_data_v2,
        };
        if self.authorization_fields.is_some() { return Err(First::Authorization); }
        self.authorization_fields = Some(fence.authorization_witness_fields_v2(open, challenge));
        self.authorization_encoding = Some((|| {
            let fields = *self.authorization_fields.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(DeleteRootWireErrorV2::Association)?;
            let header = fields.encode_v2()?;
            let input = fence.authorization_input_data_v2();
            let length = DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2.checked_add(input.len())
                .and_then(|bytes| bytes.checked_add(DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2))
                .ok_or(DeleteRootWireErrorV2::Format)?;
            self.authorization_reservation = Some(self.authorization_bytes.try_reserve_exact(length));
            if !matches!(self.authorization_reservation, Some(Ok(()))) {
                return Err(DeleteRootWireErrorV2::Format);
            }
            self.authorization_bytes.extend_from_slice(&header);
            self.authorization_bytes.extend_from_slice(input);
            self.authorization_bytes.extend_from_slice(&authorization_witness_checksum_data_v2(&header, input));
            Ok(())
        })());
        if !matches!(self.authorization_encoding, Some(Ok(()))) { return Err(First::Authorization); }
        self.authorization_sent = Some(self.authorization_io.run_once(stream, &mut self.authorization_bytes,
            cutoff, crate::policy_compiler::bounded_stream_io::DeadlineStreamDirectionV1::Write));
        if matches!(self.authorization_sent, Some(Ok(()))) { Ok(()) }
        else { Err(First::SendAuthorization) }
    }

    pub(super) fn finish_clock_once(
        &mut self,
        open: Option<DeleteRootOpenDataV2>,
        challenge: Option<DeleteRootChallengeDataV2>,
    ) -> Result<(), Closed> {
        if self.after.is_some() {
            return Err(Closed);
        }
        self.after = Some(self.after_original.observe_once(None));
        self.clock_post = Some((|| {
            let before = *self
                .origin
                .as_ref()
                .and_then(|sample| sample.as_ref().ok())
                .ok_or(DeleteRootWireErrorV2::Clock)?;
            let after = *self
                .after
                .as_ref()
                .and_then(|sample| sample.as_ref().ok())
                .ok_or(DeleteRootWireErrorV2::Clock)?;
            require_clock_bracket(before, after, open, challenge)?;
            Ok(())
        })());
        if self.after_original.failure().is_none() && matches!(self.clock_post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn open_failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.encoding).or_else(|| cause(&self.deadline))
    }

    pub(super) fn failure(&self, first: First) -> Option<&(dyn Error + 'static)> {
        match first {
            First::ClockBefore => self
                .origin_original
                .failure()
                .or_else(|| cause(&self.origin)),
            First::PeerBefore => self
                .peer_before
                .failure()
                .or_else(|| cause(&self.peer_before_result)),
            First::Reporting => cause(&self.reporting),
            First::SendOpen => self
                .sent_open
                .failure()
                .or_else(|| cause(&self.sent_open_result)),
            First::Preparation => self.received.failure().or_else(|| cause(&self.prepared)),
            First::Chunk => self
                .chunk
                .as_ref()
                .and_then(|chunk| chunk.failure(&self.received)),
            First::ControllerCut => cause(&self.controller_cut_encoding),
            First::SendControllerCut => self
                .controller_cut_io
                .failure()
                .or_else(|| cause(&self.controller_cut_sent)),
            First::Authorization => cause(&self.authorization_fields)
                .or_else(|| cause(&self.authorization_reservation))
                .or_else(|| cause(&self.authorization_encoding)),
            First::SendAuthorization => self.authorization_io.failure()
                .or_else(|| cause(&self.authorization_sent)),
            First::Copy => cause(&self.reservation),
            First::SendBatch => self
                .sent_batch
                .failure()
                .or_else(|| cause(&self.sent_batch_result)),
            First::PeerAfter => self
                .peer_after
                .failure()
                .or_else(|| cause(&self.peer_after_result)),
            First::ClockAfter => self
                .after_original
                .failure()
                .or_else(|| cause(&self.after))
                .or_else(|| cause(&self.clock_post)),
            First::Settlement => self
                .peer_before
                .failure()
                .or_else(|| self.peer_after.failure())
                .or_else(|| cause(&self.settlement)),
            _ => None,
        }
    }

    pub(super) fn property_failure_view(
        &self,
        first: First,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match first {
            First::PeerBefore => self.peer_before.property_failure_view_v1(),
            First::PeerAfter => self.peer_after.property_failure_view_v1(),
            First::Chunk => self
                .chunk
                .as_ref()?
                .property_failure_view_v1(),
            First::Settlement => self
                .peer_before
                .property_failure_view_v1()
                .or_else(|| self.peer_after.property_failure_view_v1()),
            _ => None,
        }
    }
}


impl RootDeleteClientOriginalV1<'_> {
    pub(super) fn receive_challenge(
        &mut self,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), Closed> {
        let local = self.opening.as_mut().ok_or(self.closed)?;
        local.prepared = Some(local.received.prepare_exact_once(224));
        if !matches!(local.prepared, Some(Ok(()))) {
            self.first = Some(First::Preparation);
            return Err(self.closed);
        }
        let geometry = super::CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| self.closed)?;
        while !self
            .opening
            .as_ref()
            .ok_or(self.closed)?
            .received
            .completed_exact()
        {
            // The independent whole-opening after was paid before the first
            // sample. A refused new increment cannot suppress that owed post.
            self.admission = Some(Self::peer_traffic_v1(1).and_then(|traffic| {
                fence.reserve_preaccept_additional_v1(
                    controller,
                    launch,
                    self.profile.lower_original_v1(),
                    traffic,
                )
            }));
            if !matches!(self.admission, Some(Ok(()))) {
                self.first = Some(First::Admission);
                return Err(self.closed);
            }
            let local = self.opening.as_mut().ok_or(self.closed)?;
            local.chunk = Some(Box::new(ChunkV1::default()));
            let cutoff = local.cutoff()?;
            let chunk = local.chunk.as_mut().ok_or(self.closed)?;
            if chunk.receive_once(&mut local.received,
                self.connection.stream_mut().map_err(|_| self.closed)?,
                &local.peer_before, self.profile, &geometry, cutoff).is_err() {
                self.first = Some(First::Chunk);
                return Err(self.closed);
            }
            // This completed native subject leaf has its own stream/C current
            // posts and cutoff. The cumulative raw224 and first Root anchor
            // remain through the separately owed whole-opening Root/C posts.
            drop(local.chunk.take());
        }
        Ok(())
    }
}

// Comparison DATA never produces an actual clock, peer or completed client.
fn require_clock_bracket(
    before: RawPairedClockSample,
    after: RawPairedClockSample,
    open: Option<DeleteRootOpenDataV2>,
    challenge: Option<DeleteRootChallengeDataV2>,
) -> Result<(), DeleteRootWireErrorV2> {
    before
        .validate_later_sample(after)
        .map_err(|_| DeleteRootWireErrorV2::Clock)?;
    let origin_cutoff = before
        .boottime_nanoseconds()
        .checked_add(5_000_000_000)
        .ok_or(DeleteRootWireErrorV2::Clock)?;
    if after.boottime_nanoseconds() >= origin_cutoff {
        return Err(DeleteRootWireErrorV2::Clock);
    }
    if let Some(open) = open {
        if after.boottime_nanoseconds() >= open.cutoff_for_root_sample_v1(before)? {
            return Err(DeleteRootWireErrorV2::Clock);
        }
    }
    if let Some(challenge) = challenge {
        before
            .validate_later_sample(challenge.clock)
            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
        challenge
            .clock
            .validate_later_sample(after)
            .map_err(|_| DeleteRootWireErrorV2::Clock)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;
    use aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1;

    fn sample(wall: i64, boot: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [2; 16],
            wall,
            boot * 1_000_000_000,
        )
        .unwrap()
    }

    #[test]
    fn completed_local_posts_must_precede_the_original_five_second_boundary() {
        let before = sample(100, 10);
        assert!(require_clock_bracket(before, sample(104, 14), None, None).is_ok());
        assert!(require_clock_bracket(before, sample(105, 15), None, None).is_err());
    }

    #[test]
    fn root_sample_cannot_be_later_than_the_actual_controller_after() {
        let clock = sample(103, 13);
        let challenge = DeleteRootChallengeDataV2 {
            open: [3; 32],
            clock,
            source: SourceDeleteCurrentQueryDataV1 {
                nonce: [4; 16],
                project: [5; 16],
                operation: [6; 16],
                batch: [7; 32],
                boot: clock.host_boot_id(),
                started: clock.boottime_nanoseconds(),
                cutoff: 70_000_000_000,
            },
        };
        // Synthetic DATA exercises only the clock comparison; it creates no
        // actual client, native Root peer, C17 turn or challenge borrower.
        assert!(
            require_clock_bracket(sample(100, 10), sample(102, 12), None, Some(challenge)).is_err()
        );
    }
}
