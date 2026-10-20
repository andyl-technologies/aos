//! Verifies actual physical cleanup and terminal Source on the same Root D.
//!
//! Fixed frame/capture backing is paid first. Each captured native prefix and
//! reached full model has its own finite prepay frontier. The same Session,
//! Source canonical replay, auxiliary reducer and signer transport engines
//! retain all primary failures before independent native and Root posts.

use super::controller::sessions::model::{
    DeleteCleanupTerminalPurposeV4 as SessionPurpose, DeleteSessionModelsOriginalV2,
};
use super::preparation_current::RootDeletePreparationSourceModelsV3;
use super::*;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::journal::JournalError;
use crate::policy_compiler::{
    RetainedKernelPairedClockAttemptV1,
    create_storage_current::controller_readonly::native_read::RootFixedNativeReadOriginalsV1 as Reader,
    source_signer_transport::{RootSourceSignerTransportOriginalsV1, RootSourceTransportClosedV1},
};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_root::{
    completion::{
        DeleteCompletionDataErrorV4, DeleteRootSourceCompletionDataV4 as Frame,
        completion_approval_commitment_data_v4,
    },
    resource_exchange::DeleteRootResourcePurposeDataV3 as Purpose,
    source_current::{
        SOURCE_DELETE_CURRENT_QUERY_BYTES_V1 as Q, SOURCE_DELETE_CURRENT_REPLY_BYTES_V1 as A,
        SourceDeleteCurrentPurposeDataV3 as SourcePurpose, SourceDeleteCurrentReplyDataV1,
    },
};

type Cause = Box<dyn StdError>;
const CLOCKS: usize = 11;

/// Names actual distinct terminal native and model frontiers.
#[derive(Clone, Copy)]
pub(crate) enum RootDeleteCompletionPhaseV4 {
    Fixed,
    MountNative,
    MountModels,
    StorageNative,
    StorageModels,
    SourceNative,
    SourceSemantic,
    SourceModels,
}

impl RootDeleteCompletionPhaseV4 {
    pub(crate) const fn index_v4(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy)]
enum First {
    Geometry(usize),
    Funding(usize),
    Posts,
    Clock(usize),
    Frame,
    Ack,
    Native(usize),
    Models(usize),
    SourceModels,
    Signature,
    Comparison,
    Primary,
    Reentry,
}

/// Retains one native finality conjunction; supplied frames construct no grant.
pub(crate) struct RootDeleteCompletionCurrentOriginalV4 {
    phase: Option<RootDeleteCompletionPhaseV4>,
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
    message: body::message::RootDeleteMessageReceivingV2,
    received: Option<Result<(), RootDeleteErrorV1>>,
    frame: Option<Result<Frame, DeleteCompletionDataErrorV4>>,
    request_eof: FixedDeadlineStreamIoV1<1>,
    eof_byte: [u8; 1],
    request_end: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    >,
    ack: [u8; 32],
    ack_io: FixedDeadlineStreamIoV1<32>,
    ack_result: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    >,
    readers: [Reader; 3],
    native: [Option<Result<(), JournalError>>; 3],
    sessions: [DeleteSessionModelsOriginalV2; 2],
    models: [Option<Result<(), JournalError>>; 2],
    source_models: RootDeletePreparationSourceModelsV3,
    source_result: Option<Result<(), JournalError>>,
    transport: RootSourceSignerTransportOriginalsV1<Q, A>,
    transport_result: Option<Result<(), RootSourceTransportClosedV1>>,
    reply: Option<Result<SourceDeleteCurrentReplyDataV1, Cause>>,
    compared: Option<Result<(), Cause>>,
    primary: Option<Result<(), Cause>>,
    entered: bool,
    posts_owed: bool,
    complete: bool,
    first: Option<First>,
}

impl Default for RootDeleteCompletionCurrentOriginalV4 {
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
            message: Default::default(),
            received: None,
            frame: None,
            request_eof: Default::default(),
            eof_byte: [0],
            request_end: None,
            ack: [0; 32],
            ack_io: Default::default(),
            ack_result: None,
            readers: [
                Reader::mount_session_v2(),
                Reader::default(),
                Reader::source_current_v1(),
            ],
            native: std::array::from_fn(|_| None),
            sessions: std::array::from_fn(|_| Default::default()),
            models: std::array::from_fn(|_| None),
            source_models: Default::default(),
            source_result: None,
            transport: Default::default(),
            transport_result: None,
            reply: None,
            compared: None,
            primary: None,
            entered: false,
            posts_owed: false,
            complete: false,
            first: None,
        }
    }
}

pub(super) struct CompletionInputsV4<'held> {
    pub(super) challenge: &'held RootDeleteChallengeOriginalsV1,
    pub(super) current: &'held RootDeletePreparationCurrentOriginalV3,
    pub(super) cleanup: &'held RootDeleteCleanupCurrentOriginalV4,
    pub(super) mount: &'held apply_issuer::RootDeleteApplyIssuerOriginalV3,
    pub(super) storage: &'held apply_issuer::RootDeleteApplyIssuerOriginalV3,
    pub(super) controller: &'held RootDeleteControllerCurrentOriginalV1,
    pub(super) batch: &'held body::RootDeleteBatchReceivingV1,
}

impl RootDeleteCompletionCurrentOriginalV4 {
    pub(crate) fn admission_phase_v4(
        &self,
    ) -> Result<RootDeleteCompletionPhaseV4, ResourceReservationErrorV1> {
        let phase = self.phase.ok_or(ResourceReservationErrorV1::Conflict)?;
        if !self.entered
            || self.first.is_some()
            || self.permits[phase.index_v4()].is_some()
            || !matches!(self.demands[phase.index_v4()], Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(phase)
    }

    pub(crate) fn receiving_demand_v4(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.demands[self.admission_phase_v4()?.index_v4()]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn observe_once_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        inputs: CompletionInputsV4<'_>,
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
        for (index, reader) in self.readers.iter_mut().enumerate() {
            reader.finish_post_once();
            if reader.post_failure().is_some() {
                self.first.get_or_insert(First::Native(index));
            }
        }
        if self.posts_owed {
            self.after = Some(self.posts.observe_after_once_v1(flight, inputs.challenge));
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(First::Posts);
            }
            self.sample_once_v4(10, &inputs);
        }
        self.complete = self.first.is_none()
            && matches!(self.primary, Some(Ok(())))
            && matches!(self.compared, Some(Ok(())));
        self.require_completed_v4()
    }

    fn observe_inner_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        inputs: &CompletionInputsV4<'_>,
    ) -> Result<(), Cause> {
        use RootDeleteCompletionPhaseV4 as P;
        inputs.current.require_completed_v3()?;
        inputs.cleanup.require_completed_v4()?;
        inputs
            .mount
            .completed_approval_for_v4(Purpose::MountReap62)?;
        inputs.storage.completed_approval_for_v4(Purpose::Apply7)?;
        self.admit_v4(flight, P::Fixed, Self::fixed_demand_v4())?;
        self.posts_owed = true;
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(inputs.challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(First::Posts);
        }
        self.sample_once_v4(0, inputs);
        self.before = Some(self.posts.observe_before_once_v1(flight, inputs.challenge));
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(First::Posts);
        }
        self.require_primary_v4()?;
        self.received = Some(self.message.receive_continuation_once_v2(
            flight,
            original,
            inputs.challenge,
            544,
        ));
        if !matches!(self.received, Some(Ok(()))) {
            self.first = Some(First::Frame);
        }
        self.require_primary_v4()?;
        self.frame = Some(Frame::decode_v4(self.message.bytes_v2()?));
        if !matches!(self.frame, Some(Ok(_))) {
            self.first = Some(First::Frame);
        }
        self.require_primary_v4()?;
        let mut stream = original;
        self.request_end = Some(self.request_eof.run_once(
            &mut stream,
            &mut self.eof_byte,
            inputs.challenge.source_query_v1()?.cutoff,
            DeadlineStreamDirectionV1::Eof,
        ));
        if !matches!(self.request_end, Some(Ok(()))) || !self.request_eof.completed_exact() {
            self.first = Some(First::Frame);
        }
        self.sample_once_v4(1, inputs);
        self.require_primary_v4()?;
        let frame = *positive(&self.frame)?;
        let prior = inputs.current.completed_frame_data_v3()?;
        let cleanup = inputs.cleanup.completed_frame_v4()?;
        if frame.physical.challenge != prior.challenge
            || frame.physical.opening != prior.opening
            || frame.controller != prior.controller
            || frame.physical.cleanup != cleanup.commitment_v4()?
            || frame.physical.approved_mount
                != completion_approval_commitment_data_v4(
                    inputs
                        .mount
                        .completed_approval_for_v4(Purpose::MountReap62)?,
                    Purpose::MountReap62,
                )?
            || frame.physical.approved_storage
                != completion_approval_commitment_data_v4(
                    inputs.storage.completed_approval_for_v4(Purpose::Apply7)?,
                    Purpose::Apply7,
                )?
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        let query = inputs.current.terminal_source_query_data_v4()?;
        let ids = flight
            .delete_cut_startup_v1()?
            .native_startup_original_v1()
            .fields()
            .profile
            .identities;
        for index in 0..2 {
            let (native, models, proof, purpose) = if index == 0 {
                (
                    P::MountNative,
                    P::MountModels,
                    frame.physical.mount,
                    SessionPurpose::MountReap62,
                )
            } else {
                (
                    P::StorageNative,
                    P::StorageModels,
                    frame.physical.storage,
                    SessionPurpose::StorageDestroy7,
                )
            };
            self.readers[index].prepare_delete_completion_session_observation_v4(proof.native)?;
            self.readers[index].capture_once(ids[0]);
            if self.readers[index].require_captured_v1().is_err() {
                self.first = Some(First::Native(index));
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.admit_v4(
                flight,
                native,
                self.readers[index]
                    .replay_demand_v1()
                    .map_err(|cause| cause.into()),
            )?;
            self.sample_once_v4(2 + index * 2, inputs);
            self.require_primary_v4()?;
            self.readers[index].replay_once();
            self.readers[index].finish_post_once();
            self.native[index] = Some(
                self.readers[index]
                    .delete_preparation_native_data_v3()
                    .map(|_| ()),
            );
            if !matches!(self.native[index], Some(Ok(()))) {
                self.first = Some(First::Native(index));
            }
            self.require_primary_v4()?;
            let bytes = usize::try_from(self.readers[index].terminal_native_v1()?.end)
                .map_err(|_| JournalError::JournalTooLarge)?;
            self.admit_v4(
                flight,
                models,
                DeleteSessionModelsOriginalV2::cleanup_packet_demand_v4(bytes, purpose)
                    .map_err(|cause| cause.into()),
            )?;
            self.sample_once_v4(3 + index * 2, inputs);
            self.require_primary_v4()?;
            let manifests = inputs.controller.broker_manifests_v2()?;
            self.models[index] = Some(self.sessions[index].observe_cleanup_packets_once_v4(
                self.readers[index].terminal_native_v1()?,
                self.readers[index].completed_delete_storage_history_rows_v3()?,
                if index == 0 { manifests.1 } else { manifests.2 },
                query.cutoff,
                query.boot,
                purpose,
            ));
            if !matches!(self.models[index], Some(Ok(()))) {
                self.first = Some(First::Models(index));
            }
            self.require_primary_v4()?;
        }
        self.readers[2].prepare_delete_terminal_observation_v4(query)?;
        self.readers[2].capture_once(ids[0]);
        if self.readers[2].require_captured_v1().is_err() {
            self.first = Some(First::Native(2));
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.admit_v4(
            flight,
            P::SourceNative,
            self.readers[2]
                .replay_demand_v1()
                .map_err(|cause| cause.into()),
        )?;
        self.sample_once_v4(6, inputs);
        self.require_primary_v4()?;
        self.readers[2].audit_once();
        if self.readers[2].failure().is_some() {
            self.first = Some(First::Native(2));
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.admit_v4(
            flight,
            P::SourceSemantic,
            self.readers[2]
                .additional_delete_preparation_semantic_demand_v3()
                .map_err(|cause| cause.into()),
        )?;
        self.sample_once_v4(7, inputs);
        self.require_primary_v4()?;
        self.readers[2].replay_once();
        self.readers[2].finish_post_once();
        self.native[2] = Some((|| {
            if self.readers[2].delete_preparation_native_data_v3()? != frame.source
                || self.readers[2].delete_terminal_historical_source_native_v4()? != prior.source
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
        if !matches!(self.native[2], Some(Ok(()))) {
            self.first = Some(First::Native(2));
        }
        self.require_primary_v4()?;
        self.admit_v4(
            flight,
            P::SourceModels,
            RootDeletePreparationSourceModelsV3::receiving_demand_v3(&self.readers[2])
                .map_err(|cause| cause.into()),
        )?;
        self.sample_once_v4(8, inputs);
        self.require_primary_v4()?;
        self.source_result = Some(self.source_models.observe_terminal_once_v4(
            &self.readers[2],
            aos_sandbox_core::OperationId::from_bytes(query.operation),
            inputs.batch.bytes_for_graph_comparison_v2()?,
            &frame.controller,
            &frame.source,
            inputs.current.accepted_source_models_v4()?,
            frame.physical.commitment_v4()?,
        ));
        if !matches!(self.source_result, Some(Ok(()))) {
            self.first = Some(First::SourceModels);
        }
        self.require_primary_v4()?;
        let request = query.encode_for_purpose_v3(SourcePurpose::Terminal4)?;
        self.transport_result =
            Some(
                self.transport
                    .run_once_v1(ids[3], ids[1], &request, query.cutoff),
            );
        if !matches!(self.transport_result, Some(Ok(()))) {
            self.first = Some(First::Signature);
        }
        self.sample_once_v4(9, inputs);
        self.require_primary_v4()?;
        self.reply = Some((|| {
            let wire = self.transport.frame_v1();
            if &wire[..8] != SourcePurpose::Terminal4.reply_magic_v3() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let reply = SourceDeleteCurrentReplyDataV1::decode_for_purpose_v3(
                &wire[8..],
                SourcePurpose::Terminal4,
            )?;
            let signer = flight.delete_source_signer_pin_v1()?;
            source::verify_source_signature_for_purpose_v3(
                wire,
                reply.signature,
                signer,
                SourcePurpose::Terminal4,
            )?;
            reply.fields.require_query_for_purpose_v3(
                query,
                signer.generation(),
                SourcePurpose::Terminal4,
            )?;
            source::require_fresh_interval_v1(
                *positive(&self.samples[8])?,
                *positive(&self.samples[9])?,
                reply.fields,
            )?;
            let native = self.readers[2].terminal_native_v1()?;
            let tree = aos_sandbox_ledger_replay::delete_pending::source_delete_tree_data_v1(
                native.state.iter().map(|((namespace, key), value)| {
                    (*namespace, key.as_slice(), value.as_slice())
                }),
                aos_sandbox_core::ProjectId::from_bytes(query.project),
            )?;
            if reply.fields.pending_native != frame.source
                || reply.fields.names != native.names
                || (reply.fields.next, reply.fields.end) != (native.next, native.end)
                || (
                    reply.fields.tree_generation,
                    reply.fields.tree_commitment,
                    reply.fields.tree_head,
                    reply.fields.lineage_head,
                ) != (tree.generation, tree.commitment, tree.head, tree.lineage)
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            Ok(reply)
        })());
        if !matches!(self.reply, Some(Ok(_))) {
            self.first = Some(First::Signature);
        }
        self.require_primary_v4()?;
        self.compared = Some((|| {
            inputs.mount.compare_completed_resource_outcome_v4(
                self.sessions[0].completed_cleanup_outcome_v4()?,
                frame.physical.mount,
                query.cutoff,
            )?;
            inputs.storage.compare_completed_resource_outcome_v4(
                self.sessions[1].completed_cleanup_outcome_v4()?,
                frame.physical.storage,
                query.cutoff,
            )?;
            Ok(())
        })());
        if !matches!(self.compared, Some(Ok(()))) {
            self.first = Some(First::Comparison);
        }
        self.require_primary_v4()?;
        self.ack = frame.acknowledgement_digest_v4()?;
        let mut stream = original;
        self.ack_result = Some(self.ack_io.run_once(
            &mut stream,
            &mut self.ack,
            query.cutoff,
            DeadlineStreamDirectionV1::Write,
        ));
        if !matches!(self.ack_result, Some(Ok(()))) || !self.ack_io.completed_exact() {
            self.first = Some(First::Ack);
        }
        self.require_primary_v4()
    }

    fn fixed_demand_v4() -> Result<ResourceVector, Cause> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(544 * 3 + Q * 3 + A * 3))
            .and_then(|bytes| {
                bytes.checked_add(
                    RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?
                        .checked_mul(CLOCKS)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    3 * std::mem::size_of::<sha2::Sha256>()
                        + 3 * std::mem::size_of::<blake3::Hasher>(),
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(CLOCKS))
            .and_then(|names| u64::try_from(names).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(Reader::mount_session_fixed_demand_v2()?.checked_add(Reader::fixed_demand_v1()?)?
            .checked_add(Reader::source_current_fixed_demand_v1()?)?
            .checked_add(RootDeleteChunkPostsV1::fixed_demand_v1()?)?
            .checked_add(crate::policy_compiler::root_subject_chunk::RootSubjectChunkReceivingV1::delete_receiving_demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::MetadataEntries, names + 2)
                .with(D::OpenFiles, 1 + CLOCKS as u64 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
                .with(D::NetworkBytes, (544 + Q + A + 32 + 2) as u64).with(D::OutputBytes, (Q + 32) as u64))?)
    }

    fn admit_v4(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        phase: RootDeleteCompletionPhaseV4,
        demand: Result<ResourceVector, Cause>,
    ) -> Result<(), Cause> {
        let index = phase.index_v4();
        self.phase = Some(phase);
        self.demands[index] = Some(demand);
        if !matches!(self.demands[index], Some(Ok(_))) {
            self.first = Some(First::Geometry(index));
        }
        self.require_primary_v4()?;
        self.permits[index] = Some(flight.admit_delete_completion_once_v4(self));
        if !matches!(self.permits[index], Some(Ok(()))) {
            self.first = Some(First::Funding(index));
        }
        self.require_primary_v4()
    }

    fn sample_once_v4(&mut self, index: usize, inputs: &CompletionInputsV4<'_>) {
        self.samples[index] = Some(self.clocks[index].observe_once(None));
        self.times[index] = Some((|| {
            let sample = *positive(&self.samples[index])?;
            if let Some(prior) = self.latest {
                prior.validate_later_sample(sample)?;
            }
            self.latest = Some(sample);
            inputs.challenge.require_current_clock_v1(sample)?;
            inputs.mount.require_cleanup_sample_v4(sample)?;
            inputs.storage.require_cleanup_sample_v4(sample)?;
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

    pub(super) fn require_completed_v4(&self) -> Result<(), RootDeleteErrorV1> {
        if self.complete && self.first.is_none() && self.failure().is_none() {
            Ok(())
        } else {
            Err(RootDeleteErrorV1::Original)
        }
    }

    pub(super) fn acknowledgement_digest_v4(&self) -> Result<[u8; 32], RootDeleteErrorV1> {
        self.require_completed_v4()?;
        if !self.ack_io.completed_exact() || !self.request_eof.completed_exact() {
            return Err(RootDeleteErrorV1::Original);
        }
        Ok(self.ack)
    }

    pub(crate) fn funding_failed_v4(&self) -> bool {
        matches!(self.first, Some(First::Funding(_)))
            || matches!(self.first, Some(First::Posts)) && self.posts.funding_failed_v1()
    }

    pub(crate) fn property_failure_view_v4(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(First::Posts)) {
            self.posts.property_failure_view_v1(self.failure()?)
        } else {
            None
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match self.first? {
            First::Geometry(index) => self.demands[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
            First::Funding(index) => cause(&self.permits[index]),
            First::Posts => self
                .posts
                .before_failure_v1()
                .or_else(|| self.posts.after_failure_v1())
                .or_else(|| cause(&self.arm))
                .or_else(|| cause(&self.before))
                .or_else(|| cause(&self.after)),
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
            First::Frame => self
                .message
                .failure()
                .or_else(|| cause(&self.received))
                .or_else(|| cause(&self.frame))
                .or_else(|| self.request_eof.failure())
                .or_else(|| cause(&self.request_end)),
            First::Ack => self.ack_io.failure().or_else(|| cause(&self.ack_result)),
            First::Native(index) => self.readers[index]
                .failure()
                .or_else(|| cause(&self.native[index])),
            First::Models(index) => self.sessions[index]
                .failure()
                .or_else(|| cause(&self.models[index])),
            First::SourceModels => self
                .source_models
                .failure()
                .or_else(|| cause(&self.source_result)),
            First::Signature => self
                .transport
                .failure()
                .or_else(|| cause(&self.transport_result))
                .or_else(|| {
                    self.reply
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref())
                }),
            First::Comparison => self
                .compared
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref()),
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

fn positive<T, E: StdError + 'static>(slot: &Option<Result<T, E>>) -> Result<&T, Cause> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or_else(|| RootDeleteErrorV1::Original.into())
}
