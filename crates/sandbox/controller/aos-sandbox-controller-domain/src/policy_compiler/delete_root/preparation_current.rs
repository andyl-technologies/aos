//! Independently verifies the actual post26 C, Source and Storage successor.
//!
//! The same retained D funds every native, semantic, model and signed-current
//! frontier. Preparatory192 supplies no destruction permission: this complete
//! original must precede construction of a new catalog-bound Destroy7 plan.

mod source_models;

use super::*;
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{DeleteAdmissionAuditInputsDataV3, JournalError};
use crate::policy_compiler::{
    RetainedKernelPairedClockAttemptV1,
    create_storage_current::controller_readonly::native_read::RootFixedNativeReadOriginalsV1,
    source_signer_transport::{RootSourceSignerTransportOriginalsV1, RootSourceTransportClosedV1},
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_batch::LifecycleDeleteBatchRecordV1;
use aos_sandbox_protocol::domain_ledger::delete_root::{
    preparation_current::{
        DELETE_ROOT_PREPARATION_CURRENT_BYTES_V3, DeleteRootPreparationCurrentDataV3,
        DeleteRootPreparationCurrentErrorV3,
    },
    source_current::{
        SOURCE_DELETE_CURRENT_QUERY_BYTES_V1, SOURCE_DELETE_CURRENT_REPLY_BYTES_V1,
        SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3, SourceDeleteCurrentDataErrorV1,
        SourceDeleteCurrentPurposeDataV3, SourceDeleteCurrentQueryDataV1,
        SourceDeleteCurrentReplyDataV1,
    },
    transport::{DeleteRootChallengeDataV2, DeleteRootOpenDataV2},
};
use body::message::RootDeleteMessageReceivingV2;
use controller::sessions::model::DeleteSessionModelsOriginalV2;
pub(super) use source_models::RootDeletePreparationSourceModelsV3;

type Cause = Box<dyn StdError>;
const CLOCKS: usize = 15;
const PHASES: usize = 12;

/// Names the twelve finite stages of the same post26 Root comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootDeletePreparationCurrentPhaseV3 {
    ControllerFixed,
    ControllerNative,
    ControllerSemantic,
    SourceFixed,
    SourceNative,
    SourceSemantic,
    SourceModels,
    SourceSignature,
    StorageFixed,
    StorageNative,
    StorageModels,
    Comparison,
}

impl RootDeletePreparationCurrentPhaseV3 {
    pub(crate) const fn index_v3(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy)]
enum CurrentFirst {
    Geometry(usize),
    Funding(usize),
    Arm,
    Before,
    Clock(usize),
    Frame,
    Decode,
    Binding,
    Query,
    Controller,
    Source,
    SourceModels,
    SourceSignature,
    Storage,
    StorageModels,
    Comparison,
    Primary,
    After,
    Reentry,
}

pub(crate) struct RootDeletePreparationCurrentOriginalV3 {
    phase: Option<RootDeletePreparationCurrentPhaseV3>,
    demands: [Option<Result<ResourceVector, Cause>>; PHASES],
    permits: [Option<Result<(), ResourceReservationErrorV1>>; PHASES],
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; CLOCKS],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; CLOCKS],
    times: [Option<Result<(), Cause>>; CLOCKS],
    latest: Option<RawPairedClockSample>,
    frame: RootDeleteMessageReceivingV2,
    received: Option<Result<(), RootDeleteErrorV1>>,
    decoded:
        Option<Result<DeleteRootPreparationCurrentDataV3, DeleteRootPreparationCurrentErrorV3>>,
    binding: Option<Result<(), Cause>>,
    controller: RootFixedNativeReadOriginalsV1,
    source: RootFixedNativeReadOriginalsV1,
    storage: RootFixedNativeReadOriginalsV1,
    native: [Option<Result<(), JournalError>>; 3],
    planned: Option<Result<LifecycleDeleteBatchRecordV1, Box<dyn StdError + Send + Sync>>>,
    committed: Option<
        Result<
            LifecycleDeleteBatchRecordV1,
            aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError,
        >,
    >,
    query: Option<Result<SourceDeleteCurrentQueryDataV1, Cause>>,
    query_bytes:
        Option<Result<[u8; SOURCE_DELETE_CURRENT_QUERY_BYTES_V1], SourceDeleteCurrentDataErrorV1>>,
    source_models: RootDeletePreparationSourceModelsV3,
    source_models_result: Option<Result<(), JournalError>>,
    transport: RootSourceSignerTransportOriginalsV1<
        SOURCE_DELETE_CURRENT_QUERY_BYTES_V1,
        SOURCE_DELETE_CURRENT_REPLY_BYTES_V1,
    >,
    transport_result: Option<Result<(), RootSourceTransportClosedV1>>,
    reply: Option<Result<SourceDeleteCurrentReplyDataV1, SourceDeleteCurrentDataErrorV1>>,
    signature: Option<Result<(), ed25519_dalek::SignatureError>>,
    signed_comparison: Option<Result<(), Cause>>,
    storage_models: DeleteSessionModelsOriginalV2,
    storage_models_result: Option<Result<(), JournalError>>,
    compared: Option<Result<aos_sandbox_protocol::semantics::CatalogBindingV1, Cause>>,
    primary: Option<Result<(), Cause>>,
    native_entered: bool,
    entered: bool,
    complete: bool,
    first: Option<CurrentFirst>,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeletePreparationCurrentOriginalV3 {
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
            binding: None,
            controller: RootFixedNativeReadOriginalsV1::controller_current_v1(),
            source: RootFixedNativeReadOriginalsV1::source_current_v1(),
            storage: Default::default(),
            native: std::array::from_fn(|_| None),
            planned: None,
            committed: None,
            query: None,
            query_bytes: None,
            source_models: Default::default(),
            source_models_result: None,
            transport: Default::default(),
            transport_result: None,
            reply: None,
            signature: None,
            signed_comparison: None,
            storage_models: Default::default(),
            storage_models_result: None,
            compared: None,
            primary: None,
            native_entered: false,
            entered: false,
            complete: false,
            first: None,
            closed: None,
        }
    }
}

// Every reference below is an actual retained predecessor in the same enclosing
// D receiver. This private grouping supplies no standalone constructor or grant.
pub(super) struct CurrentInputsV3<'a> {
    pub(super) challenge: &'a RootDeleteChallengeOriginalsV1,
    pub(super) batch: &'a body::RootDeleteBatchReceivingV1,
    pub(super) controller: &'a RootDeleteControllerCurrentOriginalV1,
    pub(super) source: &'a RootDeleteSourceCurrentOriginalV1,
    pub(super) approval: &'a RootDeletePreparatoryApprovalOriginalV3,
    pub(super) policy: &'a RootDeleteResourcePolicyOriginalV2,
    pub(super) inputs: &'a RootDeleteCleanupInputsOriginalV2,
    pub(super) preparation: &'a RootDeleteResourcePreparationOriginalV2,
    pub(super) draft: &'a RootDeleteResourceDraftOriginalV2,
    pub(super) signature: &'a RootDeleteResourceSignatureOriginalV2,
    pub(super) opening: DeleteRootOpenDataV2,
}

impl RootDeletePreparationCurrentOriginalV3 {
    pub(crate) fn admission_phase_v3(
        &self,
    ) -> Result<RootDeletePreparationCurrentPhaseV3, ResourceReservationErrorV1> {
        let phase = self.phase.ok_or(ResourceReservationErrorV1::Conflict)?;
        let index = phase.index_v3();
        if !self.entered
            || self.first.is_some()
            || self.permits[index].is_some()
            || !matches!(self.demands[index], Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(phase)
    }

    pub(crate) fn receiving_demand_v3(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.demands[self.admission_phase_v3()?.index_v3()]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn observe_once_v3(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        inputs: CurrentInputsV3<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(CurrentFirst::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.primary = Some(self.observe_inner_v3(flight, original, &inputs));
        self.select_primary_before_posts_v3();
        // Every reached native reader owns independent name/mount/length posts.
        // Neither a later payer refusal nor a failed model suppresses them.
        for (index, reader) in [&mut self.controller, &mut self.source, &mut self.storage]
            .into_iter()
            .enumerate()
        {
            reader.finish_post_once();
            if reader.post_failure().is_some() {
                self.first.get_or_insert(match index {
                    0 => CurrentFirst::Controller,
                    1 => CurrentFirst::Source,
                    _ => CurrentFirst::Storage,
                });
            }
        }
        if self.native_entered {
            self.after = Some(self.posts.observe_after_once_v1(flight, inputs.challenge));
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(CurrentFirst::After);
            }
            self.sample_once_v3(12, &inputs);
        }
        self.complete = matches!(self.primary, Some(Ok(())))
            && self.first.is_none()
            && matches!(self.compared, Some(Ok(_)))
            && self.failure().is_none();
        if self.complete {
            Ok(())
        } else {
            Err(RootDeleteErrorV1::Opening)
        }
    }

    fn select_primary_before_posts_v3(&mut self) {
        if self.primary.as_ref().is_some_and(Result::is_err) {
            // A propagated inner error predates every independently owed post.
            // Preserve it even when that frontier has no specialized marker.
            self.first.get_or_insert(CurrentFirst::Primary);
        }
    }

    fn observe_inner_v3(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        inputs: &CurrentInputsV3<'_>,
    ) -> Result<(), Cause> {
        use RootDeletePreparationCurrentPhaseV3 as P;
        self.admit_v3(
            flight,
            inputs,
            P::ControllerFixed,
            Self::fixed_demand_v3(inputs),
        )?;
        self.native_entered = true;
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(inputs.challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(CurrentFirst::Arm);
        }
        self.sample_once_v3(0, inputs);
        self.before = Some(self.posts.observe_before_once_v1(flight, inputs.challenge));
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(CurrentFirst::Before);
        }
        self.require_primary_v3()?;
        self.received = Some(self.frame.receive_continuation_once_v2(
            flight,
            original,
            inputs.challenge,
            DELETE_ROOT_PREPARATION_CURRENT_BYTES_V3,
        ));
        if !matches!(self.received, Some(Ok(()))) {
            self.first = Some(CurrentFirst::Frame);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.decoded = Some(DeleteRootPreparationCurrentDataV3::decode_v3(
            self.frame.bytes_v2()?,
        ));
        if !matches!(self.decoded, Some(Ok(_))) {
            self.first = Some(CurrentFirst::Decode);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.binding = Some((|| {
            let frame = *positive(&self.decoded)?;
            let challenge =
                DeleteRootChallengeDataV2::decode_v2(inputs.challenge.challenge_bytes_v1()?)?;
            let draft = inputs.draft.draft_data_v2(inputs.preparation)?;
            let signature = inputs.signature.signed_data_v3()?;
            if frame.challenge != challenge.source.nonce
                || frame.opening != challenge.open
                || frame.draft != *signature.draft
                || frame.draft != draft.digest_v2()?
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            Ok(())
        })());
        if !matches!(self.binding, Some(Ok(()))) {
            self.first = Some(CurrentFirst::Binding);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        let frame = *positive(&self.decoded)?;
        self.planned = Some(inputs.source.planned_batch_data_v3());
        if !matches!(self.planned, Some(Ok(_))) {
            self.first = Some(CurrentFirst::Query);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.committed =
            Some(positive(&self.planned)?.controller_committed_data_v3(&frame.controller));
        if !matches!(self.committed, Some(Ok(_))) {
            self.first = Some(CurrentFirst::Query);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.query = Some((|| {
            let mut query = inputs.challenge.source_query_v1()?;
            let encoded = positive(&self.committed)?.encode()?;
            query.batch = aos_sandbox_protocol::domain_ledger::delete_root::source_current::source_delete_controller_committed_batch_digest_v3(&encoded)?;
            Ok(query)
        })());
        if !matches!(self.query, Some(Ok(_))) {
            self.first = Some(CurrentFirst::Query);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        let query = *positive(&self.query)?;
        self.sample_once_v3(14, inputs);
        self.require_primary_v3()?;
        self.controller
            .prepare_delete_accepted_observation_v3(frame.controller)?;
        let uid = flight
            .delete_cut_startup_v1()?
            .native_startup_original_v1()
            .fields()
            .profile
            .identities[0];
        self.controller.capture_once(uid);
        self.admit_v3(
            flight,
            inputs,
            P::ControllerNative,
            (|| {
                self.controller
                    .replay_demand_v1()?
                    .checked_add(self.controller.delete_admission_comparison_demand_v3(
                        inputs.batch.bytes_for_graph_comparison_v2()?,
                        inputs.controller.verified_authorized_input_v2()?,
                    )?)
                    .map_err(|cause| Box::new(cause) as Cause)
            })(),
        )?;
        self.sample_once_v3(1, inputs);
        self.require_primary_v3()?;
        self.controller.prepare_delete_admission_comparison_v3(
            DeleteAdmissionAuditInputsDataV3 {
                native: frame.controller,
                batch: inputs.batch.bytes_for_graph_comparison_v2()?.to_vec(),
                input: inputs.controller.verified_authorized_input_v2()?.to_vec(),
                fields: inputs.controller.verified_authorization_fields_v3()?,
                opening: inputs.opening,
                authorization: inputs.controller.verified_authorization_cut_data_v2()?,
            },
        )?;
        self.controller.audit_once();
        self.admit_v3(
            flight,
            inputs,
            P::ControllerSemantic,
            self.controller
                .additional_delete_preparation_semantic_demand_v3()
                .map_err(|cause| cause.into()),
        )?;
        self.sample_once_v3(2, inputs);
        self.require_primary_v3()?;
        self.controller.replay_once();
        self.controller.finish_post_once();
        self.native[0] = Some(
            self.controller
                .delete_preparation_native_data_v3()
                .map(|_| ()),
        );
        if !matches!(self.native[0], Some(Ok(()))) {
            self.first = Some(CurrentFirst::Controller);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.admit_v3(
            flight,
            inputs,
            P::SourceFixed,
            Ok(RootFixedNativeReadOriginalsV1::source_current_fixed_demand_v1()?),
        )?;
        self.sample_once_v3(3, inputs);
        self.require_primary_v3()?;
        self.source.prepare_delete_current_observation_v3(query)?;
        self.source.capture_once(uid);
        self.admit_v3(
            flight,
            inputs,
            P::SourceNative,
            self.source.replay_demand_v1().map_err(|cause| cause.into()),
        )?;
        self.sample_once_v3(4, inputs);
        self.require_primary_v3()?;
        self.source.audit_once();
        self.admit_v3(
            flight,
            inputs,
            P::SourceSemantic,
            self.source
                .additional_delete_preparation_semantic_demand_v3()
                .map_err(|cause| cause.into()),
        )?;
        self.sample_once_v3(5, inputs);
        self.require_primary_v3()?;
        self.source.replay_once();
        self.source.finish_post_once();
        self.native[1] = Some(
            self.source
                .delete_preparation_native_data_v3()
                .and_then(|actual| {
                    if actual == frame.source {
                        Ok(())
                    } else {
                        Err(JournalError::StaleAuthoritySnapshot)
                    }
                }),
        );
        if !matches!(self.native[1], Some(Ok(()))) {
            self.first = Some(CurrentFirst::Source);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.admit_v3(
            flight,
            inputs,
            P::SourceModels,
            RootDeletePreparationSourceModelsV3::receiving_demand_v3(&self.source)
                .map_err(|cause| cause.into()),
        )?;
        self.sample_once_v3(6, inputs);
        self.require_primary_v3()?;
        self.source_models_result = Some(self.source_models.observe_once_v3(
            &self.source,
            aos_sandbox_model::OperationId::from_bytes(query.operation),
            inputs.batch.bytes_for_graph_comparison_v2()?,
            &frame.controller,
            &frame.source,
        ));
        if !matches!(self.source_models_result, Some(Ok(()))) {
            self.first = Some(CurrentFirst::SourceModels);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.admit_v3(flight, inputs, P::SourceSignature, Ok(ResourceVector::ZERO))?;
        self.sample_once_v3(7, inputs);
        self.require_primary_v3()?;
        self.verify_source_signature_v3(flight, inputs, query)?;
        self.admit_v3(
            flight,
            inputs,
            P::StorageFixed,
            Ok(RootFixedNativeReadOriginalsV1::fixed_demand_v1()?),
        )?;
        self.sample_once_v3(8, inputs);
        self.require_primary_v3()?;
        self.storage
            .prepare_delete_preparation_session_observation_v3(frame.session)?;
        self.storage.capture_once(uid);
        self.admit_v3(
            flight,
            inputs,
            P::StorageNative,
            self.storage
                .replay_demand_v1()
                .map_err(|cause| cause.into()),
        )?;
        self.sample_once_v3(9, inputs);
        self.require_primary_v3()?;
        self.storage.replay_once();
        self.storage.finish_post_once();
        self.native[2] = Some(self.storage.delete_preparation_native_data_v3().map(|_| ()));
        if !matches!(self.native[2], Some(Ok(()))) {
            self.first = Some(CurrentFirst::Storage);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        let storage = self.storage.terminal_native_v1()?;
        let extent = usize::try_from(storage.end).map_err(|_| JournalError::JournalTooLarge)?;
        let packet_demand = (|| -> Result<ResourceVector, Cause> {
            let body = inputs
                .preparation
                .preparation_data_v2()?
                .deadline_free_body_v2()
                .len();
            let bytes = body
                .checked_add(32)
                .and_then(|bytes| bytes.checked_mul(4))
                .and_then(|bytes| {
                    bytes.checked_add(
                        3 * std::mem::size_of::<
                            aos_sandbox_api::aos::sandbox::local::v1::PrepareStorageCatalogRequest,
                        >(),
                    )
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            Ok(
                DeleteSessionModelsOriginalV2::preparation_packet_demand_v3(extent)?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?,
            )
        })();
        self.admit_v3(flight, inputs, P::StorageModels, packet_demand)?;
        self.sample_once_v3(10, inputs);
        self.require_primary_v3()?;
        self.storage_models_result = Some(self.storage_models.observe_preparation_packets_once_v3(
            self.storage.terminal_native_v1()?,
            self.storage.completed_delete_storage_history_rows_v3()?,
            inputs.controller.broker_manifests_v2()?.2,
            query.cutoff,
            query.boot,
        ));
        if !matches!(self.storage_models_result, Some(Ok(()))) {
            self.first = Some(CurrentFirst::StorageModels);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.admit_v3(flight, inputs, P::Comparison, Ok(ResourceVector::ZERO))?;
        self.sample_once_v3(11, inputs);
        self.require_primary_v3()?;
        self.compared = Some(self.compare_completed_v3(inputs));
        if !matches!(self.compared, Some(Ok(_))) {
            self.first = Some(CurrentFirst::Comparison);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        Ok(())
    }

    fn fixed_demand_v3(inputs: &CurrentInputsV3<'_>) -> Result<ResourceVector, Cause> {
        inputs.approval.require_completed_v3()?;
        let width = inputs.batch.bytes_for_graph_comparison_v2()?.len();
        let batch = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::decode_receiving_bytes_v1(width)
            .and_then(|bytes| bytes.checked_mul(6)).ok_or(JournalError::JournalTooLarge)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(batch))
            .and_then(|bytes| {
                bytes.checked_add(
                    RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?
                        .checked_mul(CLOCKS)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3)
            })
            // Same concrete transport's bounded pathname/error backing, shared
            // with the original fixed Source query recipe.
            .and_then(|bytes| bytes.checked_add(30 * 256))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let batch_names = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::nested_decode_metadata_entries_v1(width)
            .and_then(|count| count.checked_mul(6)).ok_or(JournalError::JournalTooLarge)?;
        let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|count| count.checked_mul(CLOCKS))
            .and_then(|count| count.checked_add(6))
            .and_then(|count| count.checked_add(batch_names))
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let fixed = RootDeleteChunkPostsV1::fixed_demand_v1()?
            .checked_add(crate::policy_compiler::root_subject_chunk::RootSubjectChunkReceivingV1::delete_receiving_demand_v1()?)?
            .checked_add(RootFixedNativeReadOriginalsV1::controller_current_fixed_demand_v1()?)?;
        Ok(fixed.checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, memory)
                .with(D::MetadataEntries, names)
                .with(
                    D::OpenFiles,
                    1 + CLOCKS as u64
                        * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
                )
                .with(
                    D::NetworkBytes,
                    (DELETE_ROOT_PREPARATION_CURRENT_BYTES_V3
                        + SOURCE_DELETE_CURRENT_QUERY_BYTES_V1
                        + SOURCE_DELETE_CURRENT_REPLY_BYTES_V1
                        + 1) as u64,
                )
                .with(D::OutputBytes, SOURCE_DELETE_CURRENT_QUERY_BYTES_V1 as u64),
        )?)
    }

    fn admit_v3(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        inputs: &CurrentInputsV3<'_>,
        phase: RootDeletePreparationCurrentPhaseV3,
        demand: Result<ResourceVector, Cause>,
    ) -> Result<(), Cause> {
        let index = phase.index_v3();
        self.phase = Some(phase);
        self.demands[index] = Some(demand);
        if !matches!(self.demands[index], Some(Ok(_))) {
            self.first.get_or_insert(CurrentFirst::Geometry(index));
            return Err(RootDeleteErrorV1::Opening.into());
        }
        self.permits[index] =
            Some(flight.admit_delete_preparation_current_once_v3(inputs.approval, self));
        if !matches!(self.permits[index], Some(Ok(()))) {
            self.first.get_or_insert(CurrentFirst::Funding(index));
            return Err(RootDeleteErrorV1::Opening.into());
        }
        Ok(())
    }

    fn sample_once_v3(&mut self, index: usize, inputs: &CurrentInputsV3<'_>) {
        self.samples[index] = Some(self.clocks[index].observe_once(None));
        self.times[index] = Some((|| {
            let sample = *positive(&self.samples[index])?;
            let prior = self.latest.unwrap_or(inputs.approval.completed_clock_v3()?);
            // Retain the actual last paid sample even when a later temporal
            // check refuses; independently owed samples compare that frontier.
            self.latest = Some(sample);
            prior.validate_later_sample(sample)?;
            inputs.challenge.require_current_clock_v1(sample)?;
            let signed = inputs.policy.verified_sources_v2()?;
            let lease = inputs.inputs.lease_v2()?;
            let plan = inputs
                .preparation
                .preparation_data_v2()?
                .preparation_v2()
                .plan_data_v1();
            if sample.wall_seconds() >= signed.0.head().expires_at()
                || sample.wall_seconds() >= signed.1.expires_at()
                || sample.wall_seconds() >= lease.authority_expires_seconds()
                || sample.wall_seconds() >= plan.expires_seconds()
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            Ok(())
        })());
        if !matches!(self.times[index], Some(Ok(()))) {
            self.first.get_or_insert(CurrentFirst::Clock(index));
        }
    }

    fn require_primary_v3(&self) -> Result<(), Cause> {
        if self.first.is_none() {
            Ok(())
        } else {
            Err(RootDeleteErrorV1::Opening.into())
        }
    }

    fn verify_source_signature_v3(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        inputs: &CurrentInputsV3<'_>,
        query: SourceDeleteCurrentQueryDataV1,
    ) -> Result<(), Cause> {
        let purpose = SourceDeleteCurrentPurposeDataV3::ControllerCommitted;
        self.query_bytes = Some(query.encode_for_purpose_v3(purpose));
        if !matches!(self.query_bytes, Some(Ok(_))) {
            self.first = Some(CurrentFirst::SourceSignature);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        let ids = flight
            .delete_cut_startup_v1()?
            .native_startup_original_v1()
            .fields()
            .profile
            .identities;
        self.transport_result = Some(self.transport.run_once_v1(
            ids[3],
            ids[1],
            positive(&self.query_bytes)?,
            query.cutoff,
        ));
        if !matches!(self.transport_result, Some(Ok(()))) {
            self.first.get_or_insert(CurrentFirst::SourceSignature);
        }
        self.sample_once_v3(13, inputs);
        self.require_primary_v3()?;
        self.reply = Some((|| {
            if &self.transport.frame_v1()[..8] != purpose.reply_magic_v3() {
                return Err(SourceDeleteCurrentDataErrorV1::Format);
            }
            SourceDeleteCurrentReplyDataV1::decode_for_purpose_v3(
                &self.transport.frame_v1()[8..],
                purpose,
            )
        })());
        let reply = match &self.reply {
            Some(Ok(reply)) => *reply,
            _ => {
                self.first = Some(CurrentFirst::SourceSignature);
                return Err(RootDeleteErrorV1::Opening.into());
            }
        };
        let signer = flight.delete_source_signer_pin_v1()?;
        self.signature = Some(source::verify_source_signature_for_purpose_v3(
            self.transport.frame_v1(),
            reply.signature,
            signer,
            purpose,
        ));
        self.signed_comparison = Some((|| {
            if !matches!(self.signature, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            reply
                .fields
                .require_query_for_purpose_v3(query, signer.generation(), purpose)?;
            source::require_fresh_interval_v1(
                *positive(&self.samples[7])?,
                *positive(&self.samples[13])?,
                reply.fields,
            )?;
            let native = self.source.terminal_native_v1()?;
            let frame = *positive(&self.decoded)?;
            let tree = aos_sandbox_ledger_replay::delete_pending::source_delete_tree_data_v1(
                native.state.iter().map(|((namespace, key), value)| {
                    (*namespace, key.as_slice(), value.as_slice())
                }),
                aos_sandbox_model::ProjectId::from_bytes(query.project),
            )?;
            if reply.fields.pending_native != frame.source
                || reply.fields.names != native.names
                || (reply.fields.next, reply.fields.end) != (native.next, native.end)
                || reply.fields.tree_generation != tree.generation
                || reply.fields.tree_commitment != tree.commitment
                || reply.fields.tree_head != tree.head
                || reply.fields.lineage_head != tree.lineage
            {
                return Err(JournalError::StaleAuthoritySnapshot.into());
            }
            Ok(())
        })());
        if !matches!(self.signature, Some(Ok(())))
            || !matches!(self.signed_comparison, Some(Ok(())))
        {
            self.first = Some(CurrentFirst::SourceSignature);
            return Err(RootDeleteErrorV1::Opening.into());
        }
        Ok(())
    }

    fn compare_completed_v3(
        &self,
        inputs: &CurrentInputsV3<'_>,
    ) -> Result<aos_sandbox_protocol::semantics::CatalogBindingV1, Cause> {
        self.controller.require_delete_admission_comparison_v3()?;
        let frame = *positive(&self.decoded)?;
        let outcome = self.storage_models.outcome_v2()?;
        let request = outcome.request();
        let actual = request
            .authorization()
            .ok_or(JournalError::ProtectedBoundary)?;
        let prepared = inputs.preparation.preparation_data_v2()?;
        let original = prepared.preparation_v2();
        let signature = inputs.signature.signed_data_v3()?;
        let lease = inputs.inputs.lease_v2()?;
        let query = *positive(&self.query)?;
        let body = aos_sandbox_protocol::dispatch_template::inject_deadline(
            prepared.deadline_free_body_v2(),
            query.cutoff,
        )?;
        if request.method() != prepared.method_v2()
            || request.exact_body() != body
            || actual.broker_plan() != original.canonical_plan()
            || actual.broker_plan_signature() != signature.canonical_signature
            || actual.ownership_lease() != lease.canonical_lease()
            || actual.ownership_lease_signature() != lease.canonical_signature()
            || request.deadline_boottime_nanoseconds() != query.cutoff
            || request.signed_request_digest() != frame.request
            || blake3::hash(outcome.canonical_packet()).as_bytes() != &frame.outcome
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        // Both same-native joins are complete before this passive catalog is
        // returned. A matching packet alone never supplies native authority.
        if self.storage.delete_preparation_native_data_v3()? != frame.session
            || self.source.delete_preparation_native_data_v3()? != frame.source
            || self.controller.delete_preparation_native_data_v3()? != frame.controller
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        let response = self.storage_models.preparation_response_data_v3()?;
        let digest = response
            .catalog_digest
            .as_slice()
            .try_into()
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?;
        Ok(
            aos_sandbox_protocol::semantics::CatalogBindingV1::from_publisher(
                response.catalog_generation,
                aos_sandbox_model::ObjectDigest::from_bytes(digest),
            )?,
        )
    }

    pub(crate) fn require_completed_v3(&self) -> Result<(), RootDeleteErrorV1> {
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

    pub(super) fn completed_frame_data_v3(&self) -> Result<DeleteRootPreparationCurrentDataV3, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        positive(&self.decoded).copied().map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn accepted_source_models_v4(&self) -> Result<&RootDeletePreparationSourceModelsV3, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        if !matches!(self.source_models_result, Some(Ok(()))) { return Err(RootDeleteErrorV1::Original); }
        Ok(&self.source_models)
    }

    pub(super) fn terminal_source_query_data_v4(&self) -> Result<SourceDeleteCurrentQueryDataV1, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        positive(&self.query).copied().map_err(|_| RootDeleteErrorV1::Original)
    }

    /// Borrows the same independently current Source rows and canonical replay.
    pub(super) fn completed_stop_source_data_v5(&self) -> Result<(
        aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
        &crate::lifecycle::LifecycleHistoricalReadOriginalV1,
    ), JournalError> {
        self.require_completed_v3().map_err(|_| JournalError::ProtectedBoundary)?;
        Ok((self.source.completed_rows_data_v3()?,
            self.accepted_source_models_v4().map_err(|_| JournalError::ProtectedBoundary)?
                .current_lifecycle_data_v5()?))
    }

    pub(super) fn current_assignment_rows_v3(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>, JournalError>
    {
        self.require_completed_v3().map_err(|_| JournalError::ProtectedBoundary)?;
        self.controller.completed_rows_data_v3()
    }

    pub(super) fn current_assignment_state_v3(&self)
        -> Result<&std::collections::BTreeMap<(crate::journal::RecordNamespace, Vec<u8>), Vec<u8>>, JournalError>
    {
        self.require_completed_v3().map_err(|_| JournalError::ProtectedBoundary)?;
        Ok(self.controller.terminal_native_v1()?.state)
    }

    pub(super) fn catalog_data_v3(
        &self,
    ) -> Result<aos_sandbox_protocol::semantics::CatalogBindingV1, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        positive(&self.compared)
            .copied()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn completed_clock_v3(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        positive(&self.samples[12])
            .copied()
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn funding_failed_v3(&self) -> bool {
        matches!(self.first, Some(CurrentFirst::Funding(_)))
            || matches!(self.first, Some(CurrentFirst::Arm | CurrentFirst::Before))
                && self.posts.funding_failed_v1()
            || matches!(self.first, Some(CurrentFirst::Frame))
                && self.frame.financial_failure_is_selected_v1()
    }

    pub(super) fn property_failure_view_v3(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            CurrentFirst::Arm | CurrentFirst::Before | CurrentFirst::After => {
                self.posts.property_failure_view_v1(self.failure()?)
            }
            CurrentFirst::Frame => self.frame.property_failure_view_v1(),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        let selected = match self.first {
            Some(CurrentFirst::Geometry(index)) => match index {
                1 | 2 => self.controller.failure(),
                4 | 5 => self.source.failure(),
                9 | 10 => self.storage.failure(),
                _ => None,
            }
            .or_else(|| {
                self.demands[index]
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .map(|e| e.as_ref())
            }),
            Some(CurrentFirst::Funding(index)) => cause(&self.permits[index]),
            Some(CurrentFirst::Arm | CurrentFirst::Before) => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.arm))
                .or_else(|| cause(&self.before)),
            Some(CurrentFirst::After) => {
                self.posts.after_failure_v1().or_else(|| cause(&self.after))
            }
            Some(CurrentFirst::Clock(index)) => self.clocks[index]
                .failure()
                .or_else(|| cause(&self.samples[index]))
                .or_else(|| {
                    self.times[index]
                        .as_ref()
                        .and_then(|r| r.as_ref().err())
                        .map(|e| e.as_ref())
                }),
            Some(CurrentFirst::Frame) => self.frame.failure().or_else(|| cause(&self.received)),
            Some(CurrentFirst::Decode) => cause(&self.decoded),
            Some(CurrentFirst::Binding) => self
                .binding
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e.as_ref()),
            Some(CurrentFirst::Query) => self
                .planned
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e.as_ref() as _)
                .or_else(|| cause(&self.committed))
                .or_else(|| {
                    self.query
                        .as_ref()
                        .and_then(|r| r.as_ref().err())
                        .map(|e| e.as_ref())
                }),
            Some(CurrentFirst::Controller) => self
                .controller
                .failure()
                .or_else(|| self.controller.post_failure())
                .or_else(|| cause(&self.native[0])),
            Some(CurrentFirst::Source) => self
                .source
                .failure()
                .or_else(|| self.source.post_failure())
                .or_else(|| cause(&self.native[1])),
            Some(CurrentFirst::Storage) => self
                .storage
                .failure()
                .or_else(|| self.storage.post_failure())
                .or_else(|| cause(&self.native[2])),
            Some(CurrentFirst::SourceModels) => self
                .source_models
                .failure()
                .or_else(|| cause(&self.source_models_result)),
            Some(CurrentFirst::StorageModels) => self
                .storage_models
                .failure()
                .or_else(|| cause(&self.storage_models_result)),
            Some(CurrentFirst::SourceSignature) => self
                .transport
                .failure()
                .or_else(|| cause(&self.transport_result))
                .or_else(|| cause(&self.query_bytes))
                .or_else(|| cause(&self.reply))
                .or_else(|| cause(&self.signature))
                .or_else(|| {
                    self.signed_comparison
                        .as_ref()
                        .and_then(|r| r.as_ref().err())
                        .map(|e| e.as_ref())
                }),
            Some(CurrentFirst::Comparison) => self
                .compared
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e.as_ref()),
            Some(CurrentFirst::Primary) => self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
            Some(CurrentFirst::Reentry) => self.closed.as_ref().map(|e| e as _),
            None => None,
        };
        selected.or_else(|| {
            self.primary
                .as_ref()
                .and_then(|r| r.as_ref().err())
                .map(|e| e.as_ref())
        })
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref()
        .and_then(|r| r.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

#[cfg(test)]
mod chronology_tests {
    use super::*;

    #[test]
    fn an_untagged_primary_retains_its_cause_across_a_failed_owed_post() {
        let mut owner = RootDeletePreparationCurrentOriginalV3::default();
        owner.primary = Some(Err(JournalError::StaleAuthoritySnapshot.into()));
        owner.select_primary_before_posts_v3();
        let primary = owner.failure().unwrap() as *const dyn StdError;

        owner.after = Some(Err(NormalRootStartupErrorV1::Service));
        owner.first.get_or_insert(CurrentFirst::After);

        assert!(matches!(owner.first, Some(CurrentFirst::Primary)));
        assert!(std::ptr::eq(primary, owner.failure().unwrap() as *const dyn StdError));
        assert!(matches!(owner.after, Some(Err(_))));
    }

    #[test]
    fn a_tagged_primary_keeps_its_more_specific_owner() {
        let mut owner = RootDeletePreparationCurrentOriginalV3::default();
        owner.first = Some(CurrentFirst::SourceSignature);
        owner.primary = Some(Err(JournalError::ProtectedBoundary.into()));

        owner.select_primary_before_posts_v3();

        assert!(matches!(owner.first, Some(CurrentFirst::SourceSignature)));
    }
}
