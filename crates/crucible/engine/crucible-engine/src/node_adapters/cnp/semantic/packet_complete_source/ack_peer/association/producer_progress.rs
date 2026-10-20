//! Retains real restored Producer attempts beside immutable first-observe ancestry.
//!
//! Every SDK request and typed/raw/report partial belongs to this Source before
//! it can fail. A verified post-retirement checkpoint is distinct from the old
//! held Commit and the first Observe. Neither DTOs nor row equality grant work.

use super::restoration_observation::OriginalSourceRestorationObservationConstructionData;
use super::*;
use crate::node_admission::{
    OriginalInstalledRestorationObservationSigningInputs, ProducerExecutionPhase,
};
use crate::node_admission::{
    OriginalRestoredProducerExecutionClaim, OriginalRestoredProducerExecutionConstructionData,
};
use crate::node_contract::{NodeRuntime, OperationAdmission, OperationOutcome, RuntimeError};
use crucible_node_format::{Bytes, Extensions, Id, Position, U64, Validate, canonical};
use crucible_node_transport::{bodies::*, client::OriginalRestoredSuffixBody};
use crucible_node_transport::{
    bodies::{BeginRequest, ExactRunArguments, ObserveRequest, PollRequest, RetireRequest},
    client::OriginalRestoredSuffixHostAttempt,
    reference_packet::{
        control::{PacketNative5UnderlyingRecord, PacketNativeRecord},
        service::{
            PacketNative5SourceLaunch,
            complete_restore::{PacketNativeRestoredRecord, producer_progress::*},
        },
    },
};
use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    mem::size_of,
    thread::ThreadId,
};

#[path = "producer_progress/capture.rs"]
pub(super) mod capture;
#[path = "producer_progress/checkpoint_cache17.rs"]
mod checkpoint_cache17;
#[path = "producer_progress/construction.rs"]
mod construction;
#[path = "producer_progress/deferred.rs"]
mod deferred;
#[path = "producer_progress/effect.rs"]
mod effect;
#[path = "producer_progress/owner.rs"]
mod owner;
#[path = "producer_progress/projection.rs"]
mod projection;
#[path = "producer_progress/proof.rs"]
mod proof;
#[path = "producer_progress/publication.rs"]
mod publication;
#[path = "producer_progress/read.rs"]
mod read;
#[path = "producer_progress/sdk.rs"]
mod sdk;

pub(crate) use capture::OriginalSourceRestoredProducerHistory17Read;
pub(crate) use proof::OriginalSourceRestoredProducerPhaseCompletion;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Started,
    Begun,
    Completed,
    Durable,
    Retired,
    Verified,
    Failed,
}

struct ProducerProgressAttempt {
    row: OriginalRestoredProducerExecutionConstructionData,
    slot: usize,
    admission: Option<OperationAdmission>,
    authorization: Option<crate::node_scheduling::InputPayload>,
    arguments: Option<ExactRunArguments>,
    begin_body: Option<BeginRequest>,
    poll_body: Option<PollRequest>,
    retire_body: Option<RetireRequest>,
    observe_body: Option<ObserveRequest>,
    begin: Option<OriginalRestoredSuffixHostAttempt>,
    poll: Option<OriginalRestoredSuffixHostAttempt>,
    retire: Option<OriginalRestoredSuffixHostAttempt>,
    observe: Option<OriginalRestoredSuffixHostAttempt>,
    uploads: Vec<Option<OriginalRestoredSuffixHostAttempt>>,
    upload_bodies: Vec<UploadBody>,
    request_ids: Vec<Id>,
    record_values: [Option<serde_json::Value>; 4],
    record_canonical: [Vec<u8>; 4],
    completed_record: Option<PacketNativeRestoredRecord>,
    completed_producer: Option<PacketNative5UnderlyingRecord>,
    completed_measurement: Option<ContentRef>,
    outcome: Option<OperationOutcome>,
    report_value: Option<serde_json::Value>,
    report_bytes: Vec<u8>,
    report_reference: Option<ContentRef>,
    durable_root: RefCell<Option<ContentRef>>,
    consumption: Option<crate::node_scheduling::InputPayload>,
    consumption_value: Option<serde_json::Value>,
    checkpoint_record: Option<PacketNativeRestoredRecord>,
    checkpoint_producer: Option<PacketNative5UnderlyingRecord>,
    checkpoint_measurement: Option<ContentRef>,
    scheduling: Option<crate::node_scheduling::NativeSchedulingObservation>,
    previous: [u8; 32],
    signature: Option<[u8; 32]>,
    stage: Cell<Stage>,
}

pub(super) struct ProducerProgressHistory {
    process: u32,
    thread: ThreadId,
    failed: bool,
    attempts: Vec<ProducerProgressAttempt>,
}

impl ProducerProgressHistory {
    pub(super) fn new() -> Self {
        Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            failed: false,
            attempts: Vec::new(),
        }
    }

    fn origin_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn is_used_data(&self) -> bool {
        self.failed || !self.attempts.is_empty() || self.attempts.capacity() != 0
    }

    fn require_verified_prefix_data(&self) -> Result<(), RuntimeError> {
        self.origin_data()?;
        if self.failed
            || self
                .attempts
                .last()
                .is_some_and(|attempt| attempt.stage.get() != Stage::Verified)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    fn checkpoint_data<'a>(
        &'a self,
        original: &'a OriginalAckPeerAssociation,
    ) -> Result<
        (
            &'a PacketNativeRestoredRecord,
            &'a PacketNativeRecord,
            &'a ContentRef,
        ),
        RuntimeError,
    > {
        self.require_verified_prefix_data()?;
        match self.attempts.last() {
            Some(attempt) => {
                let PacketNative5UnderlyingRecord::Producer(producer) = attempt
                    .checkpoint_producer
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                else {
                    return Err(RuntimeError::UnsupportedFacet);
                };
                Ok((
                    attempt
                        .checkpoint_record
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    producer,
                    attempt
                        .checkpoint_measurement
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                ))
            }
            None => original
                .restoration_observation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .original_producer_checkpoint_data(),
        }
    }
}

enum UploadBody {
    Begin(BlobBeginRequest),
    Chunk(BlobChunkRequest),
    Finish(BlobFinishRequest),
}

impl UploadBody {
    fn body_data(&self) -> OriginalRestoredSuffixBody<'_> {
        match self {
            Self::Begin(body) => OriginalRestoredSuffixBody::BlobBegin(body),
            Self::Chunk(body) => OriginalRestoredSuffixBody::BlobChunk(body),
            Self::Finish(body) => OriginalRestoredSuffixBody::BlobFinish(body),
        }
    }
}

struct AttemptGuard<'a> {
    history: &'a RefCell<ProducerProgressHistory>,
    completed: std::cell::Cell<bool>,
}

impl<'a> AttemptGuard<'a> {
    fn new(history: &'a RefCell<ProducerProgressHistory>) -> Self {
        Self {
            history,
            completed: std::cell::Cell::new(false),
        }
    }

    fn complete_data(&self) {
        self.completed.set(true);
    }
}

impl Drop for AttemptGuard<'_> {
    fn drop(&mut self) {
        if !self.completed.get()
            && let Ok(mut history) = self.history.try_borrow_mut()
            && let Some(attempt) = history.attempts.last_mut()
            && attempt.stage.get() != Stage::Verified
        {
            attempt.stage.set(Stage::Failed);
            history.failed = true;
        }
    }
}

pub(crate) use capture::{
    OriginalSourceRestoredFirstObservationHistory17Read, OriginalSourceRestoredInstallation17,
    OriginalSourceRestoredInstallationExpected17, OriginalSourceRestoredLimits17,
    OriginalSourceRestoredProducerCheckpoint17, OriginalSourceRestoredSettled17DecodeAttempt,
    OriginalSourceRestoredSettled17Prelude, OriginalSourceRestoredSettled17Read,
    OriginalSourceRestoredSettled17ReadInputs,
};

pub(crate) use capture::{
    OriginalSourceRestoredCaptureCompletion, OriginalSourceRestoredCaptureQuoteInputs,
};

pub(crate) use capture::OriginalSourceRestoredCaptureEncodingInputs;

pub(crate) use capture::OriginalSourceRestoredCaptureCountingBanksData;

#[path = "producer_progress/checkpoint17.rs"]
mod checkpoint17;
#[path = "producer_progress/typed_checkpoint17.rs"]
mod typed_checkpoint17;

pub use capture::OriginalSourceRestoredCaptureConstructionData;
