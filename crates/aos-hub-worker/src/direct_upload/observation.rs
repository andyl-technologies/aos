//! Value-free production observations of direct controls, queues and byte reads.
//!
//! These events describe effects at their actual runtime boundary. They are
//! diagnostics, not publication authority or provider qualification. A missing
//! finish after termination remains unknown; an ACK event records the local
//! queue acknowledgement invocation, not a durable provider delivery promise.
//!
//! ```text
//! direct_upload_observation {"version":1,"kind":"queue_start",...}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Largest encoded observation, including one bounded control batch.
pub(crate) const MAX_EVENT_BYTES: usize = 16 * 1024;

/// Names the actual control, queue or consumed-stream boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    ControlRequest,
    ControlReply,
    QueueEnqueue,
    QueueStart,
    QueueFinish,
    QueueAck,
    QueueRetry,
    ProviderReadStart,
    ProviderReadFinish,
}

/// Distinguishes Native metadata transport from provider source consumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    WorkerToNative,
    NativeToWorker,
    ProviderToWorker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Preserves the separate content and semantic verification queue classes.
pub(crate) enum QueueClass {
    Bulk,
    Metadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Prevents standalone storage reads from being labeled production deliveries.
pub(crate) enum Scope {
    NativeControl,
    ProductionQueue,
    StorageRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Separates full integrity consumption from bounded semantic rereads.
pub(crate) enum ReadKind {
    FullIntegrity,
    SemanticMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Identifies the closed payload category whose bytes were observed.
pub(crate) enum DataKind {
    LogicalMetadata,
    QueueMetadata,
    SourceObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Records a boundary result without inferring settlement from missing replies.
pub(crate) enum Outcome {
    Pending,
    Positive,
    Refused,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Correlates one original session without exposing its identifier.
pub(crate) struct Session {
    /// SHA-256 of the original session ID, without the raw identifier.
    pub(crate) session_digest: String,
    /// SHA-256 of the immutable logical fingerprint's UTF-8 representation.
    pub(crate) original_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Binds one queue or read observation to its immutable object declaration.
pub(crate) struct Object {
    pub(crate) session: Session,
    pub(crate) client_operation_digest: String,
    pub(crate) placement_digest: String,
    /// Physical verification operation commitment; absent if its derivation fails.
    pub(crate) operation_digest: Option<String>,
    /// Queue-only stable Complete operation commitment, distinct from the read step.
    pub(crate) complete_operation_digest: Option<String>,
    pub(crate) dependency_phase: DirectDependencyPhase,
    /// Declared original object size, never an observed traffic count.
    pub(crate) byte_size: WireInteger,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Correlates exact signed metadata traffic with its original batch members.
pub(crate) struct Control {
    pub(crate) request_digest: String,
    pub(crate) public_body_digest: String,
    /// Exact offered signed logical-envelope SHA-256.
    pub(crate) signed_body_digest: String,
    /// Exact observed reply-body SHA-256, absent on a failed transport.
    pub(crate) reply_body_digest: Option<String>,
    pub(crate) step: Step,
    pub(crate) sessions: Vec<Session>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Identifies the logical authorization boundary independently of the HTTP route.
pub(crate) enum Step {
    Admission,
    Status,
    GrantParts,
    ReportParts,
    Freeze,
    Complete,
    Baseline,
    Promote,
    Commit,
    Abort,
    AbortReport,
}

/// One bounded event containing only closed categories, commitments and counts.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Event {
    pub(crate) version: u32,
    pub(crate) kind: Kind,
    pub(crate) scope: Scope,
    /// Runtime clock observation; cross-isolate comparisons need clock uncertainty.
    pub(crate) at_millis: u64,
    pub(crate) isolate_digest: String,
    /// Build-derived compiled source identity; development may have no identity.
    pub(crate) source_digest: Option<String>,
    pub(crate) object: Option<Object>,
    pub(crate) queue_class: Option<QueueClass>,
    pub(crate) read_kind: Option<ReadKind>,
    pub(crate) data_kind: DataKind,
    pub(crate) control: Option<Control>,
    /// Hash of the actual queue message ID, absent for enqueue/control/read events.
    pub(crate) delivery_digest: Option<String>,
    pub(crate) attempt_digest: String,
    pub(crate) direction: Option<Direction>,
    /// Observed/offered bytes for this boundary; `None` means no known reply length.
    pub(crate) bytes: Option<WireInteger>,
    pub(crate) outcome: Outcome,
    /// Positive retained verification replay, never fresh source consumption.
    pub(crate) replayed: Option<bool>,
    pub(crate) aggregate_active: u32,
    pub(crate) bulk_active: u32,
    pub(crate) metadata_active: u32,
    pub(crate) provider_active: u32,
    pub(crate) provider_bulk_active: u32,
    pub(crate) provider_metadata_active: u32,
}

/// Commits an identifier without exposing its raw UTF-8 representation.
pub(crate) fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

impl Session {
    /// Commits the exact session and immutable original fingerprint.
    pub(crate) fn new(session: &str, fingerprint: &str) -> Self {
        Self {
            session_digest: digest(session),
            original_digest: digest(fingerprint),
        }
    }
}

impl Object {
    /// Projects only commitments, retained dependency phase and declared size.
    pub(crate) fn new(
        session: &str,
        fingerprint: &str,
        intent: &DirectUploadIntent,
        placement: WireInteger,
        operation: &str,
    ) -> Self {
        Self {
            session: Session::new(session, fingerprint),
            client_operation_digest: digest(&intent.client_operation_id),
            placement_digest: digest(&placement.get().to_string()),
            operation_digest: Some(digest(operation)),
            complete_operation_digest: None,
            dependency_phase: intent.dependency_phase,
            byte_size: intent.byte_size,
        }
    }
}

impl Event {
    /// Creates an event from closed runtime categories and bounded commitments.
    pub(crate) fn new(kind: Kind, object: Option<Object>, attempt: &str) -> Self {
        let provider = super::provider_capacity::observation();
        Self {
            version: 1,
            kind,
            scope: match kind {
                Kind::ControlRequest | Kind::ControlReply => Scope::NativeControl,
                Kind::ProviderReadStart | Kind::ProviderReadFinish => Scope::StorageRead,
                _ => Scope::ProductionQueue,
            },
            at_millis: now_millis(),
            isolate_digest: digest(&provider.isolate_id),
            source_digest: option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
                .filter(|value| valid_direct_digest(value))
                .map(str::to_owned),
            queue_class: object.as_ref().map(|object| {
                if object.dependency_phase == DirectDependencyPhase::Content {
                    QueueClass::Bulk
                } else {
                    QueueClass::Metadata
                }
            }),
            object,
            read_kind: None,
            data_kind: match kind {
                Kind::ControlRequest | Kind::ControlReply => DataKind::LogicalMetadata,
                Kind::ProviderReadStart | Kind::ProviderReadFinish => DataKind::SourceObject,
                _ => DataKind::QueueMetadata,
            },
            control: None,
            delivery_digest: None,
            attempt_digest: digest(attempt),
            direction: None,
            bytes: Some(WireInteger::new(0)),
            outcome: Outcome::Pending,
            replayed: None,
            aggregate_active: 0,
            bulk_active: 0,
            metadata_active: 0,
            provider_active: provider.active,
            provider_bulk_active: provider.bulk_active,
            provider_metadata_active: provider.metadata_active,
        }
    }

    /// Encodes one closed event within its diagnostic byte bound.
    ///
    /// # Errors
    /// Returns an error for an oversized event or serialization failure.
    pub(crate) fn encoded(&self) -> Result<String> {
        let text = serde_json::to_string(self)?;
        ensure!(
            text.len() <= MAX_EVENT_BYTES,
            "direct observation exceeds bound"
        );
        Ok(text)
    }
}

impl Control {
    /// Commits the signed metadata request and exact original session references.
    pub(crate) fn new(
        context: &DirectRequestContext,
        request: &DirectUploadLogicalRequest,
        body: &[u8],
    ) -> Self {
        let (step, sessions) = match request {
            DirectUploadLogicalRequest::Admission { .. } => (Step::Admission, Vec::new()),
            DirectUploadLogicalRequest::Authorize {
                action,
                complete_step,
                sessions,
                ..
            } => {
                let step = match action {
                    DirectLogicalAction::Status => Step::Status,
                    DirectLogicalAction::GrantParts => Step::GrantParts,
                    DirectLogicalAction::ReportParts => Step::ReportParts,
                    DirectLogicalAction::Abort => Step::Abort,
                    DirectLogicalAction::Complete => match complete_step {
                        Some(DirectCompleteStep::Freeze) => Step::Freeze,
                        Some(DirectCompleteStep::Baseline) => Step::Baseline,
                        Some(DirectCompleteStep::Promote) => Step::Promote,
                        None => Step::Complete,
                    },
                };
                (
                    step,
                    sessions
                        .iter()
                        .map(|item| {
                            Session::new(
                                &item.session.session_id,
                                &item.session.logical_fingerprint,
                            )
                        })
                        .collect(),
                )
            }
            DirectUploadLogicalRequest::Commit { evidence, .. } => (
                Step::Commit,
                evidence
                    .iter()
                    .map(|item| Session::new(&item.session_id, &item.logical_fingerprint))
                    .collect(),
            ),
            DirectUploadLogicalRequest::AbortReport { outcomes } => (
                Step::AbortReport,
                outcomes
                    .iter()
                    .map(|item| {
                        Session::new(&item.session.session_id, &item.session.logical_fingerprint)
                    })
                    .collect(),
            ),
        };
        Self {
            request_digest: digest(&context.request_nonce),
            public_body_digest: digest(&context.request_body_sha256),
            signed_body_digest: hex::encode(Sha256::digest(body)),
            reply_body_digest: None,
            step,
            sessions,
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn now_millis() -> u64 {
    js_sys::Date::now().max(0.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_millis() -> u64 {
    0
}

/// Emits diagnostics without making telemetry availability an effect precondition.
pub(crate) fn emit(event: &Event) {
    let mut event = event.clone();
    event.at_millis = now_millis();
    let provider = super::provider_capacity::observation();
    event.provider_active = provider.active;
    event.provider_bulk_active = provider.bulk_active;
    event.provider_metadata_active = provider.metadata_active;
    if let Ok(text) = event.encoded() {
        #[cfg(test)]
        CAPTURE.with(|capture| capture.borrow_mut().push(event.clone()));
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("direct_upload_observation {}", text);
        #[cfg(not(target_arch = "wasm32"))]
        let _ = text;
    }
}

#[cfg(test)]
thread_local! {
    static CAPTURE: std::cell::RefCell<Vec<Event>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn take_events() -> Vec<Event> {
    CAPTURE.with(|capture| std::mem::take(&mut *capture.borrow_mut()))
}

/// Counts views actually consumed by one stream, including partial failed reads.
pub(crate) struct Read {
    event: Event,
    bytes: std::cell::Cell<u64>,
}

impl Read {
    /// Opens a measured full-integrity stream interval.
    pub(crate) fn new(object: Object) -> Self {
        Self::with_kind(object, ReadKind::FullIntegrity)
    }

    /// Opens a measured bounded semantic-read interval.
    pub(crate) fn metadata(object: Object) -> Self {
        Self::with_kind(object, ReadKind::SemanticMetadata)
    }

    fn with_kind(object: Object, kind: ReadKind) -> Self {
        let attempt = uuid::Uuid::new_v4().to_string();
        let mut event = Event::new(Kind::ProviderReadStart, Some(object), &attempt);
        event.direction = Some(Direction::ProviderToWorker);
        event.read_kind = Some(kind);
        emit(&event);
        event.kind = Kind::ProviderReadFinish;
        event.outcome = Outcome::Unknown;
        Self {
            event,
            bytes: std::cell::Cell::new(0),
        }
    }

    /// Adds only the byte length of an actual returned reader view.
    pub(crate) fn consumed(&self, amount: u64) {
        self.bytes.set(self.bytes.get().saturating_add(amount));
    }

    /// Records successful completion after the caller's independent checks.
    pub(crate) fn positive(&mut self) {
        self.event.outcome = Outcome::Positive;
    }
}

impl Drop for Read {
    fn drop(&mut self) {
        self.event.at_millis = now_millis();
        self.event.bytes = Some(WireInteger::new(self.bytes.get()));
        emit(&self.event);
    }
}

#[cfg(test)]
mod tests;
