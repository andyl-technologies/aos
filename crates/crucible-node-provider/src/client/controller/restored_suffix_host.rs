//! Retains separately assigned baseline suffix requests and every partial reply.
//!
//! These owners supply transport custody only. A genuine Core action claim and
//! SourceRead must independently admit and authenticate each action. The first
//! signed Observe stays in its original once-only Controller slot; recurring
//! requests neither replace it nor renew its deadline or evidence authority.

use super::*;
use crate::operational_time::OperationalDeadline;
use std::mem::size_of;

#[path = "restored_suffix_host/input_reactive17.rs"]
mod input_reactive17;
pub use input_reactive17::{
    OriginalCompletedRestoredObservation17Data, PreparedOriginalRestoredInputReactive17HostAttempt,
};

/// Borrows one closed ordinary request without creating execution authority.
pub enum OriginalRestoredSuffixBody<'a> {
    /// Borrows an exact execution or same-time settlement request.
    Begin(&'a BeginRequest),
    /// Borrows an independently admitted input stage or commit request.
    Input(&'a InputRequest),
    /// Borrows a poll for an actual retained suffix operation.
    Poll(&'a PollRequest),
    /// Borrows authenticated retirement of actual suffix originals.
    Retire(&'a RetireRequest),
    /// Borrows a fresh current inventory inspection, independently of first Observe.
    Observe(&'a ObserveRequest),
    /// Borrows the actual bounded authorization/consumption upload declaration.
    BlobBegin(&'a BlobBeginRequest),
    /// Borrows one independently debited original upload chunk.
    BlobChunk(&'a BlobChunkRequest),
    /// Borrows the exact original upload completion.
    BlobFinish(&'a BlobFinishRequest),
}

impl OriginalRestoredSuffixBody<'_> {
    fn method_data(&self) -> Result<Method, ProviderError> {
        match self {
            Self::Begin(body)
                if matches!(body.kind, BeginKind::ExactRun | BeginKind::BoundarySettle)
                    && body.extensions.is_empty() =>
            {
                Ok(Method::Begin)
            }
            Self::Input(body) if body.extensions.is_empty() => Ok(Method::Input),
            Self::Poll(body) if body.extensions.is_empty() => Ok(Method::Poll),
            Self::Retire(body)
                if body.disposition == RetirementDisposition::Consumed
                    && body.extensions.is_empty() =>
            {
                Ok(Method::Retire)
            }
            Self::Observe(body)
                if body.after_observation_sequence == U64::new(0)
                    && body.maximum_items == U64::new(1)
                    && body.extensions.is_empty() =>
            {
                Ok(Method::Observe)
            }
            Self::BlobBegin(body) if body.extensions.is_empty() => Ok(Method::BlobBegin),
            Self::BlobChunk(body) if body.extensions.is_empty() => Ok(Method::BlobChunk),
            Self::BlobFinish(body) if body.extensions.is_empty() => Ok(Method::BlobFinish),
            _ => Err(refused()),
        }
    }
}

impl Serialize for OriginalRestoredSuffixBody<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Begin(value) => value.serialize(serializer),
            Self::Input(value) => value.serialize(serializer),
            Self::Poll(value) => value.serialize(serializer),
            Self::Retire(value) => value.serialize(serializer),
            Self::Observe(value) => value.serialize(serializer),
            Self::BlobBegin(value) => value.serialize(serializer),
            Self::BlobChunk(value) => value.serialize(serializer),
            Self::BlobFinish(value) => value.serialize(serializer),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Preparing,
    Assigned,
    Publishing,
    Complete,
}

/// Owns one assigned standard original, terminal and independently owned typed reply.
///
/// The Source retains this slot before the first fallible assignment. No public
/// constructor or retry path exists. A failed preparation or publication keeps
/// all initialized fields; the caller counts them even after revocation.
pub struct OriginalRestoredSuffixHostAttempt {
    request_id: Id,
    operation_id: Option<Id>,
    method: Method,
    controller: *const CnpController,
    process: u32,
    thread: std::thread::ThreadId,
    cut: Option<OperationalDeadline>,
    completed_frontier: Option<U64>,
    original: Option<Envelope>,
    response: Option<Envelope>,
    decoded: Option<Box<ResponseBody>>,
    roots: Vec<ContentRef>,
    stage: Stage,
}

/// Keeps the same Controller and caller-owned partial exclusively borrowed.
#[must_use = "retain the original attempt through failed or uncertain publication"]
pub struct PreparedOriginalRestoredSuffixHostAttempt<'a> {
    controller: &'a mut CnpController,
    attempt: &'a mut OriginalRestoredSuffixHostAttempt,
}

impl CnpController {
    /// Assigns one ordinary suffix request after a genuine first Observe.
    ///
    /// The caller supplies its actual independently admitted Source slot. The
    /// selected startup reservation and complete source/runtime action grant
    /// remain separate prerequisites; this SDK marker supplies no such grant.
    ///
    /// # Errors
    /// Refuses another actor, missing suffix negotiation or first observation,
    /// a reused slot/ID, unsupported method, failed sizing or expired assignment.
    /// All initialized partial owners remain in `completed` on every failure.
    pub fn prepare_original_restored_suffix_into<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        operation_id: Option<Id>,
        body: OriginalRestoredSuffixBody<'_>,
        extensions: Extensions,
        completed: &'a mut Option<OriginalRestoredSuffixHostAttempt>,
    ) -> Result<PreparedOriginalRestoredSuffixHostAttempt<'a>, ProviderError> {
        self.authenticate_original_installed_restored_suffix_data(emitter)?;
        self.ensure_no_pending_original_ack_admit()?;
        self.ensure_no_pending_original_complete_restore()?;
        if self.fenced || completed.is_some() || self.original(&request_id).is_some() {
            return Err(refused());
        }
        let method = body.method_data()?;
        if method != Method::Input && !extensions.is_empty() {
            return Err(refused());
        }
        if matches!(method, Method::Begin | Method::Poll) != operation_id.is_some() {
            return Err(refused());
        }
        *completed = Some(OriginalRestoredSuffixHostAttempt {
            request_id,
            operation_id,
            method,
            controller: self,
            process: std::process::id(),
            thread: std::thread::current().id(),
            cut: None,
            completed_frontier: None,
            original: None,
            response: None,
            decoded: None,
            roots: Vec::new(),
            stage: Stage::Preparing,
        });
        let attempt = completed.as_mut().ok_or_else(refused)?;
        let (sequence, cut) = self.session.begin_original_ack_admit(self.budget)?;
        attempt.cut = Some(cut);

        let node = Some(self.route.node.clone());
        let owner = Some(self.route.execution_owner.clone());
        let session = self.authority().session_id().clone();
        let incarnation = self.authority().incarnation_id().clone();
        count_serialized(
            &BorrowedEnvelope {
                protocol: "CNP/1",
                message: MessageKind::Request,
                session_id: &session,
                incarnation_id: &incarnation,
                node_id: &node,
                execution_owner_id: &owner,
                capture_owner_id: None,
                request_id: &attempt.request_id,
                operation_id: &attempt.operation_id,
                sequence: U64::new(u64::MAX),
                method,
                body: &body,
                extensions: &extensions,
            },
            self.maximum_frame()?,
        )?;
        let Value::Object(body) =
            serde_json::to_value(&body).map_err(crucible_node_contract::ContractError::from)?
        else {
            return Err(refused());
        };
        attempt.original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(session)),
            incarnation_id: Nullable(Some(incarnation)),
            node_id: Nullable(node),
            execution_owner_id: Nullable(owner),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(attempt.request_id.clone())),
            operation_id: Nullable(attempt.operation_id.clone()),
            sequence,
            method,
            body,
            extensions,
        });
        let original = attempt.original.as_ref().ok_or_else(refused)?;
        // The actual typed validation can allocate. Its complete native/host row
        // must already be admitted; the original DOM is retained before decoding.
        decode_request(original.method, &original.body)?;
        original.validate()?;
        self.session
            .authenticate_original_ack_admit_cut(sequence, cut)?;
        attempt.stage = Stage::Assigned;

        Ok(PreparedOriginalRestoredSuffixHostAttempt {
            controller: self,
            attempt,
        })
    }
}

impl PreparedOriginalRestoredSuffixHostAttempt<'_> {
    /// Borrows the actual assigned original for Source signing and correspondence.
    ///
    /// # Errors
    /// Refuses a nonassigned attempt, changed actor/sequence or expired original cut.
    pub fn original_data(&self) -> Result<&Envelope, ProviderError> {
        if self.attempt.stage != Stage::Assigned {
            return Err(refused());
        }
        let original = self.attempt.original.as_ref().ok_or_else(refused)?;
        self.controller
            .session
            .authenticate_original_ack_admit_cut(
                original.sequence,
                self.attempt.cut.ok_or_else(refused)?,
            )?;
        Ok(original)
    }

    /// Publishes the same assigned baseline original without retry or cut renewal.
    ///
    /// # Errors
    /// Refuses a foreign emitter, incomplete assignment or failed/uncertain IO.
    /// Raw and typed terminals precede correspondence, journal and evidence checks.
    pub fn publish_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        self.controller
            .authenticate_original_installed_restored_suffix_data(emitter)?;
        self.original_data()?;
        self.attempt.stage = Stage::Publishing;
        self.controller
            .session
            .publish_original_restored_suffix_into(
                &mut self.controller.custody,
                self.attempt.original.as_ref().ok_or_else(refused)?,
                self.attempt.cut.ok_or_else(refused)?,
                &mut self.attempt.response,
                &mut self.attempt.decoded,
            )?;
        let response = self.attempt.response.as_ref().ok_or_else(refused)?;
        for value in response.body.values() {
            references(value, &mut self.attempt.roots)?;
        }
        self.controller.session.receive_content(
            &mut self.controller.custody,
            &self.attempt.roots,
            self.controller.budget,
        )?;
        self.attempt.completed_frontier =
            Some(self.controller.session.fresh_restore_query_sequence()?);
        self.attempt.stage = Stage::Complete;
        Ok(())
    }
}

impl OriginalRestoredSuffixHostAttempt {
    /// Lends the same complete original, raw terminal and independent typed reply.
    ///
    /// This is correspondence DATA. The Source separately authenticates its
    /// keyed history, current native proof and terminal SourceRead member fence.
    ///
    /// # Errors
    /// Refuses partial custody, a missing terminal or changed response correlation.
    pub fn completed_pair_data(
        &self,
    ) -> Result<(&Envelope, &Envelope, &ResponseBody), ProviderError> {
        if self.stage != Stage::Complete {
            return Err(refused());
        }
        let original = self.original.as_ref().ok_or_else(refused)?;
        let response = self.response.as_ref().ok_or_else(refused)?;
        original.matches_response(response)?;
        Ok((
            original,
            response,
            self.decoded.as_deref().ok_or_else(refused)?,
        ))
    }

    /// Returns the saved completed frontier without checking currentness.
    ///
    /// This inert DATA selects a later exact validator; an old or failed attempt
    /// cannot become current merely because its saved sequence is greatest.
    pub fn completed_frontier_data(&self) -> Option<U64> {
        if self.stage == Stage::Complete {
            self.completed_frontier
        } else {
            None
        }
    }

    /// Authenticates the complete pair at the unchanged current SDK frontier.
    ///
    /// Historical operation outcomes use `completed_pair_data` instead. Any
    /// subsequent original, including content ACK traffic, makes this checkpoint
    /// stale; neither a deadline reset nor a replay can renew the captured cut.
    /// This does not authenticate a native proof or issue a Core action claim.
    ///
    /// # Errors
    /// Refuses another creator or Controller, incomplete retained custody, a
    /// changed actual journal pair, revoked negotiation or an advanced frontier.
    pub fn authenticate_current_pair_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(&Envelope, &Envelope, &ResponseBody), ProviderError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.controller, controller)
        {
            return Err(refused());
        }
        controller.authenticate_original_installed_restored_suffix_data(emitter)?;
        let (original, terminal, typed) = self.completed_pair_data()?;
        let actual = controller.original(&self.request_id).ok_or_else(refused)?;
        if &actual.request != original
            || actual.response.as_ref() != Some(terminal)
            || self.completed_frontier != Some(controller.session.fresh_restore_query_sequence()?)
        {
            return Err(refused());
        }

        Ok((original, terminal, typed))
    }

    /// Observes actual partial child capacities without invoking live predicates.
    ///
    /// The Source checks creator identity and counts this outer owner separately.
    /// Repeated raw/typed/reference backing is deliberately counted independently.
    ///
    /// # Errors
    /// Refuses unsupported typed replies, overflow or metadata traversal exhaustion.
    pub fn retained_metadata_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_historical_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Names the fixed assignment, retained owner and actual Session return views.
    pub fn counter_scratch_data() -> usize {
        size_of::<Option<U64>>()
            + size_of::<&Self>()
            + size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<Option<&mut Self>>()
            + size_of::<Result<&mut Self, ProviderError>>()

            + size_of::<OriginalRestoredSuffixBody<'static>>()
            + size_of::<PreparedOriginalRestoredSuffixHostAttempt<'static>>()
            + size_of::<Result<PreparedOriginalRestoredSuffixHostAttempt<'static>, ProviderError>>()
            + size_of::<(&Envelope, &Envelope, &ResponseBody)>()
            + size_of::<Result<(&Envelope, &Envelope, &ResponseBody), ProviderError>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<Result<&Envelope, ProviderError>>()
            + size_of::<Option<&ResponseBody>>()
            + size_of::<Result<&ResponseBody, ProviderError>>()
            + size_of::<Result<RequestBody, ProviderError>>()
            + size_of::<Result<Method, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()

            + size_of::<serde_json::map::Values<'static>>()
            + size_of::<(
                &Id,
                &Option<Id>,
                &Method,
                &*const CnpController,
                &u32,
                &std::thread::ThreadId,
                &Option<OperationalDeadline>,
                &Option<U64>,
                &Option<Envelope>,
                &Option<Envelope>,
                &Option<Box<ResponseBody>>,
                &Vec<ContentRef>,
                &Stage
            )>()
            + size_of::<Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError>>()

            + crate::retained_metadata::restored_suffix::counter_scratch_data()
            + ClientSession::original_restored_suffix_counter_scratch_data()
            + CnpController::original_installed_restoration_observation_counter_scratch_data()
            + crate::reference_packet::service::native_startup::original_native_suffix_counter_scratch_data()
            + crate::connection::original_serialized_credit_counter_scratch_data()

            + size_of::<BorrowedEnvelope<'static, OriginalRestoredSuffixBody<'static>>>()
            + size_of::<crate::retained_metadata::MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Envelope>()
            + size_of::<RequestBody>()
            + size_of::<ResponseBody>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Result<Value, crucible_node_contract::ContractError>>()
            + size_of::<Value>()
            + size_of::<serde_json::Map<String, Value>>()
            + size_of::<Option<Box<ResponseBody>>>()
            + size_of::<Result<(), crucible_node_contract::ContractError>>()
            + size_of::<Result<(), std::num::TryFromIntError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<U64, ProviderError>>()
            + size_of::<Option<U64>>()

            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<&CnpController>()
            + size_of::<&mut CnpController>()
            + size_of::<&Extensions>()
            + size_of::<Extensions>()
            + size_of::<Option<&ClientOriginal>>()
            + size_of::<Result<&ClientOriginal, ProviderError>>()
            + size_of::<(&Envelope, &Envelope)>()
            + size_of::<(
                &crate::reference_packet::control::PacketControlSelection,
                &crate::handshake::ConnectionAuthority
            )>()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("assigned restored suffix original changed or incomplete")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> OriginalRestoredSuffixHostAttempt {
        OriginalRestoredSuffixHostAttempt {
            request_id: Id::new("suffix/actual-request").unwrap(),
            operation_id: None,
            method: Method::Observe,
            controller: std::ptr::null(),
            process: std::process::id(),
            thread: std::thread::current().id(),
            cut: None,
            completed_frontier: None,
            original: None,
            response: None,
            decoded: None,
            roots: Vec::new(),
            stage: Stage::Preparing,
        }
    }

    #[test]
    fn suffix_raw_partial_counts_independent_typed_spare_capacity_and_error() {
        let mut attempt = attempt();
        let observations = Vec::with_capacity(7);
        let observation_bytes =
            observations.capacity() * size_of::<crucible_node_contract::ObservationBatch>();
        let mut message = String::with_capacity(173);
        message.push_str("partial reply remains owned");
        let message_bytes = message.capacity();
        attempt.roots = Vec::with_capacity(5);
        let roots_bytes = attempt.roots.capacity() * size_of::<ContentRef>();
        attempt.decoded = Some(Box::new(ResponseBody {
            shape: ResponseShape::Error {
                operation_state: OperationState::Unknown,
                error: ErrorRecord {
                    code: "OUTCOME_UNKNOWN".into(),
                    message,
                    effect: EffectCertainty::Unknown,
                    retryable: false,
                    details: Default::default(),
                },
                extensions: Extensions::new(),
            },
            // A typed partial can coexist with a rejected raw shape. The raw
            // census must count both rather than demand terminal completion.
            result: Some(MethodResult::Observe(ObserveResult {
                observations,
                next_sequence: U64::new(1),
                complete: true,
                inventory_hash: canonical::content_ref(b"partial", "application/octet-stream")
                    .unwrap()
                    .hash,
            })),
        }));

        let before = attempt.retained_metadata_data().unwrap();
        assert!(before.vector_capacity_bytes >= observation_bytes + roots_bytes);
        assert!(before.string_capacity_bytes >= message_bytes);
        assert!(before.boxed_value_bytes >= size_of::<ResponseBody>());
        assert!(attempt.completed_pair_data().is_err());

        attempt.stage = Stage::Publishing;
        let after = attempt.retained_metadata_data().unwrap();
        assert_eq!(before, after);
        assert!(attempt.completed_pair_data().is_err());
    }

    #[test]
    fn suffix_pair_requires_actual_complete_correlation_and_keeps_failed_owner() {
        let mut attempt = attempt();
        let original = crate::envelope::tests::request();
        let mut terminal = original.clone();
        terminal.message = MessageKind::Response;
        attempt.original = Some(original);
        attempt.response = Some(terminal);
        attempt.decoded = Some(Box::new(ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: Default::default(),
                extensions: Extensions::new(),
            },
            result: None,
        }));

        for stage in [Stage::Preparing, Stage::Assigned, Stage::Publishing] {
            attempt.stage = stage;
            assert!(attempt.completed_pair_data().is_err());
            assert!(attempt.original.is_some());
            assert!(attempt.response.is_some());
            assert!(attempt.decoded.is_some());
        }
        attempt.stage = Stage::Complete;
        assert!(attempt.completed_pair_data().is_ok());
        attempt.response.as_mut().unwrap().request_id =
            Nullable(Some(Id::new("suffix/wrong-terminal").unwrap()));
        assert!(attempt.completed_pair_data().is_err());
        assert!(attempt.retained_metadata_data().is_ok());
    }
}

impl OriginalRestoredSuffixHostAttempt {
    fn observe_historical_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            request_id,
            operation_id,
            method: _,
            controller: _,
            process: _,
            thread: _,
            cut: _,
            completed_frontier: _,
            original,
            response,
            decoded,
            roots,
            stage: _,
        } = self;
        observer.observe(request_id)?;
        observer.observe(operation_id)?;
        observer.observe(original)?;
        observer.observe(response)?;
        observer.observe(roots)?;
        if let Some(decoded) = decoded {
            observer.boxed_value(decoded.as_ref())?;
            crate::retained_metadata::restored_suffix::response(decoded, observer)?;
        }
        Ok(())
    }
}

#[path = "restored_suffix_host/history.rs"]
mod history;
pub use history::OriginalRestoredSuffixHostHistoricalData;

#[path = "restored_suffix_host/checkpoint_cache17.rs"]
mod checkpoint_cache17;
