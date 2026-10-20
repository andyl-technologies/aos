//! Closed response envelopes, retained terminal outcomes, and notification metadata.

use super::*;

/// States registered operation progress independently of transport delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Proves the operation has not started.
    NotStarted,
    /// Retains running operation custody.
    Running,
    /// Retains completed operation custody.
    Completed,
    /// Discloses unresolved native effects requiring containment.
    Unknown,
}

/// States certainty about the reported operation's effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectCertainty {
    /// Proves no effects began.
    NotStarted,
    /// Retains custody of ongoing effects.
    InProgress,
    /// Proves the reported effects completed.
    Completed,
    /// Discloses uncertain effects without implying rollback.
    Unknown,
}

/// Carries a bounded refusal without permitting replacement execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorRecord {
    /// Names a baseline error or explicitly negotiated extension code.
    pub code: String,
    /// Explains the refusal in at most 4096 UTF-8 bytes.
    pub message: String,
    /// States known effect certainty without inferring rollback.
    pub effect: EffectCertainty,
    /// Permits retry of the same identity only.
    pub retryable: bool,
    /// Carries bounded machine-readable metadata under negotiated schemas.
    pub details: Map<String, Value>,
}

impl Validate for ErrorRecord {
    fn validate(&self) -> Result<(), ContractError> {
        Id::new(self.code.clone())?;
        if self.message.len() > 4096 {
            return Err(invalid("message", "error message exceeds 4096 UTF-8 bytes"));
        }
        canonical::canonical_json(&Value::Object(self.details.clone()))?;
        Ok(())
    }
}

impl ErrorRecord {
    /// Returns baseline handling, weakening unknown codes to unknown effects.
    pub fn baseline_handling(&self) -> (&str, EffectCertainty) {
        const BASELINE: &[&str] = &[
            "INVALID_ARGUMENT",
            "UNSUPPORTED_VERSION",
            "UNSUPPORTED_FEATURE",
            "UNAUTHORIZED",
            "STALE_SESSION",
            "UNKNOWN_NODE",
            "OWNER_MISMATCH",
            "BINDING_MISMATCH",
            "STATE_BINDING_MISMATCH",
            "INVALID_STATE",
            "CONFLICT",
            "RESOURCE_EXHAUSTED",
            "DEADLINE_EXCEEDED",
            "CANCELED",
            "OPERATION_RETIRED",
            "OUTCOME_UNKNOWN",
            "CONTENT_MISMATCH",
            "PROTOCOL_ERROR",
            "IMPLEMENTATION_FAILURE",
        ];
        if BASELINE.contains(&self.code.as_str()) {
            (self.code.as_str(), self.effect)
        } else {
            ("IMPLEMENTATION_FAILURE", EffectCertainty::Unknown)
        }
    }
}

/// Represents the closed common response body before method result decoding.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseShape {
    /// Proves bounded journal registration while retaining running custody.
    Accepted {
        /// States registered running custody.
        operation_state: OperationState,
        /// Contains the selected method's immediate registration result.
        result: Map<String, Value>,
        /// Carries explicitly negotiated response extensions.
        extensions: Extensions,
    },
    /// Carries the method's completed result and required evidence.
    Completed {
        /// States completed method custody.
        operation_state: OperationState,
        /// Contains the selected method's complete result fields.
        result: Map<String, Value>,
        /// Carries explicitly negotiated response extensions.
        extensions: Extensions,
    },
    /// Discloses an error and its actual effect certainty.
    Error {
        /// States retained operation progress rather than guessed completion.
        operation_state: OperationState,
        /// Contains the bounded refusal and machine-readable details.
        error: ErrorRecord,
        /// Carries explicitly negotiated response extensions.
        extensions: Extensions,
    },
}

impl std::fmt::Debug for ResponseShape {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The raw result map can contain hello credentials before typed decoding.
        let status = match self {
            Self::Accepted { .. } => "accepted",
            Self::Completed { .. } => "completed",
            Self::Error { .. } => "error",
        };
        formatter
            .debug_struct("ResponseShape")
            .field("status", &status)
            .field("operation_state", &self.operation_state())
            .finish_non_exhaustive()
    }
}

impl Validate for ResponseShape {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Accepted {
                operation_state, ..
            } if *operation_state != OperationState::Running => Err(invalid(
                "operation_state",
                "accepted response requires running custody",
            )),
            Self::Completed {
                operation_state, ..
            } if *operation_state != OperationState::Completed => Err(invalid(
                "operation_state",
                "completed response requires completed custody",
            )),
            Self::Error { error, .. } => error.validate(),
            _ => Ok(()),
        }
    }
}

impl ResponseShape {
    /// Returns whether the response proves registration without completion.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    /// Returns the retained operation state, including uncertainty.
    pub fn operation_state(&self) -> OperationState {
        match self {
            Self::Accepted {
                operation_state, ..
            }
            | Self::Completed {
                operation_state, ..
            }
            | Self::Error {
                operation_state, ..
            } => *operation_state,
        }
    }
}

pub(crate) fn decode_response_shape(
    body: &Map<String, Value>,
) -> Result<ResponseShape, ContractError> {
    object(body)
}

/// Contains a selected successful baseline method result.
#[derive(Clone, Debug, PartialEq)]
pub enum MethodResult {
    /// Contains the complete `Hello` result fields.
    Hello(HelloResult),
    /// Contains the complete `Discover` result fields.
    Discover(DiscoverResult),
    /// Contains the complete `Realize` result fields.
    Realize(RealizeResult),
    /// Contains the complete `Admit` result fields.
    Admit(AdmitResult),
    /// Contains the complete `Activate` result fields.
    Activate(ActivateResult),
    /// Contains the complete `Input` result fields.
    Input(InputResult),
    /// Contains the complete `Observe` result fields.
    Observe(ObserveResult),
    /// Contains the complete `Poll` result fields.
    Poll(PollResult),
    /// Contains the complete `Cancel` result fields.
    Cancel(CancelResult),
    /// Contains the complete `QuantumClose` result fields.
    QuantumClose(QuantumCloseResult),
    /// Contains the complete `WorldActivate` result fields.
    WorldActivate(WorldActivateResult),
    /// Contains the complete `Abort` result fields.
    Abort(AbortResult),
    /// Contains the complete `Retire` result fields.
    Retire(RetireResult),
    /// Contains the complete `BlobBegin` result fields.
    BlobBegin(BlobBeginResult),
    /// Contains the complete `BlobChunk` result fields.
    BlobChunk(BlobChunkResult),
    /// Contains the complete `BlobFinish` result fields.
    BlobFinish(BlobFinishResult),
    /// Contains the complete `Release` result fields.
    Release(ReleaseResult),
    /// Contains the selected `BeginAccepted` operation result.
    BeginAccepted(BeginAccepted),
    /// Contains the selected `ExactRun` operation result.
    ExactRun(ExactRunResult),
    /// Contains the selected `BoundarySettle` operation result.
    BoundarySettle(ExactRunResult),
    /// Contains the selected `QuantumBegin` operation result.
    QuantumBegin(QuantumBeginResult),
    /// Contains the selected `Pause` operation result.
    Pause(PauseResult),
    /// Contains the selected `Capture` operation result.
    Capture(CaptureResult),
    /// Contains the selected `PrepareRestore` operation result.
    PrepareRestore(PrepareRestoreResult),
    /// Contains the selected `Shutdown` operation result.
    Shutdown(ShutdownResult),
}

/// Retains a validated common response and its decoded method result.
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseBody {
    /// Preserves original status, error, state, and negotiated extensions.
    pub shape: ResponseShape,
    /// Contains a selected success result; refusals have no result.
    pub result: Option<MethodResult>,
}

/// Decodes a closed response against its original request and selected kind.
///
/// # Errors
/// Rejects malformed status, missing fields/evidence, unknown fields, changed
/// operation identifiers or grant coordinates, and incompatible method results.
/// Referenced native receipts and live scope still require host verification.
pub fn decode_response(
    request: &RequestBody,
    body: &Map<String, Value>,
) -> Result<ResponseBody, ProviderError> {
    let shape = decode_response_shape(body)?;
    if shape.is_accepted()
        && matches!(
            request,
            RequestBody::Hello(_)
                | RequestBody::Discover(_)
                | RequestBody::Observe(_)
                | RequestBody::Poll(_)
        )
    {
        return Err(ProviderError::Correlation(
            "immediate read-only method must return completed",
        ));
    }
    let result = match &shape {
        ResponseShape::Error { .. } => None,
        ResponseShape::Accepted { result, .. } | ResponseShape::Completed { result, .. } => {
            Some(match request {
                RequestBody::Hello(_) => MethodResult::Hello(object(result)?),
                RequestBody::Discover(_) => MethodResult::Discover(object(result)?),
                RequestBody::Realize(_) => MethodResult::Realize(object(result)?),
                RequestBody::Admit(_) => MethodResult::Admit(object(result)?),
                RequestBody::Activate(_) => MethodResult::Activate(object(result)?),
                RequestBody::Input(_) => MethodResult::Input(object(result)?),
                RequestBody::Observe(_) => MethodResult::Observe(object(result)?),
                RequestBody::Poll(_) => MethodResult::Poll(object(result)?),
                RequestBody::Cancel(_) => MethodResult::Cancel(object(result)?),
                RequestBody::QuantumClose(_) => MethodResult::QuantumClose(object(result)?),
                RequestBody::WorldActivate(_) => MethodResult::WorldActivate(object(result)?),
                RequestBody::Abort(_) => MethodResult::Abort(object(result)?),
                RequestBody::Retire(_) => MethodResult::Retire(object(result)?),
                RequestBody::BlobBegin(_) => MethodResult::BlobBegin(object(result)?),
                RequestBody::BlobChunk(_) => MethodResult::BlobChunk(object(result)?),
                RequestBody::BlobFinish(_) => MethodResult::BlobFinish(object(result)?),
                RequestBody::Release(_) => MethodResult::Release(object(result)?),
                RequestBody::Begin(request) => {
                    if shape.is_accepted() {
                        let accepted: BeginAccepted = object(result)?;
                        if accepted.kind != request.kind {
                            return Err(ProviderError::Correlation(
                                "accepted operation kind changed",
                            ));
                        }
                        MethodResult::BeginAccepted(accepted)
                    } else {
                        match request.kind {
                            BeginKind::ExactRun => MethodResult::ExactRun(object(result)?),
                            BeginKind::BoundarySettle => {
                                MethodResult::BoundarySettle(object(result)?)
                            }
                            BeginKind::QuantumBegin => MethodResult::QuantumBegin(object(result)?),
                            BeginKind::Pause => MethodResult::Pause(object(result)?),
                            BeginKind::Capture => MethodResult::Capture(object(result)?),
                            BeginKind::PrepareRestore => {
                                MethodResult::PrepareRestore(object(result)?)
                            }
                            BeginKind::Shutdown => MethodResult::Shutdown(object(result)?),
                        }
                    }
                }
            })
        }
    };
    let response = ResponseBody { shape, result };
    validate_result_identity(request, &response)?;
    Ok(response)
}

fn validate_result_identity(
    request: &RequestBody,
    response: &ResponseBody,
) -> Result<(), ProviderError> {
    let Some(result) = &response.result else {
        return Ok(());
    };
    let matches = match (request, result) {
        (RequestBody::Realize(request), MethodResult::Realize(result)) => {
            request.realization_id == result.realization_manifest.realization_id
        }
        (RequestBody::Admit(request), MethodResult::Admit(result)) => {
            let mut expected = request
                .bindings
                .iter()
                .map(NodeBinding::identity)
                .collect::<Result<Vec<_>, _>>()?;
            expected.sort();
            expected == result.accepted_binding_hashes
        }
        (RequestBody::Input(request), MethodResult::Input(result)) => {
            let expected: std::collections::BTreeSet<_> = request
                .events
                .iter()
                .map(|event| event.id.clone())
                .collect();
            expected.into_iter().collect::<Vec<_>>() == result.accepted_event_ids
                && result.input_watermark >= request.batch_sequence
        }
        (RequestBody::Activate(request), MethodResult::Activate(result)) => {
            request.gate_id == result.gate_id
        }
        (RequestBody::WorldActivate(request), MethodResult::WorldActivate(result)) => {
            request.gate_id == result.gate_id
        }
        (RequestBody::Abort(request), MethodResult::Abort(result)) => {
            request.transaction_id == result.transaction_id
        }
        (RequestBody::Release(request), MethodResult::Release(result)) => {
            request.realization_id == result.realization_id
        }
        (RequestBody::BlobBegin(request), MethodResult::BlobBegin(result)) => {
            request.transfer_id == result.transfer_id
                && result.next_offset <= request.content.length
        }
        (RequestBody::BlobChunk(request), MethodResult::BlobChunk(result)) => {
            request.transfer_id == result.transfer_id
                && result.next_offset
                    == request.offset.checked_add(U64::new(
                        u64::try_from(request.bytes.as_slice().len())
                            .map_err(|_| ContractError::Overflow)?,
                    ))?
        }
        (RequestBody::BlobFinish(request), MethodResult::BlobFinish(result)) => {
            request.transfer_id == result.transfer_id
        }
        (RequestBody::Retire(request), MethodResult::Retire(result)) => {
            request.request_ids == result.retired_request_ids
                && request.operation_ids == result.retired_operation_ids
        }
        (RequestBody::Observe(request), MethodResult::Observe(result)) => {
            u64::try_from(result.observations.len()).map_err(|_| ContractError::Overflow)?
                <= request.maximum_items.get()
        }
        (RequestBody::QuantumClose(request), MethodResult::QuantumClose(result)) => {
            request.grant_id == result.grant_id
                && request.quantum_index == result.quantum_index
                && request.cut == result.cut
                && request.policy_hash == result.policy_hash
                && request.activation_id == result.activation_id
                && request.world_generation == result.world_generation
                && request.owner_generation == result.owner_generation
                && request.input_epoch == result.input_epoch
        }
        (
            RequestBody::Begin(request),
            MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result),
        ) => match request.decoded_arguments()? {
            BeginArguments::ExactRun(arguments) | BeginArguments::BoundarySettle(arguments) => {
                arguments.grant_id == result.grant_id
                    && result.reached >= arguments.start
                    && result.reached <= arguments.limit
            }
            _ => false,
        },
        (RequestBody::Begin(request), MethodResult::QuantumBegin(result)) => {
            match request.decoded_arguments()? {
                BeginArguments::QuantumBegin(arguments) => {
                    arguments.grant_id == result.grant_id
                        && arguments.quantum_index == result.quantum_index
                }
                _ => false,
            }
        }
        (RequestBody::Begin(request), MethodResult::PrepareRestore(result)) => {
            match request.decoded_arguments()? {
                BeginArguments::PrepareRestore(arguments) => {
                    arguments.transaction_id == result.transaction_id
                        && arguments.expected_world_binding_hash == result.world_binding_hash
                        && arguments.expected_owner_binding_hash == result.owner_binding_hash
                        && arguments.destination_owner_ids == result.staged_owner_ids
                }
                _ => false,
            }
        }
        _ => true,
    };
    if !matches {
        return Err(ProviderError::Correlation(
            "method result changed original request identity or bounds",
        ));
    }
    Ok(())
}

/// Carries bounded notification metadata without an authoritative result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationBody {
    /// States currently reported operation progress.
    pub operation_state: OperationState,
    /// Reports an observation cursor without releasing staged output.
    pub last_observation_sequence: U64,
    /// Contains bounded notification details; poll retrieves actual evidence.
    pub details: Map<String, Value>,
    /// Carries explicitly negotiated notification extensions.
    pub extensions: Extensions,
}

impl Validate for NotificationBody {
    fn validate(&self) -> Result<(), ContractError> {
        canonical::canonical_json(&Value::Object(self.details.clone()))?;
        Ok(())
    }
}

/// Decodes one baseline unsolicited notification's bounded metadata.
///
/// # Errors
/// Rejects a request method used as a notification, unknown fields, and bounds.
pub fn decode_notification(
    method: Method,
    body: &Map<String, Value>,
) -> Result<NotificationBody, ProviderError> {
    match method {
        Method::OperationUpdate | Method::ObservationReady | Method::ProviderFault => {
            Ok(object(body)?)
        }
        _ => Err(ProviderError::Frame(
            "request method cannot originate a notification",
        )),
    }
}
