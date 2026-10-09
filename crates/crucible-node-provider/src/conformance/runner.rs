//! Independent typed exchange, binding resolution and fail-closed probe execution.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Bytes, ContentRef, U64, Validate, canonical};
use serde_json::Value;

use crate::ProviderError;
use crate::bodies::{self, MethodResult, RequestBody, ResponseBody, ResponseShape};
use crate::envelope::{Envelope, MessageKind, Method, RequestOrigin};
use crate::handshake::Limits;
use crate::session::CorrelationGuard;

use super::{
    CheckDisposition, CheckKind, CheckResult, ConformanceReport, EndpointMeasurement, Expectation,
    ProbePlan, ProbeStep, REPORT_VERSION,
};

#[path = "blob.rs"]
mod incoming_blob;

/// Supplies a bounded independent peer transport without granting native authority.
pub trait ProbeSession {
    /// Returns independently observed local peer facts, when available.
    fn measurement(&self) -> Option<EndpointMeasurement>;

    /// Sends one JSON frame under explicit receiving bounds.
    ///
    /// # Errors
    /// Returns framing, limit, deadline or transport failures.
    fn send(&mut self, value: &Value, limits: Limits) -> Result<(), ProviderError>;

    /// Sends the exact intentionally hostile length-prefixed payload.
    ///
    /// # Errors
    /// Returns a bounded-write or transport failure; no retry is inferred.
    fn send_malformed(&mut self, payload: &[u8]) -> Result<(), ProviderError>;

    /// Reads one bounded frame without inventing a response on EOF or timeout.
    ///
    /// # Errors
    /// Returns malformed-frame, deadline or transport failures.
    fn receive(&mut self, limits: Limits) -> Result<Option<Value>, ProviderError>;

    /// Fences both directions without declaring native operation completion.
    fn fence(&mut self);
}

/// Establishes each fresh or resumed actual probe connection.
pub trait ProbeConnector {
    /// Opens a new bounded stream after independently checking endpoint facts.
    ///
    /// # Errors
    /// Returns refused endpoint identity, transport or local resource failures.
    fn connect(&mut self) -> Result<Box<dyn ProbeSession>, ProviderError>;
}

struct Runner<'a> {
    connector: &'a mut dyn ProbeConnector,
    session: Option<Box<dyn ProbeSession>>,
    guard: Option<CorrelationGuard>,
    limits: Limits,
    bindings: BTreeMap<String, Value>,
    endpoints: Vec<EndpointMeasurement>,
    originals: BTreeMap<(String, String, String), crucible_node_contract::HashRef>,
    binding_bytes: usize,
    hello_attempted: bool,
    outgoing_sequence: u64,
}

/// Executes a portable independent protocol plan and retains every failed/omitted case.
///
/// Initial private bindings are kept in memory and excluded from reports. On a
/// case failure, dependent work is not retried: the stream is fenced and every
/// remaining case is reported as not executed. Native custody stays with the
/// externally supervised provider and its original operation journal.
///
/// # Errors
/// Rejects an invalid or unbounded plan/binding inventory before execution,
/// or a failure to derive its canonical plan identity. Exchange failures are
/// retained in the returned report rather than discarded as transient errors.
pub fn run(
    plan: &ProbePlan,
    connector: &mut dyn ProbeConnector,
    bindings: BTreeMap<String, Value>,
) -> Result<ConformanceReport, ProviderError> {
    plan.validate()?;
    if bindings.len() > 4096 {
        return Err(ProviderError::ResourceExhausted(
            "conformance initial bindings",
        ));
    }
    let mut binding_bytes = 0_usize;
    for (name, value) in &bindings {
        crucible_node_contract::Id::new(name.clone())?;
        binding_bytes = checked_binding_bytes(binding_bytes, value)?;
    }
    let plan_value =
        serde_json::to_value(plan).map_err(crucible_node_contract::ContractError::from)?;
    let plan_identity = canonical::json_hash("cnp.conformance-plan.v1", &plan_value)?;
    let mut runner = Runner {
        connector,
        session: None,
        guard: None,
        limits: Limits {
            frame_bytes: U64::new(crate::transport::MAX_FRAME_BYTES as u64),
            nesting: U64::new(crate::transport::MAX_NESTING as u64),
            requests: U64::new(256),
            journal_entries: U64::new(4096),
            blob_chunk_bytes: U64::new(1_048_576),
        },
        bindings,
        endpoints: Vec::new(),
        originals: BTreeMap::new(),
        binding_bytes,
        hello_attempted: false,
        outgoing_sequence: 2,
    };
    let mut results = Vec::new();
    let mut failed = false;
    let mut observed_checks = BTreeSet::new();
    for step in &plan.steps {
        let mut result = CheckResult {
            case: step.id().clone(),
            check: step.check(),
            disposition: CheckDisposition::NotExecuted,
            request_identity: None,
            response_identity: None,
            diagnostic: String::from("dependent case not executed after failure"),
        };
        if !failed {
            match runner.step(step, &mut result) {
                Ok(()) => {
                    result.disposition = CheckDisposition::Passed;
                    result.diagnostic = String::from("protocol oracle satisfied");
                    if let Some(check) = result.check {
                        observed_checks.insert(check);
                    }
                }
                Err(error) => {
                    result.disposition = CheckDisposition::Failed;
                    result.diagnostic = error_category(&error).to_owned();
                    runner.disconnect();
                    failed = true;
                }
            }
        }
        results.push(result);
    }
    runner.disconnect();

    Ok(ConformanceReport {
        schema_version: REPORT_VERSION,
        harness: String::from("crucible-node-conformance.protocol-v1"),
        harness_executable: None,
        plan_identity,
        fixture: plan.fixture.clone(),
        endpoints: runner.endpoints,
        results,
        missing_checks: plan
            .required_checks
            .difference(&observed_checks)
            .copied()
            .collect(),
        protocol_only: true,
    })
}

impl Runner<'_> {
    fn disconnect(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.fence();
        }
        self.guard = None;
        self.hello_attempted = false;
        self.outgoing_sequence = 2;
    }

    fn connected(&mut self) -> Result<&mut Box<dyn ProbeSession>, ProviderError> {
        if self.session.is_none() {
            let session = self.connector.connect()?;
            if let Some(measurement) = session.measurement() {
                self.endpoints.push(measurement);
            }
            self.session = Some(session);
        }
        self.session
            .as_mut()
            .ok_or(ProviderError::Frame("probe has no connected stream"))
    }

    fn step(&mut self, step: &ProbeStep, result: &mut CheckResult) -> Result<(), ProviderError> {
        match step {
            ProbeStep::ReceiveBlob {
                reference,
                maximum_chunks,
                reference_binding,
                bytes_binding,
                ..
            } => {
                let reference: ContentRef =
                    serde_json::from_value(resolve(reference, &self.bindings, 0)?)
                        .map_err(crucible_node_contract::ContractError::from)?;
                self.receive_blob(
                    reference,
                    *maximum_chunks,
                    reference_binding,
                    bytes_binding,
                    result,
                )
            }
            ProbeStep::CanonicalContent {
                value,
                reference_binding,
                bytes_binding,
                ..
            } => {
                let value = resolve(value, &self.bindings, 0)?;
                let bytes = canonical::canonical_json(&value)?;
                if bytes.len() > super::MAX_PLAN_BYTES {
                    return Err(ProviderError::ResourceExhausted("probe canonical content"));
                }
                let reference = canonical::content_ref(&bytes, "application/json")?;
                self.retain_binding(
                    reference_binding.as_str(),
                    serde_json::to_value(reference)
                        .map_err(crucible_node_contract::ContractError::from)?,
                )?;
                self.retain_binding(
                    bytes_binding.as_str(),
                    serde_json::to_value(Bytes::new(bytes))
                        .map_err(crucible_node_contract::ContractError::from)?,
                )?;
                Ok(())
            }
            ProbeStep::InspectContent {
                reference,
                bytes,
                assertions,
                captures,
                ..
            } => {
                let reference: ContentRef =
                    serde_json::from_value(resolve(reference, &self.bindings, 0)?)
                        .map_err(crucible_node_contract::ContractError::from)?;
                let bytes: Bytes = serde_json::from_value(resolve(bytes, &self.bindings, 0)?)
                    .map_err(crucible_node_contract::ContractError::from)?;
                reference.verify(bytes.as_slice())?;
                if reference.media_type != "application/json" {
                    return Err(ProviderError::Frame(
                        "content inspection requires application/json",
                    ));
                }
                let object = canonical::parse_json(bytes.as_slice(), super::MAX_PLAN_BYTES)?;
                self.inspect_fields(&object, assertions, captures)
            }
            ProbeStep::Disconnect { .. } => {
                self.disconnect();
                Ok(())
            }
            ProbeStep::Malformed {
                payload, expected, ..
            } => {
                self.connected()?.send_malformed(payload.as_slice())?;
                let limits = self.limits;
                let response = self.connected()?.receive(limits)?;
                match (expected, response) {
                    (Expectation::Disconnected, None) => {
                        self.disconnect();
                        Ok(())
                    }
                    (Expectation::Error { code, effect }, Some(value)) => {
                        let reply = decode_envelope(&value)?;
                        let shape: ResponseShape =
                            serde_json::from_value(Value::Object(reply.body))
                                .map_err(crucible_node_contract::ContractError::from)?;
                        shape.validate()?;
                        check_shape(expected, &shape)?;
                        let _ = (code, effect);
                        result.response_identity =
                            Some(canonical::json_hash("cnp.conformance-reply.v1", &value)?);
                        self.disconnect();
                        Ok(())
                    }
                    _ => Err(ProviderError::Correlation(
                        "hostile frame was not refused as expected",
                    )),
                }
            }
            ProbeStep::Exchange {
                check,
                request,
                expected,
                assertions,
                captures,
                ..
            } => {
                let mut value = resolve(request, &self.bindings, 0)?;
                if value.get("sequence") == Some(&serde_json::json!({"$sequence":"outgoing"})) {
                    value["sequence"] = Value::String(self.outgoing_sequence.to_string());
                }
                let original = decode_envelope(&value)?;
                if original.message != MessageKind::Request {
                    return Err(ProviderError::Frame("probe exchange is not a request"));
                }
                let body = bodies::decode_request(original.method, &original.body)?;
                check_method(*check, original.method, &body)?;
                check_oracle(*check, expected)?;
                // Handshake credentials and challenge bytes never enter report
                // commitments, including refusals and reconnect attempts.
                if original.method != Method::Hello {
                    result.request_identity =
                        Some(original.request_hash(RequestOrigin::Controller)?);
                }
                let key = (
                    original
                        .session_id
                        .0
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    original
                        .incarnation_id
                        .0
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    original
                        .request_id
                        .0
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                );
                if *check == CheckKind::Duplicate {
                    let prior = self.originals.get(&key).ok_or(ProviderError::Frame(
                        "duplicate case has no original request",
                    ))?;
                    if Some(prior) != result.request_identity.as_ref()
                        && !matches!(expected, Expectation::Error { code, .. } if code.as_str() == "CONFLICT")
                    {
                        return Err(ProviderError::Frame(
                            "changed duplicate must expect original identity conflict",
                        ));
                    }
                }
                self.prepare_request(&original)?;
                if let Some(identity) = &result.request_identity {
                    self.originals.entry(key).or_insert(identity.clone());
                }
                let limits = self.limits;
                self.connected()?.send(&value, limits)?;
                let Some(reply_value) = self.connected()?.receive(limits)? else {
                    return if matches!(expected, Expectation::Disconnected) {
                        self.disconnect();
                        Ok(())
                    } else {
                        Err(ProviderError::Correlation(
                            "peer disconnected with original outcome unresolved",
                        ))
                    };
                };
                let reply = decode_envelope(&reply_value)?;
                self.correlate(&original, &reply)?;
                let response = bodies::decode_response(&body, &reply.body)?;
                if original.method != Method::Hello {
                    result.response_identity = Some(canonical::json_hash(
                        "cnp.conformance-reply.v1",
                        &reply_value,
                    )?);
                }
                check_shape(expected, &response.shape)?;
                self.complete_hello(&body, &response, &reply)?;

                self.inspect_fields(&reply_value, assertions, captures)
            }
        }
    }

    fn inspect_fields(
        &mut self,
        object: &Value,
        assertions: &[super::ReplyAssertion],
        captures: &BTreeMap<String, String>,
    ) -> Result<(), ProviderError> {
        for assertion in assertions {
            let actual = object
                .pointer(&assertion.pointer)
                .ok_or(ProviderError::Correlation(
                    "original object lacks independently asserted field",
                ))?;
            let expected = resolve(&assertion.equals, &self.bindings, 0)?;
            if actual != &expected {
                return Err(ProviderError::Correlation(
                    "independent original-field oracle failed",
                ));
            }
        }
        for (name, pointer) in captures {
            let value = object.pointer(pointer).ok_or(ProviderError::Correlation(
                "original object lacks capture field",
            ))?;
            self.retain_binding(name, value.clone())?;
        }
        Ok(())
    }

    fn retain_binding(&mut self, name: &str, value: Value) -> Result<(), ProviderError> {
        if self.bindings.contains_key(name) || self.bindings.len() >= 4096 {
            return Err(ProviderError::Conflict(
                "captured binding replaces original evidence",
            ));
        }
        self.binding_bytes = checked_binding_bytes(self.binding_bytes, &value)?;
        self.bindings.insert(name.to_owned(), value);
        Ok(())
    }

    fn prepare_request(&mut self, request: &Envelope) -> Result<(), ProviderError> {
        if request.method == Method::Hello {
            if self.hello_attempted || self.guard.is_some() || request.sequence.get() != 1 {
                return Err(ProviderError::Correlation(
                    "hello requires fresh stream sequence one",
                ));
            }
            self.hello_attempted = true;
        } else {
            self.guard
                .as_mut()
                .ok_or(ProviderError::Correlation("request preceded hello"))?
                .register_request(request.clone())?;
            self.outgoing_sequence = self
                .outgoing_sequence
                .checked_add(1)
                .ok_or(ProviderError::ResourceExhausted("probe outgoing sequence"))?;
        }
        Ok(())
    }

    fn correlate(&mut self, request: &Envelope, reply: &Envelope) -> Result<(), ProviderError> {
        if request.method == Method::Hello {
            if reply.method != Method::Hello
                || reply.message != MessageKind::Response
                || request.request_id != reply.request_id
                || reply.sequence.get() != 1
                || reply.node_id.0.is_some()
                || reply.execution_owner_id.0.is_some()
                || reply.capture_owner_id.0.is_some()
                || reply.operation_id.0.is_some()
            {
                return Err(ProviderError::Correlation(
                    "hello reply changed original scope",
                ));
            }
            Ok(())
        } else {
            request.matches_response(reply)?;
            self.guard
                .as_mut()
                .ok_or(ProviderError::Correlation("response preceded hello"))?
                .receive(reply)
        }
    }

    fn complete_hello(
        &mut self,
        request: &RequestBody,
        response: &ResponseBody,
        reply: &Envelope,
    ) -> Result<(), ProviderError> {
        let (RequestBody::Hello(request), Some(MethodResult::Hello(result))) =
            (request, &response.result)
        else {
            return Ok(());
        };
        if request.session_id != result.session_id
            || reply.session_id.0.as_ref() != Some(&result.session_id)
            || reply.incarnation_id.0.as_ref() != Some(&result.incarnation_id)
            || request.controller_nonce != result.controller_nonce
            || !request.versions.contains(&result.version)
            || request
                .required_features
                .iter()
                .any(|feature| !result.selected_features.contains(feature))
            || result.selected_features.iter().any(|feature| {
                !request.required_features.contains(feature)
                    && !request.optional_features.contains(feature)
            })
        {
            return Err(ProviderError::Correlation(
                "hello selection or challenge disagrees",
            ));
        }
        if result.limits.intersection(request.limits)? != result.limits {
            return Err(ProviderError::Correlation(
                "hello exceeded controller receiving limits",
            ));
        }
        if let Some(resume) = &request.resume_session {
            if resume.session_id != result.session_id
                || resume.incarnation_id != result.incarnation_id
                || resume.unresolved_operation_ids.iter().ne(result
                    .resumed_operations
                    .iter()
                    .map(|entry| &entry.operation_id))
            {
                return Err(ProviderError::Correlation(
                    "resumption discarded original incarnation or operations",
                ));
            }
        } else if !result.resumed_operations.is_empty() {
            return Err(ProviderError::Correlation(
                "initial hello invented retained operations",
            ));
        }
        self.limits = result.limits;
        self.guard = Some(CorrelationGuard::new(
            result.session_id.clone(),
            result.incarnation_id.clone(),
            usize::try_from(result.limits.requests.get())
                .map_err(|_| ProviderError::ResourceExhausted("request credit representation"))?,
            BTreeSet::new(),
        )?);
        Ok(())
    }
}

fn decode_envelope(value: &Value) -> Result<Envelope, ProviderError> {
    let bytes = canonical::canonical_json(value)?;
    Envelope::decode(&bytes, crate::transport::MAX_FRAME_BYTES)
}

fn check_shape(expected: &Expectation, shape: &ResponseShape) -> Result<(), ProviderError> {
    let accepted = match (expected, shape) {
        (Expectation::Completed, ResponseShape::Completed { .. })
        | (Expectation::Accepted, ResponseShape::Accepted { .. }) => true,
        (Expectation::Error { code, effect }, ResponseShape::Error { error, .. }) => {
            error.code.as_str() == code.as_str() && &error.effect == effect
        }
        _ => false,
    };
    if accepted {
        Ok(())
    } else {
        Err(ProviderError::Correlation(
            "response status or effect certainty disagrees",
        ))
    }
}

fn check_method(check: CheckKind, method: Method, body: &RequestBody) -> Result<(), ProviderError> {
    let permitted = match check {
        CheckKind::Hello | CheckKind::Limits | CheckKind::UnsupportedContract => {
            method == Method::Hello
        }
        CheckKind::Reconnect => {
            matches!(body, RequestBody::Hello(request) if request.resume_session.is_some())
        }
        CheckKind::DescriptorBinding => {
            matches!(method, Method::Discover | Method::Realize | Method::Admit)
        }
        CheckKind::PausedActivation => {
            matches!(method, Method::Realize | Method::Activate | Method::Observe)
        }
        CheckKind::ActivationGate | CheckKind::Grant => matches!(body, RequestBody::Begin(request)
            if matches!(request.kind, bodies::BeginKind::ExactRun | bodies::BeginKind::BoundarySettle | bodies::BeginKind::QuantumBegin)),
        CheckKind::Capture => {
            matches!(body, RequestBody::Begin(request) if request.kind == bodies::BeginKind::Capture)
        }
        CheckKind::Input => method == Method::Input,
        CheckKind::Publication => matches!(method, Method::QuantumClose | Method::Observe),
        CheckKind::Release => matches!(method, Method::Release | Method::Begin),
        CheckKind::Duplicate => method != Method::Hello,
        CheckKind::Resources => true,
        CheckKind::Malformed => false,
    };
    if permitted {
        Ok(())
    } else {
        Err(ProviderError::Frame(
            "case classification disagrees with exercised method",
        ))
    }
}

fn resolve(
    value: &Value,
    bindings: &BTreeMap<String, Value>,
    depth: usize,
) -> Result<Value, ProviderError> {
    if depth > crate::transport::MAX_NESTING {
        return Err(ProviderError::ResourceExhausted("probe template nesting"));
    }
    match value {
        Value::Object(object) if object.len() == 1 && object.contains_key("$binding") => {
            let name = object["$binding"]
                .as_str()
                .ok_or(ProviderError::Frame("binding name is not text"))?;
            bindings
                .get(name)
                .cloned()
                .ok_or(ProviderError::Frame("unresolved private probe binding"))
        }
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| Ok((key.clone(), resolve(value, bindings, depth + 1)?)))
            .collect::<Result<serde_json::Map<_, _>, ProviderError>>()
            .map(Value::Object),
        Value::Array(array) => array
            .iter()
            .map(|value| resolve(value, bindings, depth + 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        value => Ok(value.clone()),
    }
}

fn check_oracle(check: CheckKind, expected: &Expectation) -> Result<(), ProviderError> {
    let valid = match check {
        CheckKind::ActivationGate => matches!(expected, Expectation::Error { code, effect }
            if code.as_str() == "INVALID_STATE" && *effect == bodies::EffectCertainty::NotStarted),
        CheckKind::Resources => matches!(expected, Expectation::Error { code, .. }
            if code.as_str() == "RESOURCE_EXHAUSTED"),
        CheckKind::UnsupportedContract => matches!(expected, Expectation::Error { code, .. }
            if matches!(code.as_str(), "UNSUPPORTED_VERSION" | "UNSUPPORTED_FEATURE")),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(ProviderError::Frame(
            "check requires its independent refusal oracle",
        ))
    }
}

fn error_category(error: &ProviderError) -> &'static str {
    match error {
        ProviderError::Io(_) => {
            "bounded transport failure; original native outcome remains unresolved"
        }
        ProviderError::Contract(_) => "closed portable schema validation failed",
        ProviderError::Frame(_) => "frame or probe-plan validation failed",
        ProviderError::Correlation(_) => "original scope, sequence or independent oracle disagreed",
        ProviderError::ResourceExhausted(_) => {
            "finite local or negotiated resource allowance exhausted"
        }
        ProviderError::Conflict(_) => "original identity or captured evidence conflicted",
    }
}

fn checked_binding_bytes(current: usize, value: &Value) -> Result<usize, ProviderError> {
    let next = current
        .checked_add(canonical::canonical_json(value)?.len())
        .ok_or(ProviderError::ResourceExhausted(
            "probe binding bytes overflow",
        ))?;
    if next > 64 * 1024 * 1024 {
        return Err(ProviderError::ResourceExhausted(
            "probe retained binding bytes",
        ));
    }
    Ok(next)
}
