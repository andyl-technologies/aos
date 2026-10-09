//! Portable bounded plans and operation-specific protocol oracles.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{Bytes, Id, Validate, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ProviderError;
use crate::bodies::EffectCertainty;

use super::{MAX_PLAN_BYTES, MAX_PLAN_STEPS, PLAN_VERSION};

/// Identifies an independently reported protocol obligation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    /// Checks version, nonce, feature, session and incarnation negotiation.
    Hello,
    /// Checks negotiated finite receiving ceilings.
    Limits,
    /// Checks refusal of an unsupported protocol or required feature.
    UnsupportedContract,
    /// Checks stable descriptors and complete selected bindings.
    DescriptorBinding,
    /// Checks preparation/activation responses with execution withheld.
    PausedActivation,
    /// Checks refusal of native advancement before complete world activation.
    ActivationGate,
    /// Checks an input batch's identity and admission outcome.
    Input,
    /// Checks a bounded advancement request and matching response coordinates.
    Grant,
    /// Checks declared capture response or truthful unsupported-facet refusal.
    Capture,
    /// Checks retained duplicate/conflicting original request behavior.
    Duplicate,
    /// Checks same-incarnation reconnect and retained original operation custody.
    Reconnect,
    /// Checks declared finite-resource refusal without fabricated completion.
    Resources,
    /// Checks fatal refusal of malformed wire data.
    Malformed,
    /// Checks explicit output-publication and acknowledgment behavior.
    Publication,
    /// Checks bounded shutdown and resource-release protocol behavior.
    Release,
}

/// Selects the exact expected common response or a fatal stream refusal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expectation {
    /// Requires a structurally valid completed method-specific result.
    Completed,
    /// Requires registered running custody without a fabricated completion.
    Accepted,
    /// Requires the specified machine-readable refusal and effect certainty.
    Error {
        /// Names the exact expected baseline error code.
        code: Id,
        /// Preserves the refusal's actual effect certainty.
        effect: EffectCertainty,
    },
    /// Requires the peer to close or fatally refuse the transport.
    Disconnected,
}

/// Compares an independently specified reply field with an exact expected value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyAssertion {
    /// Selects a field in the complete reply envelope using JSON Pointer.
    pub pointer: String,
    /// Contains the expected value, optionally resolved through exact bindings.
    pub equals: Value,
}

/// Defines one explicitly bounded exchange or adversarial stream action.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeStep {
    /// Accepts a bounded provider-origin transfer into independent probe custody.
    ReceiveBlob {
        /// Identifies the complete content-transfer case.
        id: Id,
        /// Requires the exact content reference previously promised by the peer.
        reference: Value,
        /// Bounds chunk requests separately from the content byte ceiling.
        maximum_chunks: usize,
        /// Names a fresh binding for the verified original ContentRef.
        reference_binding: Id,
        /// Names a fresh binding for its complete verified Bytes.
        bytes_binding: Id,
    },
    /// Materializes bounded canonical JSON from prior original reply bindings.
    CanonicalContent {
        /// Identifies the local content construction step.
        id: Id,
        /// Contains the exact JSON template, resolved through private bindings.
        value: Value,
        /// Names a fresh binding for its application/json ContentRef.
        reference_binding: Id,
        /// Names a fresh binding for its exact canonical bytes.
        bytes_binding: Id,
    },
    /// Verifies and independently inspects original downloaded JSON content.
    InspectContent {
        /// Identifies the local independent content oracle.
        id: Id,
        /// Contains the exact original ContentRef or its binding object.
        reference: Value,
        /// Contains the exact encoded Bytes or its binding object.
        bytes: Value,
        /// Selects independent expected fields in the decoded content object.
        assertions: Vec<ReplyAssertion>,
        /// Maps fresh binding names to pointers in the verified original object.
        captures: BTreeMap<String, String>,
    },
    /// Sends a closed baseline request and checks its complete correlated reply.
    Exchange {
        /// Identifies the case independently of its request or operation ID.
        id: Id,
        /// Classifies the narrowly observed protocol obligation.
        check: CheckKind,
        /// Contains one CNP envelope, with exact binding objects where needed.
        request: Value,
        /// Specifies the expected common response shape.
        expected: Expectation,
        /// Adds independent field oracles beyond method-schema validation.
        assertions: Vec<ReplyAssertion>,
        /// Maps fresh binding names to JSON Pointers in the original reply.
        captures: BTreeMap<String, String>,
    },
    /// Sends an intentionally invalid length-prefixed JSON payload.
    Malformed {
        /// Identifies this negative case.
        id: Id,
        /// Contains exact hostile bytes, bounded by the plan and frame ceiling.
        payload: Bytes,
        /// Specifies either a correlated protocol error or fatal disconnection.
        expected: Expectation,
    },
    /// Fences the current probe transport without settling native operations.
    Disconnect {
        /// Identifies the explicit transport loss.
        id: Id,
    },
}

impl ProbeStep {
    /// Returns the case's stable identity.
    pub fn id(&self) -> &Id {
        match self {
            Self::ReceiveBlob { id, .. }
            | Self::CanonicalContent { id, .. }
            | Self::InspectContent { id, .. }
            | Self::Exchange { id, .. }
            | Self::Malformed { id, .. }
            | Self::Disconnect { id } => id,
        }
    }

    /// Returns the protocol obligation, absent for transport setup actions.
    pub fn check(&self) -> Option<CheckKind> {
        match self {
            Self::Exchange { check, .. } => Some(*check),
            Self::Malformed { .. } => Some(CheckKind::Malformed),
            Self::ReceiveBlob { .. }
            | Self::CanonicalContent { .. }
            | Self::InspectContent { .. }
            | Self::Disconnect { .. } => None,
        }
    }
}

/// Binds a finite vendor protocol test plan to its fixture and intended coverage.
///
/// Private handshake credentials must use runner bindings so portable plan
/// commitments cannot expose their hashes. Expected replies are independent
/// test oracles supplied by the test authority, not accepted provider claims.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbePlan {
    /// Selects plan schema version one.
    pub schema_version: u32,
    /// Identifies the exact fixture revision tested by this plan.
    pub fixture: Id,
    /// Lists the checks whose absence must remain visible as not executed.
    pub required_checks: BTreeSet<CheckKind>,
    /// Contains a finite ordered program of independently asserted exchanges.
    pub steps: Vec<ProbeStep>,
}

impl ProbePlan {
    /// Decodes a bounded portable plan with strict object and UTF-8 parsing.
    ///
    /// # Errors
    /// Rejects oversized, malformed, duplicate-key, unsupported-version or
    /// semantically unbounded plans before any socket is opened.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, MAX_PLAN_BYTES)?;
        let plan: Self =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        plan.validate()?;
        Ok(plan)
    }

    /// Verifies plan bounds, distinct case identities and finite field oracles.
    ///
    /// # Errors
    /// Rejects unknown versions, empty/oversized plans, duplicate case IDs,
    /// malformed pointers or excessive assertion/capture collections.
    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.schema_version != PLAN_VERSION
            || self.steps.is_empty()
            || self.steps.len() > MAX_PLAN_STEPS
            || self.required_checks.is_empty()
        {
            return Err(ProviderError::Frame(
                "unsupported or unbounded conformance plan",
            ));
        }
        if serde_json::to_vec(self)
            .map_err(crucible_node_contract::ContractError::from)?
            .len()
            > MAX_PLAN_BYTES
        {
            return Err(ProviderError::ResourceExhausted("conformance plan bytes"));
        }
        self.fixture.validate()?;
        let mut cases = BTreeSet::new();
        for step in &self.steps {
            if !cases.insert(step.id()) {
                return Err(ProviderError::Conflict(
                    "duplicate conformance case identity",
                ));
            }
            match step {
                ProbeStep::Exchange {
                    request,
                    assertions,
                    captures,
                    ..
                } => {
                    validate_private_hello(request, assertions)?;
                    validate_field_oracles(assertions, captures)?;
                }
                ProbeStep::InspectContent {
                    assertions,
                    captures,
                    ..
                } => {
                    validate_field_oracles(assertions, captures)?;
                }
                ProbeStep::ReceiveBlob {
                    maximum_chunks,
                    reference_binding,
                    bytes_binding,
                    ..
                } => {
                    if *maximum_chunks == 0 || *maximum_chunks > MAX_PLAN_STEPS {
                        return Err(ProviderError::ResourceExhausted(
                            "incoming blob chunk allowance",
                        ));
                    }
                    validate_content_names(reference_binding, bytes_binding)?;
                }
                ProbeStep::CanonicalContent {
                    reference_binding,
                    bytes_binding,
                    ..
                } => {
                    validate_content_names(reference_binding, bytes_binding)?;
                }
                ProbeStep::Malformed {
                    payload, expected, ..
                } => {
                    if payload.as_slice().len() > crate::transport::MAX_FRAME_BYTES {
                        return Err(ProviderError::ResourceExhausted("negative probe bytes"));
                    }
                    if !matches!(
                        expected,
                        Expectation::Disconnected | Expectation::Error { .. }
                    ) {
                        return Err(ProviderError::Frame(
                            "negative probe expects successful work",
                        ));
                    }
                }
                ProbeStep::Disconnect { .. } => {}
            }
        }
        Ok(())
    }
}

fn validate_content_names(reference_binding: &Id, bytes_binding: &Id) -> Result<(), ProviderError> {
    reference_binding.validate()?;
    bytes_binding.validate()?;
    if reference_binding == bytes_binding {
        return Err(ProviderError::Conflict(
            "content bindings require distinct names",
        ));
    }
    Ok(())
}

fn validate_field_oracles(
    assertions: &[ReplyAssertion],
    captures: &BTreeMap<String, String>,
) -> Result<(), ProviderError> {
    if assertions.len() > 256 || captures.len() > 256 {
        return Err(ProviderError::ResourceExhausted(
            "conformance field oracles",
        ));
    }
    for pointer in assertions
        .iter()
        .map(|assertion| &assertion.pointer)
        .chain(captures.values())
    {
        if pointer.len() > 4096 || !pointer.starts_with('/') {
            return Err(ProviderError::Frame("invalid reply JSON pointer"));
        }
    }
    for name in captures.keys() {
        Id::new(name.clone())?;
    }
    Ok(())
}

fn validate_private_hello(
    request: &Value,
    assertions: &[ReplyAssertion],
) -> Result<(), ProviderError> {
    if request.get("method").and_then(Value::as_str) != Some("hello") {
        return Ok(());
    }

    for pointer in [
        "/body/admission_token",
        "/body/controller_nonce",
        "/body/resume_session/resume_token",
    ] {
        if let Some(value) = request.pointer(pointer) {
            require_private_binding(value)?;
        }
    }
    for assertion in assertions {
        let contains_credentials = ["/body", "/body/result"].contains(&assertion.pointer.as_str());
        let selects_credentials = [
            "/body/result/controller_nonce",
            "/body/result/provider_nonce",
            "/body/result/resume_token",
        ]
        .iter()
        .any(|pointer| {
            assertion.pointer == *pointer || assertion.pointer.starts_with(&format!("{pointer}/"))
        });
        if (contains_credentials || selects_credentials) && !assertion.equals.is_null() {
            require_private_binding(&assertion.equals)?;
        }
    }
    Ok(())
}

fn require_private_binding(value: &Value) -> Result<(), ProviderError> {
    let Some(binding) = value.as_object().filter(|object| object.len() == 1) else {
        return Err(ProviderError::Frame(
            "Hello credentials require private bindings",
        ));
    };
    let Some(name) = binding.get("$binding").and_then(Value::as_str) else {
        return Err(ProviderError::Frame(
            "Hello credentials require private bindings",
        ));
    };
    Id::new(name.to_owned())?;
    Ok(())
}
