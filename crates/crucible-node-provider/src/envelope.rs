//! Closed CNP/1 envelopes and origin-scoped request identity.
//!
//! Nullable envelope fields are required on the wire. Connection sequence is
//! separate from immutable request identity, so reconnecting never renumbers a
//! previously submitted effect.

use crucible_node_contract::{Extensions, HashRef, Id, U64, canonical};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ProviderError;

/// Requires an explicitly present value or JSON null rather than omission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Nullable<T>(pub Option<T>);

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize a value rather than delegating to Option: serde's
        // missing-field deserializer otherwise silently supplies None.
        let value = Value::deserialize(deserializer)?;
        if value.is_null() {
            return Ok(Self(None));
        }
        serde_json::from_value(value)
            .map(|value| Self(Some(value)))
            .map_err(serde::de::Error::custom)
    }
}

/// Classifies a stream message without granting effect authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Starts or retries an origin-scoped request.
    Request,
    /// Reports the original request's retained status or result.
    Response,
    /// Reports an unsolicited observation subject to its visibility contract.
    Event,
}

/// Identifies the sender that originally registered a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOrigin {
    /// The world controller originated this request.
    Controller,
    /// The native provider originated this request.
    Provider,
}

/// Selects a baseline CNP/1 operation with a separately validated body schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Negotiates protocol, limits and admitted connection identity.
    Hello,
    /// Enumerates supported profiles without realization or execution.
    Discover,
    /// Prepares stopped resources under bounded allowances.
    Realize,
    /// Installs the host-authenticated realized binding.
    Admit,
    /// Arms owner readiness while withholding execution.
    Activate,
    /// Retains an original admitted input batch.
    Input,
    /// Reads bounded observations without releasing staged effects.
    Observe,
    /// Registers one effectful operation and its original identity.
    Begin,
    /// Reads the retained state of an existing operation.
    Poll,
    /// Requests cancellation while retaining the eventual completion duty.
    Cancel,
    /// Settles the original quantized window's visibility obligations.
    QuantumClose,
    /// Publishes the complete all-owner activation transaction.
    WorldActivate,
    /// Contains an unactivated preparation transaction.
    Abort,
    /// Retires consumed outcomes without permitting identity reuse.
    Retire,
    /// Starts a bounded inert content transfer.
    BlobBegin,
    /// Adds an authenticated transfer's next bounded chunk.
    BlobChunk,
    /// Verifies complete transferred content before its use.
    BlobFinish,
    /// Discharges resources after reaping or authenticated transfer.
    Release,
    /// Notifies retained operation status without settling its original request.
    OperationUpdate,
    /// Notifies the availability of bounded retained observations.
    ObservationReady,
    /// Notifies a provider failure without implying physical containment.
    ProviderFault,
}

/// Carries portable correlation fields without native pointers or receipts.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Identifies exactly `CNP/1`.
    pub protocol: String,
    /// Distinguishes requests, responses and unsolicited events.
    pub message: MessageKind,
    /// Names the world session, or null only during initial hello.
    pub session_id: Nullable<Id>,
    /// Names the surviving native provider incarnation.
    pub incarnation_id: Nullable<Id>,
    /// Names a specific logical node when the scope is node-local.
    pub node_id: Nullable<Id>,
    /// Names the indivisible execution owner when progress is involved.
    pub execution_owner_id: Nullable<Id>,
    /// Names the indivisible capture owner when preservation is involved.
    pub capture_owner_id: Nullable<Id>,
    /// Correlates one original request, or null for an unsolicited event.
    pub request_id: Nullable<Id>,
    /// Names the retained long-lived effectful operation, if any.
    pub operation_id: Nullable<Id>,
    /// Counts frames in this connection direction, beginning at one.
    pub sequence: U64,
    /// Selects a negotiated method's exact semantics.
    pub method: Method,
    /// Contains the method-specific closed request/result/event object.
    pub body: Map<String, Value>,
    /// Carries only explicitly negotiated envelope extensions.
    pub extensions: Extensions,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Control bodies may carry launch/resume tokens or sensitive payloads.
        // Correlation metadata is enough to diagnose transport ordering.
        formatter
            .debug_struct("Envelope")
            .field("protocol", &self.protocol)
            .field("message", &self.message)
            .field("session_id", &self.session_id)
            .field("incarnation_id", &self.incarnation_id)
            .field("node_id", &self.node_id)
            .field("execution_owner_id", &self.execution_owner_id)
            .field("capture_owner_id", &self.capture_owner_id)
            .field("request_id", &self.request_id)
            .field("operation_id", &self.operation_id)
            .field("sequence", &self.sequence)
            .field("method", &self.method)
            .field("body", &"<redacted>")
            .field(
                "extension_names",
                &self.extensions.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Envelope {
    /// Decodes a closed envelope without accepting duplicate object keys.
    ///
    /// # Errors
    /// Rejects invalid JSON, bounds, missing nullable fields, unknown fields,
    /// invalid scalar representations and inconsistent baseline correlation.
    /// Method-specific body validation and live authority remain separate.
    pub fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, maximum_bytes)?;
        let envelope: Self =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Checks local envelope shape without authenticating a live owner.
    ///
    /// # Errors
    /// Rejects a foreign protocol, zero sequence, missing request correlation,
    /// unsolicited events with request IDs, and non-hello null sessions.
    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.protocol != "CNP/1" {
            return Err(ProviderError::Frame("unsupported protocol"));
        }
        if self.sequence.get() == 0 {
            return Err(ProviderError::Correlation("sequence begins at one"));
        }
        let notification = matches!(
            self.method,
            Method::OperationUpdate | Method::ObservationReady | Method::ProviderFault
        );
        if notification != (self.message == MessageKind::Event) {
            return Err(ProviderError::Correlation(
                "method and message kind disagree",
            ));
        }
        match self.message {
            MessageKind::Event if self.request_id.0.is_some() => {
                return Err(ProviderError::Correlation(
                    "unsolicited event has request ID",
                ));
            }
            MessageKind::Request | MessageKind::Response if self.request_id.0.is_none() => {
                return Err(ProviderError::Correlation("missing request ID"));
            }
            _ => {}
        }
        if self.session_id.0.is_none()
            && (self.method != Method::Hello || self.message == MessageKind::Event)
        {
            return Err(ProviderError::Correlation(
                "null session outside initial hello",
            ));
        }
        if self.incarnation_id.0.is_none()
            && !(self.method == Method::Hello
                && self.message == MessageKind::Request
                && self.session_id.0.is_none())
        {
            return Err(ProviderError::Correlation("missing provider incarnation"));
        }
        Ok(())
    }

    /// Hashes the exact origin-scoped request projection, excluding sequence.
    ///
    /// # Errors
    /// Rejects non-request envelopes, invalid correlation or noncanonical JSON.
    pub fn request_hash(&self, origin: RequestOrigin) -> Result<HashRef, ProviderError> {
        self.validate()?;
        if self.message != MessageKind::Request || self.method == Method::Hello {
            return Err(ProviderError::Correlation(
                "only requests have request identity",
            ));
        }

        let mut projection =
            serde_json::to_value(self).map_err(crucible_node_contract::ContractError::from)?;
        let fields = projection
            .as_object_mut()
            .ok_or(ProviderError::Frame("request projection is not an object"))?;
        fields.remove("message");
        fields.remove("sequence");
        fields.insert(
            "request_origin".into(),
            serde_json::to_value(origin).map_err(crucible_node_contract::ContractError::from)?,
        );

        Ok(canonical::json_hash("cnp.request.v1", &projection)?)
    }

    /// Checks that a response echoes the request's full original scope.
    ///
    /// # Errors
    /// Rejects message-kind, method, session, incarnation, node, owner, request
    /// or operation disagreement. Sequence belongs to the response direction.
    pub fn matches_response(&self, response: &Self) -> Result<(), ProviderError> {
        if self.message != MessageKind::Request
            || response.message != MessageKind::Response
            || self.method != response.method
            || self.session_id != response.session_id
            || self.incarnation_id != response.incarnation_id
            || self.node_id != response.node_id
            || self.execution_owner_id != response.execution_owner_id
            || self.capture_owner_id != response.capture_owner_id
            || self.request_id != response.request_id
            || self.operation_id != response.operation_id
        {
            return Err(ProviderError::Correlation(
                "response does not echo original scope",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These envelope tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;

    pub(crate) fn request() -> Envelope {
        Envelope::decode(
            &serde_json::to_vec(&json!({
                "protocol": "CNP/1", "message": "request", "session_id": "session-1",
                "incarnation_id": "provider-1", "node_id": null,
                "execution_owner_id": "owner-1", "capture_owner_id": null,
                "request_id": "request-1", "operation_id": "operation-1", "sequence": "1",
                "method": "poll", "body": {"after_observation_sequence": "0", "extensions": {}},
                "extensions": {}
            }))
            .unwrap(),
            2048,
        )
        .unwrap()
    }

    #[test]
    fn nullable_field_is_required_even_when_its_value_can_be_null() {
        let mut value = serde_json::to_value(request()).unwrap();
        value.as_object_mut().unwrap().remove("node_id");

        assert!(Envelope::decode(&serde_json::to_vec(&value).unwrap(), 2048).is_err());
    }

    #[test]
    fn debug_output_never_discloses_control_body_secrets() {
        let mut frame = request();
        frame.body.insert(
            "admission_token".into(),
            Value::String("launch-secret-value".into()),
        );

        let diagnostic = format!("{frame:?}");
        assert!(diagnostic.contains("<redacted>"));
        assert!(!diagnostic.contains("launch-secret-value"));
    }

    #[test]
    fn request_identity_survives_connection_sequences_but_not_origin_or_arguments() {
        let original = request();
        let mut retransmission = original.clone();
        retransmission.sequence = U64::new(17);

        assert_eq!(
            original.request_hash(RequestOrigin::Controller).unwrap(),
            retransmission
                .request_hash(RequestOrigin::Controller)
                .unwrap()
        );
        assert_ne!(
            original.request_hash(RequestOrigin::Controller).unwrap(),
            original.request_hash(RequestOrigin::Provider).unwrap()
        );
        retransmission
            .body
            .insert("after_observation_sequence".into(), json!("1"));
        assert_ne!(
            original.request_hash(RequestOrigin::Controller).unwrap(),
            retransmission
                .request_hash(RequestOrigin::Controller)
                .unwrap()
        );
    }

    #[test]
    fn response_cannot_move_the_same_request_to_another_owner() {
        let original = request();
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.sequence = U64::new(72);
        original.matches_response(&response).unwrap();

        response.execution_owner_id = Nullable(Some(Id::new("foreign-owner").unwrap()));
        assert!(original.matches_response(&response).is_err());
    }
}
