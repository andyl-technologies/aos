//! Bounded observations of retained controls for the installed checksum witness.
//!
//! These values contain canonical encodings of original decoded envelopes,
//! rather than a complete byte-for-byte stream history. They neither authorize
//! native effects nor certify implementation behavior. A separate source-owned
//! witness selects its complete case population and authenticates the evidence.

use std::collections::BTreeSet;

use crucible_node_contract::{
    BindingCompatibility, Bytes, ContentRef, HashRef, Id, IdSet, U64, canonical,
};
use serde::Serialize;
use serde_json::Value;

use crate::ProviderError;
use crate::client::ClientOriginal;
use crate::envelope::{Envelope, Method, Nullable, RequestOrigin};

use super::ReferenceController;

#[path = "observer.rs"]
mod observer;

pub(super) use observer::ObservationRecorder;
pub use observer::{ObservationHandle, RecordedReferenceObservation};

const MAX_REQUESTS: usize = 4096;
const MAX_OBJECTS: usize = 4096;
const MAX_BYTES: usize = 64 * 1024 * 1024;

/// Bounds independently selected observations before persistent copies are made.
#[derive(Clone, Copy, Debug)]
pub struct ObservationLimits {
    /// Bounds selected original request identities across both directions.
    pub maximum_requests: usize,
    /// Bounds selected immutable content objects, excluding encoded controls.
    pub maximum_objects: usize,
    /// Bounds the aggregate raw control and selected content bytes.
    pub maximum_bytes: usize,
}

impl ObservationLimits {
    fn validate(self) -> Result<(), ProviderError> {
        if self.maximum_requests == 0
            || self.maximum_requests > MAX_REQUESTS
            || self.maximum_objects == 0
            || self.maximum_objects > MAX_OBJECTS
            || self.maximum_bytes == 0
            || self.maximum_bytes > MAX_BYTES
        {
            return Err(ProviderError::ResourceExhausted(
                "invalid control observation ceilings",
            ));
        }
        Ok(())
    }
}

/// Identifies an original without conflating equal IDs in opposite directions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ObservedRequestKey {
    /// Names the independently retained originating endpoint.
    pub origin: RequestOrigin,
    /// Names that endpoint's immutable original request.
    pub request_id: Id,
}

/// Retains verified bytes without making a claim about their native semantics.
#[derive(Clone, Debug, Serialize)]
pub struct ObservedContent {
    /// Commits to the exact bytes, length and original media type.
    pub reference: ContentRef,
    /// Contains selected original bytes, encoded as base64url when serialized.
    pub bytes: Bytes,
}

/// Retains the canonical original control and its latest authentic response.
#[derive(Clone, Debug, Serialize)]
pub struct ObservedRequest {
    /// Preserves the original endpoint namespace and request ID.
    pub key: ObservedRequestKey,
    /// Preserves the original origin-scoped request identity, excluding sequence.
    pub identity: HashRef,
    /// Contains the original decoded envelope's canonical JSON bytes.
    pub request: ObservedContent,
    /// Contains the latest received response, or explicit null when absent.
    ///
    /// Null does not imply that native effects were absent. Earlier responses
    /// and arbitrary noncanonical transport encodings are not reconstructed.
    pub response: Nullable<ObservedContent>,
}

/// Describes measured and negotiated scope without copying private credentials.
#[derive(Clone, Debug, Serialize)]
pub struct ObservationScope {
    /// Names the actual kernel peer from the retained authenticated connection.
    pub provider_pid: U64,
    /// Commits to the independently measured public endpoint executable.
    pub provider_executable: ContentRef,
    /// Names the original admitted session.
    pub session_id: Id,
    /// Names the actual surviving owner incarnation.
    pub incarnation_id: Id,
    /// Names the physical connection whose custody is observed.
    pub connection_id: Id,
    /// Retains the host-local connection epoch, independently of world time.
    pub connection_epoch: U64,
    /// Lists the exact mutually selected semantic features.
    pub selected_features: IdSet,
    /// Contains the complete immutable installed compatibility projection.
    pub compatibility: BindingCompatibility,
    /// Commits to that exact compatibility projection.
    pub binding_hash: HashRef,
}

/// Contains selected original observations for a separate fixed-source witness.
///
/// Selection is explicit and is not a claim that the selected content is a
/// complete native state or receipt closure. The independent witness supplies
/// source/tool/environment identities, companion enrollment, case definitions,
/// and oracle results. This object carries no qualification verdict.
#[derive(Clone, Debug, Serialize)]
pub struct ReferenceObservationSnapshot {
    /// Selects observation encoding version 1.
    pub schema_version: u16,
    /// Names the truthful decoded-envelope custody encoding.
    pub encoding: &'static str,
    /// Retains the exact observed installation and negotiated connection scope.
    pub scope: ObservationScope,
    /// Lists explicitly selected originals in endpoint/ID order.
    pub requests: Vec<ObservedRequest>,
    /// Lists explicitly selected verified objects in complete-reference order.
    pub objects: Vec<ObservedContent>,
}

impl ReferenceObservationSnapshot {
    /// Encodes the observation with a separate finite serialized-byte ceiling.
    ///
    /// This operation does not persist files, acknowledge receipts, or grant
    /// qualification. The caller chooses a bounded local artifact destination.
    ///
    /// # Errors
    /// Refuses zero or greater-than64MiB ceilings, oversized serialization, or
    /// noncanonical values. Base64 expansion counts against this output limit.
    pub fn encode(&self, maximum_bytes: usize) -> Result<Vec<u8>, ProviderError> {
        encode_observation(self, maximum_bytes)
    }
}

fn encode_observation(
    value: &impl Serialize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ProviderError> {
    if maximum_bytes == 0 || maximum_bytes > MAX_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "invalid serialized observation ceiling",
        ));
    }
    let mut counter = SerializationBudget {
        remaining: maximum_bytes,
    };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| ProviderError::ResourceExhausted("serialized observation ceiling"))?;

    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > maximum_bytes {
        return Err(ProviderError::ResourceExhausted(
            "canonical observation ceiling",
        ));
    }
    Ok(bytes)
}

impl ReferenceController {
    /// Observes explicitly selected originals and verified content without effects.
    ///
    /// Handshake and bootstrap objects are never exported. The controller's
    /// read-only journal preserves endpoint origin, original IDs and actual
    /// sequence values. Unanswered requests remain unanswered; taking a
    /// snapshot does not retry, poll, release, or replace their obligations.
    ///
    /// # Errors
    /// Refuses absent originals, duplicate selectors, invalid original scope or
    /// identity, credential-bearing controls, unavailable or changed content,
    /// private bootstrap content, or exhausted observation credit.
    pub fn observation_snapshot(
        &self,
        requests: &[ObservedRequestKey],
        references: &[ContentRef],
        limits: ObservationLimits,
    ) -> Result<ReferenceObservationSnapshot, ProviderError> {
        limits.validate()?;
        if requests.len() > limits.maximum_requests || references.len() > limits.maximum_objects {
            return Err(ProviderError::ResourceExhausted(
                "selected observation cardinality",
            ));
        }
        let scope = self.observation_scope()?;

        let mut selected = Vec::with_capacity(requests.len());
        let mut keys = BTreeSet::new();
        for key in requests {
            if !keys.insert(key.clone()) {
                return Err(ProviderError::Conflict("duplicate observed original"));
            }
            let original = self
                .custody
                .original(key.origin, &key.request_id)
                .ok_or(ProviderError::Correlation("observed original unavailable"))?;
            reject_private_envelope(&original.request, self.bootstrap.admission_token.as_slice())?;
            if let Some(response) = &original.response {
                reject_private_envelope(response, self.bootstrap.admission_token.as_slice())?;
            }
            selected.push((key, original));
        }
        selected.sort_by_key(|(key, _)| *key);

        let mut content = Vec::with_capacity(references.len());
        let mut selected_references = BTreeSet::new();
        for reference in references {
            if !selected_references.insert(reference) {
                return Err(ProviderError::Conflict("duplicate observed content"));
            }
            let bytes = self.content(reference)?;
            // Secret bootstrap bytes are not installed as public content, but
            // reject their exact token if a caller selected an accidental copy.
            reject_private_content(bytes, self.bootstrap.admission_token.as_slice())?;
            content.push((reference, bytes));
        }
        content.sort_by_key(|(reference, _)| *reference);
        snapshot(scope, &selected, &content, limits)
    }

    fn observation_scope(&self) -> Result<ObservationScope, ProviderError> {
        let authority = self.session.authority();
        let (binding, _) = self.binding()?;
        reject_credentials(
            &serde_json::to_value(&binding.compatibility)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?;
        Ok(ObservationScope {
            provider_pid: U64::new(u64::from(self.peer_pid())),
            provider_executable: self.peer_executable().clone(),
            session_id: authority.session_id().clone(),
            incarnation_id: authority.incarnation_id().clone(),
            connection_id: authority.connection_id().clone(),
            connection_epoch: U64::new(authority.epoch()),
            selected_features: authority.selected_features().clone(),
            binding_hash: binding.identity()?,
            compatibility: binding.compatibility,
        })
    }
}

fn snapshot(
    scope: ObservationScope,
    originals: &[(&ObservedRequestKey, &ClientOriginal)],
    content: &[(&ContentRef, &[u8])],
    limits: ObservationLimits,
) -> Result<ReferenceObservationSnapshot, ProviderError> {
    limits.validate()?;
    if originals.len() > limits.maximum_requests || content.len() > limits.maximum_objects {
        return Err(ProviderError::ResourceExhausted(
            "selected observation cardinality",
        ));
    }
    let mut budget = ByteBudget(limits.maximum_bytes);
    for (reference, bytes) in content {
        budget.reserve(bytes.len())?;
        reference.verify(bytes)?;
    }

    let mut requests = Vec::with_capacity(originals.len());
    for (key, original) in originals {
        let request = &original.request;
        if request.method == Method::Hello {
            return Err(ProviderError::Frame("handshake observations are private"));
        }
        if request.request_id.0.as_ref() != Some(&key.request_id)
            || request.session_id.0.as_ref() != Some(&scope.session_id)
            || request.incarnation_id.0.as_ref() != Some(&scope.incarnation_id)
        {
            return Err(ProviderError::Correlation(
                "observed original scope changed",
            ));
        }
        reject_credentials(
            &serde_json::to_value(request).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        if request.request_hash(key.origin)? != original.identity {
            return Err(ProviderError::Conflict(
                "observed original identity changed",
            ));
        }
        let request = envelope_content(request, &mut budget)?;
        let response = original
            .response
            .as_ref()
            .map(|response| {
                original.request.matches_response(response)?;
                envelope_content(response, &mut budget)
            })
            .transpose()?;
        requests.push(ObservedRequest {
            key: (*key).clone(),
            identity: original.identity.clone(),
            request,
            response: Nullable(response),
        });
    }

    // Persistent content copies happen only after the complete aggregate fits.
    let objects = content
        .iter()
        .map(|(reference, bytes)| ObservedContent {
            reference: (*reference).clone(),
            bytes: Bytes::new(bytes.to_vec()),
        })
        .collect();
    Ok(ReferenceObservationSnapshot {
        schema_version: 1,
        encoding: "retained-canonical-envelope-v1",
        scope,
        requests,
        objects,
    })
}

fn envelope_content(
    envelope: &Envelope,
    budget: &mut ByteBudget,
) -> Result<ObservedContent, ProviderError> {
    envelope.validate()?;
    let value =
        serde_json::to_value(envelope).map_err(crucible_node_contract::ContractError::from)?;
    reject_credentials(&value)?;
    let bytes = canonical::canonical_json(&value)?;
    budget.reserve(bytes.len())?;
    Ok(ObservedContent {
        reference: canonical::content_ref(&bytes, "application/json")?,
        bytes: Bytes::new(bytes),
    })
}

fn reject_credentials(value: &Value) -> Result<(), ProviderError> {
    reject_credentials_at_depth(value, 0)
}

fn reject_credentials_at_depth(value: &Value, depth: usize) -> Result<(), ProviderError> {
    if matches!(value, Value::Array(_) | Value::Object(_)) && depth >= crate::transport::MAX_NESTING
    {
        return Err(ProviderError::Frame("observation nesting ceiling"));
    }
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if matches!(
                    name.as_str(),
                    "admission_token" | "resume_token" | "controller_nonce" | "provider_nonce"
                ) {
                    return Err(ProviderError::Frame("private control credential selected"));
                }
                reject_credentials_at_depth(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_credentials_at_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_private_content(bytes: &[u8], secret: &[u8]) -> Result<(), ProviderError> {
    if secret.is_empty() || bytes.windows(secret.len()).any(|window| window == secret) {
        return Err(ProviderError::Frame("private launch content selected"));
    }
    let encoded = serde_json::to_value(Bytes::new(secret.to_vec()))
        .map_err(crucible_node_contract::ContractError::from)?;
    let encoded = encoded
        .as_str()
        .ok_or(ProviderError::Frame("invalid private credential encoding"))?;
    if bytes
        .windows(encoded.len())
        .any(|window| window == encoded.as_bytes())
    {
        return Err(ProviderError::Frame("private launch credential selected"));
    }
    if let Ok(value) = canonical::parse_json(bytes, MAX_BYTES) {
        reject_credentials(&value)?;
        if contains_private_text(&value, encoded) {
            return Err(ProviderError::Frame("private launch credential selected"));
        }
    }
    Ok(())
}

fn contains_private_text(value: &Value, secret: &str) -> bool {
    match value {
        Value::String(text) => text.contains(secret),
        Value::Object(fields) => fields
            .iter()
            .any(|(name, value)| name.contains(secret) || contains_private_text(value, secret)),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_private_text(value, secret)),
        _ => false,
    }
}

fn reject_private_envelope(envelope: &Envelope, secret: &[u8]) -> Result<(), ProviderError> {
    if envelope.method == Method::Hello {
        return Err(ProviderError::Frame("handshake observations are private"));
    }
    let bytes =
        serde_json::to_vec(envelope).map_err(crucible_node_contract::ContractError::from)?;
    reject_private_content(&bytes, secret)
}

struct ByteBudget(usize);

impl ByteBudget {
    fn reserve(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.0 = self
            .0
            .checked_sub(bytes)
            .ok_or(ProviderError::ResourceExhausted(
                "control observation bytes",
            ))?;
        Ok(())
    }
}

struct SerializationBudget {
    remaining: usize,
}

impl std::io::Write for SerializationBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self.remaining.checked_sub(bytes.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::OutOfMemory, "observation byte ceiling")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
