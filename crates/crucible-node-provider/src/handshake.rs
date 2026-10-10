//! Authenticated initial and resumed CNP/1 negotiation beneath host custody.
//!
//! Negotiated wire fields remain claims until a trusted in-process verifier
//! binds them to installed launch identity, actual peer credentials, verified
//! schemas, and qualification. A connection lease authorizes control-stream
//! registration only; it never grants native execution or global activation.

use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use crucible_node_contract::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    ProviderError,
    bodies::{OperationState, ResponseShape, invalid},
    envelope::Nullable,
};

mod extension_contract;
mod extension_handshake;
mod negotiation;

pub use extension_contract::*;
pub use extension_handshake::ExtensionHandshake;
pub use negotiation::*;

fn optional_nonnull<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Declares positive receiving ceilings within the baseline hard limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Bounds one UTF-8 JSON frame to at most 16777216 bytes.
    pub frame_bytes: U64,
    /// Bounds JSON container nesting to at most 64.
    pub nesting: U64,
    /// Bounds outstanding IDs in each request direction to at most 256.
    pub requests: U64,
    /// Bounds retained journal entries per request origin to at most 4096.
    pub journal_entries: U64,
    /// Bounds decoded inline chunks to at most 1048576 bytes.
    pub blob_chunk_bytes: U64,
}

impl Validate for Limits {
    fn validate(&self) -> Result<(), ContractError> {
        for (value, maximum) in [
            (self.frame_bytes, 16_777_216),
            (self.nesting, 64),
            (self.requests, 256),
            (self.journal_entries, 4096),
            (self.blob_chunk_bytes, 1_048_576),
        ] {
            if value.get() == 0 || value.get() > maximum {
                return Err(invalid(
                    "limits",
                    "require positive receiving ceilings within baseline hard caps",
                ));
            }
        }
        Ok(())
    }
}

impl Limits {
    /// Selects each smaller advertised positive receiving limit.
    ///
    /// # Errors
    /// Rejects either advertisement if it exceeds baseline bounds.
    pub fn intersection(self, other: Self) -> Result<Self, ContractError> {
        self.validate()?;
        other.validate()?;
        Ok(Self {
            frame_bytes: self.frame_bytes.min(other.frame_bytes),
            nesting: self.nesting.min(other.nesting),
            requests: self.requests.min(other.requests),
            journal_entries: self.journal_entries.min(other.journal_entries),
            blob_chunk_bytes: self.blob_chunk_bytes.min(other.blob_chunk_bytes),
        })
    }
}

/// Requests same-incarnation resumption without resetting retained identities.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeSession {
    /// Identifies the surviving admitted session.
    pub session_id: Id,
    /// Identifies the surviving process incarnation and native custody.
    pub incarnation_id: Id,
    /// Contains the 32-byte secret issued by the previous admitted exchange.
    pub resume_token: Bytes,
    /// Lists all unresolved operation IDs in strict ASCII order.
    pub unresolved_operation_ids: IdSet,
}

impl fmt::Debug for ResumeSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumeSession")
            .field("session_id", &self.session_id)
            .field("incarnation_id", &self.incarnation_id)
            .field("resume_token", &"<redacted>")
            .field("unresolved_operation_ids", &self.unresolved_operation_ids)
            .finish()
    }
}

impl Validate for ResumeSession {
    fn validate(&self) -> Result<(), ContractError> {
        if self.resume_token.as_slice().len() != 32 {
            return Err(invalid("resume_token", "require exactly 32 secret octets"));
        }
        self.unresolved_operation_ids.validate()
    }
}

/// Carries the sole initial or resumed pre-negotiation hello request.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloRequest {
    /// Offers protocol version identifiers, including CNP/1.
    pub versions: Vec<String>,
    /// Names the intended admitted world session.
    pub session_id: Id,
    /// Contains exactly 32 unpredictable controller challenge bytes.
    pub controller_nonce: Bytes,
    /// Lists every required feature, including cnp.core/1.
    pub required_features: IdSet,
    /// Lists offered optional feature identifiers.
    pub optional_features: IdSet,
    /// Advertises positive controller receiving limits.
    pub limits: Limits,
    /// Contains exactly 32 secret bytes from the private host launch channel.
    pub admission_token: Bytes,
    /// Adds a negotiated resumption object only when resuming a live incarnation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_nonnull"
    )]
    pub resume_session: Option<ResumeSession>,
    /// Carries explicitly negotiated hello extensions.
    pub extensions: Extensions,
}

impl fmt::Debug for HelloRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloRequest")
            .field("versions", &self.versions)
            .field("session_id", &self.session_id)
            .field("controller_nonce", &"<redacted>")
            .field("required_features", &self.required_features)
            .field("optional_features", &self.optional_features)
            .field("limits", &self.limits)
            .field("admission_token", &"<redacted>")
            .field("resume_session", &self.resume_session)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl Validate for HelloRequest {
    fn validate(&self) -> Result<(), ContractError> {
        if self.versions.is_empty() || self.versions.len() > MAX_ARRAY_ELEMENTS {
            return Err(invalid(
                "versions",
                "require bounded nonempty version advertisement",
            ));
        }
        let mut versions = BTreeSet::new();
        for version in &self.versions {
            Id::new(version.clone())?;
            if !versions.insert(version) {
                return Err(invalid("versions", "duplicate protocol version"));
            }
        }
        if !versions.contains(&"CNP/1".to_owned()) {
            return Err(invalid("versions", "baseline requires offered CNP/1"));
        }
        self.required_features.validate()?;
        self.optional_features.validate()?;
        if !self
            .required_features
            .iter()
            .any(|id| id.as_str() == "cnp.core/1")
        {
            return Err(invalid(
                "required_features",
                "controller must require cnp.core/1",
            ));
        }
        if self.controller_nonce.as_slice().len() != 32
            || self.admission_token.as_slice().len() != 32
        {
            return Err(invalid(
                "nonce",
                "hello challenge and admission token require exactly 32 octets",
            ));
        }
        self.limits.validate()?;
        if let Some(resume) = &self.resume_session {
            resume.validate()?;
        }
        Ok(())
    }
}

/// Retains one requested unresolved operation without re-executing it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumedOperation {
    /// Identifies the original registered operation.
    pub operation_id: Id,
    /// Reports its retained state, including unresolved native uncertainty.
    pub operation_state: OperationState,
    /// Retains the original terminal response, or explicit null while nonterminal.
    pub outcome: Nullable<Map<String, Value>>,
}

impl Validate for ResumedOperation {
    fn validate(&self) -> Result<(), ContractError> {
        if self.operation_state == OperationState::Completed && self.outcome.0.is_none() {
            return Err(invalid(
                "outcome",
                "completed resume record requires retained terminal response",
            ));
        }
        if let Some(outcome) = &self.outcome.0 {
            let response: ResponseShape = serde_json::from_value(Value::Object(outcome.clone()))?;
            response.validate()?;
            if response.is_accepted() || response.operation_state() != self.operation_state {
                return Err(invalid(
                    "outcome",
                    "resume record must retain original terminal state",
                ));
            }
        }
        Ok(())
    }
}

/// Carries negotiated wire claims that still require trusted host verification.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloResult {
    /// Selects the common baseline version CNP/1.
    pub version: String,
    /// Echoes the admitted session identity.
    pub session_id: Id,
    /// Names the surviving measured provider incarnation.
    pub incarnation_id: Id,
    /// Echoes the controller's exact challenge bytes.
    pub controller_nonce: Bytes,
    /// Contains exactly 32 unpredictable provider challenge bytes.
    pub provider_nonce: Bytes,
    /// Lists the exact mutually selected features in ASCII order.
    pub selected_features: IdSet,
    /// Selects each smaller advertised receiving limit.
    pub limits: Limits,
    /// Returns a fresh 32-byte resume secret, or explicit null without resumption.
    pub resume_token: Nullable<Bytes>,
    /// Reports the implementation manifest without asserting host measurement.
    pub provider_identity: ProviderManifest,
    /// Lists exactly the requested retained operation records, or empty initially.
    pub resumed_operations: Vec<ResumedOperation>,
}

impl fmt::Debug for HelloResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelloResult")
            .field("version", &self.version)
            .field("session_id", &self.session_id)
            .field("incarnation_id", &self.incarnation_id)
            .field("controller_nonce", &"<redacted>")
            .field("provider_nonce", &"<redacted>")
            .field("selected_features", &self.selected_features)
            .field("limits", &self.limits)
            .field("resume_token", &"<redacted>")
            .field("provider_identity", &self.provider_identity)
            .field("resumed_operations", &self.resumed_operations)
            .finish()
    }
}

impl Validate for HelloResult {
    fn validate(&self) -> Result<(), ContractError> {
        if self.version != "CNP/1" {
            return Err(invalid("version", "unsupported baseline protocol"));
        }
        if self.controller_nonce.as_slice().len() != 32
            || self.provider_nonce.as_slice().len() != 32
        {
            return Err(invalid(
                "nonce",
                "challenge values require exactly 32 octets",
            ));
        }
        self.selected_features.validate()?;
        self.limits.validate()?;
        self.provider_identity.validate()?;
        if !self
            .provider_identity
            .protocol_versions
            .iter()
            .any(|version| version.as_str() == "CNP/1")
        {
            return Err(invalid(
                "provider_identity",
                "manifest does not offer selected CNP/1 version",
            ));
        }
        if !self
            .selected_features
            .iter()
            .any(|feature| feature.as_str() == "cnp.core/1")
        {
            return Err(invalid(
                "selected_features",
                "baseline hello must select core feature",
            ));
        }
        let resume = self
            .selected_features
            .iter()
            .any(|id| id.as_str() == "cnp.resume/1");
        match (&self.resume_token.0, resume) {
            (Some(token), true) if token.as_slice().len() == 32 => {}
            (None, false) => {}
            _ => {
                return Err(invalid(
                    "resume_token",
                    "resume selection requires exactly one 32-byte token",
                ));
            }
        }
        if self.resumed_operations.len() > MAX_ARRAY_ELEMENTS
            || self
                .resumed_operations
                .windows(2)
                .any(|pair| pair[0].operation_id >= pair[1].operation_id)
        {
            return Err(invalid(
                "resumed_operations",
                "require bounded strictly sorted operation records",
            ));
        }
        for operation in &self.resumed_operations {
            operation.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These handshake tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
pub(crate) mod tests;
