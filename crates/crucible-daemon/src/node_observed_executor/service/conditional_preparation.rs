//! Durable data-only admission receipts for original conditional source requests.
//!
//! ```text
//! ConditionalPreparation.1 = execution + exact original request ContentId
//!   + awaiting_admission | admitted(original ObservedRequest.2 bytes) | unavailable
//! ```
//!
//! Awaiting admission authenticates no source, node, capability or readiness.
//! Only the owning installed actor can link a genuine admitted observed request.

use crucible_campaign::observed_node_attempt::ObservedAttemptRequest;
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_node_contract::{Bytes, ContentRef, Id, Validate, canonical};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{NodeObservationServiceError, refused};

#[path = "conditional_preparation/ledger.rs"]
pub(super) mod ledger;

/// Retains a bounded original request before source authentication or allocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalPreparationRequest {
    /// Names the original durable observation ledger.
    pub ledger: String,
    /// Retains the original independent nonzero execution nonce.
    pub execution: String,
    /// Names both original signed source documents by exact typed references.
    pub sources: BTreeMap<Id, ContentRef>,
    /// Retains exact original configuration bytes without normalization.
    pub configuration: Bytes,
}

impl ConditionalPreparationRequest {
    /// Checks finite syntax without authenticating source applicability.
    ///
    /// # Errors
    /// Refuses invalid nonce/ledger geometry, incomplete actor roster, malformed
    /// typed references or excessive original configuration bytes.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        validate_execution(&self.execution)?;
        if self.ledger.is_empty()
            || self.ledger.len() > 128
            || !self
                .ledger
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            || self.sources.len() != 2
            || self.configuration.as_slice().len() > 4096
        {
            return Err(refused("conditional preparation request geometry differs"));
        }
        for (actor, reference) in &self.sources {
            actor.validate().map_err(refused)?;
            reference.validate().map_err(refused)?;
        }
        super::NodeRunConfiguration::from_json(self.configuration.as_slice()).map_err(refused)?;
        Ok(())
    }
}

/// Reports original preparation custody without claiming unverified readiness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionalPreparationState {
    /// The durable original request is owned; slow authentication is unfinished.
    AwaitingAdmission {},
    /// The installed actor linked its actual original observed request.
    Admitted {
        /// Preserves exact admitted RequestV2 bytes and its source-origin taint.
        observed_request: Bytes,
    },
    /// Preparation or publication became unavailable under original custody.
    ///
    /// This states no no-effect guarantee and permits no replacement dispatch.
    Unavailable {},
}

/// Carries the durable original admission receipt and its unique request commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalPreparationRecord {
    /// Identifies the closed data-only receipt format.
    pub format: String,
    /// Identifies this receipt's edition independently of control transport.
    pub version: u32,
    /// Retains the original independent nonzero execution nonce.
    pub execution: String,
    /// Names exact original request bytes as a Trace.1 ContentId.
    pub request: String,
    /// Retains pending custody or the genuinely authenticated observed request.
    pub outcome: ConditionalPreparationState,
}

impl ConditionalPreparationRecord {
    /// Checks the closed receipt's geometry without minting source authority.
    ///
    /// # Errors
    /// Refuses unsupported formats, invalid request identities or an admitted
    /// observed request with different nonce/mode or noncanonical raw bytes.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        validate_execution(&self.execution)?;
        let request = ContentId::parse(&self.request).map_err(refused)?;
        if self.format != "crucible.conditional-preparation"
            || self.version != 1
            || request.encode() != self.request
            || request.kind() != ObjectKind::Trace
            || request.schema_version() != 1
        {
            return Err(refused("conditional preparation receipt edition differs"));
        }
        if let ConditionalPreparationState::Admitted { observed_request } = &self.outcome {
            let request = ObservedAttemptRequest::from_canonical_bytes(observed_request.as_slice())
                .map_err(refused)?;
            if request.conditional_scope().is_none()
                || request.execution() != execution_id(&self.execution)?
                || request.canonical_bytes() != observed_request.as_slice()
            {
                return Err(refused(
                    "conditional preparation admitted another original request",
                ));
            }
        }
        Ok(())
    }

    /// Decodes finite canonical receipt bytes without granting execution authority.
    ///
    /// # Errors
    /// Refuses excessive size, unknown fields, altered spelling or invalid scope.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let value = canonical::parse_json(bytes, 1024 * 1024).map_err(refused)?;
        let record: Self = serde_json::from_value(value).map_err(refused)?;
        record.validate()?;
        if encode(&record)? != bytes {
            return Err(refused("conditional preparation receipt is not canonical"));
        }
        Ok(record)
    }

    /// Encodes the closed original receipt as finite canonical JSON bytes.
    ///
    /// # Errors
    /// Refuses invalid receipt geometry or excessive encoded size.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NodeObservationServiceError> {
        self.validate()?;
        let bytes = encode(self)?;
        if bytes.len() > 1024 * 1024 {
            return Err(refused(
                "conditional preparation receipt exceeds byte credit",
            ));
        }
        Ok(bytes)
    }
}

pub(super) fn validate_execution(execution: &str) -> Result<(), NodeObservationServiceError> {
    if execution.len() != 32
        || execution.bytes().all(|byte| byte == b'0')
        || !execution
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused(
            "conditional preparation requires original lowercase nonce32hex",
        ));
    }
    Ok(())
}

pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>, NodeObservationServiceError> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(refused)?).map_err(refused)
}

pub(super) fn execution_id(
    value: &str,
) -> Result<crucible_campaign::ExecutionId, NodeObservationServiceError> {
    validate_execution(value)?;
    let mut bytes = [0; 16];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte: u8| {
            if byte.is_ascii_digit() {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    crucible_campaign::ExecutionId::from_bytes(bytes).map_err(refused)
}

impl super::NodeObservationService {
    /// Durably reserves original source admission and queues it without waiting for verification.
    ///
    /// The returned pending record grants no readiness or replay capability.
    /// Exact retries return original custody, including a reservation from an
    /// earlier actor; they never dispatch its source request again.
    ///
    /// # Errors
    /// Refuses absent installed archive, changed original nonce/bytes, excessive
    /// geometry, nondurable storage, stopped admission or unresolved publication.
    pub fn submit_conditional_preparation(
        &self,
        request: ConditionalPreparationRequest,
    ) -> Result<ConditionalPreparationRecord, NodeObservationServiceError> {
        if self.stopping.load(std::sync::atomic::Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        let ledger = self
            .preparations
            .as_ref()
            .ok_or_else(|| refused("conditional source archive is not installed"))?;
        let reservation = ledger.reserve(&request)?;
        let original = reservation.record.clone();
        if !reservation.original_dispatch {
            return Ok(original);
        }
        match self
            .commands
            .try_send(super::Command::ConditionalPreparation {
                request,
                reservation,
                ledger: ledger.clone(),
            }) {
            Ok(()) => Ok(original),
            Err(
                std::sync::mpsc::TrySendError::Full(work)
                | std::sync::mpsc::TrySendError::Disconnected(work),
            ) => {
                let super::Command::ConditionalPreparation {
                    reservation,
                    ledger,
                    ..
                } = work
                else {
                    return Err(refused(
                        "conditional preparation queue returned another work scope",
                    ));
                };
                ledger.complete(&reservation, ConditionalPreparationState::Unavailable {})
            }
        }
    }

    /// Reads the original durable preparation status without native dispatch or actor waiting.
    ///
    /// # Errors
    /// Refuses missing original receipt, invalid nonce, absent installed archive
    /// or unavailable/corrupt original durable custody.
    pub fn conditional_preparation_status(
        &self,
        execution: &str,
    ) -> Result<ConditionalPreparationRecord, NodeObservationServiceError> {
        self.preparations
            .as_ref()
            .ok_or_else(|| refused("conditional source archive is not installed"))?
            .state(execution)
    }
}

#[cfg(test)]
#[path = "conditional_preparation/tests.rs"]
mod tests;
