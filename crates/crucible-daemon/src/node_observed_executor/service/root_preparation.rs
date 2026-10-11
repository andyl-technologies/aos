//! Retains queued fixed Root/Clock requests and their original native custody.
//!
//! ```text
//! RootPreparation.1 = original request + awaiting_admission | described | completed | unavailable
//! RootRecipe.1 = describe_held_uart | capture_held_uart | continue_held_uart(original signed artifact)
//! ```
//!
//! This route exposes the installed closed model's reviewed recipe, rather than
//! arbitrary Linux configurations or an imported prepared-world authority.

mod custody_geometry;
pub(super) mod diagnostics;
pub use diagnostics::{RootFirstRefusal, RootGrantedOperation, RootPreparationDiagnostic};
pub(super) mod ledger;
pub(super) mod worker;

use super::{NodeObservationServiceError, refused};
use crate::{node_observed_executor::InstalledNodeSelection, node_scenario::NodeScenario};
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_node_contract::{Bytes, ContentRef, Validate, canonical};
use serde::{Deserialize, Serialize};

pub(super) use super::conditional_preparation::{encode, execution_id, validate_execution};

/// Selects the fixed original UART cut or its authenticated held continuation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RootPreparationAction {
    /// Compiles immutable installed scenario data without preparing native owners.
    DescribeHeldUart {},
    /// Captures the original uncommitted UART publication at the reviewed cut.
    CaptureHeldUart {},
    /// Commits the same held publication beneath independently restored owners.
    ContinueHeldUart {
        /// Names the original signed artifact in the daemon's local archive.
        source: ContentRef,
    },
}

/// Commits exact ordered selections and scenario before slow native preparation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPreparationRequest {
    /// Names the closed request format.
    pub format: String,
    /// Names the recipe request edition independently of transport.
    pub version: u32,
    /// Preserves the nonzero original execution nonce.
    pub execution: String,
    /// Supplies the complete installed selection, never a resolved authority.
    pub selections: Vec<InstalledNodeSelection>,
    /// Retains the original independently compiled scenario bytes.
    pub scenario: Bytes,
    /// Selects only the source-qualified original recipe.
    pub action: RootPreparationAction,
}

impl RootPreparationRequest {
    /// Checks closed authored geometry before reservation or native effects.
    ///
    /// # Errors
    /// Refuses unknown editions, unsafe nonces, another selection or scenario,
    /// malformed artifact references, and excessive complete frame geometry.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        validate_execution(&self.execution)?;
        if self.format != "crucible.root-preparation-request"
            || self.version != 1
            || encode(&self.selections)? != encode(&worker::selections()?)?
            || self.scenario.as_slice().len() > 1024 * 1024
            || encode(self)?.len() > 4 * 1024 * 1024
        {
            return Err(refused("Root recipe edition or complete selection differs"));
        }
        if matches!(self.action, RootPreparationAction::DescribeHeldUart {}) {
            if !self.scenario.as_slice().is_empty() {
                return Err(refused(
                    "Root description requires the explicit empty scenario slot",
                ));
            }
        } else {
            NodeScenario::from_json(self.scenario.as_slice()).map_err(refused)?;
        }
        if let RootPreparationAction::ContinueHeldUart { source } = &self.action {
            source.validate().map_err(refused)?;
        }
        Ok(())
    }

    /// Decodes bounded raw request data without granting installed authority.
    ///
    /// # Errors
    /// Refuses duplicate or unknown fields, invalid geometry and unsupported recipes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let request: Self =
            serde_json::from_value(canonical::parse_json(bytes, 4 * 1024 * 1024).map_err(refused)?)
                .map_err(refused)?;
        request.validate()?;
        Ok(request)
    }
}

/// Reports original reservation or genuinely completed native work and retirement.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RootPreparationState {
    /// Returns independently measured scenario data without native readiness.
    Described {
        /// Retains the complete source-regenerated immutable scenario bytes.
        scenario: Bytes,
    },
    /// Original request bytes are retained without readiness or native authority.
    AwaitingAdmission {},
    /// The fixed recipe completed and both original supervisors reclaimed its world.
    Completed {
        /// Retains the exact source-regenerated complete scenario.
        scenario: Bytes,
        /// Names the original signed held-publication artifact.
        artifact: ContentRef,
        /// Retains the actual original operation outcome, including publication bytes.
        progress: Bytes,
        /// Distinguishes capture from genuine restored original commit and ACK.
        continued: bool,
    },
    /// Readiness or completion failed; the original request cannot dispatch again.
    Unavailable {
        /// Retains a finite diagnostic without claiming no native effects.
        reason: String,
    },
}

/// Retains the original request commitment and data-only durable status.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootPreparationRecord {
    /// Names the closed receipt format.
    pub format: String,
    /// Names this receipt edition.
    pub version: u32,
    /// Preserves the original operational nonce.
    pub execution: String,
    /// Commits exact original request bytes as a Trace.1 ContentId.
    pub request: String,
    /// Reports original custody without furnishing execution authority to clients.
    pub outcome: RootPreparationState,
}

impl RootPreparationRecord {
    /// Checks original scope and finite portable status bodies.
    ///
    /// # Errors
    /// Refuses changed editions or nonces, malformed identities and excessive bodies.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        validate_execution(&self.execution)?;
        let identity = ContentId::parse(&self.request).map_err(refused)?;
        if self.format != "crucible.root-preparation"
            || self.version != 1
            || identity.kind() != ObjectKind::Trace
            || identity.schema_version() != 1
            || identity.encode() != self.request
        {
            return Err(refused("Root original receipt edition differs"));
        }
        match &self.outcome {
            RootPreparationState::Described { scenario } => {
                if scenario.as_slice().len() > 1024 * 1024 {
                    return Err(refused("Root description exceeds complete scenario credit"));
                }
                NodeScenario::from_json(scenario.as_slice()).map_err(refused)?;
            }
            RootPreparationState::Completed {
                scenario,
                artifact,
                progress,
                ..
            } => {
                NodeScenario::from_json(scenario.as_slice()).map_err(refused)?;
                artifact.validate().map_err(refused)?;
                if scenario.as_slice().len() > 1024 * 1024
                    || progress.as_slice().len() > 1024 * 1024
                {
                    return Err(refused(
                        "Root original status exceeds reserved frame credit",
                    ));
                }
                canonical::parse_json(progress.as_slice(), 1024 * 1024).map_err(refused)?;
            }
            RootPreparationState::Unavailable { reason } if reason.len() > 4096 => {
                return Err(refused("Root refusal exceeds diagnostic credit"));
            }
            _ => {}
        }
        Ok(())
    }

    /// Decodes canonical original status without importing native readiness.
    ///
    /// # Errors
    /// Refuses invalid scope, unknown fields, excessive bytes or noncanonical records.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let record: Self =
            serde_json::from_value(canonical::parse_json(bytes, 4 * 1024 * 1024).map_err(refused)?)
                .map_err(refused)?;
        record.validate()?;
        if encode(&record)? != bytes {
            return Err(refused("Root original receipt is not canonical"));
        }
        Ok(record)
    }

    /// Encodes bounded original status for durable storage and control transport.
    ///
    /// # Errors
    /// Refuses invalid original scope or a status exceeding complete byte credit.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NodeObservationServiceError> {
        self.validate()?;
        let bytes = encode(self)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(refused(
                "Root original record exceeds reserved frame credit",
            ));
        }
        Ok(bytes)
    }
}

// Keep the original diagnostic within the receipt's byte ceiling, including
// multibyte text. Truncation never changes an effect or reclamation result.
pub(super) fn diagnostic(error: impl std::fmt::Display) -> String {
    let mut reason = error.to_string();
    if reason.len() > 4096 {
        let mut boundary = 4096;
        while !reason.is_char_boundary(boundary) {
            boundary -= 1;
        }
        reason.truncate(boundary);
    }
    reason
}

impl super::NodeObservationService {
    /// Reserves exact original Root recipe bytes before queueing slow preparation.
    ///
    /// # Errors
    /// Refuses changed scope, exhausted credits, stopped admission or uncertain
    /// durable reservation. Retained records never authorize another dispatch.
    pub fn submit_root_preparation(
        &self,
        request: RootPreparationRequest,
    ) -> Result<RootPreparationRecord, NodeObservationServiceError> {
        if self.stopping.load(std::sync::atomic::Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        let reservation = self.root_preparations.reserve(&request)?;
        let original = reservation.record.clone();
        if !reservation.original_dispatch {
            return Ok(original);
        }
        match self.commands.try_send(super::Command::RootPreparation {
            request,
            reservation: Box::new(reservation),
            ledger: self.root_preparations.clone(),
        }) {
            Ok(()) => Ok(original),
            Err(
                std::sync::mpsc::TrySendError::Full(super::Command::RootPreparation {
                    reservation,
                    ledger,
                    ..
                })
                | std::sync::mpsc::TrySendError::Disconnected(super::Command::RootPreparation {
                    reservation,
                    ledger,
                    ..
                }),
            ) => ledger.complete(
                &reservation,
                RootPreparationState::Unavailable {
                    reason: "original Root request could not enter the owning queue".into(),
                },
            ),
            Err(_) => Err(NodeObservationServiceError::Unavailable),
        }
    }

    /// Reads original diagnostics directly without waiting for the native actor.
    ///
    /// # Errors
    /// Refuses absent or corrupt original diagnostics; supplies no completion authority.
    pub fn root_preparation_diagnostic(
        &self,
        execution: &str,
    ) -> Result<RootPreparationDiagnostic, NodeObservationServiceError> {
        self.root_preparations.diagnostic(execution)
    }

    /// Reads the same durable Root status without native dispatch or actor waiting.
    ///
    /// # Errors
    /// Refuses unsafe nonces, absent original records and corrupt retained bytes.
    pub fn root_preparation_status(
        &self,
        execution: &str,
    ) -> Result<RootPreparationRecord, NodeObservationServiceError> {
        self.root_preparations.state(execution)
    }
}

#[cfg(test)]
mod tests;
