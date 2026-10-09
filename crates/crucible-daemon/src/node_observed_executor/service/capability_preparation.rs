//! Owns original authored capability requests across asynchronous admission.
//!
//! ```text
//! CapabilityPreparation.1 = original request commitment + pending | admitted
//!   (complete scenario + original observed request) | native(archive + progress)
//! ```
//!
//! Raw requirements remain immutable bytes. Candidate recipes select installed
//! models; they cannot supply resolved authority or replace catalog policy.

pub(super) mod ledger;
mod native;
#[cfg(test)]
mod tests;

use super::{ActorStorage, ActorWorker, NodeObservationServiceError, refused};
use crate::{
    node_observed_executor::{
        InstalledCapabilityCandidate, InstalledNodeCatalog, InstalledNodeSelection,
    },
    node_scenario::{NodeRunConfiguration, NodeScenario},
};
use crucible_campaign::{
    ExecutionId,
    observed_node_attempt::{ObservedAttemptRequest, ObservedAttemptWorker},
};
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_node_contract::{Bytes, ContentRef, Id, Validate, canonical};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// The record is itself wrapped in portable Bytes by control7. These ceilings
// reserve both base64 expansions and bounded transport metadata before native
// allocation; an independently valid scenario may exceed this operator route.
const MAX_RECEIPT_SCENARIO_BYTES: usize = 6 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 12 * 1024 * 1024 - 32 * 1024;

/// Supplies a complete installed candidate recipe without claiming applicability.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCandidateRecipe {
    /// Names this complete alternative without imposing a preference.
    pub id: Id,
    /// Names every installed node and owner in this alternative.
    pub selections: Vec<InstalledNodeSelection>,
}

/// Selects live observation or the independently qualified standalone Clock codec.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityPreparationAction {
    /// Executes the selected complete world through its ordinary observed worker.
    Observe {},
    /// Captures an actual standalone Clock at the configuration's planner horizon.
    Capture {},
    /// Continues an authenticated original standalone Clock under fresh custody.
    Continue {
        /// Names the original signed native artifact in the installed local archive.
        source: ContentRef,
    },
}

/// Preserves raw demands and complete choices before slow native admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPreparationRequest {
    /// Identifies this closed authored request format.
    pub format: String,
    /// Identifies the request edition independently of transport.
    pub version: u32,
    /// Names the durable observed execution ledger.
    pub ledger: String,
    /// Preserves the original nonzero lowercase execution nonce.
    pub execution: String,
    /// Retains exact authored mandatory requirements bytes without normalization.
    pub requirements: Bytes,
    /// Supplies complete bounded alternatives, sorted by unique identity.
    pub candidates: Vec<CapabilityCandidateRecipe>,
    /// Retains exact authored execution configuration bytes.
    pub configuration: Bytes,
    /// Selects the source-qualified operation without imported resolved authority.
    pub action: CapabilityPreparationAction,
}

impl CapabilityPreparationRequest {
    /// Checks bounded authored syntax before reservation or native allocation.
    ///
    /// # Errors
    /// Refuses unknown formats, unsafe nonce/ledger spelling, excessive choices,
    /// invalid raw demand/configuration geometry, or malformed source references.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        validate_execution(&self.execution)?;
        if self.format != "crucible.capability-preparation-request"
            || self.version != 1
            || self.ledger.is_empty()
            || self.ledger.len() > 128
            || !self
                .ledger
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            || self.candidates.is_empty()
            || self.candidates.len() > 64
            || self
                .candidates
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || self.configuration.as_slice().len() > 4096
            || self.requirements.as_slice().len() > 1024 * 1024
        {
            return Err(refused(
                "capability request edition or finite geometry differs",
            ));
        }
        let demands: crucible::node_admission::CapabilityRequirements = serde_json::from_value(
            canonical::parse_json(self.requirements.as_slice(), 1024 * 1024).map_err(refused)?,
        )
        .map_err(refused)?;
        demands.validate().map_err(refused)?;
        NodeRunConfiguration::from_json(self.configuration.as_slice()).map_err(refused)?;
        for candidate in &self.candidates {
            candidate.id.validate().map_err(refused)?;
            if candidate.selections.is_empty()
                || candidate.selections.len() > 64
                || candidate
                    .selections
                    .windows(2)
                    .any(|pair| pair[0].node >= pair[1].node)
            {
                return Err(refused("capability complete candidate geometry differs"));
            }
        }
        if let CapabilityPreparationAction::Continue { source } = &self.action {
            source.validate().map_err(refused)?;
        }
        if encode(self)?.len() > 4 * 1024 * 1024 {
            return Err(refused("capability original request exceeds byte credit"));
        }
        Ok(())
    }

    /// Decodes bounded closed JSON while preserving nested original raw bytes.
    ///
    /// # Errors
    /// Refuses duplicate keys, excessive size, unknown fields or invalid geometry.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let request: Self =
            serde_json::from_value(canonical::parse_json(bytes, 4 * 1024 * 1024).map_err(refused)?)
                .map_err(refused)?;
        request.validate()?;
        Ok(request)
    }
}

/// Reports data-only custody or an actual source-qualified installed operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityPreparationState {
    /// Original request bytes are durable; no native applicability is claimed.
    AwaitingAdmission {},
    /// An ordinary observed worker owns this exact installed selected world.
    Admitted {
        /// Retains the complete capability wrapper and all selected compatibilities.
        scenario: Bytes,
        /// Retains exact original ordinary observed request bytes.
        observed_request: Bytes,
    },
    /// A qualified Clock native operation completed under original custody.
    Native {
        /// Retains the complete selected capability-bearing scenario bytes.
        scenario: Bytes,
        /// Names the signed unchanged-cut or genuine future native capture.
        artifact: ContentRef,
        /// Retains actual original operation outcome bytes, without relabeling.
        progress: Bytes,
    },
    /// The original operation could not become usable; redispatch is forbidden.
    Unavailable {
        /// Retains a bounded diagnostic without claiming no native effects.
        reason: String,
    },
}

/// Retains a durable original request and its source-qualified admission result.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPreparationRecord {
    /// Names the closed receipt format.
    pub format: String,
    /// Names this data edition independently of transport.
    pub version: u32,
    /// Preserves the original operational execution nonce.
    pub execution: String,
    /// Commits exact original request bytes as a Trace.1 ContentId.
    pub request: String,
    /// Reports custody without granting runtime authority to the client.
    pub outcome: CapabilityPreparationState,
}

impl CapabilityPreparationRecord {
    /// Checks scope and finite bodies without minting installed authority.
    ///
    /// # Errors
    /// Refuses altered receipt editions, raw identities, original observed scope,
    /// capability wrappers, source references or excessive body sizes.
    pub fn validate(&self) -> Result<(), NodeObservationServiceError> {
        validate_execution(&self.execution)?;
        let identity = ContentId::parse(&self.request).map_err(refused)?;
        if self.format != "crucible.capability-preparation"
            || self.version != 1
            || identity.kind() != ObjectKind::Trace
            || identity.schema_version() != 1
            || identity.encode() != self.request
        {
            return Err(refused("capability receipt edition differs"));
        }
        match &self.outcome {
            CapabilityPreparationState::Admitted {
                scenario,
                observed_request,
            } => {
                validate_scenario(scenario)?;
                let observed =
                    ObservedAttemptRequest::from_canonical_bytes(observed_request.as_slice())
                        .map_err(refused)?;
                if observed.execution() != execution_id(&self.execution)?
                    || observed.conditional_scope().is_some()
                    || observed.canonical_bytes() != observed_request.as_slice()
                {
                    return Err(refused(
                        "capability receipt changed original observed scope",
                    ));
                }
            }
            CapabilityPreparationState::Native {
                scenario,
                artifact,
                progress,
            } => {
                validate_scenario(scenario)?;
                artifact.validate().map_err(refused)?;
                if progress.as_slice().len() > 1024 * 1024 {
                    return Err(refused("native progress credit differs"));
                }
                canonical::parse_json(progress.as_slice(), 1024 * 1024).map_err(refused)?;
            }
            CapabilityPreparationState::Unavailable { reason } if reason.len() > 4096 => {
                return Err(refused("capability diagnostic exceeds credit"));
            }
            _ => {}
        }
        Ok(())
    }

    /// Decodes exact canonical original receipt bytes.
    ///
    /// # Errors
    /// Refuses unsupported fields, changed scope, excessive bytes or noncanonical spelling.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NodeObservationServiceError> {
        let record: Self = serde_json::from_value(
            canonical::parse_json(bytes, MAX_RECEIPT_BYTES).map_err(refused)?,
        )
        .map_err(refused)?;
        record.validate()?;
        if encode(&record)? != bytes {
            return Err(refused("capability receipt is not canonical"));
        }
        Ok(record)
    }

    /// Encodes the immutable data-only receipt under finite byte credit.
    ///
    /// # Errors
    /// Refuses invalid scope or an encoded body larger than its reserved ceiling.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NodeObservationServiceError> {
        self.validate()?;
        let bytes = encode(self)?;
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(refused("capability receipt exceeds byte credit"));
        }
        Ok(bytes)
    }
}

fn validate_scenario_credit(bytes: &Bytes) -> Result<(), NodeObservationServiceError> {
    if bytes.as_slice().len() > MAX_RECEIPT_SCENARIO_BYTES {
        return Err(refused(
            "capability scenario exceeds complete transport receipt credit",
        ));
    }
    Ok(())
}

fn validate_scenario(bytes: &Bytes) -> Result<(), NodeObservationServiceError> {
    validate_scenario_credit(bytes)?;
    let scenario = NodeScenario::from_json(bytes.as_slice()).map_err(refused)?;
    if scenario.world.scenario_ref.media_type
        != crucible::node_admission::CAPABILITY_SELECTION_MEDIA_TYPE
    {
        return Err(refused(
            "capability receipt lacks original requirement wrapper",
        ));
    }
    Ok(())
}

pub(super) use super::conditional_preparation::{encode, execution_id, validate_execution};

impl super::NodeObservationService {
    /// Durably reserves original authored requirements and queues one installed resolution.
    ///
    /// # Errors
    /// Refuses changed nonce/bytes, finite quota exhaustion, stopped admission or
    /// unavailable durable publication. Retries return original custody only.
    pub fn submit_capability_preparation(
        &self,
        request: CapabilityPreparationRequest,
    ) -> Result<CapabilityPreparationRecord, NodeObservationServiceError> {
        if self.stopping.load(std::sync::atomic::Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        let reservation = self.capabilities.reserve(&request)?;
        let original = reservation.record.clone();
        if !reservation.original_dispatch {
            return Ok(original);
        }
        match self
            .commands
            .try_send(super::Command::CapabilityPreparation {
                request,
                reservation: Box::new(reservation),
                ledger: self.capabilities.clone(),
            }) {
            Ok(()) => Ok(original),
            Err(
                std::sync::mpsc::TrySendError::Full(super::Command::CapabilityPreparation {
                    reservation,
                    ledger,
                    ..
                })
                | std::sync::mpsc::TrySendError::Disconnected(
                    super::Command::CapabilityPreparation {
                        reservation,
                        ledger,
                        ..
                    },
                ),
            ) => ledger.complete(
                &reservation,
                CapabilityPreparationState::Unavailable {
                    reason: "finite owning admission queue unavailable".into(),
                },
            ),
            Err(_) => Err(refused("capability queue returned another original scope")),
        }
    }

    /// Reads original durable admission without waiting for a native actor.
    ///
    /// # Errors
    /// Refuses absent original requests, invalid identities or unavailable storage.
    pub fn capability_preparation_status(
        &self,
        execution: &str,
    ) -> Result<CapabilityPreparationRecord, NodeObservationServiceError> {
        self.capabilities.state(execution)
    }
}

pub(super) fn execute(
    request: CapabilityPreparationRequest,
    workers: &mut BTreeMap<ExecutionId, ActorWorker>,
    catalog: &mut InstalledNodeCatalog,
    maximum_worlds: usize,
    storage: &ActorStorage,
) -> Result<CapabilityPreparationState, NodeObservationServiceError> {
    request.validate()?;
    let execution = execution_id(&request.execution)?;
    // A different ordinary/conditional reservation never becomes an imported
    // capability dispatch permission, even if its scenario happens to match.
    if workers.contains_key(&execution)
        || storage
            .repository
            .observed_execution_state(execution)
            .map_err(refused)?
            .is_some()
    {
        return Err(refused(
            "execution nonce already belongs to another original worker",
        ));
    }
    if workers.len() >= maximum_worlds {
        return Err(NodeObservationServiceError::Capacity);
    }
    let candidates = request
        .candidates
        .iter()
        .map(|recipe| InstalledCapabilityCandidate {
            id: recipe.id.clone(),
            selections: recipe.selections.clone(),
        })
        .collect::<Vec<_>>();
    let resolved = catalog
        .resolve_capabilities_raw(&candidates, request.requirements.as_slice())
        .map_err(refused)?;
    let scenario = Bytes::new(resolved.scenario().canonical_bytes().map_err(refused)?);
    validate_scenario_credit(&scenario)?;
    let configuration =
        NodeRunConfiguration::from_json(request.configuration.as_slice()).map_err(refused)?;
    if !matches!(request.action, CapabilityPreparationAction::Observe {}) {
        return native::execute(request, catalog, resolved, configuration, storage);
    }
    let backend = catalog
        .prepare_capability(
            &resolved,
            configuration,
            execution,
            storage.blobs.clone(),
            storage.refs.clone(),
        )
        .map_err(refused)?;
    let artifact = backend.scenario_artifact();
    storage
        .repository
        .publish_scenario_artifact(
            artifact.scenario(),
            artifact.payload_schema(),
            artifact.payload().to_vec(),
        )
        .map_err(refused)?;
    let config = backend.configuration_artifact();
    storage
        .repository
        .publish_configuration_artifact(
            config.scenario(),
            config.scenario_artifact(),
            config.configuration(),
            config.payload_schema(),
            config.payload().to_vec(),
        )
        .map_err(refused)?;
    let original = backend.request(execution).map_err(refused)?;
    let admission = backend.admission().clone();
    let worker =
        ObservedAttemptWorker::new(storage.repository.clone(), backend, 1).map_err(refused)?;
    workers.insert(
        execution,
        ActorWorker {
            worker,
            request: original,
            admission,
            replay: None,
        },
    );
    let owned = workers
        .get_mut(&execution)
        .ok_or_else(|| refused("original capability worker custody absent"))?;
    let original = owned
        .worker
        .submit(&request.ledger, &owned.request, &owned.admission)
        .map_err(refused)?;
    Ok(CapabilityPreparationState::Admitted {
        scenario,
        observed_request: Bytes::new(original.request().canonical_bytes()),
    })
}

pub(super) fn execution_text(execution: ExecutionId) -> String {
    execution
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
