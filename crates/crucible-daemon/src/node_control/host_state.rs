//! Versioned local exact host-world requests and immutable operation records.
//!
//! ```text
//! HostStateV1 = {operation:capture|restore|status, execution:nonce32hex, ...}
//! HostStateRecordV1 = {format:"crucible.node-state-operation", version:1,
//!   execution:nonce32hex, request:ContentId, state:reserved|completed|refused}
//! ```
//!
//! A durable reservation belongs to one complete request and one original
//! execution nonce. Reading or retrying it never authorizes native dispatch.

use crucible_cas::content_store::{ContentId, ObjectKind, RefName};
use crucible_node_contract::{Bytes, CaptureManifest, ContentRef, U64, Validate};
use serde::{Deserialize, Serialize};

use crate::{
    node_observed_executor::{InstalledNodeKind, InstalledNodeSelection},
    node_scenario::{MAX_NODE_SCENARIO_BYTES, NodeScenario},
};

use super::terminal_state::NodeTerminalStateRequest;
use super::{NodeControlError, execution_id, refused, validate_selections};

/// Selects one exact whole-world operation on qualified synchronous host models.
///
/// Restoration requires an original archive authenticated by this installation.
/// The selected scenario and implementations remain bound to that archive; a
/// source digest never supplies native qualification or execution permission.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeHostStateRequest {
    /// Retains a distinct terminal edition without changing legacy state bytes.
    Terminal {
        /// Contains an explicit terminal operation, never a horizon EOF claim.
        request: Box<NodeTerminalStateRequest>,
    },
    /// Executes a new admitted exact host world to a coherent cut and captures it.
    Capture {
        /// Names an independent original state-operation nonce in lowercase hex.
        execution: String,
        /// Selects installed complete host owners, without model substitution.
        selections: Vec<InstalledNodeSelection>,
        /// Retains the exact actor-compiled scenario bytes.
        scenario: Bytes,
        /// Selects the coherent final physical time in picoseconds.
        horizon_ps: U64,
    },
    /// Reconstructs an authenticated whole world and captures its continued cut.
    Restore {
        /// Names a new independent restoration operation nonce in lowercase hex.
        execution: String,
        /// Selects the original installed complete host owners.
        selections: Vec<InstalledNodeSelection>,
        /// Retains the exact original actor-compiled scenario bytes.
        scenario: Bytes,
        /// Identifies a complete original archive in the private host realm.
        source: ContentRef,
        /// Selects a final time at or after the original unchanged capture cut.
        horizon_ps: U64,
    },
    /// Reads one original durable operation without native allocation or dispatch.
    Status {
        /// Selects the original state-operation nonce.
        execution: String,
    },
}

impl NodeHostStateRequest {
    /// Builds an exact capture request retaining complete authored scenario bytes.
    ///
    /// # Errors
    /// Refuses invalid nonces, unsupported owner selections or malformed scenarios.
    pub fn capture(
        execution: String,
        selections: Vec<InstalledNodeSelection>,
        scenario: Vec<u8>,
        horizon_ps: u64,
    ) -> Result<Self, NodeControlError> {
        let request = Self::Capture {
            execution,
            selections,
            scenario: Bytes::new(scenario),
            horizon_ps: U64::new(horizon_ps),
        };
        request.validate()?;
        Ok(request)
    }

    /// Builds a restore request naming an original authenticated archive.
    ///
    /// This constructor validates portable inputs only. The installed actor must
    /// authenticate the original source, complete native model and fresh roster.
    ///
    /// # Errors
    /// Refuses invalid nonces, unsupported owners, malformed scenario or source.
    pub fn restore(
        execution: String,
        selections: Vec<InstalledNodeSelection>,
        scenario: Vec<u8>,
        source: ContentRef,
        horizon_ps: u64,
    ) -> Result<Self, NodeControlError> {
        let request = Self::Restore {
            execution,
            selections,
            scenario: Bytes::new(scenario),
            source,
            horizon_ps: U64::new(horizon_ps),
        };
        request.validate()?;
        Ok(request)
    }

    /// Builds a read-only request for the original durable state-operation record.
    ///
    /// # Errors
    /// Refuses a malformed or zero execution nonce.
    pub fn status(execution: String) -> Result<Self, NodeControlError> {
        let request = Self::Status { execution };
        request.validate()?;
        Ok(request)
    }

    /// Returns the original operation identity used by persistent state custody.
    #[must_use]
    pub fn execution(&self) -> &str {
        match self {
            Self::Terminal { request } => request.execution(),
            Self::Capture { execution, .. }
            | Self::Restore { execution, .. }
            | Self::Status { execution } => execution,
        }
    }

    pub(super) fn validate(&self) -> Result<(), NodeControlError> {
        if let Self::Terminal { request } = self {
            return request.validate();
        }
        execution_id(self.execution())?;
        let (selections, scenario) = match self {
            Self::Capture {
                selections,
                scenario,
                ..
            } => (selections, scenario),
            Self::Restore {
                selections,
                scenario,
                source,
                ..
            } => {
                source.validate()?;
                (selections, scenario)
            }
            Self::Status { .. } => return Ok(()),
            Self::Terminal { .. } => {
                return Err(refused("terminal request uses its own validator"));
            }
        };

        validate_selections(selections)?;
        if selections.iter().any(|selection| {
            !matches!(
                selection.kind,
                InstalledNodeKind::HostClock
                    | InstalledNodeKind::HostIo { .. }
                    | InstalledNodeKind::HostScripted { .. }
                    | InstalledNodeKind::HostSeededLink { .. }
                    | InstalledNodeKind::HostFaultedLink { .. }
                    | InstalledNodeKind::HostControlledFaultLink { .. }
                    | InstalledNodeKind::HostPacketReceiver { .. }
            )
        }) {
            return Err(refused(
                "exact host-state operations require qualified complete host models",
            ));
        }
        if scenario.as_slice().len() > MAX_NODE_SCENARIO_BYTES {
            return Err(refused("host-state scenario exceeds its finite ceiling"));
        }
        NodeScenario::from_json(scenario.as_slice()).map_err(refused)?;
        Ok(())
    }
}

/// Retains the original durable lifecycle of one whole-world state operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHostStateRecord {
    /// Names the independent original state-operation format.
    pub format: String,
    /// Selects its supported codec edition.
    pub version: u32,
    /// Preserves the original independent execution nonce.
    pub execution: String,
    /// Binds exact original request bytes, including source and installed choices.
    #[serde(with = "request_identity")]
    pub request: ContentId,
    /// Preserves original admission, completion, or irreversible refusal.
    pub state: NodeHostStateOutcome,
}

impl NodeHostStateRecord {
    /// Parses a bounded original record without qualifying its source for restoration.
    ///
    /// # Errors
    /// Refuses malformed closed JSON, unsupported editions, invalid original
    /// nonces, and inconsistent complete capture identity or manifest.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeControlError> {
        let value = crucible_node_contract::canonical::parse_json(bytes, 8 * 1024 * 1024)?;
        let record: Self =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        record.validate()?;
        Ok(record)
    }

    pub(super) fn validate(&self) -> Result<(), NodeControlError> {
        if self.format != "crucible.node-state-operation" || !matches!(self.version, 1 | 2) {
            return Err(refused("unsupported exact-state operation record edition"));
        }
        execution_id(&self.execution)?;
        if self.request.kind() != ObjectKind::Trace || self.request.schema_version() != 1 {
            return Err(refused(
                "exact-state record has an unsupported request identity",
            ));
        }
        if self.version == 1 && matches!(self.state, NodeHostStateOutcome::Unknown { .. }) {
            return Err(refused(
                "legacy state records cannot acquire terminal uncertainty",
            ));
        }
        if let NodeHostStateOutcome::Refused { reason } | NodeHostStateOutcome::Unknown { reason } =
            &self.state
            && reason.len() > 4096
        {
            return Err(refused("exact-state refusal exceeds its finite ceiling"));
        }
        if let NodeHostStateOutcome::Completed { artifact, manifest } = &self.state {
            artifact.validate()?;
            manifest.validate()?;
            let manifest_bytes = crucible_node_contract::canonical::canonical_json(
                &serde_json::to_value(manifest)
                    .map_err(crucible_node_contract::ContractError::from)?,
            )?;
            if crucible_node_contract::canonical::content_ref(&manifest_bytes, "application/json")?
                != *artifact
            {
                return Err(refused(
                    "exact-state record artifact differs from its manifest",
                ));
            }
        }
        Ok(())
    }
}

/// Reports exact preservation separately from native operation completion.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeHostStateOutcome {
    /// Retains original terminal custody after effects or uncertain publication.
    Unknown {
        /// Reports a bounded class without granting replacement dispatch.
        reason: String,
    },
    /// Retains the original reservation without issuing retry or resume authority.
    Reserved {},
    /// Retains a host-authenticated complete capture from the original operation.
    Completed {
        /// Identifies the immutable complete native and coordinator archive.
        artifact: ContentRef,
        /// Preserves its complete original backend bindings and guarantee roster.
        manifest: Box<CaptureManifest>,
    },
    /// Refuses the original operation while preserving any original native custody.
    Refused {
        /// Contains a fixed bounded class without peer data or private state paths.
        reason: String,
    },
}

pub(super) fn activation_reference(execution: &str) -> Result<RefName, NodeControlError> {
    execution_id(execution)?;
    RefName::new(format!("node-world-activations/state-{execution}")).map_err(refused)
}

// The CAS identity is a typed host value, while this format uses its canonical
// kind.schema.digest spelling rather than a Rust-specific struct layout.
mod request_identity {
    use crucible_cas::content_store::ContentId;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    // Retains the public CAS spelling independently of its in-memory layout.
    pub(super) fn serialize<S: Serializer>(
        identity: &ContentId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&identity.encode())
    }

    // Rejects alternate textual spellings before decoding an original record.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ContentId, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let identity = ContentId::parse(&encoded).map_err(D::Error::custom)?;
        if identity.encode() != encoded {
            return Err(D::Error::custom("noncanonical original request identity"));
        }
        Ok(identity)
    }
}
