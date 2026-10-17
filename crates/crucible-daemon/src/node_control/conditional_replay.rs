//! Explicit portable unchanged-source requests for conditional control edition five.
//!
//! ```json
//! {"format":"crucible.node-conditional-replay","version":1,
//!  "ledger":"original-replay","execution":"00112233445566778899aabbccddeeff",
//!  "sources":{},"configuration":[]}
//! ```
//!
//! Source references are data. Only the daemon's installed private archive signer
//! and current catalog can authenticate their raw source context and applicability.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, Validate};

use super::*;

/// Declares one bounded original-source replay without supplying native authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConditionalReplayRequest {
    /// Names the closed portable conditional request format.
    pub format: String,
    /// Selects exact format edition one.
    pub version: u16,
    /// Names the original durable observation ledger, one ref segment.
    pub ledger: String,
    /// Names a fresh operational execution nonce as 32 lowercase hex digits.
    pub execution: String,
    /// Names every original signed actor transcript under the installed signer.
    pub sources: BTreeMap<Id, ContentRef>,
    /// Retains the unchanged original bounded run configuration JSON.
    pub configuration: Bytes,
}

impl NodeConditionalReplayRequest {
    /// Constructs data for an explicitly selected conditional replay operation.
    ///
    /// # Errors
    /// Refuses malformed execution/ledger/source identities, unsupported source
    /// geometry, incomplete actor roster or malformed original configuration.
    pub fn new(
        ledger: String,
        execution: String,
        sources: BTreeMap<Id, ContentRef>,
        configuration: Vec<u8>,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-conditional-replay".into(),
            version: 1,
            ledger,
            execution,
            sources,
            configuration: Bytes::new(configuration),
        };
        request.validate()?;
        Ok(request)
    }

    pub(super) fn validate(&self) -> Result<(), NodeControlError> {
        execution_id(&self.execution)?;
        if self.format != "crucible.node-conditional-replay"
            || self.version != 1
            || self.ledger.is_empty()
            || self.ledger.len() > 128
            || self.ledger.contains('/')
            || self.configuration.as_slice().len() > 4096
            || self.sources.len() != 2
        {
            return Err(refused(
                "unsupported or oversized conditional replay request",
            ));
        }
        crucible_cas::content_store::RefName::new(format!(
            "observed-attempt-ledgers/{}",
            self.ledger
        ))
        .map_err(|_| refused("conditional ledger is not a safe ref segment"))?;
        for (actor, reference) in &self.sources {
            actor.validate()?;
            reference.validate()?;
            if reference.length.get() > 64 * 1024 * 1024 {
                return Err(refused(
                    "conditional raw source exceeds installed allocation ceiling",
                ));
            }
        }
        crate::node_scenario::NodeRunConfiguration::from_json(self.configuration.as_slice())
            .map_err(refused)?;
        Ok(())
    }
}

/// Decodes a bounded exact original actor/reference roster without qualification.
///
/// # Errors
/// Refuses invalid/duplicate JSON keys, invalid typed identities, an unsupported
/// actor count or excessive metadata before the archive reads any source body.
pub fn decode_conditional_replay_sources(
    bytes: &[u8],
) -> Result<BTreeMap<Id, ContentRef>, NodeControlError> {
    let value = canonical::parse_json(bytes, 65_536)?;
    let sources: BTreeMap<Id, ContentRef> = serde_json::from_value(value)
        .map_err(|_| refused("conditional source roster shape differs"))?;
    if sources.len() != 2 {
        return Err(refused(
            "conditional installed edition requires its complete actor pair",
        ));
    }
    for (actor, reference) in &sources {
        actor.validate()?;
        reference.validate()?;
    }
    Ok(sources)
}

impl NodeControlRequest {
    /// Builds control edition five without changing ordinary fresh request bytes.
    ///
    /// # Errors
    /// Refuses unsupported original-source geometry, invalid exchange identities
    /// or a changed context format. This creates no source or execution authority.
    pub fn conditional_replay(
        request_id: &str,
        request: NodeConditionalReplayRequest,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 5,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::ConditionalReplay {
                request: Box::new(request),
            },
        };
        request.validate()?;
        Ok(request)
    }
}

/// Decodes an original data-only conditional preparation receipt.
///
/// # Errors
/// Refuses another result kind, excessive/altered receipt bytes or actual daemon
/// refusal. Pending receipt data cannot issue node readiness or replay authority.
pub fn decode_conditional_preparation(
    reply: &NodeControlReply,
) -> Result<crate::node_observed_executor::ConditionalPreparationRecord, NodeControlError> {
    if reply.version != 5 {
        return Err(refused(
            "conditional preparation requires explicit control edition five",
        ));
    }
    match &reply.result {
        NodeControlResult::ConditionalPreparation { record } => {
            crate::node_observed_executor::ConditionalPreparationRecord::from_canonical_bytes(
                record.as_slice(),
            )
            .map_err(refused)
        }
        NodeControlResult::Refused { reason } => Err(refused(reason)),
        _ => Err(refused("conditional control returned another result kind")),
    }
}

impl NodeControlRequest {
    /// Reads original admission custody without redispatch or source preparation.
    ///
    /// # Errors
    /// Refuses invalid exchange identity or original nonzero execution nonce.
    pub fn conditional_replay_status(
        request_id: &str,
        execution: String,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 5,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::ConditionalReplayStatus { execution },
        };
        request.validate()?;
        Ok(request)
    }
}

impl NodeControlDaemon {
    /// Opens the operator's private source archive before publishing an endpoint.
    ///
    /// The fixed finite geometry matches this installed conditional edition.
    /// Client requests carry only typed source references; they cannot select
    /// this directory, signer or source qualification.
    ///
    /// # Errors
    /// Refuses invalid private archive custody and the same installation, state
    /// ownership or finite actor conditions as [`Self::start`].
    pub fn start_with_conditional_directory(
        policy: NodeDaemonPolicy,
        directory: std::path::PathBuf,
    ) -> Result<Self, NodeControlError> {
        let archive = crucible::node_adapters::transcript::TranscriptArchive::open(
            directory,
            crucible::node_adapters::transcript::TranscriptLimits {
                maximum_records: crucible_node_contract::U64::new(4096),
                maximum_record_bytes: crucible_node_contract::U64::new(16 * 1024 * 1024),
                maximum_total_bytes: crucible_node_contract::U64::new(64 * 1024 * 1024),
            },
        )
        .map_err(refused)?;
        Self::start_with_conditional_archive(policy, archive)
    }

    /// Installs an owned local transcript signer for explicit conditional control.
    ///
    /// The ordinary daemon policy remains unchanged. A portable client cannot
    /// replace this signer, choose its filesystem namespace or install profiles.
    ///
    /// # Errors
    /// Refuses the same private-state, installation, durable storage and finite
    /// actor conditions as [`Self::start`]. Each source is authenticated later.
    pub fn start_with_conditional_archive(
        policy: NodeDaemonPolicy,
        archive: crucible::node_adapters::transcript::TranscriptArchive,
    ) -> Result<Self, NodeControlError> {
        Self::start_inner(policy, Some(archive))
    }
}
