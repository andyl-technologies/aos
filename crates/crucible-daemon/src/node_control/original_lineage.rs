//! Carries bounded original-lineage preparation data in explicit control edition eleven.
//!
//! ```json
//! {"format":"crucible.node-original-lineage-preparation","version":1,
//!  "execution":"00112233445566778899aabbccddeeff","sources":{},"configuration":""}
//! ```
//!
//! Exactly three signed source commitments are data. Only independently installed
//! source policy and behavioral acceptance may prepare their inactive models.

use super::*;
use crucible_node_contract::{ContentRef, Validate};
use std::collections::BTreeMap;

/// Selects original signed sources without supplying target graphs or authorities.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeOriginalLineageRequest {
    /// Names the exact original-lineage preparation format.
    pub format: String,
    /// Selects the closed first request edition.
    pub version: u16,
    /// Names a fresh original operational nonce as 32 lowercase hexadecimal digits.
    pub execution: String,
    /// Pins the complete three-actor signed source roster.
    pub sources: BTreeMap<Id, ContentRef>,
    /// Retains unchanged original bounded run configuration bytes.
    pub configuration: Bytes,
}

impl NodeOriginalLineageRequest {
    /// Constructs bounded data for an independently installed source inspection.
    ///
    /// # Errors
    /// Refuses foreign formats, malformed identities, incomplete source rosters,
    /// exhausted aggregate source credit or unsupported configuration.
    pub fn new(
        execution: String,
        sources: BTreeMap<Id, ContentRef>,
        configuration: Vec<u8>,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-original-lineage-preparation".into(),
            version: 1,
            execution,
            sources,
            configuration: Bytes::new(configuration),
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(&self) -> Result<(), NodeControlError> {
        execution_id(&self.execution)?;
        if self.format != "crucible.node-original-lineage-preparation"
            || self.version != 1
            || self.sources.len() != 3
            || self.configuration.as_slice().len() > 4096
        {
            return Err(refused("unsupported original-lineage preparation request"));
        }
        let mut total = 0u64;
        for (actor, reference) in &self.sources {
            actor.validate()?;
            reference.validate()?;
            total = total
                .checked_add(reference.length.get())
                .ok_or_else(|| refused("original signed source credit overflow"))?;
        }
        if total > 64 * 1024 * 1024 {
            return Err(refused("original signed source credit exhausted"));
        }
        crate::node_scenario::NodeRunConfiguration::from_json(self.configuration.as_slice())
            .map_err(refused)?;
        Ok(())
    }
}

/// Decodes exactly three original full typed references before source body reads.
///
/// # Errors
/// Refuses duplicate keys, malformed or non-object JSON, a changed roster size,
/// foreign identities or excessive metadata before allocating the typed roster.
pub fn decode_original_lineage_sources(
    bytes: &[u8],
) -> Result<BTreeMap<Id, ContentRef>, NodeControlError> {
    let value = canonical::parse_json(bytes, 65_536)?;
    if value.as_object().is_none_or(|map| map.len() != 3) {
        return Err(refused(
            "original-lineage source roster must contain exactly three actors",
        ));
    }
    let sources: BTreeMap<Id, ContentRef> = serde_json::from_value(value)
        .map_err(|_| refused("original-lineage source roster differs"))?;
    for (actor, reference) in &sources {
        actor.validate()?;
        reference.validate()?;
    }
    Ok(sources)
}

impl NodeControlRequest {
    /// Selects control edition eleven without changing existing replay bytes.
    ///
    /// # Errors
    /// Refuses invalid correlation identity or unsupported original request data.
    pub fn original_lineage_prepare(
        request_id: &str,
        request: NodeOriginalLineageRequest,
    ) -> Result<Self, NodeControlError> {
        let request = Self {
            format: "crucible.node-control".into(),
            version: 11,
            request_id: Id::new(request_id)?,
            command: NodeControlCommand::OriginalLineagePrepare {
                request: Box::new(request),
            },
        };
        request.validate()?;
        Ok(request)
    }
}

impl NodeControlDaemon {
    /// Publishes the normal local endpoint with independently configured source and acceptance authorities.
    ///
    /// The portable daemon policy selects installation paths and finite capacity.
    /// The source policy and accepted-class authority are separate owned host
    /// objects; JSON and CLI data cannot install them or select their trust roots.
    ///
    /// # Errors
    /// Refuses invalid authority pins, missing archive or the same private state,
    /// source-built artifact and exclusive owning actor conditions as [`Self::start`].
    pub fn start_with_original_lineage_authorities(
        policy: NodeDaemonPolicy,
        archive: crucible::node_adapters::transcript::TranscriptArchive,
        installation: crate::node_observed_executor::OriginalLineageHostInstallation,
    ) -> Result<Self, NodeControlError> {
        Self::start_inner_original(policy, Some(archive), Some(installation))
    }
}

// This new operation's source roster and decoded byte-string credit precede typed copies.
// Other control editions keep their original decoding and serialization.
pub(super) fn precredit(value: &serde_json::Value) -> Result<(), NodeControlError> {
    if value
        .as_array()
        .is_some_and(|fields| fields.get(1).and_then(serde_json::Value::as_u64) == Some(11))
    {
        return Err(refused(
            "original-lineage control requires a closed named object",
        ));
    }
    let Some(command) = value.get("command") else {
        return Ok(());
    };
    if command.get("operation").and_then(serde_json::Value::as_str)
        != Some("original_lineage_prepare")
    {
        return Ok(());
    }
    let request = command
        .get("request")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| refused("original-lineage request is not a closed object"))?;
    if request.len() != 5
        || !["format", "version", "execution", "sources", "configuration"]
            .iter()
            .all(|key| request.contains_key(*key))
        || request
            .get("sources")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|sources| sources.len() != 3)
        || request
            .get("configuration")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|encoded| {
                encoded.len() % 4 == 1
                    || encoded
                        .len()
                        .checked_mul(3)
                        .map(|bytes| bytes / 4)
                        .is_none_or(|bytes| bytes > 4096)
            })
    {
        return Err(refused(
            "original-lineage raw roster or configuration credit exceeded",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- These cfg(test)-only controls panic when wire identity or borrowed precredit invariants fail.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_node_contract::U64;

    fn original() -> NodeOriginalLineageRequest {
        let bytes = b"{}";
        let reference = ContentRef {
            hash: canonical::hash("cnp.blob.v1", bytes).unwrap(),
            length: U64::new(2),
            media_type: "application/json".into(),
        };
        NodeOriginalLineageRequest::new("112233445566778899aabbccddeeff00".into(),
            ["disk", "link", "source"].into_iter().map(|actor| (Id::new(actor).unwrap(), reference.clone())).collect(),
            br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"3000","maximum_rounds":"3"}"#.to_vec()).unwrap()
    }

    #[test]
    fn new_wire_round_trips_and_cannot_relabel_legacy_pair_edition() {
        let request =
            NodeControlRequest::original_lineage_prepare("operator/original", original()).unwrap();
        let value = serde_json::to_value(&request).unwrap();
        precredit(&value).unwrap();
        let decoded: NodeControlRequest = serde_json::from_value(value).unwrap();
        decoded.validate().unwrap();
        let mut legacy = decoded;
        legacy.version = 5;
        assert!(legacy.validate().is_err());
        assert!(matches!(
            legacy.command,
            NodeControlCommand::OriginalLineagePrepare { .. }
        ));
    }

    #[test]
    fn raw_extra_actor_and_oversized_base64_refuse_before_typed_copies() {
        let request =
            NodeControlRequest::original_lineage_prepare("operator/original", original()).unwrap();
        let original = serde_json::to_value(&request).unwrap();
        let mut extra = original.clone();
        extra["command"]["request"]["sources"]["foreign"] =
            extra["command"]["request"]["sources"]["disk"].clone();
        assert!(precredit(&extra).is_err());
        let mut bytes = original.clone();
        bytes["command"]["request"]["configuration"] = serde_json::Value::String("A".repeat(5463));
        assert!(precredit(&bytes).is_err());
        bytes["command"]["request"]["configuration"] = serde_json::Value::String("A".repeat(5462));
        assert!(precredit(&bytes).is_ok());
        let positional = serde_json::json!([
            "crucible.node-control",
            11,
            "operator/original",
            original["command"]
        ]);
        assert!(precredit(&positional).is_err());
    }

    #[test]
    fn missing_actor_duplicate_keys_and_changed_request_policy_refuse() {
        assert!(decode_original_lineage_sources(b"{}").is_err());
        assert!(decode_original_lineage_sources(b"[]").is_err());
        assert!(decode_original_lineage_sources(br#"{"disk":{},"disk":{},"link":{}}"#).is_err());
        let mut request = original();
        request.sources.remove(&Id::new("disk").unwrap());
        assert!(request.validate().is_err());
        let mut value = serde_json::to_value(original()).unwrap();
        value["acceptance_policy"] = serde_json::json!("caller/foreign-authority");
        assert!(serde_json::from_value::<NodeOriginalLineageRequest>(value).is_err());
    }

    #[test]
    fn actual_private_endpoint_refuses_missing_authorities_before_archive_or_child() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let state = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let socket = state.path().join("node.sock");
        let executable = std::fs::canonicalize("/proc/self/exe").unwrap();
        let expected = canonical::content_ref(
            &std::fs::read(&executable).unwrap(),
            "application/octet-stream",
        )
        .unwrap();
        let policy = NodeDaemonPolicy {
            format: "crucible.node-daemon-policy".into(),
            version: 1,
            state_directory: state.path().to_owned(),
            socket: socket.clone(),
            device_executable: executable,
            expected_device: expected,
            control_timeout_ms: 1000,
            maximum_worlds: 1,
            maximum_pending_requests: 1,
            maximum_host_state_worlds: None,
            maximum_native_state_requests: None,
            immutable_artifacts: Vec::new(),
        };
        let mut daemon = NodeControlDaemon::start(policy).unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopping);
        let server = std::thread::spawn(move || daemon.serve(&stop));
        let request =
            NodeControlRequest::original_lineage_prepare("operator/original", original()).unwrap();

        let reply = request_node_control(&socket, &request);
        stopping.store(true, Ordering::SeqCst);
        let stopped = server.join();

        assert!(stopped.unwrap().is_ok());
        let reply = reply.unwrap();
        assert_eq!(reply.version, 11);
        assert!(matches!(reply.result, NodeControlResult::Refused { reason }
            if reason == "node actor refused; read original retained execution state"));
        assert!(!socket.exists());
    }
}
