//! Bounded topology receipts that precede host RAM catalog admission.
//!
//! ```text
//! {"execute":"crucible-checkpoint-prepare-topology","arguments":{
//!   "root-fdname":"ram-output","cancellation-fdname":"cancel",
//!   "checkpoint-sha256":"...","target-sha256":"...",
//!   "frontier-sha256":"..."}}
//! ```
//!
//! The returned receipt authorizes one capture of the same topology and exact
//! identity. The host verifies the descriptor before admitting graph capacity.

use super::*;

pub(crate) const COMMAND: &str = "crucible-checkpoint-prepare-topology";
pub(crate) const MAX_RECORD_BYTES: usize = 3 * 1024 * 1024;

/// Authenticated size and identity of a topology-only preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QmpCheckpointTopology {
    pub(crate) generation: u64,
    pub(crate) root_bytes: usize,
    pub(crate) root: crucible::ContentHash,
    pub(crate) topology: crucible::ContentHash,
}

impl QmpCheckpointTopology {
    pub(crate) const MAX_RECORD_BYTES: usize = MAX_RECORD_BYTES;
}

pub(super) fn parse(value: &Value) -> Result<QmpCheckpointTopology, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::CheckpointTopology,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    if object.len() != 5
        || object.get("schema-version").and_then(Value::as_u64)
            != Some(checkpoint::QMP_CHECKPOINT_SCHEMA_VERSION as u64)
    {
        return Err(malformed());
    }
    let generation = object
        .get("topology-admission-generation")
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(&malformed)?;
    let root_bytes = object
        .get("root-bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= MAX_RECORD_BYTES as u64)
        .ok_or_else(&malformed)? as usize;
    let root = checkpoint::parse_hash(object.get("ram-root-blake3")).ok_or_else(&malformed)?;
    let topology = checkpoint::parse_hash(object.get("topology-blake3")).ok_or_else(&malformed)?;
    Ok(QmpCheckpointTopology {
        generation,
        root_bytes,
        root,
        topology,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> Value {
        json!({"schema-version":3,"topology-admission-generation":17,
            "root-bytes":512,"ram-root-blake3":"01".repeat(32),
            "topology-blake3":"02".repeat(32)})
    }

    #[test]
    fn topology_receipt_requires_bounded_canonical_closed_fields() {
        let report =
            parse(&response()).unwrap_or_else(|error| panic!("fixture topology report: {error}"));
        assert_eq!((report.generation, report.root_bytes), (17, 512));
        assert_eq!(report.topology.bytes, [2; 32]);
        for (field, invalid) in [
            ("schema-version", json!(2)),
            ("topology-admission-generation", json!(0)),
            ("root-bytes", json!(MAX_RECORD_BYTES + 1)),
            ("root-bytes", json!(-1)),
            ("topology-blake3", json!("FF".repeat(32))),
            ("ram-root-blake3", json!("00".repeat(31))),
        ] {
            let mut malformed = response();
            malformed[field] = invalid;
            assert!(parse(&malformed).is_err(), "field {field}");
        }
        let mut extra = response();
        extra["unchecked-owner"] = json!(1);
        assert!(parse(&extra).is_err());
    }
}
