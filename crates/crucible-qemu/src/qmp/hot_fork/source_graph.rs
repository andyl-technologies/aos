//! Complete native graph membership bound to an original prepared template.
//!
//! This closed socket contract reports descriptor identity and complete file
//! hashes. The host independently authenticates its retained files; wire epochs
//! alone never replace QEMU's retained native source and barrier ownership.

use crate::qmp::{QmpCommandKind, QmpError};
use serde::Deserialize;
use serde_json::Value;

/// Native query that binds the complete graph before physical child planning.
pub const QMP_HOT_FORK_SOURCE_GRAPH_COMMAND: &str = "crucible-hot-fork-source-graph";
/// Version of the complete native graph receipt.
pub const QMP_HOT_FORK_SOURCE_GRAPH_SCHEMA_VERSION: u32 = 1;
/// Maximum graph visits admitted by the native receipt operation.
pub const QMP_HOT_FORK_SOURCE_GRAPH_MAX_NODES: u32 = 4096;
/// Maximum complete file bytes admitted by the native receipt operation.
pub const QMP_HOT_FORK_SOURCE_GRAPH_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// One native node and its incoming edge in the complete graph.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct QmpHotForkSourceGraphMember {
    /// Identifies the zero-based native root ordinal.
    pub root_index: u64,
    /// Identifies the depth-first node ordinal within its root.
    pub node_index: u64,
    /// Identifies the incoming parent ordinal, or -1 for a root.
    pub parent_index: i64,
    /// Identifies the original backend, or zero for a parentless root.
    pub backend_id: u64,
    /// Names the original backend, or is empty for a parentless root.
    pub backend_name: String,
    /// Names the original retained native root.
    pub root_node_name: String,
    /// Names this native graph node.
    pub node_name: String,
    /// Names the incoming edge, or is empty for a root.
    pub edge_name: String,
    /// Names the native block driver.
    pub driver_name: String,
    /// Reports whether this member pins a regular file.
    pub file_backed: bool,
    /// Reports whether this file was writable before capture.
    pub originally_writable_file: bool,
    /// Carries descriptor display metadata; it does not authorize reopening.
    pub file_path: String,
    /// Identifies the device of the retained native regular inode.
    pub file_device: u64,
    /// Identifies the retained native regular inode.
    pub file_inode: u64,
    /// Reports the complete pinned file length.
    pub file_size: u64,
    /// Contains the lowercase SHA256 of the complete pinned file.
    pub file_sha256: String,
}

/// A complete native graph under the original stopped template and barriers.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct QmpHotForkSourceGraphReceipt {
    /// Identifies graph receipt schema version one.
    pub schema_version: u32,
    /// Identifies the original source process.
    pub qemu_pid: i64,
    /// Identifies the original prepared template.
    pub template_generation: u64,
    /// Records the native stop transition generation.
    pub runstate_generation: u64,
    /// Records the plugin stop completion generation.
    pub vmstop_generation: u64,
    /// Records the native stop request generation.
    pub vmstop_request_generation: u64,
    /// Records the retained block barrier generation.
    pub barrier_generation: u64,
    /// Records the retained graph barrier generation.
    pub graph_barrier_generation: u64,
    /// Records the observed native graph generation.
    pub graph_mutation_generation: u64,
    /// Records the frozen snapshot binding generation.
    pub snapshot_generation: u64,
    /// Records the bound backend inventory generation.
    pub backend_generation: u64,
    /// Reports every retained native root.
    pub root_count: u64,
    /// Reports every graph member visit, including shared edges.
    pub node_count: u64,
    /// Contains complete depth-first membership in root order.
    pub members: Vec<QmpHotForkSourceGraphMember>,
}

pub(crate) fn parse_hot_fork_source_graph(
    value: &Value,
    expected_qemu_pid: i64,
    expected_template_generation: u64,
) -> Result<QmpHotForkSourceGraphReceipt, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkSourceGraph,
        response: value.to_string(),
    };
    let receipt: QmpHotForkSourceGraphReceipt =
        serde_json::from_value(value.clone()).map_err(|_| malformed())?;
    if receipt.schema_version != QMP_HOT_FORK_SOURCE_GRAPH_SCHEMA_VERSION
        || receipt.qemu_pid != expected_qemu_pid
        || expected_qemu_pid <= 0
        || receipt.template_generation != expected_template_generation
        || expected_template_generation == 0
        || receipt.root_count == 0
        || receipt.node_count != receipt.members.len() as u64
        || receipt.node_count > u64::from(QMP_HOT_FORK_SOURCE_GRAPH_MAX_NODES)
        || ![
            receipt.template_generation,
            receipt.vmstop_generation,
            receipt.barrier_generation,
            receipt.graph_barrier_generation,
            receipt.graph_mutation_generation,
            receipt.snapshot_generation,
            receipt.backend_generation,
        ]
        .into_iter()
        .all(|generation| generation > 0 && generation < u64::MAX)
        || receipt.runstate_generation == u64::MAX
        || receipt.vmstop_request_generation == u64::MAX
        || !complete_members(&receipt)
    {
        return Err(malformed());
    }
    Ok(receipt)
}

fn complete_members(receipt: &QmpHotForkSourceGraphReceipt) -> bool {
    let mut roots = 0_u64;
    let mut node_index = 0_u64;
    let mut root: Option<&QmpHotForkSourceGraphMember> = None;
    let mut total_bytes = 0_u64;
    let mut incoming_edges = std::collections::BTreeSet::new();
    for member in &receipt.members {
        if member.parent_index == -1 {
            if member.root_index != roots
                || member.node_index != 0
                || !member.edge_name.is_empty()
                || member.root_node_name.is_empty()
                || member.node_name != member.root_node_name
            {
                return false;
            }
            roots += 1;
            node_index = 0;
            root = Some(member);
            incoming_edges.clear();
        } else if member.parent_index < 0
            || member.parent_index as u64 >= member.node_index
            || member.edge_name.is_empty()
            || !incoming_edges.insert((member.parent_index, member.edge_name.as_str()))
        {
            return false;
        }
        let Some(root) = root else {
            return false;
        };
        if member.root_index != root.root_index
            || member.node_index != node_index
            || member.backend_id != root.backend_id
            || member.backend_name != root.backend_name
            || member.root_node_name != root.root_node_name
            || (member.backend_id == 0) != member.backend_name.is_empty()
            || member.driver_name.is_empty()
            || [
                &member.backend_name,
                &member.root_node_name,
                &member.node_name,
                &member.edge_name,
                &member.driver_name,
            ]
            .into_iter()
            .any(|name| name.len() > 256 || name.as_bytes().contains(&0))
            || member.file_path.len() > 4096
            || member.file_path.as_bytes().contains(&0)
        {
            return false;
        }
        if member.file_backed {
            if member.file_device == 0
                || member.file_inode == 0
                || member.file_sha256.len() != 64
                || !member
                    .file_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return false;
            }
            let Some(bytes) = total_bytes.checked_add(member.file_size) else {
                return false;
            };
            total_bytes = bytes;
            if total_bytes > QMP_HOT_FORK_SOURCE_GRAPH_MAX_BYTES {
                return false;
            }
        } else if member.originally_writable_file
            || member.file_device != 0
            || member.file_inode != 0
            || member.file_size != 0
            || !member.file_sha256.is_empty()
            || !member.file_path.is_empty()
        {
            return false;
        }
        node_index += 1;
    }
    roots == receipt.root_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn receipt() -> Value {
        json!({
            "schema-version": 1, "qemu-pid": 451, "template-generation": 7,
            "runstate-generation": 2, "vmstop-generation": 3,
            "vmstop-request-generation": 4, "barrier-generation": 5,
            "graph-barrier-generation": 6, "graph-mutation-generation": 8,
            "snapshot-generation": 9, "backend-generation": 10,
            "root-count": 1, "node-count": 2,
            "members": [
                { "root-index": 0, "node-index": 0, "parent-index": -1,
                  "backend-id": 0, "backend-name": "", "root-node-name": "vmstate",
                  "node-name": "vmstate", "edge-name": "", "driver-name": "qcow2",
                  "file-backed": false, "originally-writable-file": false,
                  "file-path": "", "file-device": 0, "file-inode": 0,
                  "file-size": 0, "file-sha256": "" },
                { "root-index": 0, "node-index": 1, "parent-index": 0,
                  "backend-id": 0, "backend-name": "", "root-node-name": "vmstate",
                  "node-name": "", "edge-name": "file", "driver-name": "file",
                  "file-backed": true, "originally-writable-file": true,
                  "file-path": "diagnostic-only", "file-device": 11, "file-inode": 12,
                  "file-size": 13, "file-sha256": "a".repeat(64) }
            ]
        })
    }

    #[test]
    fn closed_graph_requires_original_process_template_and_full_roster() {
        let value = receipt();
        assert!(parse_hot_fork_source_graph(&value, 451, 7).is_ok());
        assert!(parse_hot_fork_source_graph(&value, 452, 7).is_err());
        assert!(parse_hot_fork_source_graph(&value, 451, 8).is_err());
        for (field, replacement) in [
            ("schema-version", json!(2)),
            ("root-count", json!(2)),
            ("node-count", json!(3)),
            ("snapshot-generation", json!(0)),
        ] {
            let mut invalid = value.clone();
            invalid[field] = replacement;
            assert!(
                parse_hot_fork_source_graph(&invalid, 451, 7).is_err(),
                "{field}"
            );
        }
        let mut extra = value.clone();
        extra["native-pointer"] = json!(1);
        assert!(parse_hot_fork_source_graph(&extra, 451, 7).is_err());
    }

    #[test]
    fn graph_rejects_invalid_edges_identity_digest_and_byte_budget() {
        for (field, replacement) in [
            ("parent-index", json!(1)),
            ("root-index", json!(1)),
            ("node-index", json!(2)),
            ("edge-name", json!("")),
            ("backend-name", json!("foreign")),
            ("file-inode", json!(0)),
            ("file-sha256", json!("A".repeat(64))),
            ("file-size", json!(QMP_HOT_FORK_SOURCE_GRAPH_MAX_BYTES + 1)),
        ] {
            let mut invalid = receipt();
            invalid["members"][1][field] = replacement;
            assert!(
                parse_hot_fork_source_graph(&invalid, 451, 7).is_err(),
                "{field}"
            );
        }
        let mut invalid = receipt();
        invalid["members"][1]["unknown-field"] = json!(0);
        assert!(parse_hot_fork_source_graph(&invalid, 451, 7).is_err());
    }
}
