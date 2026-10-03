//! Current writable-root inventory and native hot-fork block seal receipt.
//!
//! The receipt identifies QEMU's open files and graph. The host separately
//! authenticates the bytes and complete backing chain before PREPARE.

use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::qmp::{QmpCommandKind, QmpError};

/// Native command that installs one detached empty overlay per writable root.
pub const QMP_HOT_FORK_BLOCK_SEAL_COMMAND: &str = "crucible-hot-fork-block-seal";
/// Native query for current candidates and the retained seal receipt.
pub const QMP_QUERY_HOT_FORK_BLOCK_SEAL_COMMAND: &str = "query-crucible-hot-fork-block-seal";
/// Version of the native block seal response.
pub const QMP_HOT_FORK_BLOCK_SEAL_SCHEMA_VERSION: u32 = 1;

/// One QEMU-open writable root before sealing.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct QmpHotForkBlockSealCandidate {
    backend_id: u64,
    backend_name: String,
    root_node_name: String,
    file_path: String,
    file_device: u64,
    file_inode: u64,
    virtual_size: u64,
}

impl QmpHotForkBlockSealCandidate {
    /// Returns the process-local block backend identity.
    #[must_use]
    pub const fn backend_id(&self) -> u64 {
        self.backend_id
    }

    /// Returns the monitor-visible backend name.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }

    /// Returns the current writable root node name.
    #[must_use]
    pub fn root_node_name(&self) -> &str {
        &self.root_node_name
    }

    /// Returns diagnostic display metadata for the native root descriptor.
    #[must_use]
    pub fn file_path(&self) -> &Path {
        Path::new(&self.file_path)
    }

    /// Returns the open file's device and inode numbers.
    #[must_use]
    pub const fn file_identity(&self) -> (u64, u64) {
        (self.file_device, self.file_inode)
    }

    /// Returns the guest-visible size in bytes.
    #[must_use]
    pub const fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    fn complete(&self) -> bool {
        self.backend_id != 0
            && !self.backend_name.is_empty()
            && valid_node_name(&self.root_node_name)
            && self.file_path.len() <= 4096
            && !self.file_path.as_bytes().contains(&0)
            && self.file_device != 0
            && self.file_inode != 0
            && self.virtual_size != 0
    }
}

/// Exact QEMU candidate and detached empty overlay to install above it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkBlockSealRequest {
    candidate: QmpHotForkBlockSealCandidate,
    overlay_node_name: String,
}

impl QmpHotForkBlockSealRequest {
    /// Binds an overlay to one complete current candidate.
    ///
    /// # Errors
    ///
    /// Returns an error if the candidate lacks a sealable file or either
    /// graph node name is invalid or identical.
    pub fn new(
        candidate: QmpHotForkBlockSealCandidate,
        overlay_node_name: impl Into<String>,
    ) -> Result<Self, QmpError> {
        let overlay_node_name = overlay_node_name.into();
        if !candidate.complete()
            || !valid_node_name(&overlay_node_name)
            || candidate.root_node_name == overlay_node_name
        {
            return Err(QmpError::MalformedTypedResponse {
                command: QmpCommandKind::HotForkBlockSeal,
                response: "invalid current block-seal candidate or detached node".to_owned(),
            });
        }
        Ok(Self {
            candidate,
            overlay_node_name,
        })
    }

    /// Returns the exact original candidate.
    #[must_use]
    pub const fn candidate(&self) -> &QmpHotForkBlockSealCandidate {
        &self.candidate
    }

    /// Returns the detached overlay node name.
    #[must_use]
    pub fn overlay_node_name(&self) -> &str {
        &self.overlay_node_name
    }

    pub(crate) fn wire_value(&self) -> Value {
        json!({
            "backend-id": self.candidate.backend_id,
            "backend-name": self.candidate.backend_name,
            "snapshot-node-name": self.candidate.root_node_name,
            "overlay-node-name": self.overlay_node_name,
            "snapshot-file-path": self.candidate.file_path,
            "snapshot-file-device": self.candidate.file_device,
            "snapshot-file-inode": self.candidate.file_inode,
        })
    }
}

/// One installed empty overlay over a read-only current-content snapshot.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct QmpHotForkBlockSealedRoot {
    backend_id: u64,
    backend_name: String,
    overlay_node_name: String,
    snapshot_node_name: String,
    snapshot_file_path: String,
    snapshot_file_device: u64,
    snapshot_file_inode: u64,
    virtual_size: u64,
    overlay_empty: bool,
    snapshot_read_only: bool,
}

impl QmpHotForkBlockSealedRoot {
    /// Returns diagnostic display metadata for the retained snapshot descriptor.
    #[must_use]
    pub fn snapshot_file_path(&self) -> &Path {
        Path::new(&self.snapshot_file_path)
    }

    /// Returns the open snapshot file's device and inode numbers.
    #[must_use]
    pub const fn snapshot_file_identity(&self) -> (u64, u64) {
        (self.snapshot_file_device, self.snapshot_file_inode)
    }

    /// Returns the guest-visible disk size.
    #[must_use]
    pub const fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    /// Checks this receipt against the whole request, including read-only and
    /// empty-overlay facts. It does not authenticate file contents.
    #[must_use]
    pub fn matches_request(&self, request: &QmpHotForkBlockSealRequest) -> bool {
        let candidate = &request.candidate;
        self.backend_id == candidate.backend_id
            && self.backend_name == candidate.backend_name
            && self.overlay_node_name == request.overlay_node_name
            && self.snapshot_node_name == candidate.root_node_name
            && self.snapshot_file_device == candidate.file_device
            && self.snapshot_file_inode == candidate.file_inode
            && self.virtual_size == candidate.virtual_size
            && self.overlay_empty
            && self.snapshot_read_only
    }
}

/// Native inventory and current seal receipt for one stopped QEMU process.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct QmpHotForkBlockSealState {
    schema_version: u32,
    qemu_pid: i64,
    receipt_generation: u64,
    backend_generation: u64,
    graph_mutation_generation: u64,
    barrier_held: bool,
    barrier_generation: u64,
    barrier_quiescent: bool,
    candidates: Vec<QmpHotForkBlockSealCandidate>,
    sealed_roots: Vec<QmpHotForkBlockSealedRoot>,
}

impl QmpHotForkBlockSealState {
    /// Returns QEMU's process identifier.
    #[must_use]
    pub const fn qemu_pid(&self) -> i64 {
        self.qemu_pid
    }

    /// Returns the retained native seal generation, or zero without a seal.
    #[must_use]
    pub const fn receipt_generation(&self) -> u64 {
        self.receipt_generation
    }

    /// Returns whether the native graph and block-drain barrier is held.
    #[must_use]
    pub const fn barrier_held(&self) -> bool {
        self.barrier_held
    }

    /// Returns whether all rooted block I/O has quiesced.
    #[must_use]
    pub const fn barrier_quiescent(&self) -> bool {
        self.barrier_quiescent
    }

    /// Returns the original backend inventory generation.
    #[must_use]
    pub const fn backend_generation(&self) -> u64 {
        self.backend_generation
    }

    /// Returns the original graph mutation generation.
    #[must_use]
    pub const fn graph_mutation_generation(&self) -> u64 {
        self.graph_mutation_generation
    }

    /// Returns the candidate roots ordered by backend identity.
    #[must_use]
    pub fn candidates(&self) -> &[QmpHotForkBlockSealCandidate] {
        &self.candidates
    }

    /// Returns the retained installed roots ordered by backend identity.
    #[must_use]
    pub fn sealed_roots(&self) -> &[QmpHotForkBlockSealedRoot] {
        &self.sealed_roots
    }

    /// Returns true only for a complete retained native receipt matching all
    /// requested roots. The host must still authenticate current file bytes.
    #[must_use]
    pub fn seals(&self, requests: &[QmpHotForkBlockSealRequest]) -> bool {
        self.receipt_generation != 0
            && self.barrier_held
            && self.barrier_quiescent
            && self.barrier_generation != 0
            && self.sealed_roots.len() == requests.len()
            && self
                .sealed_roots
                .iter()
                .zip(requests)
                .all(|(root, request)| root.matches_request(request))
    }
}

pub(crate) fn parse_hot_fork_block_seal_state(
    value: &Value,
    command: QmpCommandKind,
) -> Result<QmpHotForkBlockSealState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command,
        response: value.to_string(),
    };
    let state: QmpHotForkBlockSealState =
        serde_json::from_value(value.clone()).map_err(|_error| malformed())?;
    if state.schema_version != QMP_HOT_FORK_BLOCK_SEAL_SCHEMA_VERSION
        || state.qemu_pid <= 0
        || state.backend_generation == 0
        || state.graph_mutation_generation == 0
        || !strictly_increasing(
            state
                .candidates
                .iter()
                .map(|candidate| candidate.backend_id),
        )
        || !strictly_increasing(state.sealed_roots.iter().map(|root| root.backend_id))
        || (state.receipt_generation != 0
            && (!state.barrier_held || !state.barrier_quiescent || state.barrier_generation == 0))
        || (state.receipt_generation == 0 && !state.sealed_roots.is_empty())
    {
        return Err(malformed());
    }
    Ok(state)
}

fn strictly_increasing(ids: impl Iterator<Item = u64>) -> bool {
    let mut previous = 0;
    for id in ids {
        if id <= previous {
            return false;
        }
        previous = id;
    }
    true
}

fn valid_node_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 31
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- malformed fixture receipts must fail the protocol test.
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn inventory() -> Value {
        json!({
            "schema-version": 1,
            "qemu-pid": 431,
            "receipt-generation": 0,
            "backend-generation": 7,
            "graph-mutation-generation": 9,
            "barrier-held": true,
            "barrier-generation": 11,
            "barrier-quiescent": true,
            "candidates": [{
                "backend-id": 2,
                "backend-name": "crucible-root0",
                "root-node-name": "crucible-root-overlay",
                "file-path": "/run/node-0/crucible-root-overlay.qcow2",
                "file-device": 12,
                "file-inode": 34,
                "virtual-size": 4096,
            }],
            "sealed-roots": [],
        })
    }

    #[test]
    fn exact_current_root_is_required_for_a_seal() {
        let current =
            parse_hot_fork_block_seal_state(&inventory(), QmpCommandKind::QueryHotForkBlockSeal)
                .unwrap();
        let request = QmpHotForkBlockSealRequest::new(
            current.candidates()[0].clone(),
            "crucible-root-overlay-next",
        )
        .unwrap();
        let mut sealed = inventory();
        sealed["receipt-generation"] = json!(1);
        sealed["sealed-roots"] = json!([{
            "backend-id": 2,
            "backend-name": "crucible-root0",
            "overlay-node-name": "crucible-root-overlay-next",
            "snapshot-node-name": "crucible-root-overlay",
            "snapshot-file-path": "/run/node-0/crucible-root-overlay.qcow2",
            "snapshot-file-device": 12,
            "snapshot-file-inode": 34,
            "virtual-size": 4096,
            "overlay-empty": true,
            "snapshot-read-only": true,
        }]);
        let receipt =
            parse_hot_fork_block_seal_state(&sealed, QmpCommandKind::HotForkBlockSeal).unwrap();
        assert!(receipt.seals(std::slice::from_ref(&request)));

        // Native sealing acquires the barrier after its graph mutation. Its
        // returned receipt must retain that authority before host capture.
        for (field, value) in [
            ("barrier-held", json!(false)),
            ("barrier-quiescent", json!(false)),
            ("barrier-generation", json!(0)),
            ("receipt-generation", json!(0)),
        ] {
            let mut unretained = sealed.clone();
            unretained[field] = value;
            assert!(
                parse_hot_fork_block_seal_state(&unretained, QmpCommandKind::HotForkBlockSeal)
                    .is_err(),
                "unretained native seal accepted: {field}"
            );
        }
        for field in ["overlay-empty", "snapshot-read-only"] {
            let mut writable = sealed.clone();
            writable["sealed-roots"][0][field] = json!(false);
            let receipt =
                parse_hot_fork_block_seal_state(&writable, QmpCommandKind::HotForkBlockSeal)
                    .unwrap();
            assert!(!receipt.seals(std::slice::from_ref(&request)));
        }

        sealed["sealed-roots"][0]["snapshot-file-inode"] = json!(35);
        let swapped =
            parse_hot_fork_block_seal_state(&sealed, QmpCommandKind::HotForkBlockSeal).unwrap();
        assert!(!swapped.seals(&[request]));
    }

    #[test]
    fn malformed_and_unsealed_reports_do_not_authorize_prepare() {
        let mut response = inventory();
        response["candidates"][0]["root-node-name"] = json!("");
        let unsealable =
            parse_hot_fork_block_seal_state(&response, QmpCommandKind::QueryHotForkBlockSeal)
                .unwrap();
        assert!(
            QmpHotForkBlockSealRequest::new(unsealable.candidates()[0].clone(), "fresh-root",)
                .is_err()
        );

        response["unknown"] = json!(true);
        assert!(
            parse_hot_fork_block_seal_state(&response, QmpCommandKind::QueryHotForkBlockSeal,)
                .is_err()
        );
    }
}
