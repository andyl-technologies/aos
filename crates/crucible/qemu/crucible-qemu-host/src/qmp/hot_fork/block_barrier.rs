//! Retained QEMU-owned block-graph writer and all-block drain barrier.

mod source_proof;

pub use source_proof::{
    QMP_HOT_FORK_BLOCK_SOURCE_PROOF_SCHEMA_VERSION, QmpHotForkBlockSourceProof,
};

use blake3::Hash;
use serde_json::{Value, json};
use thiserror::Error;

use super::QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX;
use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command name used for QEMU's reversible graph and block-drain barrier.
pub const QMP_HOT_FORK_BLOCK_BARRIER_COMMAND: &str = "crucible-hot-fork-block-barrier";
/// Version of the QEMU-owned graph-writer and block-drain barrier contract.
pub const QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION: u32 = 4;
/// Maximum UTF-8 byte length of a QEMU block-graph node name.
pub const QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES: usize = 31;

/// Error returned while constructing one immutable block-snapshot binding.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QmpHotForkBlockSnapshotBindingError {
    /// The process-local backend identity was zero.
    #[error("hot-fork block snapshot backend identity must be positive")]
    InvalidBackendId,
    /// A QEMU identifier did not satisfy the exact protocol grammar or bound.
    #[error("invalid hot-fork block snapshot {field} identifier: {value}")]
    InvalidIdentifier {
        /// Name of the rejected binding field.
        field: &'static str,
        /// Rejected identifier.
        value: String,
    },
}

/// Host-authenticated immutable-root identity for one writable backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkBlockSnapshotBinding {
    backend_id: u64,
    backend_name: String,
    overlay_node_name: String,
    snapshot_node_name: String,
    snapshot_content_id: Hash,
}

impl QmpHotForkBlockSnapshotBinding {
    /// Constructs one exact writable-overlay/read-only-snapshot binding.
    ///
    /// # Errors
    ///
    /// Returns [`QmpHotForkBlockSnapshotBindingError`] when the backend ID is
    /// zero or a backend/node name violates QEMU's identifier grammar or its
    /// protocol byte bound.
    pub fn new(
        backend_id: u64,
        backend_name: impl Into<String>,
        overlay_node_name: impl Into<String>,
        snapshot_node_name: impl Into<String>,
        snapshot_content_id: Hash,
    ) -> Result<Self, QmpHotForkBlockSnapshotBindingError> {
        if backend_id == 0 {
            return Err(QmpHotForkBlockSnapshotBindingError::InvalidBackendId);
        }
        let backend_name = backend_name.into();
        let overlay_node_name = overlay_node_name.into();
        let snapshot_node_name = snapshot_node_name.into();
        validate_qemu_identifier("backend-name", &backend_name, 255)?;
        validate_qemu_identifier(
            "overlay-node-name",
            &overlay_node_name,
            QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES,
        )?;
        validate_qemu_identifier(
            "snapshot-node-name",
            &snapshot_node_name,
            QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES,
        )?;
        Ok(Self {
            backend_id,
            backend_name,
            overlay_node_name,
            snapshot_node_name,
            snapshot_content_id,
        })
    }

    /// Returns the process-local backend identity.
    #[must_use]
    pub const fn backend_id(&self) -> u64 {
        self.backend_id
    }

    /// Returns the exact monitor-visible backend name.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }

    /// Returns the exact active empty-overlay node name.
    #[must_use]
    pub fn overlay_node_name(&self) -> &str {
        &self.overlay_node_name
    }

    /// Returns the exact immediate read-only snapshot node name.
    #[must_use]
    pub fn snapshot_node_name(&self) -> &str {
        &self.snapshot_node_name
    }

    /// Returns the host-authenticated immutable snapshot content identity.
    #[must_use]
    pub const fn snapshot_content_id(&self) -> Hash {
        self.snapshot_content_id
    }

    pub(crate) fn wire_value(&self) -> Value {
        json!({
            "backend-id": self.backend_id,
            "backend-name": self.backend_name,
            "overlay-node-name": self.overlay_node_name,
            "snapshot-node-name": self.snapshot_node_name,
            "snapshot-content-id": self.snapshot_content_id.to_hex().as_str(),
        })
    }
}

/// QEMU-attested immutable snapshot root retained by the block barrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkBlockSnapshotRoot {
    binding: QmpHotForkBlockSnapshotBinding,
    virtual_size: u64,
}

impl QmpHotForkBlockSnapshotRoot {
    /// Returns the exact requested graph/content binding QEMU attested.
    #[must_use]
    pub const fn binding(&self) -> &QmpHotForkBlockSnapshotBinding {
        &self.binding
    }

    /// Returns the exact guest-visible root size in bytes.
    #[must_use]
    pub const fn virtual_size(&self) -> u64 {
        self.virtual_size
    }
}

/// Exact state of QEMU's retained graph-writer and all-block drain barriers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkBlockBarrierState {
    generation: u64,
    owner_thread_id: i64,
    graph_barrier_generation: u64,
    graph_mutation_generation: u64,
    held_graph_mutation_generation: u64,
    graph_owner_thread_id: i64,
    held: bool,
    graph_held: bool,
    graph_writer_active: bool,
    graph_waiting_writers: u32,
    graph_stable: bool,
    snapshot_generation: u64,
    snapshot_backend_generation: u64,
    snapshot_graph_mutation_generation: u64,
    snapshot_owner_thread_id: i64,
    snapshot_bound: bool,
    snapshot_complete: bool,
    snapshot_roots: Vec<QmpHotForkBlockSnapshotRoot>,
    snapshot_sources: QmpHotForkBlockSourceProof,
    complete: bool,
    backend_count: u64,
    rooted_backends: u64,
    writable_backends: u64,
    writable_rooted_backends: u64,
    quiesced_rooted_backends: u64,
    in_flight: u64,
    quiescent: bool,
}

impl QmpHotForkBlockBarrierState {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn one_quiescent(generation: u64) -> Self {
        Self {
            generation,
            owner_thread_id: 1,
            graph_barrier_generation: generation,
            graph_mutation_generation: 1,
            held_graph_mutation_generation: 1,
            graph_owner_thread_id: 1,
            held: true,
            graph_held: true,
            graph_writer_active: false,
            graph_waiting_writers: 0,
            graph_stable: true,
            snapshot_generation: generation,
            snapshot_backend_generation: generation,
            snapshot_graph_mutation_generation: 1,
            snapshot_owner_thread_id: 1,
            snapshot_bound: true,
            snapshot_complete: true,
            snapshot_roots: Vec::new(),
            snapshot_sources: QmpHotForkBlockSourceProof::empty_frozen(),
            complete: true,
            backend_count: 0,
            rooted_backends: 0,
            writable_backends: 0,
            writable_rooted_backends: 0,
            quiesced_rooted_backends: 0,
            in_flight: 0,
            quiescent: true,
        }
    }

    /// Returns the process-local hold/release generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the coordinator thread that acquired the retained barrier.
    #[must_use]
    pub const fn owner_thread_id(&self) -> i64 {
        self.owner_thread_id
    }

    /// Returns the process-local graph-barrier state generation.
    #[must_use]
    pub const fn graph_barrier_generation(&self) -> u64 {
        self.graph_barrier_generation
    }

    /// Returns the generation of the latest completed block-graph mutation.
    #[must_use]
    pub const fn graph_mutation_generation(&self) -> u64 {
        self.graph_mutation_generation
    }

    /// Returns the graph-mutation generation captured by the retained hold.
    #[must_use]
    pub const fn held_graph_mutation_generation(&self) -> u64 {
        self.held_graph_mutation_generation
    }

    /// Returns the coordinator thread retaining block-graph writer exclusion.
    #[must_use]
    pub const fn graph_owner_thread_id(&self) -> i64 {
        self.graph_owner_thread_id
    }

    /// Returns whether the native all-block drain section remains retained.
    #[must_use]
    pub const fn held(&self) -> bool {
        self.held
    }

    /// Returns whether block-graph writer admission remains closed.
    #[must_use]
    pub const fn graph_held(&self) -> bool {
        self.graph_held
    }

    /// Returns whether a graph writer is inside its critical section.
    #[must_use]
    pub const fn graph_writer_active(&self) -> bool {
        self.graph_writer_active
    }

    /// Returns writers admitted but not yet inside their critical section.
    #[must_use]
    pub const fn graph_waiting_writers(&self) -> u32 {
        self.graph_waiting_writers
    }

    /// Returns whether the retained graph generation remains unchanged.
    #[must_use]
    pub const fn graph_stable(&self) -> bool {
        self.graph_stable
    }

    /// Returns the process-local immutable-root binding generation.
    #[must_use]
    pub const fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }

    /// Returns the backend generation captured by immutable-root binding.
    #[must_use]
    pub const fn snapshot_backend_generation(&self) -> u64 {
        self.snapshot_backend_generation
    }

    /// Returns the completed graph generation bound to the snapshot roots.
    #[must_use]
    pub const fn snapshot_graph_mutation_generation(&self) -> u64 {
        self.snapshot_graph_mutation_generation
    }

    /// Returns the coordinator retaining the immutable-root binding.
    #[must_use]
    pub const fn snapshot_owner_thread_id(&self) -> i64 {
        self.snapshot_owner_thread_id
    }

    /// Returns whether QEMU retains an immutable-root binding.
    #[must_use]
    pub const fn snapshot_bound(&self) -> bool {
        self.snapshot_bound
    }

    /// Returns whether every bound root still matches the retained barriers.
    #[must_use]
    pub const fn snapshot_complete(&self) -> bool {
        self.snapshot_complete
    }

    /// Returns the exact roots in increasing backend-ID order.
    #[must_use]
    pub fn snapshot_roots(&self) -> &[QmpHotForkBlockSnapshotRoot] {
        &self.snapshot_roots
    }

    /// Returns the native source provenance authenticated by snapshot binding.
    #[must_use]
    pub const fn snapshot_sources(&self) -> &QmpHotForkBlockSourceProof {
        &self.snapshot_sources
    }

    /// Returns whether QEMU observed the complete bounded backend registry.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns the exact allocated BlockBackend count.
    #[must_use]
    pub const fn backend_count(&self) -> u64 {
        self.backend_count
    }

    /// Returns the exact count of backends with a block root.
    #[must_use]
    pub const fn rooted_backends(&self) -> u64 {
        self.rooted_backends
    }

    /// Returns the exact count of backends requesting write permission.
    #[must_use]
    pub const fn writable_backends(&self) -> u64 {
        self.writable_backends
    }

    /// Returns rooted backends requesting write permission.
    #[must_use]
    pub const fn writable_rooted_backends(&self) -> u64 {
        self.writable_rooted_backends
    }

    /// Returns rooted backends retained inside a native drain section.
    #[must_use]
    pub const fn quiesced_rooted_backends(&self) -> u64 {
        self.quiesced_rooted_backends
    }

    /// Returns the checked aggregate BlockBackend in-flight I/O count.
    #[must_use]
    pub const fn in_flight(&self) -> u64 {
        self.in_flight
    }

    /// Returns whether every rooted backend is quiesced with no in-flight I/O.
    #[must_use]
    pub const fn quiescent(&self) -> bool {
        self.quiescent
    }
}

fn qemu_identifier_valid(value: &str, maximum_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic())
        && value.len() <= maximum_bytes
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
}

fn validate_qemu_identifier(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), QmpHotForkBlockSnapshotBindingError> {
    if qemu_identifier_valid(value, maximum_bytes) {
        return Ok(());
    }
    Err(QmpHotForkBlockSnapshotBindingError::InvalidIdentifier {
        field,
        value: value.to_owned(),
    })
}

pub(crate) fn parse_hot_fork_block_barrier_state(
    value: &Value,
) -> Result<QmpHotForkBlockBarrierState, QmpError> {
    parse_hot_fork_block_barrier_state_for(QmpCommandKind::HotForkBlockBarrier, value)
}

pub(crate) fn parse_hot_fork_block_barrier_state_for(
    command: QmpCommandKind,
    value: &Value,
) -> Result<QmpHotForkBlockBarrierState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "owner-thread-id",
        "graph-barrier-generation",
        "graph-mutation-generation",
        "held-graph-mutation-generation",
        "graph-owner-thread-id",
        "held",
        "graph-held",
        "graph-writer-active",
        "graph-waiting-writers",
        "graph-stable",
        "snapshot-generation",
        "snapshot-backend-generation",
        "snapshot-graph-mutation-generation",
        "snapshot-owner-thread-id",
        "snapshot-bound",
        "snapshot-complete",
        "snapshot-roots",
        "snapshot-sources",
        "complete",
        "backend-count",
        "rooted-backends",
        "writable-backends",
        "writable-rooted-backends",
        "quiesced-rooted-backends",
        "in-flight",
        "quiescent",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let owner_thread_id = object
        .get("owner-thread-id")
        .and_then(Value::as_i64)
        .ok_or_else(&malformed)?;
    let graph_barrier_generation = object
        .get("graph-barrier-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let graph_mutation_generation = object
        .get("graph-mutation-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let held_graph_mutation_generation = object
        .get("held-graph-mutation-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let graph_owner_thread_id = object
        .get("graph-owner-thread-id")
        .and_then(Value::as_i64)
        .ok_or_else(&malformed)?;
    let held = object
        .get("held")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let graph_held = object
        .get("graph-held")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let graph_writer_active = object
        .get("graph-writer-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let graph_waiting_writers = object
        .get("graph-waiting-writers")
        .and_then(Value::as_u64)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let graph_stable = object
        .get("graph-stable")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let snapshot_generation = object
        .get("snapshot-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let snapshot_backend_generation = object
        .get("snapshot-backend-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let snapshot_graph_mutation_generation = object
        .get("snapshot-graph-mutation-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let snapshot_owner_thread_id = object
        .get("snapshot-owner-thread-id")
        .and_then(Value::as_i64)
        .ok_or_else(&malformed)?;
    let snapshot_bound = object
        .get("snapshot-bound")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let snapshot_complete = object
        .get("snapshot-complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let snapshot_sources = QmpHotForkBlockSourceProof::parse(
        command,
        object.get("snapshot-sources").ok_or_else(&malformed)?,
    )?;
    let snapshot_root_values = object
        .get("snapshot-roots")
        .and_then(Value::as_array)
        .filter(|roots| roots.len() <= QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX)
        .ok_or_else(&malformed)?;
    let mut snapshot_roots = Vec::with_capacity(snapshot_root_values.len());
    let mut previous_backend_id = 0;
    for value in snapshot_root_values {
        let root = value.as_object().ok_or_else(&malformed)?;
        let root_fields = [
            "backend-id",
            "backend-name",
            "overlay-node-name",
            "snapshot-node-name",
            "snapshot-content-id",
            "virtual-size",
            "overlay-empty",
            "snapshot-read-only",
        ];
        if root.len() != root_fields.len()
            || !root_fields.iter().all(|field| root.contains_key(*field))
        {
            return Err(malformed());
        }
        let backend_id = root
            .get("backend-id")
            .and_then(Value::as_u64)
            .filter(|id| *id > previous_backend_id)
            .ok_or_else(&malformed)?;
        let backend_name = root
            .get("backend-name")
            .and_then(Value::as_str)
            .filter(|name| qemu_identifier_valid(name, 255))
            .ok_or_else(&malformed)?;
        let overlay_node_name = root
            .get("overlay-node-name")
            .and_then(Value::as_str)
            .filter(|name| qemu_identifier_valid(name, QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES))
            .ok_or_else(&malformed)?;
        let snapshot_node_name = root
            .get("snapshot-node-name")
            .and_then(Value::as_str)
            .filter(|name| qemu_identifier_valid(name, QMP_HOT_FORK_BLOCK_NODE_NAME_MAX_BYTES))
            .ok_or_else(&malformed)?;
        let snapshot_content_id = root
            .get("snapshot-content-id")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .and_then(|value| Hash::from_hex(value).ok())
            .ok_or_else(&malformed)?;
        let virtual_size = root
            .get("virtual-size")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?;
        let overlay_empty = root
            .get("overlay-empty")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let snapshot_read_only = root
            .get("snapshot-read-only")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        if !overlay_empty || !snapshot_read_only {
            return Err(malformed());
        }
        snapshot_roots.push(QmpHotForkBlockSnapshotRoot {
            binding: QmpHotForkBlockSnapshotBinding {
                backend_id,
                backend_name: backend_name.to_owned(),
                overlay_node_name: overlay_node_name.to_owned(),
                snapshot_node_name: snapshot_node_name.to_owned(),
                snapshot_content_id,
            },
            virtual_size,
        });
        previous_backend_id = backend_id;
    }
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let backend_count = object
        .get("backend-count")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let rooted_backends = object
        .get("rooted-backends")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let writable_backends = object
        .get("writable-backends")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let writable_rooted_backends = object
        .get("writable-rooted-backends")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let quiesced_rooted_backends = object
        .get("quiesced-rooted-backends")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let in_flight = object
        .get("in-flight")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let quiescent = object
        .get("quiescent")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let expected_graph_stable = graph_held
        && !graph_writer_active
        && graph_mutation_generation == held_graph_mutation_generation;
    let expected_snapshot_complete = snapshot_bound
        && held
        && complete
        && snapshot_owner_thread_id == owner_thread_id
        && snapshot_backend_generation != 0
        && snapshot_graph_mutation_generation == held_graph_mutation_generation
        && if snapshot_sources.frozen() {
            writable_backends == 0
                && snapshot_roots.len() as u64
                    == snapshot_sources.originally_writable_backend_count()
        } else {
            snapshot_roots.len() as u64 == writable_rooted_backends
        };
    let expected_quiescent = held
        && graph_stable
        && complete
        && in_flight == 0
        && quiesced_rooted_backends == rooted_backends;
    let valid = schema_version == u64::from(QMP_HOT_FORK_BLOCK_BARRIER_SCHEMA_VERSION)
        && backend_count <= QMP_HOT_FORK_BLOCK_BACKEND_INVENTORY_MAX as u64
        && rooted_backends <= backend_count
        && writable_backends <= backend_count
        && writable_rooted_backends <= writable_backends
        && writable_rooted_backends <= rooted_backends
        && quiesced_rooted_backends <= rooted_backends
        && (!snapshot_sources.frozen()
            || (snapshot_bound
                && rooted_backends == backend_count
                && rooted_backends <= snapshot_sources.root_count()
                && snapshot_sources.originally_writable_backend_count() <= rooted_backends))
        && graph_stable == expected_graph_stable
        && snapshot_complete == expected_snapshot_complete
        && quiescent == expected_quiescent
        && if held {
            generation != 0
                && owner_thread_id > 0
                && graph_barrier_generation != 0
                && graph_held
                && graph_owner_thread_id == owner_thread_id
                && graph_stable
                && if snapshot_bound {
                    snapshot_generation != 0
                        && snapshot_owner_thread_id == owner_thread_id
                        && snapshot_backend_generation != 0
                        && snapshot_graph_mutation_generation == held_graph_mutation_generation
                } else {
                    snapshot_owner_thread_id == 0
                        && snapshot_backend_generation == 0
                        && snapshot_graph_mutation_generation == 0
                        && snapshot_roots.is_empty()
                        && !snapshot_complete
                }
        } else {
            owner_thread_id == 0
                && !graph_held
                && graph_owner_thread_id == 0
                && held_graph_mutation_generation == 0
                && !graph_stable
                && !snapshot_bound
                && !snapshot_complete
                && snapshot_owner_thread_id == 0
                && snapshot_backend_generation == 0
                && snapshot_graph_mutation_generation == 0
                && snapshot_roots.is_empty()
                && !quiescent
        };
    if !valid {
        return Err(malformed());
    }

    Ok(QmpHotForkBlockBarrierState {
        generation,
        owner_thread_id,
        graph_barrier_generation,
        graph_mutation_generation,
        held_graph_mutation_generation,
        graph_owner_thread_id,
        held,
        graph_held,
        graph_writer_active,
        graph_waiting_writers,
        graph_stable,
        snapshot_generation,
        snapshot_backend_generation,
        snapshot_graph_mutation_generation,
        snapshot_owner_thread_id,
        snapshot_bound,
        snapshot_complete,
        snapshot_roots,
        snapshot_sources,
        complete,
        backend_count,
        rooted_backends,
        writable_backends,
        writable_rooted_backends,
        quiesced_rooted_backends,
        in_flight,
        quiescent,
    })
}
