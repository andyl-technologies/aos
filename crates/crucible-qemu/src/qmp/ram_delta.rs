//! Typed QMP contract for QEMU-owned exact RAM checkpoint epochs.
//!
//! A capture binds checkpoint, target, and scheduler-frontier identities to a
//! direct or parent-relative RAM artifact. QEMU retains the candidate until an
//! exact commit or abort, while the host durably stages both imported outputs.
//!
//! ```text
//! {"execute":"crucible-checkpoint-commit","arguments":{
//!   "checkpoint-sha256":"<64 lowercase hex>",
//!   "target-sha256":"<64 lowercase hex>",
//!   "frontier-sha256":"<64 lowercase hex>"}}
//! ```

use crucible::ContentHash;
use serde_json::{Map, Value, json};

use super::{QmpCommandKind, QmpDescriptorName, QmpError};

/// Version of the QEMU exact checkpoint capture and epoch contract.
pub(crate) const QMP_CHECKPOINT_SCHEMA_VERSION: u32 = 2;
/// QMP command that captures one direct or delta checkpoint candidate.
pub(crate) const QMP_CHECKPOINT_CAPTURE_COMMAND: &str = "crucible-checkpoint-capture";
/// QMP command that commits one exact checkpoint candidate.
pub(crate) const QMP_CHECKPOINT_COMMIT_COMMAND: &str = "crucible-checkpoint-commit";
/// QMP command that aborts one exact checkpoint candidate.
pub(crate) const QMP_CHECKPOINT_ABORT_COMMAND: &str = "crucible-checkpoint-abort";
/// QMP command that restores one authenticated direct-plus-delta chain.
pub(crate) const QMP_CHECKPOINT_RESTORE_COMMAND: &str = "crucible-checkpoint-restore";
/// QMP command that queries QEMU's exact checkpoint authority.
pub(crate) const QMP_QUERY_CHECKPOINT_EPOCH_COMMAND: &str = "query-crucible-checkpoint-epoch";

/// Exact identity triple that distinguishes one checkpoint frontier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpCheckpointIdentity {
    checkpoint: ContentHash,
    target: ContentHash,
    frontier: ContentHash,
}

impl QmpCheckpointIdentity {
    /// Builds an exact checkpoint, target, and scheduler-frontier identity.
    #[must_use]
    pub const fn new(checkpoint: ContentHash, target: ContentHash, frontier: ContentHash) -> Self {
        Self {
            checkpoint,
            target,
            frontier,
        }
    }

    /// Returns the exact checkpoint identity.
    #[must_use]
    pub const fn checkpoint(self) -> ContentHash {
        self.checkpoint
    }

    /// Returns the exact target identity.
    #[must_use]
    pub const fn target(self) -> ContentHash {
        self.target
    }

    /// Returns the exact scheduler-frontier identity.
    #[must_use]
    pub const fn frontier(self) -> ContentHash {
        self.frontier
    }

    pub(super) fn wire_value(self) -> Value {
        json!({
            "checkpoint-sha256": self.checkpoint.to_hex(),
            "target-sha256": self.target.to_hex(),
            "frontier-sha256": self.frontier.to_hex(),
        })
    }
}

/// RAM payload selected for one exact checkpoint capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpCheckpointRamKind {
    /// Complete canonical migratable RAMBlock contents.
    Direct,
    /// Pages dirtied since the exact committed parent epoch.
    Delta,
}

impl QmpCheckpointRamKind {
    pub(super) const fn wire_name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Delta => "delta",
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "direct" => Some(Self::Direct),
            "delta" => Some(Self::Delta),
            _ => None,
        }
    }
}

/// Bounded descriptor-backed exact checkpoint capture request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QmpCheckpointCaptureRequest {
    kind: QmpCheckpointRamKind,
    identity: QmpCheckpointIdentity,
    parent: Option<QmpCheckpointIdentity>,
    ram_descriptor: QmpDescriptorName,
    device_descriptor: QmpDescriptorName,
    cancellation_descriptor: QmpDescriptorName,
    maximum_ram_bytes: u64,
    maximum_device_bytes: u64,
}

struct QmpCheckpointCaptureOutputs {
    ram_descriptor: QmpDescriptorName,
    device_descriptor: QmpDescriptorName,
    cancellation_descriptor: QmpDescriptorName,
    maximum_ram_bytes: u64,
    maximum_device_bytes: u64,
}

impl QmpCheckpointCaptureRequest {
    /// Builds a bounded direct capture request without a parent.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidBound`] when either output ceiling is zero.
    pub(crate) fn direct(
        identity: QmpCheckpointIdentity,
        ram_descriptor: QmpDescriptorName,
        device_descriptor: QmpDescriptorName,
        cancellation_descriptor: QmpDescriptorName,
        maximum_ram_bytes: u64,
        maximum_device_bytes: u64,
    ) -> Result<Self, QmpError> {
        Self::new(
            QmpCheckpointRamKind::Direct,
            identity,
            None,
            QmpCheckpointCaptureOutputs {
                ram_descriptor,
                device_descriptor,
                cancellation_descriptor,
                maximum_ram_bytes,
                maximum_device_bytes,
            },
        )
    }

    /// Builds a bounded delta capture bound to one exact committed parent.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidBound`] when either output ceiling is zero.
    pub(crate) fn delta(
        identity: QmpCheckpointIdentity,
        parent: QmpCheckpointIdentity,
        ram_descriptor: QmpDescriptorName,
        device_descriptor: QmpDescriptorName,
        cancellation_descriptor: QmpDescriptorName,
        maximum_ram_bytes: u64,
        maximum_device_bytes: u64,
    ) -> Result<Self, QmpError> {
        Self::new(
            QmpCheckpointRamKind::Delta,
            identity,
            Some(parent),
            QmpCheckpointCaptureOutputs {
                ram_descriptor,
                device_descriptor,
                cancellation_descriptor,
                maximum_ram_bytes,
                maximum_device_bytes,
            },
        )
    }

    fn new(
        kind: QmpCheckpointRamKind,
        identity: QmpCheckpointIdentity,
        parent: Option<QmpCheckpointIdentity>,
        outputs: QmpCheckpointCaptureOutputs,
    ) -> Result<Self, QmpError> {
        let QmpCheckpointCaptureOutputs {
            ram_descriptor,
            device_descriptor,
            cancellation_descriptor,
            maximum_ram_bytes,
            maximum_device_bytes,
        } = outputs;
        if maximum_ram_bytes == 0 || maximum_device_bytes == 0 {
            return Err(QmpError::InvalidBound {
                operation: "capture an exact QEMU checkpoint candidate",
            });
        }
        if ram_descriptor == device_descriptor
            || ram_descriptor == cancellation_descriptor
            || device_descriptor == cancellation_descriptor
        {
            return Err(QmpError::InvalidBound {
                operation: "capture an exact QEMU checkpoint with distinct descriptors",
            });
        }
        Ok(Self {
            kind,
            identity,
            parent,
            ram_descriptor,
            device_descriptor,
            cancellation_descriptor,
            maximum_ram_bytes,
            maximum_device_bytes,
        })
    }

    /// Returns the candidate identity triple.
    #[must_use]
    pub const fn identity(&self) -> QmpCheckpointIdentity {
        self.identity
    }

    /// Returns the exact parent triple for a delta capture.
    #[must_use]
    pub const fn parent(&self) -> Option<QmpCheckpointIdentity> {
        self.parent
    }

    /// Returns the QMP name receiving the RAM output descriptor.
    #[must_use]
    pub const fn ram_descriptor(&self) -> &QmpDescriptorName {
        &self.ram_descriptor
    }

    /// Returns the QMP name receiving the device-state output descriptor.
    #[must_use]
    pub const fn device_descriptor(&self) -> &QmpDescriptorName {
        &self.device_descriptor
    }

    /// Returns the QMP name receiving the cancellation descriptor.
    #[must_use]
    pub const fn cancellation_descriptor(&self) -> &QmpDescriptorName {
        &self.cancellation_descriptor
    }

    pub(super) fn wire_value(&self) -> Value {
        let mut arguments = self
            .identity
            .wire_value()
            .as_object()
            .cloned()
            .unwrap_or_default();

        arguments.insert(
            "kind".to_owned(),
            Value::String(self.kind.wire_name().to_owned()),
        );
        arguments.insert(
            "ram-fdname".to_owned(),
            Value::String(self.ram_descriptor.as_str().to_owned()),
        );
        arguments.insert(
            "device-fdname".to_owned(),
            Value::String(self.device_descriptor.as_str().to_owned()),
        );
        arguments.insert(
            "cancellation-fdname".to_owned(),
            Value::String(self.cancellation_descriptor.as_str().to_owned()),
        );
        arguments.insert(
            "maximum-ram-bytes".to_owned(),
            Value::from(self.maximum_ram_bytes),
        );
        arguments.insert(
            "maximum-device-bytes".to_owned(),
            Value::from(self.maximum_device_bytes),
        );
        if let Some(parent) = self.parent {
            arguments.insert(
                "parent-checkpoint-sha256".to_owned(),
                Value::String(parent.checkpoint.to_hex()),
            );
            arguments.insert(
                "parent-target-sha256".to_owned(),
                Value::String(parent.target.to_hex()),
            );
            arguments.insert(
                "parent-frontier-sha256".to_owned(),
                Value::String(parent.frontier.to_hex()),
            );
        }
        Value::Object(arguments)
    }
}

/// QEMU-authenticated result of writing one exact checkpoint candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QmpCheckpointCapture {
    kind: QmpCheckpointRamKind,
    identity: QmpCheckpointIdentity,
    topology: ContentHash,
    ram_regions: u64,
    ram_records: u64,
    ram_bytes: u64,
    device_bytes: u64,
}

/// One authenticated CRUCRAM2 input in direct-then-delta chain order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpCheckpointRestoreLayer {
    descriptor: QmpDescriptorName,
    content: ContentHash,
    maximum_bytes: u64,
}

impl QmpCheckpointRestoreLayer {
    /// Builds one bounded restore layer.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidBound`] when `maximum_bytes` is zero.
    pub(crate) fn new(
        descriptor: QmpDescriptorName,
        content: ContentHash,
        maximum_bytes: u64,
    ) -> Result<Self, QmpError> {
        if maximum_bytes == 0 {
            return Err(QmpError::InvalidBound {
                operation: "restore a bounded exact QEMU checkpoint RAM layer",
            });
        }
        Ok(Self {
            descriptor,
            content,
            maximum_bytes,
        })
    }

    /// Returns the QMP name receiving this RAM layer descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &QmpDescriptorName {
        &self.descriptor
    }

    /// Returns the maximum bytes QEMU may read from this layer.
    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    fn wire_value(&self) -> Value {
        json!({
            "ram-fdname": self.descriptor.as_str(),
            "ram-sha256": self.content.to_hex(),
            "maximum-ram-bytes": self.maximum_bytes,
        })
    }
}

/// Bounded request to restore a complete direct-plus-delta chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpCheckpointRestoreRequest {
    layers: Vec<QmpCheckpointRestoreLayer>,
    device_descriptor: QmpDescriptorName,
    device_content: ContentHash,
    cancellation_descriptor: QmpDescriptorName,
    identity: QmpCheckpointIdentity,
    maximum_device_bytes: u64,
}

impl QmpCheckpointRestoreRequest {
    /// Builds one exact restore request with at most eight RAM layers.
    ///
    /// # Errors
    ///
    /// Returns [`QmpError::InvalidBound`] for an empty or oversized chain, a
    /// zero device ceiling, or any aliased descriptor name.
    pub(crate) fn new(
        layers: Vec<QmpCheckpointRestoreLayer>,
        device_descriptor: QmpDescriptorName,
        device_content: ContentHash,
        cancellation_descriptor: QmpDescriptorName,
        identity: QmpCheckpointIdentity,
        maximum_device_bytes: u64,
    ) -> Result<Self, QmpError> {
        let maximum_ram_bytes = layers
            .iter()
            .try_fold(0_u64, |total, layer| total.checked_add(layer.maximum_bytes));
        if layers.is_empty()
            || layers.len() > crucible::exact_checkpoint::MAX_EXACT_CHECKPOINT_RAM_LAYERS
            || maximum_ram_bytes.is_none()
            || maximum_device_bytes == 0
        {
            return Err(QmpError::InvalidBound {
                operation: "restore an exact QEMU checkpoint chain",
            });
        }
        let reserved_alias = layers.iter().any(|layer| {
            layer.descriptor == device_descriptor || layer.descriptor == cancellation_descriptor
        });
        let layer_alias = layers.iter().enumerate().any(|(index, layer)| {
            layers[index + 1..]
                .iter()
                .any(|other| layer.descriptor == other.descriptor)
        });
        if device_descriptor == cancellation_descriptor || reserved_alias || layer_alias {
            return Err(QmpError::InvalidBound {
                operation: "restore an exact QEMU checkpoint with distinct descriptors",
            });
        }
        Ok(Self {
            layers,
            device_descriptor,
            device_content,
            cancellation_descriptor,
            identity,
            maximum_device_bytes,
        })
    }

    /// Returns the final checkpoint identity requested from QEMU.
    #[must_use]
    pub const fn identity(&self) -> QmpCheckpointIdentity {
        self.identity
    }

    /// Returns the ordered direct-then-delta RAM layer requests.
    #[must_use]
    pub fn layers(&self) -> &[QmpCheckpointRestoreLayer] {
        &self.layers
    }

    /// Returns the QMP name receiving the final device-state descriptor.
    #[must_use]
    pub const fn device_descriptor(&self) -> &QmpDescriptorName {
        &self.device_descriptor
    }

    /// Returns the QMP name receiving the cancellation descriptor.
    #[must_use]
    pub const fn cancellation_descriptor(&self) -> &QmpDescriptorName {
        &self.cancellation_descriptor
    }

    fn maximum_ram_bytes(&self) -> Option<u64> {
        self.layers
            .iter()
            .try_fold(0_u64, |total, layer| total.checked_add(layer.maximum_bytes))
    }

    pub(super) fn wire_value(&self) -> Value {
        let mut arguments = self
            .identity
            .wire_value()
            .as_object()
            .cloned()
            .unwrap_or_default();
        arguments.insert(
            "layers".to_owned(),
            Value::Array(
                self.layers
                    .iter()
                    .map(QmpCheckpointRestoreLayer::wire_value)
                    .collect(),
            ),
        );
        arguments.insert(
            "device-fdname".to_owned(),
            Value::String(self.device_descriptor.as_str().to_owned()),
        );
        arguments.insert(
            "device-sha256".to_owned(),
            Value::String(self.device_content.to_hex()),
        );
        arguments.insert(
            "cancellation-fdname".to_owned(),
            Value::String(self.cancellation_descriptor.as_str().to_owned()),
        );
        arguments.insert(
            "maximum-device-bytes".to_owned(),
            Value::from(self.maximum_device_bytes),
        );
        Value::Object(arguments)
    }
}

/// QEMU-authenticated result of restoring one exact checkpoint chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QmpCheckpointRestore {
    pub(super) identity: QmpCheckpointIdentity,
    topology: ContentHash,
    pub(super) ram_layers: u64,
    pub(super) ram_bytes: u64,
    pub(super) device_bytes: u64,
}

impl QmpCheckpointRestore {
    /// Returns the canonical restored RAMBlock topology identity.
    #[must_use]
    pub const fn topology(self) -> ContentHash {
        self.topology
    }
}

impl QmpCheckpointCapture {
    #[cfg(test)]
    pub(crate) fn for_test(request: &QmpCheckpointCaptureRequest, topology: ContentHash) -> Self {
        Self {
            kind: request.kind,
            identity: request.identity,
            topology,
            ram_regions: 1,
            ram_records: 1,
            ram_bytes: 1,
            device_bytes: 1,
        }
    }

    /// Returns whether the candidate contains direct or delta RAM.
    #[must_use]
    pub const fn kind(&self) -> QmpCheckpointRamKind {
        self.kind
    }

    /// Returns the exact candidate identity triple.
    #[must_use]
    pub const fn identity(&self) -> QmpCheckpointIdentity {
        self.identity
    }

    /// Returns the canonical QEMU RAMBlock topology identity.
    #[must_use]
    pub const fn topology(&self) -> ContentHash {
        self.topology
    }

    /// Returns the number of canonical RAMBlock topology entries.
    #[must_use]
    pub const fn ram_regions(&self) -> u64 {
        self.ram_regions
    }

    /// Returns the number of bounded RAM payload records.
    #[must_use]
    pub const fn ram_records(&self) -> u64 {
        self.ram_records
    }

    /// Returns the exact bytes written to the RAM artifact.
    #[must_use]
    pub const fn ram_bytes(&self) -> u64 {
        self.ram_bytes
    }

    /// Returns the exact bytes written to the non-RAM VMState artifact.
    #[must_use]
    pub const fn device_bytes(&self) -> u64 {
        self.device_bytes
    }
}

/// QEMU-owned committed checkpoint and active candidate authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpCheckpointEpochState {
    epoch_generation: u64,
    committed: Option<QmpCheckpointIdentity>,
    candidate: Option<QmpCheckpointIdentity>,
}

impl QmpCheckpointEpochState {
    #[cfg(test)]
    pub(crate) const fn for_test(
        epoch_generation: u64,
        committed: Option<QmpCheckpointIdentity>,
        candidate: Option<QmpCheckpointIdentity>,
    ) -> Self {
        Self {
            epoch_generation,
            committed,
            candidate,
        }
    }

    /// Returns the monotonically increasing committed epoch generation.
    #[must_use]
    pub const fn epoch_generation(self) -> u64 {
        self.epoch_generation
    }

    /// Returns the exact committed checkpoint authority, when initialized.
    #[must_use]
    pub const fn committed(self) -> Option<QmpCheckpointIdentity> {
        self.committed
    }

    /// Returns the exact active candidate awaiting commit or abort.
    #[must_use]
    pub const fn candidate(self) -> Option<QmpCheckpointIdentity> {
        self.candidate
    }
}

fn parse_hash(value: Option<&Value>) -> Option<ContentHash> {
    let encoded = value?.as_str()?;
    if encoded.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        if pair[0].is_ascii_uppercase() || pair[1].is_ascii_uppercase() {
            return None;
        }
        bytes[index] = u8::try_from(high * 16 + low).ok()?;
    }
    Some(ContentHash { bytes })
}

fn parse_identity(object: &Map<String, Value>, prefix: &str) -> Option<QmpCheckpointIdentity> {
    Some(QmpCheckpointIdentity::new(
        parse_hash(object.get(&format!("{prefix}checkpoint-sha256")))?,
        parse_hash(object.get(&format!("{prefix}target-sha256")))?,
        parse_hash(object.get(&format!("{prefix}frontier-sha256")))?,
    ))
}

pub(super) fn parse_checkpoint_capture(
    value: &Value,
    request: &QmpCheckpointCaptureRequest,
) -> Result<QmpCheckpointCapture, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::CheckpointCapture,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "kind",
        "checkpoint-sha256",
        "target-sha256",
        "frontier-sha256",
        "topology-sha256",
        "ram-regions",
        "ram-records",
        "ram-bytes",
        "device-bytes",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }
    let capture = QmpCheckpointCapture {
        kind: object
            .get("kind")
            .and_then(Value::as_str)
            .and_then(QmpCheckpointRamKind::from_wire)
            .ok_or_else(&malformed)?,
        identity: parse_identity(object, "").ok_or_else(&malformed)?,
        topology: parse_hash(object.get("topology-sha256")).ok_or_else(&malformed)?,
        ram_regions: object
            .get("ram-regions")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
        ram_records: object
            .get("ram-records")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
        ram_bytes: object
            .get("ram-bytes")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
        device_bytes: object
            .get("device-bytes")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
    };
    let valid = object.get("schema-version").and_then(Value::as_u64)
        == Some(u64::from(QMP_CHECKPOINT_SCHEMA_VERSION))
        && capture.kind == request.kind
        && capture.identity == request.identity
        && capture.ram_regions > 0
        && capture.ram_bytes > 0
        && capture.ram_bytes <= request.maximum_ram_bytes
        && capture.device_bytes > 0
        && capture.device_bytes <= request.maximum_device_bytes;
    if !valid {
        return Err(malformed());
    }
    Ok(capture)
}

pub(super) fn parse_checkpoint_restore(
    value: &Value,
    request: &QmpCheckpointRestoreRequest,
) -> Result<QmpCheckpointRestore, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::CheckpointRestore,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "checkpoint-sha256",
        "target-sha256",
        "frontier-sha256",
        "topology-sha256",
        "ram-layers",
        "ram-bytes",
        "device-bytes",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }
    let restore = QmpCheckpointRestore {
        identity: parse_identity(object, "").ok_or_else(&malformed)?,
        topology: parse_hash(object.get("topology-sha256")).ok_or_else(&malformed)?,
        ram_layers: object
            .get("ram-layers")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
        ram_bytes: object
            .get("ram-bytes")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
        device_bytes: object
            .get("device-bytes")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
    };
    let valid = object.get("schema-version").and_then(Value::as_u64)
        == Some(u64::from(QMP_CHECKPOINT_SCHEMA_VERSION))
        && restore.identity == request.identity
        && restore.ram_layers == request.layers.len() as u64
        && restore.ram_bytes > 0
        && request
            .maximum_ram_bytes()
            .is_some_and(|maximum| restore.ram_bytes <= maximum)
        && restore.device_bytes > 0
        && restore.device_bytes <= request.maximum_device_bytes;
    if !valid {
        return Err(malformed());
    }
    Ok(restore)
}

pub(super) fn parse_checkpoint_epoch_state(
    command: QmpCommandKind,
    value: &Value,
) -> Result<QmpCheckpointEpochState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let required = [
        "schema-version",
        "epoch-active",
        "epoch-generation",
        "candidate-active",
    ];
    let optional = [
        "committed-checkpoint-sha256",
        "committed-target-sha256",
        "committed-frontier-sha256",
        "candidate-checkpoint-sha256",
        "candidate-target-sha256",
        "candidate-frontier-sha256",
    ];
    if !required.iter().all(|field| object.contains_key(*field))
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err(malformed());
    }
    let epoch_active = object
        .get("epoch-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let candidate_active = object
        .get("candidate-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let committed_fields = optional[..3]
        .iter()
        .filter(|field| object.contains_key(**field))
        .count();
    let candidate_fields = optional[3..]
        .iter()
        .filter(|field| object.contains_key(**field))
        .count();
    let committed = (committed_fields == 3)
        .then(|| parse_identity(object, "committed-"))
        .flatten();
    let candidate = (candidate_fields == 3)
        .then(|| parse_identity(object, "candidate-"))
        .flatten();
    let state = QmpCheckpointEpochState {
        epoch_generation: object
            .get("epoch-generation")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
        committed,
        candidate,
    };
    let valid = object.get("schema-version").and_then(Value::as_u64)
        == Some(u64::from(QMP_CHECKPOINT_SCHEMA_VERSION))
        && committed_fields != 1
        && committed_fields != 2
        && candidate_fields != 1
        && candidate_fields != 2
        && (committed_fields == 0 || committed.is_some())
        && (candidate_fields == 0 || candidate.is_some())
        && epoch_active == state.committed.is_some()
        && candidate_active == state.candidate.is_some()
        && (!epoch_active || state.epoch_generation > 0);
    if !valid {
        return Err(malformed());
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> QmpCheckpointIdentity {
        QmpCheckpointIdentity::new(
            ContentHash { bytes: [byte; 32] },
            ContentHash {
                bytes: [byte + 1; 32],
            },
            ContentHash {
                bytes: [byte + 2; 32],
            },
        )
    }

    #[test]
    fn delta_wire_request_binds_complete_parent_triple() -> Result<(), QmpError> {
        let request = QmpCheckpointCaptureRequest::delta(
            identity(1),
            identity(4),
            QmpDescriptorName::new("ram")?,
            QmpDescriptorName::new("device")?,
            QmpDescriptorName::new("cancel")?,
            4096,
            8192,
        )?;
        let wire = request.wire_value();

        assert_eq!(wire["kind"], "delta");
        assert_eq!(wire["checkpoint-sha256"], "01".repeat(32));
        assert_eq!(wire["parent-checkpoint-sha256"], "04".repeat(32));
        assert_eq!(wire["parent-target-sha256"], "05".repeat(32));
        assert_eq!(wire["parent-frontier-sha256"], "06".repeat(32));
        Ok(())
    }

    #[test]
    fn epoch_parser_preserves_parent_when_candidate_is_absent() -> Result<(), QmpError> {
        let committed = identity(7);
        let value = json!({
            "schema-version": 2,
            "epoch-active": true,
            "epoch-generation": 3,
            "candidate-active": false,
            "committed-checkpoint-sha256": committed.checkpoint().to_hex(),
            "committed-target-sha256": committed.target().to_hex(),
            "committed-frontier-sha256": committed.frontier().to_hex(),
        });

        let state = parse_checkpoint_epoch_state(QmpCommandKind::CheckpointAbort, &value)?;
        assert_eq!(state.committed(), Some(committed));
        assert_eq!(state.candidate(), None);
        assert_eq!(state.epoch_generation(), 3);
        Ok(())
    }

    #[test]
    fn epoch_parser_rejects_partial_parent_identity() {
        let value = json!({
            "schema-version": 2,
            "epoch-active": true,
            "epoch-generation": 1,
            "candidate-active": false,
            "committed-checkpoint-sha256": "11".repeat(32),
        });

        assert!(parse_checkpoint_epoch_state(QmpCommandKind::CheckpointCommit, &value).is_err());
    }

    #[test]
    fn epoch_parser_rejects_inactive_committed_identity() {
        let committed = identity(10);
        let value = json!({
            "schema-version": 2,
            "epoch-active": false,
            "epoch-generation": 0,
            "candidate-active": false,
            "committed-checkpoint-sha256": committed.checkpoint().to_hex(),
            "committed-target-sha256": committed.target().to_hex(),
            "committed-frontier-sha256": committed.frontier().to_hex(),
        });

        assert!(
            parse_checkpoint_epoch_state(QmpCommandKind::QueryCheckpointEpoch, &value).is_err()
        );
    }

    #[test]
    fn epoch_parser_rejects_inactive_malformed_committed_identity() {
        let value = json!({
            "schema-version": 2,
            "epoch-active": false,
            "epoch-generation": 0,
            "candidate-active": false,
            "committed-checkpoint-sha256": "gg".repeat(32),
            "committed-target-sha256": "hh".repeat(32),
            "committed-frontier-sha256": "ii".repeat(32),
        });

        assert!(
            parse_checkpoint_epoch_state(QmpCommandKind::QueryCheckpointEpoch, &value).is_err()
        );
    }

    #[test]
    fn epoch_parser_rejects_inactive_candidate_identity() {
        let candidate = identity(13);
        let value = json!({
            "schema-version": 2,
            "epoch-active": false,
            "epoch-generation": 0,
            "candidate-active": false,
            "candidate-checkpoint-sha256": candidate.checkpoint().to_hex(),
            "candidate-target-sha256": candidate.target().to_hex(),
            "candidate-frontier-sha256": candidate.frontier().to_hex(),
        });

        assert!(
            parse_checkpoint_epoch_state(QmpCommandKind::QueryCheckpointEpoch, &value).is_err()
        );
    }

    #[test]
    fn epoch_parser_rejects_inactive_malformed_candidate_identity() {
        let value = json!({
            "schema-version": 2,
            "epoch-active": false,
            "epoch-generation": 0,
            "candidate-active": false,
            "candidate-checkpoint-sha256": "xx".repeat(32),
            "candidate-target-sha256": "yy".repeat(32),
            "candidate-frontier-sha256": "zz".repeat(32),
        });

        assert!(
            parse_checkpoint_epoch_state(QmpCommandKind::QueryCheckpointEpoch, &value).is_err()
        );
    }

    #[test]
    fn epoch_parser_retains_generation_after_fail_closed_invalidation() -> Result<(), QmpError> {
        let value = json!({
            "schema-version": 2,
            "epoch-active": false,
            "epoch-generation": 4,
            "candidate-active": false,
        });

        let state = parse_checkpoint_epoch_state(QmpCommandKind::QueryCheckpointEpoch, &value)?;
        assert_eq!(state.epoch_generation(), 4);
        assert_eq!(state.committed(), None);
        assert_eq!(state.candidate(), None);
        Ok(())
    }

    #[test]
    fn epoch_parser_rejects_prior_nanosecond_schema() {
        let value = json!({
            "schema-version": 1,
            "epoch-active": false,
            "epoch-generation": 4,
            "candidate-active": false,
        });

        assert!(parse_checkpoint_epoch_state(QmpCommandKind::QueryCheckpointEpoch, &value).is_err());
    }

    #[test]
    fn capture_rejects_aliased_descriptor_names() -> Result<(), QmpError> {
        let shared = QmpDescriptorName::new("shared")?;

        assert!(
            QmpCheckpointCaptureRequest::direct(
                identity(1),
                shared.clone(),
                shared,
                QmpDescriptorName::new("cancel")?,
                4096,
                8192,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn restore_wire_request_preserves_order_and_final_identity() -> Result<(), QmpError> {
        let request = QmpCheckpointRestoreRequest::new(
            vec![
                QmpCheckpointRestoreLayer::new(
                    QmpDescriptorName::new("direct")?,
                    identity(20).checkpoint(),
                    4096,
                )?,
                QmpCheckpointRestoreLayer::new(
                    QmpDescriptorName::new("delta")?,
                    identity(21).checkpoint(),
                    2048,
                )?,
            ],
            QmpDescriptorName::new("device")?,
            identity(22).checkpoint(),
            QmpDescriptorName::new("cancel")?,
            identity(23),
            8192,
        )?;
        let wire = request.wire_value();

        assert_eq!(wire["layers"][0]["ram-fdname"], "direct");
        assert_eq!(wire["layers"][1]["ram-fdname"], "delta");
        assert_eq!(wire["checkpoint-sha256"], "17".repeat(32));
        assert_eq!(wire["maximum-device-bytes"], 8192);
        Ok(())
    }

    #[test]
    fn restore_parser_binds_identity_layer_count_and_ceilings() -> Result<(), QmpError> {
        let final_identity = identity(30);
        let request = QmpCheckpointRestoreRequest::new(
            vec![QmpCheckpointRestoreLayer::new(
                QmpDescriptorName::new("direct")?,
                identity(31).checkpoint(),
                4096,
            )?],
            QmpDescriptorName::new("device")?,
            identity(32).checkpoint(),
            QmpDescriptorName::new("cancel")?,
            final_identity,
            8192,
        )?;
        let response = json!({
            "schema-version": 2,
            "checkpoint-sha256": final_identity.checkpoint().to_hex(),
            "target-sha256": final_identity.target().to_hex(),
            "frontier-sha256": final_identity.frontier().to_hex(),
            "topology-sha256": "44".repeat(32),
            "ram-layers": 1,
            "ram-bytes": 3072,
            "device-bytes": 4096,
        });

        let restore = parse_checkpoint_restore(&response, &request)?;
        assert_eq!(restore.identity, final_identity);
        assert_eq!(restore.ram_layers, 1);
        assert_eq!(restore.ram_bytes, 3072);
        assert_eq!(restore.device_bytes, 4096);
        Ok(())
    }

    #[test]
    fn restore_rejects_aliased_descriptor_names() -> Result<(), QmpError> {
        let shared = QmpDescriptorName::new("shared")?;
        let layer =
            QmpCheckpointRestoreLayer::new(shared.clone(), identity(40).checkpoint(), 4096)?;

        assert!(
            QmpCheckpointRestoreRequest::new(
                vec![layer],
                shared,
                identity(41).checkpoint(),
                QmpDescriptorName::new("cancel")?,
                identity(42),
                8192,
            )
            .is_err()
        );
        Ok(())
    }
}
