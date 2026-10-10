//! Typed QMP contract for QEMU-owned exact RAM checkpoint epochs.
//!
//! A capture binds checkpoint, target, and scheduler-frontier identities to a
//! frozen page stream and RAM root. QEMU retains the candidate until its exact
//! capture generation is committed or aborted after durable publication.
//!
//! ```text
//! {"execute":"crucible-checkpoint-commit","arguments":{
//!   "checkpoint-sha256":"<64 lowercase hex>",
//!   "target-sha256":"<64 lowercase hex>",
//!   "frontier-sha256":"<64 lowercase hex>","capture-generation":17}}
//! ```

use crucible::ContentHash;
use serde_json::{Map, Value, json};

use super::{QmpCommandKind, QmpDescriptorName, QmpError};

/// Version of the QEMU exact checkpoint capture and epoch contract.
pub(crate) const QMP_CHECKPOINT_SCHEMA_VERSION: u32 = 3;
/// QMP command that captures one coherent paged checkpoint candidate.
pub(crate) const QMP_CHECKPOINT_CAPTURE_COMMAND: &str = "crucible-checkpoint-capture";
/// QMP command that commits one exact checkpoint candidate.
pub(crate) const QMP_CHECKPOINT_COMMIT_COMMAND: &str = "crucible-checkpoint-commit";
/// QMP command that aborts one exact checkpoint candidate.
pub(crate) const QMP_CHECKPOINT_ABORT_COMMAND: &str = "crucible-checkpoint-abort";
/// QMP command that restores one authenticated RAM root and device state.
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

/// Bounded descriptor-backed exact checkpoint capture request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QmpCheckpointCaptureRequest {
    topology_admission_generation: u64,
    initial_required: bool,
    identity: QmpCheckpointIdentity,
    parent: Option<QmpCheckpointIdentity>,
    ram_descriptor: QmpDescriptorName,
    device_descriptor: QmpDescriptorName,
    cancellation_descriptor: QmpDescriptorName,
    maximum_ram_bytes: u64,
    maximum_device_bytes: u64,
}

pub(crate) struct QmpCheckpointCaptureOutputs {
    pub(crate) ram_descriptor: QmpDescriptorName,
    pub(crate) device_descriptor: QmpDescriptorName,
    pub(crate) cancellation_descriptor: QmpDescriptorName,
    pub(crate) maximum_ram_bytes: u64,
    pub(crate) maximum_device_bytes: u64,
}

impl QmpCheckpointCaptureRequest {
    /// Builds one bounded logical-page capture request.
    ///
    /// The committed parent is operational epoch authority. Complete page
    /// selection is independent of that parent, so a restored process can
    /// initialize a new local catalog without forgetting its exact frontier.
    ///
    /// # Errors
    ///
    /// Returns an error for zero output limits or aliased descriptor names.
    pub(crate) fn paged(
        identity: QmpCheckpointIdentity,
        parent: Option<QmpCheckpointIdentity>,
        initial_required: bool,
        outputs: QmpCheckpointCaptureOutputs,
    ) -> Result<Self, QmpError> {
        Self::new(initial_required, identity, parent, outputs)
    }

    fn new(
        initial_required: bool,
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
            topology_admission_generation: 0,
            initial_required,
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

    /// Returns the exact committed parent whose operational epoch is preserved.
    #[must_use]
    pub const fn parent(&self) -> Option<QmpCheckpointIdentity> {
        self.parent
    }

    /// Installs the single-use receipt after authenticated host graph admission.
    pub(crate) fn admit_topology(&mut self, generation: u64) -> Result<(), QmpError> {
        if generation == 0 || self.topology_admission_generation != 0 {
            return Err(QmpError::InvalidBound {
                operation: "admit checkpoint RAM topology once",
            });
        }
        self.topology_admission_generation = generation;
        Ok(())
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
            "initial-required".to_owned(),
            Value::Bool(self.initial_required),
        );
        arguments.insert(
            "topology-admission-generation".to_owned(),
            Value::from(self.topology_admission_generation),
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
    initial_required: bool,
    capture_generation: u64,
    identity: QmpCheckpointIdentity,
    ram_root: ContentHash,
    ram_regions: u64,
    ram_records: u64,
    ram_bytes: u64,
    device_bytes: u64,
}

impl QmpCheckpointCapture {
    #[cfg(test)]
    pub(crate) fn for_test(request: &QmpCheckpointCaptureRequest, topology: ContentHash) -> Self {
        Self {
            initial_required: request.initial_required,
            capture_generation: 1,
            identity: request.identity,
            ram_root: topology,
            ram_regions: 1,
            ram_records: 1,
            ram_bytes: 1,
            device_bytes: 1,
        }
    }

    pub(crate) const fn initial_required(&self) -> bool {
        self.initial_required
    }

    pub(crate) const fn capture_generation(&self) -> u64 {
        self.capture_generation
    }

    /// Returns the exact candidate identity triple.
    #[must_use]
    pub const fn identity(&self) -> QmpCheckpointIdentity {
        self.identity
    }

    /// Returns the canonical QEMU RAMBlock topology identity.
    #[must_use]
    pub const fn ram_root(&self) -> ContentHash {
        self.ram_root
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
    committed_capture_generation: Option<u64>,
    candidate_capture_generation: Option<u64>,
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
            committed_capture_generation: if committed.is_some() {
                Some(epoch_generation)
            } else {
                None
            },
            candidate_capture_generation: if candidate.is_some() {
                Some(epoch_generation + 1)
            } else {
                None
            },
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

    /// Returns the exact acknowledged operational capture generation.
    #[must_use]
    pub const fn committed_capture_generation(self) -> Option<u64> {
        self.committed_capture_generation
    }

    /// Returns the exact active operational capture generation.
    #[must_use]
    pub const fn candidate_capture_generation(self) -> Option<u64> {
        self.candidate_capture_generation
    }
}

pub(super) fn parse_hash(value: Option<&Value>) -> Option<ContentHash> {
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
        "initial-capture",
        "capture-generation",
        "checkpoint-sha256",
        "target-sha256",
        "frontier-sha256",
        "ram-root-blake3",
        "ram-regions",
        "ram-records",
        "ram-bytes",
        "device-bytes",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }
    let capture = QmpCheckpointCapture {
        initial_required: object
            .get("initial-capture")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?,
        capture_generation: object
            .get("capture-generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation != 0)
            .ok_or_else(&malformed)?,
        identity: parse_identity(object, "").ok_or_else(&malformed)?,
        ram_root: parse_hash(object.get("ram-root-blake3")).ok_or_else(&malformed)?,
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
        && capture.initial_required == request.initial_required
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
        "candidate-capture-generation",
        "committed-capture-generation",
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
    let committed_generation = object
        .get("committed-capture-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let candidate_generation = object
        .get("candidate-capture-generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let state = QmpCheckpointEpochState {
        epoch_generation: object
            .get("epoch-generation")
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?,
        committed,
        candidate,
        committed_capture_generation: (committed_generation != 0).then_some(committed_generation),
        candidate_capture_generation: (candidate_generation != 0).then_some(candidate_generation),
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
        && (!epoch_active || state.epoch_generation > 0)
        && epoch_active == state.committed_capture_generation.is_some()
        && candidate_active == state.candidate_capture_generation.is_some();
    if !valid {
        return Err(malformed());
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> QmpCheckpointIdentity {
        QmpCheckpointIdentity::new(
            ContentHash { bytes: [1; 32] },
            ContentHash { bytes: [2; 32] },
            ContentHash { bytes: [3; 32] },
        )
    }

    #[test]
    fn complete_page_selection_retains_expected_parent() -> Result<(), QmpError> {
        let request = QmpCheckpointCaptureRequest::paged(
            identity(),
            Some(identity()),
            true,
            QmpCheckpointCaptureOutputs {
                ram_descriptor: QmpDescriptorName::new("pages")?,
                device_descriptor: QmpDescriptorName::new("device")?,
                cancellation_descriptor: QmpDescriptorName::new("cancel")?,
                maximum_ram_bytes: 8192,
                maximum_device_bytes: 4096,
            },
        )?;
        let wire = request.wire_value();
        assert_eq!(wire["initial-required"], true);
        assert_eq!(
            wire["parent-checkpoint-sha256"],
            identity().checkpoint().to_hex()
        );
        Ok(())
    }

    #[test]
    fn inactive_epoch_cannot_claim_an_acknowledged_capture() {
        let value = json!({"schema-version":3,"epoch-active":false,"epoch-generation":0,
            "candidate-active":false,"candidate-capture-generation":0,"committed-capture-generation":1});
        assert!(
            parse_checkpoint_epoch_state(QmpCommandKind::QueryCheckpointEpoch, &value).is_err()
        );
    }

    #[test]
    fn earlier_epoch_schema_is_rejected() {
        let value = json!({"schema-version":2,"epoch-active":false,"epoch-generation":0,
            "candidate-active":false,"candidate-capture-generation":0,"committed-capture-generation":0});
        assert!(
            parse_checkpoint_epoch_state(QmpCommandKind::QueryCheckpointEpoch, &value).is_err()
        );
    }
}
