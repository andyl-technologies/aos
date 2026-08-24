//! Preallocated lifecycle publication ownership and canonical field storage.

use super::*;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

pub(in crate::vm_lifecycle::quantum_loop) struct PreparedTerminalReplacement {
    pub(in crate::vm_lifecycle::quantum_loop) decision: QemuNodeLifecycleDecision,
    pub(in crate::vm_lifecycle::quantum_loop) snapshot: QemuVmSnapshot,
    pub(in crate::vm_lifecycle::quantum_loop) run_directory: PathBuf,
    pub(in crate::vm_lifecycle::quantum_loop) launch: ProductionLiveNodeStepGateConfig,
    pub(in crate::vm_lifecycle::quantum_loop) generation: u64,
    pub(in crate::vm_lifecycle::quantum_loop) replacement: Option<QemuNode>,
    pub(in crate::vm_lifecycle::quantum_loop) service_state: ProductionNodeServiceState,
    pub(in crate::vm_lifecycle::quantum_loop) debug_backend_path: Option<PathBuf>,
    pub(in crate::vm_lifecycle::quantum_loop) crash_detector: String,
    pub(in crate::vm_lifecycle::quantum_loop) process_owner: Option<PreparedLifecycleProcessOwner>,
}

pub(in crate::vm_lifecycle::quantum_loop) struct PreparedLifecycleProcessOwner {
    pub(in crate::vm_lifecycle::quantum_loop) action: ContentHash,
    pub(in crate::vm_lifecycle::quantum_loop) decision_node: Option<NodeId>,
    pub(in crate::vm_lifecycle::quantum_loop) manifest_node: String,
    pub(in crate::vm_lifecycle::quantum_loop) manifest_identity: QemuProcessIdentity,
    pub(in crate::vm_lifecycle::quantum_loop) journal_identity: QemuProcessIdentity,
}

pub(in crate::vm_lifecycle::quantum_loop) struct PreparedLifecycleTerminal {
    pub(in crate::vm_lifecycle::quantum_loop) decision: QemuNodeLifecycleDecision,
    pub(in crate::vm_lifecycle::quantum_loop) process_owner: PreparedLifecycleProcessOwner,
}

pub(in crate::vm_lifecycle::quantum_loop) struct PreparedLifecyclePrecommit {
    pub(in crate::vm_lifecycle::quantum_loop) checkpoint: Arc<Checkpoint>,
    pub(in crate::vm_lifecycle::quantum_loop) actions: Vec<ContentHash>,
    pub(in crate::vm_lifecycle::quantum_loop) process_owners:
        Vec<Option<PreparedLifecycleProcessOwner>>,
    pub(in crate::vm_lifecycle::quantum_loop) terminal_decisions: Vec<PreparedLifecycleTerminal>,
    pub(in crate::vm_lifecycle::quantum_loop) reserved_event_records: u64,
    pub(in crate::vm_lifecycle::quantum_loop) reserved_event_log_bytes: u64,
}

pub(in crate::vm_lifecycle::quantum_loop) fn lifecycle_resource_error(
    field: &'static str,
    current: usize,
    requested: usize,
    limits: FaultResourceLimits,
) -> SchedulerError {
    SchedulerError::ResourceLimit {
        field,
        current: u64::try_from(current).unwrap_or(u64::MAX),
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: limits.configured(field).unwrap_or(0),
        hard: FaultResourceLimits::compiled_maximum()
            .configured(field)
            .unwrap_or(0),
    }
}

pub(in crate::vm_lifecycle::quantum_loop) fn lifecycle_transition_text(
    transition: crucible::model::NodeLifecycleTransition,
) -> &'static str {
    match transition {
        crucible::model::NodeLifecycleTransition::Boot => "Boot",
        crucible::model::NodeLifecycleTransition::Crash => "Crash",
        crucible::model::NodeLifecycleTransition::Reset => "Reset",
        crucible::model::NodeLifecycleTransition::PowerOff => "PowerOff",
        crucible::model::NodeLifecycleTransition::PowerCycle => "PowerCycle",
        crucible::model::NodeLifecycleTransition::PermanentFailure => "PermanentFailure",
    }
}

/// Reports whether an intent can commit a transition that advances generation.
///
/// Boot is included because a bounded ready policy may exhaust into Crash or
/// PowerOff even though the originally requested transition does not itself
/// advance the generation. Permanent failure is the only transition that can
/// never retain a successor process generation.
pub(in crate::vm_lifecycle::quantum_loop) fn lifecycle_intent_may_require_successor_generation(
    transition: crucible::model::NodeLifecycleTransition,
) -> bool {
    transition != crucible::model::NodeLifecycleTransition::PermanentFailure
}

pub(in crate::vm_lifecycle::quantum_loop) fn try_lifecycle_string(
    value: &str,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<String, SchedulerError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| lifecycle_resource_error("nodes", current, 1, limits))?;
    owned.push_str(value);
    Ok(owned)
}

pub(in crate::vm_lifecycle::quantum_loop) fn try_lifecycle_path(
    value: &Path,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<PathBuf, SchedulerError> {
    let bytes = value.as_os_str().as_bytes();
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| lifecycle_resource_error("event_log_bytes", current, bytes.len(), limits))?;
    owned.extend_from_slice(bytes);
    Ok(PathBuf::from(OsString::from_vec(owned)))
}

pub(in crate::vm_lifecycle::quantum_loop) fn try_lifecycle_hash(
    value: ContentHash,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<String, SchedulerError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::new();
    encoded
        .try_reserve_exact(64)
        .map_err(|_| lifecycle_resource_error("event_log_bytes", current, 64, limits))?;
    for byte in value.bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

pub(in crate::vm_lifecycle::quantum_loop) fn try_lifecycle_transition(
    transition: crucible::model::NodeLifecycleTransition,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<String, SchedulerError> {
    let mut storage = try_lifecycle_string("PermanentFailure", current, limits)?;
    storage.clear();
    storage.push_str(lifecycle_transition_text(transition));
    Ok(storage)
}

pub(in crate::vm_lifecycle::quantum_loop) fn replace_lifecycle_hash(
    storage: &mut String,
    value: ContentHash,
) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    debug_assert!(storage.capacity() >= 64);
    storage.clear();
    for byte in value.bytes {
        storage.push(HEX[(byte >> 4) as usize] as char);
        storage.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

pub(in crate::vm_lifecycle::quantum_loop) fn lifecycle_hash_matches(
    storage: &str,
    value: ContentHash,
) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    storage.len() == 64
        && storage
            .as_bytes()
            .chunks_exact(2)
            .zip(value.bytes)
            .all(|(encoded, byte)| {
                encoded[0] == HEX[(byte >> 4) as usize] && encoded[1] == HEX[(byte & 0x0f) as usize]
            })
}

pub(in crate::vm_lifecycle::quantum_loop) fn try_lifecycle_crash_detector(
    node: &str,
    generation: u64,
    current: usize,
    limits: FaultResourceLimits,
) -> Result<String, SchedulerError> {
    let mut digits = [0_u8; 20];
    let mut cursor = digits.len();
    let mut remaining = generation;
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    let required = 10_usize
        .checked_add(node.len())
        .and_then(|length| length.checked_add(12))
        .and_then(|length| length.checked_add(digits.len() - cursor))
        .ok_or_else(|| lifecycle_resource_error("event_log_bytes", current, usize::MAX, limits))?;
    let mut detector = String::new();
    detector
        .try_reserve_exact(required)
        .map_err(|_| lifecycle_resource_error("event_log_bytes", current, required, limits))?;
    detector.push_str("lifecycle-");
    detector.push_str(node);
    detector.push_str("-generation-");
    for digit in &digits[cursor..] {
        detector.push(*digit as char);
    }
    Ok(detector)
}

#[cfg(test)]
mod tests {
    use super::lifecycle_intent_may_require_successor_generation;
    use crucible::model::NodeLifecycleTransition;

    #[test]
    fn terminal_precommit_reserves_effective_successor_generation() {
        for transition in [
            NodeLifecycleTransition::Boot,
            NodeLifecycleTransition::Crash,
            NodeLifecycleTransition::Reset,
            NodeLifecycleTransition::PowerOff,
            NodeLifecycleTransition::PowerCycle,
        ] {
            assert!(lifecycle_intent_may_require_successor_generation(
                transition
            ));
        }
        assert!(!lifecycle_intent_may_require_successor_generation(
            NodeLifecycleTransition::PermanentFailure
        ));
    }
}
