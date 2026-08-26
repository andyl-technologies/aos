//! Versioned QEMU-owned hot-fork readiness proofs.
//!
//! The report is deliberately observational: it authenticates which
//! quiescence classes patched QEMU can prove at the current boundary, but it
//! does not prepare or fork a template. Unknown proof contracts fail closed.

use serde_json::Value;

use super::{QmpCommandKind, QmpError};

/// QMP command name used for the versioned QEMU-owned hot-fork readiness report.
pub const QMP_QUERY_HOT_FORK_READINESS_COMMAND: &str = "query-crucible-hot-fork-readiness";

/// Version of the QEMU-owned hot-fork proof-bit contract.
pub const QMP_HOT_FORK_READINESS_SCHEMA_VERSION: u32 = 1;

/// Complete proof bitmap required by the version-1 hot-fork contract.
pub const QMP_HOT_FORK_REQUIRED_PROOFS: u64 = (1_u64 << 9) - 1;

/// One independently acknowledged hot-fork readiness proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QmpHotForkProof {
    /// Precise instruction counting is active.
    PreciseIcount = 0,
    /// The deterministic sim accelerator uses one round-robin TCG thread.
    SingleThreadedSimRoundRobin = 1,
    /// QEMU stopped at an exact boundary and completed device flushes.
    ExactPausedBoundary = 2,
    /// AIO contexts, bottom halves, and timers are drained or parked.
    AioBottomHalvesAndTimers = 3,
    /// Every relevant RCU callback and read-side section is quiescent.
    Rcu = 4,
    /// Every writable block root is at an immutable external-snapshot boundary.
    BlockSnapshot = 5,
    /// Plugin command, event, and shared-memory rings are frozen.
    PluginRings = 6,
    /// Every mapping and descriptor has a closed child disposition.
    MappingAndDescriptors = 7,
    /// Every omitted thread and process-private resource has a child reinitializer.
    ChildReinitialization = 8,
}

impl QmpHotForkProof {
    const ALL: [Self; 9] = [
        Self::PreciseIcount,
        Self::SingleThreadedSimRoundRobin,
        Self::ExactPausedBoundary,
        Self::AioBottomHalvesAndTimers,
        Self::Rcu,
        Self::BlockSnapshot,
        Self::PluginRings,
        Self::MappingAndDescriptors,
        Self::ChildReinitialization,
    ];

    const fn mask(self) -> u64 {
        1_u64 << self as u8
    }
}

/// Exact typed hot-fork readiness report returned by patched QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkReadiness {
    acknowledged_proofs: u64,
    ready: bool,
}

impl QmpHotForkReadiness {
    /// Builds one valid version-1 report from its exact acknowledged bitmap.
    ///
    /// The `ready` value is derived rather than supplied, so callers cannot
    /// construct a contradictory typed report.
    #[must_use]
    pub const fn from_acknowledged_proofs(acknowledged_proofs: u64) -> Option<Self> {
        if acknowledged_proofs & !QMP_HOT_FORK_REQUIRED_PROOFS != 0 {
            return None;
        }
        Some(Self {
            acknowledged_proofs,
            ready: acknowledged_proofs == QMP_HOT_FORK_REQUIRED_PROOFS,
        })
    }

    /// Returns whether QEMU attested every required version-1 proof.
    #[must_use]
    pub const fn ready(self) -> bool {
        self.ready
    }

    /// Returns the exact acknowledged version-1 proof bitmap.
    #[must_use]
    pub const fn acknowledged_proofs(self) -> u64 {
        self.acknowledged_proofs
    }

    /// Returns whether QEMU attested one exact proof class.
    #[must_use]
    pub const fn acknowledges(self, proof: QmpHotForkProof) -> bool {
        self.acknowledged_proofs & proof.mask() != 0
    }

    /// Iterates over proof classes that QEMU did not acknowledge.
    pub fn missing_proofs(self) -> impl Iterator<Item = QmpHotForkProof> {
        QmpHotForkProof::ALL
            .into_iter()
            .filter(move |proof| !self.acknowledges(*proof))
    }
}

pub(super) fn parse_hot_fork_readiness(value: &Value) -> Result<QmpHotForkReadiness, QmpError> {
    let schema_version = value.get("schema-version").and_then(Value::as_u64);
    let required_proofs = value.get("required-proofs").and_then(Value::as_u64);
    let acknowledged_proofs = value.get("acknowledged-proofs").and_then(Value::as_u64);
    let ready = value.get("ready").and_then(Value::as_bool);

    match (schema_version, required_proofs, acknowledged_proofs, ready) {
        (Some(schema_version), Some(required_proofs), Some(acknowledged_proofs), Some(ready))
            if schema_version == u64::from(QMP_HOT_FORK_READINESS_SCHEMA_VERSION)
                && required_proofs == QMP_HOT_FORK_REQUIRED_PROOFS
                && acknowledged_proofs & !required_proofs == 0
                && ready == (acknowledged_proofs == required_proofs) =>
        {
            QmpHotForkReadiness::from_acknowledged_proofs(acknowledged_proofs).ok_or_else(|| {
                QmpError::MalformedTypedResponse {
                    command: QmpCommandKind::QueryHotForkReadiness,
                    response: value.to_string(),
                }
            })
        }
        _ => Err(QmpError::MalformedTypedResponse {
            command: QmpCommandKind::QueryHotForkReadiness,
            response: value.to_string(),
        }),
    }
}
