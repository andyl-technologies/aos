//! Versioned QEMU-owned hot-fork readiness proofs.
//!
//! The report is deliberately observational: it authenticates which
//! quiescence classes patched QEMU can prove at the current boundary, but it
//! does not prepare or fork a template. Unknown proof contracts fail closed.

use serde_json::Value;

use super::{QmpCommandKind, QmpError};

/// QMP command name used for the versioned QEMU-owned hot-fork readiness report.
pub const QMP_QUERY_HOT_FORK_READINESS_COMMAND: &str = "query-crucible-hot-fork-readiness";
/// QMP command name used for QEMU's bounded active-thread inventory.
pub const QMP_QUERY_HOT_FORK_THREAD_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-thread-inventory";

/// Version of the QEMU-owned hot-fork proof-bit contract.
pub const QMP_HOT_FORK_READINESS_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned active-thread inventory contract.
pub const QMP_HOT_FORK_THREAD_INVENTORY_SCHEMA_VERSION: u32 = 2;

/// Complete proof bitmap required by the version-1 hot-fork contract.
pub const QMP_HOT_FORK_REQUIRED_PROOFS: u64 = (1_u64 << 9) - 1;
/// Maximum active QEMU-created threads retained by one inventory response.
pub const QMP_HOT_FORK_THREAD_INVENTORY_MAX: usize = 65_536;
/// Maximum UTF-8 bytes retained for one QEMU thread name.
pub const QMP_HOT_FORK_THREAD_NAME_MAX_BYTES: usize = 256;

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

/// QEMU-owned fork disposition for one internally registered thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpHotForkThreadDisposition {
    /// QMP main-loop authority for a future fork transaction.
    Coordinator,
    /// Active QEMU-created thread without a child disposition.
    Unclassified,
    /// RCU callback worker without an accepted barrier or child reinitializer.
    UnclassifiedRcu,
    /// AIO-context worker without an accepted barrier or child reinitializer.
    UnclassifiedAio,
}

/// One active thread in QEMU's bounded internal fork registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkThread {
    thread_id: u32,
    name: String,
    name_valid: bool,
    joinable: bool,
    disposition: QmpHotForkThreadDisposition,
}

impl QmpHotForkThread {
    /// Returns the positive operating-system thread identifier.
    #[must_use]
    pub const fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Returns the bounded UTF-8 QEMU thread name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the name is the exact nonempty creation-time value.
    #[must_use]
    pub const fn name_valid(&self) -> bool {
        self.name_valid
    }

    /// Returns whether QEMU created the thread as joinable.
    #[must_use]
    pub const fn joinable(&self) -> bool {
        self.joinable
    }

    /// Returns QEMU's current fork disposition for the thread.
    #[must_use]
    pub const fn disposition(&self) -> QmpHotForkThreadDisposition {
        self.disposition
    }
}

/// Exact bounded snapshot of QEMU's internal active-thread registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkThreadInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    unclassified_threads: usize,
    threads: Vec<QmpHotForkThread>,
}

impl QmpHotForkThreadInventory {
    #[cfg(test)]
    pub(crate) fn one_coordinator(thread_id: u32) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            unclassified_threads: 0,
            threads: vec![QmpHotForkThread {
                thread_id,
                name: String::from("qmp-main-loop"),
                name_valid: true,
                joinable: false,
                disposition: QmpHotForkThreadDisposition::Coordinator,
            }],
        }
    }

    /// Returns the process-local register/unregister/disposition generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether the bounded internal registry is structurally complete.
    ///
    /// Completeness does not make the process fork-ready: unclassified and
    /// externally created threads still require explicit dispositions.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether active QEMU-created threads exceeded the registry bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns the exact number of retained threads without dispositions.
    #[must_use]
    pub const fn unclassified_threads(&self) -> usize {
        self.unclassified_threads
    }

    /// Returns every retained active thread in ascending identifier order.
    #[must_use]
    pub fn threads(&self) -> &[QmpHotForkThread] {
        &self.threads
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

pub(super) fn parse_hot_fork_thread_inventory(
    value: &Value,
) -> Result<QmpHotForkThreadInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkThreadInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    if object.len() != 6
        || ![
            "schema-version",
            "generation",
            "complete",
            "overflowed",
            "unclassified-threads",
            "threads",
        ]
        .iter()
        .all(|field| object.contains_key(*field))
    {
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
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_unclassified = object
        .get("unclassified-threads")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let values = object
        .get("threads")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_THREAD_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_THREAD_INVENTORY_MAX
    {
        return Err(malformed());
    }

    let mut threads = Vec::with_capacity(values.len());
    let mut previous_thread_id = None;
    let mut coordinator_count = 0_usize;
    let mut unclassified_threads = 0_usize;
    let mut names_valid = true;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        if entry.len() != 5
            || !["thread-id", "name", "name-valid", "joinable", "disposition"]
                .iter()
                .all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }
        let thread_id = entry
            .get("thread-id")
            .and_then(Value::as_i64)
            .and_then(|thread_id| u32::try_from(thread_id).ok())
            .filter(|thread_id| *thread_id != 0)
            .ok_or_else(&malformed)?;
        if previous_thread_id.is_some_and(|previous| previous >= thread_id) {
            return Err(malformed());
        }
        previous_thread_id = Some(thread_id);
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= QMP_HOT_FORK_THREAD_NAME_MAX_BYTES)
            .ok_or_else(&malformed)?;
        let name_valid = entry
            .get("name-valid")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let joinable = entry
            .get("joinable")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let disposition = match entry.get("disposition").and_then(Value::as_str) {
            Some("coordinator") => {
                coordinator_count += 1;
                QmpHotForkThreadDisposition::Coordinator
            }
            Some("unclassified") => {
                unclassified_threads += 1;
                QmpHotForkThreadDisposition::Unclassified
            }
            Some("unclassified-rcu") => {
                unclassified_threads += 1;
                QmpHotForkThreadDisposition::UnclassifiedRcu
            }
            Some("unclassified-aio") => {
                unclassified_threads += 1;
                QmpHotForkThreadDisposition::UnclassifiedAio
            }
            _ => return Err(malformed()),
        };
        names_valid &= name_valid;
        threads.push(QmpHotForkThread {
            thread_id,
            name: name.to_owned(),
            name_valid,
            joinable,
            disposition,
        });
    }
    if declared_unclassified != unclassified_threads
        || coordinator_count > 1
        || complete != (!overflowed && names_valid && coordinator_count == 1)
    {
        return Err(malformed());
    }
    Ok(QmpHotForkThreadInventory {
        generation,
        complete,
        overflowed,
        unclassified_threads,
        threads,
    })
}
