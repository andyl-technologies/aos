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
/// QMP command name used for QEMU's bounded RCU-state inventory.
pub const QMP_QUERY_HOT_FORK_RCU_INVENTORY_COMMAND: &str = "query-crucible-hot-fork-rcu-inventory";
/// QMP command name used for QEMU's bounded AioContext activity inventory.
pub const QMP_QUERY_HOT_FORK_AIO_INVENTORY_COMMAND: &str = "query-crucible-hot-fork-aio-inventory";
/// QMP command name used for QEMU's bounded mutex ownership inventory.
pub const QMP_QUERY_HOT_FORK_MUTEX_INVENTORY_COMMAND: &str =
    "query-crucible-hot-fork-mutex-inventory";

/// Version of the QEMU-owned hot-fork proof-bit contract.
pub const QMP_HOT_FORK_READINESS_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned active-thread inventory contract.
pub const QMP_HOT_FORK_THREAD_INVENTORY_SCHEMA_VERSION: u32 = 2;
/// Version of the QEMU-owned RCU-state inventory contract.
pub const QMP_HOT_FORK_RCU_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned AioContext activity inventory contract.
pub const QMP_HOT_FORK_AIO_INVENTORY_SCHEMA_VERSION: u32 = 1;
/// Version of the QEMU-owned mutex ownership inventory contract.
pub const QMP_HOT_FORK_MUTEX_INVENTORY_SCHEMA_VERSION: u32 = 1;

/// Complete proof bitmap required by the version-1 hot-fork contract.
pub const QMP_HOT_FORK_REQUIRED_PROOFS: u64 = (1_u64 << 9) - 1;
/// Maximum active QEMU-created threads retained by one inventory response.
pub const QMP_HOT_FORK_THREAD_INVENTORY_MAX: usize = 65_536;
/// Maximum registered RCU readers retained by one inventory response.
pub const QMP_HOT_FORK_RCU_INVENTORY_MAX: usize = 65_536;
/// Maximum registered AioContexts retained by one inventory response.
pub const QMP_HOT_FORK_AIO_INVENTORY_MAX: usize = 65_536;
/// Maximum registered mutexes retained by one inventory response.
pub const QMP_HOT_FORK_MUTEX_INVENTORY_MAX: usize = 65_536;
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

/// One thread registered as a QEMU RCU read-side participant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkRcuReader {
    thread_id: u32,
    active: bool,
}

impl QmpHotForkRcuReader {
    /// Returns the positive operating-system thread identifier.
    #[must_use]
    pub const fn thread_id(self) -> u32 {
        self.thread_id
    }

    /// Returns whether the reader was active at the inventory instant.
    #[must_use]
    pub const fn active(self) -> bool {
        self.active
    }
}

/// Exact bounded observational snapshot of QEMU's RCU state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkRcuInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    active_readers: usize,
    pending_callbacks: u64,
    drain_active: bool,
    readers: Vec<QmpHotForkRcuReader>,
}

impl QmpHotForkRcuInventory {
    #[cfg(test)]
    pub(crate) fn from_reader_ids(thread_ids: &[u32]) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            active_readers: 0,
            pending_callbacks: 0,
            drain_active: false,
            readers: thread_ids
                .iter()
                .copied()
                .map(|thread_id| QmpHotForkRcuReader {
                    thread_id,
                    active: false,
                })
                .collect(),
        }
    }

    /// Returns the process-local reader register/unregister generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether QEMU retained structurally valid identifiers for every reader.
    ///
    /// Completeness does not prove quiescence and cannot authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether registered readers exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns the exact number of retained active read-side participants.
    #[must_use]
    pub const fn active_readers(&self) -> usize {
        self.active_readers
    }

    /// Returns callbacks submitted but not yet completed.
    #[must_use]
    pub const fn pending_callbacks(&self) -> u64 {
        self.pending_callbacks
    }

    /// Returns whether `drain_call_rcu()` was active at the inventory instant.
    #[must_use]
    pub const fn drain_active(&self) -> bool {
        self.drain_active
    }

    /// Returns every retained reader in ascending thread-identifier order.
    #[must_use]
    pub fn readers(&self) -> &[QmpHotForkRcuReader] {
        &self.readers
    }
}

/// One registered QEMU AioContext and its instantaneous activity counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkAioContext {
    context_id: u64,
    home_thread_id: Option<u32>,
    active_polls: u32,
    active_dispatches: u32,
    pending_bottom_halves: u32,
    active_bottom_halves: u32,
    queued_coroutines: u32,
    notify_pending: bool,
}

impl QmpHotForkAioContext {
    /// Returns the positive process-local AioContext identifier.
    #[must_use]
    pub const fn context_id(self) -> u64 {
        self.context_id
    }

    /// Returns the assigned operating-system home thread, if it has run.
    #[must_use]
    pub const fn home_thread_id(self) -> Option<u32> {
        self.home_thread_id
    }

    /// Returns the number of active `aio_poll()` calls.
    #[must_use]
    pub const fn active_polls(self) -> u32 {
        self.active_polls
    }

    /// Returns the number of active GLib AIO dispatch calls.
    #[must_use]
    pub const fn active_dispatches(self) -> u32 {
        self.active_dispatches
    }

    /// Returns enqueued bottom halves not yet dequeued.
    #[must_use]
    pub const fn pending_bottom_halves(self) -> u32 {
        self.pending_bottom_halves
    }

    /// Returns bottom-half callbacks currently executing.
    #[must_use]
    pub const fn active_bottom_halves(self) -> u32 {
        self.active_bottom_halves
    }

    /// Returns coroutines queued through this context's scheduling bottom half.
    #[must_use]
    pub const fn queued_coroutines(self) -> u32 {
        self.queued_coroutines
    }

    /// Returns whether this context has an unaccepted notification.
    #[must_use]
    pub const fn notify_pending(self) -> bool {
        self.notify_pending
    }
}

/// Exact bounded observational snapshot of QEMU's registered AioContexts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkAioInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    contexts: Vec<QmpHotForkAioContext>,
}

impl QmpHotForkAioInventory {
    #[cfg(test)]
    pub(crate) fn one_idle(context_id: u64, home_thread_id: u32) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            contexts: vec![QmpHotForkAioContext {
                context_id,
                home_thread_id: Some(home_thread_id),
                active_polls: 0,
                active_dispatches: 0,
                pending_bottom_halves: 0,
                active_bottom_halves: 0,
                queued_coroutines: 0,
                notify_pending: false,
            }],
        }
    }

    /// Returns the process-local context lifecycle and home-assignment generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether every retained context has a valid assigned home thread.
    ///
    /// Completeness is observational and does not prove that AIO, bottom
    /// halves, handlers, or timers are drained or authorize a fork.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether registered contexts exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns every retained context in ascending process-local identifier order.
    #[must_use]
    pub fn contexts(&self) -> &[QmpHotForkAioContext] {
        &self.contexts
    }
}

/// One live QEMU mutex and its instantaneous ownership state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkMutex {
    mutex_id: u64,
    owner_thread_id: Option<u32>,
    recursion_depth: u32,
    acquisition_waiters: u32,
    condition_waiters: u32,
    recursive: bool,
    unlock_active: bool,
    ownership_valid: bool,
}

impl QmpHotForkMutex {
    /// Returns the positive process-local mutex identifier.
    #[must_use]
    pub const fn mutex_id(self) -> u64 {
        self.mutex_id
    }

    /// Returns the operating-system owner thread, if held.
    #[must_use]
    pub const fn owner_thread_id(self) -> Option<u32> {
        self.owner_thread_id
    }

    /// Returns the current recursive ownership depth.
    #[must_use]
    pub const fn recursion_depth(self) -> u32 {
        self.recursion_depth
    }

    /// Returns threads currently inside lock acquisition.
    #[must_use]
    pub const fn acquisition_waiters(self) -> u32 {
        self.acquisition_waiters
    }

    /// Returns threads sleeping or reacquiring through a condition wait.
    #[must_use]
    pub const fn condition_waiters(self) -> u32 {
        self.condition_waiters
    }

    /// Returns whether this record describes a recursive mutex.
    #[must_use]
    pub const fn recursive(self) -> bool {
        self.recursive
    }

    /// Returns whether an owner is inside the unlock transition.
    #[must_use]
    pub const fn unlock_active(self) -> bool {
        self.unlock_active
    }

    /// Returns whether every observed ownership transition was valid.
    #[must_use]
    pub const fn ownership_valid(self) -> bool {
        self.ownership_valid
    }
}

/// Exact bounded observational snapshot of QEMU mutex ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkMutexInventory {
    generation: u64,
    complete: bool,
    overflowed: bool,
    mutexes: Vec<QmpHotForkMutex>,
}

impl QmpHotForkMutexInventory {
    #[cfg(test)]
    pub(crate) fn one_owned(mutex_id: u64, owner_thread_id: u32) -> Self {
        Self {
            generation: 1,
            complete: true,
            overflowed: false,
            mutexes: vec![QmpHotForkMutex {
                mutex_id,
                owner_thread_id: Some(owner_thread_id),
                recursion_depth: 1,
                acquisition_waiters: 0,
                condition_waiters: 0,
                recursive: false,
                unlock_active: false,
                ownership_valid: true,
            }],
        }
    }

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: true,
            mutexes: Vec::new(),
        }
    }

    /// Returns the process-local mutex lifecycle generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether the bounded registry and ownership records are valid.
    ///
    /// Completeness is observational and does not prove that omitted threads
    /// hold no locks across a later fork operation.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether live mutexes exceeded the inventory bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns every retained mutex in ascending process-local identifier order.
    #[must_use]
    pub fn mutexes(&self) -> &[QmpHotForkMutex] {
        &self.mutexes
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

pub(super) fn parse_hot_fork_rcu_inventory(
    value: &Value,
) -> Result<QmpHotForkRcuInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkRcuInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    if object.len() != 9
        || ![
            "schema-version",
            "generation",
            "complete",
            "overflowed",
            "registered-readers",
            "active-readers",
            "pending-callbacks",
            "drain-active",
            "readers",
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
    let registered_readers = object
        .get("registered-readers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_active_readers = object
        .get("active-readers")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let pending_callbacks = object
        .get("pending-callbacks")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let drain_active = object
        .get("drain-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let values = object
        .get("readers")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_RCU_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_RCU_INVENTORY_MAX
        || registered_readers != values.len()
    {
        return Err(malformed());
    }

    let mut readers = Vec::with_capacity(values.len());
    let mut previous_thread_id = None;
    let mut active_readers = 0_usize;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        if entry.len() != 2
            || !["thread-id", "active"]
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
        let active = entry
            .get("active")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        active_readers += usize::from(active);
        readers.push(QmpHotForkRcuReader { thread_id, active });
    }
    if declared_active_readers != active_readers || complete == overflowed {
        return Err(malformed());
    }
    Ok(QmpHotForkRcuInventory {
        generation,
        complete,
        overflowed,
        active_readers,
        pending_callbacks,
        drain_active,
        readers,
    })
}

pub(super) fn parse_hot_fork_aio_inventory(
    value: &Value,
) -> Result<QmpHotForkAioInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkAioInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "context-count",
        "assigned-contexts",
        "active-polls",
        "active-dispatches",
        "pending-bottom-halves",
        "active-bottom-halves",
        "queued-coroutines",
        "contexts",
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
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_contexts = object
        .get("context-count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_assigned = object
        .get("assigned-contexts")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let aggregate_fields = [
        "active-polls",
        "active-dispatches",
        "pending-bottom-halves",
        "active-bottom-halves",
        "queued-coroutines",
    ];
    let mut declared_aggregates = [0_u64; 5];
    for (index, field) in aggregate_fields.iter().enumerate() {
        declared_aggregates[index] = object
            .get(*field)
            .and_then(Value::as_u64)
            .ok_or_else(&malformed)?;
    }
    let values = object
        .get("contexts")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_AIO_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_AIO_INVENTORY_MAX
        || declared_contexts != values.len()
    {
        return Err(malformed());
    }

    let mut contexts = Vec::with_capacity(values.len());
    let mut previous_context_id = None;
    let mut assigned_contexts = 0_usize;
    let mut actual_aggregates = [0_u64; 5];
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        let entry_fields = [
            "context-id",
            "home-thread-id",
            "active-polls",
            "active-dispatches",
            "pending-bottom-halves",
            "active-bottom-halves",
            "queued-coroutines",
            "notify-pending",
        ];
        if entry.len() != entry_fields.len()
            || !entry_fields.iter().all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }
        let context_id = entry
            .get("context-id")
            .and_then(Value::as_u64)
            .filter(|context_id| *context_id != 0)
            .ok_or_else(&malformed)?;
        if previous_context_id.is_some_and(|previous| previous >= context_id) {
            return Err(malformed());
        }
        previous_context_id = Some(context_id);
        let home_thread_id = match entry.get("home-thread-id").and_then(Value::as_i64) {
            Some(0) => None,
            Some(thread_id) => Some(
                u32::try_from(thread_id)
                    .ok()
                    .filter(|thread_id| *thread_id != 0)
                    .ok_or_else(&malformed)?,
            ),
            None => return Err(malformed()),
        };
        assigned_contexts += usize::from(home_thread_id.is_some());
        let mut counters = [0_u32; 5];
        for (index, field) in aggregate_fields.iter().enumerate() {
            counters[index] = entry
                .get(*field)
                .and_then(Value::as_u64)
                .and_then(|count| u32::try_from(count).ok())
                .ok_or_else(&malformed)?;
            actual_aggregates[index] = actual_aggregates[index]
                .checked_add(u64::from(counters[index]))
                .ok_or_else(&malformed)?;
        }
        let notify_pending = entry
            .get("notify-pending")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        contexts.push(QmpHotForkAioContext {
            context_id,
            home_thread_id,
            active_polls: counters[0],
            active_dispatches: counters[1],
            pending_bottom_halves: counters[2],
            active_bottom_halves: counters[3],
            queued_coroutines: counters[4],
            notify_pending,
        });
    }
    if declared_assigned != assigned_contexts
        || declared_aggregates != actual_aggregates
        || complete != (!overflowed && assigned_contexts == contexts.len())
    {
        return Err(malformed());
    }
    Ok(QmpHotForkAioInventory {
        generation,
        complete,
        overflowed,
        contexts,
    })
}

pub(super) fn parse_hot_fork_mutex_inventory(
    value: &Value,
) -> Result<QmpHotForkMutexInventory, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::QueryHotForkMutexInventory,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "complete",
        "overflowed",
        "mutex-count",
        "recursive-mutexes",
        "owned-mutexes",
        "acquisition-waiters",
        "condition-waiters",
        "unlock-transitions",
        "invalid-mutexes",
        "mutexes",
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
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let overflowed = object
        .get("overflowed")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let declared_mutexes = object
        .get("mutex-count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_recursive = object
        .get("recursive-mutexes")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_owned = object
        .get("owned-mutexes")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_acquisition_waiters = object
        .get("acquisition-waiters")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let declared_condition_waiters = object
        .get("condition-waiters")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let declared_unlocks = object
        .get("unlock-transitions")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let declared_invalid = object
        .get("invalid-mutexes")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(&malformed)?;
    let values = object
        .get("mutexes")
        .and_then(Value::as_array)
        .ok_or_else(&malformed)?;
    if schema_version != u64::from(QMP_HOT_FORK_MUTEX_INVENTORY_SCHEMA_VERSION)
        || values.len() > QMP_HOT_FORK_MUTEX_INVENTORY_MAX
        || declared_mutexes != values.len()
    {
        return Err(malformed());
    }

    let mut mutexes = Vec::with_capacity(values.len());
    let mut previous_mutex_id = None;
    let mut recursive_mutexes = 0_usize;
    let mut owned_mutexes = 0_usize;
    let mut acquisition_waiters = 0_u64;
    let mut condition_waiters = 0_u64;
    let mut unlock_transitions = 0_usize;
    let mut invalid_mutexes = 0_usize;
    for value in values {
        let entry = value.as_object().ok_or_else(&malformed)?;
        let entry_fields = [
            "mutex-id",
            "owner-thread-id",
            "recursion-depth",
            "acquisition-waiters",
            "condition-waiters",
            "recursive",
            "unlock-active",
            "ownership-valid",
        ];
        if entry.len() != entry_fields.len()
            || !entry_fields.iter().all(|field| entry.contains_key(*field))
        {
            return Err(malformed());
        }

        let mutex_id = entry
            .get("mutex-id")
            .and_then(Value::as_u64)
            .filter(|mutex_id| *mutex_id != 0)
            .ok_or_else(&malformed)?;
        if previous_mutex_id.is_some_and(|previous| previous >= mutex_id) {
            return Err(malformed());
        }
        previous_mutex_id = Some(mutex_id);
        let owner_thread_id = match entry.get("owner-thread-id").and_then(Value::as_i64) {
            Some(0) => None,
            Some(thread_id) => Some(
                u32::try_from(thread_id)
                    .ok()
                    .filter(|thread_id| *thread_id != 0)
                    .ok_or_else(&malformed)?,
            ),
            None => return Err(malformed()),
        };
        let recursion_depth = entry
            .get("recursion-depth")
            .and_then(Value::as_u64)
            .and_then(|depth| u32::try_from(depth).ok())
            .ok_or_else(&malformed)?;
        let entry_acquisition_waiters = entry
            .get("acquisition-waiters")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(&malformed)?;
        let entry_condition_waiters = entry
            .get("condition-waiters")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(&malformed)?;
        let recursive = entry
            .get("recursive")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let unlock_active = entry
            .get("unlock-active")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        let ownership_valid = entry
            .get("ownership-valid")
            .and_then(Value::as_bool)
            .ok_or_else(&malformed)?;
        if owner_thread_id.is_some() != (recursion_depth != 0)
            || (!recursive && recursion_depth > 1)
        {
            return Err(malformed());
        }

        recursive_mutexes += usize::from(recursive);
        owned_mutexes += usize::from(owner_thread_id.is_some());
        acquisition_waiters = acquisition_waiters
            .checked_add(u64::from(entry_acquisition_waiters))
            .ok_or_else(&malformed)?;
        condition_waiters = condition_waiters
            .checked_add(u64::from(entry_condition_waiters))
            .ok_or_else(&malformed)?;
        unlock_transitions += usize::from(unlock_active);
        invalid_mutexes += usize::from(!ownership_valid);
        mutexes.push(QmpHotForkMutex {
            mutex_id,
            owner_thread_id,
            recursion_depth,
            acquisition_waiters: entry_acquisition_waiters,
            condition_waiters: entry_condition_waiters,
            recursive,
            unlock_active,
            ownership_valid,
        });
    }
    if declared_recursive != recursive_mutexes
        || declared_owned != owned_mutexes
        || declared_acquisition_waiters != acquisition_waiters
        || declared_condition_waiters != condition_waiters
        || declared_unlocks != unlock_transitions
        || declared_invalid != invalid_mutexes
        || complete != (!overflowed && invalid_mutexes == 0)
    {
        return Err(malformed());
    }

    Ok(QmpHotForkMutexInventory {
        generation,
        complete,
        overflowed,
        mutexes,
    })
}
