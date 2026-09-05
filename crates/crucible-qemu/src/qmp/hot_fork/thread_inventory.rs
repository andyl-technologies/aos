//! Bounded QEMU thread inventory decoding and fork-disposition evidence.
//!
//! Completeness requires an exact coordinator and valid registry metadata;
//! it does not substitute for the independent child-disposition barriers.
//!
//! ```text
//! {"schema-version":4,"generation":1,"complete":false,"overflowed":false,
//!  "unclassified-threads":0,"threads":[]}
//! ```

use super::*;

/// QEMU-owned fork disposition for one internally registered thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpHotForkThreadDisposition {
    /// QMP main-loop authority for a future fork transaction.
    Coordinator,
    /// Active QEMU-created thread without a child disposition.
    Unclassified,
    /// RCU callback worker discarded in the child and restarted after reconstruction.
    RcuRestart,
    /// Internal QMP IOThread discarded and restarted while replacement input is held.
    MonitorRestart,
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

    #[cfg(test)]
    pub(crate) fn incomplete() -> Self {
        Self {
            generation: 1,
            complete: false,
            overflowed: true,
            unclassified_threads: 0,
            threads: Vec::new(),
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

pub(in crate::qmp) fn parse_hot_fork_thread_inventory(
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
            Some("rcu-restart") => QmpHotForkThreadDisposition::RcuRestart,
            Some("monitor-restart") => QmpHotForkThreadDisposition::MonitorRestart,
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
