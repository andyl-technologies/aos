//! Bounded lifecycle ownership-state encoding and atomic publication.
//!
//! One file owns the process manifest and lifecycle journal together so a
//! rename cannot publish half of an ownership transition:
//!
//! ```text
//! {"version":1,"runtime_event_records":0,"runtime_event_log_bytes":0,"manifest":{...},"journal":{...}}
//! ```

use super::*;
use crucible::model::FaultResourceLimitError;

mod recovery;
#[cfg(test)]
pub(in crate::vm_lifecycle) use recovery::validate_recovered_lifecycle_journal;
pub(in crate::vm_lifecycle) use recovery::{decode_prior_run_state, decode_run_json_bounded};

const HARD_RUN_STATE_JSON_BYTES: u64 = 67_108_864;
const PRODUCTION_RUN_STATE_VERSION: u32 = 1;
pub(in crate::vm_lifecycle) const PRODUCTION_RUN_STATE_FILE: &str = "run-state.json";

#[derive(serde::Serialize)]
struct ProductionRunStateRef<'a> {
    version: u32,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
    manifest: &'a ProductionRunManifest,
    journal: &'a ProductionLifecycleJournal,
}

pub(in crate::vm_lifecycle) fn persist_run_state_atomic(
    path: &Path,
    manifest: &ProductionRunManifest,
    journal: &ProductionLifecycleJournal,
    limits: FaultResourceLimits,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
) -> Result<usize, String> {
    for (role, count) in [
        ("current process", manifest.processes.len()),
        ("staged process", manifest.staged_processes.len()),
        ("lifecycle node", journal.nodes.len()),
    ] {
        limits
            .reserve("nodes", 0, u64::try_from(count).unwrap_or(u64::MAX))
            .map_err(|error| format!("admit durable {role} count: {error}"))?;
    }
    let lifecycle_records = journal
        .nodes
        .len()
        .checked_add(journal.completed_exits.len())
        .ok_or_else(|| String::from("durable lifecycle record count overflow"))?;
    limits
        .reserve(
            "event_records",
            runtime_event_records,
            u64::try_from(lifecycle_records).unwrap_or(u64::MAX),
        )
        .map_err(|error| format!("admit durable lifecycle record count: {error}"))?;
    let state = ProductionRunStateRef {
        version: PRODUCTION_RUN_STATE_VERSION,
        runtime_event_records,
        runtime_event_log_bytes,
        manifest,
        journal,
    };
    let mut counter = CountingJournalWriter::default();
    serde_json::to_writer_pretty(&mut counter, &state)
        .map_err(|error| format!("measure durable lifecycle state: {error}"))?;
    limits
        .reserve(
            "event_log_bytes",
            runtime_event_log_bytes,
            u64::try_from(counter.length).unwrap_or(u64::MAX),
        )
        .map_err(|error| format!("admit durable lifecycle state: {error}"))?;
    let mut encoding = Vec::new();
    encoding
        .try_reserve_exact(counter.length)
        .map_err(|_| format!("reserve {} durable state bytes", counter.length))?;
    serde_json::to_writer_pretty(
        FixedJournalWriter {
            destination: &mut encoding,
        },
        &state,
    )
    .map_err(|error| format!("encode durable lifecycle state: {error}"))?;
    let next = path.with_extension("next");
    let mut file = File::create(&next)
        .map_err(|error| format!("create durable state {}: {error}", next.display()))?;
    file.write_all(&encoding)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("flush durable state {}: {error}", next.display()))?;
    fs::rename(&next, path)
        .map_err(|error| format!("commit durable state {}: {error}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("durable state path {} has no parent", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("flush durable state directory: {error}"))?;
    Ok(encoding.capacity())
}

pub(in crate::vm_lifecycle) fn map_journal_limit(
    error: FaultResourceLimitError,
    limits: FaultResourceLimits,
) -> SchedulerError {
    match error {
        FaultResourceLimitError::Exceeded {
            field,
            current,
            requested,
            configured,
            hard,
        }
        | FaultResourceLimitError::UsageOverflow {
            field,
            current,
            requested,
            configured,
            hard,
        } => SchedulerError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        FaultResourceLimitError::Representation { field, value } => SchedulerError::ResourceLimit {
            field,
            current: 0,
            requested: value,
            configured: limits.configured(field).unwrap_or(0),
            hard: FaultResourceLimits::compiled_maximum()
                .configured(field)
                .unwrap_or(0),
        },
        FaultResourceLimitError::Zero { field } => SchedulerError::ResourceLimit {
            field,
            current: 0,
            requested: 1,
            configured: 0,
            hard: FaultResourceLimits::compiled_maximum()
                .configured(field)
                .unwrap_or(0),
        },
        FaultResourceLimitError::ConfiguredAboveHard {
            field,
            configured,
            hard,
        } => SchedulerError::ResourceLimit {
            field,
            current: 0,
            requested: configured,
            configured,
            hard,
        },
        FaultResourceLimitError::UnknownField { field } => SchedulerError::BoundaryViolation {
            message: format!("unknown lifecycle journal resource field `{field}`"),
        },
    }
}

pub(in crate::vm_lifecycle) struct LifecycleStatePersistence {
    path: PathBuf,
    next: PathBuf,
    encoding: Vec<u8>,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
}

impl LifecycleStatePersistence {
    pub(in crate::vm_lifecycle) fn new(run_directory: &Path) -> Result<Self, String> {
        let path = run_directory.join(PRODUCTION_RUN_STATE_FILE);
        let length = match path.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(format!("inspect {}: {error}", path.display())),
        };
        let capacity = usize::try_from(length)
            .map_err(|_| format!("{} length is not representable", path.display()))?;
        let mut encoding = Vec::new();
        encoding
            .try_reserve_exact(capacity)
            .map_err(|_| format!("reserve {capacity} live durable-state bytes"))?;
        Ok(Self {
            path,
            next: run_directory.join("run-state.next"),
            encoding,
            runtime_event_records: 0,
            runtime_event_log_bytes: 0,
        })
    }
}

struct FixedJournalWriter<'a> {
    destination: &'a mut Vec<u8>,
}

impl std::io::Write for FixedJournalWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let available = self
            .destination
            .capacity()
            .saturating_sub(self.destination.len());
        if bytes.len() > available {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "reserved lifecycle journal encoding is exhausted",
            ));
        }
        self.destination.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct CountingJournalWriter {
    length: usize,
}

impl std::io::Write for CountingJournalWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.length = self.length.checked_add(bytes.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "lifecycle journal encoding length is not representable",
            )
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn ensure_lifecycle_encoding_capacity(
    destination: &mut Vec<u8>,
    required: usize,
) -> Result<(), usize> {
    destination.clear();
    let current = destination.capacity();
    if current >= required {
        return Ok(());
    }
    destination
        .try_reserve_exact(required)
        .map_err(|_| required.saturating_sub(current))
}

impl ProductionVmLifecycleLoop {
    pub(super) fn refresh_lifecycle_state_resource_usage(
        &mut self,
        limits: FaultResourceLimits,
    ) -> Result<(), SchedulerError> {
        let (runtime_event_records, runtime_event_log_bytes) = {
            let runtime =
                self.fault_runtime
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from("production fault runtime lock is poisoned"),
                    })?;
            runtime
                .lifecycle_journal_resource_usage()
                .map_err(|error| match error {
                    crucible_qemu::ProductionFaultRuntimeError::ResourceLimit(error) => {
                        map_journal_limit(error, runtime.resource_limits())
                    }
                    error => SchedulerError::BoundaryViolation {
                        message: format!("measure lifecycle journal resource base: {error}"),
                    },
                })?
        };
        self.reserve_lifecycle_state_encoding(
            limits,
            runtime_event_records,
            runtime_event_log_bytes,
        )
    }

    pub(in crate::vm_lifecycle) fn reserve_lifecycle_state_encoding(
        &mut self,
        limits: FaultResourceLimits,
        runtime_event_records: u64,
        runtime_event_log_bytes: u64,
    ) -> Result<(), SchedulerError> {
        let mut counter = CountingJournalWriter::default();
        let state = ProductionRunStateRef {
            version: PRODUCTION_RUN_STATE_VERSION,
            runtime_event_records,
            runtime_event_log_bytes,
            manifest: &self.run_manifest,
            journal: &self.lifecycle_journal,
        };
        serde_json::to_writer_pretty(&mut counter, &state).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("measure lifecycle transaction journal: {error}"),
            }
        })?;
        let replacement_growth =
            self.lifecycle_journal
                .nodes
                .iter()
                .try_fold(0_usize, |total, node| {
                    let escaped_node = node.node.len().checked_mul(6)?;
                    let path_bytes = node
                        .current_process
                        .executable
                        .as_os_str()
                        .as_encoded_bytes()
                        .len();
                    let escaped_path = path_bytes.checked_mul(6)?;
                    // A staged owner adds another map key and process identity,
                    // while the journal adds the same replacement identity.
                    // Six bytes per input byte is JSON's maximum escaping growth;
                    // 256 covers the fixed field names, numeric values, and the
                    // later completed-exit fields.
                    let identity_growth =
                        escaped_node.checked_add(escaped_path)?.checked_add(256)?;
                    total.checked_add(identity_growth.checked_mul(2)?)
                });
        let required = replacement_growth
            .and_then(|growth| counter.length.checked_add(growth))
            .ok_or_else(|| lifecycle_resource_error("event_log_bytes", 0, usize::MAX, limits))?;
        limits
            .reserve(
                "event_log_bytes",
                runtime_event_log_bytes,
                u64::try_from(required).unwrap_or(u64::MAX),
            )
            .map_err(|error| map_journal_limit(error, limits))?;
        let current = self.lifecycle_persistence.encoding.capacity();
        ensure_lifecycle_encoding_capacity(&mut self.lifecycle_persistence.encoding, required)
            .map_err(|additional| {
                lifecycle_resource_error("event_log_bytes", current, additional, limits)
            })?;
        self.lifecycle_persistence.runtime_event_records = runtime_event_records;
        self.lifecycle_persistence.runtime_event_log_bytes = runtime_event_log_bytes;
        Ok(())
    }

    pub(in crate::vm_lifecycle) fn persist_lifecycle_state(
        &mut self,
    ) -> Result<(), SchedulerError> {
        let limits = self.source.plan().fault_signals().resource_limits();
        self.refresh_lifecycle_state_resource_usage(limits)?;
        self.lifecycle_persistence.encoding.clear();
        let state = ProductionRunStateRef {
            version: PRODUCTION_RUN_STATE_VERSION,
            runtime_event_records: self.lifecycle_persistence.runtime_event_records,
            runtime_event_log_bytes: self.lifecycle_persistence.runtime_event_log_bytes,
            manifest: &self.run_manifest,
            journal: &self.lifecycle_journal,
        };
        serde_json::to_writer_pretty(
            FixedJournalWriter {
                destination: &mut self.lifecycle_persistence.encoding,
            },
            &state,
        )
        .map_err(|_| {
            lifecycle_resource_error(
                "event_log_bytes",
                self.lifecycle_persistence.encoding.capacity(),
                1,
                limits,
            )
        })?;
        let mut file = File::create(&self.lifecycle_persistence.next).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "create lifecycle transaction journal {}: {error}",
                    self.lifecycle_persistence.next.display()
                ),
            }
        })?;
        file.write_all(&self.lifecycle_persistence.encoding)
            .and_then(|()| file.sync_all())
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "flush lifecycle transaction journal {}: {error}",
                    self.lifecycle_persistence.next.display()
                ),
            })?;
        fs::rename(
            &self.lifecycle_persistence.next,
            &self.lifecycle_persistence.path,
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!(
                "commit lifecycle transaction journal {}: {error}",
                self.lifecycle_persistence.path.display()
            ),
        })?;
        File::open(self._run_directory.path())
            .and_then(|directory| directory.sync_all())
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("flush lifecycle journal directory: {error}"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_journal_writer_uses_only_reserved_storage() {
        let mut destination = Vec::new();
        destination
            .try_reserve_exact(4)
            .unwrap_or_else(|error| panic!("test journal storage should reserve: {error}"));
        let capacity = destination.capacity();
        let mut writer = FixedJournalWriter {
            destination: &mut destination,
        };

        writer
            .write_all(b"four")
            .unwrap_or_else(|error| panic!("exact reserved write should succeed: {error}"));

        assert_eq!(writer.destination.as_slice(), b"four");
        assert_eq!(writer.destination.capacity(), capacity);
    }

    #[test]
    fn fixed_journal_writer_rejects_growth_without_mutation() {
        let mut destination = Vec::new();
        destination
            .try_reserve_exact(3)
            .unwrap_or_else(|error| panic!("test journal storage should reserve: {error}"));
        let capacity = destination.capacity();
        let mut writer = FixedJournalWriter {
            destination: &mut destination,
        };

        let Some(error) = writer.write_all(b"four").err() else {
            panic!("write beyond reserved journal storage must fail");
        };

        assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
        assert!(writer.destination.is_empty());
        assert_eq!(writer.destination.capacity(), capacity);
    }

    #[test]
    fn lifecycle_encoding_reserve_uses_the_measured_total_capacity() {
        let mut destination = Vec::new();
        destination
            .try_reserve_exact(4)
            .unwrap_or_else(|error| panic!("initial test storage should reserve: {error}"));
        destination.extend_from_slice(b"four");

        ensure_lifecycle_encoding_capacity(&mut destination, 8)
            .unwrap_or_else(|additional| panic!("test storage should grow by {additional}"));

        assert!(destination.is_empty());
        assert!(destination.capacity() >= 8);
    }
}
