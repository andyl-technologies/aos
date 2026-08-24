//! Bounded lifecycle ownership-state encoding and atomic publication.
//!
//! One file owns the process manifest and lifecycle journal together so a
//! rename cannot publish half of an ownership transition:
//!
//! ```text
//! {"version":2,"runtime_event_records":0,"runtime_event_log_bytes":0,"manifest":{...},"journal":{...}}
//! ```

use super::*;
use crucible::model::FaultResourceLimitError;

mod recovery;
#[cfg(test)]
pub(in crate::vm_lifecycle) use recovery::validate_recovered_lifecycle_journal;
pub(in crate::vm_lifecycle) use recovery::{
    DurableRunStateError, decode_prior_run_state, decode_run_json_bounded,
};

pub(in crate::vm_lifecycle) const HARD_RUN_STATE_JSON_BYTES: u64 = 67_108_864;
const PRODUCTION_RUN_STATE_VERSION: u32 = 2;
pub(in crate::vm_lifecycle) const PRODUCTION_RUN_STATE_FILE: &str = "run-state.json";

#[derive(serde::Serialize)]
struct ProductionRunStateRef<'a> {
    version: u32,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
    manifest: &'a ProductionRunManifest,
    journal: &'a ProductionLifecycleJournal,
}

fn borrowed_json_string_is_canonical(value: &str) -> bool {
    !value
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'"' | b'\\' | 0..=0x1f))
}

fn borrowed_process_identity_is_canonical(identity: &QemuProcessIdentity) -> bool {
    identity
        .executable
        .to_str()
        .is_some_and(borrowed_json_string_is_canonical)
}

fn validate_borrowed_run_state_strings(
    manifest: &ProductionRunManifest,
    journal: &ProductionLifecycleJournal,
) -> Result<(), String> {
    let manifest_strings_are_canonical = borrowed_json_string_is_canonical(&manifest.scenario)
        && borrowed_process_identity_is_canonical(&manifest.owner)
        && manifest
            .processes
            .iter()
            .chain(manifest.staged_processes.iter())
            .all(|(node, identity)| {
                borrowed_json_string_is_canonical(node)
                    && borrowed_process_identity_is_canonical(identity)
            });
    let journal_strings_are_canonical = journal.nodes.iter().all(|node| {
        borrowed_json_string_is_canonical(&node.node)
            && borrowed_process_identity_is_canonical(&node.current_process)
            && node
                .replacement_process
                .as_ref()
                .is_none_or(borrowed_process_identity_is_canonical)
            && borrowed_json_string_is_canonical(&node.transition)
            && borrowed_json_string_is_canonical(&node.action_sha256)
            && borrowed_json_string_is_canonical(&node.evidence_sha256)
    }) && journal.completed_exits.iter().all(|exit| {
        borrowed_json_string_is_canonical(&exit.node)
            && borrowed_process_identity_is_canonical(&exit.process)
            && borrowed_json_string_is_canonical(&exit.transition)
            && borrowed_json_string_is_canonical(&exit.action_sha256)
            && borrowed_json_string_is_canonical(&exit.evidence_sha256)
    });
    if manifest_strings_are_canonical && journal_strings_are_canonical {
        Ok(())
    } else {
        Err(String::from(
            "durable lifecycle strings must be UTF-8 JSON strings without escape sequences",
        ))
    }
}

pub(in crate::vm_lifecycle) fn persist_run_state_atomic(
    path: &Path,
    manifest: &ProductionRunManifest,
    journal: &ProductionLifecycleJournal,
    limits: FaultResourceLimits,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
) -> Result<usize, DurableRunStateError> {
    validate_borrowed_run_state_strings(manifest, journal).map_err(DurableRunStateError::from)?;
    for count in [
        manifest.processes.len(),
        manifest.staged_processes.len(),
        journal.nodes.len(),
    ] {
        limits
            .reserve("nodes", 0, u64::try_from(count).unwrap_or(u64::MAX))
            .map_err(recovery::map_limit)?;
    }
    let lifecycle_records = journal
        .nodes
        .len()
        .checked_add(journal.completed_exits.len())
        .ok_or_else(|| DurableRunStateError::Invalid {
            message: String::from("durable lifecycle record count overflow"),
        })?;
    limits
        .reserve(
            "event_records",
            runtime_event_records,
            u64::try_from(lifecycle_records).unwrap_or(u64::MAX),
        )
        .map_err(recovery::map_limit)?;
    let state = ProductionRunStateRef {
        version: PRODUCTION_RUN_STATE_VERSION,
        runtime_event_records,
        runtime_event_log_bytes,
        manifest,
        journal,
    };
    let mut counter = CountingJournalWriter::default();
    serde_json::to_writer_pretty(&mut counter, &state)
        .map_err(|error| DurableRunStateError::Invalid {
            message: format!("measure durable lifecycle state: {error}"),
        })?;
    limits
        .reserve(
            "event_log_bytes",
            runtime_event_log_bytes,
            u64::try_from(counter.length).unwrap_or(u64::MAX),
        )
        .map_err(recovery::map_limit)?;
    let mut encoding = Vec::new();
    encoding.try_reserve_exact(counter.length).map_err(|_| {
        DurableRunStateError::ResourceLimit {
            field: "event_log_bytes",
            current: runtime_event_log_bytes,
            requested: u64::try_from(counter.length).unwrap_or(u64::MAX),
            configured: limits.event_log_bytes,
            hard: FaultResourceLimits::compiled_maximum().event_log_bytes,
        }
    })?;
    serde_json::to_writer_pretty(
        FixedJournalWriter {
            destination: &mut encoding,
        },
        &state,
    )
    .map_err(|error| DurableRunStateError::Invalid {
        message: format!("encode durable lifecycle state: {error}"),
    })?;
    let next = path.with_extension("next");
    let mut file = File::create(&next).map_err(|error| DurableRunStateError::Invalid {
        message: format!("create durable state {}: {error}", next.display()),
    })?;
    file.write_all(&encoding)
        .and_then(|()| file.sync_all())
        .map_err(|error| DurableRunStateError::Invalid {
            message: format!("flush durable state {}: {error}", next.display()),
        })?;
    fs::rename(&next, path).map_err(|error| DurableRunStateError::Invalid {
        message: format!("commit durable state {}: {error}", path.display()),
    })?;
    let parent = path.parent().ok_or_else(|| DurableRunStateError::Invalid {
        message: format!("durable state path {} has no parent", path.display()),
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| DurableRunStateError::Invalid {
            message: format!("flush durable state directory: {error}"),
        })?;
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

fn decimal_digits(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
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
        self.admit_lifecycle_state_encoding(
            limits,
            runtime_event_records,
            runtime_event_log_bytes,
            false,
        )?;
        Ok(())
    }

    pub(in crate::vm_lifecycle) fn reserve_lifecycle_state_encoding(
        &mut self,
        limits: FaultResourceLimits,
        runtime_event_records: u64,
        runtime_event_log_bytes: u64,
    ) -> Result<usize, SchedulerError> {
        self.admit_lifecycle_state_encoding(
            limits,
            runtime_event_records,
            runtime_event_log_bytes,
            true,
        )
    }

    fn admit_lifecycle_state_encoding(
        &mut self,
        limits: FaultResourceLimits,
        runtime_event_records: u64,
        runtime_event_log_bytes: u64,
        allow_storage_growth: bool,
    ) -> Result<usize, SchedulerError> {
        validate_borrowed_run_state_strings(&self.run_manifest, &self.lifecycle_journal)
            .map_err(|message| SchedulerError::BoundaryViolation { message })?;
        let lifecycle_records = self
            .lifecycle_journal
            .nodes
            .len()
            .checked_add(self.lifecycle_journal.completed_exits.len())
            .ok_or_else(|| lifecycle_resource_error("event_records", usize::MAX, 1, limits))?;
        limits
            .reserve(
                "event_records",
                runtime_event_records,
                u64::try_from(lifecycle_records).unwrap_or(u64::MAX),
            )
            .map_err(|error| map_journal_limit(error, limits))?;
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
        let numeric_growth = (20_usize.saturating_sub(decimal_digits(runtime_event_records)))
            .checked_add(20_usize.saturating_sub(decimal_digits(runtime_event_log_bytes)));
        let required = replacement_growth
            .and_then(|growth| numeric_growth.and_then(|digits| growth.checked_add(digits)))
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
        if allow_storage_growth {
            ensure_lifecycle_encoding_capacity(&mut self.lifecycle_persistence.encoding, required)
                .map_err(|additional| {
                    lifecycle_resource_error("event_log_bytes", current, additional, limits)
                })?;
        } else if current < required {
            return Err(lifecycle_resource_error(
                "event_log_bytes",
                current,
                required.saturating_sub(current),
                limits,
            ));
        }
        self.lifecycle_persistence.runtime_event_records = runtime_event_records;
        self.lifecycle_persistence.runtime_event_log_bytes = runtime_event_log_bytes;
        Ok(required)
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
