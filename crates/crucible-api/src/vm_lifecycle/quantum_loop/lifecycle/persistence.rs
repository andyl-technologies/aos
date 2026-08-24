//! Bounded lifecycle-journal encoding and atomic publication.

use super::*;
use crucible::model::FaultResourceLimitError;

fn map_journal_limit(
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

pub(in crate::vm_lifecycle) struct LifecycleJournalPersistence {
    path: PathBuf,
    next: PathBuf,
    encoding: Vec<u8>,
}

impl LifecycleJournalPersistence {
    pub(in crate::vm_lifecycle) fn new(run_directory: &Path) -> Self {
        Self {
            path: run_directory.join("lifecycle-journal.json"),
            next: run_directory.join("lifecycle-journal.next"),
            encoding: Vec::new(),
        }
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

impl ProductionVmLifecycleLoop {
    pub(super) fn reserve_lifecycle_journal_encoding(
        &mut self,
        limits: FaultResourceLimits,
    ) -> Result<(), SchedulerError> {
        let mut counter = CountingJournalWriter::default();
        serde_json::to_writer_pretty(&mut counter, &self.lifecycle_journal).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("measure lifecycle transaction journal: {error}"),
            }
        })?;
        let replacement_growth =
            self.lifecycle_journal
                .nodes
                .iter()
                .try_fold(0_usize, |total, node| {
                    let path_bytes = node
                        .current_process
                        .executable
                        .as_os_str()
                        .as_encoded_bytes()
                        .len();
                    let escaped_path = path_bytes.checked_mul(6)?;
                    total.checked_add(escaped_path.checked_add(256)?)
                });
        let required = replacement_growth
            .and_then(|growth| counter.length.checked_add(growth))
            .ok_or_else(|| lifecycle_resource_error("event_log_bytes", 0, usize::MAX, limits))?;
        limits
            .reserve(
                "event_log_bytes",
                0,
                u64::try_from(required).unwrap_or(u64::MAX),
            )
            .map_err(|error| map_journal_limit(error, limits))?;
        let current = self.lifecycle_persistence.encoding.capacity();
        let additional = required.saturating_sub(current);
        self.lifecycle_persistence.encoding.clear();
        self.lifecycle_persistence
            .encoding
            .try_reserve_exact(required)
            .map_err(|_| lifecycle_resource_error("event_log_bytes", current, additional, limits))
    }

    pub(in crate::vm_lifecycle) fn persist_lifecycle_journal(
        &mut self,
    ) -> Result<(), SchedulerError> {
        let limits = self.source.plan().fault_signals().resource_limits();
        self.lifecycle_persistence.encoding.clear();
        serde_json::to_writer_pretty(
            FixedJournalWriter {
                destination: &mut self.lifecycle_persistence.encoding,
            },
            &self.lifecycle_journal,
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
}
