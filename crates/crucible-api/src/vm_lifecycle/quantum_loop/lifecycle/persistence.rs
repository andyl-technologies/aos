//! Bounded lifecycle-journal encoding and atomic publication.

use super::*;
use crucible::model::FaultResourceLimitError;
use serde::de::DeserializeOwned;
use std::io::Read as _;

const HARD_RUN_STATE_JSON_BYTES: u64 = 67_108_864;

pub(in crate::vm_lifecycle) fn decode_run_json_bounded<T: DeserializeOwned>(
    path: &Path,
    configured_maximum: u64,
) -> Result<T, String> {
    let maximum = configured_maximum.min(HARD_RUN_STATE_JSON_BYTES);
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let length = file
        .metadata()
        .map_err(|error| format!("inspect {}: {error}", path.display()))?
        .len();
    if length > maximum {
        return Err(format!(
            "{} contains {length} bytes, above the bounded maximum {maximum}",
            path.display()
        ));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| format!("{} length is not representable", path.display()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| format!("reserve {capacity} bytes for {}", path.display()))?;
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(format!("{} grew beyond {maximum} bytes", path.display()));
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("decode {}: {error}", path.display()))
}

pub(in crate::vm_lifecycle) fn decode_prior_run_state(
    directory: &Path,
    scenario_identity: &str,
    limits: FaultResourceLimits,
) -> Result<(ProductionRunManifest, ProductionLifecycleJournal), String> {
    let manifest_path = directory.join("run-manifest.json");
    let manifest: ProductionRunManifest =
        decode_run_json_bounded(&manifest_path, limits.event_log_bytes)
            .map_err(|message| format!("invalid prior run manifest: {message}"))?;
    if manifest.version != 2 || manifest.scenario != scenario_identity {
        return Err(format!(
            "prior run manifest {} has incompatible identity or version",
            manifest_path.display()
        ));
    }
    if let Some(node) = manifest
        .staged_processes
        .keys()
        .find(|node| !manifest.processes.contains_key(*node))
    {
        return Err(format!(
            "prior run manifest stages replacement for unknown current node `{node}`"
        ));
    }
    // A Prepared transaction owns two process generations for one logical
    // node. `nodes` bounds logical topology, not the temporary generation
    // multiplicity required for atomic replacement and crash recovery.
    let process_records = manifest.processes.len();
    if u64::try_from(process_records).unwrap_or(u64::MAX) > limits.nodes {
        return Err(format!(
            "prior run manifest has {process_records} process records above node limit {}",
            limits.nodes
        ));
    }
    let journal_path = directory.join("lifecycle-journal.json");
    let journal = decode_run_json_bounded(&journal_path, limits.event_log_bytes)
        .map_err(|message| format!("invalid prior lifecycle journal: {message}"))?;
    validate_recovered_lifecycle_journal(&journal, &manifest, limits).map_err(|message| {
        format!(
            "invalid prior lifecycle journal {}: {message}",
            journal_path.display()
        )
    })?;
    Ok((manifest, journal))
}

pub(in crate::vm_lifecycle) fn validate_recovered_lifecycle_journal(
    journal: &ProductionLifecycleJournal,
    manifest: &ProductionRunManifest,
    limits: FaultResourceLimits,
) -> Result<(), String> {
    if journal.version != 1 {
        return Err(format!(
            "unsupported lifecycle journal version {}",
            journal.version
        ));
    }
    let records = journal
        .nodes
        .len()
        .checked_add(journal.completed_exits.len())
        .ok_or_else(|| String::from("lifecycle journal record count overflow"))?;
    if u64::try_from(records).unwrap_or(u64::MAX) > limits.event_records {
        return Err(format!(
            "lifecycle journal has {records} records above limit {}",
            limits.event_records
        ));
    }
    if u64::try_from(journal.nodes.len()).unwrap_or(u64::MAX) > limits.nodes {
        return Err(format!(
            "lifecycle journal has {} nodes above limit {}",
            journal.nodes.len(),
            limits.nodes
        ));
    }
    if matches!(
        journal.phase,
        ProductionLifecycleJournalPhase::Idle | ProductionLifecycleJournalPhase::Committed
    ) && !journal.nodes.is_empty()
    {
        return Err(format!(
            "lifecycle journal phase {:?} cannot retain live node ownership",
            journal.phase
        ));
    }
    for (index, node) in journal.nodes.iter().enumerate() {
        if node.node.is_empty()
            || journal.nodes[..index]
                .iter()
                .any(|prior| prior.node == node.node)
        {
            return Err(format!(
                "lifecycle journal node {} is empty or duplicated",
                node.node
            ));
        }
        let current = manifest.processes.get(&node.node);
        let staged = manifest.staged_processes.get(&node.node);
        if !journal_process_ownership_is_exact(&journal.phase, node, current, staged) {
            return Err(format!(
                "lifecycle journal node {} is not bound to manifest process ownership",
                node.node
            ));
        }
        if node.current_generation == 0
            || node.next_generation < node.current_generation
            || node.next_generation > node.current_generation.saturating_add(1)
            || !valid_lifecycle_transition(&node.transition)
            || !valid_lifecycle_hash(&node.action_sha256)
            || !valid_lifecycle_hash(&node.evidence_sha256)
            || node.current_process.process_id == 0
            || node.current_process.start_time_ticks == 0
            || !node.current_process.executable.is_absolute()
        {
            return Err(format!(
                "lifecycle journal node {} has invalid canonical fields",
                node.node
            ));
        }
    }
    for exit in &journal.completed_exits {
        if exit.node.is_empty()
            || exit.generation == 0
            || !valid_lifecycle_transition(&exit.transition)
            || !valid_lifecycle_hash(&exit.action_sha256)
            || !valid_lifecycle_hash(&exit.evidence_sha256)
            || exit.expected_exit_code != exit.observed_exit_code
            || exit.process.process_id == 0
            || exit.process.start_time_ticks == 0
            || !exit.process.executable.is_absolute()
        {
            return Err(format!(
                "completed lifecycle exit for {} has invalid canonical fields",
                exit.node
            ));
        }
    }
    Ok(())
}

fn journal_process_ownership_is_exact(
    phase: &ProductionLifecycleJournalPhase,
    node: &ProductionLifecycleJournalNode,
    current: Option<&QemuProcessIdentity>,
    staged: Option<&QemuProcessIdentity>,
) -> bool {
    match phase {
        ProductionLifecycleJournalPhase::Idle | ProductionLifecycleJournalPhase::Committed => false,
        ProductionLifecycleJournalPhase::Intent => {
            current == Some(&node.current_process)
                && staged.is_none()
                && node.replacement_process.is_none()
        }
        ProductionLifecycleJournalPhase::Prepared
        | ProductionLifecycleJournalPhase::ExitsReaped => {
            current == Some(&node.current_process) && staged == node.replacement_process.as_ref()
        }
        ProductionLifecycleJournalPhase::Quarantined => {
            quarantined_process_ownership_is_recoverable(node, current, staged)
        }
    }
}

fn quarantined_process_ownership_is_recoverable(
    node: &ProductionLifecycleJournalNode,
    current: Option<&QemuProcessIdentity>,
    staged: Option<&QemuProcessIdentity>,
) -> bool {
    if current == Some(&node.current_process) {
        // Quarantine can follow Intent, any replacement-launch failure, or a
        // manifest publication failure. The staged entry is either the exact
        // journal replacement, absent because publication never committed, or
        // still manifest-owned after commit consumed the journal copy.
        return node
            .replacement_process
            .as_ref()
            .is_none_or(|replacement| staged.is_none() || staged == Some(replacement));
    }
    if staged.is_some() {
        return false;
    }
    if let Some(replacement) = node.replacement_process.as_ref() {
        return current == Some(replacement);
    }

    // Commit moves replacement ownership into the manifest before persisting
    // it, and consumes the journal's replacement field. If directory fsync
    // then fails, quarantine durably observes the new manifest owner without
    // a duplicate journal identity. Only a generation-advancing replacement
    // transition can create that state. Permanent failure instead removes the
    // manifest owner entirely.
    (current.is_some()
        && node.next_generation == node.current_generation.saturating_add(1)
        && matches!(
            node.transition.as_str(),
            "Crash" | "PowerOff" | "PowerCycle" | "Reset"
        ))
        || (current.is_none()
            && node.next_generation == node.current_generation
            && node.transition == "PermanentFailure")
}

fn valid_lifecycle_transition(value: &str) -> bool {
    matches!(
        value,
        "Boot" | "Crash" | "Reset" | "PowerOff" | "PowerCycle" | "PermanentFailure"
    )
}

fn valid_lifecycle_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

pub(in crate::vm_lifecycle) fn persist_recovered_lifecycle_journal(
    path: &Path,
    journal: &ProductionLifecycleJournal,
    limits: FaultResourceLimits,
) -> Result<(), String> {
    let mut counter = CountingJournalWriter::default();
    serde_json::to_writer_pretty(&mut counter, journal)
        .map_err(|error| format!("measure recovered lifecycle journal: {error}"))?;
    limits
        .reserve(
            "event_log_bytes",
            0,
            u64::try_from(counter.length).unwrap_or(u64::MAX),
        )
        .map_err(|error| format!("admit recovered lifecycle journal: {error}"))?;
    let mut encoding = Vec::new();
    encoding
        .try_reserve_exact(counter.length)
        .map_err(|_| format!("reserve {} recovered journal bytes", counter.length))?;
    serde_json::to_writer_pretty(
        FixedJournalWriter {
            destination: &mut encoding,
        },
        journal,
    )
    .map_err(|error| format!("encode recovered lifecycle journal: {error}"))?;
    let next = path.with_extension("recovery-next");
    let mut file = File::create(&next)
        .map_err(|error| format!("create recovered journal {}: {error}", next.display()))?;
    file.write_all(&encoding)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("flush recovered journal {}: {error}", next.display()))?;
    fs::rename(&next, path)
        .map_err(|error| format!("commit recovered journal {}: {error}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("journal path {} has no parent", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("flush recovered journal directory: {error}"))
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
        runtime_event_log_bytes: u64,
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
                runtime_event_log_bytes,
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

        let error = writer
            .write_all(b"four")
            .expect_err("write beyond reserved journal storage must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
        assert!(writer.destination.is_empty());
        assert_eq!(writer.destination.capacity(), capacity);
    }
}
