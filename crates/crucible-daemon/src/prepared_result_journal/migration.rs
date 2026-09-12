//! Explicit one-way migration of legacy prepared-result journals.
//!
//! This module owns every v1 name and decoder. Normal journal creation and
//! restart opens remain confined to the current v2 format.

use super::*;
use std::io::Write;

use crate::OperationalStateMigrationError;
use crate::anchored_fs::{AnchoredDirectory, AnchoredFile};
use crate::crucible_artifact::decode_migration_prepared_result;
#[cfg(test)]
use crate::crucible_artifact::encode_legacy_prepared_result;
use crate::operational_state_migration::receipt::{
    ACTIVE_MARKER, MigrationObjectReceipt, PREPARED_RECEIPT, authenticated_id, load_phase_receipt,
    persist_phase_receipt,
};

pub(super) const JOURNAL_RESULT_FILE_V1: &str = "result-v1";
pub(super) const JOURNAL_STATE_FILE_V1: &str = "state-v1";
const JOURNAL_STATE_MAGIC_V1: &[u8] = b"crucible.executor.prepared-result-journal-state.v1\0";
const JOURNAL_STATE_HASH_DOMAIN_V1: &str = "crucible.executor.prepared-result-journal-state.v1";
pub(super) const CURRENT_RESULT_PENDING: &str = ".result-v2.pending";
pub(super) const CURRENT_STATE_PENDING: &str = ".state-v2.pending";

pub(super) fn migrate_prepared_result_journals(
    namespace: &AnchoredDirectory,
    receipt_guard: &AnchoredDirectory,
    ledger: &mut DirectoryAssignmentLedger,
    maximum_entries: usize,
    maximum_payload_bytes: usize,
) -> Result<PreparedResultJournalMigrationSummary, OperationalStateMigrationError> {
    const OUTPUT_SCHEMA: &str = "crucible.executor.prepared-result-journal.v2";
    let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
    let inventory = inventory_namespace(namespace, maximum_entries, maximum_payload_bytes)?;
    let existing = load_phase_receipt(receipt_guard, PREPARED_RECEIPT, OUTPUT_SCHEMA)?;
    let mut migrations = Vec::with_capacity(inventory.len());

    // Retain every per-key lock and child directory authority through cleanup.
    for journal in inventory {
        if (journal.files.pending_state.is_some()
            || journal.files.pending_result.is_some()
            || !journal.files.removals.is_empty())
            && existing.is_none()
        {
            return Err(OperationalStateMigrationError::InvalidReceipt);
        }
        let source_version = journal.files.source_version()?;
        let (source, recovery_destinations) =
            match read_migration_journal(&journal.root, maximum_payload_bytes, source_version) {
                Ok(source) => (source, None),
                Err(_)
                    if source_version == MigrationJournalVersion::V2
                        && journal.files.pending_state.is_some()
                        && journal.files.pending_result.is_some()
                        && existing.is_some() =>
                {
                    let source = read_migration_journal_files(
                        &journal.root,
                        maximum_payload_bytes,
                        source_version,
                        CURRENT_STATE_PENDING,
                        CURRENT_RESULT_PENDING,
                    )?;
                    if !source.payload_current {
                        return Err(PreparedResultJournalError::InvalidState.into());
                    }
                    let result_destination = journal
                        .root
                        .open_regular_optional(
                            &journal.root.path().join(JOURNAL_RESULT_FILE),
                            "pin-interrupted-result-destination",
                        )?
                        .ok_or(PreparedResultJournalError::Incomplete)?;
                    let state_destination = journal
                        .root
                        .open_regular_optional(
                            &journal.root.path().join(JOURNAL_STATE_FILE),
                            "pin-interrupted-state-destination",
                        )?
                        .ok_or(PreparedResultJournalError::Incomplete)?;
                    (source, Some((result_destination, state_destination)))
                }
                Err(error) => return Err(error.into()),
            };
        let namespace_lock = acquire_namespace_lock(&namespace.anchored_path(), source.key)?;
        validate_ledger_binding(ledger, &source)?;

        let current =
            if source_version == MigrationJournalVersion::V1 && journal.files.current_complete() {
                let current = read_migration_journal(
                    &journal.root,
                    maximum_payload_bytes,
                    MigrationJournalVersion::V2,
                )?;
                validate_equivalent_journals(&source, &current)?;
                Some(current)
            } else {
                None
            };
        let output_id = current
            .as_ref()
            .map(|journal| Ok(journal.object_id.clone()))
            .unwrap_or_else(|| current_journal_object_id(&source, maximum_payload_bytes))?;
        let current_id = source.object_id.clone();
        let key = hex(source.key.storage_digest().as_bytes());
        let prior = existing
            .as_ref()
            .and_then(|receipt| receipt.objects.iter().find(|object| object.key == key));
        let source_id = match prior {
            Some(object)
                if object.output_object_id == output_id
                    && (object.source_object_id == current_id || output_id == current_id) =>
            {
                object.source_object_id.clone()
            }
            Some(_) => return Err(OperationalStateMigrationError::InvalidReceipt),
            None if journal.files.legacy_partial() => {
                return Err(OperationalStateMigrationError::InvalidReceipt);
            }
            None => current_id,
        };
        migrations.push(JournalMigration {
            source,
            root: journal.root,
            files: journal.files,
            receipt: MigrationObjectReceipt {
                key,
                source_object_id: source_id,
                output_object_id: output_id,
            },
            recovery_destinations,
            _namespace_lock: namespace_lock,
        });
    }

    let mut objects = migrations
        .iter()
        .map(|migration| migration.receipt.clone())
        .collect::<Vec<_>>();
    if let Some(existing) = &existing {
        for migration in &migrations {
            migration.validate_removal_receipts(existing, maximum_payload_bytes)?;
        }
        objects.extend(
            existing
                .objects
                .iter()
                .filter(|object| object.key.starts_with("cleanup/"))
                .cloned(),
        );
    } else {
        for migration in &migrations {
            objects.extend(migration.initial_cleanup_receipts(maximum_payload_bytes)?);
        }
    }
    objects.sort_by(|left, right| left.key.cmp(&right.key));
    let receipt = match existing {
        Some(existing) if existing.objects == objects => existing,
        Some(_) => return Err(OperationalStateMigrationError::InvalidReceipt),
        None => persist_phase_receipt(receipt_guard, PREPARED_RECEIPT, OUTPUT_SCHEMA, objects)?,
    };

    receipt.verify_path_binding()?;
    let journals = migrations.len();
    let mut migrated = 0;
    for migration in migrations {
        migrated += usize::from(migration.apply(maximum_payload_bytes)?);
    }

    Ok(PreparedResultJournalMigrationSummary {
        journals,
        migrated,
        receipt,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MigrationJournalVersion {
    V1,
    V2,
}

struct MigrationJournal {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    result: PreparedSemanticAttemptResult,
    version: MigrationJournalVersion,
    payload_current: bool,
    object_id: String,
    state_authority: AnchoredFile,
    result_authority: AnchoredFile,
}

struct JournalMigration {
    source: MigrationJournal,
    root: AnchoredDirectory,
    files: JournalFiles,
    receipt: MigrationObjectReceipt,
    recovery_destinations: Option<(AnchoredFile, AnchoredFile)>,
    _namespace_lock: OwnedAdvisoryLock,
}

impl JournalMigration {
    fn apply(self, maximum_payload_bytes: usize) -> Result<bool, OperationalStateMigrationError> {
        let migrated = self.source.version == MigrationJournalVersion::V1
            || !self.source.payload_current
            || self.files.has_legacy()
            || !self.files.removals.is_empty()
            || self.recovery_destinations.is_some();
        let root = self.root.path();
        if let Some((result_destination, state_destination)) = &self.recovery_destinations {
            let (payload, state) = self.current_pair(maximum_payload_bytes)?;
            result_destination.replace_contents(&payload)?;
            state_destination.replace_contents(&state)?;
            self.root
                .remove_bound_file(&self.source.state_authority, "remove-resumed-current-state")?;
            self.root.remove_bound_file(
                &self.source.result_authority,
                "remove-resumed-current-result",
            )?;
        }
        if self.source.version == MigrationJournalVersion::V1 && !self.files.current_complete() {
            let (payload, state) = self.current_pair(maximum_payload_bytes)?;
            if !self.files.current_result {
                publish_resumable(&self.root, &root.join(JOURNAL_RESULT_FILE), &payload)?;
            }
            if !self.files.current_state {
                publish_resumable(&self.root, &root.join(JOURNAL_STATE_FILE), &state)?;
            }
        } else if !self.source.payload_current {
            let (payload, state) = self.current_pair(maximum_payload_bytes)?;
            let result_pending = root.join(CURRENT_RESULT_PENDING);
            let state_pending = root.join(CURRENT_STATE_PENDING);
            write_pending(&self.root, &result_pending, &payload)?;
            write_pending(&self.root, &state_pending, &state)?;
            let result_pending_authority = self
                .root
                .open_regular_optional(&result_pending, "pin-staged-current-result")?
                .ok_or(PreparedResultJournalError::Incomplete)?;
            let state_pending_authority = self
                .root
                .open_regular_optional(&state_pending, "pin-staged-current-state")?
                .ok_or(PreparedResultJournalError::Incomplete)?;
            self.source.result_authority.replace_contents(&payload)?;
            self.source.state_authority.replace_contents(&state)?;
            self.root
                .remove_bound_file(&result_pending_authority, "remove-staged-current-result")?;
            self.root
                .remove_bound_file(&state_pending_authority, "remove-staged-current-state")?;
        }
        let current = read_migration_journal(
            &self.root,
            maximum_payload_bytes,
            MigrationJournalVersion::V2,
        )?;
        if current.key != self.source.key
            || current.execution != self.source.execution
            || current.result != self.source.result
        {
            return Err(PreparedResultJournalError::InvalidState.into());
        }
        if let Some(authority) = &self.files.legacy_result {
            self.root
                .remove_bound_file(authority, "remove-legacy-result")?;
        }
        if let Some(authority) = &self.files.legacy_state {
            self.root
                .remove_bound_file(authority, "remove-legacy-state")?;
        }
        if self.source.version == MigrationJournalVersion::V2
            && self.source.payload_current
            && self.recovery_destinations.is_none()
        {
            if let Some(authority) = &self.files.pending_result {
                self.root
                    .remove_bound_file(authority, "remove-staged-current-result")?;
            }
            if let Some(authority) = &self.files.pending_state {
                self.root
                    .remove_bound_file(authority, "remove-staged-current-state")?;
            }
        }
        for removal in &self.files.removals {
            self.root
                .remove_bound_file(&removal.authority, "complete-interrupted-journal-removal")?;
        }
        self.root.verify_path_binding()?;
        Ok(migrated)
    }

    fn current_pair(
        &self,
        maximum_payload_bytes: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), PreparedResultJournalError> {
        let payload = self
            .source
            .result
            .canonical_bytes_with_limit(maximum_payload_bytes)?;
        let state = encode_state(
            self.source.key,
            self.source.execution,
            maximum_payload_bytes,
            &self.source.result,
            &payload,
        )?;
        Ok((payload, state))
    }

    fn initial_cleanup_receipts(
        &self,
        maximum_payload_bytes: usize,
    ) -> Result<Vec<MigrationObjectReceipt>, OperationalStateMigrationError> {
        let mut receipts = Vec::new();
        for (name, authority, maximum) in [
            (
                JOURNAL_STATE_FILE_V1,
                self.files.legacy_state.as_ref(),
                MAX_JOURNAL_STATE_BYTES as u64,
            ),
            (
                JOURNAL_RESULT_FILE_V1,
                self.files.legacy_result.as_ref(),
                maximum_payload_bytes as u64,
            ),
        ] {
            if let Some(authority) = authority {
                receipts.push(self.cleanup_receipt(name, &authority.read_bounded(maximum)?));
            }
        }
        if (self.source.version == MigrationJournalVersion::V1 && !self.files.current_complete())
            || !self.source.payload_current
        {
            let (payload, state) = self.current_pair(maximum_payload_bytes)?;
            receipts.push(self.cleanup_receipt(CURRENT_RESULT_PENDING, &payload));
            receipts.push(self.cleanup_receipt(CURRENT_STATE_PENDING, &state));
        }
        Ok(receipts)
    }

    fn validate_removal_receipts(
        &self,
        receipt: &crate::operational_state_migration::receipt::PhaseReceipt,
        maximum_payload_bytes: usize,
    ) -> Result<(), OperationalStateMigrationError> {
        let (payload, state) = self.current_pair(maximum_payload_bytes)?;
        for (name, authority, expected) in [
            (
                CURRENT_RESULT_PENDING,
                self.files.pending_result.as_ref(),
                payload.as_slice(),
            ),
            (
                CURRENT_STATE_PENDING,
                self.files.pending_state.as_ref(),
                state.as_slice(),
            ),
        ] {
            if let Some(authority) = authority {
                let bytes = authority.read_bounded(expected.len() as u64)?;
                if !expected.starts_with(&bytes)
                    || !receipt
                        .objects
                        .contains(&self.cleanup_receipt(name, expected))
                {
                    return Err(OperationalStateMigrationError::InvalidReceipt);
                }
            }
        }
        for removal in &self.files.removals {
            let maximum = match removal.logical_name.as_str() {
                JOURNAL_STATE_FILE_V1 | CURRENT_STATE_PENDING => MAX_JOURNAL_STATE_BYTES as u64,
                JOURNAL_RESULT_FILE_V1 | CURRENT_RESULT_PENDING => maximum_payload_bytes as u64,
                _ => return Err(OperationalStateMigrationError::InvalidReceipt),
            };
            let bytes = removal.authority.read_bounded(maximum)?;
            let expected = match removal.logical_name.as_str() {
                CURRENT_RESULT_PENDING => payload.as_slice(),
                CURRENT_STATE_PENDING => state.as_slice(),
                _ => bytes.as_slice(),
            };
            if !expected.starts_with(&bytes)
                || !receipt
                    .objects
                    .contains(&self.cleanup_receipt(&removal.logical_name, expected))
            {
                return Err(OperationalStateMigrationError::InvalidReceipt);
            }
        }
        Ok(())
    }

    fn cleanup_receipt(&self, name: &str, bytes: &[u8]) -> MigrationObjectReceipt {
        let key = hex(self.source.key.storage_digest().as_bytes());
        MigrationObjectReceipt {
            key: format!("cleanup/{key}/{name}"),
            source_object_id: authenticated_id(
                "crucible.prepared-result-migration-cleanup-source.v1",
                &[bytes],
            ),
            output_object_id: authenticated_id(
                "crucible.prepared-result-migration-cleanup-output.v1",
                &[b"absent"],
            ),
        }
    }
}

fn write_pending(
    root: &AnchoredDirectory,
    path: &Path,
    bytes: &[u8],
) -> Result<(), OperationalStateMigrationError> {
    match root.open_regular_optional(path, "open-journal-migration-pending")? {
        Some(pending) => {
            let existing = pending.read_bounded(bytes.len() as u64)?;
            if !bytes.starts_with(&existing) {
                return Err(OperationalStateMigrationError::InvalidReceipt);
            }
            pending.replace_contents(bytes)?;
        }
        None => {
            let mut file = root.create_file(path, "create-journal-migration-pending")?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| io_error("write-journal-migration-pending", path, source))?;
        }
    }
    Ok(root.sync()?)
}

fn publish_resumable(
    root: &AnchoredDirectory,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), OperationalStateMigrationError> {
    let pending_path = root.write_once_pending_path(destination)?;
    write_pending(root, &pending_path, bytes)?;
    root.rename_noreplace(&pending_path, destination, "publish-journal-migration-file")?;
    Ok(())
}

struct JournalInventory {
    root: AnchoredDirectory,
    files: JournalFiles,
}

struct JournalFiles {
    legacy_state: Option<AnchoredFile>,
    legacy_result: Option<AnchoredFile>,
    current_state: bool,
    current_result: bool,
    pending_state: Option<AnchoredFile>,
    pending_result: Option<AnchoredFile>,
    removals: Vec<RemovalFile>,
}

struct RemovalFile {
    logical_name: String,
    authority: AnchoredFile,
}

impl JournalFiles {
    fn source_version(&self) -> Result<MigrationJournalVersion, PreparedResultJournalError> {
        if self.legacy_state.is_some() && self.legacy_result.is_some() {
            Ok(MigrationJournalVersion::V1)
        } else if self.current_complete() {
            Ok(MigrationJournalVersion::V2)
        } else {
            Err(PreparedResultJournalError::Incomplete)
        }
    }

    fn current_complete(&self) -> bool {
        self.current_state && self.current_result
    }

    fn has_legacy(&self) -> bool {
        self.legacy_state.is_some() || self.legacy_result.is_some()
    }

    fn legacy_partial(&self) -> bool {
        self.legacy_state.is_some() != self.legacy_result.is_some()
    }
}

fn inventory_namespace(
    namespace: &AnchoredDirectory,
    maximum_entries: usize,
    maximum_payload_bytes: usize,
) -> Result<Vec<JournalInventory>, OperationalStateMigrationError> {
    let anchored = namespace.anchored_path();
    let mut journals = Vec::new();
    let mut entries = 0usize;
    let mut bytes = 0u64;
    let maximum_bytes = (maximum_payload_bytes as u64)
        .checked_add(MAX_JOURNAL_STATE_BYTES as u64)
        .and_then(|per_journal| per_journal.checked_mul(maximum_entries as u64))
        .ok_or(PreparedResultJournalError::MigrationLimitExceeded)?;
    for entry in fs::read_dir(&anchored)
        .map_err(|source| io_error("read-journal-migration-namespace", &anchored, source))?
    {
        let entry =
            entry.map_err(|source| io_error("read-journal-migration-entry", &anchored, source))?;
        admit_inventory_entry(&mut entries, maximum_entries)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?
            .to_owned();
        let file_type = entry
            .file_type()
            .map_err(|source| io_error("stat-journal-migration-entry", &entry.path(), source))?;
        if name == ACTIVE_MARKER || name.starts_with(JOURNAL_LOCK_PREFIX) {
            if (name != ACTIVE_MARKER && !valid_keyed_name(&name, JOURNAL_LOCK_PREFIX))
                || !file_type.is_file()
            {
                return Err(PreparedResultJournalError::InvalidDirectory.into());
            }
            admit_inventory_bytes(
                &mut bytes,
                entry
                    .metadata()
                    .map_err(|source| {
                        io_error("inspect-journal-migration-file", &entry.path(), source)
                    })?
                    .len(),
                maximum_bytes,
            )?;
            continue;
        }
        if name.starts_with(JOURNAL_STAGED_PREFIX) || name.starts_with(JOURNAL_RETIRED_PREFIX) {
            return Err(PreparedResultJournalError::RecoveryRequired.into());
        }
        if !is_lower_hex(&name, 64) || !file_type.is_dir() {
            return Err(PreparedResultJournalError::InvalidDirectory.into());
        }
        let root = namespace.open_child(&entry.path(), "open-migration-journal")?;
        let files = inventory_journal_directory(
            &root,
            &mut entries,
            &mut bytes,
            maximum_entries,
            maximum_bytes,
        )?;
        journals.push(JournalInventory { root, files });
    }
    journals.sort_by(|left, right| left.root.path().cmp(right.root.path()));
    Ok(journals)
}

fn inventory_journal_directory(
    root: &AnchoredDirectory,
    entries: &mut usize,
    bytes: &mut u64,
    maximum_entries: usize,
    maximum_bytes: u64,
) -> Result<JournalFiles, PreparedResultJournalError> {
    let mut files = JournalFiles {
        legacy_state: None,
        legacy_result: None,
        current_state: false,
        current_result: false,
        pending_state: None,
        pending_result: None,
        removals: Vec::new(),
    };
    let anchored = root.anchored_path();
    for entry in fs::read_dir(&anchored)
        .map_err(|source| io_error("inventory-journal-directory", &anchored, source))?
    {
        let entry =
            entry.map_err(|source| io_error("inventory-journal-entry", &anchored, source))?;
        admit_inventory_entry(entries, maximum_entries)?;
        if !entry
            .file_type()
            .map_err(|source| io_error("stat-inventory-journal-entry", &entry.path(), source))?
            .is_file()
        {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        admit_inventory_bytes(
            bytes,
            entry
                .metadata()
                .map_err(|source| {
                    io_error("inspect-inventory-journal-entry", &entry.path(), source)
                })?
                .len(),
            maximum_bytes,
        )?;
        let actual_name = entry.file_name();
        let removal = crate::anchored_fs::removal_original_name(&actual_name);
        let logical_name = removal.as_deref().unwrap_or(&actual_name);
        let authority = root
            .open_inventory_file(&entry.path(), "pin-journal-migration-file")
            .map_err(migration_guard_error)?
            .ok_or(PreparedResultJournalError::Incomplete)?;
        if removal.is_some() {
            match logical_name.to_str() {
                Some(
                    JOURNAL_STATE_FILE_V1
                    | JOURNAL_RESULT_FILE_V1
                    | CURRENT_STATE_PENDING
                    | CURRENT_RESULT_PENDING,
                ) => files.removals.push(RemovalFile {
                    logical_name: logical_name
                        .to_str()
                        .ok_or(PreparedResultJournalError::InvalidDirectory)?
                        .to_owned(),
                    authority,
                }),
                _ => return Err(PreparedResultJournalError::InvalidDirectory),
            }
            continue;
        }
        match logical_name.to_str() {
            Some(JOURNAL_STATE_FILE_V1) if files.legacy_state.is_none() => {
                files.legacy_state = Some(authority);
            }
            Some(JOURNAL_RESULT_FILE_V1) if files.legacy_result.is_none() => {
                files.legacy_result = Some(authority);
            }
            Some(JOURNAL_STATE_FILE) if !files.current_state => files.current_state = true,
            Some(JOURNAL_RESULT_FILE) if !files.current_result => files.current_result = true,
            Some(CURRENT_STATE_PENDING) if files.pending_state.is_none() => {
                files.pending_state = Some(authority);
            }
            Some(CURRENT_RESULT_PENDING) if files.pending_result.is_none() => {
                files.pending_result = Some(authority);
            }
            _ => return Err(PreparedResultJournalError::InvalidDirectory),
        }
    }
    if !(files.legacy_state.is_some() && files.legacy_result.is_some()) && !files.current_complete()
    {
        return Err(PreparedResultJournalError::Incomplete);
    }
    Ok(files)
}

fn valid_keyed_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|suffix| is_lower_hex(suffix, 64))
}

fn admit_inventory_entry(
    count: &mut usize,
    maximum: usize,
) -> Result<(), PreparedResultJournalError> {
    *count = count
        .checked_add(1)
        .ok_or(PreparedResultJournalError::MigrationLimitExceeded)?;
    if *count > maximum {
        return Err(PreparedResultJournalError::MigrationLimitExceeded);
    }
    Ok(())
}

fn admit_inventory_bytes(
    total: &mut u64,
    length: u64,
    maximum: u64,
) -> Result<(), PreparedResultJournalError> {
    *total = total
        .checked_add(length)
        .ok_or(PreparedResultJournalError::MigrationLimitExceeded)?;
    if *total > maximum {
        return Err(PreparedResultJournalError::MigrationLimitExceeded);
    }
    Ok(())
}

fn read_migration_journal(
    root: &AnchoredDirectory,
    maximum_payload_bytes: usize,
    version: MigrationJournalVersion,
) -> Result<MigrationJournal, PreparedResultJournalError> {
    let (state_name, result_name) = match version {
        MigrationJournalVersion::V1 => (JOURNAL_STATE_FILE_V1, JOURNAL_RESULT_FILE_V1),
        MigrationJournalVersion::V2 => (JOURNAL_STATE_FILE, JOURNAL_RESULT_FILE),
    };
    read_migration_journal_files(
        root,
        maximum_payload_bytes,
        version,
        state_name,
        result_name,
    )
}

fn read_migration_journal_files(
    root: &AnchoredDirectory,
    maximum_payload_bytes: usize,
    version: MigrationJournalVersion,
    state_name: &str,
    result_name: &str,
) -> Result<MigrationJournal, PreparedResultJournalError> {
    let anchored = root.anchored_path();
    let state_path = anchored.join(state_name);
    let state_authority = root
        .open_regular_optional(&state_path, "open-migration-journal-state")
        .map_err(migration_guard_error)?
        .ok_or(PreparedResultJournalError::Incomplete)?;
    let state = state_authority
        .read_bounded(MAX_JOURNAL_STATE_BYTES as u64)
        .map_err(migration_guard_error)?;
    let key = decode_migration_key(&state, version)?;
    let envelope = decode_migration_state(&state, key, maximum_payload_bytes, version)?;
    let result_path = anchored.join(result_name);
    let result_authority = root
        .open_regular_optional(&result_path, "open-migration-journal-result")
        .map_err(migration_guard_error)?
        .ok_or(PreparedResultJournalError::Incomplete)?;
    let payload = result_authority
        .read_bounded(maximum_payload_bytes as u64)
        .map_err(migration_guard_error)?;
    envelope.validate_payload(&payload)?;
    let decoded = decode_migration_prepared_result(&payload, maximum_payload_bytes)?;
    if version == MigrationJournalVersion::V1 && decoded.current {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let result = decoded.result;
    envelope.validate_result(&result)?;
    validate_result_key(key, &result)?;
    let directory_name = root
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PreparedResultJournalError::InvalidDirectory)?;
    let expected_name = hex(key.storage_digest().as_bytes());
    if directory_name != expected_name {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let object_id = authenticated_id(
        "crucible.prepared-result-journal-migration-object.v1",
        &[&state, &payload],
    );
    Ok(MigrationJournal {
        key,
        execution: envelope.execution,
        result,
        version,
        payload_current: decoded.current,
        object_id,
        state_authority,
        result_authority,
    })
}

fn current_journal_object_id(
    journal: &MigrationJournal,
    maximum_payload_bytes: usize,
) -> Result<String, PreparedResultJournalError> {
    if journal.version == MigrationJournalVersion::V2 && journal.payload_current {
        return Ok(journal.object_id.clone());
    }
    let payload = journal
        .result
        .canonical_bytes_with_limit(maximum_payload_bytes)?;
    let state = encode_state(
        journal.key,
        journal.execution,
        maximum_payload_bytes,
        &journal.result,
        &payload,
    )?;
    Ok(authenticated_id(
        "crucible.prepared-result-journal-migration-object.v1",
        &[&state, &payload],
    ))
}

fn decode_migration_key(
    state: &[u8],
    version: MigrationJournalVersion,
) -> Result<AttemptExecutionKey, PreparedResultJournalError> {
    let body = authenticated_state_body(state, version)?;
    let mut decoder = JournalStateDecoder::new(body);
    decoder.expect_exact(migration_magic(version))?;
    let digest = decoder.take(32)?;
    let lineage_text = std::str::from_utf8(decoder.bytes()?)
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    let lineage = CampaignLineageId::parse(&format!("crucible.campaign.lineage@{lineage_text}"))
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    let attempt_text = std::str::from_utf8(decoder.bytes()?)
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    let attempt = AttemptId::parse(&format!("crucible.campaign.attempt@{attempt_text}"))
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    let scope = AttemptExecutionScope::from_canonical_bytes(decoder.bytes()?)
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    let key = AttemptExecutionKey::new_scoped(lineage, attempt, scope);
    if digest != key.storage_digest().as_bytes() {
        return Err(PreparedResultJournalError::InvalidState);
    }
    Ok(key)
}

fn decode_migration_state<'a>(
    state: &'a [u8],
    key: AttemptExecutionKey,
    maximum_payload_bytes: usize,
    version: MigrationJournalVersion,
) -> Result<JournalStateEnvelope<'a>, PreparedResultJournalError> {
    if version == MigrationJournalVersion::V2 {
        return decode_state(state, key, None, maximum_payload_bytes);
    }
    let body = authenticated_state_body(state, version)?;
    let mut decoder = JournalStateDecoder::new(body);
    decoder.expect_exact(JOURNAL_STATE_MAGIC_V1)?;
    decoder.expect_exact(key.storage_digest().as_bytes().as_slice())?;
    decoder.expect_bytes(key.lineage().content_id().encode().as_bytes())?;
    decoder.expect_bytes(key.attempt().content_id().encode().as_bytes())?;
    decoder.expect_bytes(&key.scope().canonical_bytes())?;
    let execution = ExecutionId::from_bytes(
        decoder
            .take(16)?
            .try_into()
            .map_err(|_| PreparedResultJournalError::InvalidState)?,
    )
    .map_err(|_| PreparedResultJournalError::InvalidState)?;
    let expected_limit = u64::try_from(maximum_payload_bytes)
        .map_err(|_| PreparedResultJournalError::InvalidPayloadLimit)?;
    if decoder.u64()? != expected_limit {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let observation = decoder.bytes()?;
    let finding = match decoder.byte()? {
        0 => None,
        1 => Some(decoder.bytes()?),
        _ => return Err(PreparedResultJournalError::InvalidState),
    };
    let payload_length =
        usize::try_from(decoder.u64()?).map_err(|_| PreparedResultJournalError::InvalidState)?;
    if payload_length > maximum_payload_bytes {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let payload_hash = decoder
        .take(32)?
        .try_into()
        .map_err(|_| PreparedResultJournalError::InvalidState)?;
    decoder.finish()?;
    Ok(JournalStateEnvelope {
        execution,
        observation,
        measurement_evidence: None,
        finding,
        payload_length,
        payload_hash,
    })
}

fn authenticated_state_body(
    state: &[u8],
    version: MigrationJournalVersion,
) -> Result<&[u8], PreparedResultJournalError> {
    let offset = state
        .len()
        .checked_sub(32)
        .ok_or(PreparedResultJournalError::InvalidState)?;
    let (body, checksum) = state.split_at(offset);
    let key = blake3::derive_key(migration_hash_domain(version), migration_magic(version));
    if blake3::keyed_hash(&key, body).as_bytes() != checksum {
        return Err(PreparedResultJournalError::InvalidState);
    }
    Ok(body)
}

const fn migration_magic(version: MigrationJournalVersion) -> &'static [u8] {
    match version {
        MigrationJournalVersion::V1 => JOURNAL_STATE_MAGIC_V1,
        MigrationJournalVersion::V2 => JOURNAL_STATE_MAGIC_V2,
    }
}

const fn migration_hash_domain(version: MigrationJournalVersion) -> &'static str {
    match version {
        MigrationJournalVersion::V1 => JOURNAL_STATE_HASH_DOMAIN_V1,
        MigrationJournalVersion::V2 => JOURNAL_STATE_HASH_DOMAIN_V2,
    }
}

fn validate_ledger_binding(
    ledger: &mut DirectoryAssignmentLedger,
    journal: &MigrationJournal,
) -> Result<(), PreparedResultJournalError> {
    let state = ledger
        .load_attempt(journal.key)
        .map_err(PreparedResultJournalError::Ledger)?
        .ok_or(PreparedResultJournalError::InvalidState)?;
    let observation = journal
        .result
        .observation()
        .observation()
        .id()
        .map_err(PreparedSemanticResultCodecError::from)?;
    if state.execution() != journal.execution || state.observation() != Some(observation) {
        return Err(PreparedResultJournalError::InvalidState);
    }
    Ok(())
}

fn validate_equivalent_journals(
    source: &MigrationJournal,
    staged: &MigrationJournal,
) -> Result<(), PreparedResultJournalError> {
    if source.key != staged.key
        || source.execution != staged.execution
        || source.result != staged.result
        || source.version == staged.version
    {
        return Err(PreparedResultJournalError::InvalidState);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn write_legacy_journal_for_test(
    namespace: &Path,
    key: AttemptExecutionKey,
    execution: ExecutionId,
    maximum_payload_bytes: usize,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), PreparedResultJournalError> {
    let payload = encode_legacy_prepared_result(result, maximum_payload_bytes)?;
    let observation = result
        .observation()
        .observation()
        .id()
        .map_err(PreparedSemanticResultCodecError::from)?;
    let finding = result
        .finding()
        .map(|finding| finding.id().map_err(PreparedSemanticResultCodecError::from))
        .transpose()?;
    let mut state = Vec::new();
    state.extend_from_slice(JOURNAL_STATE_MAGIC_V1);
    state.extend_from_slice(&key.storage_digest().as_bytes());
    push_text(&mut state, &key.lineage().content_id().encode())?;
    push_text(&mut state, &key.attempt().content_id().encode())?;
    push_bytes(&mut state, &key.scope().canonical_bytes())?;
    state.extend_from_slice(&execution.as_bytes());
    state.extend_from_slice(&(maximum_payload_bytes as u64).to_be_bytes());
    push_text(&mut state, &observation.content_id().encode())?;
    match finding {
        Some(finding) => {
            state.push(1);
            push_text(&mut state, &finding.content_id().encode())?;
        }
        None => state.push(0),
    }
    state.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    state.extend_from_slice(blake3::hash(&payload).as_bytes());
    let checksum_key = blake3::derive_key(JOURNAL_STATE_HASH_DOMAIN_V1, JOURNAL_STATE_MAGIC_V1);
    let checksum = blake3::keyed_hash(&checksum_key, &state);
    state.extend_from_slice(checksum.as_bytes());

    let root = journal_path(namespace, key);
    fs::create_dir(&root).map_err(|source| io_error("create-test-v1-journal", &root, source))?;
    fs::write(root.join(JOURNAL_RESULT_FILE_V1), payload)
        .map_err(|source| io_error("write-test-v1-result", &root, source))?;
    fs::write(root.join(JOURNAL_STATE_FILE_V1), state)
        .map_err(|source| io_error("write-test-v1-state", &root, source))?;
    sync_directory(&root, "sync-test-v1-journal")?;
    sync_directory(namespace, "sync-test-v1-journal-parent")
}
