//! Explicit one-way migration of legacy prepared-result journals.
//!
//! This module owns every v1 name and decoder. Normal journal creation and
//! restart opens remain confined to the current v2 format.

use super::*;

const JOURNAL_MIGRATION_PREFIX: &str = ".migration-v2-";
pub(super) const JOURNAL_RESULT_FILE_V1: &str = "result-v1";
pub(super) const JOURNAL_STATE_FILE_V1: &str = "state-v1";
const JOURNAL_STATE_MAGIC_V1: &[u8] = b"crucible.executor.prepared-result-journal-state.v1\0";
const JOURNAL_STATE_HASH_DOMAIN_V1: &str = "crucible.executor.prepared-result-journal-state.v1";

pub(super) fn migrate_prepared_result_journals(
    namespace: impl AsRef<Path>,
    ledger: &mut DirectoryAssignmentLedger,
    maximum_journals: usize,
    maximum_payload_bytes: usize,
) -> Result<PreparedResultJournalMigrationSummary, PreparedResultJournalError> {
    let namespace = namespace.as_ref();
    validate_namespace(namespace)?;
    let maximum_payload_bytes = validate_payload_limit(maximum_payload_bytes)?;
    let roots = visible_journal_roots(namespace, maximum_journals)?;
    let mut migrations = Vec::with_capacity(roots.len());

    // Retain every per-key lock so validation stays stable until all commits.
    for root in roots {
        let source = read_migration_journal(&root, maximum_payload_bytes)?;
        let namespace_lock = acquire_namespace_lock(namespace, source.key)?;
        validate_ledger_binding(ledger, &source)?;
        let staging = migration_path(namespace, source.key);
        let staged = if path_presence(&staging, "inspect-journal-migration-staging")? {
            let staged = read_migration_journal(&staging, maximum_payload_bytes)?;
            validate_equivalent_journals(&source, &staged)?;
            Some(staged.version)
        } else {
            None
        };
        migrations.push(JournalMigration {
            source,
            staging,
            staged,
            _namespace_lock: namespace_lock,
        });
    }

    for migration in &mut migrations {
        migration.stage_current(maximum_payload_bytes)?;
    }
    let mut migrated = 0;
    for migration in &migrations {
        if migration.commit(namespace)? {
            migrated += 1;
        }
    }

    Ok(PreparedResultJournalMigrationSummary {
        journals: migrations.len(),
        migrated,
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
    maximum_payload_bytes: usize,
    result: PreparedSemanticAttemptResult,
    version: MigrationJournalVersion,
}

struct JournalMigration {
    source: MigrationJournal,
    staging: PathBuf,
    staged: Option<MigrationJournalVersion>,
    _namespace_lock: OwnedAdvisoryLock,
}

impl JournalMigration {
    fn stage_current(
        &mut self,
        maximum_payload_bytes: usize,
    ) -> Result<(), PreparedResultJournalError> {
        if self.source.version == MigrationJournalVersion::V2 || self.staged.is_some() {
            return Ok(());
        }
        fs::create_dir(&self.staging).map_err(|source| {
            io_error("create-journal-migration-staging", &self.staging, source)
        })?;
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
        initialize_new(&self.staging, &payload, &state)?;
        sync_parent(&self.staging, "sync-journal-parent-after-migration-stage")?;
        self.staged = Some(MigrationJournalVersion::V2);
        Ok(())
    }

    fn commit(&self, namespace: &Path) -> Result<bool, PreparedResultJournalError> {
        match (self.source.version, self.staged) {
            (MigrationJournalVersion::V1, Some(MigrationJournalVersion::V2)) => {
                rename_exchange(&journal_path(namespace, self.source.key), &self.staging)?;
                sync_directory(namespace, "sync-journal-parent-after-migration-exchange")?;
                remove_migration_directory(&self.staging)?;
                sync_directory(namespace, "sync-journal-parent-after-migration-cleanup")?;
                Ok(true)
            }
            (MigrationJournalVersion::V2, Some(MigrationJournalVersion::V1)) => {
                remove_migration_directory(&self.staging)?;
                sync_directory(namespace, "sync-journal-parent-after-migration-cleanup")?;
                Ok(true)
            }
            (MigrationJournalVersion::V2, None) => Ok(false),
            _ => Err(PreparedResultJournalError::RecoveryRequired),
        }
    }
}

fn visible_journal_roots(
    namespace: &Path,
    maximum: usize,
) -> Result<Vec<PathBuf>, PreparedResultJournalError> {
    let mut roots = Vec::new();
    for entry in fs::read_dir(namespace)
        .map_err(|source| io_error("read-journal-migration-namespace", namespace, source))?
    {
        let entry =
            entry.map_err(|source| io_error("read-journal-migration-entry", namespace, source))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        let file_type = entry
            .file_type()
            .map_err(|source| io_error("stat-journal-migration-entry", &entry.path(), source))?;
        if name.starts_with(JOURNAL_LOCK_PREFIX) {
            if !file_type.is_file() {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            continue;
        }
        if name.starts_with(JOURNAL_MIGRATION_PREFIX) {
            if !file_type.is_dir() {
                return Err(PreparedResultJournalError::InvalidDirectory);
            }
            continue;
        }
        if name.starts_with(JOURNAL_STAGED_PREFIX) || name.starts_with(JOURNAL_RETIRED_PREFIX) {
            return Err(PreparedResultJournalError::RecoveryRequired);
        }
        if !is_lower_hex(name, 64) || !file_type.is_dir() {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        if roots.len() == maximum {
            return Err(PreparedResultJournalError::MigrationLimitExceeded);
        }
        roots.push(entry.path());
    }
    roots.sort();
    Ok(roots)
}

fn read_migration_journal(
    root: &Path,
    maximum_payload_bytes: usize,
) -> Result<MigrationJournal, PreparedResultJournalError> {
    validate_journal_directory(root)?;
    let (state_name, result_name, version) = migration_journal_files(root)?;
    let state = read_bounded_file(
        &root.join(state_name),
        MAX_JOURNAL_STATE_BYTES,
        "read-migration-journal-state",
    )?;
    let key = decode_migration_key(&state, version)?;
    let envelope = decode_migration_state(&state, key, maximum_payload_bytes, version)?;
    let payload = read_bounded_file(
        &root.join(result_name),
        maximum_payload_bytes,
        "read-migration-journal-result",
    )?;
    envelope.validate_payload(&payload)?;
    let payload_version = PreparedSemanticResultVersion::from_payload(&payload)
        .ok_or(PreparedResultJournalError::InvalidState)?;
    if (version == MigrationJournalVersion::V1
        && payload_version != PreparedSemanticResultVersion::V1)
        || (version == MigrationJournalVersion::V2 && !current_payload_version(payload_version))
    {
        return Err(PreparedResultJournalError::InvalidState);
    }
    let result = PreparedSemanticAttemptResult::from_canonical_bytes_with_limit(
        &payload,
        maximum_payload_bytes,
    )?;
    envelope.validate_result(&result)?;
    validate_result_key(key, &result)?;
    let directory_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PreparedResultJournalError::InvalidDirectory)?;
    let expected_name = hex(key.storage_digest().as_bytes());
    if directory_name != expected_name
        && directory_name != format!("{JOURNAL_MIGRATION_PREFIX}{expected_name}")
    {
        return Err(PreparedResultJournalError::InvalidState);
    }
    Ok(MigrationJournal {
        key,
        execution: envelope.execution,
        maximum_payload_bytes,
        result,
        version,
    })
}

fn migration_journal_files(
    root: &Path,
) -> Result<(&'static str, &'static str, MigrationJournalVersion), PreparedResultJournalError> {
    let current = (
        root.join(JOURNAL_STATE_FILE).exists(),
        root.join(JOURNAL_RESULT_FILE).exists(),
    );
    let legacy = (
        root.join(JOURNAL_STATE_FILE_V1).exists(),
        root.join(JOURNAL_RESULT_FILE_V1).exists(),
    );
    match (current, legacy) {
        ((true, true), (false, false)) => Ok((
            JOURNAL_STATE_FILE,
            JOURNAL_RESULT_FILE,
            MigrationJournalVersion::V2,
        )),
        ((false, false), (true, true)) => Ok((
            JOURNAL_STATE_FILE_V1,
            JOURNAL_RESULT_FILE_V1,
            MigrationJournalVersion::V1,
        )),
        _ => Err(PreparedResultJournalError::Incomplete),
    }
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
        || source.maximum_payload_bytes != staged.maximum_payload_bytes
        || source.result != staged.result
        || source.version == staged.version
    {
        return Err(PreparedResultJournalError::InvalidState);
    }
    Ok(())
}

pub(super) fn migration_path(namespace: &Path, key: AttemptExecutionKey) -> PathBuf {
    namespace.join(format!(
        "{JOURNAL_MIGRATION_PREFIX}{}",
        hex(key.storage_digest().as_bytes())
    ))
}

fn rename_exchange(source: &Path, destination: &Path) -> Result<(), PreparedResultJournalError> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        io_error(
            "exchange-journal-migration-directory",
            destination,
            io::Error::from(error),
        )
    })
}

fn remove_migration_directory(path: &Path) -> Result<(), PreparedResultJournalError> {
    validate_journal_directory(path)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)
        .map_err(|source| io_error("read-legacy-journal-for-removal", path, source))?
    {
        let entry = entry
            .map_err(|source| io_error("read-legacy-journal-entry-for-removal", path, source))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        if entries.len() == 2 || (name != JOURNAL_STATE_FILE_V1 && name != JOURNAL_RESULT_FILE_V1) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        entries.push(entry.path());
    }
    for entry in entries {
        remove_file_if_present(&entry, "remove-legacy-journal-file")?;
    }
    fs::remove_dir(path).map_err(|source| io_error("remove-legacy-journal-directory", path, source))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
pub(super) fn write_legacy_journal_for_test(
    namespace: &Path,
    key: AttemptExecutionKey,
    execution: ExecutionId,
    maximum_payload_bytes: usize,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), PreparedResultJournalError> {
    let payload = result.canonical_v1_bytes_with_limit(maximum_payload_bytes)?;
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
    write_atomic(&root, JOURNAL_RESULT_FILE_V1, &payload)?;
    write_atomic(&root, JOURNAL_STATE_FILE_V1, &state)?;
    sync_directory(namespace, "sync-test-v1-journal-parent")
}

#[cfg(test)]
pub(super) fn interrupt_migration_for_test(
    namespace: &Path,
    key: AttemptExecutionKey,
    maximum_payload_bytes: usize,
    after_exchange: bool,
) -> Result<(), PreparedResultJournalError> {
    let source = read_migration_journal(&journal_path(namespace, key), maximum_payload_bytes)?;
    let namespace_lock = acquire_namespace_lock(namespace, key)?;
    let mut migration = JournalMigration {
        staging: migration_path(namespace, key),
        source,
        staged: None,
        _namespace_lock: namespace_lock,
    };
    migration.stage_current(maximum_payload_bytes)?;
    if after_exchange {
        rename_exchange(&journal_path(namespace, key), &migration.staging)?;
        sync_directory(namespace, "sync-test-interrupted-migration-exchange")?;
    }
    Ok(())
}
