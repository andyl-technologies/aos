//! Explicit one-way migration of legacy assignment attempt records.
//!
//! This module is reachable only from the stopped-daemon operator migration.
//! Normal execution and restart decoding remain confined to v15.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::codec::*;
use super::*;

pub(super) const ATTEMPT_STATE_MAGIC_V14: &[u8] = b"crucible.executor.attempt-state-record.v14\0";
pub(super) const ATTEMPT_STATE_MAGIC_V13: &[u8] = b"crucible.executor.attempt-state-record.v13\0";
pub(super) const ATTEMPT_STATE_MAGIC_V12: &[u8] = b"crucible.executor.attempt-state-record.v12\0";
pub(super) const ATTEMPT_STATE_MAGIC_V11: &[u8] = b"crucible.executor.attempt-state-record.v11\0";
pub(super) const ATTEMPT_STATE_MAGIC_V10: &[u8] = b"crucible.executor.attempt-state-record.v10\0";
pub(super) const ATTEMPT_STATE_MAGIC_V9: &[u8] = b"crucible.executor.attempt-state-record.v9\0";
pub(super) const ATTEMPT_STATE_MAGIC_V8: &[u8] = b"crucible.executor.attempt-state-record.v8\0";
pub(super) const ATTEMPT_STATE_MAGIC_V7: &[u8] = b"crucible.executor.attempt-state-record.v7\0";
pub(super) const ATTEMPT_STATE_MAGIC_V6: &[u8] = b"crucible.executor.attempt-state-record.v6\0";
pub(super) const ATTEMPT_STATE_MAGIC_V5: &[u8] = b"crucible.executor.attempt-state-record.v5\0";
pub(super) const ATTEMPT_STATE_MAGIC_V4: &[u8] = b"crucible.executor.attempt-state-record.v4\0";
pub(super) const ATTEMPT_STATE_MAGIC_V3: &[u8] = b"crucible.executor.attempt-state-record.v3\0";
pub(super) const ATTEMPT_STATE_MAGIC_V2: &[u8] = b"crucible.executor.attempt-state-record.v2\0";
pub(super) const ATTEMPT_STATE_MAGIC_V1: &[u8] = b"crucible.executor.attempt-state-record.v1\0";

pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V14: &str =
    "crucible.executor.attempt-state-record.v14";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V13: &str =
    "crucible.executor.attempt-state-record.v13";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V12: &str =
    "crucible.executor.attempt-state-record.v12";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V11: &str =
    "crucible.executor.attempt-state-record.v11";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V10: &str =
    "crucible.executor.attempt-state-record.v10";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V9: &str =
    "crucible.executor.attempt-state-record.v9";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V8: &str =
    "crucible.executor.attempt-state-record.v8";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V7: &str =
    "crucible.executor.attempt-state-record.v7";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V6: &str =
    "crucible.executor.attempt-state-record.v6";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V5: &str =
    "crucible.executor.attempt-state-record.v5";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V4: &str =
    "crucible.executor.attempt-state-record.v4";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V3: &str =
    "crucible.executor.attempt-state-record.v3";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V2: &str =
    "crucible.executor.attempt-state-record.v2";
pub(super) const ATTEMPT_STATE_CHECKSUM_DOMAIN_V1: &str =
    "crucible.executor.attempt-state-record.v1";

pub(super) fn decode_migratable_attempt_state(
    bytes: &[u8],
) -> Result<(AttemptExecutionKey, AttemptRuntimeState), AssignmentLedgerError> {
    let (payload, magic) = if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN) {
        (payload, ATTEMPT_STATE_MAGIC)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V14) {
        (payload, ATTEMPT_STATE_MAGIC_V14)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V13) {
        (payload, ATTEMPT_STATE_MAGIC_V13)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V12) {
        (payload, ATTEMPT_STATE_MAGIC_V12)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V11) {
        (payload, ATTEMPT_STATE_MAGIC_V11)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V10) {
        (payload, ATTEMPT_STATE_MAGIC_V10)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V9) {
        (payload, ATTEMPT_STATE_MAGIC_V9)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V8) {
        (payload, ATTEMPT_STATE_MAGIC_V8)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V7) {
        (payload, ATTEMPT_STATE_MAGIC_V7)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V6) {
        (payload, ATTEMPT_STATE_MAGIC_V6)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V5) {
        (payload, ATTEMPT_STATE_MAGIC_V5)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V4) {
        (payload, ATTEMPT_STATE_MAGIC_V4)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V3) {
        (payload, ATTEMPT_STATE_MAGIC_V3)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V2) {
        (payload, ATTEMPT_STATE_MAGIC_V2)
    } else {
        (
            open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V1)?,
            ATTEMPT_STATE_MAGIC_V1,
        )
    };
    let mut cursor = RecordCursor::new(payload);
    cursor.require(magic)?;
    let lineage = parse_typed(cursor.bytes()?, CampaignLineageId::parse)?;
    let attempt = parse_typed(cursor.bytes()?, AttemptId::parse)?;
    let scope = if ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
        || magic == ATTEMPT_STATE_MAGIC_V13)
        || magic == ATTEMPT_STATE_MAGIC_V12
        || magic == ATTEMPT_STATE_MAGIC_V11
    {
        AttemptExecutionScope::from_canonical_bytes(cursor.bytes()?)?
    } else {
        AttemptExecutionScope::Semantic
    };
    let execution_basis = CampaignHash::from_bytes(cursor.fixed()?);
    let origin = if ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
        || magic == ATTEMPT_STATE_MAGIC_V13)
        || magic == ATTEMPT_STATE_MAGIC_V12
        || magic == ATTEMPT_STATE_MAGIC_V11
        || magic == ATTEMPT_STATE_MAGIC_V10
        || magic == ATTEMPT_STATE_MAGIC_V9
        || magic == ATTEMPT_STATE_MAGIC_V8
        || magic == ATTEMPT_STATE_MAGIC_V7
        || magic == ATTEMPT_STATE_MAGIC_V6
        || magic == ATTEMPT_STATE_MAGIC_V5
        || magic == ATTEMPT_STATE_MAGIC_V4
    {
        decode_attempt_origin(
            &mut cursor,
            ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                || magic == ATTEMPT_STATE_MAGIC_V13)
                || magic == ATTEMPT_STATE_MAGIC_V12,
        )?
    } else {
        AttemptExecutionOrigin::Initial
    };
    let tag = cursor.byte()?;
    let daemon_epoch = DaemonEpoch::from_bytes(cursor.fixed()?)?;
    let execution = ExecutionId::from_bytes(cursor.fixed()?)?;
    let state = match tag {
        0 => AttemptRuntimeState::Running {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        1 => {
            let observation = parse_typed(cursor.bytes()?, ObservationId::parse)?;
            let finding_candidate = decode_legacy_optional_finding_candidate(&mut cursor, magic)?;
            let finding_candidate_acknowledged = if ((magic == ATTEMPT_STATE_MAGIC
                || magic == ATTEMPT_STATE_MAGIC_V14)
                || magic == ATTEMPT_STATE_MAGIC_V13)
                || magic == ATTEMPT_STATE_MAGIC_V12
                || magic == ATTEMPT_STATE_MAGIC_V11
                || magic == ATTEMPT_STATE_MAGIC_V10
                || magic == ATTEMPT_STATE_MAGIC_V9
            {
                match cursor.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(corrupt("attempt-state-finding-candidate-acknowledged-tag")),
                }
            } else {
                false
            };
            let finding_candidate = match (finding_candidate, finding_candidate_acknowledged) {
                (None, false) => CompletedFindingCandidate::None,
                (Some(candidate), false) => CompletedFindingCandidate::Pending(candidate),
                (Some(candidate), true) => CompletedFindingCandidate::Acknowledged(candidate),
                (None, true) => {
                    return Err(corrupt(
                        "attempt-state-acknowledged-finding-candidate-missing",
                    ));
                }
            };
            AttemptRuntimeState::Completed {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                observation,
                finding_candidate,
                prepared_result_digest: if magic == ATTEMPT_STATE_MAGIC {
                    decode_optional_campaign_hash(&mut cursor)?
                } else {
                    None
                },
            }
        }
        2 => AttemptRuntimeState::Canceled {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        8 if ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7 =>
        {
            AttemptRuntimeState::TerminalFailure {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
            }
        }
        3 if ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5
            || magic == ATTEMPT_STATE_MAGIC_V4
            || magic == ATTEMPT_STATE_MAGIC_V3
            || magic == ATTEMPT_STATE_MAGIC_V2 =>
        {
            AttemptRuntimeState::Publishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                observation: parse_typed(cursor.bytes()?, ObservationId::parse)?,
                finding_candidate: decode_legacy_optional_finding_candidate(&mut cursor, magic)?,
                finding_replay_captures: if (magic == ATTEMPT_STATE_MAGIC
                    || magic == ATTEMPT_STATE_MAGIC_V14)
                    || magic == ATTEMPT_STATE_MAGIC_V13
                {
                    decode_optional_finding_replay_captures(&mut cursor)?
                } else {
                    None
                },
                finding_exact_retention_roots: if magic == ATTEMPT_STATE_MAGIC
                    || magic == ATTEMPT_STATE_MAGIC_V14
                {
                    decode_finding_exact_retention_roots(&mut cursor)?
                } else {
                    [None; MAX_PUBLISHING_FINDING_EXACT_ROOTS]
                },
                prepared_result_digest: if magic == ATTEMPT_STATE_MAGIC
                    || magic == ATTEMPT_STATE_MAGIC_V14
                {
                    decode_optional_campaign_hash(&mut cursor)?
                } else {
                    None
                },
            }
        }
        4 if (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12)
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5
            || magic == ATTEMPT_STATE_MAGIC_V4
            || magic == ATTEMPT_STATE_MAGIC_V3 =>
        {
            AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
            }
        }
        5 if (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12)
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5
            || magic == ATTEMPT_STATE_MAGIC_V4
            || magic == ATTEMPT_STATE_MAGIC_V3 =>
        {
            AttemptRuntimeState::CheckpointPublishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            }
        }
        6 if (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12)
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5
            || magic == ATTEMPT_STATE_MAGIC_V4
            || magic == ATTEMPT_STATE_MAGIC_V3 =>
        {
            AttemptRuntimeState::Paused {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
                promotion_basis: if matches!(
                    magic,
                    ATTEMPT_STATE_MAGIC
                        | ATTEMPT_STATE_MAGIC_V14
                        | ATTEMPT_STATE_MAGIC_V13
                        | ATTEMPT_STATE_MAGIC_V12
                        | ATTEMPT_STATE_MAGIC_V11
                        | ATTEMPT_STATE_MAGIC_V10
                        | ATTEMPT_STATE_MAGIC_V9
                        | ATTEMPT_STATE_MAGIC_V8
                        | ATTEMPT_STATE_MAGIC_V7
                        | ATTEMPT_STATE_MAGIC_V6
                ) {
                    decode_checkpoint_promotion_basis(
                        &mut cursor,
                        (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12)
                            || magic == ATTEMPT_STATE_MAGIC_V11
                            || magic == ATTEMPT_STATE_MAGIC_V10,
                        (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12)
                            || magic == ATTEMPT_STATE_MAGIC_V11,
                        ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12,
                    )?
                } else {
                    None
                },
            }
        }
        7 if (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
            || magic == ATTEMPT_STATE_MAGIC_V13)
            || magic == ATTEMPT_STATE_MAGIC_V12)
            || magic == ATTEMPT_STATE_MAGIC_V11
            || magic == ATTEMPT_STATE_MAGIC_V10
            || magic == ATTEMPT_STATE_MAGIC_V9
            || magic == ATTEMPT_STATE_MAGIC_V8
            || magic == ATTEMPT_STATE_MAGIC_V7
            || magic == ATTEMPT_STATE_MAGIC_V6
            || magic == ATTEMPT_STATE_MAGIC_V5 =>
        {
            AttemptRuntimeState::CheckpointPromoting {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                source_checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
                promoted_checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
                promotion_basis: if matches!(
                    magic,
                    ATTEMPT_STATE_MAGIC
                        | ATTEMPT_STATE_MAGIC_V14
                        | ATTEMPT_STATE_MAGIC_V13
                        | ATTEMPT_STATE_MAGIC_V12
                        | ATTEMPT_STATE_MAGIC_V11
                        | ATTEMPT_STATE_MAGIC_V10
                        | ATTEMPT_STATE_MAGIC_V9
                        | ATTEMPT_STATE_MAGIC_V8
                        | ATTEMPT_STATE_MAGIC_V7
                        | ATTEMPT_STATE_MAGIC_V6
                ) {
                    decode_checkpoint_promotion_basis(
                        &mut cursor,
                        (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12)
                            || magic == ATTEMPT_STATE_MAGIC_V11
                            || magic == ATTEMPT_STATE_MAGIC_V10,
                        (((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12)
                            || magic == ATTEMPT_STATE_MAGIC_V11,
                        ((magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V14)
                            || magic == ATTEMPT_STATE_MAGIC_V13)
                            || magic == ATTEMPT_STATE_MAGIC_V12,
                    )?
                } else {
                    None
                },
            }
        }
        _ => return Err(corrupt("attempt-state-unknown-tag")),
    };
    let promotion_basis = match state {
        AttemptRuntimeState::Paused {
            promotion_basis, ..
        }
        | AttemptRuntimeState::CheckpointPromoting {
            promotion_basis, ..
        } => promotion_basis,
        AttemptRuntimeState::Running { .. }
        | AttemptRuntimeState::CheckpointRequested { .. }
        | AttemptRuntimeState::CheckpointPublishing { .. }
        | AttemptRuntimeState::Publishing { .. }
        | AttemptRuntimeState::Completed { .. }
        | AttemptRuntimeState::Canceled { .. }
        | AttemptRuntimeState::TerminalFailure { .. } => None,
    };
    if let Some(promotion_basis) = promotion_basis
        && attempt_execution_basis_digest_for_start_mode(
            lineage,
            attempt,
            promotion_basis.resources(),
            promotion_basis.retention(),
            promotion_basis.start_mode(),
        ) != execution_basis
    {
        return Err(corrupt("checkpoint-promotion-execution-basis-mismatch"));
    }
    let key = AttemptExecutionKey::new_scoped(lineage, attempt, scope);
    if !state.validates_for_key(key) {
        return Err(corrupt("attempt-state-does-not-match-execution-scope"));
    }
    cursor.finish()?;
    Ok((key, state))
}

fn decode_legacy_optional_finding_candidate(
    cursor: &mut RecordCursor<'_>,
    magic: &[u8],
) -> Result<Option<FindingCandidateBundleId>, AssignmentLedgerError> {
    if magic != ATTEMPT_STATE_MAGIC
        && magic != ATTEMPT_STATE_MAGIC_V14
        && magic != ATTEMPT_STATE_MAGIC_V13
        && magic != ATTEMPT_STATE_MAGIC_V12
        && magic != ATTEMPT_STATE_MAGIC_V11
        && magic != ATTEMPT_STATE_MAGIC_V10
        && magic != ATTEMPT_STATE_MAGIC_V9
        && magic != ATTEMPT_STATE_MAGIC_V8
    {
        return Ok(None);
    }
    decode_optional_finding_candidate(cursor)
}

#[derive(Debug)]
struct ValidatedAttemptMigration {
    path: PathBuf,
    current_bytes: Option<Vec<u8>>,
}

pub(super) fn migrate_attempt_records(
    ledger: &DirectoryAssignmentLedger,
    maximum_records: usize,
) -> Result<AssignmentMigrationSummary, AssignmentLedgerError> {
    let paths = attempt_record_paths(&ledger.root, maximum_records)?;
    let mut records = Vec::with_capacity(paths.len());

    // Authenticate every source before creating or replacing anything.
    for path in paths {
        let bytes = read_optional_bounded(&path)?
            .ok_or_else(|| corrupt("attempt-root-record-disappeared"))?;
        let (key, state) = decode_migratable_attempt_state(&bytes)?;
        if attempt_path_at(&ledger.root, key) != path {
            return Err(corrupt("attempt-root-record-path-identity-mismatch"));
        }
        let current_bytes = match decode_attempt_state(&bytes) {
            Ok((current_key, current_state)) if current_key == key && current_state == state => {
                None
            }
            Ok(_) => return Err(corrupt("attempt-state-migration-current-mismatch")),
            Err(_) => Some(encode_attempt_state(key, state)),
        };
        records.push(ValidatedAttemptMigration {
            path,
            current_bytes,
        });
    }

    let mut staged = Vec::new();
    for record in &records {
        let Some(bytes) = &record.current_bytes else {
            continue;
        };
        let directory = record
            .path
            .parent()
            .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
        let (path, mut file) = create_staging(directory)?;
        if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            remove_staged(&staged);
            return Err(io_error("write-attempt-migration-staging", &path, source));
        }
        sync_directory(directory)?;
        staged.push((path, record.path.clone()));
    }

    let migrated = staged.len();
    for (staging, destination) in staged {
        fs::rename(&staging, &destination)
            .map_err(|source| io_error("publish-attempt-state-migration", &destination, source))?;
        sync_record_parent(&destination)?;
    }

    Ok(AssignmentMigrationSummary {
        records: records.len(),
        migrated,
    })
}

fn remove_staged(paths: &[(PathBuf, PathBuf)]) {
    for (path, _) in paths {
        let _ = fs::remove_file(path);
    }
}

fn attempt_record_paths(
    root: &Path,
    maximum: usize,
) -> Result<Vec<PathBuf>, AssignmentLedgerError> {
    let attempts = root.join("attempts");
    let shards = match fs::read_dir(&attempts) {
        Ok(shards) => shards,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(io_error("read-attempt-root-shards", &attempts, source)),
    };
    let mut paths = Vec::new();
    for shard in shards {
        let shard =
            shard.map_err(|source| io_error("read-attempt-root-shard", &attempts, source))?;
        let shard_path = shard.path();
        let shard_name = shard.file_name();
        let shard_name = shard_name
            .to_str()
            .ok_or_else(|| corrupt("attempt-root-shard-name"))?;
        if !is_lower_hex(shard_name, 2)
            || !shard
                .file_type()
                .map_err(|source| io_error("stat-attempt-root-shard", &shard_path, source))?
                .is_dir()
        {
            return Err(corrupt("attempt-root-shard-shape"));
        }
        for record in fs::read_dir(&shard_path)
            .map_err(|source| io_error("read-attempt-root-records", &shard_path, source))?
        {
            let record = record
                .map_err(|source| io_error("read-attempt-root-record", &shard_path, source))?;
            let name = record.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| corrupt("attempt-root-record-name"))?;
            if name.starts_with('.') && is_staging_name(name) {
                if !record
                    .file_type()
                    .map_err(|source| {
                        io_error(
                            "stat-attempt-root-migration-staging",
                            &record.path(),
                            source,
                        )
                    })?
                    .is_file()
                {
                    return Err(corrupt("attempt-root-migration-staging-shape"));
                }
                continue;
            }
            if !is_lower_hex(name, 64)
                || !record
                    .file_type()
                    .map_err(|source| io_error("stat-attempt-root-record", &record.path(), source))?
                    .is_file()
            {
                return Err(corrupt("attempt-root-record-shape"));
            }
            if paths.len() == maximum {
                return Err(corrupt("attempt-record-migration-limit"));
            }
            paths.push(record.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
