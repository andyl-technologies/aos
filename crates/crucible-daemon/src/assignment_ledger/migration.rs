//! Explicit one-way migration of legacy assignment attempt records.
//!
//! This module is reachable only from the stopped-daemon operator migration.
//! Normal execution and restart decoding remain confined to v15.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use crate::OperationalStateMigrationError;
use crate::anchored_fs::{AnchoredDirectory, AnchoredFile};
use crate::operational_state_migration::receipt::{
    ASSIGNMENT_RECEIPT, MigrationObjectReceipt, authenticated_id, load_phase_receipt,
    persist_phase_receipt,
};

use super::codec::*;
use super::*;

pub(super) fn decode_migratable_attempt_state(
    bytes: &[u8],
) -> Result<(AttemptExecutionKey, AttemptRuntimeState), AssignmentLedgerError> {
    let current = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN)
        .ok()
        .map(|payload| (15, payload, ATTEMPT_STATE_MAGIC.to_vec()));
    let legacy = (1..=14).rev().find_map(|version| {
        let domain = format!("crucible.executor.attempt-state-record.v{version}");
        let mut magic = domain.as_bytes().to_vec();
        magic.push(0);
        open_sealed(bytes, &domain)
            .ok()
            .map(|payload| (version, payload, magic))
    });
    let (version, payload, magic) = current
        .or(legacy)
        .ok_or_else(|| corrupt("attempt-state-checksum"))?;
    let mut cursor = RecordCursor::new(payload);
    cursor.require(&magic)?;
    let lineage = parse_typed(cursor.bytes()?, CampaignLineageId::parse)?;
    let attempt = parse_typed(cursor.bytes()?, AttemptId::parse)?;
    let scope = if version >= 11 {
        AttemptExecutionScope::from_canonical_bytes(cursor.bytes()?)?
    } else {
        AttemptExecutionScope::Semantic
    };
    let execution_basis = CampaignHash::from_bytes(cursor.fixed()?);
    let origin = if version >= 4 {
        decode_attempt_origin(&mut cursor, version >= 12)?
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
            let finding_candidate = decode_legacy_optional_finding_candidate(&mut cursor, version)?;
            let finding_candidate_acknowledged = if version >= 9 {
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
                prepared_result_digest: if version >= 15 {
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
        8 if version >= 7 => AttemptRuntimeState::TerminalFailure {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        3 if version >= 2 => AttemptRuntimeState::Publishing {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            observation: parse_typed(cursor.bytes()?, ObservationId::parse)?,
            finding_candidate: decode_legacy_optional_finding_candidate(&mut cursor, version)?,
            finding_replay_captures: if version >= 13 {
                decode_optional_finding_replay_captures(&mut cursor)?
            } else {
                None
            },
            finding_exact_retention_roots: if version >= 14 {
                decode_finding_exact_retention_roots(&mut cursor)?
            } else {
                [None; MAX_PUBLISHING_FINDING_EXACT_ROOTS]
            },
            prepared_result_digest: if version >= 14 {
                decode_optional_campaign_hash(&mut cursor)?
            } else {
                None
            },
        },
        4 if version >= 3 => AttemptRuntimeState::CheckpointRequested {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        5 if version >= 3 => AttemptRuntimeState::CheckpointPublishing {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
        },
        6 if version >= 3 => AttemptRuntimeState::Paused {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            promotion_basis: if version >= 6 {
                decode_checkpoint_promotion_basis(
                    &mut cursor,
                    version >= 10,
                    version >= 11,
                    version >= 12,
                )?
            } else {
                None
            },
        },
        7 if version >= 5 => AttemptRuntimeState::CheckpointPromoting {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            source_checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            promoted_checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            promotion_basis: if version >= 6 {
                decode_checkpoint_promotion_basis(
                    &mut cursor,
                    version >= 10,
                    version >= 11,
                    version >= 12,
                )?
            } else {
                None
            },
        },
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
    version: u8,
) -> Result<Option<FindingCandidateBundleId>, AssignmentLedgerError> {
    if version < 8 {
        return Ok(None);
    }
    decode_optional_finding_candidate(cursor)
}

#[derive(Debug)]
struct ValidatedAttemptMigration {
    path: PathBuf,
    source: AnchoredFile,
    current_bytes: Option<Vec<u8>>,
    staging: Option<StaleAttemptStaging>,
    receipt: MigrationObjectReceipt,
}

#[derive(Debug)]
struct StaleAttemptStaging {
    authority: AnchoredFile,
    receipt: MigrationObjectReceipt,
    destroyed: bool,
}

pub(super) fn migrate_attempt_records(
    ledger: &DirectoryAssignmentLedger,
    receipt_guard: &AnchoredDirectory,
    maximum_entries: usize,
    maximum_bytes: u64,
) -> Result<AssignmentMigrationSummary, OperationalStateMigrationError> {
    let root_guard = ledger.authority();
    let anchored_root = root_guard.anchored_path();
    let existing = load_phase_receipt(
        receipt_guard,
        ASSIGNMENT_RECEIPT,
        ATTEMPT_MIGRATION_OUTPUT_SCHEMA,
    )?;
    let mut inventory = AttemptInventory {
        records: Vec::new(),
        staging: Vec::new(),
        removals: Vec::new(),
    };
    visit_bounded_ledger_inventory(
        &anchored_root,
        usize::MAX,
        maximum_entries,
        maximum_bytes,
        true,
        None,
        &mut |entry| {
            match entry {
                AttemptInventoryEntry::Record(path) => inventory.records.push(path.to_owned()),
                AttemptInventoryEntry::Staging(path) => inventory.staging.push(path.to_owned()),
                AttemptInventoryEntry::Removal(path) => inventory.removals.push(path.to_owned()),
                AttemptInventoryEntry::Tombstone => {
                    return Err(corrupt("unexpected-attempt-migration-tombstone"));
                }
            }
            Ok(())
        },
    )?;
    inventory.records.sort();
    inventory.staging.sort();
    inventory.removals.sort();
    if !inventory.removals.is_empty() && existing.is_none() {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    let mut staging = BTreeMap::new();
    let mut stale_staging = Vec::new();
    for path in inventory.staging {
        let authority = root_guard
            .open_inventory_file(&path, "pin-attempt-migration-staging")?
            .ok_or_else(|| corrupt("attempt-staging-disappeared"))?;
        let bytes = authority.read_bounded(MAX_LEDGER_RECORD_BYTES)?;
        let Ok((key, state)) = decode_attempt_state(&bytes) else {
            stale_staging.push(staging_cleanup(&path, authority, &bytes)?);
            continue;
        };
        let destination = attempt_path_at(&anchored_root, key);
        if destination.parent() != path.parent()
            || staging
                .insert(destination, (path, authority, bytes, key, state))
                .is_some()
        {
            return Err(corrupt("attempt-staging-identity-mismatch").into());
        }
    }
    for path in inventory.removals {
        let authority = root_guard
            .open_inventory_file(&path, "pin-attempt-removal-state")?
            .ok_or_else(|| corrupt("attempt-removal-state-disappeared"))?;
        let bytes = authority.read_bounded(MAX_LEDGER_RECORD_BYTES)?;
        stale_staging.push(staging_cleanup(&path, authority, &bytes)?);
    }
    let mut records = Vec::with_capacity(inventory.records.len());

    // Authenticate every source before creating or replacing anything.
    for path in inventory.records {
        let source = root_guard
            .open_regular_optional(&path, "pin-attempt-migration-source")?
            .ok_or_else(|| corrupt("attempt-root-record-disappeared"))?;
        let bytes = source.read_bounded(MAX_LEDGER_RECORD_BYTES)?;
        let staged = staging.remove(&path);
        let recovered = decode_migratable_attempt_state(&bytes).is_err();
        let (key, state) = if recovered {
            let Some((_, _, _, key, state)) = &staged else {
                return Err(corrupt("attempt-state-migration-source-corrupt").into());
            };
            (*key, state.clone())
        } else {
            decode_migratable_attempt_state(&bytes)?
        };
        if attempt_path_at(&anchored_root, key) != path {
            return Err(corrupt("attempt-root-record-path-identity-mismatch").into());
        }
        let current_bytes = match decode_attempt_state(&bytes) {
            Ok((current_key, current_state)) if current_key == key && current_state == state => {
                None
            }
            Ok(_) => return Err(corrupt("attempt-state-migration-current-mismatch").into()),
            Err(_) => Some(encode_attempt_state(key, state)),
        };
        if let Some((_, _, staged_bytes, staged_key, staged_state)) = &staged
            && (*staged_key != key
                || staged_state != &state
                || staged_bytes != current_bytes.as_ref().unwrap_or(&bytes))
        {
            return Err(corrupt("attempt-staging-output-mismatch").into());
        }
        let output = current_bytes.as_deref().unwrap_or(&bytes);
        let key = key.storage_digest().to_hex().to_string();
        let current_id = authenticated_id("crucible.assignment-migration-object.v1", &[&bytes]);
        let output_id = authenticated_id("crucible.assignment-migration-object.v1", &[output]);
        let source_id = existing
            .as_ref()
            .and_then(|receipt| receipt.objects.iter().find(|object| object.key == key))
            .map(|object| {
                if object.output_object_id != output_id
                    || (!recovered
                        && object.source_object_id != current_id
                        && output_id != current_id)
                {
                    Err(OperationalStateMigrationError::InvalidReceipt)
                } else {
                    Ok(object.source_object_id.clone())
                }
            })
            .transpose()?
            .unwrap_or(current_id);
        let staging = staged
            .map(|(staging_path, authority, staged_bytes, ..)| {
                staging_cleanup(&staging_path, authority, &staged_bytes)
            })
            .transpose()?;
        records.push(ValidatedAttemptMigration {
            path,
            source,
            current_bytes,
            staging,
            receipt: MigrationObjectReceipt {
                key,
                source_object_id: source_id,
                output_object_id: output_id,
            },
        });
    }
    if !staging.is_empty() {
        return Err(corrupt("attempt-staging-target-missing").into());
    }

    // Stage every replacement before sealing the receipt. A retry can therefore
    // authenticate every complete or partial staging file before any source is
    // replaced, including a file left by an interrupted create or write.
    for record in &mut records {
        let Some(bytes) = &record.current_bytes else {
            continue;
        };
        if record.staging.is_some() {
            continue;
        }
        if existing.is_some() {
            return Err(OperationalStateMigrationError::InvalidReceipt);
        }
        let directory = record
            .path
            .parent()
            .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
        let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".staging-{}-{ordinal}", std::process::id()));
        let mut file = root_guard.create_file(&path, "create-attempt-migration-staging")?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error("write-attempt-migration-staging", &path, source))?;
        root_guard.sync()?;
        let authority = root_guard
            .open_regular_optional(&path, "pin-created-attempt-staging")?
            .ok_or_else(|| corrupt("attempt-staging-disappeared"))?;
        record.staging = Some(staging_cleanup(&path, authority, bytes)?);
    }

    let mut receipt_objects = records
        .iter()
        .map(|record| record.receipt.clone())
        .collect::<Vec<_>>();
    let cleanups = stale_staging
        .iter()
        .chain(records.iter().filter_map(|record| record.staging.as_ref()));
    if let Some(existing) = &existing {
        for cleanup in cleanups {
            let prior = existing
                .objects
                .iter()
                .find(|object| object.key == cleanup.receipt.key);
            if !prior.is_some_and(|prior| {
                prior.output_object_id == cleanup.receipt.output_object_id
                    && (cleanup.destroyed || prior == &cleanup.receipt)
            }) {
                return Err(OperationalStateMigrationError::InvalidReceipt);
            }
        }
        receipt_objects.extend(
            existing
                .objects
                .iter()
                .filter(|object| object.key.starts_with("cleanup/"))
                .cloned(),
        );
    } else {
        receipt_objects.extend(stale_staging.iter().map(|stale| stale.receipt.clone()));
        receipt_objects.extend(
            records
                .iter()
                .filter_map(|record| record.staging.as_ref())
                .map(|staging| staging.receipt.clone()),
        );
    }
    receipt_objects.sort_by(|left, right| left.key.cmp(&right.key));
    let receipt = match existing {
        Some(existing) if existing.objects == receipt_objects => existing,
        Some(_) => return Err(OperationalStateMigrationError::InvalidReceipt),
        None => persist_phase_receipt(
            receipt_guard,
            ASSIGNMENT_RECEIPT,
            ATTEMPT_MIGRATION_OUTPUT_SCHEMA,
            receipt_objects,
        )?,
    };

    receipt.verify_path_binding()?;
    for stale in stale_staging {
        root_guard.remove_bound_file(&stale.authority, "remove-invalid-attempt-staging")?;
    }
    let migrated = records
        .iter()
        .filter(|record| record.current_bytes.is_some())
        .count();
    for record in &mut records {
        let Some(bytes) = &record.current_bytes else {
            if let Some(staging) = record.staging.take() {
                root_guard
                    .remove_bound_file(&staging.authority, "remove-completed-attempt-staging")?;
            }
            continue;
        };
        let staging = record
            .staging
            .take()
            .ok_or_else(|| corrupt("attempt-staging-without-current-output"))?;
        record.source.replace_contents(bytes)?;
        root_guard.remove_bound_file(&staging.authority, "remove-published-attempt-staging")?;
    }

    Ok(AssignmentMigrationSummary {
        records: records.len(),
        migrated,
        receipt,
    })
}

fn staging_cleanup(
    path: &std::path::Path,
    authority: AnchoredFile,
    bytes: &[u8],
) -> Result<StaleAttemptStaging, AssignmentLedgerError> {
    let destroyed = authority.removal_original_name().is_some() && bytes.is_empty();
    let logical_name = authority
        .removal_original_name()
        .or_else(|| path.file_name().map(ToOwned::to_owned))
        .ok_or_else(|| corrupt("attempt-staging-name-missing"))?;
    let shard = path
        .parent()
        .and_then(std::path::Path::file_name)
        .ok_or_else(|| corrupt("attempt-staging-shard-missing"))?;
    let (device, inode) = authority.identity();
    Ok(StaleAttemptStaging {
        authority,
        receipt: MigrationObjectReceipt {
            key: attempt_cleanup_key(shard, &logical_name, device, inode),
            source_object_id: authenticated_id(
                "crucible.assignment-migration-cleanup-source.v1",
                &[bytes],
            ),
            output_object_id: authenticated_id(
                "crucible.assignment-migration-cleanup-output.v1",
                &[b"absent"],
            ),
        },
        destroyed,
    })
}

struct AttemptInventory {
    records: Vec<PathBuf>,
    staging: Vec<PathBuf>,
    removals: Vec<PathBuf>,
}
