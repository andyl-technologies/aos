//! Blob-pack liveness, relocation, and repack helper routines.

use super::*;

use ratchet_cache::file_replace::{FileReplacement, FileReplacementError, FileReplacementSet};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn push_blob_index_roots(
    roots: &mut Vec<PersistBlobLiveRoot>,
    entries: Vec<PersistBlobIndexEntry>,
    expected_store: PersistBlobStore,
    source: PersistBlobLiveRootSource,
) -> Result<(), PersistBlobLiveRootError> {
    for entry in entries {
        let key = entry.key();
        let actual_store = key.store();
        if actual_store != expected_store {
            return Err(PersistBlobLiveRootError::WrongStoreEntry {
                expected: expected_store,
                actual: actual_store,
            });
        }
        roots.push(PersistBlobLiveRoot::new(source, key, entry.location()));
    }
    Ok(())
}

pub(super) fn blob_record_identity(
    key: PersistBlobKey,
    location: PersistBlobLocation,
) -> ([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64) {
    (
        key.index_bytes(),
        location.record_offset(),
        location.payload_len(),
    )
}

pub(super) fn blob_live_root_identity(
    root: PersistBlobLiveRoot,
) -> ([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64) {
    blob_record_identity(root.key(), root.location())
}

pub(super) const fn blob_record_bytes(record: PersistBlobPackRecord) -> u64 {
    PERSIST_BLOB_RECORD_HEADER_LEN as u64 + record.location().payload_len()
}

pub(super) fn blob_pack_repack_plan_from_liveness(
    store: PersistBlobStore,
    liveness: PersistBlobPackLivenessPlan,
) -> Result<PersistBlobPackRepackPlan, PersistBlobPackRepackPlanError> {
    let mut next_offset = PERSIST_BLOB_PACK_HEADER_LEN as u64;
    let mut record_relocations = Vec::new();
    for record in liveness.rooted_records() {
        let new_location = PersistBlobLocation::new(next_offset, record.location().payload_len());
        record_relocations.push(PersistBlobRecordRelocation::new(
            record.key(store),
            record.location(),
            new_location,
        ));
        let after_header = next_offset
            .checked_add(PERSIST_BLOB_RECORD_HEADER_LEN as u64)
            .ok_or(PersistBlobPackRepackPlanError::RecordBoundsOverflow {
                record_offset: next_offset,
                payload_len: record.location().payload_len(),
            })?;
        next_offset = after_header
            .checked_add(record.location().payload_len())
            .ok_or(PersistBlobPackRepackPlanError::RecordBoundsOverflow {
                record_offset: next_offset,
                payload_len: record.location().payload_len(),
            })?;
    }
    Ok(PersistBlobPackRepackPlan::new(
        liveness.live_roots().to_vec(),
        record_relocations,
        liveness.unrooted_records().to_vec(),
        liveness.bytes_before(),
        next_offset,
        liveness.rooted_record_bytes(),
        liveness.unrooted_record_bytes(),
    ))
}

pub(super) fn write_repacked_blob_index(
    tmp_path: &Path,
    relocations: &[PersistBlobRecordRelocation],
) -> Result<(), PersistBlobIndexError> {
    let mut entries = relocations
        .iter()
        .map(|relocation| PersistBlobIndexEntry::new(relocation.key(), relocation.new_location()))
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.key().index_bytes());
    PersistBlobIndex::write_entries_to(tmp_path, &entries)?;
    Ok(())
}

pub(super) fn file_relocation_locations(
    relocations: &[PersistBlobRecordRelocation],
) -> BTreeMap<([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64), PersistBlobLocation> {
    relocations
        .iter()
        .map(|relocation| {
            (
                blob_record_identity(relocation.key(), relocation.old_location()),
                relocation.new_location(),
            )
        })
        .collect()
}

pub(super) fn relocate_file_artifact_entries(
    entries: Vec<PersistFileArtifactIndexEntry>,
    relocations: &BTreeMap<([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64), PersistBlobLocation>,
) -> Result<Vec<PersistFileArtifactIndexEntry>, PersistFileBlobPackRepackError> {
    entries
        .into_iter()
        .map(|entry| {
            let value = entry.value();
            let key = value.blob_key();
            let location = value.location();
            let Some(new_location) = relocations
                .get(&blob_record_identity(key, location))
                .copied()
            else {
                return Err(PersistFileBlobPackRepackError::MissingRelocation { key, location });
            };
            Ok(PersistFileArtifactIndexEntry::new(
                entry.key(),
                PersistFileArtifactIndexValue::new(value.blob_hash(), new_location),
            ))
        })
        .collect()
}

pub(super) fn relocate_parse_artifact_entries(
    entries: Vec<PersistParseArtifactIndexEntry>,
    relocations: &BTreeMap<([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64), PersistBlobLocation>,
) -> Result<Vec<PersistParseArtifactIndexEntry>, PersistFileBlobPackRepackError> {
    entries
        .into_iter()
        .map(|entry| {
            let value = entry.value();
            let key = value.blob_key();
            let location = value.location();
            let Some(new_location) = relocations
                .get(&blob_record_identity(key, location))
                .copied()
            else {
                return Err(PersistFileBlobPackRepackError::MissingRelocation { key, location });
            };
            Ok(PersistParseArtifactIndexEntry::new(
                entry.key(),
                PersistParseArtifactIndexValue::new(value.blob_hash(), new_location),
            ))
        })
        .collect()
}

/// Rewrites root-record index entries against a planned file-pack relocation.
///
/// Every newest root-record entry is re-pointed at its record blob's new pack
/// location. Matching prefers the exact `(hash, old location)` relocation
/// identity; an entry whose embedded location is already stale (written before
/// root-record relocation support existed) falls back to matching the planned
/// relocations by content hash alone, which is unambiguous because the
/// compacted pack holds one record per hash. Entries whose record blob is not
/// relocated at all reference a dead blob and are dropped — the record could
/// never hydrate again anyway.
pub(super) fn relocate_root_record_entries(
    entries: Vec<PersistRootRecordIndexEntry>,
    relocations: &[PersistBlobRecordRelocation],
) -> Vec<PersistRootRecordIndexEntry> {
    let by_identity = file_relocation_locations(relocations);
    let mut by_hash = BTreeMap::new();
    for relocation in relocations {
        by_hash.insert(relocation.key().index_bytes(), relocation.new_location());
    }
    entries
        .into_iter()
        .filter_map(|entry| {
            let value = entry.value();
            let key = value.blob_key();
            let new_location = by_identity
                .get(&blob_record_identity(key, value.location()))
                .or_else(|| by_hash.get(&key.index_bytes()))
                .copied()?;
            Some(PersistRootRecordIndexEntry::new(
                entry.key(),
                PersistRootRecordIndexValue::new(value.blob_hash(), new_location),
            ))
        })
        .collect()
}

pub(super) fn write_repacked_root_record_index(
    tmp_path: &Path,
    entries: &[PersistRootRecordIndexEntry],
) -> Result<(), PersistRootRecordIndexError> {
    PersistRootRecordIndex::write_entries_to(tmp_path, entries)?;
    Ok(())
}

pub(super) fn write_repacked_file_artifact_index(
    tmp_path: &Path,
    entries: &[PersistFileArtifactIndexEntry],
) -> Result<(), PersistFileArtifactIndexError> {
    PersistFileArtifactIndex::write_entries_to(tmp_path, entries)?;
    Ok(())
}

pub(super) fn write_repacked_parse_artifact_index(
    tmp_path: &Path,
    entries: &[PersistParseArtifactIndexEntry],
) -> Result<(), PersistParseArtifactIndexError> {
    PersistParseArtifactIndex::write_entries_to(tmp_path, entries)?;
    Ok(())
}

pub(super) fn swap_repacked_value_store(
    replacements: &FileReplacementSet,
) -> Result<(), PersistValueBlobPackRepackError> {
    replacements
        .replace_all()
        .map_err(value_repack_replacement_error_to_persist)
}

const VALUE_REPACK_PACK_REPLACEMENT: usize = 0;
const VALUE_REPACK_INDEX_REPLACEMENT: usize = 1;

pub(super) fn value_repack_replacements(
    pack_path: &Path,
    index_path: &Path,
    tmp_pack_path: &Path,
    tmp_index_path: &Path,
    rewrite_id: u64,
) -> FileReplacementSet {
    FileReplacementSet::new([
        FileReplacement::new(
            pack_path.to_path_buf(),
            tmp_pack_path.to_path_buf(),
            pack_path.with_extension(format!(
                "repack-backup-pack-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            index_path.to_path_buf(),
            tmp_index_path.to_path_buf(),
            index_path.with_extension(format!(
                "repack-backup-index-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
    ])
}

fn value_repack_replacement_error_to_persist(
    error: FileReplacementError,
) -> PersistValueBlobPackRepackError {
    match error {
        FileReplacementError::RemoveBackup {
            index,
            path,
            source,
        } => value_repack_file_error(index, path, source),
        FileReplacementError::BackupTarget {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::InstallStaged {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::RemoveTargetBeforeRestore {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::RestoreBackup {
            index,
            target: path,
            source,
            ..
        } => value_repack_file_error(index, path, source),
    }
}

fn value_repack_file_error(
    index: usize,
    path: PathBuf,
    source: io::Error,
) -> PersistValueBlobPackRepackError {
    match index {
        VALUE_REPACK_PACK_REPLACEMENT => PersistValueBlobPackRepackError::Pack {
            source: PersistBlobPackError::Write { path, source },
        },
        VALUE_REPACK_INDEX_REPLACEMENT => PersistValueBlobPackRepackError::BlobIndex {
            source: PersistBlobIndexError::Write { path, source },
        },
        _ => PersistValueBlobPackRepackError::BlobIndex {
            source: PersistBlobIndexError::Write { path, source },
        },
    }
}

#[derive(Clone, Copy)]
pub(super) struct FileRepackPaths<'a> {
    pub(super) pack: &'a Path,
    pub(super) blob_index: &'a Path,
    pub(super) file_artifact_index: &'a Path,
    pub(super) parse_artifact_index: &'a Path,
    pub(super) root_record_index: &'a Path,
}

#[derive(Clone, Copy)]
pub(super) struct FileRepackStagePaths<'a> {
    pub(super) pack: &'a Path,
    pub(super) blob_index: &'a Path,
    pub(super) file_artifact_index: &'a Path,
    pub(super) parse_artifact_index: &'a Path,
    pub(super) root_record_index: &'a Path,
}

pub(super) fn swap_repacked_file_store(
    replacements: &FileReplacementSet,
) -> Result<(), PersistFileBlobPackRepackError> {
    replacements
        .replace_all()
        .map_err(file_repack_replacement_error_to_persist)
}

const FILE_REPACK_PACK_REPLACEMENT: usize = 0;
const FILE_REPACK_BLOB_INDEX_REPLACEMENT: usize = 1;
const FILE_REPACK_FILE_ARTIFACT_REPLACEMENT: usize = 2;
const FILE_REPACK_PARSE_ARTIFACT_REPLACEMENT: usize = 3;
const FILE_REPACK_ROOT_RECORD_REPLACEMENT: usize = 4;

pub(super) fn file_repack_replacements(
    paths: FileRepackPaths<'_>,
    stage: FileRepackStagePaths<'_>,
    rewrite_id: u64,
) -> FileReplacementSet {
    FileReplacementSet::new([
        FileReplacement::new(
            paths.pack.to_path_buf(),
            stage.pack.to_path_buf(),
            paths.pack.with_extension(format!(
                "repack-backup-pack-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            paths.blob_index.to_path_buf(),
            stage.blob_index.to_path_buf(),
            paths.blob_index.with_extension(format!(
                "repack-backup-index-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            paths.file_artifact_index.to_path_buf(),
            stage.file_artifact_index.to_path_buf(),
            paths.file_artifact_index.with_extension(format!(
                "repack-backup-file-artifacts-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            paths.parse_artifact_index.to_path_buf(),
            stage.parse_artifact_index.to_path_buf(),
            paths.parse_artifact_index.with_extension(format!(
                "repack-backup-parse-artifacts-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            paths.root_record_index.to_path_buf(),
            stage.root_record_index.to_path_buf(),
            paths.root_record_index.with_extension(format!(
                "repack-backup-root-records-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
    ])
}

fn file_repack_replacement_error_to_persist(
    error: FileReplacementError,
) -> PersistFileBlobPackRepackError {
    match error {
        FileReplacementError::RemoveBackup {
            index,
            path,
            source,
        } => file_repack_file_error(index, path, source),
        FileReplacementError::BackupTarget {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::InstallStaged {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::RemoveTargetBeforeRestore {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::RestoreBackup {
            index,
            target: path,
            source,
            ..
        } => file_repack_file_error(index, path, source),
    }
}

fn file_repack_file_error(
    index: usize,
    path: PathBuf,
    source: io::Error,
) -> PersistFileBlobPackRepackError {
    match index {
        FILE_REPACK_PACK_REPLACEMENT => PersistFileBlobPackRepackError::Pack {
            source: PersistBlobPackError::Write { path, source },
        },
        FILE_REPACK_BLOB_INDEX_REPLACEMENT => PersistFileBlobPackRepackError::BlobIndex {
            source: PersistBlobIndexError::Write { path, source },
        },
        FILE_REPACK_FILE_ARTIFACT_REPLACEMENT => {
            PersistFileBlobPackRepackError::FileArtifactIndex {
                source: PersistFileArtifactIndexError::Write { path, source },
            }
        }
        FILE_REPACK_PARSE_ARTIFACT_REPLACEMENT => {
            PersistFileBlobPackRepackError::ParseArtifactIndex {
                source: PersistParseArtifactIndexError::Write { path, source },
            }
        }
        FILE_REPACK_ROOT_RECORD_REPLACEMENT => PersistFileBlobPackRepackError::RootRecordIndex {
            source: PersistRootRecordIndexError::Write { path, source },
        },
        _ => {
            debug_assert!(
                index <= FILE_REPACK_ROOT_RECORD_REPLACEMENT,
                "unexpected file repack replacement index {index}"
            );
            PersistFileBlobPackRepackError::RootRecordIndex {
                source: PersistRootRecordIndexError::Write { path, source },
            }
        }
    }
}
