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
}

#[derive(Clone, Copy)]
pub(super) struct FileRepackStagePaths<'a> {
    pub(super) pack: &'a Path,
    pub(super) blob_index: &'a Path,
    pub(super) file_artifact_index: &'a Path,
    pub(super) parse_artifact_index: &'a Path,
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
        _ => {
            debug_assert!(
                index <= FILE_REPACK_PARSE_ARTIFACT_REPLACEMENT,
                "unexpected file repack replacement index {index}"
            );
            PersistFileBlobPackRepackError::ParseArtifactIndex {
                source: PersistParseArtifactIndexError::Write { path, source },
            }
        }
    }
}
