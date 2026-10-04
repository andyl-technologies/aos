//! Durable transfer-journal filesystem operations.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use crucible_cas::content_store::ContentId;

use super::{
    CampaignTransferJournalError, MAX_TRANSFER_RECORD_BYTES, MAX_TRANSFER_RECORDS,
    STAGING_DIRECTORY,
};

pub(super) fn encode_content_id(
    id: ContentId,
    bytes: &mut Vec<u8>,
) -> Result<(), CampaignTransferJournalError> {
    let encoded = id.encode();
    let length = u32::try_from(encoded.len()).map_err(|_| CampaignTransferJournalError::Corrupt)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(encoded.as_bytes());
    Ok(())
}

pub(super) fn read_bounded_file(path: &Path) -> Result<Vec<u8>, CampaignTransferJournalError> {
    let file = File::open(path).map_err(|source| io_error("open-transfer-record", path, source))?;
    let length = file
        .metadata()
        .map_err(|source| io_error("stat-transfer-record", path, source))?
        .len();
    if length > MAX_TRANSFER_RECORD_BYTES {
        return Err(CampaignTransferJournalError::ObjectLimit);
    }
    let read_limit = MAX_TRANSFER_RECORD_BYTES
        .checked_add(1)
        .ok_or(CampaignTransferJournalError::ObjectLimit)?;
    let capacity = usize::try_from(length.min(read_limit))
        .map_err(|_| CampaignTransferJournalError::ObjectLimit)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-transfer-record", path, source))?;
    if bytes.len() as u64 > MAX_TRANSFER_RECORD_BYTES {
        return Err(CampaignTransferJournalError::ObjectLimit);
    }
    Ok(bytes)
}

pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CampaignTransferJournalError> {
    let root = path
        .parent()
        .and_then(Path::parent)
        .ok_or(CampaignTransferJournalError::Corrupt)?;
    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or(CampaignTransferJournalError::Corrupt)?;
    let temporary = root.join(STAGING_DIRECTORY).join(format!("{stem}.staging"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| io_error("create-transfer-staging", &temporary, source))?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(io_error("write-transfer-staging", &temporary, source));
    }
    fs::rename(&temporary, path)
        .map_err(|source| io_error("rename-transfer-record", path, source))?;
    sync_directory(path.parent().ok_or(CampaignTransferJournalError::Corrupt)?)?;
    sync_directory(&root.join(STAGING_DIRECTORY))
}

pub(super) fn create_journal_directory(path: &Path) -> Result<(), CampaignTransferJournalError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::metadata(path)
                .map_err(|source| io_error("stat-transfer-journal", path, source))?
                .is_dir()
            {
                return Err(CampaignTransferJournalError::UnexpectedEntry);
            }
        }
        Err(source) => return Err(io_error("create-transfer-journal", path, source)),
    }
    let parent = path.parent().ok_or(CampaignTransferJournalError::Corrupt)?;
    sync_directory(parent)
}

pub(super) fn create_child_directory(
    root: &Path,
    name: &str,
) -> Result<(), CampaignTransferJournalError> {
    let path = root.join(name);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::metadata(&path)
                .map_err(|source| io_error("stat-transfer-directory", &path, source))?
                .is_dir()
            {
                return Err(CampaignTransferJournalError::UnexpectedEntry);
            }
        }
        Err(source) => return Err(io_error("create-transfer-directory", &path, source)),
    }
    sync_directory(root)
}

pub(super) fn cleanup_staging(path: &Path) -> Result<(), CampaignTransferJournalError> {
    let mut entries = 0_usize;
    for entry in
        fs::read_dir(path).map_err(|source| io_error("read-transfer-staging", path, source))?
    {
        entries = entries
            .checked_add(1)
            .ok_or(CampaignTransferJournalError::RecordLimit)?;
        if entries > MAX_TRANSFER_RECORDS {
            return Err(CampaignTransferJournalError::RecordLimit);
        }
        let entry = entry.map_err(|source| io_error("read-transfer-staging", path, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CampaignTransferJournalError::UnexpectedEntry)?;
        let valid_name = name.strip_suffix(".staging").is_some_and(|stem| {
            stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        if !valid_name
            || !entry
                .file_type()
                .map_err(|source| io_error("stat-transfer-staging", &entry.path(), source))?
                .is_file()
        {
            return Err(CampaignTransferJournalError::UnexpectedEntry);
        }
        fs::remove_file(entry.path())
            .map_err(|source| io_error("remove-transfer-staging", path, source))?;
    }
    if entries != 0 {
        sync_directory(path)?;
    }
    Ok(())
}

pub(super) fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

pub(super) fn sync_directory(path: &Path) -> Result<(), CampaignTransferJournalError> {
    #[cfg(test)]
    if super::FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.replace(false)) {
        return Err(io_error(
            "sync-transfer-directory",
            path,
            io::Error::other("injected directory sync failure"),
        ));
    }
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync-transfer-directory", path, source))
}

#[cfg(test)]
pub(super) fn fail_next_directory_sync() {
    super::FAIL_NEXT_DIRECTORY_SYNC.with(|fail| fail.set(true));
}

pub(super) fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> CampaignTransferJournalError {
    CampaignTransferJournalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
