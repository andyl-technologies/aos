//! Authenticated provenance receipts for offline state rewrites.

use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::anchored_fs::{AnchoredDirectory, AnchoredFile};

use super::OperationalStateMigrationError;

pub(crate) const MIGRATION_TOOL_ID: &str = "crucible.store-repair.operational-state.v1";
const RECEIPT_SCHEMA: &str = "crucible.daemon.operational-state-migration-receipt.v1";
const RECEIPT_HASH_DOMAIN: &str = "crucible.daemon.operational-state-migration-receipt.v1";
const MAX_RECEIPT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const ACTIVE_MARKER: &str = ".operational-state-migration-v1";
const MARKER_MAGIC: &[u8] = b"crucible.daemon.operational-state-migration-marker.v1\0";
const MARKER_ACTIVE: u8 = 0;
const MARKER_COMPLETE: u8 = 1;
pub(crate) const ASSIGNMENT_RECEIPT: &str = "assignment-rewrite-v1.json";
pub(crate) const PREPARED_RECEIPT: &str = "prepared-result-rewrite-v1.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationObjectReceipt {
    pub key: String,
    pub source_object_id: String,
    pub output_object_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptBody {
    schema: String,
    migration_tool: String,
    output_schema: String,
    objects: Vec<MigrationObjectReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptEnvelope {
    body: ReceiptBody,
    checksum: String,
}

#[derive(Debug)]
pub(crate) struct PhaseReceipt {
    pub objects: Vec<MigrationObjectReceipt>,
    pub id: String,
    authority: AnchoredFile,
}

impl PhaseReceipt {
    pub(crate) fn verify_path_binding(&self) -> Result<(), OperationalStateMigrationError> {
        Ok(self.authority.verify_path_binding()?)
    }
}

pub(crate) struct ActiveMarker {
    authority: AnchoredFile,
    phase_offset: u64,
}

pub(crate) fn load_phase_receipt(
    directory: &AnchoredDirectory,
    name: &str,
    output_schema: &str,
) -> Result<Option<PhaseReceipt>, OperationalStateMigrationError> {
    let path = directory.path().join(name);
    let Some(authority) = directory.open_regular_optional(&path, "open-receipt")? else {
        return Ok(None);
    };
    let bytes = authority.read_bounded(MAX_RECEIPT_BYTES)?;
    let envelope: ReceiptEnvelope = serde_json::from_slice(&bytes)
        .map_err(|_| OperationalStateMigrationError::InvalidReceipt)?;
    let canonical = serde_json::to_vec(&envelope)
        .map_err(|_| OperationalStateMigrationError::InvalidReceipt)?;
    if bytes != canonical
        || envelope.body.schema != RECEIPT_SCHEMA
        || envelope.body.migration_tool != MIGRATION_TOOL_ID
        || envelope.body.output_schema != output_schema
        || !envelope
            .body
            .objects
            .windows(2)
            .all(|pair| pair[0].key < pair[1].key)
    {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    let body = serde_json::to_vec(&envelope.body)
        .map_err(|_| OperationalStateMigrationError::InvalidReceipt)?;
    let id = authenticated_id(RECEIPT_HASH_DOMAIN, &[&body]);
    if envelope.checksum != id {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    Ok(Some(PhaseReceipt {
        objects: envelope.body.objects,
        id,
        authority,
    }))
}

pub(crate) fn persist_phase_receipt(
    directory: &AnchoredDirectory,
    name: &str,
    output_schema: &str,
    mut objects: Vec<MigrationObjectReceipt>,
) -> Result<PhaseReceipt, OperationalStateMigrationError> {
    objects.sort_by(|left, right| left.key.cmp(&right.key));
    if objects.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    let body = ReceiptBody {
        schema: RECEIPT_SCHEMA.to_owned(),
        migration_tool: MIGRATION_TOOL_ID.to_owned(),
        output_schema: output_schema.to_owned(),
        objects,
    };
    let body_bytes =
        serde_json::to_vec(&body).map_err(|_| OperationalStateMigrationError::InvalidReceipt)?;
    let id = authenticated_id(RECEIPT_HASH_DOMAIN, &[&body_bytes]);
    let bytes = serde_json::to_vec(&ReceiptEnvelope {
        body: body.clone(),
        checksum: id.clone(),
    })
    .map_err(|_| OperationalStateMigrationError::InvalidReceipt)?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    let path = directory.path().join(name);
    directory.write_once(&path, &bytes)?;
    let authority = directory
        .open_regular_optional(&path, "pin-receipt")?
        .ok_or(OperationalStateMigrationError::InvalidReceipt)?;
    Ok(PhaseReceipt {
        objects: body.objects,
        id,
        authority,
    })
}

pub(crate) fn prepare_receipt_directory(
    directory: &Path,
) -> Result<AnchoredDirectory, OperationalStateMigrationError> {
    match fs::create_dir(directory) {
        Ok(()) => sync_parent(directory)?,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(directory)
                .map_err(|source| receipt_io("inspect-directory", directory, source))?
                .file_type()
                .is_dir()
            {
                return Err(OperationalStateMigrationError::InvalidReceipt);
            }
        }
        Err(source) => return Err(receipt_io("create-directory", directory, source)),
    }
    let guard = AnchoredDirectory::new(directory.to_owned())?;
    reconcile_receipt_directory(&guard)?;
    Ok(guard)
}

fn reconcile_receipt_directory(
    directory: &AnchoredDirectory,
) -> Result<(), OperationalStateMigrationError> {
    let mut pending = Vec::new();
    let mut entries = 0usize;
    let valid = [ASSIGNMENT_RECEIPT, PREPARED_RECEIPT];
    let anchored = directory.anchored_path();
    for entry in
        fs::read_dir(&anchored).map_err(|source| receipt_io("read-directory", &anchored, source))?
    {
        let entry =
            entry.map_err(|source| receipt_io("read-directory-entry", &anchored, source))?;
        entries += 1;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(OperationalStateMigrationError::InvalidReceipt)?
            .to_owned();
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|source| receipt_io("inspect-directory-entry", &entry.path(), source))?;
        if entries > 4 || !metadata.is_file() || metadata.len() > MAX_RECEIPT_BYTES {
            return Err(OperationalStateMigrationError::InvalidReceipt);
        }
        if valid.contains(&name.as_str()) {
            continue;
        }
        if valid
            .iter()
            .any(|receipt| name == format!(".{receipt}.pending"))
        {
            let authority = directory
                .open_regular_optional(&entry.path(), "pin-pending-receipt")?
                .ok_or(OperationalStateMigrationError::InvalidReceipt)?;
            pending.push(authority);
        } else {
            return Err(OperationalStateMigrationError::InvalidReceipt);
        }
    }
    for authority in pending {
        directory.remove_bound_file(&authority, "remove-pending")?;
    }
    Ok(directory.sync()?)
}

pub(crate) fn activate_marker(
    root: &AnchoredDirectory,
    receipt_directory: &AnchoredDirectory,
    assignment_ledger: &Path,
    prepared_results: &Path,
) -> Result<ActiveMarker, OperationalStateMigrationError> {
    receipt_directory.verify_path_binding()?;
    let path = root.path().join(ACTIVE_MARKER);
    let active = marker_bytes(
        receipt_directory.path(),
        assignment_ledger,
        prepared_results,
        MARKER_ACTIVE,
    )?;
    let complete = marker_bytes(
        receipt_directory.path(),
        assignment_ledger,
        prepared_results,
        MARKER_COMPLETE,
    )?;
    let authority = match root.open_regular_optional(&path, "open-marker")? {
        Some(authority) => authority,
        None => {
            root.write_once(&path, &active)?;
            root.open_regular_optional(&path, "pin-marker")?
                .ok_or(OperationalStateMigrationError::InvalidReceipt)?
        }
    };
    let bytes = authority.read_bounded(MAX_RECEIPT_BYTES)?;
    if bytes == complete {
        authority.write_byte((bytes.len() - 1) as u64, MARKER_ACTIVE)?;
    } else if bytes != active {
        return Err(OperationalStateMigrationError::InvalidReceipt);
    }
    authority.verify_path_binding()?;
    Ok(ActiveMarker {
        authority,
        phase_offset: (active.len() - 1) as u64,
    })
}

pub(crate) fn finish_marker(
    marker: &ActiveMarker,
    receipt_directory: &AnchoredDirectory,
) -> Result<(), OperationalStateMigrationError> {
    receipt_directory.verify_path_binding()?;
    Ok(marker
        .authority
        .write_byte(marker.phase_offset, MARKER_COMPLETE)?)
}

pub(crate) fn marker_present_guarded(root: &AnchoredDirectory) -> std::io::Result<bool> {
    let path = root.path().join(ACTIVE_MARKER);
    match root.open_regular_optional(&path, "open-marker") {
        Ok(Some(marker)) => marker
            .read_bounded(MAX_RECEIPT_BYTES)
            .map_err(receipt_error_as_io)
            .and_then(|bytes| marker_is_active(&bytes)),
        Ok(None) => Ok(false),
        Err(error) => Err(receipt_error_as_io(error)),
    }
}

pub(crate) fn authenticated_id(domain: &str, parts: &[&[u8]]) -> String {
    let key = blake3::derive_key(domain, domain.as_bytes());
    let mut hasher = blake3::Hasher::new_keyed(&key);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn combined_receipt_id(assignment: &str, prepared: &str) -> String {
    authenticated_id(
        "crucible.daemon.operational-state-migration-bundle.v1",
        &[assignment.as_bytes(), prepared.as_bytes()],
    )
}

fn marker_bytes(
    receipt_directory: &Path,
    assignment_ledger: &Path,
    prepared_results: &Path,
    phase: u8,
) -> Result<Vec<u8>, OperationalStateMigrationError> {
    let paths = [receipt_directory, assignment_ledger, prepared_results];
    let mut bytes = Vec::with_capacity(MARKER_MAGIC.len() + 3 * 128 + 33);
    bytes.extend_from_slice(MARKER_MAGIC);
    for path in paths {
        let path = path.as_os_str().as_bytes();
        let length = u32::try_from(path.len())
            .map_err(|_| OperationalStateMigrationError::InvalidReceipt)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(path);
    }
    let checksum = blake3::derive_key(RECEIPT_HASH_DOMAIN, &bytes);
    bytes.extend_from_slice(&checksum);
    bytes.push(phase);
    Ok(bytes)
}

fn marker_is_active(bytes: &[u8]) -> std::io::Result<bool> {
    if bytes.len() < MARKER_MAGIC.len() + 3 * 4 + 33 || !bytes.starts_with(MARKER_MAGIC) {
        return Err(invalid_marker());
    }
    let mut offset = MARKER_MAGIC.len();
    for _ in 0..3 {
        let length = u32::from_be_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or_else(invalid_marker)?
                .try_into()
                .map_err(|_| invalid_marker())?,
        ) as usize;
        offset = offset.checked_add(4 + length).ok_or_else(invalid_marker)?;
        if offset > bytes.len() {
            return Err(invalid_marker());
        }
    }
    let checksum_offset = offset;
    if checksum_offset.checked_add(33) != Some(bytes.len()) {
        return Err(invalid_marker());
    }
    let expected = blake3::derive_key(RECEIPT_HASH_DOMAIN, &bytes[..checksum_offset]);
    if bytes[checksum_offset..checksum_offset + 32] != expected {
        return Err(invalid_marker());
    }
    match bytes[checksum_offset + 32] {
        MARKER_ACTIVE => Ok(true),
        MARKER_COMPLETE => Ok(false),
        _ => Err(invalid_marker()),
    }
}

fn invalid_marker() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid migration marker")
}

fn receipt_error_as_io(error: crate::anchored_fs::AnchoredFsError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

fn sync_parent(path: &Path) -> Result<(), OperationalStateMigrationError> {
    let parent = path
        .parent()
        .ok_or(OperationalStateMigrationError::InvalidReceipt)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| receipt_io("sync-directory", parent, source))
}

fn receipt_io(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> OperationalStateMigrationError {
    OperationalStateMigrationError::ReceiptIo {
        operation,
        path: PathBuf::from(path),
        source,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn receipt_authentication_rejects_tamper_and_symlink_reuse() {
        for kind in ["tampered", "symlink"] {
            let parent = TempDir::new().expect("parent");
            let receipt = parent.path().join("receipt");
            let guard = prepare_receipt_directory(&receipt).expect("prepare receipt directory");
            persist_phase_receipt(
                &guard,
                ASSIGNMENT_RECEIPT,
                "test.output.v1",
                vec![MigrationObjectReceipt {
                    key: "key".to_owned(),
                    source_object_id: "source".to_owned(),
                    output_object_id: "output".to_owned(),
                }],
            )
            .expect("persist receipt");
            let path = receipt.join(ASSIGNMENT_RECEIPT);
            if kind == "tampered" {
                fs::write(&path, b"{}").expect("tamper receipt");
            } else {
                fs::remove_file(&path).expect("remove receipt");
                symlink("missing-receipt", &path).expect("symlink receipt");
            }

            assert!(matches!(
                load_phase_receipt(&guard, ASSIGNMENT_RECEIPT, "test.output.v1"),
                Err(OperationalStateMigrationError::InvalidReceipt)
                    | Err(OperationalStateMigrationError::ReceiptIo { .. })
            ));
        }
    }

    #[test]
    fn pinned_receipt_and_marker_reject_same_bytes_at_replacement_inodes() {
        let root = TempDir::new().expect("root");
        let receipt_parent = TempDir::new().expect("receipt parent");
        let receipt_path = receipt_parent.path().join("receipt");
        let root_guard = AnchoredDirectory::new(root.path().to_owned()).expect("guard root");
        let receipt_guard = prepare_receipt_directory(&receipt_path).expect("receipt directory");
        let receipt = persist_phase_receipt(
            &receipt_guard,
            ASSIGNMENT_RECEIPT,
            "test.output.v1",
            Vec::new(),
        )
        .expect("receipt");
        let receipt_name = receipt_path.join(ASSIGNMENT_RECEIPT);
        let moved_receipt = receipt_path.join("moved-receipt");
        fs::rename(&receipt_name, &moved_receipt).expect("move receipt");
        fs::copy(&moved_receipt, &receipt_name).expect("replace receipt with same bytes");
        assert!(receipt.verify_path_binding().is_err());

        let marker = activate_marker(
            &root_guard,
            &receipt_guard,
            root.path(),
            receipt_parent.path(),
        )
        .expect("active marker");
        let marker_name = root.path().join(ACTIVE_MARKER);
        let moved_marker = root.path().join("moved-marker");
        fs::rename(&marker_name, &moved_marker).expect("move marker");
        fs::copy(&moved_marker, &marker_name).expect("replace marker with same bytes");
        assert!(finish_marker(&marker, &receipt_guard).is_err());
        assert!(marker_present_guarded(&root_guard).expect("replacement remains active"));
    }

    #[test]
    fn marker_reader_rejects_nonregular_symlink_and_bad_authentication() {
        for kind in ["directory", "symlink", "tampered"] {
            let root = TempDir::new().expect("root");
            let marker = root.path().join(ACTIVE_MARKER);
            match kind {
                "directory" => fs::create_dir(&marker).expect("marker directory"),
                "symlink" => symlink("missing-marker", &marker).expect("marker symlink"),
                "tampered" => fs::write(&marker, b"bad marker").expect("marker bytes"),
                _ => unreachable!(),
            }

            let guard = AnchoredDirectory::new(root.path().to_owned()).expect("guard root");
            assert!(marker_present_guarded(&guard).is_err());
        }
    }
}
