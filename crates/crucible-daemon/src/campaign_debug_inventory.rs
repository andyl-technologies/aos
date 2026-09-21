//! Durable owner inventory for campaign-derived debug sessions.
//!
//! The inventory retains the complete authenticated campaign request and
//! finding response needed to reconstruct a lifecycle session after daemon
//! restart. It is a current-only owner file under the campaign state lock; live
//! actor and session identifiers remain in the shared lifecycle registry.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crucible_campaign::GetCampaignFindingObjectResponse;
use thiserror::Error;

use crate::OpenCampaignDebugSessionRequest;

const MAGIC: &[u8; 8] = b"CRCDSI01";
const VERSION: u32 = 1;
const MAX_RECORDS: usize = 64;
const MAX_FILE_BYTES: usize = 256 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 128 * 1024 * 1024;

/// One durable authenticated debug-session recovery basis.
#[derive(Clone)]
pub(crate) struct CampaignDebugSessionInventoryRecord {
    request: OpenCampaignDebugSessionRequest,
    finding: GetCampaignFindingObjectResponse,
}

impl CampaignDebugSessionInventoryRecord {
    /// Returns the exact authenticated open request retained for recovery.
    pub(crate) const fn request(&self) -> &OpenCampaignDebugSessionRequest {
        &self.request
    }

    /// Returns the snapshot-bound finding proof retained for recovery.
    pub(crate) const fn finding(&self) -> &GetCampaignFindingObjectResponse {
        &self.finding
    }

    fn same_logical_session(&self, request: &OpenCampaignDebugSessionRequest) -> bool {
        self.request.campaign() == request.campaign() && self.request.finding() == request.finding()
    }
}

/// Durable campaign-owner inventory for long-lived debug sessions.
pub(crate) struct CampaignDebugSessionInventory {
    path: PathBuf,
    records: Mutex<Vec<CampaignDebugSessionInventoryRecord>>,
}

impl CampaignDebugSessionInventory {
    /// Opens and strictly validates the current inventory.
    ///
    /// The caller must hold the campaign state-directory owner lock for the
    /// complete lifetime of this value.
    pub(crate) fn open(path: PathBuf) -> Result<Self, CampaignDebugSessionInventoryError> {
        let records = if path.exists() {
            decode_inventory(&read_inventory(&path)?)?
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            records: Mutex::new(records),
        })
    }

    /// Returns a stable snapshot of all retained recovery records.
    pub(crate) fn records(
        &self,
    ) -> Result<Vec<CampaignDebugSessionInventoryRecord>, CampaignDebugSessionInventoryError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| CampaignDebugSessionInventoryError::Poisoned)?
            .clone())
    }

    /// Durably retains one request and its exact authenticated finding proof.
    pub(crate) fn retain(
        &self,
        request: &OpenCampaignDebugSessionRequest,
        finding: &GetCampaignFindingObjectResponse,
    ) -> Result<(), CampaignDebugSessionInventoryError> {
        let proof_request = request
            .finding_object_request()
            .map_err(|_| CampaignDebugSessionInventoryError::InvalidRecord)?;
        finding
            .validate_for(&proof_request)
            .map_err(|_| CampaignDebugSessionInventoryError::InvalidRecord)?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| CampaignDebugSessionInventoryError::Poisoned)?;
        if let Some(existing) = records
            .iter()
            .find(|record| record.same_logical_session(request))
        {
            if existing.request.canonical_bytes() == request.canonical_bytes()
                && existing.finding.canonical_bytes() == finding.canonical_bytes()
            {
                return Ok(());
            }
            return Err(CampaignDebugSessionInventoryError::Conflict);
        }
        if records.len() >= MAX_RECORDS {
            return Err(CampaignDebugSessionInventoryError::Capacity);
        }

        let mut next = records.clone();
        next.push(CampaignDebugSessionInventoryRecord {
            request: request.clone(),
            finding: finding.clone(),
        });
        next.sort_by(|left, right| {
            left.request
                .campaign()
                .cmp(right.request.campaign())
                .then_with(|| left.request.finding().cmp(&right.request.finding()))
        });
        persist_inventory(&self.path, &next)?;
        *records = next;
        Ok(())
    }

    /// Durably removes the logical session selected by an exact open request.
    pub(crate) fn remove(
        &self,
        request: &OpenCampaignDebugSessionRequest,
    ) -> Result<(), CampaignDebugSessionInventoryError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| CampaignDebugSessionInventoryError::Poisoned)?;
        let mut next = records.clone();
        next.retain(|record| !record.same_logical_session(request));
        if next.len() == records.len() {
            return Ok(());
        }
        persist_inventory(&self.path, &next)?;
        *records = next;
        Ok(())
    }
}

/// Failure to authenticate or update the durable debug-session inventory.
#[derive(Debug, Error)]
pub enum CampaignDebugSessionInventoryError {
    /// Inventory I/O failed.
    #[error("campaign debug-session inventory I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Inventory bytes are malformed, noncanonical, or use another schema.
    #[error("campaign debug-session inventory is invalid")]
    Invalid,
    /// One retained request and finding proof do not bind each other.
    #[error("campaign debug-session inventory record is invalid")]
    InvalidRecord,
    /// Another snapshot already owns the same campaign/finding session key.
    #[error("campaign debug-session inventory contains a conflicting logical session")]
    Conflict,
    /// The fixed durable session bound is exhausted.
    #[error("campaign debug-session inventory capacity is exhausted")]
    Capacity,
    /// In-memory inventory synchronization was poisoned.
    #[error("campaign debug-session inventory synchronization failed")]
    Poisoned,
}

fn read_inventory(path: &Path) -> Result<Vec<u8>, CampaignDebugSessionInventoryError> {
    let metadata = fs::symlink_metadata(path)?;
    let parent = path
        .parent()
        .ok_or(CampaignDebugSessionInventoryError::Invalid)?;
    let parent_metadata = fs::metadata(parent)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != parent_metadata.uid()
        || metadata.gid() != parent_metadata.gid()
    {
        return Err(CampaignDebugSessionInventoryError::Invalid);
    }
    let length =
        usize::try_from(metadata.len()).map_err(|_| CampaignDebugSessionInventoryError::Invalid)?;
    if length > MAX_FILE_BYTES {
        return Err(CampaignDebugSessionInventoryError::Invalid);
    }
    let mut bytes = Vec::with_capacity(length);
    File::open(path)?
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != length || bytes.len() > MAX_FILE_BYTES {
        return Err(CampaignDebugSessionInventoryError::Invalid);
    }
    Ok(bytes)
}

fn persist_inventory(
    path: &Path,
    records: &[CampaignDebugSessionInventoryRecord],
) -> Result<(), CampaignDebugSessionInventoryError> {
    let bytes = encode_inventory(records)?;
    let temporary = path.with_extension("v1.new");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(
        path.parent()
            .ok_or(CampaignDebugSessionInventoryError::Invalid)?,
    )?
    .sync_all()?;
    Ok(())
}

fn encode_inventory(
    records: &[CampaignDebugSessionInventoryRecord],
) -> Result<Vec<u8>, CampaignDebugSessionInventoryError> {
    let count =
        u32::try_from(records.len()).map_err(|_| CampaignDebugSessionInventoryError::Capacity)?;
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    for record in records {
        put_bytes(&mut output, &record.request.canonical_bytes())?;
        put_bytes(&mut output, &record.finding.canonical_bytes())?;
    }
    if output.len() > MAX_FILE_BYTES {
        return Err(CampaignDebugSessionInventoryError::Capacity);
    }
    Ok(output)
}

fn decode_inventory(
    bytes: &[u8],
) -> Result<Vec<CampaignDebugSessionInventoryRecord>, CampaignDebugSessionInventoryError> {
    let mut decoder = InventoryDecoder::new(bytes);
    if decoder.fixed::<8>()? != *MAGIC || decoder.u32()? != VERSION {
        return Err(CampaignDebugSessionInventoryError::Invalid);
    }
    let count =
        usize::try_from(decoder.u32()?).map_err(|_| CampaignDebugSessionInventoryError::Invalid)?;
    if count > MAX_RECORDS {
        return Err(CampaignDebugSessionInventoryError::Invalid);
    }
    let mut records: Vec<CampaignDebugSessionInventoryRecord> = Vec::with_capacity(count);
    for _ in 0..count {
        let request = OpenCampaignDebugSessionRequest::from_canonical_bytes(decoder.bytes()?)
            .map_err(|_| CampaignDebugSessionInventoryError::InvalidRecord)?;
        let finding = GetCampaignFindingObjectResponse::from_canonical_bytes(decoder.bytes()?)
            .map_err(|_| CampaignDebugSessionInventoryError::InvalidRecord)?;
        let proof_request = request
            .finding_object_request()
            .map_err(|_| CampaignDebugSessionInventoryError::InvalidRecord)?;
        finding
            .validate_for(&proof_request)
            .map_err(|_| CampaignDebugSessionInventoryError::InvalidRecord)?;
        if let Some(previous) = records.last()
            && (previous.request.campaign(), previous.request.finding())
                >= (request.campaign(), request.finding())
        {
            return Err(if previous.same_logical_session(&request) {
                CampaignDebugSessionInventoryError::Conflict
            } else {
                CampaignDebugSessionInventoryError::Invalid
            });
        }
        records.push(CampaignDebugSessionInventoryRecord { request, finding });
    }
    decoder.finish()?;
    let canonical = encode_inventory(&records)?;
    if canonical != bytes {
        return Err(CampaignDebugSessionInventoryError::Invalid);
    }
    Ok(records)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CampaignDebugSessionInventoryError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CampaignDebugSessionInventoryError::Capacity);
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| CampaignDebugSessionInventoryError::Capacity)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct InventoryDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> InventoryDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u32(&mut self) -> Result<u32, CampaignDebugSessionInventoryError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CampaignDebugSessionInventoryError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CampaignDebugSessionInventoryError::Invalid)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(CampaignDebugSessionInventoryError::Invalid)?;
        let mut output = [0; N];
        output.copy_from_slice(source);
        self.offset = end;
        Ok(output)
    }

    fn bytes(&mut self) -> Result<&'a [u8], CampaignDebugSessionInventoryError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| CampaignDebugSessionInventoryError::Invalid)?;
        if length > MAX_RECORD_BYTES {
            return Err(CampaignDebugSessionInventoryError::Invalid);
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CampaignDebugSessionInventoryError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CampaignDebugSessionInventoryError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), CampaignDebugSessionInventoryError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CampaignDebugSessionInventoryError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn empty_current_inventory_round_trips_as_owner_only_state() {
        let temporary = TempDir::new()
            .unwrap_or_else(|error| panic!("temporary directory should open: {error}"));
        let path = temporary.path().join("debug-sessions.v1");

        persist_inventory(&path, &[])
            .unwrap_or_else(|error| panic!("empty inventory should persist: {error}"));
        let inventory = CampaignDebugSessionInventory::open(path.clone())
            .unwrap_or_else(|error| panic!("empty inventory should reopen: {error}"));

        assert!(
            inventory
                .records()
                .unwrap_or_else(|error| panic!("records should load: {error}"))
                .is_empty()
        );
        assert_eq!(
            fs::metadata(path)
                .unwrap_or_else(|error| panic!("inventory metadata should load: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn inventory_rejects_noncurrent_or_noncanonical_bytes() {
        let mut wrong_version = encode_inventory(&[])
            .unwrap_or_else(|error| panic!("empty inventory should encode: {error}"));
        wrong_version[11] = 2;
        assert!(matches!(
            decode_inventory(&wrong_version),
            Err(CampaignDebugSessionInventoryError::Invalid)
        ));

        let mut trailing = encode_inventory(&[])
            .unwrap_or_else(|error| panic!("empty inventory should encode: {error}"));
        trailing.push(0);
        assert!(matches!(
            decode_inventory(&trailing),
            Err(CampaignDebugSessionInventoryError::Invalid)
        ));
    }
}
