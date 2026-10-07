//! Original-operation batch dispatch and final receipt allocation custody.

use std::ops::Deref;
use std::sync::Arc;

use crate::owned_decode::{DecodeBudget, DecodeScratch};

use super::{BlobHandle, ContentId, PlacementReceipt, PutReceipt, StoreError, validate_bytes};

/// Retains fully read bytes with the original account that admitted them.
pub struct OwnedBlobBytes {
    bytes: Vec<u8>,
    _credit: DecodeScratch,
}

impl std::fmt::Debug for OwnedBlobBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedBlobBytes")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl Deref for OwnedBlobBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// Retains ordered publication receipts with their original metadata credits.
///
/// Receipt bodies close before their account. Borrowing the ordered slice does
/// not detach placement metadata from the authority that admitted it.
pub struct PutBatchReceipt {
    pub(super) receipts: Vec<PutReceipt>,
    resources: Option<Box<BatchResources>>,
    credit: DecodeScratch,
}

// Each node's allocation is covered by its enclosing credit. Field order
// closes the previous node and its resources before releasing their loan.
struct BatchResources {
    _previous: Option<Box<BatchResources>>,
    _resources: Arc<dyn Send + Sync>,
    _previous_credit: DecodeScratch,
}

impl PutBatchReceipt {
    pub(super) fn new(receipts: Vec<PutReceipt>, credit: DecodeScratch) -> Self {
        Self {
            receipts,
            resources: None,
            credit,
        }
    }

    pub(super) fn retain_resources(
        &mut self,
        account: &DecodeBudget,
        resources: Arc<dyn Send + Sync>,
        additional_bytes: u64,
    ) -> Result<(), StoreError> {
        let bytes = additional_bytes
            .checked_add(std::mem::size_of::<BatchResources>() as u64)
            .ok_or(StoreError::Quota)?;
        let credit = account.reserve_scratch_bytes(bytes).map_err(admission)?;
        let previous_credit = std::mem::replace(&mut self.credit, credit);
        self.resources = Some(Box::new(BatchResources {
            _previous: self.resources.take(),
            _resources: resources,
            _previous_credit: previous_credit,
        }));
        Ok(())
    }
}

impl std::fmt::Debug for PutBatchReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.receipts.fmt(formatter)
    }
}

impl Deref for PutBatchReceipt {
    type Target = [PutReceipt];

    fn deref(&self) -> &Self::Target {
        &self.receipts
    }
}

pub(super) fn account() -> Result<DecodeBudget, StoreError> {
    let account = crate::owned_decode::current_budget().ok_or(StoreError::Unsupported {
        capability: "original-batch-metadata-account",
    })?;
    account.verify_live().map_err(admission)?;
    Ok(account)
}

pub(super) fn admission(source: crate::owned_decode::DecodeAdmissionError) -> StoreError {
    StoreError::DecodeAdmission {
        source,
        custody: crate::owned_decode::current_custody(),
    }
}

pub(super) fn allocation(source: std::collections::TryReserveError) -> StoreError {
    StoreError::Allocation {
        source,
        custody: crate::owned_decode::current_custody(),
    }
}

pub(super) fn admit_receipts(
    account: &DecodeBudget,
    count: usize,
    name_bytes: usize,
) -> Result<DecodeScratch, StoreError> {
    let per_receipt = std::mem::size_of::<PutReceipt>()
        .checked_add(std::mem::size_of::<PlacementReceipt>())
        .and_then(|bytes| bytes.checked_add(name_bytes))
        .ok_or(StoreError::Quota)?;
    let bytes = count.checked_mul(per_receipt).ok_or(StoreError::Quota)?;
    account
        .reserve_scratch_bytes(bytes as u64)
        .map_err(admission)
}

/// Borrows the fixed-size content identifier rendering for checked SQL only.
pub(super) fn with_id_text<T>(
    id: ContentId,
    consume: impl FnOnce(&str) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    id.with_encoded_text(|bytes| {
        let text = std::str::from_utf8(bytes).map_err(|_| StoreError::Corrupt { id })?;
        consume(text)
    })
}

pub(super) fn verify_source(
    id: ContentId,
    source: &BlobHandle,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    boundary()?;
    if source.authenticated_id == Some(id) {
        return Ok(source.clone());
    }
    let bytes =
        read_source(source, source.logical_length(), boundary).map_err(|error| match error {
            StoreError::InvalidSourceLength { .. } => StoreError::Corrupt { id },
            other => other,
        })?;
    validate_bytes(id, &bytes)?;
    boundary()?;
    let mut verified = source.clone();
    verified.authenticated_id = Some(id);
    verified.integrity_id = Some(id);
    verified.self_authenticating = false;
    Ok(verified)
}

/// Reads directly into the bounded output, without a second chunk buffer.
pub(super) fn read_source(
    source: &BlobHandle,
    maximum: u64,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<OwnedBlobBytes, StoreError> {
    source.read_all_with_boundary(maximum, boundary)
}

pub(super) fn read_reader<F>(
    length: u64,
    maximum: u64,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    read: &mut F,
) -> Result<OwnedBlobBytes, StoreError>
where
    F: FnMut(&mut [u8], &mut dyn FnMut() -> Result<(), StoreError>) -> Result<usize, StoreError>,
{
    boundary()?;
    let account = account()?;
    if length > maximum {
        return Err(StoreError::Quota);
    }
    let capacity = usize::try_from(length).map_err(|_| StoreError::Quota)?;
    let credit = account
        .reserve_scratch_array::<u8>(capacity)
        .map_err(admission)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(allocation)?;
    bytes.resize(capacity, 0);
    boundary()?;
    let mut observed = 0;
    while observed < capacity {
        boundary()?;
        let end = capacity.min(observed.saturating_add(64 * 1024));
        let count = read(&mut bytes[observed..end], boundary)?;
        boundary()?;
        if count > end - observed {
            return Err(StoreError::InvalidSourceLength {
                declared: length,
                observed: length.saturating_add(1),
            });
        }
        if count == 0 {
            break;
        }
        observed += count;
    }
    let mut extra = [0_u8; 1];
    boundary()?;
    let count = read(&mut extra, boundary)?;
    boundary()?;
    if observed != capacity || count != 0 {
        return Err(StoreError::InvalidSourceLength {
            declared: length,
            observed: (observed as u64).saturating_add(count as u64),
        });
    }
    account.verify_live().map_err(admission)?;
    Ok(OwnedBlobBytes {
        bytes,
        _credit: credit,
    })
}
