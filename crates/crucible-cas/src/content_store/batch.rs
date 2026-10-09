//! Original-operation batch dispatch and final receipt allocation custody.

use super::admin::{CheckedReceipt, PreparedResources};
use super::sqlite::Accepted;
use crate::owned_decode::{DecodeBudget, DecodeScratch};
use std::ops::Deref;

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

impl OwnedBlobBytes {
    pub(crate) fn prepared(bytes: Vec<u8>, credit: DecodeScratch) -> Self {
        Self {
            bytes,
            _credit: credit,
        }
    }

    /// Borrows the original account that funds this owned output.
    ///
    /// Deferred sources may fund output from their retained account instead of
    /// the caller's account. This borrow neither creates credit nor changes
    /// the output's resource lifetime.
    #[must_use]
    pub fn original_account(&self) -> &DecodeBudget {
        self._credit.original_account()
    }
}

/// Retains ordered publication receipts with their original metadata credits.
///
/// Receipt bodies close before their account. Borrowing the ordered slice does
/// not detach placement metadata from the authority that admitted it.
/// The actual leaf outcome and diagnostic bank remain owned until explicit
/// acceptance or drop, including while outer facades validate the result.
pub struct PutBatchReceipt {
    receipt: CheckedReceipt<Vec<PutReceipt>>,
    original: DecodeBudget,
}

impl PutBatchReceipt {
    pub(super) fn new_composite(
        accepted: super::composite_publication::Accepted<Vec<PutReceipt>>,
        credit: DecodeScratch,
        original: DecodeBudget,
    ) -> Self {
        Self {
            receipt: CheckedReceipt::new_composite(accepted, credit),
            original,
        }
    }

    pub(super) fn release_diagnostic(&mut self) {
        self.receipt.release_diagnostic();
    }

    pub(super) fn new_memory(
        accepted: super::memory::Accepted<Vec<PutReceipt>>,
        credit: DecodeScratch,
        original: DecodeBudget,
    ) -> Self {
        Self {
            receipt: CheckedReceipt::new_memory(accepted, credit),
            original,
        }
    }

    pub(super) fn new_directory(
        accepted: super::directory::Accepted<Vec<PutReceipt>>,
        credit: DecodeScratch,
        original: DecodeBudget,
    ) -> Self {
        Self {
            receipt: CheckedReceipt::new_directory(accepted, credit),
            original,
        }
    }

    pub(super) fn new_packed(
        accepted: super::packed::Accepted<Vec<PutReceipt>>,
        credit: DecodeScratch,
        original: DecodeBudget,
    ) -> Self {
        Self {
            receipt: CheckedReceipt::new_packed(accepted, credit),
            original,
        }
    }

    pub(super) fn new(
        accepted: Accepted<Vec<PutReceipt>>,
        credit: DecodeScratch,
        original: DecodeBudget,
    ) -> Self {
        Self {
            receipt: CheckedReceipt::new(accepted, credit),
            original,
        }
    }

    pub(super) fn retain_resources(&mut self, prepared: PreparedResources) {
        self.receipt.retain_resources(prepared);
    }

    pub(crate) fn check(
        self,
        check: impl FnOnce(&mut Vec<PutReceipt>) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let Self { receipt, original } = self;
        Ok(Self {
            receipt: receipt.check(check)?,
            original,
        })
    }

    /// Accepts the outer publication result under its same original operation.
    ///
    /// Successful acceptance releases the leaf's retained diagnostic bank.
    /// Receipt bodies, resource loans and the actual outcome token remain
    /// owned. Callers supply their existing finite boundary; this method never
    /// starts or renews an operation.
    ///
    /// # Errors
    /// Returns original admission or boundary failure with the actual leaf
    /// outcome and diagnostic custody still retained by the error.
    pub fn accept_with_boundary(
        self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        let Self { receipt, original } = self;
        let mut receipt = receipt.check(|_| {
            original
                .verify_live()
                .map_err(|error| admission_under(&original, error))?;
            boundary()?;
            original
                .verify_live()
                .map_err(|error| admission_under(&original, error))
        })?;
        receipt.release_diagnostic();
        Ok(Self { receipt, original })
    }
}

impl std::fmt::Debug for PutBatchReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.deref().fmt(formatter)
    }
}

impl Deref for PutBatchReceipt {
    type Target = [PutReceipt];

    fn deref(&self) -> &Self::Target {
        self.receipt.value()
    }
}

pub(super) fn account() -> Result<DecodeBudget, StoreError> {
    let account = crate::owned_decode::current_budget().ok_or(StoreError::Unsupported {
        capability: "original-batch-metadata-account",
    })?;
    account
        .verify_live()
        .map_err(|error| admission_under(&account, error))?;
    Ok(account)
}

// Inline typed failures keep the saved original, even if a callback changes TLS.
pub(crate) fn admission_under(
    account: &DecodeBudget,
    source: crate::owned_decode::DecodeAdmissionError,
) -> StoreError {
    StoreError::DecodeAdmission {
        source,
        custody: Some(account.custody()),
    }
}

pub(super) fn allocation_under(
    account: &DecodeBudget,
    source: std::collections::TryReserveError,
) -> StoreError {
    StoreError::Allocation {
        source,
        custody: Some(account.custody()),
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
        .map_err(|error| admission_under(account, error))
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
    original: &DecodeBudget,
    id: ContentId,
    source: &BlobHandle,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    original
        .verify_live()
        .map_err(|error| admission_under(original, error))?;
    boundary()?;
    original
        .verify_live()
        .map_err(|error| admission_under(original, error))?;
    if source.authenticated_id == Some(id) {
        return Ok(source.clone());
    }
    let bytes =
        read_source(original, source, source.logical_length(), boundary).map_err(|error| {
            match error {
                StoreError::InvalidSourceLength { .. } => StoreError::Corrupt { id },
                other => other,
            }
        })?;
    validate_bytes(id, &bytes)?;
    super::checked_reader::check(original, boundary)?;
    let mut verified = source.clone();
    verified.authenticated_id = Some(id);
    verified.integrity_id = Some(id);
    verified.self_authenticating = false;
    Ok(verified)
}

/// Reads directly into the bounded output, without a second chunk buffer.
pub(super) fn read_source(
    original: &DecodeBudget,
    source: &BlobHandle,
    maximum: u64,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<OwnedBlobBytes, StoreError> {
    source.read_all_with_boundary(original, maximum, boundary)
}

// Callers supply their saved account before callbacks. Allocations and terminal
// checks use that borrow directly; no ambient recapture occurs here.
pub(crate) fn read_reader_under<F>(
    account: &DecodeBudget,
    caller: &DecodeBudget,
    length: u64,
    maximum: u64,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    read: &mut F,
) -> Result<OwnedBlobBytes, StoreError>
where
    F: FnMut(&mut [u8], &mut dyn FnMut() -> Result<(), StoreError>) -> Result<usize, StoreError>,
{
    super::checked_reader::check_pair(caller, account, boundary)?;
    if length > maximum {
        return Err(StoreError::Quota);
    }
    let capacity = usize::try_from(length).map_err(|_| StoreError::Quota)?;
    let credit = account
        .reserve_scratch_array::<u8>(capacity)
        .map_err(|error| admission_under(account, error))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| allocation_under(account, error))?;
    bytes.resize(capacity, 0);
    super::checked_reader::check_pair(caller, account, boundary)?;
    let mut observed = 0;
    while observed < capacity {
        super::checked_reader::check_pair(caller, account, boundary)?;
        let end = capacity.min(observed.saturating_add(64 * 1024));
        let count = read(&mut bytes[observed..end], boundary)?;
        super::checked_reader::check_pair(caller, account, boundary)?;
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
    super::checked_reader::check_pair(caller, account, boundary)?;
    let count = read(&mut extra, boundary)?;
    super::checked_reader::check_pair(caller, account, boundary)?;
    if observed != capacity || count != 0 {
        return Err(StoreError::InvalidSourceLength {
            declared: length,
            observed: (observed as u64).saturating_add(count as u64),
        });
    }
    account
        .verify_live()
        .map_err(|error| admission_under(account, error))?;
    Ok(OwnedBlobBytes {
        bytes,
        _credit: credit,
    })
}
