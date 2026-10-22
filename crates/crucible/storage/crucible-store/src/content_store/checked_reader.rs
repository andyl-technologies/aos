//! Owning original-account readers and deferred EOF authentication.

use super::*;
use crate::owned_decode::{DecodeBudget, DecodeScratch, ResourceLoanSlot};

/// An owning byte reader supervised by the same finite caller at every step.
///
/// A nonempty read returning zero completes EOF authentication. Empty output
/// does not authenticate EOF. Any failed read permanently refuses reuse.
pub trait CheckedBlobReader: Send {
    /// Borrows the actual original account retained by this reader.
    fn original_account(&self) -> &DecodeBudget;

    /// Reads at most 64 KiB while checking the existing original boundary.
    ///
    /// # Errors
    /// Returns original admission, cancellation, I/O or integrity failures.
    /// Readers refuse subsequent calls after any failure.
    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError>;

    /// Reports an identity that an audited reader authenticates at nonempty EOF.
    ///
    /// Custom implementations cannot grant this contract through
    /// [`CheckedReader::new`]; that constructor ignores this method entirely.
    fn full_eof_identity(&self) -> Option<ContentId> {
        None
    }
}

/// Restricts internal contract admission to reviewed concrete reader types.
pub(crate) trait AuditedCheckedBlobReader: CheckedBlobReader {}

/// Owns a checked reader and its private whole-object EOF contract.
///
/// The optional internal identity describes authentication that the reader
/// must finish at nonempty EOF, not a proof that EOF has already succeeded.
/// Ordinary constructors cannot claim that contract. An owning handle adds
/// full length and digest checks when its source does not supply one.
pub struct CheckedReader {
    reader: Box<dyn CheckedBlobReader>,
    // External loans close after Box has dropped and deallocated its reader.
    _resources: ResourceLoanSlot,
    _credit: Option<DecodeScratch>,
    audited_eof_contract: bool,
}

impl CheckedReader {
    /// Wraps a reader without granting a whole-object authentication contract.
    #[must_use]
    pub fn new(reader: Box<dyn CheckedBlobReader>) -> Self {
        Self {
            reader,
            _resources: ResourceLoanSlot::default(),
            _credit: None,
            audited_eof_contract: false,
        }
    }

    /// Prepays a reader's Box from the same original account it retains.
    ///
    /// The original loan is admitted before the Box allocation and closes
    /// after that Box is deallocated. This constructor does not grant an EOF
    /// authentication contract; owning handles still validate the full stream.
    ///
    /// # Errors
    /// Returns an original admission refusal or rejects a reader that retains
    /// a different account from the supplied original.
    pub fn new_prepaid<T: CheckedBlobReader + 'static>(
        reader: T,
        original: &DecodeBudget,
    ) -> Result<Self, StoreError> {
        original
            .verify_live()
            .map_err(|error| batch::admission_under(original, error))?;
        if !original.same_account(reader.original_account()) {
            return Err(StoreError::InvalidComposition {
                reason: "checked reader retains another original account",
            });
        }
        let credit = original
            .reserve_scratch_array::<T>(1)
            .map_err(|error| batch::admission_under(original, error))?;

        Ok(Self {
            reader: Box::new(reader),
            _resources: ResourceLoanSlot::default(),
            _credit: Some(credit),
            audited_eof_contract: false,
        })
    }

    /// Retains a test reader's prepaid allocation without trusting its identity.
    ///
    /// The caller reserves the exact reader extent from its original account
    /// before allocating the Box. The same loan closes after that Box, and
    /// ordinary handle validation still authenticates the exposed stream.
    #[cfg(test)]
    pub(crate) fn funded(reader: Box<dyn CheckedBlobReader>, credit: DecodeScratch) -> Self {
        Self {
            _credit: Some(credit),
            ..Self::new(reader)
        }
    }

    /// Borrows the genuine original account retained by the reader.
    #[must_use]
    pub fn original_account(&self) -> &DecodeBudget {
        self.reader.original_account()
    }

    /// Reads one checked chunk or accepts nonempty EOF under the reader's contract.
    ///
    /// # Errors
    /// Returns the reader's original admission, boundary, I/O or integrity
    /// failure. Failed readers permanently refuse reuse.
    pub fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        self.reader.read_with_boundary(output, boundary)
    }

    // Only audited internal wrappers can forward the full-stream contract.
    // They still must observe underlying EOF and its terminal boundary before
    // returning zero for a nonempty output buffer.
    pub(crate) fn admitted<T: AuditedCheckedBlobReader + 'static>(
        reader: Box<T>,
        credit: DecodeScratch,
        resources: ResourceLoanSlot,
    ) -> Self {
        Self {
            reader,
            _resources: resources,
            _credit: Some(credit),
            audited_eof_contract: true,
        }
    }

    pub(super) fn full_eof_identity(&self) -> Option<ContentId> {
        if self.audited_eof_contract {
            self.reader.full_eof_identity()
        } else {
            None
        }
    }
}

pub(crate) fn check(
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    original
        .verify_live()
        .map_err(|error| batch::admission_under(original, error))?;
    boundary()?;
    original
        .verify_live()
        .map_err(|error| batch::admission_under(original, error))
}

pub(super) fn failed() -> StoreError {
    StoreError::Unsupported {
        capability: "failed-checked-blob-reader",
    }
}

// Caller and stored source accounts can differ. Both remain authoritative;
// callback TLS changes never select allocation or failure custody.
pub(crate) fn check_pair(
    caller: &DecodeBudget,
    source: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    // Exact aliases share all failure and liveness state. The same callback
    // still runs once between the original account's preflight and recheck.
    if caller.same_account(source) {
        return check(caller, boundary);
    }

    caller
        .verify_live()
        .map_err(|error| batch::admission_under(caller, error))?;
    source
        .verify_live()
        .map_err(|error| batch::admission_under(source, error))?;
    boundary()?;
    caller
        .verify_live()
        .map_err(|error| batch::admission_under(caller, error))?;
    source
        .verify_live()
        .map_err(|error| batch::admission_under(source, error))
}

pub(super) fn read_all<S: BlobSource + ?Sized>(
    source: &S,
    caller: &DecodeBudget,
    maximum: u64,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<OwnedBlobBytes, StoreError> {
    check(caller, boundary)?;
    let mut reader = source.open_with_boundary(caller, boundary)?;
    read_owned(
        &mut reader,
        caller,
        source.logical_length(),
        maximum,
        boundary,
    )
}

pub(super) fn read_owned(
    reader: &mut CheckedReader,
    caller: &DecodeBudget,
    length: u64,
    maximum: u64,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<OwnedBlobBytes, StoreError> {
    let source = reader.original_account().clone();
    batch::read_reader_under(
        &source,
        caller,
        length,
        maximum,
        boundary,
        &mut |output, boundary| reader.read_with_boundary(output, boundary),
    )
}

pub(super) fn open_handle(
    handle: &BlobHandle,
    caller: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedReader, StoreError> {
    let reader = handle.source.open_with_boundary(caller, boundary)?;
    let original = reader.original_account().clone();
    check_pair(caller, &original, boundary)?;
    let credit = original
        .reserve_scratch_array::<HandleReader>(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    check_pair(caller, &original, boundary)?;
    let full_eof_identity = handle.integrity_id;
    let needs_digest = !handle.self_authenticating
        && (full_eof_identity.is_none() || reader.full_eof_identity() != full_eof_identity);
    Ok(CheckedReader::admitted(
        Box::new(HandleReader {
            reader,
            original,
            caller: caller.clone(),
            length: handle.logical_length,
            observed: 0,
            hasher: needs_digest
                .then(|| {
                    handle.integrity_id.map(|id| {
                        content_hasher(id.kind(), id.schema_version(), handle.logical_length)
                    })
                })
                .flatten(),
            id: handle.integrity_id,
            failed: false,
        }),
        credit,
        ResourceLoanSlot::default(),
    ))
}

struct HandleReader {
    reader: CheckedReader,
    original: DecodeBudget,
    caller: DecodeBudget,
    length: u64,
    observed: u64,
    hasher: Option<blake3::Hasher>,
    id: Option<ContentId>,
    failed: bool,
}

impl AuditedCheckedBlobReader for HandleReader {}

impl CheckedBlobReader for HandleReader {
    fn full_eof_identity(&self) -> Option<ContentId> {
        self.id
    }

    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(failed());
        }
        let original = &self.original;
        let result = (|| {
            let mut check = || check_pair(&self.caller, original, boundary);
            check()?;
            let limit = output.len().min(64 * 1024);
            let count = self
                .reader
                .read_with_boundary(&mut output[..limit], &mut check)?;
            if count > limit {
                return Err(StoreError::InvalidSourceLength {
                    declared: self.length,
                    observed: self.length.saturating_add(1),
                });
            }
            self.observed = self
                .observed
                .checked_add(count as u64)
                .ok_or(StoreError::Quota)?;
            if self.observed > self.length
                || (!output.is_empty() && count == 0 && self.observed != self.length)
            {
                return Err(StoreError::InvalidSourceLength {
                    declared: self.length,
                    observed: self.observed,
                });
            }
            if let Some(hasher) = &mut self.hasher {
                hasher.update(&output[..count]);
                if !output.is_empty()
                    && count == 0
                    && Some(*hasher.finalize().as_bytes()) != self.id.map(|id| id.digest())
                {
                    return Err(StoreError::Corrupt {
                        id: self.id.ok_or(StoreError::Quota)?,
                    });
                }
            }
            // The child's terminal boundary runs while its failure bank is
            // still live. Identity validation above allocates no diagnostics.
            original
                .verify_live()
                .map_err(|error| batch::admission_under(original, error))?;
            Ok(count)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

pub(super) fn memory(
    bytes: Arc<[u8]>,
    caller: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedReader, StoreError> {
    let original = caller.clone();
    check(&original, boundary)?;
    let credit = original
        .reserve_scratch_array::<MemoryReader>(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    check(&original, boundary)?;
    Ok(CheckedReader::admitted(
        Box::new(MemoryReader {
            reader: Cursor::new(bytes),
            original,
            failed: false,
        }),
        credit,
        ResourceLoanSlot::default(),
    ))
}

struct MemoryReader {
    reader: Cursor<Arc<[u8]>>,
    original: DecodeBudget,
    failed: bool,
}

impl AuditedCheckedBlobReader for MemoryReader {}

impl CheckedBlobReader for MemoryReader {
    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(failed());
        }
        let original = &self.original;
        let result = (|| {
            check(original, boundary)?;
            let limit = output.len().min(64 * 1024);
            let count =
                self.reader
                    .read(&mut output[..limit])
                    .map_err(|source| StoreError::StreamIo {
                        operation: "read-checked-memory-source",
                        source,
                    })?;
            check(original, boundary)?;
            Ok(count)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

pub(super) fn range(
    source: &BlobHandle,
    range: ByteRange,
    caller: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedReader, StoreError> {
    let reader = open_handle(source, caller, boundary)?;
    let original = reader.original_account().clone();
    check(&original, boundary)?;
    let credit = original
        .reserve_scratch_bytes((std::mem::size_of::<RangeReader>() + 64 * 1024) as u64)
        .map_err(|error| batch::admission_under(&original, error))?;
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(64 * 1024)
        .map_err(|error| batch::allocation_under(&original, error))?;
    scratch.resize(64 * 1024, 0);
    Ok(CheckedReader::admitted(
        Box::new(RangeReader {
            reader,
            original,
            caller: caller.clone(),
            prefix: range.offset,
            remaining: range.length,
            suffix: source.logical_length - range.offset - range.length,
            failed: false,
            scratch,
        }),
        credit,
        ResourceLoanSlot::default(),
    ))
}

struct RangeReader {
    reader: CheckedReader,
    original: DecodeBudget,
    caller: DecodeBudget,
    prefix: u64,
    remaining: u64,
    suffix: u64,
    failed: bool,
    scratch: Vec<u8>,
}

impl AuditedCheckedBlobReader for RangeReader {}

impl RangeReader {
    fn skip(
        reader: &mut CheckedReader,
        scratch: &mut [u8],
        remaining: &mut u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        while *remaining > 0 {
            let limit = (*remaining).min(scratch.len() as u64) as usize;
            let count = reader.read_with_boundary(&mut scratch[..limit], boundary)?;
            if count == 0 || count > limit {
                return Err(StoreError::Quota);
            }
            *remaining -= count as u64;
        }
        Ok(())
    }
}

impl CheckedBlobReader for RangeReader {
    fn full_eof_identity(&self) -> Option<ContentId> {
        self.reader.full_eof_identity()
    }

    fn original_account(&self) -> &DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(failed());
        }
        let original = &self.original;
        let result = (|| {
            let mut check = || check_pair(&self.caller, original, boundary);
            check()?;
            if output.is_empty() {
                return Ok(0);
            }
            Self::skip(
                &mut self.reader,
                &mut self.scratch,
                &mut self.prefix,
                &mut check,
            )?;
            if self.remaining > 0 {
                let limit = self.remaining.min(output.len() as u64).min(64 * 1024) as usize;
                let count = self
                    .reader
                    .read_with_boundary(&mut output[..limit], &mut check)?;
                if count == 0 || count > limit {
                    return Err(StoreError::Quota);
                }
                self.remaining -= count as u64;
                check()?;
                return Ok(count);
            }
            Self::skip(
                &mut self.reader,
                &mut self.scratch,
                &mut self.suffix,
                &mut check,
            )?;
            let mut extra = [0; 1];
            if self.reader.read_with_boundary(&mut extra, &mut check)? != 0 {
                return Err(StoreError::Quota);
            }
            check()?;
            Ok(0)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

pub(super) fn slice_handle(
    handle: BlobHandle,
    range: Option<ByteRange>,
    caller: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    let Some(range) = range else {
        return Ok(handle);
    };
    let original = caller.clone();
    check(&original, boundary)?;
    validate_range(handle.logical_length, range)?;
    let credit = original
        .reserve_scratch_bytes(
            (std::mem::size_of::<RangeBlobSource>() + 2 * std::mem::size_of::<usize>()) as u64,
        )
        .map_err(|error| batch::admission_under(&original, error))?;
    let integrity_id = handle.integrity_id;
    let self_authenticating = handle.self_authenticating;
    let mut sliced = BlobHandle::new(RangeBlobSource {
        source: handle,
        range,
        _credit: Some(credit),
    });
    sliced.integrity_id = integrity_id;
    sliced.self_authenticating = self_authenticating;
    check(&original, boundary)?;
    Ok(sliced)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fastpath_tests;

#[cfg(test)]
mod pair_tests;
