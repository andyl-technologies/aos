//! Separately admitted, kernel-sealed production mark copies.
//!
//! Fresh authenticated run reads supply one strictly ordered fixed-record
//! stream. Complete input and tail precede Linux's immutable seal verification.
//! Exact length and full readback hash are checked after sealing. Membership
//! then reads this closed copy, rather than treating
//! an earlier mutable SQLite lookup as current storage. Generic mark lookups
//! retain their independent current-row semantics.
//!
//! ```text
//! record[126] = typed_mark_key[32] | id_length:u8 | canonical_id[93]
//! unused canonical_id bytes are zero; records strictly increase by key
//! ```
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::os::unix::fs::FileExt;

use crucible_store::owned_decode::ResourceLoan;
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, memfd_create};

use super::*;

const ID_BYTES: usize = 93;
const RECORD_BYTES: usize = 32 + 1 + ID_BYTES;
const BUFFER_BYTES: usize = RECORD_BYTES * MerkleMap::MAX_CHECKED_PREFIX_UPSERTS;

// The caller selects the concrete returned error before constructing marks.
// This loan therefore precedes both the file and a possible boxed close cause.
/// Prepays the concrete caller's owning cleanup error before file creation.
pub(in crate::campaign_gc) struct ClosePurpose<E> {
    _credit: ResourceLoan,
    _error: PhantomData<fn() -> E>,
}

impl<E> ClosePurpose<E> {
    /// Admits the exact boxed error/control extent from the original namespace.
    ///
    /// # Errors
    /// Refuses original liveness, size overflow or insufficient existing credit.
    pub(in crate::campaign_gc) fn new(
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<Self, StoreError> {
        let bytes = std::mem::size_of::<CloseFailure<E>>()
            .checked_add(std::mem::size_of::<io::Error>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .ok_or(StoreError::Quota)?;
        Ok(Self {
            _credit: operation.reserve_bytes(bytes as u64)?,
            _error: PhantomData,
        })
    }
}

/// Owns one immutable mark copy and its original backing/descriptor reservation.
pub(super) struct SealedMarks {
    file: Option<File>,
    count: u64,
    bytes: u64,
    digest: blake3::Hash,
    close_uncertain: bool,
    credit: Option<ResourceLoan>,
}

impl SealedMarks {
    /// Copies one complete authenticated input and verifies its immutable bytes.
    ///
    /// # Errors
    /// Refuses original admission, incomplete or noncanonical input, native
    /// file/seal/readback failure, or cleanup. Insufficient original resources
    /// refuse before file creation; they never create another account.
    pub(super) fn from_entries(
        count: u64,
        input: impl IntoIterator<Item = Result<MarkEntry, StoreError>>,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<Self, StoreError> {
        let close = ClosePurpose::<StoreError>::new(operation)?;
        let bytes = count
            .checked_mul(RECORD_BYTES as u64)
            .filter(|_| count <= MAX_CAMPAIGN_CLOSURE_OBJECTS as u64)
            .ok_or(StoreError::Quota)?;
        let page_bytes = rustix::param::page_size() as u64;
        let backing = bytes
            .checked_add(page_bytes.checked_sub(1).ok_or(StoreError::Quota)?)
            .map(|bytes| bytes / page_bytes * page_bytes)
            .ok_or(StoreError::Quota)?;
        let controls = std::mem::size_of::<Self>()
            .checked_add(BUFFER_BYTES)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<u8>>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<blake3::Hasher>()))
            .ok_or(StoreError::Quota)?;
        // Resident backing and one descriptor come from this actual original
        // namespace. No mmap or second physical copy is created. Kernel and
        // allocator overhead still require the complete external Source case.
        let credit = operation.reserve_resources(
            1,
            backing
                .checked_add(controls as u64)
                .ok_or(StoreError::Quota)?,
        )?;
        let mut owner = Self {
            file: None,
            count,
            bytes,
            digest: blake3::hash(&[]),
            close_uncertain: false,
            credit: Some(credit),
        };
        let result = owner.fill(input, operation);
        match result {
            Ok(()) => Ok(owner),
            Err(error) => owner.finish(close, Err(error), operation, |error| error),
        }
    }

    fn fill(
        &mut self,
        input: impl IntoIterator<Item = Result<MarkEntry, StoreError>>,
        operation: &CampaignGcOperationContext<'_>,
    ) -> Result<(), StoreError> {
        operation.check()?;
        let created = memfd_create(
            "crucible-gc-sealed-marks",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        );
        // Publish the real descriptor before the originating postcut.
        let created = match created {
            Ok(file) => {
                self.file = Some(File::from(file));
                Ok(())
            }
            Err(source) => Err(io_error("create sealed GC marks", source.into())),
        };
        created?;
        operation.check()?;
        let file = self.file.as_mut().ok_or_else(missing_file)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(BUFFER_BYTES)
            .map_err(|source| StoreError::Allocation {
                source,
                custody: Some(operation.original().custody()),
            })?;
        let mut hasher = blake3::Hasher::new();
        let mut previous = None;
        let mut observed = 0_u64;

        for entry in input {
            let (key, id) = entry?;
            operation.check()?;
            if observed >= self.count
                || previous.is_some_and(|previous| previous >= key)
                || key != mark_key(id)
            {
                return Err(invalid_stream());
            }
            let mut record = [0_u8; RECORD_BYTES];
            record[..32].copy_from_slice(&key.as_bytes());
            id.with_encoded_text(|text| {
                if text.len() > ID_BYTES {
                    return Err(invalid_stream());
                }
                record[32] = text.len() as u8;
                record[33..33 + text.len()].copy_from_slice(text);
                Ok(())
            })?;
            buffer.extend_from_slice(&record);
            hasher.update(&record);
            previous = Some(key);
            observed += 1;
            if buffer.len() == BUFFER_BYTES {
                write_buffer(file, &buffer, operation)?;
                buffer.clear();
            }
        }
        // Exhausting the actual fallible iterator authenticates its complete
        // run tail. Count and order errors precede any immutable publication.
        if observed != self.count {
            return Err(invalid_stream());
        }
        if !buffer.is_empty() {
            write_buffer(file, &buffer, operation)?;
        }
        self.digest = hasher.finalize();
        drop(hasher);
        operation.check()?;
        let sealed = fcntl_add_seals(&*file, required_seals());
        sealed.map_err(|source| io_error("seal GC marks", source.into()))?;
        operation.check()?;
        let seals = fcntl_get_seals(&*file)
            .map_err(|source| io_error("read sealed GC mark seals", source.into()))?;
        if !seals.contains(required_seals()) {
            return Err(invalid_stream());
        }
        operation.check()?;
        let length = file
            .metadata()
            .map_err(|source| io_error("read sealed GC mark length", source))?
            .len();
        if length != self.bytes {
            return Err(invalid_stream());
        }
        buffer.resize(BUFFER_BYTES, 0);
        let mut readback = blake3::Hasher::new();
        let mut offset = 0_u64;
        while offset < self.bytes {
            let count = (self.bytes - offset).min(BUFFER_BYTES as u64) as usize;
            read_exact_at_checked(
                &mut buffer[..count],
                offset,
                &mut || operation.check(),
                "authenticate sealed GC mark copy",
                |bytes, offset| file.read_at(bytes, offset),
            )?;
            readback.update(&buffer[..count]);
            offset += count as u64;
        }
        if readback.finalize() != self.digest {
            return Err(invalid_stream());
        }
        drop(readback);
        drop(buffer);
        operation.check()
    }

    /// Searches the sealed copy under the same saved original boundary.
    ///
    /// # Errors
    /// Refuses original liveness, native read failure, closed ownership or a
    /// wrong typed ContentId on a matching key. It performs no mutable SQL read.
    pub(super) fn contains(
        &self,
        id: ContentId,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<bool, StoreError> {
        let check = |boundary: &mut dyn FnMut() -> Result<(), StoreError>| {
            original
                .verify_live()
                .map_err(|error| mark_admission(original, error))?;
            boundary()?;
            original
                .verify_live()
                .map_err(|error| mark_admission(original, error))
        };
        check(boundary)?;
        let file = self.file.as_ref().ok_or_else(missing_file)?;
        let wanted = mark_key(id).as_bytes();
        let mut low = 0;
        let mut high = self.count;
        let mut record = [0_u8; RECORD_BYTES];
        while low < high {
            let middle = low + (high - low) / 2;
            read_exact_at_checked(
                &mut record,
                middle * RECORD_BYTES as u64,
                &mut || check(boundary),
                "search sealed GC marks",
                |bytes, offset| file.read_at(bytes, offset),
            )?;
            match record[..32].cmp(&wanted) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => {
                    let length = usize::from(record[32]);
                    if length > ID_BYTES || record[33 + length..].iter().any(|byte| *byte != 0) {
                        return Err(invalid_stream());
                    }
                    let text = std::str::from_utf8(&record[33..33 + length])
                        .map_err(|_| invalid_stream())?;
                    let actual = ContentId::parse(text).map_err(|_| invalid_stream())?;
                    if actual != id || mark_key(actual).as_bytes() != wanted {
                        return Err(invalid_stream());
                    }
                    check(boundary)?;
                    return Ok(true);
                }
            }
        }
        check(boundary)?;
        Ok(false)
    }

    /// Returns the authenticated complete input count.
    pub(super) fn len(&self) -> u64 {
        self.count
    }

    /// Closes the descriptor before releasing credit or exposing the result.
    ///
    /// # Errors
    /// Preserves the initiating caller failure; native close or a success-only
    /// original postcut refusal retains its paid owning cleanup frame.
    pub(super) fn finish<T, E>(
        self,
        purpose: ClosePurpose<E>,
        result: Result<T, E>,
        operation: &CampaignGcOperationContext<'_>,
        failure: impl FnOnce(StoreError) -> E,
    ) -> Result<T, E>
    where
        E: Error + Send + Sync + 'static,
    {
        self.finish_with(purpose, result, operation, failure, close_file)
    }

    fn finish_with<T, E>(
        mut self,
        purpose: ClosePurpose<E>,
        result: Result<T, E>,
        operation: &CampaignGcOperationContext<'_>,
        failure: impl FnOnce(StoreError) -> E,
        close: impl FnOnce(File) -> Result<(), rustix::io::Errno>,
    ) -> Result<T, E>
    where
        E: Error + Send + Sync + 'static,
    {
        let closed = match self.file.take() {
            Some(file) => close(file),
            None => Ok(()),
        };
        self.close_uncertain = closed.is_err();
        // An initiating refusal never invokes a later success-only callback.
        // Real close runs regardless. A failed close and independent original
        // postcut stay separate, with the initiating cause rendered first.
        let post = if result.is_ok() {
            operation.check().err()
        } else {
            None
        };
        match (result, closed, post) {
            (Ok(value), Ok(()), None) => Ok(value),
            (Err(error), Ok(()), None) => Err(error),
            (result, closed, post) => {
                let held = CloseFailure {
                    primary: result.err(),
                    close: closed.err(),
                    post,
                    _owner: self,
                    _purpose: purpose,
                };
                Err(failure(StoreError::StreamIo {
                    operation: "close sealed GC mark scope",
                    source: io::Error::other(held),
                }))
            }
        }
    }
}

impl Drop for SealedMarks {
    fn drop(&mut self) {
        if self.file.is_some() || self.close_uncertain {
            // Explicit finish is the normal route. An unwind or uncertain
            // native close may not refund physical credit. Conservatively
            // quarantine it for this original process's remaining lifetime.
            if let Some(credit) = self.credit.take() {
                std::mem::forget(credit);
            }
        }
    }
}

struct CloseFailure<E> {
    primary: Option<E>,
    close: Option<rustix::io::Errno>,
    post: Option<StoreError>,
    _owner: SealedMarks,
    _purpose: ClosePurpose<E>,
}

impl<E: fmt::Debug> fmt::Debug for CloseFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedMarkCloseFailure")
            .field("primary", &self.primary)
            .field("close", &self.close)
            .field("post", &self.post)
            .finish_non_exhaustive()
    }
}

impl<E: fmt::Display> fmt::Display for CloseFailure<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(primary) = &self.primary {
            fmt::Display::fmt(primary, formatter)
        } else if let Some(close) = &self.close {
            fmt::Display::fmt(close, formatter)
        } else if let Some(post) = &self.post {
            fmt::Display::fmt(post, formatter)
        } else {
            formatter.write_str("sealed GC mark close refused")
        }
    }
}

impl<E: Error + 'static> Error for CloseFailure<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match (&self.primary, &self.close, &self.post) {
            (Some(error), _, _) => Some(error),
            (_, Some(error), _) => Some(error),
            (_, _, Some(error)) => Some(error),
            (None, None, None) => None,
        }
    }
}

fn required_seals() -> SealFlags {
    SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL
}

fn close_file(file: File) -> Result<(), rustix::io::Errno> {
    crucible_host_resources::descriptor::close_owned_descriptor(file.into())
}

fn write_buffer(
    file: &mut File,
    bytes: &[u8],
    operation: &CampaignGcOperationContext<'_>,
) -> Result<(), StoreError> {
    write_all_checked(bytes, &mut || operation.check(), |bytes| file.write(bytes))
}

// Each attempt is one syscall. Successful attempts have their own postcut;
// interrupted attempts return through the original precheck before retrying.
fn read_exact_at_checked(
    mut bytes: &mut [u8],
    mut offset: u64,
    check: &mut impl FnMut() -> Result<(), StoreError>,
    operation: &'static str,
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> Result<(), StoreError> {
    while !bytes.is_empty() {
        check()?;
        let result = read(bytes, offset);
        match result {
            Ok(0) => {
                return Err(io_error(operation, io::ErrorKind::UnexpectedEof.into()));
            }
            Ok(count) => {
                check()?;
                offset = offset.checked_add(count as u64).ok_or(StoreError::Quota)?;
                bytes = bytes.get_mut(count..).ok_or(StoreError::Quota)?;
            }
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(io_error(operation, source)),
        }
    }
    Ok(())
}

fn write_all_checked(
    mut bytes: &[u8],
    check: &mut impl FnMut() -> Result<(), StoreError>,
    mut write: impl FnMut(&[u8]) -> io::Result<usize>,
) -> Result<(), StoreError> {
    while !bytes.is_empty() {
        check()?;
        let result = write(bytes);
        match result {
            Ok(0) => {
                return Err(io_error(
                    "write sealed GC marks",
                    io::ErrorKind::WriteZero.into(),
                ));
            }
            Ok(count) => {
                check()?;
                bytes = bytes.get(count..).ok_or(StoreError::Quota)?;
            }
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(io_error("write sealed GC marks", source)),
        }
    }
    Ok(())
}

fn invalid_stream() -> StoreError {
    StoreError::InvalidComposition {
        reason: "sealed GC mark copy is incomplete or noncanonical",
    }
}

fn missing_file() -> StoreError {
    StoreError::Unsupported {
        capability: "closed-sealed-GC-mark-copy",
    }
}

fn io_error(operation: &'static str, source: io::Error) -> StoreError {
    StoreError::StreamIo { operation, source }
}

#[cfg(test)]
mod tests;
