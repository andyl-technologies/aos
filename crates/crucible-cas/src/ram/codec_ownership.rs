//! Final-owner custody for bounded RAM object codec allocations.

use std::io::{Cursor, Read};
use std::ops::Deref;
use std::sync::Arc;

use crate::content_envelope::ContentEnvelope;
use crate::content_store::{BlobHandle, BlobSource, StoreError};
use crate::owned_decode::{DecodeBudget, DecodeCustody, DecodeScratch};

use super::RamStoreError;

impl super::RamStore {
    /// Admits one bounded object from the caller or backend's original bank.
    ///
    /// # Errors
    /// Refuses missing original metadata authority, earlier caller failure, or
    /// exhausted aggregate credits. It creates no independent allowance.
    pub(super) fn object_account(&self) -> Result<DecodeBudget, RamStoreError> {
        if let Some(account) = crate::owned_decode::current_child_budget().map_err(admission)? {
            return Ok(account);
        }
        // Native source workers may carry explicit root/page-in loans without
        // an ambient thread scope. Project their existing namespace authority
        // before any backend read can populate a persistent memory cache.
        DecodeBudget::for_store(self.backend.metadata_resources()?).map_err(admission)
    }
}

pub(super) fn admission(source: crate::owned_decode::DecodeAdmissionError) -> RamStoreError {
    StoreError::Supervision {
        source: Box::new(source),
    }
    .into()
}

pub(super) struct OwnedEnvelope {
    envelope: ContentEnvelope,
    _custody: DecodeCustody,
}

impl OwnedEnvelope {
    pub(super) fn new(envelope: ContentEnvelope, account: &DecodeBudget) -> Self {
        Self {
            envelope,
            _custody: account.custody(),
        }
    }
}

impl Deref for OwnedEnvelope {
    type Target = ContentEnvelope;

    fn deref(&self) -> &ContentEnvelope {
        &self.envelope
    }
}

impl PartialEq for OwnedEnvelope {
    fn eq(&self, other: &Self) -> bool {
        self.envelope == other.envelope
    }
}

impl PartialEq<ContentEnvelope> for OwnedEnvelope {
    fn eq(&self, other: &ContentEnvelope) -> bool {
        self.envelope == *other
    }
}

/// Distinguishes original borrowed inputs from explicitly owned small records.
pub(super) enum PublicationInput<'a> {
    Borrowed(&'a ContentEnvelope),
    OwnedSmall(Arc<OwnedEnvelope>),
}

impl PublicationInput<'_> {
    pub(super) fn envelope(&self) -> &ContentEnvelope {
        match self {
            Self::Borrowed(envelope) => envelope,
            Self::OwnedSmall(envelope) => envelope,
        }
    }

    pub(super) fn into_pending(
        self,
        account: &DecodeBudget,
        length: usize,
    ) -> Result<PendingEnvelope, RamStoreError> {
        match self {
            Self::Borrowed(envelope) => {
                account
                    .charge_bytes(ContentEnvelope::decoding_memory_bound(
                        length,
                        envelope.children().len(),
                    )?)
                    .map_err(admission)?;
                Ok(PendingEnvelope::OriginalCopy(OwnedEnvelope::new(
                    envelope.clone(),
                    account,
                )))
            }
            Self::OwnedSmall(envelope) => Ok(PendingEnvelope::OwnedSmall(envelope)),
        }
    }
}

pub(super) enum PendingEnvelope {
    OriginalCopy(OwnedEnvelope),
    OwnedSmall(Arc<OwnedEnvelope>),
}

impl Deref for PendingEnvelope {
    type Target = ContentEnvelope;

    fn deref(&self) -> &ContentEnvelope {
        match self {
            Self::OriginalCopy(envelope) => envelope,
            Self::OwnedSmall(envelope) => envelope,
        }
    }
}

struct OwnedBytes {
    bytes: Vec<u8>,
    original: DecodeBudget,
    _custody: DecodeCustody,
}

struct EncodedSource(Arc<OwnedBytes>);

struct SharedBytes(Arc<OwnedBytes>);

impl AsRef<[u8]> for SharedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0.bytes
    }
}

struct EncodedReader {
    reader: Cursor<SharedBytes>,
    _credit: DecodeScratch,
}

impl Read for EncodedReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(bytes)
    }
}

impl BlobSource for EncodedSource {
    fn logical_length(&self) -> u64 {
        self.0.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        // Deferred opens must not route backend or reader credits into the
        // prepaid codec partition, even after its creating thread scope closes.
        let account = self
            .0
            .original
            .child()
            .map_err(|source| StoreError::Supervision {
                source: Box::new(source),
            })?;
        let credit = account
            .reserve_scratch_bytes(std::mem::size_of::<EncodedReader>() as u64)
            .map_err(|source| StoreError::Supervision {
                source: Box::new(source),
            })?;
        Ok(Box::new(EncodedReader {
            reader: Cursor::new(SharedBytes(Arc::clone(&self.0))),
            _credit: credit,
        }))
    }
}

pub(super) fn encoded_source_bytes() -> u64 {
    (std::mem::size_of::<OwnedBytes>()
        + std::mem::size_of::<EncodedSource>()
        + 4 * std::mem::size_of::<usize>()) as u64
}

pub(super) fn encoded_source(
    bytes: Vec<u8>,
    account: &DecodeBudget,
    original: &DecodeBudget,
) -> Result<BlobHandle, RamStoreError> {
    // The vector moves into the shared body; cloning handles never copies it.
    account
        .charge_bytes(encoded_source_bytes())
        .map_err(admission)?;
    let body = Arc::new(OwnedBytes {
        bytes,
        original: original.clone(),
        _custody: account.custody(),
    });
    Ok(BlobHandle::new(Arc::new(EncodedSource(body))))
}
