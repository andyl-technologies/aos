//! Copies ordered Blob inputs into the seven previously reserved exact banks.
//!
//! The defining native dispatcher must authenticate each actual current
//! Prepare/token/connection/original before these private DATA mutations. Its
//! ProtocolGuard owns literal retries and cached replies; a new Chunk must be
//! contiguous. This module neither interprets the bodies nor installs a model.

use super::*;
use crate::bodies::{BlobBeginRequest, BlobChunkRequest, BlobFinishRequest};
use crucible_node_format::Id;

const MAXIMUM_CHUNK_BYTES: usize = 4096;

impl InputBank {
    fn matches(&self, transfer: &Id) -> bool {
        self.begun && self.transfer[..self.transfer_length] == *transfer.as_str().as_bytes()
    }
}

impl OriginalImport18ReceivingBanks {
    /// Starts the next exact full-reference transfer without allocating.
    ///
    /// # Errors
    /// Refuses absent reservation, foreign/reused transfers, changed full
    /// references or extensions. A refused new request poisons this occurrence.
    pub(in super::super) fn begin_data(
        &mut self,
        begin: &BlobBeginRequest,
    ) -> Result<usize, ProviderError> {
        let result = self.begin_current(begin);
        self.retain_outcome(result)
    }

    fn begin_current(&mut self, begin: &BlobBeginRequest) -> Result<usize, ProviderError> {
        if self.phase != ReceivePhase::Receiving || !begin.extensions.is_empty() {
            return Err(unavailable());
        }
        let bank = self.banks.get(self.next_input).ok_or_else(unavailable)?;
        if bank.reference.as_ref() != Some(&begin.content) || bank.finished {
            return Err(unavailable());
        }
        if bank.begun {
            return if bank.matches(&begin.transfer_id) {
                Ok(bank.received)
            } else {
                Err(unavailable())
            };
        }
        let transfer = begin.transfer_id.as_str().as_bytes();
        if transfer.is_empty()
            || transfer.len() > bank.transfer.len()
            || self.banks.iter().any(|old| old.matches(&begin.transfer_id))
        {
            return Err(unavailable());
        }

        let bank = self
            .banks
            .get_mut(self.next_input)
            .ok_or_else(unavailable)?;
        bank.transfer[..transfer.len()].copy_from_slice(transfer);
        bank.transfer_length = transfer.len();
        bank.begun = true;
        Ok(0)
    }

    /// Appends the next contiguous bounded chunk within already reserved space.
    ///
    /// The original literal/reply cache handles retransmission of the same
    /// request. This new-request mutation never rewrites previously copied data.
    ///
    /// # Errors
    /// Refuses a foreign transfer, gap, overlap, empty/overlarge chunk, extensions
    /// or excess bytes. Refusal retains existing bytes and poisons the occurrence.
    pub(in super::super) fn chunk_data(
        &mut self,
        chunk: &BlobChunkRequest,
    ) -> Result<usize, ProviderError> {
        let result = self.chunk_current(chunk);
        self.retain_outcome(result)
    }

    fn chunk_current(&mut self, chunk: &BlobChunkRequest) -> Result<usize, ProviderError> {
        if self.phase != ReceivePhase::Receiving || !chunk.extensions.is_empty() {
            return Err(unavailable());
        }
        let bank = self
            .banks
            .get_mut(self.next_input)
            .ok_or_else(unavailable)?;
        let offset = usize::try_from(chunk.offset.get()).map_err(|_| unavailable())?;
        let bytes = chunk.bytes.as_slice();
        let end = offset.checked_add(bytes.len()).ok_or_else(exhausted)?;
        let expected = bank.reference.as_ref().ok_or_else(unavailable)?;
        if !bank.matches(&chunk.transfer_id)
            || bank.finished
            || offset != bank.received
            || bank.bytes.len() != bank.received
            || bytes.is_empty()
            || bytes.len() > MAXIMUM_CHUNK_BYTES
            || u64::try_from(end).map_err(|_| exhausted())? > expected.length.get()
            || end > bank.bytes.capacity()
        {
            return Err(unavailable());
        }

        // Exact reservation and the checked end make this append non-growing.
        bank.bytes.extend_from_slice(bytes);
        bank.received = end;
        Ok(end)
    }

    /// Checks the complete next bank against its retained normative reference.
    ///
    /// # Errors
    /// Refuses incomplete, foreign, changed or incorrectly hashed content,
    /// extensions or order. Refusal retains the full failed bank and reference.
    pub(in super::super) fn finish_data(
        &mut self,
        finish: &BlobFinishRequest,
    ) -> Result<usize, ProviderError> {
        let result = self.finish_current(finish);
        self.retain_outcome(result)
    }

    fn finish_current(&mut self, finish: &BlobFinishRequest) -> Result<usize, ProviderError> {
        if self.phase != ReceivePhase::Receiving || !finish.extensions.is_empty() {
            return Err(unavailable());
        }
        let bank = self
            .banks
            .get_mut(self.next_input)
            .ok_or_else(unavailable)?;
        if !bank.matches(&finish.transfer_id) || bank.finished || bank.received != bank.bytes.len()
        {
            return Err(unavailable());
        }
        verify_content(
            bank.reference.as_ref().ok_or_else(unavailable)?,
            &bank.bytes,
        )?;
        bank.finished = true;
        let ordinal = bank.role.ordinal_data();
        self.next_input = self.next_input.checked_add(1).ok_or_else(exhausted)?;
        if self.next_input == self.banks.len() {
            self.phase = ReceivePhase::Complete;
        }
        Ok(ordinal)
    }

    /// Borrows only all seven completely hash-checked bodies in their exact order.
    ///
    /// Original token/connection/cut currentness remains the enclosing lender's
    /// obligation. These bytes create no validated model or opaque phase result.
    ///
    /// # Errors
    /// Refuses partial, failed or unreserved transfer state.
    pub(in super::super) fn bodies_data(&self) -> Result<[&[u8]; 7], ProviderError> {
        if self.phase != ReceivePhase::Complete
            || self.next_input != self.banks.len()
            || self.banks.iter().any(|bank| !bank.finished)
        {
            return Err(unavailable());
        }
        Ok(self.banks.each_ref().map(|bank| bank.bytes.as_slice()))
    }

    fn retain_outcome<T>(&mut self, result: Result<T, ProviderError>) -> Result<T, ProviderError> {
        if result.is_err() {
            self.phase = ReceivePhase::Failed;
        }
        result
    }
}

fn verify_content(reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError> {
    if reference.length.get() != u64::try_from(bytes.len()).map_err(|_| exhausted())? {
        return Err(unavailable());
    }
    // The full reference was checked before reservation. This is the normative
    // CNP/1 blob framing, with no allocating HashRef or hexadecimal String.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&reference.length.get().to_be_bytes());
    hasher.update(bytes);
    if hasher.finalize().to_hex().as_str() != reference.hash.digest {
        return Err(unavailable());
    }
    Ok(())
}

/// Names the fixed request, copying, full-content hashing and body-loan controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        // ArrayString returned by BLAKE3 includes its length header as well as
        // the complete fixed hexadecimal bank. Infer that actual return layout.
        + hex_layout(blake3::Hash::to_hex)
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + size_of::<&BlobBeginRequest>()
        + size_of::<&BlobChunkRequest>()
        + size_of::<&BlobFinishRequest>()
        + size_of::<&OriginalImport18ReceivingBanks>()
        + size_of::<&mut OriginalImport18ReceivingBanks>() * 2
        + size_of::<&ContentRef>() * 2
        + size_of::<&HashRef>() * 2
        + size_of::<&String>() * 4
        + size_of::<&crucible_node_format::Extensions>()
        + size_of::<&Vec<u8>>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<&Id>()
        + size_of::<&str>() * 2
        + size_of::<&[u8]>() * 3
        + size_of::<&InputBank>()
        + size_of::<&mut InputBank>()
        + size_of::<Option<&InputBank>>()
        + size_of::<Option<&mut InputBank>>()
        + size_of::<Option<&ContentRef>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<Result<(), ProviderError>>()
        + size_of::<[&[u8]; 7]>()
        + size_of::<Result<[&[u8]; 7], ProviderError>>()
        + size_of::<[&InputBank; 7]>()
        + size_of::<std::array::IntoIter<&InputBank, 7>>()
        + size_of::<usize>() * 4
        + size_of::<u64>()
        + size_of::<bool>() * 2
}

fn hex_layout<T>(_method: fn(&blake3::Hash) -> T) -> usize {
    size_of::<T>()
}
