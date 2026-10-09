//! Original post-Applied source bytes joined with the actual initialization journal.
//!
//! Native sampling occurs only at the original Applied callback. Administrative
//! readers recover retained bytes and never sample source state. Partial fetches,
//! allocation refusal, token loss and failed validation retain the original source
//! identity and bytes. This module grants no Ready, input, capture or fork proof.

use std::sync::{Mutex, TryLockError};

use crucible_protocol::node_control::{
    NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES, NativeCommandError, NativeInitializationReceipt,
    NativeInitializationStatus, NativePreparationSuccessorChunk, NativePreparationSuccessorFacts,
    NativePreparationSuccessorObservation, NativePreparationSuccessorQuery,
};

use super::initialization_custody::InitializationCustody;
use super::preparation_successor_abi::{
    NativePreparationSuccessorAbi, QueryPreparationSuccessor, ReadPreparationSuccessor,
};

const CHUNK_BYTES: usize = 3000;

#[derive(Default)]
struct OriginalSuccessor {
    receipt: Option<NativeInitializationReceipt>,
    facts: Option<NativePreparationSuccessorFacts>,
    bytes: Vec<u8>,
    decoded: Option<NativePreparationSuccessorObservation>,
    failed: bool,
}

#[cfg(test)]
#[path = "preparation_successor_custody_tests.rs"]
mod tests;

/// Retains one immutable source object without replacing historical initial cuts.
pub(crate) struct PreparationSuccessorCustody {
    query: QueryPreparationSuccessor,
    read: ReadPreparationSuccessor,
    original: Mutex<OriginalSuccessor>,
}

impl PreparationSuccessorCustody {
    pub(crate) fn new(query: QueryPreparationSuccessor, read: ReadPreparationSuccessor) -> Self {
        Self {
            query,
            read,
            original: Mutex::new(OriginalSuccessor::default()),
        }
    }

    /// Captures only the original source Applied callback's complete observation.
    ///
    /// A cached retry reads no source. A transient native read refusal preserves
    /// its original identity and prefix, so a later retry continues that object.
    /// No observation can replace the source-selected initial sequence-zero cut.
    ///
    /// # Errors
    /// Refuses busy/poisoned custody, non-Applied or changed original receipts,
    /// foreign source facts, malformed bytes, and bounded allocation failures.
    pub(crate) fn observe_after_applied(
        &self,
        receipt: &NativeInitializationReceipt,
    ) -> Result<(), NativeCommandError> {
        receipt.validate()?;
        if receipt.status != NativeInitializationStatus::Applied {
            return Err(NativeCommandError::Conflict);
        }
        let mut original = self.try_original()?;
        if original.failed
            || original
                .receipt
                .as_ref()
                .is_some_and(|value| value != receipt)
        {
            return Err(NativeCommandError::Conflict);
        }
        if original.decoded.is_some() {
            return Ok(());
        }
        if original.receipt.is_none() {
            // The complete allowance is reserved before the native source can
            // create its original object. No subsequent receive/effect depends
            // on acquiring a new byte allowance.
            original
                .bytes
                .try_reserve_exact(NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES)
                .map_err(|_| NativeCommandError::ResourceLimit)?;
            original.receipt = Some(receipt.clone());
        }
        if original.facts.is_none() {
            let mut facts = NativePreparationSuccessorAbi::default();
            let status = (self.query)(
                receipt.prepared_scope_hash.as_ptr(),
                receipt.sequence.get(),
                receipt.original_cut_digest.as_ptr(),
                &mut facts,
            );
            if status != 0 {
                if facts != NativePreparationSuccessorAbi::default() {
                    original.failed = true;
                }
                return Err(NativeCommandError::Conflict);
            }
            let facts = match facts.decode() {
                Ok(facts) => facts,
                Err(error) => {
                    original.failed = true;
                    return Err(error);
                }
            };
            if facts.initialization_sequence != receipt.sequence
                || facts.hold_generation != receipt.hold_generation
                || facts.prepared_scope_hash != receipt.prepared_scope_hash
                || facts.initialization_commitment != receipt.initialization_commitment
                || facts.realize_request_digest != receipt.realize_request_digest
                || facts.original_cut_digest != receipt.original_cut_digest
            {
                original.failed = true;
                return Err(NativeCommandError::Conflict);
            }
            original.facts = Some(facts);
        }
        let facts = original.facts.clone().ok_or(NativeCommandError::Conflict)?;
        let length = usize::try_from(facts.content_length.get())
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        while original.bytes.len() < length {
            let capacity = (length - original.bytes.len()).min(CHUNK_BYTES);
            let mut bytes = [0; CHUNK_BYTES];
            let mut copied = 0;
            let status = (self.read)(
                facts.prepared_scope_hash.as_ptr(),
                facts.initialization_sequence.get(),
                facts.content_sha256.as_ptr(),
                original.bytes.len() as u64,
                bytes.as_mut_ptr(),
                capacity as u32,
                &mut copied,
            );
            if status != 0 {
                if copied != 0 {
                    original.failed = true;
                }
                return Err(NativeCommandError::Conflict);
            }
            if copied as usize != capacity {
                original.failed = true;
                return Err(NativeCommandError::Conflict);
            }
            original.bytes.extend_from_slice(&bytes[..capacity]);
        }
        let decoded = match NativePreparationSuccessorObservation::decode(facts, &original.bytes) {
            Ok(decoded) => decoded,
            Err(error) => {
                if !matches!(error, NativeCommandError::ResourceLimit) {
                    original.failed = true;
                }
                return Err(error);
            }
        };
        if &decoded.initialization != receipt {
            original.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        original.decoded = Some(decoded);
        Ok(())
    }

    /// Copies historical source bytes only after the actual original ACK is held.
    ///
    /// The byte copy carries no execution permission or Ready attestation. The
    /// installed common adapter still needs complete worker, queue and phase
    /// evidence. An Applied source flag is never substituted for this journal ACK.
    ///
    /// # Errors
    /// Refuses an absent, changed or unacknowledged original initialization,
    /// incomplete/failed source custody, busy ownership or bounded copy refusal.
    pub(crate) fn acknowledged_original_chunk(
        &self,
        initialization: &InitializationCustody,
        query: &NativePreparationSuccessorQuery,
    ) -> Result<NativePreparationSuccessorChunk, NativeCommandError> {
        query.validate()?;
        if !initialization.permits_execution_transport() {
            return Err(NativeCommandError::Conflict);
        }
        let receipt = initialization
            .original_receipt()
            .ok_or(NativeCommandError::Conflict)?;
        let original = self.try_original()?;
        if original.failed
            || original.decoded.is_none()
            || original.receipt.as_ref() != Some(&receipt)
        {
            return Err(NativeCommandError::Conflict);
        }
        let facts = original
            .facts
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        if query.prepared_scope_hash != facts.prepared_scope_hash
            || query.initialization_sequence != facts.initialization_sequence
            || query.original_cut_digest != facts.original_cut_digest
        {
            return Err(NativeCommandError::Conflict);
        }
        let offset =
            usize::try_from(query.offset.get()).map_err(|_| NativeCommandError::ResourceLimit)?;
        if offset >= original.bytes.len() {
            return Err(NativeCommandError::Conflict);
        }
        let length = (original.bytes.len() - offset).min(CHUNK_BYTES);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        bytes.extend_from_slice(&original.bytes[offset..offset + length]);
        Ok(NativePreparationSuccessorChunk {
            facts: facts.clone(),
            offset: query.offset,
            bytes,
        })
    }

    fn try_original(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, OriginalSuccessor>, NativeCommandError> {
        match self.original.try_lock() {
            Ok(original) => Ok(original),
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {
                Err(NativeCommandError::Conflict)
            }
        }
    }
}
