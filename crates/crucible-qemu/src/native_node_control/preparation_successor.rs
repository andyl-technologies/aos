//! Original post-initialization evidence under independently retained ACK custody.
//!
//! The host assembles exact source bytes and preserves their distinct historical
//! identity. A verified digest and original ACK do not establish current native
//! suspension, input closure, simulation-node readiness or capture qualification.

use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES, NativeCommandError, NativeControlEdition, NativeFrame,
    NativeInitializationReceipt, NativePhasePreparation, NativePreparationSuccessorChunk,
    NativePreparationSuccessorFacts, NativePreparationSuccessorObservation,
    NativePreparationSuccessorQuery,
};

use super::{NativeLaunchEndpoint, NativeQemuControlError, NativeQemuControlTransport};

#[derive(Default)]
pub(super) struct SuccessorAssembly {
    receipt: Option<NativeInitializationReceipt>,
    facts: Option<NativePreparationSuccessorFacts>,
    bytes: Vec<u8>,
    complete: Option<NativePreparationSuccessorObservation>,
    failed: bool,
}

impl NativeQemuControlTransport {
    /// Pins separately negotiated successor recovery before native launch.
    ///
    /// The installed provider must authenticate the original preparation and
    /// source exports. This optional diagnostic transport grants no node profile.
    ///
    /// # Errors
    /// Rejects invalid preparation or bounded socket/framing failures.
    pub fn prepare_successor(
        preparation: NativePhasePreparation,
    ) -> Result<(Self, NativeLaunchEndpoint), NativeQemuControlError> {
        let (mut transport, endpoint) = Self::prepare_phase_for_edition(
            preparation,
            NativeControlEdition::PreparationSuccessor,
        )?;
        transport.preparation_successor = Some(SuccessorAssembly::default());
        Ok((transport, endpoint))
    }

    /// Requests the next original source byte slice after its actual matching ACK.
    ///
    /// Credit is reserved before emitting the first request. Lost replies retry
    /// the same prefix or the original completed object; no source cut is selected.
    ///
    /// # Errors
    /// Rejects missing preparation/ACK, source faults, sticky divergence, bounded
    /// allocation failure or physical channel failure.
    pub fn request_preparation_successor(&mut self) -> Result<bool, NativeQemuControlError> {
        if self.channel.edition() != NativeControlEdition::PreparationSuccessor {
            return Err(NativeCommandError::Conflict.into());
        }
        let receipt = self.acknowledged_initialization_receipt()?.clone();
        let original = self
            .preparation_successor
            .as_mut()
            .ok_or(NativeCommandError::Conflict)?;
        if original.failed
            || original
                .receipt
                .as_ref()
                .is_some_and(|value| value != &receipt)
        {
            return Err(NativeCommandError::Conflict.into());
        }
        if original.receipt.is_none() {
            original
                .bytes
                .try_reserve_exact(NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES)
                .map_err(|_| NativeCommandError::ResourceLimit)?;
            original.receipt = Some(receipt.clone());
        }
        let offset = if original.complete.is_some() {
            0
        } else {
            original.bytes.len() as u64
        };
        Ok(self.channel.send(&NativeFrame::QueryPreparationSuccessor(
            NativePreparationSuccessorQuery {
                prepared_scope_hash: receipt.prepared_scope_hash,
                initialization_sequence: receipt.sequence,
                original_cut_digest: receipt.original_cut_digest,
                offset: U64::new(offset),
            },
        ))?)
    }

    /// Returns the distinct historical object without replacing initial observations.
    pub fn preparation_successor(&self) -> Option<&NativePreparationSuccessorObservation> {
        let original = self.preparation_successor.as_ref()?;
        if original.failed {
            None
        } else {
            original.complete.as_ref()
        }
    }

    pub(super) fn accept_preparation_successor_chunk(
        &mut self,
        chunk: &NativePreparationSuccessorChunk,
    ) -> Result<(), NativeQemuControlError> {
        let receipt = self.acknowledged_initialization_receipt()?.clone();
        let original = self
            .preparation_successor
            .as_mut()
            .ok_or(NativeCommandError::Conflict)?;
        original.accept(&receipt, chunk).map_err(Into::into)
    }
}

impl SuccessorAssembly {
    fn accept(
        &mut self,
        receipt: &NativeInitializationReceipt,
        chunk: &NativePreparationSuccessorChunk,
    ) -> Result<(), NativeCommandError> {
        let result = self.accept_inner(receipt, chunk);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn accept_inner(
        &mut self,
        receipt: &NativeInitializationReceipt,
        chunk: &NativePreparationSuccessorChunk,
    ) -> Result<(), NativeCommandError> {
        chunk.validate()?;
        if self.failed
            || self.receipt.as_ref() != Some(receipt)
            || chunk.facts.prepared_scope_hash != receipt.prepared_scope_hash
            || chunk.facts.initialization_sequence != receipt.sequence
            || chunk.facts.initialization_commitment != receipt.initialization_commitment
            || chunk.facts.realize_request_digest != receipt.realize_request_digest
            || chunk.facts.original_cut_digest != receipt.original_cut_digest
            || chunk.facts.hold_generation != receipt.hold_generation
            || self
                .facts
                .as_ref()
                .is_some_and(|facts| facts != &chunk.facts)
        {
            return Err(NativeCommandError::Conflict);
        }
        let offset =
            usize::try_from(chunk.offset.get()).map_err(|_| NativeCommandError::ResourceLimit)?;
        let end = offset
            .checked_add(chunk.bytes.len())
            .ok_or(NativeCommandError::ResourceLimit)?;
        if offset < self.bytes.len() {
            return if end <= self.bytes.len() && self.bytes[offset..end] == chunk.bytes {
                Ok(())
            } else {
                Err(NativeCommandError::Conflict)
            };
        }
        if offset != self.bytes.len() || self.complete.is_some() {
            return Err(NativeCommandError::Conflict);
        }
        self.facts = Some(chunk.facts.clone());
        self.bytes.extend_from_slice(&chunk.bytes);
        if end as u64 == chunk.facts.content_length.get() {
            let decoded =
                NativePreparationSuccessorObservation::decode(chunk.facts.clone(), &self.bytes)?;
            if &decoded.initialization != receipt {
                return Err(NativeCommandError::Conflict);
            }
            self.complete = Some(decoded);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "preparation_successor_tests.rs"]
mod tests;
