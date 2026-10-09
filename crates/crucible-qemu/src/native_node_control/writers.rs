//! Checked assembly of original native writer evidence with retained retry custody.

use super::transport::{NativeQemuControlError, NativeQemuControlTransport};
use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NATIVE_WRITER_OBJECT_MAX_BYTES, NativeCommandError, NativeFrame, NativeWriterChunk,
    NativeWriterObservation, NativeWriterQuery,
};

pub(super) struct WriterAssembly {
    digest: Option<[u8; 32]>,
    total: Option<usize>,
    bytes: Vec<u8>,
    complete: Option<NativeWriterObservation>,
}

impl NativeQemuControlTransport {
    /// Requests the next slice of one retained original writer observation.
    ///
    /// Sequence zero selects the authenticated initial CPU-only park. Other
    /// sequences require the original stop already held by this transport.
    /// Retries select the same next offset and do not resample native queues.
    /// This observation grants no dispatch, input closure or owner readiness.
    ///
    /// # Errors
    /// Rejects unknown cuts, exhausted retention allowances and socket failures.
    pub fn request_writer_observation(
        &mut self,
        sequence: U64,
    ) -> Result<bool, NativeQemuControlError> {
        if self.channel.edition()
            == crucible_protocol::node_control::NativeControlEdition::Original
        {
            return Err(NativeCommandError::UnsupportedVersion(2).into());
        }
        if sequence.get() == 0 {
            if self.cpu_park.is_none() {
                return Err(NativeCommandError::Conflict.into());
            }
        } else if !self.facts.contains_key(&sequence.get()) {
            return Err(NativeCommandError::Conflict.into());
        }
        let retained_count = self.writer_objects.len();
        let assembly = match self.writer_objects.entry(sequence.get()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                // Reserve the full per-object bound before requesting bytes.
                // Later peer totals cannot enlarge this allocation policy.
                if retained_count >= 32 {
                    return Err(NativeCommandError::ResourceLimit.into());
                }
                entry.insert(WriterAssembly {
                    digest: None,
                    total: None,
                    bytes: Vec::new(),
                    complete: None,
                })
            }
        };
        let offset = if assembly.complete.is_some() {
            0
        } else {
            assembly.bytes.len() as u64
        };
        Ok(self
            .channel
            .send(&NativeFrame::QueryWriters(NativeWriterQuery {
                prepared_scope_hash: self.prepared_scope_hash,
                sequence,
                offset: U64::new(offset),
            }))?)
    }

    /// Returns the same retained coherent original writer observation after assembly.
    ///
    /// Complete writer rows establish no IRQ, input, device or output closure.
    pub fn writer_observation(&self, sequence: U64) -> Option<&NativeWriterObservation> {
        self.writer_objects.get(&sequence.get())?.complete.as_ref()
    }

    pub(super) fn accept_writer_chunk(
        &mut self,
        chunk: &NativeWriterChunk,
    ) -> Result<(), NativeQemuControlError> {
        if chunk.prepared_scope_hash != self.prepared_scope_hash {
            return Err(NativeCommandError::Conflict.into());
        }
        let initial = self
            .writer_objects
            .get(&0)
            .and_then(|initial| initial.complete.as_ref())
            .map(|cut| (cut.gate_generation, cut.roster_sha256));
        let assembly = self
            .writer_objects
            .get_mut(&chunk.sequence.get())
            .ok_or(NativeCommandError::Conflict)?;
        let total = usize::try_from(chunk.total_bytes.get())
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        let offset =
            usize::try_from(chunk.offset.get()).map_err(|_| NativeCommandError::ResourceLimit)?;
        if total > NATIVE_WRITER_OBJECT_MAX_BYTES
            || assembly
                .digest
                .is_some_and(|digest| digest != chunk.object_digest)
            || assembly.total.is_some_and(|original| original != total)
        {
            return Err(NativeCommandError::Conflict.into());
        }
        let end = offset
            .checked_add(chunk.bytes.len())
            .filter(|end| *end <= total)
            .ok_or(NativeCommandError::ResourceLimit)?;
        if offset < assembly.bytes.len() {
            if end > assembly.bytes.len() || assembly.bytes[offset..end] != chunk.bytes {
                return Err(NativeCommandError::Conflict.into());
            }
            return Ok(());
        }
        if offset != assembly.bytes.len() {
            return Err(NativeCommandError::Conflict.into());
        }
        let mut candidate = assembly.bytes.clone();
        candidate.extend_from_slice(&chunk.bytes);
        let complete = if end == total {
            if blake3::hash(&candidate).as_bytes() != &chunk.object_digest {
                return Err(NativeCommandError::Conflict.into());
            }
            let observation = NativeWriterObservation::decode(&candidate)?;
            if observation.prepared_scope_hash != self.prepared_scope_hash
                || observation.sequence != chunk.sequence
            {
                return Err(NativeCommandError::Conflict.into());
            }
            if chunk.sequence.get() == 0 {
                let original = self.cpu_park.as_ref().ok_or(NativeCommandError::Conflict)?;
                if observation.current_ps != original.current_ps
                    || observation.command_digest != [0; 32]
                    || observation.retired_count != original.retired_count
                    || observation.roster_sha256 != original.roster_sha256
                {
                    return Err(NativeCommandError::Conflict.into());
                }
            } else {
                let original = self
                    .facts
                    .get(&chunk.sequence.get())
                    .ok_or(NativeCommandError::Conflict)?;
                if observation.current_ps != original.reached.time_ps
                    || observation.command_digest != original.command_digest
                    || observation.retired_count != original.retired_count
                    || initial.is_none_or(|(generation, roster)| {
                        generation != observation.gate_generation
                            || roster != observation.roster_sha256
                    })
                {
                    return Err(NativeCommandError::Conflict.into());
                }
            }
            Some(observation)
        } else {
            None
        };
        assembly.digest = Some(chunk.object_digest);
        assembly.total = Some(total);
        assembly.bytes = candidate;
        assembly.complete = complete;
        Ok(())
    }
}
