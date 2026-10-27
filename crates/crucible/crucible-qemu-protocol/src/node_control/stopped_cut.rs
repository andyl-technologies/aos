//! Initial stopped-cut data on an independently pinned observational edition.
//!
//! The source performs its current before/after census on RR, then retains one
//! immutable result. Reader recovery never resamples it. These records provide
//! no Ready, execution, output closure, capture or operation-turnover authority.
//!
//! ```text
//! Query72: scope[32] | prefixPreparation[32] | sequence:u64be=1
//! Result480: Query72 | canonical source record408
//! record408: version/size:u32be=1/408 | actualPID/TID:u64be
//! position24 | raw/epoch/cpuIncarnation/writerGeneration:u64be
//! nextCPU24 | nativeTimer80 | consumedPreparationACK160
//! command/completed/acknowledged/remainingCPU/remainingTimers:u64be
//! timerPresent/nextKind/subset/interruptPending/startupExit/reserved:u32be
//! ```

use crucible_node_format::{Phase, Position, U64};

use super::{
    NativeCommandError, NativePrefixPreparationAcknowledgement, NativePrefixPreparationObservation,
};

/// Sizes the pointer-free initial stopped-cut source record.
pub const NATIVE_STOPPED_CUT_BYTES: usize = 408;

/// Selects the one initial observation without authorizing native effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeStoppedCutQuery {
    /// Correlates the complete independently prepared native scope.
    pub scope: [u8; 32],
    /// Correlates the unchanged complete prefix preparation.
    pub prefix_preparation: [u8; 32],
    /// Selects original observation one; subsequent cuts require a new contract.
    pub sequence: U64,
}

impl NativeStoppedCutQuery {
    /// Encodes the fixed query without granting a source handle or a new cut.
    ///
    /// # Errors
    /// Rejects absent commitments or an observation sequence other than one.
    pub fn encode(&self) -> Result<[u8; 72], NativeCommandError> {
        if self.scope == [0; 32] || self.prefix_preparation == [0; 32] || self.sequence.get() != 1 {
            return Err(NativeCommandError::Conflict);
        }
        let mut bytes = [0; 72];
        bytes[..32].copy_from_slice(&self.scope);
        bytes[32..64].copy_from_slice(&self.prefix_preparation);
        bytes[64..].copy_from_slice(&self.sequence.get().to_be_bytes());
        Ok(bytes)
    }

    /// Decodes one complete query without negotiating the endpoint edition.
    ///
    /// # Errors
    /// Rejects an incorrect extent or invalid original correlation fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let mut cursor = super::codec::Cursor(bytes);
        let query = Self {
            scope: cursor.array()?,
            prefix_preparation: cursor.array()?,
            sequence: U64::new(cursor.u64()?),
        };
        if !cursor.0.is_empty() || bytes != query.encode()? {
            return Err(NativeCommandError::Conflict);
        }
        Ok(query)
    }
}

/// Retains exact canonical data from the initial source-owned stopped census.
///
/// A decoded result remains ordinary data. The retaining host Session must
/// authenticate its query, actual process, original facts and consumed ACK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeStoppedCut {
    query: NativeStoppedCutQuery,
    record: [u8; NATIVE_STOPPED_CUT_BYTES],
}

impl NativeStoppedCut {
    /// Retains a closed source record and its exact original query.
    ///
    /// # Errors
    /// Rejects malformed records, noninitial cuts or inconsistent native fields.
    pub fn from_source_record(
        query: NativeStoppedCutQuery,
        bytes: &[u8],
    ) -> Result<Self, NativeCommandError> {
        let record = bytes.try_into().map_err(|_| NativeCommandError::Conflict)?;
        let observation = Self { query, record };
        observation.validate()?;
        Ok(observation)
    }

    /// Borrows the exact immutable query retained with this observation.
    pub fn query(&self) -> &NativeStoppedCutQuery {
        &self.query
    }

    /// Borrows the source record without converting its bytes to authority.
    pub fn source_record(&self) -> &[u8; NATIVE_STOPPED_CUT_BYTES] {
        &self.record
    }

    /// Returns the actual process identity copied by the RR source.
    ///
    /// # Errors
    /// Refuses malformed canonical scalar storage.
    pub fn process_id(&self) -> Result<u64, NativeCommandError> {
        scalar64(&self.record, 8)
    }

    /// Returns the actual RR thread identity, distinct from the socket reader.
    ///
    /// # Errors
    /// Refuses malformed canonical scalar storage.
    pub fn thread_id(&self) -> Result<u64, NativeCommandError> {
        scalar64(&self.record, 16)
    }

    /// Returns the observed full source cursor without claiming instant closure.
    ///
    /// # Errors
    /// Refuses malformed canonical scalar storage.
    pub fn position(&self) -> Result<Position, NativeCommandError> {
        position(&self.record, 24)
    }

    /// Returns actual raw native retirement independently of the source cursor.
    ///
    /// # Errors
    /// Refuses malformed canonical scalar storage.
    pub fn raw_count(&self) -> Result<u64, NativeCommandError> {
        scalar64(&self.record, 48)
    }

    /// Returns the authentic next native CPU evaluation frontier.
    ///
    /// # Errors
    /// Refuses malformed canonical scalar storage.
    pub fn next_cpu(&self) -> Result<Position, NativeCommandError> {
        position(&self.record, 80)
    }

    /// Copies the original native-consumed preparation acknowledgement data.
    ///
    /// # Errors
    /// Rejects malformed original acknowledgement bytes.
    pub fn consumed_preparation(
        &self,
    ) -> Result<NativePrefixPreparationAcknowledgement, NativeCommandError> {
        NativePrefixPreparationAcknowledgement::decode_record(&self.record[184..344])
    }

    /// Correlates data to the same live Session's independently retained owners.
    ///
    /// This comparison provides no Ready or native execution permission. The
    /// Session additionally authenticates its actual Child and sole endpoint
    /// before and after receipt; an external copy cannot perform that join.
    ///
    /// # Errors
    /// Rejects changed process, scope, initial incarnation, frontier or exact ACK.
    pub fn validate_original(
        &self,
        query: &NativeStoppedCutQuery,
        original: &NativePrefixPreparationObservation,
        consumed: &NativePrefixPreparationAcknowledgement,
        process_id: u32,
    ) -> Result<(), NativeCommandError> {
        self.validate()?;
        if &self.query != query
            || self.query.scope != original.initialization.prepared_scope_hash
            || self.query.prefix_preparation != original.preparation.identity_digest()?
            || self.process_id()? != u64::from(process_id)
            || self.position()? != original.initial
            || scalar64(&self.record, 56)? != original.epoch_incarnation.get()
            || scalar64(&self.record, 64)? != original.cpu_incarnation.get()
            || scalar64(&self.record, 72)? != original.initialization.hold_generation.get()
            || self.next_cpu()?.time_ps != original.next_cpu_deadline_ps
            || self.consumed_preparation()? != *consumed
        {
            return Err(NativeCommandError::Conflict);
        }
        match &original.first_timer {
            None if scalar32(&self.record, 384)? != 0 => {
                return Err(NativeCommandError::Conflict);
            }
            Some(timer)
                if scalar32(&self.record, 384)? != 1
                    || scalar64(&self.record, 104)? != timer.timer_id.get()
                    || scalar64(&self.record, 112)? != timer.list_id.get()
                    || scalar64(&self.record, 120)? != timer.arm_generation.get()
                    || position(&self.record, 136)? != timer.evaluation =>
            {
                return Err(NativeCommandError::Conflict);
            }
            _ => {}
        }
        Ok(())
    }

    /// Encodes the fixed response without exposing a native process layout.
    ///
    /// # Errors
    /// Rejects an invalid query or malformed source record.
    pub fn encode(&self) -> Result<[u8; 480], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; 480];
        bytes[..72].copy_from_slice(&self.query.encode()?);
        bytes[72..].copy_from_slice(&self.record);
        Ok(bytes)
    }

    /// Decodes a complete bounded response without allocating a native DTO.
    ///
    /// # Errors
    /// Rejects incorrect extents, reserved fields or a noninitial source record.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 480 {
            return Err(NativeCommandError::Conflict);
        }
        Self::from_source_record(NativeStoppedCutQuery::decode(&bytes[..72])?, &bytes[72..])
    }

    fn validate(&self) -> Result<(), NativeCommandError> {
        self.query.encode()?;
        let initial = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let next_cpu = self.next_cpu()?;
        let ack = self.consumed_preparation()?;
        let timer_present = scalar32(&self.record, 384)?;
        let next_kind = scalar32(&self.record, 388)?;
        if scalar32(&self.record, 0)? != 1
            || scalar32(&self.record, 4)? != NATIVE_STOPPED_CUT_BYTES as u32
            || self.process_id()? == 0
            || self.thread_id()? == 0
            || self.position()? != initial
            || self.raw_count()? != 0
            || [56, 64, 72]
                .into_iter()
                .any(|offset| scalar64(&self.record, offset) == Ok(0))
            || next_cpu.time_ps.get() == 0
            || next_cpu.microstep.get() != 0
            || next_cpu.phase != Phase::Reaction
            || ack.scope != self.query.scope
            || ack.prefix_preparation != self.query.prefix_preparation
            || scalar64(&self.record, 56)? != ack.epoch_incarnation.get()
            || self.record[344..384] != [0; 40]
            || timer_present > 1
            || !matches!(next_kind, 1 | 2)
            || scalar32(&self.record, 392)? != 1
            || scalar32(&self.record, 396)? > 1
            || scalar32(&self.record, 400)? > 1
            || scalar32(&self.record, 404)? != 0
        {
            return Err(NativeCommandError::Conflict);
        }
        if timer_present == 0 {
            if self.record[104..184] != [0; 80] || next_kind != 1 {
                return Err(NativeCommandError::Conflict);
            }
        } else {
            let timer = position(&self.record, 136)?;
            let parent_kind = scalar32(&self.record, 160)?;
            let parent_id = scalar64(&self.record, 168)?;
            let parent_generation = scalar64(&self.record, 176)?;
            if parent_kind > 2
                || (parent_kind == 0 && (parent_id != 0 || parent_generation != 0))
                || (parent_kind != 0 && (parent_id == 0 || parent_generation == 0))
            {
                return Err(NativeCommandError::Conflict);
            }
            if [104, 112, 120]
                .into_iter()
                .any(|offset| scalar64(&self.record, offset) == Ok(0))
                || timer.phase != Phase::Reaction
                || scalar64(&self.record, 128)? != timer.time_ps.get()
                || scalar32(&self.record, 164)? != 0
                || next_kind != (if timer <= next_cpu { 2 } else { 1 })
            {
                return Err(NativeCommandError::Conflict);
            }
        }
        Ok(())
    }
}

fn scalar32(bytes: &[u8], offset: usize) -> Result<u32, NativeCommandError> {
    let field = bytes
        .get(offset..offset + 4)
        .ok_or(NativeCommandError::Conflict)?;
    Ok(u32::from_be_bytes(
        field.try_into().map_err(|_| NativeCommandError::Conflict)?,
    ))
}

fn scalar64(bytes: &[u8], offset: usize) -> Result<u64, NativeCommandError> {
    let field = bytes
        .get(offset..offset + 8)
        .ok_or(NativeCommandError::Conflict)?;
    Ok(u64::from_be_bytes(
        field.try_into().map_err(|_| NativeCommandError::Conflict)?,
    ))
}

fn position(bytes: &[u8], offset: usize) -> Result<Position, NativeCommandError> {
    let phase = match scalar32(bytes, offset + 16)? {
        0 => Phase::BoundaryControl,
        1 => Phase::Publication,
        2 => Phase::Delivery,
        3 => Phase::Reaction,
        _ => return Err(NativeCommandError::Conflict),
    };
    if scalar32(bytes, offset + 20)? != 0 {
        return Err(NativeCommandError::Conflict);
    }
    Ok(Position::new(
        U64::new(scalar64(bytes, offset)?),
        U64::new(scalar64(bytes, offset + 8)?),
        phase,
    ))
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- Inert schema vectors fail at their defining assertion.
#[allow(clippy::unwrap_used)]
#[path = "stopped_cut_tests.rs"]
mod tests;
