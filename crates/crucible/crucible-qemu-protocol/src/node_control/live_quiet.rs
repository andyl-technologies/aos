//! Retained live-source retirement and truthful zero-evaluation operation DATA.
//!
//! ```text
//! identity104: scope32 | preparation32 | command32 | sequence:u64be
//! quiet952: identity104 | status/reserved:u32be | pid/epoch/generation:u64be
//!           before-current408 | after-current408
//! proposal640: version/size | identity | pid/epoch/raw/generation/cut:u64be
//!              position24 | resultDigest32 | current408 | reserved24
//! receipt128: proposalDigest32 | terminalArchive32 | pid/epoch/sequence/generation
//!             position24 | raw:u64be
//! commit160: receiptDigest32 | receiptArchive32 | proposalDigest32
//!            sequence/generation | position24 | raw/epoch/pid:u64be
//! ```
//!
//! These closed records grant no native handle, Ready, capture or evaluation
//! permission. Their actual source, endpoint, Child and durable archive joins
//! remain the responsibility of the retaining live Session.

use crucible_node_format::{Phase, Position, U64};
use sha2::{Digest, Sha256};

use super::{
    ExecutionCommand, ExecutionKind, NativeCommandError, NativePrefixPreparationAcknowledgement,
};

/// Correlates one original operation without reconstructing native ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLiveIdentity {
    /// Identifies the complete prepared scope.
    pub scope: [u8; 32],
    /// Identifies the complete original prefix preparation.
    pub preparation: [u8; 32],
    /// Identifies the complete unchanged execution command.
    pub command: [u8; 32],
    /// Orders operations in the same original incarnation.
    pub sequence: U64,
}

impl NativeLiveIdentity {
    /// Derives correlation DATA from the unchanged original command.
    ///
    /// # Errors
    /// Rejects invalid command material or an absent preparation identity.
    pub fn from_command(
        command: &ExecutionCommand,
        preparation: [u8; 32],
    ) -> Result<Self, NativeCommandError> {
        command.validate()?;
        let identity = Self {
            scope: command.scope.identity_digest()?,
            preparation,
            command: command.identity_digest()?,
            sequence: command.sequence,
        };
        identity.encode()?;
        Ok(identity)
    }

    /// Encodes exact fixed-endian identity bytes.
    ///
    /// # Errors
    /// Rejects absent identities or sequence zero.
    pub fn encode(&self) -> Result<[u8; 104], NativeCommandError> {
        if self.scope == [0; 32]
            || self.preparation == [0; 32]
            || self.command == [0; 32]
            || self.sequence.get() == 0
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut bytes = [0; 104];
        bytes[..32].copy_from_slice(&self.scope);
        bytes[32..64].copy_from_slice(&self.preparation);
        bytes[64..96].copy_from_slice(&self.command);
        bytes[96..].copy_from_slice(&self.sequence.get().to_be_bytes());
        Ok(bytes)
    }

    /// Decodes one complete identity, never a Source token.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes or invalid closed fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 104 {
            return Err(NativeCommandError::Conflict);
        }
        let identity = Self {
            scope: array(&bytes[..32])?,
            preparation: array(&bytes[32..64])?,
            command: array(&bytes[64..96])?,
            sequence: U64::new(u64_at(bytes, 96)?),
        };
        identity.encode()?;
        Ok(identity)
    }
}

/// Requests only a source-proved interval containing no native evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeQuietCommand {
    /// Retains the complete admitted command and full-position input closure.
    pub command: ExecutionCommand,
    /// Correlates original prefix preparation.
    pub preparation: [u8; 32],
    /// Names the exact preceding source committed record.
    pub predecessor_commit: [u8; 32],
    /// Orders the complete canonical empty input batch under the held epoch.
    pub input_batch_sequence: U64,
}

impl NativeQuietCommand {
    /// Checks quiet shape and complete empty input identity without granting work.
    ///
    /// # Errors
    /// Refuses malformed input, absent predecessor, unsupported operation or an
    /// ExactRun ceiling containing a phase at its physical ceiling tick.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.command.validate()?;
        NativeLiveIdentity::from_command(&self.command, self.preparation)?;
        let empty = crucible_node_format::InputBatch {
            schema_version: 1,
            execution_owner_id: self.command.scope.owner.clone(),
            input_epoch: self.command.input_epoch.clone(),
            batch_id: self.command.input_batch.clone(),
            batch_sequence: self.input_batch_sequence,
            events: Vec::new(),
            extensions: Default::default(),
        };
        let limit = self.command.kind.limit();
        if self.command.kind.start().time_ps.get() > i64::MAX as u64
            || limit.time_ps.get() > i64::MAX as u64
        {
            return Err(NativeCommandError::Conflict);
        }

        if matches!(
            self.command.kind,
            ExecutionKind::ExactRun {
                boundary_policy: super::BoundaryPolicy::InputBlockedPark,
                ..
            }
        ) || self.command.authorization_digest == [0; 32]
            || self.predecessor_commit == [0; 32]
            || self.input_batch_sequence.get() == 0
            || empty.identity().map_err(|_| NativeCommandError::Conflict)?
                != self.command.input_batch_hash
            || !matches!(
                self.command.kind,
                ExecutionKind::ExactRun { .. } | ExecutionKind::BoundarySettle { .. }
            )
            || (matches!(self.command.kind, ExecutionKind::ExactRun { .. })
                && (limit.microstep.get() != 0 || limit.phase != Phase::BoundaryControl))
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }
}

/// Distinguishes actual empty-prefix completion from due native work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeQuietStatus {
    /// Commits precisely the authorized half-open prefix without evaluation.
    Completed,
    /// Retains the unchanged source because genuine work prevents a quiet step.
    NeedsEvaluation,
}

/// Retains an actual current source census, distinct from the initial-only codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeCurrentCensus([u8; 408]);

impl NativeCurrentCensus {
    /// Decodes fixed scalar source facts without promoting them to authority.
    ///
    /// # Errors
    /// Refuses malformed extents, fields, identities, timer shape or reserved data.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let record: [u8; 408] = array(bytes)?;
        let census = Self(record);
        let timer = u32_at(bytes, 384)?;
        let next_kind = u32_at(bytes, 388)?;
        let cursor = census.position()?;
        let next_cpu = position(bytes, 80)?;
        if u32_at(bytes, 0)? != 1
            || u32_at(bytes, 4)? != 408
            || [8, 16, 56, 64, 72]
                .into_iter()
                .any(|at| u64_at(bytes, at) == Ok(0))
            || next_cpu.phase != Phase::Reaction
            || next_cpu.microstep.get() != 0
            || next_cpu < cursor
            || u64_at(bytes, 360)? > u64_at(bytes, 352)?
            || timer > 1
            || !matches!(next_kind, 1 | 2)
            || u32_at(bytes, 392)? != 1
            || u32_at(bytes, 396)? > 1
            || u32_at(bytes, 400)? > 1
            || u32_at(bytes, 404)? != 0
        {
            return Err(NativeCommandError::Conflict);
        }
        NativePrefixPreparationAcknowledgement::decode_record(&bytes[184..344])?;
        if timer == 0 {
            if bytes[104..184] != [0; 80] || next_kind != 1 {
                return Err(NativeCommandError::Conflict);
            }
        } else {
            let evaluation = position(bytes, 136)?;
            let parent = u32_at(bytes, 160)?;
            let id = u64_at(bytes, 168)?;
            let generation = u64_at(bytes, 176)?;
            if [104, 112, 120]
                .into_iter()
                .any(|at| u64_at(bytes, at) == Ok(0))
                || evaluation.phase != Phase::Reaction
                || evaluation < cursor
                || u64_at(bytes, 128)? != evaluation.time_ps.get()
                || u32_at(bytes, 164)? != 0
                || parent > 2
                || (parent == 0 && (id != 0 || generation != 0))
                || (parent != 0 && (id == 0 || generation == 0))
                || next_kind != if evaluation <= next_cpu { 2 } else { 1 }
            {
                return Err(NativeCommandError::Conflict);
            }
        }
        Ok(census)
    }

    /// Borrows the canonical portable bytes.
    pub fn bytes(&self) -> &[u8; 408] {
        &self.0
    }

    /// Returns the authentic full source cursor as ordinary DATA.
    ///
    /// # Errors
    /// Rejects malformed scalar storage.
    pub fn position(&self) -> Result<Position, NativeCommandError> {
        position(&self.0, 24)
    }

    /// Returns actual native retirement independently of semantic position.
    ///
    /// # Errors
    /// Rejects malformed scalar storage.
    pub fn raw(&self) -> Result<u64, NativeCommandError> {
        u64_at(&self.0, 48)
    }

    fn obstructs(&self, limit: Position) -> Result<bool, NativeCommandError> {
        Ok(u32_at(&self.0, 396)? != 0
            || u32_at(&self.0, 400)? != 0
            || position(&self.0, 80)? < limit
            || (u32_at(&self.0, 384)? == 1 && position(&self.0, 136)? < limit))
    }

    fn validate_identity(
        &self,
        identity: &NativeLiveIdentity,
        pid: u64,
        epoch: u64,
    ) -> Result<(), NativeCommandError> {
        let ack = NativePrefixPreparationAcknowledgement::decode_record(&self.0[184..344])?;
        if u64_at(&self.0, 8)? != pid
            || u64_at(&self.0, 56)? != epoch
            || ack.scope != identity.scope
            || ack.prefix_preparation != identity.preparation
            || ack.epoch_incarnation.get() != epoch
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }
}

/// Retains a truthful zero-evaluation result with genuine before/after source data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeQuietProgress([u8; 952]);

impl NativeQuietProgress {
    /// Decodes one complete portable quiet-result record.
    ///
    /// # Errors
    /// Refuses malformed identities, status, source fields or a changed lineage.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let result = Self(array(bytes)?);
        let identity = result.identity()?;
        let pid = u64_at(bytes, 112)?;
        let epoch = u64_at(bytes, 120)?;
        if !matches!(u32_at(bytes, 104)?, 1 | 2)
            || u32_at(bytes, 108)? != 0
            || pid == 0
            || epoch == 0
            || u64_at(bytes, 128)? == 0
        {
            return Err(NativeCommandError::Conflict);
        }
        let before = result.before()?;
        let after = result.after()?;
        before.validate_identity(&identity, pid, epoch)?;
        after.validate_identity(&identity, pid, epoch)?;
        let mut expected = *before.bytes();
        expected[24..48].copy_from_slice(&after.bytes()[24..48]);
        if expected != *after.bytes() {
            return Err(NativeCommandError::Conflict);
        }
        Ok(result)
    }

    /// Borrows canonical result bytes.
    pub fn bytes(&self) -> &[u8; 952] {
        &self.0
    }

    /// Returns the unchanged original command identity.
    ///
    /// # Errors
    /// Rejects malformed scalar storage.
    pub fn identity(&self) -> Result<NativeLiveIdentity, NativeCommandError> {
        NativeLiveIdentity::decode(&self.0[..104])
    }

    /// Returns the actual pre-transition census.
    ///
    /// # Errors
    /// Rejects malformed source storage.
    pub fn before(&self) -> Result<NativeCurrentCensus, NativeCommandError> {
        NativeCurrentCensus::decode(&self.0[136..544])
    }

    /// Returns the actual post-transition census.
    ///
    /// # Errors
    /// Rejects malformed source storage.
    pub fn after(&self) -> Result<NativeCurrentCensus, NativeCommandError> {
        NativeCurrentCensus::decode(&self.0[544..])
    }

    /// Validates the result against the complete retained quiet command.
    ///
    /// # Errors
    /// Rejects false completion, a hidden due source, foreign identities or an
    /// unsupported refusal without an actual source obstruction.
    pub fn validate_original(
        &self,
        original: &NativeQuietCommand,
        pid: u32,
    ) -> Result<NativeQuietStatus, NativeCommandError> {
        original.validate()?;
        let before = self.before()?;
        let after = self.after()?;
        let start = original.command.kind.start();
        let limit = original.command.kind.limit();
        if self.identity()?
            != NativeLiveIdentity::from_command(&original.command, original.preparation)?
            || u64_at(&self.0, 112)? != u64::from(pid)
            || before.position()? != start
        {
            return Err(NativeCommandError::Conflict);
        }
        match u32_at(&self.0, 104)? {
            1 if !before.obstructs(limit)? && after.position()? == limit => {
                Ok(NativeQuietStatus::Completed)
            }
            2 if before.obstructs(limit)? && after == before => {
                Ok(NativeQuietStatus::NeedsEvaluation)
            }
            _ => Err(NativeCommandError::Conflict),
        }
    }
}

/// Requests retirement of the exact current terminal operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRetireOriginal {
    /// Names the complete original operation.
    pub identity: NativeLiveIdentity,
    /// Retains the last genuine consumed prefix ACK, or zero for a quiet result.
    pub final_acknowledgement: [u8; 192],
}

/// Authenticates a durable archive boundary against an original native record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLiveAccept {
    /// Names the complete original operation.
    pub identity: NativeLiveIdentity,
    /// Names the exact SHA256 of the retained native proposal or receipt.
    pub native_digest: [u8; 32],
    /// Names the exact original durable archive terminal or receipt record.
    pub archive_digest: [u8; 32],
}

/// Retains source-owned current-cut retirement proposal DATA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRetirementProposal([u8; 640]);

impl NativeRetirementProposal {
    /// Decodes one closed portable proposal without granting native release.
    ///
    /// # Errors
    /// Refuses malformed native/source identities, reserved bytes or cursor/raw mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let result = Self(array(bytes)?);
        let identity = result.identity()?;
        let current = result.current()?;
        if u32_at(bytes, 0)? != 1
            || u32_at(bytes, 4)? != 640
            || bytes[616..] != [0; 24]
            || [112, 120, 136]
                .into_iter()
                .any(|at| u64_at(bytes, at) == Ok(0))
            || bytes[176..208] == [0; 32]
            || current.position()? != position(bytes, 152)?
            || current.raw()? != u64_at(bytes, 128)?
        {
            return Err(NativeCommandError::Conflict);
        }
        current.validate_identity(&identity, u64_at(bytes, 112)?, u64_at(bytes, 120)?)?;
        Ok(result)
    }

    /// Borrows the canonical source proposal.
    pub fn bytes(&self) -> &[u8; 640] {
        &self.0
    }

    /// Computes the canonical proposal identity, never an ownership token.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    /// Returns original operation correlation DATA.
    ///
    /// # Errors
    /// Rejects malformed storage.
    pub fn identity(&self) -> Result<NativeLiveIdentity, NativeCommandError> {
        NativeLiveIdentity::decode(&self.0[8..112])
    }

    /// Returns the freshly sampled current census.
    ///
    /// # Errors
    /// Rejects malformed source storage.
    pub fn current(&self) -> Result<NativeCurrentCensus, NativeCommandError> {
        NativeCurrentCensus::decode(&self.0[208..616])
    }
}

/// Retains native acceptance of the exact durable terminal archive record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRetirementReceipt([u8; 128]);

impl NativeRetirementReceipt {
    /// Decodes one fixed receipt without claiming host durability.
    ///
    /// # Errors
    /// Rejects malformed extent, absent identities or invalid positions.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let result = Self(array(bytes)?);
        if bytes[..32] == [0; 32]
            || bytes[32..64] == [0; 32]
            || [64, 72, 80, 88]
                .into_iter()
                .any(|at| u64_at(bytes, at) == Ok(0))
        {
            return Err(NativeCommandError::Conflict);
        }
        position(bytes, 96)?;
        Ok(result)
    }

    /// Borrows the exact native receipt.
    pub fn bytes(&self) -> &[u8; 128] {
        &self.0
    }

    /// Computes the native canonical receipt identity.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    /// Joins native acceptance to the exact proposal and original archive record.
    ///
    /// # Errors
    /// Rejects changed native source, operation, cursor, raw state or archive identity.
    pub fn validate_original(
        &self,
        proposal: &NativeRetirementProposal,
        terminal_digest: [u8; 32],
    ) -> Result<(), NativeCommandError> {
        let p = proposal.bytes();
        if self.0[..32] != proposal.digest()
            || self.0[32..64] != terminal_digest
            || self.0[64..72] != p[112..120]
            || self.0[72..80] != p[120..128]
            || self.0[80..88] != p[104..112]
            || self.0[88..96] != p[136..144]
            || self.0[96..120] != p[152..176]
            || self.0[120..128] != p[128..136]
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }
}

/// Retains actual native commit after the exact durable-receipt acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRetirementCommitted([u8; 160]);

impl NativeRetirementCommitted {
    /// Decodes bounded commit DATA without reopening a source or host slot.
    ///
    /// # Errors
    /// Rejects malformed extent, absent identities or invalid position fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        let result = Self(array(bytes)?);
        if bytes[..32] == [0; 32]
            || bytes[32..64] == [0; 32]
            || bytes[64..96] == [0; 32]
            || [96, 104, 144, 152]
                .into_iter()
                .any(|at| u64_at(bytes, at) == Ok(0))
        {
            return Err(NativeCommandError::Conflict);
        }
        position(bytes, 112)?;
        Ok(result)
    }

    /// Borrows the exact native committed record.
    pub fn bytes(&self) -> &[u8; 160] {
        &self.0
    }

    /// Names the source-confirmed predecessor for the next original quiet request.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    /// Joins commit to actual native receipt and the original durable receipt record.
    ///
    /// # Errors
    /// Rejects changed source, operation, position/raw or either archive/native digest.
    pub fn validate_original(
        &self,
        receipt: &NativeRetirementReceipt,
        receipt_archive: [u8; 32],
    ) -> Result<(), NativeCommandError> {
        let r = receipt.bytes();
        if self.0[..32] != receipt.digest()
            || self.0[32..64] != receipt_archive
            || self.0[64..96] != r[..32]
            || self.0[96..104] != r[80..88]
            || self.0[104..112] != r[88..96]
            || self.0[112..136] != r[96..120]
            || self.0[136..144] != r[120..128]
            || self.0[144..152] != r[72..80]
            || self.0[152..160] != r[64..72]
        {
            return Err(NativeCommandError::Conflict);
        }
        Ok(())
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NativeCommandError> {
    bytes.try_into().map_err(|_| NativeCommandError::Conflict)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, NativeCommandError> {
    Ok(u32::from_be_bytes(array(
        bytes
            .get(offset..offset + 4)
            .ok_or(NativeCommandError::Conflict)?,
    )?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, NativeCommandError> {
    Ok(u64::from_be_bytes(array(
        bytes
            .get(offset..offset + 8)
            .ok_or(NativeCommandError::Conflict)?,
    )?))
}

fn position(bytes: &[u8], offset: usize) -> Result<Position, NativeCommandError> {
    let phase = match u32_at(bytes, offset + 16)? {
        0 => Phase::BoundaryControl,
        1 => Phase::Publication,
        2 => Phase::Delivery,
        3 => Phase::Reaction,
        _ => return Err(NativeCommandError::Conflict),
    };
    let time = u64_at(bytes, offset)?;
    if u32_at(bytes, offset + 20)? != 0 || time > i64::MAX as u64 {
        return Err(NativeCommandError::Conflict);
    }
    Ok(Position::new(
        U64::new(time),
        U64::new(u64_at(bytes, offset + 8)?),
        phase,
    ))
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- Inert closed DATA vectors fail at defining assertions.
// crucible-lint: allow panic-shortcut -- Inert closed DATA vectors fail at defining assertions.
#[allow(clippy::unwrap_used)]
#[path = "live_quiet_tests.rs"]
mod tests;
