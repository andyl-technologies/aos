//! Staged edition-two control framing and whole-world storage geometry.
//!
//! This edition separates accepted input stages from compute operations. Public
//! data cannot certify native ownership: both endpoints retain their original
//! native/host allocations and authenticate them before accepting these bytes.
//!
//! ```text
//! Profile168: edition2; unchanged fields0..159; stages:u32@160, stage_cap:u32@164
//! Frame24: CWHLCTL\0, edition2:u32, kind:u32, body_extent:u32, reserved0:u32
//! All integers are big endian; complete bodies remain at most65536 bytes.
//! ```

#[path = "staged/body.rs"]
pub mod body;

#[path = "staged/queue_plan.rs"]
pub mod queue_plan;

#[path = "staged/plan_ack.rs"]
pub mod plan_ack;

#[path = "staged/selection.rs"]
pub mod selection;

#[path = "staged/launch.rs"]
pub mod launch;

#[path = "staged/launch2.rs"]
pub mod launch2;

#[path = "staged/administrative.rs"]
pub mod administrative;

#[path = "staged/source_ready.rs"]
pub mod source_ready;

#[cfg(test)]
#[path = "staged/tests.rs"]
pub(crate) mod tests;

use super::{
    WHOLE_ACK_BYTES, WHOLE_BODY_MAX_BYTES, WHOLE_FRAME_HEADER_BYTES, WHOLE_FRAME_MAGIC,
    WHOLE_OPERATION_MAX, WHOLE_PROFILE_BYTES, WholeControlError, WholeControlProfile,
    domain_digest, put_u32, read_u32,
};

/// Selects the independently negotiated staged control edition.
pub const STAGED_CONTROL_EDITION: u32 = 2;
/// Counts a complete original stage inventory prefix.
pub const STAGE_HEADER_BYTES: usize = 128;
/// Counts one complete source-issued stage receipt.
pub const STAGE_RECEIPT_BYTES: usize = 256;
/// Counts one complete source-issued queue-plan prefix.
pub const QUEUE_PLAN_HEADER_BYTES: usize = 128;
/// Counts the fixed public queue-role binding before its identifiers.
pub const QUEUE_PLAN_ROLE_BYTES: usize = 80;

/// Selects one body in the closed staged frame grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StagedFrameKind {
    /// Offers the original source-issued queue and clock plan.
    QueuePlan = 1,
    /// Confirms the complete same original queue plan.
    QueuePlanAcknowledgement = 2,
    /// Offers complete original input for private queue reservation.
    StageInventory = 3,
    /// Returns the original native receipt after successful reservation.
    StageReceipt = 4,
    /// Confirms the source-issued stage receipt before execution.
    StageCommit = 5,
    /// Confirms native consumption of the original stage commit.
    StageCommitAcknowledgement = 6,
    /// Requests compute using retained stage references.
    ExecutionRequest = 7,
    /// Returns the original native compute result.
    ExecutionResult = 8,
    /// Confirms the same original complete native compute result.
    ExecutionAcknowledgement = 9,
    /// Offers one source-issued complete closure receipt.
    SourceReady = 10,
    /// Confirms that exact retained source receipt and original source cut.
    SourceReadyAcknowledgement = 11,
    /// Confirms native consumption of the same readiness acknowledgement.
    SourceReadyAcknowledgementConsumed = 12,
}

/// Selects separate nonrenewing stage and compute constructor capacities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedControlProfile {
    /// Retains scope, compute capacities and whole-world aggregate allowances.
    pub compute: WholeControlProfile,
    /// Bounds separately indexed original input stages without recycling.
    pub input_stage_limit: u32,
    /// Bounds each entire staged body, including identities and evidence.
    pub stage_body_byte_limit: u32,
}

impl StagedControlProfile {
    /// Checks all public storage minima before either provider is installed.
    ///
    /// # Errors
    /// Rejects unsupported limits, overflowing whole-world geometry, or history
    /// and administrative budgets smaller than the complete public histories.
    /// Native metadata and local reservation overhead require separate checks.
    pub fn validate(&self) -> Result<(), WholeControlError> {
        self.compute.validate()?;
        if self.compute.body_byte_limit < super::WHOLE_RESULT_HEADER_BYTES as u32 + 8
            || !(1..=WHOLE_OPERATION_MAX).contains(&self.input_stage_limit)
            || self.stage_body_byte_limit < (STAGE_HEADER_BYTES + 8 + 4) as u32
            || self.stage_body_byte_limit > WHOLE_BODY_MAX_BYTES
        {
            return Err(WholeControlError::Budget);
        }

        let history = self.minimum_wire_history_bytes()?;
        let (read_attempts, write_attempts, read_bytes, write_bytes) =
            self.minimum_administrative_io();

        if self.compute.native_history_byte_limit < history
            || self.compute.provider_history_byte_limit < history
            || self.compute.administrative_read_attempt_limit < read_attempts
            || self.compute.administrative_write_attempt_limit < write_attempts
            || self.compute.administrative_read_byte_limit < read_bytes
            || self.compute.administrative_write_byte_limit < write_bytes
        {
            return Err(WholeControlError::Budget);
        }
        Ok(())
    }

    /// Checks one preowned source-readiness exchange for a selected backend.
    ///
    /// The constructor reserves a body at its selected compute ceiling, two
    /// acknowledgements and three frame headers. This capacity check neither
    /// supplies source ownership or readiness authority. Any backend using the
    /// readiness grammar checks this before effects; historical constructors
    /// that do not select this grammar retain their original capacity rules.
    ///
    /// # Errors
    /// Rejects malformed profiles or insufficient nonrenewing administrative
    /// credit and full retained history backing for the additional exchange.
    pub fn validate_ready_exchange_capacity(&self) -> Result<(), WholeControlError> {
        self.validate()?;
        let body = u64::from(self.compute.body_byte_limit);
        let history = self
            .minimum_wire_history_bytes()?
            .checked_add(body + 2 * 128 + 3 * 24)
            .ok_or(WholeControlError::Budget)?;
        let (read_attempts, write_attempts, read_bytes, write_bytes) =
            self.minimum_administrative_io();
        let direction_bytes = body + 128 + 2 * 24;
        if self.compute.native_history_byte_limit < history
            || self.compute.provider_history_byte_limit < history
            || self.compute.administrative_read_attempt_limit < read_attempts + 4
            || self.compute.administrative_write_attempt_limit < write_attempts + 2
            || self.compute.administrative_read_byte_limit < read_bytes + direction_bytes
            || self.compute.administrative_write_byte_limit < write_bytes + direction_bytes
        {
            return Err(WholeControlError::Budget);
        }
        Ok(())
    }

    fn minimum_administrative_io(&self) -> (u64, u64, u64, u64) {
        let operations = u64::from(self.compute.operation_capacity);
        let stages = u64::from(self.input_stage_limit);
        // The fixed initial handshake uses two prefix/body read pairs. Each
        // staged receive also retains its header before reading the body.
        let read_attempts = 2 * (operations * 2 + stages * 2 + 1) + 4;
        let write_attempts = operations * 2 + stages * 2 + 1 + 2;
        let read_bytes = operations * (256 + 8 + 128 + 2 * 24)
            + stages * (STAGE_HEADER_BYTES + 8 + 4 + 128 + 2 * 24) as u64
            + (128 + 24)
            + 34;
        let write_bytes = operations * (336 + 8 + 128 + 2 * 24)
            + stages * (256 + 128 + 2 * 24)
            + (QUEUE_PLAN_HEADER_BYTES + 24) as u64
            + 34;

        (read_attempts, write_attempts, read_bytes, write_bytes)
    }

    /// Counts full public histories, the original plan and parser scratch.
    ///
    /// # Errors
    /// Rejects arithmetic overflow. This lower bound does not include native
    /// allocation metadata or prove that a constructor owns sufficient memory.
    pub fn minimum_wire_history_bytes(&self) -> Result<u64, WholeControlError> {
        let body = u64::from(self.compute.body_byte_limit);
        let stage_body = u64::from(self.stage_body_byte_limit);
        let compute = u64::from(self.compute.operation_capacity)
            .checked_mul(2 * body + 2 * 128 + 4 * 24)
            .ok_or(WholeControlError::Budget)?;
        let stages = u64::from(self.input_stage_limit)
            .checked_mul(stage_body + 256 + 2 * 128 + 4 * 24)
            .ok_or(WholeControlError::Budget)?;
        compute
            .checked_add(stages)
            .and_then(|total| total.checked_add(body + 128 + 2 * 24))
            .and_then(|total| total.checked_add(body.max(stage_body) + 24))
            .ok_or(WholeControlError::Budget)
    }

    /// Encodes the entire edition-two profile into fixed portable bytes.
    ///
    /// # Errors
    /// Rejects a profile that fails its constructor geometry checks.
    pub fn encode(&self) -> Result<[u8; WHOLE_PROFILE_BYTES], WholeControlError> {
        self.validate()?;
        let mut body = self.compute.encode()?;
        put_u32(&mut body, 8, STAGED_CONTROL_EDITION);
        put_u32(&mut body, 160, self.input_stage_limit);
        put_u32(&mut body, 164, self.stage_body_byte_limit);
        Ok(body)
    }

    /// Decodes the complete independently selected staged profile.
    ///
    /// # Errors
    /// Rejects another edition, an invalid base layout, or inadequate budgets.
    pub fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        if body.len() != WHOLE_PROFILE_BYTES || read_u32(body, 8) != STAGED_CONTROL_EDITION {
            return Err(WholeControlError::Profile);
        }
        let mut base = [0; WHOLE_PROFILE_BYTES];
        base.copy_from_slice(body);
        // Reuse only the edition-one field validator; callers cannot negotiate
        // the original edition using a staged profile or vice versa.
        put_u32(&mut base, 8, super::WHOLE_CONTROL_EDITION);
        base[160..168].fill(0);
        let profile = Self {
            compute: WholeControlProfile::decode(&base)?,
            input_stage_limit: read_u32(body, 160),
            stage_body_byte_limit: read_u32(body, 164),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Hashes the complete original profile under the staged domain.
    ///
    /// # Errors
    /// Rejects malformed constructor profiles before hashing.
    pub fn digest(&self) -> Result<[u8; 32], WholeControlError> {
        Ok(domain_digest(
            b"crucible.qemu.whole.profile.v2\0",
            &self.encode()?,
        ))
    }
}

/// Encodes a closed staged frame into preowned header backing.
///
/// # Errors
/// Rejects a body outside its constructor-selected kind-specific ceiling.
pub fn encode_frame_header(
    kind: StagedFrameKind,
    body_bytes: usize,
    profile: &StagedControlProfile,
) -> Result<[u8; WHOLE_FRAME_HEADER_BYTES], WholeControlError> {
    check_extent(kind, body_bytes, profile)?;
    let mut header = [0; WHOLE_FRAME_HEADER_BYTES];
    header[..8].copy_from_slice(&WHOLE_FRAME_MAGIC);
    put_u32(&mut header, 8, STAGED_CONTROL_EDITION);
    put_u32(&mut header, 12, kind as u32);
    put_u32(&mut header, 16, body_bytes as u32);
    Ok(header)
}

/// Checks one entire staged frame header before receiving its body.
///
/// # Errors
/// Rejects unknown kinds, editions, reserved fields and inadmissible extents.
pub fn decode_frame_header(
    header: &[u8],
    profile: &StagedControlProfile,
) -> Result<(StagedFrameKind, usize), WholeControlError> {
    if header.len() != WHOLE_FRAME_HEADER_BYTES
        || header[..8] != WHOLE_FRAME_MAGIC
        || read_u32(header, 8) != STAGED_CONTROL_EDITION
        || read_u32(header, 20) != 0
    {
        return Err(WholeControlError::Envelope);
    }
    let kind = match read_u32(header, 12) {
        1 => StagedFrameKind::QueuePlan,
        2 => StagedFrameKind::QueuePlanAcknowledgement,
        3 => StagedFrameKind::StageInventory,
        4 => StagedFrameKind::StageReceipt,
        5 => StagedFrameKind::StageCommit,
        6 => StagedFrameKind::StageCommitAcknowledgement,
        7 => StagedFrameKind::ExecutionRequest,
        8 => StagedFrameKind::ExecutionResult,
        9 => StagedFrameKind::ExecutionAcknowledgement,
        10 => StagedFrameKind::SourceReady,
        11 => StagedFrameKind::SourceReadyAcknowledgement,
        12 => StagedFrameKind::SourceReadyAcknowledgementConsumed,
        _ => return Err(WholeControlError::Envelope),
    };
    let extent = read_u32(header, 16) as usize;
    check_extent(kind, extent, profile)?;
    Ok((kind, extent))
}

fn check_extent(
    kind: StagedFrameKind,
    extent: usize,
    profile: &StagedControlProfile,
) -> Result<(), WholeControlError> {
    if matches!(
        kind,
        StagedFrameKind::SourceReady
            | StagedFrameKind::SourceReadyAcknowledgement
            | StagedFrameKind::SourceReadyAcknowledgementConsumed
    ) {
        profile.validate_ready_exchange_capacity()?;
    }

    let valid = match kind {
        StagedFrameKind::QueuePlan => {
            (QUEUE_PLAN_HEADER_BYTES..=profile.compute.body_byte_limit as usize).contains(&extent)
        }
        StagedFrameKind::StageInventory => {
            (STAGE_HEADER_BYTES + 8 + 4..=profile.stage_body_byte_limit as usize).contains(&extent)
        }
        StagedFrameKind::StageReceipt => extent == STAGE_RECEIPT_BYTES,
        StagedFrameKind::SourceReady => extent == source_ready::SOURCE_READY_BYTES,
        StagedFrameKind::ExecutionRequest => {
            (256 + 8..=profile.compute.body_byte_limit as usize).contains(&extent)
        }
        StagedFrameKind::ExecutionResult => {
            (336 + 8..=profile.compute.body_byte_limit as usize).contains(&extent)
        }
        StagedFrameKind::QueuePlanAcknowledgement
        | StagedFrameKind::StageCommit
        | StagedFrameKind::StageCommitAcknowledgement
        | StagedFrameKind::ExecutionAcknowledgement
        | StagedFrameKind::SourceReadyAcknowledgement
        | StagedFrameKind::SourceReadyAcknowledgementConsumed => extent == WHOLE_ACK_BYTES,
    };
    if valid {
        Ok(())
    } else {
        Err(WholeControlError::Envelope)
    }
}
