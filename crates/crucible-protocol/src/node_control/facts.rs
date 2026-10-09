//! Portable native stop facts and original acknowledgement correlation.
//!
//! These scalar observations are not RFC-0025 complete stop receipts. They do
//! not establish input custody, output bounds or complete native queue inventory.
//! A provider must authenticate and preserve those independent records before
//! qualifying the corresponding node profile.

use crucible_node_contract::{Position, U64};

use super::{ExecutionCommand, NativeCommandError, OwnerScope};

/// Selects a closed native engine stop disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NativeStopKind {
    /// Parks at the exclusive horizon without a transition there.
    HorizonPark = 1,
    /// Stops at an independently encountered native event boundary.
    NativeBoundary = 2,
    /// Refuses a timing or phase combination the native implementation lacks.
    Unsupported = 3,
    /// Contains malformed or conflicting native command material.
    Invalid = 4,
}

/// Preserves original native observations without projecting intended progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeStopFacts {
    /// Names the original retained positive command sequence.
    pub sequence: U64,
    /// Binds every immutable byte of its original command.
    pub command_digest: [u8; 32],
    /// Selects the native stop cause independently of complete source closure.
    pub kind: NativeStopKind,
    /// Locates actual observed native logical time and phase.
    pub reached: Position,
    /// Records actual native retirement independently of logical time.
    pub retired_count: U64,
    /// Reports known pending native classes, with all bits set meaning unknown.
    ///
    /// A zero value also does not establish a complete queue inventory.
    pub pending_classes: u32,
    /// Locates the next native alarm, or null when unavailable.
    pub next_native_deadline_ps: Option<U64>,
    /// Locates the anchored pending instruction service deadline, if available.
    pub next_service_deadline_ps: Option<U64>,
    /// Preserves partially supplied instruction service across horizon parks.
    pub pending_service_credit_ps: U64,
}

impl NativeStopFacts {
    pub(super) fn validate(&self) -> Result<(), NativeCommandError> {
        if self.sequence.get() == 0 {
            return Err(NativeCommandError::Invalid(
                "native stop sequence must be positive",
            ));
        }
        if self
            .next_native_deadline_ps
            .is_some_and(|deadline| deadline.get() == u64::MAX)
            || self
                .next_service_deadline_ps
                .is_some_and(|deadline| deadline.get() == u64::MAX)
        {
            return Err(NativeCommandError::Invalid(
                "native absent deadline sentinel must be null",
            ));
        }
        Ok(())
    }
}

/// Correlates an authenticated host commitment with original native custody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptAcknowledgement {
    /// Names the original positive command sequence.
    pub sequence: U64,
    /// Binds all immutable original command bytes.
    pub command_digest: [u8; 32],
    /// Retains the original complete native authorization commitment.
    pub authorization_digest: [u8; 32],
}

/// Pins complete inactive native owner preparation before any execution command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePreparation {
    /// Names the exact originally prepared immutable and live scope.
    pub scope: OwnerScope,
    /// Locates the unchanged original initial or restored native cut.
    pub boundary: Position,
    /// Bounds original commands and retained native facts for this incarnation.
    pub maximum_commands: U64,
}

impl NativePreparation {
    pub(super) fn validate(&self) -> Result<(), NativeCommandError> {
        self.scope.validate()?;
        if self.maximum_commands.get() == 0 || self.maximum_commands.get() > 65_536 {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(())
    }
}

/// Selects a closed frame of the independently negotiated native channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeFrame {
    /// Selects a retained original held-writer object on an edition-two endpoint.
    QueryWriters(super::NativeWriterQuery),
    /// Returns bounded bytes from the same retained original writer object.
    WriterChunk(super::NativeWriterChunk),
    /// Supplies the independently prepared complete nonexecuting owner scope.
    Prepare(Box<NativePreparation>),
    /// Supplies a complete original native command claim.
    Command(Box<ExecutionCommand>),
    /// Returns original native scalar facts without complete closure claims.
    Stopped(NativeStopFacts),
    /// Settles custody after matching authenticated canonical publication.
    Acknowledge(ReceiptAcknowledgement),
    /// Returns the provider journal's original custody acknowledgement.
    ///
    /// This confirms journal settlement only, not complete native resource cleanup.
    Acknowledged(ReceiptAcknowledgement),
    /// Returns original CPU-only facts, never all-owner readiness.
    CpuPark(NativeCpuParkFacts),
    /// Requests the same retained original CPU-only observation without execution.
    QueryCpuPark([u8; 32]),
    /// Requests a slice of the same retained original timer observation.
    QueryTimers(super::NativeTimerQuery),
    /// Returns bounded original canonical timer bytes without closure claims.
    TimerChunk(super::NativeTimerChunk),
}

/// Preserves an original native CPU-only administrative park observation.
///
/// These facts authenticate no input closure, device queues, state inventory,
/// current physical suspension, all-writer readiness or execution authority.
/// A retained initial observation remains historical after a later command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeCpuParkFacts {
    /// Reports only CPU-park coverage; edition one requires exactly bit zero.
    pub coverage: u32,
    /// Counts the finalized fixed actual native CPU roster, at most 1024.
    pub cpu_count: u32,
    /// Records the original native logical clock without a superdense claim.
    pub current_ps: U64,
    /// Records actual original retirement independently of logical time.
    pub retired_count: U64,
    /// Preserves the original next service deadline, or null if unknown.
    pub next_service_deadline_ps: Option<U64>,
    /// Preserves original pending instruction service credit.
    pub pending_service_credit_ps: U64,
    /// Binds the complete immutable inactive prepared scope.
    pub prepared_scope_hash: [u8; 32],
    /// Binds the tagged ascending little-endian actual CPU indices with SHA-256.
    pub roster_sha256: [u8; 32],
}

impl NativeCpuParkFacts {
    pub(super) fn validate(&self) -> Result<(), NativeCommandError> {
        if self.coverage != 1
            || self.cpu_count == 0
            || self.cpu_count > 1024
            || self.prepared_scope_hash == [0; 32]
            || self.roster_sha256 == [0; 32]
            || self
                .next_service_deadline_ps
                .is_some_and(|deadline| deadline.get() == u64::MAX)
        {
            return Err(NativeCommandError::Invalid(
                "invalid CPU-only native park facts",
            ));
        }
        Ok(())
    }
}
