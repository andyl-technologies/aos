//! Derives monitor child identity DATA for the existing execution effect ledger.
//!
//! A caller must borrow the actual current runtime sequence anchor and original
//! admitted source. These fixed identifiers grant no native observation or
//! execution authority. The existing effect journal owns prepare/issue/complete;
//! no separate monitor journal, sequence counter or replay parser is defined.

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use aos_sandbox_core::runtime_backend::{BackendOperationIdV1, BackendOperationSequenceV1};
use sha2::{Digest as _, Sha256};

use crate::ProtocolValidationError;

const DOMAIN: &[u8] = b"aos.sandbox.execution-monitor-child.v5\0";

/// Binds an existing monitor family to a read-only Query3 request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionMonitorSelectorV3 {
    runtime: ObjectDigest,
    first_observe: BackendOperationIdV1,
    source: ObjectDigest,
    source_kind: u32,
}

impl HostExecutionMonitorSelectorV3 {
    /// Checks the fixed selectors without creating a monitor or permission.
    ///
    /// # Errors
    /// Rejects missing coordinates or any source kind other than Stream1/Capture2.
    pub fn new(runtime: ObjectDigest, first_observe: BackendOperationIdV1,
        source: ObjectDigest, source_kind: u32) -> Result<Self, ProtocolValidationError> {
        if runtime.as_bytes() == &[0; 32] || source.as_bytes() == &[0; 32]
            || !matches!(source_kind, 1 | 2) { return Err(invalid()); }
        Ok(Self { runtime, first_observe, source, source_kind })
    }

    /// Returns the protected runtime selector.
    #[must_use]
    pub const fn runtime_v3(self) -> ObjectDigest { self.runtime }

    /// Returns the original first-Observe child.
    #[must_use]
    pub const fn first_observe_v3(self) -> BackendOperationIdV1 { self.first_observe }

    /// Returns the entire tagged original lifetime/source digest.
    #[must_use]
    pub const fn source_v3(self) -> ObjectDigest { self.source }

    /// Returns Stream/PTY1 or physical Capture2.
    #[must_use]
    pub const fn source_kind_v3(self) -> u32 { self.source_kind }

    /// Encodes the fixed selector comparison bytes shared by attempts and grants.
    #[must_use]
    pub fn canonical_comparison_bytes_v3(self) -> [u8; 84] {
        let mut bytes = [0; 84];
        bytes[..32].copy_from_slice(self.runtime.as_bytes());
        bytes[32..48].copy_from_slice(self.first_observe.as_bytes());
        bytes[48..80].copy_from_slice(self.source.as_bytes());
        bytes[80..].copy_from_slice(&self.source_kind.to_be_bytes());
        bytes
    }

    pub(super) fn append_comparison_bytes_v3(self, hash: &mut Sha256) {
        hash.update(self.canonical_comparison_bytes_v3());
    }

    /// Derives an existing ordinary monitor child from the protected sequence DATA.
    ///
    /// # Errors
    /// Rejects unspecified original coordinates or sequence exhaustion.
    pub fn lineage_for_sequence_v3(self, create: OperationId, execution: ExecutionId,
        sequence: BackendOperationSequenceV1) -> Result<ExecutionMonitorLineageDataV5, ProtocolValidationError> {
        ExecutionMonitorLineageDataV5::from_original_source_data_v5(create, execution,
            self.source, self.runtime, sequence, self.first_observe)
    }
}

/// Holds deterministic child identifiers without granting permission to issue them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionMonitorLineageDataV5 {
    create: OperationId,
    execution: ExecutionId,
    source: ObjectDigest,
    runtime: ObjectDigest,
    first_observe: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    operation: BackendOperationIdV1,
    commitment: ObjectDigest,
}

impl ExecutionMonitorLineageDataV5 {
    /// Derives a distinct child from original source and actual runtime sequence DATA.
    ///
    /// The caller still verifies the same original signed admission, native
    /// runtime owner and paid interval before using any returned identifier.
    ///
    /// # Errors
    /// Rejects a missing runtime, sequence wrap, or a zero/colliding derived ID.
    pub fn from_original_source_data_v5(
        create: OperationId, execution: ExecutionId, source: ObjectDigest,
        runtime: ObjectDigest, sequence: BackendOperationSequenceV1,
        first_observe: BackendOperationIdV1,
    ) -> Result<Self, ProtocolValidationError> {
        if create.as_bytes() == &[0; 16] || execution.as_bytes() == &[0; 16]
            || source.as_bytes() == &[0; 32] || runtime.as_bytes() == &[0; 32]
            || sequence.get() == u64::MAX
        {
            return Err(invalid());
        }
        let commitment = ObjectDigest::from_bytes(Sha256::new().chain_update(DOMAIN)
            .chain_update(create.as_bytes()).chain_update(execution.as_bytes())
            .chain_update(source.as_bytes()).chain_update(runtime.as_bytes())
            .chain_update(first_observe.as_bytes()).chain_update(sequence.get().to_be_bytes())
            .finalize().into());
        let mut operation = [0; 16];
        operation.copy_from_slice(&commitment.as_bytes()[..16]);
        if operation == *create.as_bytes() || operation == *first_observe.as_bytes() {
            return Err(invalid());
        }
        let operation = BackendOperationIdV1::new(operation).map_err(|_| invalid())?;
        Ok(Self { create, execution, source, runtime, first_observe, sequence, operation, commitment })
    }

    /// Returns the original accepted Create identity as comparison DATA.
    #[must_use]
    pub const fn create_v5(&self) -> OperationId { self.create }

    /// Returns the exact original execution identity.
    #[must_use]
    pub const fn execution_v5(&self) -> ExecutionId { self.execution }

    /// Returns the complete tagged source commitment.
    #[must_use]
    pub const fn source_v5(&self) -> ObjectDigest { self.source }

    /// Returns the actual protected runtime selector supplied by the caller.
    #[must_use]
    pub const fn runtime_v5(&self) -> ObjectDigest { self.runtime }

    /// Returns the existing historical first-Observe child identity.
    #[must_use]
    pub const fn first_observe_v5(&self) -> BackendOperationIdV1 { self.first_observe }

    /// Returns the global sequence borrowed from the existing effect ledger.
    #[must_use]
    pub const fn sequence_v5(&self) -> BackendOperationSequenceV1 { self.sequence }

    /// Returns the derived child operation identifier.
    #[must_use]
    pub const fn operation_v5(&self) -> BackendOperationIdV1 { self.operation }

    /// Returns the complete lineage commitment used by current protocol binding.
    #[must_use]
    pub const fn commitment_v5(&self) -> ObjectDigest { self.commitment }
}

pub(super) fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("execution monitor child lineage")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lineage(sequence: u64, source: u8, runtime: u8) -> ExecutionMonitorLineageDataV5 {
        ExecutionMonitorLineageDataV5::from_original_source_data_v5(
            OperationId::from_bytes([1; 16]), ExecutionId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([source; 32]), ObjectDigest::from_bytes([runtime; 32]),
            BackendOperationSequenceV1::new(sequence).unwrap(),
            BackendOperationIdV1::new([3; 16]).unwrap(),
        ).unwrap()
    }

    #[test]
    fn existing_runtime_sequence_and_original_source_select_distinct_children() {
        let first = lineage(4, 5, 6);
        assert_eq!(first, lineage(4, 5, 6));
        for changed in [lineage(5, 5, 6), lineage(4, 7, 6), lineage(4, 5, 8)] {
            assert_ne!(first.operation_v5(), changed.operation_v5());
            assert_ne!(first.commitment_v5(), changed.commitment_v5());
        }
        assert_ne!(first.operation_v5().as_bytes(), first.create_v5().as_bytes());
        assert_ne!(first.operation_v5(), first.first_observe_v5());
    }

    #[test]
    fn missing_original_or_runtime_cannot_name_a_monitor_child() {
        for (source, runtime) in [(0, 6), (5, 0)] {
            assert!(ExecutionMonitorLineageDataV5::from_original_source_data_v5(
                OperationId::from_bytes([1; 16]), ExecutionId::from_bytes([2; 16]),
                ObjectDigest::from_bytes([source; 32]), ObjectDigest::from_bytes([runtime; 32]),
                BackendOperationSequenceV1::new(4).unwrap(),
                BackendOperationIdV1::new([3; 16]).unwrap(),
            ).is_err());
        }
    }
}
