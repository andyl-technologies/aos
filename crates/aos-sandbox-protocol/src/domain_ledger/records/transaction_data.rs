//! Owns nonauthorizing prepared and postcommit transaction comparison DATA.
//!
//! These values describe supplied canonical members, before/after images and
//! phase classifications. Public construction neither checks a protected owner
//! nor grants paid work, retry, settlement, publication or an effect. Actual
//! role adapters keep their native writer/original/currentness/private instance
//! outside these models and construct their accepted wrappers only there.

use aos_sandbox_core::{ObjectDigest, RecordNamespace};
use super::{
    ProtectedDomainEnvelopeV1, ProtectedDomainSchemaV1, ProtectedRecordRoleV1,
    ProtectedReducerPhaseV1,
};
use crate::domain_ledger::{DomainLedgerDataError, JournalTransactionDataError};
use crate::domain_ledger::transaction::JournalTransaction;

/// Owns exact supplied transaction/predecessor/successor comparison DATA.
///
/// Field order is the original native prepared-member destruction order. The
/// owning native snapshot/instance remains private to each actual role wrapper.
pub struct DomainPreparedTransactionDataV1 {
    /// Carries the exact canonical transaction; it is not an admitted append.
    pub transaction: JournalTransaction,
    /// Retains one original before-image per ordered record.
    pub before: Vec<Option<Vec<u8>>>,
    /// Retains one exact intended durable value per ordered record.
    pub after: Vec<Vec<u8>>,
    /// Carries supplied schema-role classifications as DATA only.
    pub roles: Vec<ProtectedRecordRoleV1>,
    /// Carries the supplied canonical transaction commitment.
    pub digest: ObjectDigest,
    /// Carries the supplied complete durable-member set commitment.
    pub set_digest: ObjectDigest,
}

impl DomainPreparedTransactionDataV1 {
    /// Moves supplied comparison fields without validating or admitting them.
    pub fn from_comparison_parts(
        transaction: JournalTransaction,
        before: Vec<Option<Vec<u8>>>,
        after: Vec<Vec<u8>>,
        roles: Vec<ProtectedRecordRoleV1>,
        digest: ObjectDigest,
        set_digest: ObjectDigest,
    ) -> Self {
        Self { transaction, before, after, roles, digest, set_digest }
    }

}

/// Bounds resident canonical payload DATA without supplying financial admission.
///
/// The actual role separately owns/pays its native operation and retained model
/// reservoir. This counter is only the same checked byte-limit recipe used by
/// those consumers; no ResourceVector, original, grant or credit is created.
pub struct ResidentCanonicalPayloadBudgetDataV1 {
    maximum: usize,
    retained: usize,
}

impl ResidentCanonicalPayloadBudgetDataV1 {
    /// Creates the supplied plain byte counter without allocation or admission.
    pub const fn new(maximum: usize) -> Self {
        Self { maximum, retained: 0 }
    }

    /// Reports the existing checked retained-byte count as DATA only.
    pub const fn retained(&self) -> usize {
        self.retained
    }

    /// Accumulates actual canonical bytes before retaining the next member.
    ///
    /// # Errors
    /// Refuses checked overflow or the supplied bound without changing the
    /// existing count, preserving the original native adapter's error class.
    pub fn reserve(&mut self, bytes: usize) -> Result<(), DomainLedgerDataError> {
        let retained = self.retained
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or(JournalTransactionDataError::LimitExceeded("resident canonical payload bytes"))?;
        self.retained = retained;
        Ok(())
    }
}

/// Holds one canonical envelope and decoded phase as comparison DATA only.
pub struct DomainPostcommitRecordDataV1<S: ProtectedDomainSchemaV1> {
    namespace: RecordNamespace,
    role: ProtectedRecordRoleV1,
    phase: ProtectedReducerPhaseV1,
    transaction_phase: ProtectedReducerPhaseV1,
    envelope: ProtectedDomainEnvelopeV1<S>,
    encoded: Vec<u8>,
}

// Preserve the existing record diagnostic even though its passive DATA moved.
impl<S: ProtectedDomainSchemaV1 + std::fmt::Debug> std::fmt::Debug
    for DomainPostcommitRecordDataV1<S>
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DomainPostcommitRecordV1")
            .field("namespace", &self.namespace)
            .field("role", &self.role)
            .field("phase", &self.phase)
            .field("transaction_phase", &self.transaction_phase)
            .field("envelope", &self.envelope)
            .field("encoded", &self.encoded)
            .finish()
    }
}

impl<S: ProtectedDomainSchemaV1> DomainPostcommitRecordDataV1<S> {
    /// Moves six existing comparison fields without native role acceptance.
    ///
    /// Neither supplied bytes nor this record can construct a current composite,
    /// settlement, effect permit or independently paid operation.
    #[must_use]
    pub fn from_comparison_parts(
        namespace: RecordNamespace,
        role: ProtectedRecordRoleV1,
        phase: ProtectedReducerPhaseV1,
        transaction_phase: ProtectedReducerPhaseV1,
        envelope: ProtectedDomainEnvelopeV1<S>,
        encoded: Vec<u8>,
    ) -> Self {
        Self {
            namespace,
            role,
            phase,
            transaction_phase,
            envelope,
            encoded,
        }
    }

    /// Borrows the exact canonical durable bytes for actual current comparison.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns the fixed shared-journal namespace selected by the domain kind.
    #[must_use]
    pub const fn namespace(&self) -> RecordNamespace {
        self.namespace
    }

    /// Returns the exact canonical envelope read back after durable commit.
    #[must_use]
    pub const fn envelope(&self) -> &ProtectedDomainEnvelopeV1<S> {
        &self.envelope
    }

    /// Reports the decoded terminal-publication comparison, without permission.
    #[must_use]
    pub fn is_publication(&self) -> bool {
        matches!(self.role, ProtectedRecordRoleV1::Publication)
            && self.phase == ProtectedReducerPhaseV1::Terminal
            && self.transaction_phase == ProtectedReducerPhaseV1::Terminal
    }

    /// Reports the decoded prepared-effect comparison, without permission.
    #[must_use]
    pub fn is_effect(&self) -> bool {
        matches!(self.role, ProtectedRecordRoleV1::Effect)
            && self.phase == ProtectedReducerPhaseV1::Prepared
            && self.transaction_phase == ProtectedReducerPhaseV1::Prepared
    }

    /// Replaces a supplied aggregate phase as comparison DATA only.
    ///
    /// This cannot make the record, its byte source or a role action current.
    pub fn set_transaction_phase_comparison_v1(&mut self, phase: ProtectedReducerPhaseV1) {
        self.transaction_phase = phase;
    }

    /// Returns the phase decoded from the canonical reducer body.
    #[must_use]
    pub const fn phase(&self) -> ProtectedReducerPhaseV1 {
        self.phase
    }
}

