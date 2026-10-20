//! Shares transaction planning and native comparison DATA between role owners.
//!
//! These recipes retain no role, original, payment or accepted effect grant.
//! Actual private role adapters keep their complete native owner borrowed,
//! authenticate its original and currentness, and perform their existing gates
//! before preflight, append, settlement and effect construction. The shared
//! caller view borrows the actual native journal and its existing index.

use std::marker::PhantomData;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError, readonly::HistoricalLedgerReadViewV1};
use aos_sandbox_protocol::domain_ledger::records::{
    DomainPreparedTransactionDataV1, ProtectedDomainEnvelopeV1, ProtectedDomainSchemaV1, ProtectedRecordRoleV1,
    domain_transaction_set_digest, encode_checkpoint_payload, encode_durable_member,
    transaction_digest, validate_successor,
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

/// Shares exact canonical capacity composition and closed DATA shapes.
pub mod capacity;
/// Shares legacy record comparisons with actual borrowed native state.
pub mod capacity_records;
/// Shares canonical member, predecessor and payload comparison recipes.
pub mod members;

/// Owns the exact canonical members before the role's native preflight.
///
/// Field order preserves the old planner's negative local cleanup: transaction,
/// roles, successor bytes, then predecessor bytes. No role acceptance follows
/// from producing or consuming this DATA value.
#[must_use]
pub struct DomainPlannedMembersDataV1<S: ProtectedDomainSchemaV1> {
    transaction: JournalTransaction,
    roles: Vec<ProtectedRecordRoleV1>,
    after: Vec<Vec<u8>>,
    before: Vec<Option<Vec<u8>>>,
    set_digest: ObjectDigest,
    marker: PhantomData<S>,
}

impl<S: ProtectedDomainSchemaV1> DomainPlannedMembersDataV1<S> {
    /// Borrows the exact transaction for the real role's existing preflight.
    #[must_use]
    pub const fn transaction(&self) -> &JournalTransaction {
        &self.transaction
    }

    /// Computes the original digest after native preflight and moves all DATA.
    ///
    /// This is infallible and accepts no success flag or role authority. The
    /// actual adapter remains responsible for performing preflight before this
    /// call and privately enclosing its accepted transaction afterwards.
    #[must_use]
    pub fn into_prepared_data_v1(self) -> DomainPreparedTransactionDataV1 {
        let digest = transaction_digest::<S>(&self.transaction);
        DomainPreparedTransactionDataV1::from_comparison_parts(
            self.transaction, self.before, self.after, self.roles, digest, self.set_digest,
        )
    }
}

/// Plans the same canonical successor DATA against actual borrowed native rows.
///
/// This owns no accepted role snapshot. Sequence and root are comparison DATA
/// supplied by the real adapter at the same original snapshot frontier.
///
/// # Errors
/// Preserves duplicate, checkpoint, successor, canonical encoding and transaction
/// errors in their original order. Private adapters retain native failures and
/// their independently owed posts separately.
pub fn plan_members_v1<S: ProtectedDomainSchemaV1>(
    ledger: HistoricalLedgerReadViewV1<'_>,
    sequence: u64,
    root: ObjectDigest,
    transaction_id: [u8; 16],
    mut successors: Vec<ProtectedDomainEnvelopeV1<S>>,
    validator: &S::ReplayValidator,
) -> Result<DomainPlannedMembersDataV1<S>, DomainLedgerDataError> {
    successors.sort_by(|left, right| {
        (S::order(left.key().kind()), left.key().as_bytes())
            .cmp(&(S::order(right.key().kind()), right.key().as_bytes()))
    });
    if successors.is_empty()
        || successors.windows(2).any(|pair| pair[0].key() == pair[1].key())
        || (successors.len() != 1
            && successors
                .iter()
                .any(|successor| S::is_checkpoint(successor.key().kind())))
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }

    let mut records = Vec::with_capacity(successors.len());
    let mut before = Vec::with_capacity(successors.len());
    let mut after = Vec::with_capacity(successors.len());
    let mut roles = Vec::with_capacity(successors.len());
    let member_count = u16::try_from(successors.len())
        .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let set_digest = domain_transaction_set_digest::<S>(transaction_id, &successors);
    let mut checkpoint = false;
    for (index, successor) in successors.into_iter().enumerate() {
        if S::is_checkpoint(successor.key().kind()) {
            if checkpoint || successor.payload() != encode_checkpoint_payload::<S>(sequence, root) {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
            checkpoint = true;
        }
        let namespace = S::namespace(successor.key().kind());
        let previous = ledger.get(namespace, successor.key().as_bytes());
        validate_successor(previous, &successor, validator)?;
        let member_index = u16::try_from(index)
            .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
        let durable = encode_durable_member(
            transaction_id,
            member_index,
            member_count,
            set_digest,
            successor,
        )?;
        let key = durable.envelope().key().as_bytes().to_vec();
        let (_, _, _, _, envelope, encoded) = durable.into_parts();

        before.push(previous.map(<[u8]>::to_vec));
        after.push(encoded.clone());
        roles.push(S::role(envelope.key().kind()));
        records.push(JournalRecord::put(namespace, key, encoded));
    }
    let transaction = JournalTransaction::new(transaction_id, records)?;
    Ok(DomainPlannedMembersDataV1 {
        transaction,
        roles,
        after,
        before,
        set_digest,
        marker: PhantomData,
    })
}

/// Shares complete promised-capacity pressure arithmetic across real native roles.
pub mod pressure;

/// Shares the same borrowed-row current/readback/recovery DATA engine.
pub mod transaction_state;
