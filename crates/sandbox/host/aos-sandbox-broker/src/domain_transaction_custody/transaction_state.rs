//! Shares borrowed-row recovery comparisons without role acceptance.
//!
//! The same canonical member parser, grouping and phase fold serve every real
//! private role wrapper. These helpers perform no IO or append and seal no
//! snapshot, instance, original, paid operation, retry or effect permission.
//! Callers retain the genuine writer and their existing currentness gates.

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_protocol::domain_ledger::{
    DomainLedgerDataError, JournalTransactionDataError,
    readonly::HistoricalLedgerReadViewV1,
    records::{
        DomainPostcommitRecordDataV1, DomainPreparedTransactionDataV1,
        MAXIMUM_COLD_REPLAY_MEMBERS, ProtectedDomainKeyV1,
        ProtectedDomainReplayPhaseV1, ProtectedDomainReplayTransactionV1,
        ProtectedDomainSchemaV1, ProtectedReducerPhaseV1,
        ResidentCanonicalPayloadBudgetDataV1, decode_durable_member,
        reconstruct_transactions, reducer_phase,
    },
};

/// Carries exact predecessor and successor comparison results as DATA only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainRecoveryImageComparisonDataV1 {
    /// Reports the complete predecessor comparison made first.
    pub before: bool,
    /// Reports the complete successor comparison made second.
    pub after: bool,
}

/// Compares predecessor then successor images at the original recovery frontier.
///
/// The two results do not authorize retry or publication. The actual role keeps
/// its accepted prepared snapshot and makes the existing ambiguity decision.
#[must_use]
pub fn compare_recovery_images_v1(
    ledger: HistoricalLedgerReadViewV1<'_>,
    prepared: &DomainPreparedTransactionDataV1,
) -> DomainRecoveryImageComparisonDataV1 {
    let before = super::members::values_match_v1(
        ledger, &prepared.transaction, &prepared.before, &prepared.after, false,
    );
    let after = super::members::values_match_v1(
        ledger, &prepared.transaction, &prepared.before, &prepared.after, true,
    );
    DomainRecoveryImageComparisonDataV1 { before, after }
}

/// Compares one original prepared image without authenticating its source.
#[must_use]
pub fn prepared_image_matches_v1(
    ledger: HistoricalLedgerReadViewV1<'_>,
    prepared: &DomainPreparedTransactionDataV1,
    after: bool,
) -> bool {
    super::members::values_match_v1(
        ledger,
        &prepared.transaction,
        &prepared.before,
        &prepared.after,
        after,
    )
}

/// Compares exact current row bytes after the real role's instance/root checks.
///
/// This only reports equality. A supplied record list cannot establish a
/// current native source, role snapshot, paid operation or effect permission.
#[must_use]
pub fn postcommit_rows_match_v1<S: ProtectedDomainSchemaV1>(
    ledger: HistoricalLedgerReadViewV1<'_>,
    records: &[DomainPostcommitRecordDataV1<S>],
) -> bool {
    records.iter().all(|record| {
        ledger.get(record.namespace(), record.envelope().key().as_bytes())
            == Some(record.encoded())
    })
}

/// Owns reconstructed postcommit comparison DATA without a current capability.
///
/// The original reconstructed transaction stays alive through the real private
/// wrapper's final phase match. It is not replaced by a copied phase scalar.
#[must_use]
pub struct DomainCurrentPostcommitCandidateDataV1<S: ProtectedDomainSchemaV1> {
    transaction: ProtectedDomainReplayTransactionV1<S>,
    transaction_digest: ObjectDigest,
    set_digest: ObjectDigest,
    records: Vec<DomainPostcommitRecordDataV1<S>>,
}

impl<S: ProtectedDomainSchemaV1> DomainCurrentPostcommitCandidateDataV1<S> {
    /// Moves the original reconstructed transaction and exact member DATA.
    ///
    /// No accepted instance, protected snapshot or effect permission is created.
    pub fn into_parts(self) -> (
        ProtectedDomainReplayTransactionV1<S>, ObjectDigest, ObjectDigest,
        Vec<DomainPostcommitRecordDataV1<S>>,
    ) {
        (self.transaction, self.transaction_digest, self.set_digest, self.records)
    }

}

/// Reconstructs the same bounded current transaction candidate from borrowed rows.
///
/// The genuine role takes its snapshot before calling, and encloses any returned
/// candidate only after its existing native/currentness and semantic gates.
/// The byte counter is canonical payload DATA, never financial admission.
///
/// # Errors
/// Preserves namespace, canonical member, checked payload, bounded member count,
/// grouping and reducer phase errors in their original order. This ordinary
/// DATA engine preserves ordinary local cleanup; it is not a retained selected
/// parser capture or an independent native-post owner.
pub fn current_postcommit_candidate_v1<S: ProtectedDomainSchemaV1>(
    ledger: HistoricalLedgerReadViewV1<'_>,
    transaction_id: [u8; 16],
    validator: &S::ReplayValidator,
    mut budget: Option<&mut ResidentCanonicalPayloadBudgetDataV1>,
) -> Result<Option<DomainCurrentPostcommitCandidateDataV1<S>>, DomainLedgerDataError> {
    let mut members = Vec::new();
    for (namespace, key_bytes, value) in ledger.all_records() {
        if !key_bytes.starts_with(S::KEY_PREFIX) {
            continue;
        }
        let key = ProtectedDomainKeyV1::<S>::decode(key_bytes)?;
        if namespace != S::namespace(key.kind()) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let member = decode_durable_member::<S>(key, value, validator)?;
        if member.transaction_id() == transaction_id {
            if let Some(budget) = budget.as_deref_mut() {
                // One retained encoded member and its decoded envelope.
                // Reserve before keeping it beyond this bounded scan.
                let payload = member
                    .encoded()
                    .len()
                    .checked_add(member.envelope().payload().len())
                    .and_then(|bytes| bytes.checked_add(member.envelope().key().as_bytes().len()))
                    .and_then(|bytes| bytes.checked_add(member.envelope().key().identity().len()))
                    .ok_or(JournalTransactionDataError::LimitExceeded("resident canonical payload bytes"))?;
                budget.reserve(payload)?;
            }
            if members.len() >= MAXIMUM_COLD_REPLAY_MEMBERS {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
            members.push(member);
        }
    }
    if members.is_empty() {
        return Ok(None);
    }
    members.sort_by_key(|member| member.member_index());
    let transactions = reconstruct_transactions::<S>(&members)?;
    let transaction = transactions
        .into_iter()
        .next()
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    if transaction.transaction_id() != transaction_id
        || transaction.phase() == ProtectedDomainReplayPhaseV1::Incomplete
        || transaction.phase() == ProtectedDomainReplayPhaseV1::Observed
        || transaction.phase() == ProtectedDomainReplayPhaseV1::Superseded
    {
        return Ok(None);
    }
    let transaction_digest = transaction.transaction_digest();
    let set_digest = transaction.set_digest();
    let mut records = Vec::with_capacity(members.len());
    for member in members {
        let namespace = S::namespace(member.envelope().key().kind());
        let role = S::role(member.envelope().key().kind());
        let phase = reducer_phase(member.envelope())?;
        let transaction_phase = match transaction.phase() {
            ProtectedDomainReplayPhaseV1::Prepared => ProtectedReducerPhaseV1::Prepared,
            ProtectedDomainReplayPhaseV1::Observed => ProtectedReducerPhaseV1::Observed,
            ProtectedDomainReplayPhaseV1::Terminal => ProtectedReducerPhaseV1::Terminal,
            ProtectedDomainReplayPhaseV1::Superseded => ProtectedReducerPhaseV1::Superseded,
            ProtectedDomainReplayPhaseV1::Incomplete => return Ok(None),
        };
        let (_, _, _, _, envelope, encoded) = member.into_parts();
        records.push(DomainPostcommitRecordDataV1::from_comparison_parts(
            namespace, role, phase, transaction_phase, envelope, encoded,
        ));
    }
    Ok(Some(DomainCurrentPostcommitCandidateDataV1 {
        transaction, transaction_digest, set_digest, records,
    }))
}
