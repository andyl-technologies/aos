//! Retains the closed pre-ACK Create Effect replacement on the same Controller.
//!
//! The genuine Source Completing context supplies the canonical516 relation.
//! This owner changes only that parent's Effect to Applied, retaining its exact
//! version-six Q04 companion. Operation Applying and the REQUESTED projection
//! are unchanged. Neither a receipt DATA value nor an ordinary append selects
//! this route, and its positive return does not publish public completion.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::RecordShape;
use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    Q04CutIdentityV1, Q04EffectSubgateV1,
};
use aos_sandbox_protocol::domain_ledger::effect_history::{
    EffectHistoryDataError, EffectLedgerRecord, EffectReceipt, EffectState,
    CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1, decode_effect_with_q04,
    effect_decoding_receiving_bytes_v1, encode_q04_effect,
    create_stopped_pre_ack_transaction_id_v1,
};
use aos_sandbox_protocol::domain_ledger::operation::{
    OperationRecord, decode_operation, effect_key,
};
use aos_sandbox_protocol::domain_ledger::public_operation::OperationState;
use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
use sha2::{Digest as _, Sha256};

use super::{CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};
use crate::CreateProvisioningOriginalsV1;
use crate::controller_resource_reservation::{
    CreateStoppedPreAckContextV1, ResourceReservationErrorV1,
};

#[derive(Clone, Copy)]
enum First { Entry, Geometry, Funding, Parent, Effect, Receipt, Encoding, Transaction, Append }

/// Retains the actual pre-ACK append and every reached typed/encoded prefix.
pub(crate) struct CreateStoppedControllerPreAckAppendOriginalV1 {
    parent: OperationId,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    models: Option<Box<Models>>,
    retired_commit: Option<CommitResult>,
    first: Option<First>,
}

struct Models {
    parent: Option<Result<OperationRecord, crate::ReconcilerError>>,
    effect: Option<Result<(EffectLedgerRecord, Option<Q04EffectSubgateV1>), EffectHistoryDataError>>,
    receipt: Option<Result<[u8; CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1], ResourceReservationErrorV1>>,
    encoded: Option<Result<Vec<u8>, EffectHistoryDataError>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    append: Option<Result<CommitResult, JournalError>>,
}

impl CreateStoppedControllerPreAckAppendOriginalV1 {
    /// Prices the actual inline attempt and its lazy constructor destinations.
    pub(crate) fn fixed_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(size_of::<Models>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(size_of::<CreateStoppedControllerPreAckAppendLoanV1<'static>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(size_of::<JournalRecord>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Requires the real durable append; this stopping projection owns no cause.
    pub(crate) fn completed_v1(&self) -> Result<CommitResult, JournalError> {
        if self.first.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.retired_commit.or_else(|| self.models.as_ref().and_then(|models| models.append.as_ref())
            .and_then(|result| result.as_ref().ok()).copied()).ok_or(JournalError::ProtectedBoundary)
    }

    /// Retires successful decode/encoding payloads after the caller's full disposition.
    ///
    /// The genuine pre-ACK attempt calls this only after its Source, C23 and
    /// Root posts have all completed. Failed or partial owners remain intact.
    pub(crate) fn retire_completed_payloads_v1(&mut self) -> Result<(), JournalError> {
        let committed = self.completed_v1()?;
        self.retired_commit = Some(committed);
        self.models = None;
        Ok(())
    }

    /// Borrows the original first reached cause without cloning or flattening it.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let models = self.models.as_deref();
        match self.first? {
            First::Entry => cause(&self.entry),
            First::Geometry => cause(&self.geometry),
            First::Funding => cause(&self.funding),
            First::Parent => models.and_then(|models| cause(&models.parent)),
            First::Effect => models.and_then(|models| cause(&models.effect)),
            First::Receipt => models.and_then(|models| cause(&models.receipt)),
            First::Encoding => models.and_then(|models| cause(&models.encoded)),
            First::Transaction => models.and_then(|models| cause(&models.transaction)),
            First::Append => models.and_then(|models| cause(&models.append)),
        }
    }

    /// Resolves only this actual debit's stopping marker to the same C cause.
    pub(crate) fn failure_with_original_v1<'cause>(&'cause self,
        original: &'cause CreateProvisioningOriginalsV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        if matches!(self.first, Some(First::Funding)) && self.funding_original
            && original.belongs_to_operation_v1(self.parent) {
            original.failure().or_else(|| self.failure())
        } else { self.failure() }
    }

    fn record_once_v1(context: &mut CreateStoppedPreAckContextV1<'_>, journal: &mut Journal) -> Self {
        let mut original = Self { parent: context.parent_operation_v1(),
            entry: None, geometry: None, funding: None, funding_original: false,
            models: None, retired_commit: None, first: None };
        original.entry = Some(context.require_current_v1(journal));
        if !matches!(original.entry, Some(Ok(()))) {
            original.first = Some(First::Entry);
            return original;
        }
        original.geometry = Some(receiving_demand_v1(journal, original.parent));
        let demand = match original.geometry.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => { original.first = Some(First::Geometry); return original; }
        };
        original.funding = Some(context.admit_controller_append_v1(journal, demand));
        if !matches!(original.funding, Some(Ok(()))) {
            original.funding_original = context.original_v1().failure().is_some();
            original.first = Some(First::Funding);
            return original;
        }
        original.models = Some(Box::new(Models { parent: None, effect: None,
            receipt: None, encoded: None, transaction: None, append: None }));
        if let Err(first) = original.record_body_v1(context, journal) { original.first = Some(first); }
        original
    }

    fn record_body_v1(&mut self, context: &mut CreateStoppedPreAckContextV1<'_>,
        journal: &mut Journal,
    ) -> Result<(), First> {
        let models = self.models.as_mut().ok_or(First::Entry)?;
        models.parent = Some((|| {
            let bytes = journal.get(RecordNamespace::Operation, self.parent.as_bytes())
                .ok_or(crate::ReconcilerError::CorruptLedger("pre-ACK Create parent is absent"))?;
            let parent = decode_operation(bytes)?;
            if parent.state() != OperationState::Applying || parent.effect_count() != 1
                || parent.ownership_gated() || parent.runtime_intent_digest().is_some()
                || parent.public_operation().is_none_or(|public|
                    public.method() != PublicOperationMethodV1::CreateSandbox
                        || public.accepted_generation() != 1) {
                return Err(crate::ReconcilerError::CorruptLedger("pre-ACK Create parent changed"));
            }
            Ok(parent)
        })());
        if !matches!(models.parent, Some(Ok(_))) { return Err(First::Parent); }
        let key = effect_key(self.parent, 0);
        models.effect = Some((|| {
            let bytes = journal.get(RecordNamespace::Effect, &key)
                .ok_or(EffectHistoryDataError::CorruptLedger("pre-ACK Create Effect is absent"))?;
            let (effect, gate) = decode_effect_with_q04(bytes)?;
            if gate.as_ref().is_none_or(|gate| gate.status() != 4)
                || !matches!(effect.state(), EffectState::Applying { .. })
                || effect.dispatch().is_some() || effect.project_admission().is_some()
                || effect.plan().authority().is_some()
                || effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::CreateSandbox) {
                return Err(EffectHistoryDataError::CorruptLedger("pre-ACK Create Effect changed"));
            }
            Ok((effect, gate))
        })());
        if !matches!(models.effect, Some(Ok(_))) { return Err(First::Effect); }
        models.receipt = Some(context.lifecycle_receipt_v1().and_then(|receipt| {
            if receipt.operation_v1() != self.parent { return Err(ResourceReservationErrorV1::Conflict); }
            receipt.encode_v1(context.lane_v1()).map_err(|cause|
                ResourceReservationErrorV1::Journal(JournalError::Q04ControllerLedger(Box::new(cause.into()))))
        }));
        if !matches!(models.receipt, Some(Ok(_))) { return Err(First::Receipt); }
        models.encoded = Some((|| {
            let (before, gate) = models.effect.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(EffectHistoryDataError::CorruptLedger("pre-ACK Effect is incomplete"))?;
            let (plan, state, dispatch, metadata) = before.clone().into_parts();
            let EffectState::Applying { attempt, .. } = state else {
                return Err(EffectHistoryDataError::CorruptLedger("pre-ACK Effect is not Applying"));
            };
            let receipt = models.receipt.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(EffectHistoryDataError::CorruptLedger("pre-ACK receipt is incomplete"))?;
            let applied = EffectLedgerRecord::from_parts((plan, EffectState::Applied {
                attempt, receipt: EffectReceipt::new(receipt.to_vec())?,
            }, dispatch, metadata));
            encode_q04_effect(&applied, gate.as_ref()
                .ok_or(EffectHistoryDataError::CorruptLedger("pre-ACK Q04 companion is absent"))?)
        })());
        if !matches!(models.encoded, Some(Ok(_))) { return Err(First::Encoding); }
        models.transaction = Some((|| {
            let encoded = models.encoded.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            JournalTransaction::new(create_stopped_pre_ack_transaction_id_v1(self.parent, encoded), vec![JournalRecord::put(
                RecordNamespace::Effect, key.to_vec(), encoded.clone(),
            )]).map_err(JournalError::from)
        })());
        if !matches!(models.transaction, Some(Ok(_))) { return Err(First::Transaction); }
        let transaction = models.transaction.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(First::Transaction)?;
        let before = journal.get(RecordNamespace::Effect, &key).ok_or(First::Effect)?;
        let mut loan = CreateStoppedControllerPreAckAppendLoanV1 {
            original: context.original_v1(), transaction, before_digest: Sha256::digest(before).into(),
            parent: self.parent,
        };
        models.append = Some(journal.commit_create_storage_original_v1(transaction,
            super::create_storage_append::CreateStorageAppendOriginalV1::CreateStoppedPreAck(&mut loan)));
        if matches!(models.append, Some(Ok(_))) { Ok(()) } else { Err(First::Append) }
    }
}

/// Borrows only a canonical transaction assembled under the genuine context.
pub(super) struct CreateStoppedControllerPreAckAppendLoanV1<'loan> {
    original: &'loan CreateProvisioningOriginalsV1,
    transaction: &'loan JournalTransaction,
    before_digest: [u8; 32],
    parent: OperationId,
}

impl CreateStoppedControllerPreAckAppendLoanV1<'_> {
    pub(super) fn matches_identity_v1(&self, identity: &Q04CutIdentityV1) -> bool {
        self.parent == identity.operation() && self.original.belongs_to_operation_v1(self.parent)
    }

    pub(super) fn require_transition(&self, journal: &Journal, transaction: &JournalTransaction)
        -> Result<(), JournalError> {
        self.original.require_current_v1(journal).map_err(|_| JournalError::ProtectedBoundary)?;
        if transaction != self.transaction { return Err(JournalError::ProtectedBoundary); }
        require_parent_effect_shape_v1(transaction, self.parent)?;
        let key = effect_key(self.parent, 0);
        if journal.get(RecordNamespace::Effect, &key).is_none_or(|before|
            <[u8; 32]>::from(Sha256::digest(before)) != self.before_digest) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn final_crossing(&self, journal: &Journal) -> Result<(), JournalError> {
        self.require_transition(journal, self.transaction)
    }
}

impl Journal {
    /// Records only the genuine Completing/Applied pre-ACK parent Effect.
    pub(crate) fn record_create_stopped_pre_ack_once_v1(&mut self,
        context: &mut CreateStoppedPreAckContextV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        let original = CreateStoppedControllerPreAckAppendOriginalV1::record_once_v1(context, self);
        // The whole semantic/native return and every reached model remain in
        // the external pre-ACK attempt before any independently owed post.
        context.retain_controller_append_original_v1(original)
    }
}

// This comparison establishes only a shape. The private constructor and actual
// original-current crossing separately establish the right to append it.
fn require_parent_effect_shape_v1(transaction: &JournalTransaction, parent: OperationId)
    -> Result<(), JournalError> {
    let [record] = transaction.records() else { return Err(JournalError::ProtectedBoundary); };
    if record.namespace() != RecordNamespace::Effect
        || record.key() != effect_key(parent, 0) || record.value().is_none_or(|value|
            transaction.id() != &create_stopped_pre_ack_transaction_id_v1(parent, value)) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn receiving_demand_v1(journal: &Journal, parent: OperationId) -> Result<ResourceVector, JournalError> {
    let bad = || JournalError::JournalTooLarge;
    let effect = journal.get(RecordNamespace::Effect, &effect_key(parent, 0))
        .ok_or(JournalError::ProtectedBoundary)?;
    let bound = effect.len().checked_add(CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1).ok_or_else(bad)?;
    let rows = [RecordShape { key_bytes: effect_key(parent, 0).len(), value_bytes: Some(bound) }];
    let native = journal.append_receiving_demand_v1(rows.into_iter()).map_err(|cause| match cause {
        super::JournalAppendReceivingDemandErrorV1::Journal(cause) => cause,
        super::JournalAppendReceivingDemandErrorV1::Accounting(cause) => JournalError::ReceivingAccounting(cause),
    })?;
    let state = journal.historical_read_view_v1().materialized_state_v1();
    let bytes = crate::cold_launch_publication::completion::controller_selector_model_bytes_v1(state)
        .and_then(|bytes| bytes.checked_add(effect_decoding_receiving_bytes_v1(bound)?))
        .and_then(|bytes| bytes.checked_add(bound.checked_mul(4)?))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(bad)?;
    let entries = crate::cold_launch_publication::completion::controller_selector_namespace_entries_v1(state)
        .and_then(|entries| u64::try_from(entries).ok()).ok_or_else(bad)?;
    // The context's retained base already includes the exact fixed owner,
    // lazy-model constructor and loan carriers before this method is entered.
    native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
        .with(D::MetadataEntries, entries)).map_err(JournalError::ReceivingAccounting)
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_ack_shape_cannot_add_an_operation_or_other_publication_row() {
        let parent = OperationId::from_bytes([1; 16]);
        let effect = || JournalRecord::put(RecordNamespace::Effect,
            effect_key(parent, 0).to_vec(), vec![1]);
        let identity = create_stopped_pre_ack_transaction_id_v1(parent, &[1]);
        let one = JournalTransaction::new(identity, vec![effect()]).unwrap();
        let with_operation = JournalTransaction::new(identity, vec![effect(),
            JournalRecord::put(RecordNamespace::Operation, parent.as_bytes().to_vec(), vec![1]),
        ]).unwrap();
        let wrong_parent = JournalTransaction::new([2; 16], vec![effect()]).unwrap();
        let wrong_step = JournalTransaction::new(identity, vec![JournalRecord::put(
            RecordNamespace::Effect, effect_key(parent, 1).to_vec(), vec![1],
        )]).unwrap();

        assert!(require_parent_effect_shape_v1(&one, parent).is_ok());
        assert!(require_parent_effect_shape_v1(&with_operation, parent).is_err());
        assert!(require_parent_effect_shape_v1(&wrong_parent, parent).is_err());
        assert!(require_parent_effect_shape_v1(&wrong_step, parent).is_err());
    }
}
