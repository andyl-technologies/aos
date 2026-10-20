//! Retains actual Storage sidecar appends on their original F programme.
//!
//! These private methods preserve the canonical constructors, authority,
//! advisory preflight, captured append and typed reader. Their caller retains
//! the original main transaction and must separately fund intent construction
//! and the outer recovery programme. The installed method46 qualification gate
//! stays closed while these selected primitives validate their actual originals.

use super::*;
use std::error::Error;
use std::mem::size_of;
use std::sync::Arc;

use aos_sandbox::{CommitResult, JournalError, ProtectedJournalCurrentnessOriginalsV1};
use aos_sandbox::journal::{ProtectedJournalPreflightOriginalV2, ProtectedJournalPreopenReplayExtentV1};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityReadCaptureV1;

use crate::recovery::StorageFloorFinancialSourceV2;

#[derive(Debug, thiserror::Error)]
enum DemandError {
    #[error(transparent)]
    Native(#[from] JournalError),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error("the actual sidecar mutation representation cannot be represented")]
    Shape,
}

struct StorageFinalSuffixDataV2 {
    token: ProtectedJournalPreflight,
    transaction: JournalTransaction,
}

/// Shares the actual prepared suffix DATA while its native owner retains it.
///
/// Its private constructor moves the original token and transaction exactly
/// once. Clones of this wrapper neither duplicate a journal nor admit an effect.
pub(crate) struct StorageFinalSuffixPreflightV2 {
    data: Arc<StorageFinalSuffixDataV2>,
}

/// Keeps the real constructor, preflight, append and independently owed post.
pub(super) struct StorageFloorMutationOriginalV2 {
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    preconstruct: Option<Result<ResourceVector, DemandError>>,
    binding: super::super::digest::FloorTransactionDigestOriginalV1,
    intent: Option<Result<FloorIntentDataV1, FloorErrorV1>>,
    predecessor: Option<Result<(), FloorErrorV1>>,
    transaction_binding: Option<Result<(), FloorErrorV1>>,
    prepare: SidecarPreparationOriginalV2,
    finalize: SidecarFinalizationOriginalV2,
    preparations: Option<[JournalTransaction; 2]>,
    finalization: Option<JournalTransaction>,
    suffix_requested: bool,
    suffix: Option<Arc<StorageFinalSuffixDataV2>>,
    native_demand: Option<Result<ResourceVector, DemandError>>,
    capacity: [CanonicalCapacityReadCaptureV1; 2],
    claim: Option<Result<(), JournalError>>,
    preflight: ProtectedJournalPreflightOriginalV2,
    token: Option<Result<ProtectedJournalPreflight, JournalError>>,
    effect: Option<Result<(), JournalError>>,
    commit: Option<Result<CommitResult, JournalError>>,
    native_entered: bool,
    primary: Option<Result<(), FloorErrorV1>>,
    after_original: ProtectedJournalCurrentnessOriginalsV1,
    after: Option<Result<(), JournalError>>,
    returned: Option<Result<(), FloorErrorV1>>,
}

impl StorageFloorMutationOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            metadata: None,
            extent: None,
            preconstruct: None,
            binding: super::super::digest::FloorTransactionDigestOriginalV1::new(),
            intent: None,
            predecessor: None,
            transaction_binding: None,
            prepare: SidecarPreparationOriginalV2::new(),
            finalize: SidecarFinalizationOriginalV2::new(),
            preparations: None,
            finalization: None,
            suffix_requested: false,
            suffix: None,
            native_demand: None,
            capacity: std::array::from_fn(|_| CanonicalCapacityReadCaptureV1::new()),
            claim: None,
            preflight: ProtectedJournalPreflightOriginalV2::new(),
            token: None,
            effect: None,
            commit: None,
            native_entered: false,
            primary: None,
            after_original: ProtectedJournalCurrentnessOriginalsV1::new(),
            after: None,
            returned: None,
        }
    }

    fn fixed_demand() -> Result<ResourceVector, AccountingError> {
        // Both the inert construction temporary and its final Box destination
        // are live at the move frontier. Archive slots are priced separately.
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    fn preconstruction_demand(&self, custody: &BrokerSidecarCustodyV1,
        transaction: Option<&JournalTransaction>, main_limits: JournalLimits)
        -> Result<ResourceVector, DemandError>
    {
        let extent = self.extent.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(DemandError::Shape)?;
        let physical = usize::try_from(extent.native_bytes).map_err(|_| DemandError::Shape)?;
        let rows = (physical / aos_sandbox_journal::framing::HEADER_BYTES)
            .min(extent.limits.maximum_materialized_records);
        let (capacity_bytes, _) = CanonicalCapacityReadCaptureV1::receiving_obligations_v1(rows)
            .ok_or(DemandError::Shape)?;
        let capacity_names = CanonicalCapacityReadCaptureV1::receiving_named_entries_v2(rows)
            .and_then(|names| names.checked_mul(2)).ok_or(DemandError::Shape)?;
        let capacity = ResourceVector::ZERO
            .with(D::MemoryBytes, capacity_bytes.checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?)
            .with(D::MetadataEntries, u64::try_from(capacity_names).map_err(|_| DemandError::Shape)?);
        let mut required = Self::fixed_demand()?.checked_add(capacity)?
            .checked_add(SidecarFinalizationOriginalV2::receiving_demand_v2()
                .ok_or(DemandError::Shape)?)?
            .checked_add(custody.held_receiving_demand_v2()?.with(D::MetadataEntries, 0))?;
        if self.suffix_requested {
            let bytes = size_of::<StorageFinalSuffixDataV2>().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(size_of::<usize>().checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(std::mem::align_of::<StorageFinalSuffixDataV2>()))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?;
            required = required.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        }
        if let Some(transaction) = transaction {
            let digest = super::super::digest::FloorTransactionDigestOriginalV1::
                actual_transaction_receiving_demand_v3(transaction).ok_or(DemandError::Shape)?;
            required = required.checked_add(digest)?
                .checked_add(SidecarPreparationOriginalV2::receiving_demand_v2(transaction, main_limits)
                    .ok_or(DemandError::Shape)?)?;
        }
        Ok(required)
    }

    fn intent_receiving_demand(transaction: &JournalTransaction)
        -> Result<ResourceVector, DemandError>
    {
        let digest = super::super::digest::FloorTransactionDigestOriginalV1::
            actual_transaction_receiving_demand_v3(transaction).ok_or(DemandError::Shape)?;
        let fixed = FloorIntentDataV1::construction_receiving_bytes_v2()
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(DemandError::Shape)?;
        Ok(Self::fixed_demand()?.checked_add(digest)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))?)
    }

    fn transactions(&self) -> Result<&[JournalTransaction], DemandError> {
        if let Some(transactions) = self.preparations.as_ref() { return Ok(transactions); }
        self.finalization.as_ref().map(core::slice::from_ref).ok_or(DemandError::Shape)
    }

    fn native_receiving_demand(&self, journal: &Journal) -> Result<ResourceVector, DemandError> {
        if !journal.has_captured_append_custody_v1() { return Err(DemandError::Shape); }
        let extent = self.extent.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(DemandError::Shape)?;
        let transactions = self.transactions()?;
        // The same preflight supplier forecasts actual future projection maps
        // and retains the reached encoder/index/model prefixes. The native
        // append owner separately supplies its real copied stage and both posts.
        let mut demand = ProtectedJournalPreflightOriginalV2::receiving_demand_v2(extent, transactions)?;
        for transaction in transactions {
            let encoded = aos_sandbox_protocol::domain_ledger::transaction::
                encoded_transaction_append_bytes(transaction).map_err(JournalError::from)?;
            demand = demand.checked_add(journal.captured_append_receiving_demand_v1(encoded)?)?;
        }
        let construction = self.preconstruct.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(DemandError::Shape)?;
        Ok(construction.checked_add(demand)?)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        error(&self.metadata).or_else(|| error(&self.extent))
            .or_else(|| error(&self.preconstruct))
            .or_else(|| error(&self.predecessor))
            .or_else(|| self.binding.failure().map(|cause| cause as _))
            .or_else(|| error(&self.intent))
            .or_else(|| error(&self.transaction_binding))
            .or_else(|| self.prepare.failure()).or_else(|| self.finalize.failure())
            .or_else(|| error(&self.native_demand)).or_else(|| error(&self.claim))
            .or_else(|| self.preflight.failure()).or_else(|| error(&self.token))
            .or_else(|| error(&self.effect)).or_else(|| error(&self.commit))
            .or_else(|| error(&self.primary))
            .or_else(|| self.after_original.failure()).or_else(|| error(&self.after))
            .or_else(|| error(&self.returned))
    }
}

impl BrokerSidecarStoreV1 {
    /// Retains recovery's exact transaction-binding digest on the same F.
    ///
    /// # Errors
    /// Keeps the original sequence-before-digest refusal and actual owning key
    /// index through a later outer recovery, native or semantic failure.
    pub(crate) fn require_transaction_storage_receiving_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, intent: FloorIntentDataV1,
        transaction: &JournalTransaction) -> Result<(), FloorErrorV1>
    {
        let mut original = self.begin_mutation_v2(main, receiving)?;
        let result = (|| {
            original.preconstruct = Some(StorageFloorMutationOriginalV2::intent_receiving_demand(transaction));
            let required = original.preconstruct.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(FloorErrorV1::Encoding)?;
            self.admit_mutation_demand_v2(main, receiving, required)?;
            original.transaction_binding = Some(intent.require_transaction_retaining_v1(transaction, &mut original.binding));
            original.transaction_binding.as_ref().copied().ok_or(FloorErrorV1::Unavailable)?
        })();
        original.returned = Some(result);
        self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?.retain_mutation_v2(original)?;
        result
    }

    /// Retains the exact final suffix preflight before dependent NV/main work.
    ///
    /// # Errors
    /// Keeps the original canonical constructor, authority scan, prospective
    /// models, token and independent owed native post on every refusal.
    pub(crate) fn preflight_final_storage_receiving_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, profile: FloorProfileV1,
        stored: StoredFloorDataViewV1<'_>) -> Result<StorageFinalSuffixPreflightV2, FloorErrorV1>
    {
        let mut original = self.begin_mutation_v2(main, receiving)?;
        original.suffix_requested = true;
        let result = (|| {
            self.admit_mutation_construction_v2(&mut original, main, receiving, None)?;
            if self.read_storage_receiving_v2(main, receiving, profile)?.view() != stored {
                return Err(FloorErrorV1::Diverged);
            }
            let (intent, _) = stored.prepared.ok_or(FloorErrorV1::Diverged)?;
            original.finalize.observe_once_v2(intent)?;
            original.finalization = Some(original.finalize.take_completed_v2().ok_or(FloorErrorV1::Encoding)?);
            original.native_demand = Some(original.native_receiving_demand(self.custody.journal()));
            let required = original.native_demand.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(FloorErrorV1::Encoding)?;
            self.admit_mutation_demand_v2(main, receiving, required)?;

            original.native_entered = true;
            let authority = match self.custody.journal_mut().claim_protected_authority_retaining_v1(
                RecordNamespace::BrokerSessionTraffic, &mut original.capacity,
            ) {
                Ok(authority) => { original.claim = Some(Ok(())); authority }
                Err(cause) => {
                    original.claim = Some(Err(cause));
                    return Err(FloorErrorV1::Unavailable);
                }
            };
            let transaction = original.finalization.as_ref().ok_or(FloorErrorV1::Encoding)?;
            original.token = Some(authority.preflight_transactions_retaining_v2(
                core::slice::from_ref(transaction), &mut original.preflight,
            ));
            if !matches!(original.token, Some(Ok(_))) { return Err(FloorErrorV1::Unavailable); }
            drop(authority);

            // Both successful DATA originals move once into the shared suffix.
            // The enclosing programme retains that same allocation through any
            // later NV, main-history, final-validation or finalization refusal.
            let token = match original.token.take() {
                Some(Ok(token)) => token,
                other => {
                    original.token = other;
                    return Err(FloorErrorV1::Unavailable);
                }
            };
            let transaction = original.finalization.take().ok_or(FloorErrorV1::Encoding)?;
            original.suffix = Some(Arc::new(StorageFinalSuffixDataV2 { token, transaction }));
            Ok(())
        })();
        let result = self.finish_mutation_native_v2(&mut original, result);
        original.returned = Some(result);
        let suffix = if result.is_ok() {
            original.suffix.as_ref().map(|data| StorageFinalSuffixPreflightV2 { data: Arc::clone(data) })
        } else { None };
        self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?.retain_mutation_v2(original)?;
        result?;
        suffix.ok_or(FloorErrorV1::Unavailable)
    }

    /// Revalidates only this programme's actual retained final suffix DATA.
    ///
    /// # Errors
    /// Refuses a foreign suffix, changed prepared model, stale native snapshot
    /// or exact transaction binding, retaining the real refusal and owed post.
    pub(crate) fn validate_final_preflight_storage_receiving_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, suffix: &StorageFinalSuffixPreflightV2,
        stored: StoredFloorDataViewV1<'_>, profile: FloorProfileV1) -> Result<(), FloorErrorV1>
    {
        let mut original = self.begin_mutation_v2(main, receiving)?;
        let result = (|| {
            let retained = self.selected_read.as_ref().ok_or(FloorErrorV1::Unavailable)?
                .mutations.iter().any(|held| held.suffix.as_ref()
                    .is_some_and(|data| Arc::ptr_eq(data, &suffix.data))
                    && matches!(held.returned, Some(Ok(()))) && held.failure().is_none());
            if !retained { return Err(FloorErrorV1::Unavailable); }
            self.admit_mutation_construction_v2(&mut original, main, receiving, None)?;
            if self.read_storage_receiving_v2(main, receiving, profile)?.view() != stored {
                return Err(FloorErrorV1::Diverged);
            }
            let (intent, _) = stored.prepared.ok_or(FloorErrorV1::Diverged)?;
            original.finalize.observe_once_v2(intent)?;
            original.finalization = Some(original.finalize.take_completed_v2().ok_or(FloorErrorV1::Encoding)?);
            if original.finalization.as_ref() != Some(&suffix.data.transaction) {
                return Err(FloorErrorV1::Diverged);
            }
            original.native_demand = Some(original.native_receiving_demand(self.custody.journal()));
            let required = original.native_demand.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(FloorErrorV1::Encoding)?;
            self.admit_mutation_demand_v2(main, receiving, required)?;

            original.native_entered = true;
            let authority = match self.custody.journal_mut().claim_protected_authority_retaining_v1(
                RecordNamespace::BrokerSessionTraffic, &mut original.capacity,
            ) {
                Ok(authority) => { original.claim = Some(Ok(())); authority }
                Err(cause) => {
                    original.claim = Some(Err(cause));
                    return Err(FloorErrorV1::Unavailable);
                }
            };
            let transaction = original.finalization.as_ref().ok_or(FloorErrorV1::Encoding)?;
            original.effect = Some(authority.validate_preflight_for_effect(
                &suffix.data.token, core::slice::from_ref(transaction),
            ));
            if !matches!(original.effect, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
            Ok(())
        })();
        let result = self.finish_mutation_native_v2(&mut original, result);
        original.returned = Some(result);
        self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?.retain_mutation_v2(original)?;
        result
    }

    /// Constructs the input intent on the original F before growing its index.
    ///
    /// # Errors
    /// Retains the existing successor-before-digest failure order, actual key
    /// index/hash prefix and first arithmetic or financial refusal.
    pub(crate) fn new_storage_intent_receiving_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, profile: FloorProfileV1,
        checkpoint: FloorCheckpointDataV1, target: super::super::FloorCutV1,
        transaction: &JournalTransaction) -> Result<FloorIntentDataV1, FloorErrorV1>
    {
        let mut original = self.begin_mutation_v2(main, receiving)?;
        let result = (|| {
            original.preconstruct = Some(StorageFloorMutationOriginalV2::
                intent_receiving_demand(transaction));
            let required = original.preconstruct.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(FloorErrorV1::Encoding)?;
            self.admit_mutation_demand_v2(main, receiving, required)?;
            original.intent = Some(FloorIntentDataV1::new_retaining_v2(
                FloorProfileDataV1::Broker(profile), checkpoint, target,
                transaction, &mut original.binding,
            ));
            original.intent.as_ref().copied().ok_or(FloorErrorV1::Unavailable)?
        })();
        original.returned = Some(result.as_ref().map(|_| ()).map_err(|cause| *cause));
        self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?.retain_mutation_v2(original)?;
        result
    }

    fn admit_mutation_demand_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, required: ResourceVector)
        -> Result<(), FloorErrorV1>
    {
        self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .admit_mutation_v2(required, main, self.custody.journal(), receiving)
    }

    fn begin_mutation_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2)
        -> Result<Box<StorageFloorMutationOriginalV2>, FloorErrorV1>
    {
        if self.storage_read_failure_v2().is_some() { return Err(FloorErrorV1::Unavailable); }
        let fixed = self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .retain_mutation_fixed_v2(StorageFloorMutationOriginalV2::fixed_demand())?;
        self.admit_mutation_demand_v2(main, receiving, fixed)?;
        self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?
            .reserve_mutation_archive_v2()?;
        Ok(Box::new(StorageFloorMutationOriginalV2::new()))
    }

    fn admit_mutation_construction_v2(&mut self, original: &mut StorageFloorMutationOriginalV2,
        main: &Journal, receiving: &mut dyn StorageFloorFinancialSourceV2,
        transaction: Option<&JournalTransaction>) -> Result<(), FloorErrorV1>
    {
        original.extent = Some(self.custody.journal()
            .held_session_receiving_extent_v1(&mut original.metadata));
        if !matches!(original.extent, Some(Ok(_))) { return Err(FloorErrorV1::Unavailable); }
        original.preconstruct = Some(original.preconstruction_demand(&self.custody, transaction, self.main_limits));
        let required = original.preconstruct.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        self.admit_mutation_demand_v2(main, receiving, required)
    }

    fn append_mutation_once_v2(&mut self, original: &mut StorageFloorMutationOriginalV2,
        main: &Journal, receiving: &mut dyn StorageFloorFinancialSourceV2)
        -> Result<(), FloorErrorV1>
    {
        original.native_demand = Some(original.native_receiving_demand(self.custody.journal()));
        let required = original.native_demand.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(FloorErrorV1::Encoding)?;
        self.admit_mutation_demand_v2(main, receiving, required)?;

        original.native_entered = true;
        let mut authority = match self.custody.journal_mut().claim_protected_authority_retaining_v1(
            RecordNamespace::BrokerSessionTraffic, &mut original.capacity,
        ) {
            Ok(authority) => { original.claim = Some(Ok(())); authority }
            Err(cause) => {
                original.claim = Some(Err(cause));
                return Err(FloorErrorV1::Unavailable);
            }
        };
        let transactions: &[JournalTransaction] = match original.preparations.as_ref() {
            Some(transactions) => transactions,
            None => core::slice::from_ref(original.finalization.as_ref().ok_or(FloorErrorV1::Encoding)?),
        };
        original.token = Some(authority.preflight_transactions_retaining_v2(transactions, &mut original.preflight));
        let token = original.token.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(FloorErrorV1::Unavailable)?;
        original.effect = Some(authority.validate_preflight_for_effect(token, transactions));
        if !matches!(original.effect, Some(Ok(()))) { return Err(FloorErrorV1::Unavailable); }
        original.commit = Some(authority.commit(&transactions[0]));
        if !matches!(original.commit, Some(Ok(_))) { return Err(FloorErrorV1::Unavailable); }
        Ok(())
    }

    fn finish_mutation_native_v2(&mut self, original: &mut StorageFloorMutationOriginalV2,
        primary: Result<(), FloorErrorV1>) -> Result<(), FloorErrorV1>
    {
        original.primary = Some(primary);
        if original.native_entered {
            // The entered advisory/append interval owes this independent sample
            // even when its primary failed. No health gate suppresses it.
            original.after = Some(self.custody.validate_held_retaining_v1(&mut original.after_original));
        }
        primary?;
        if original.native_entered && !matches!(original.after, Some(Ok(()))) {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    /// Performs the canonical preparation under the actual same-F invoice.
    ///
    /// The caller separately pays and retains the input intent's construction.
    /// This private helper does not open the selected outer recovery guard.
    ///
    /// # Errors
    /// Retains original funding, model, claim, preflight, append, post and read
    /// failures in the same enclosing programme, then returns a coarse refusal.
    pub(crate) fn prepare_storage_receiving_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, profile: FloorProfileV1,
        old: StoredFloorDataViewV1<'_>, intent: FloorIntentDataV1,
        transaction: &JournalTransaction) -> Result<(), FloorErrorV1>
    {
        let mut original = self.begin_mutation_v2(main, receiving)?;
        let result = (|| {
            self.admit_mutation_construction_v2(&mut original, main, receiving, Some(transaction))?;
            if self.read_storage_receiving_v2(main, receiving, profile)?.view() != old {
                return Err(FloorErrorV1::Diverged);
            }
            if old.prepared.is_some() { return Err(FloorErrorV1::Diverged); }
            original.predecessor = Some(intent.require_predecessor(FloorProfileDataV1::Broker(profile), old.checkpoint));
            match original.predecessor.as_ref() {
                Some(Ok(())) => (),
                Some(Err(cause)) => return Err(*cause),
                None => return Err(FloorErrorV1::Unavailable),
            }
            original.transaction_binding = Some(intent.require_transaction_retaining_v1(transaction, &mut original.binding));
            match original.transaction_binding.as_ref() {
                Some(Ok(())) => (),
                Some(Err(cause)) => return Err(*cause),
                None => return Err(FloorErrorV1::Unavailable),
            }
            original.prepare.observe_once_v2(intent, transaction, self.main_limits)?;
            original.finalize.observe_once_v2(intent)?;
            original.preparations = Some([
                original.prepare.take_completed_v2().ok_or(FloorErrorV1::Encoding)?,
                original.finalize.take_completed_v2().ok_or(FloorErrorV1::Encoding)?,
            ]);
            self.append_mutation_once_v2(&mut original, main, receiving)
        })();
        let result = self.finish_mutation_native_v2(&mut original, result).and_then(|()| {
            let retained = self.read_storage_receiving_v2(main, receiving, profile)?;
            if retained.checkpoint != old.checkpoint || !retained.prepared.as_ref()
                .is_some_and(|(actual_intent, actual_transaction)| *actual_intent == intent && actual_transaction == transaction)
            { return Err(FloorErrorV1::Diverged); }
            Ok(())
        });
        original.returned = Some(result);
        self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?.retain_mutation_v2(original)?;
        result
    }

    /// Finalizes the exact retained preparation with actual same-F funding.
    ///
    /// This helper supplies no outer recovery, TPM or main-history completion.
    ///
    /// # Errors
    /// Keeps original constructor, claim, preflight, native append, independent
    /// post and readback failures with their actual programme and journal.
    pub(crate) fn finalize_storage_receiving_v2(&mut self, main: &Journal,
        receiving: &mut dyn StorageFloorFinancialSourceV2, profile: FloorProfileV1,
        stored: StoredFloorDataViewV1<'_>) -> Result<(), FloorErrorV1>
    {
        let mut original = self.begin_mutation_v2(main, receiving)?;
        let result = (|| {
            self.admit_mutation_construction_v2(&mut original, main, receiving, None)?;
            if self.read_storage_receiving_v2(main, receiving, profile)?.view() != stored {
                return Err(FloorErrorV1::Diverged);
            }
            let (intent, _) = stored.prepared.ok_or(FloorErrorV1::Diverged)?;
            original.finalize.observe_once_v2(intent)?;
            original.finalization = Some(original.finalize.take_completed_v2().ok_or(FloorErrorV1::Encoding)?);
            self.append_mutation_once_v2(&mut original, main, receiving)
        })();
        let result = self.finish_mutation_native_v2(&mut original, result).and_then(|()| {
            let (intent, _) = stored.prepared.ok_or(FloorErrorV1::Diverged)?;
            let retained = self.read_storage_receiving_v2(main, receiving, profile)?;
            if retained.checkpoint != intent.target() || retained.prepared.is_some() {
                return Err(FloorErrorV1::Diverged);
            }
            Ok(())
        });
        original.returned = Some(result);
        self.selected_read.as_mut().ok_or(FloorErrorV1::Unavailable)?.retain_mutation_v2(original)?;
        result
    }
}
