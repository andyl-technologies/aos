//! Dormant protected-store settlement for effect-bearing publisher reducers.
//!
//! The adapter is constructed only from the claimed publisher journal. It
//! consumes one sealed reducer branch, derives its transaction identity from
//! the complete canonical mutation set, and resolves ambiguous durability
//! before returning the reducer's opaque acknowledgement. Completion paths
//! additionally retain and atomically delete the exact global-capacity
//! reservation. This module registers no controller, listener, or effect.

use std::collections::BTreeMap;

use aos_sandbox_core::OperationId;
use sha2::{Digest as _, Sha256};

use crate::journal::Journal;

use super::{
    AdmissionError, AdmissionLedger, AdmissionLimits, AppliedPublisherAdmissionTransactionV1,
    CapacityPolicyV1, CapacityProtectedStoreSettlementV1, CatalogEvictionObservation,
    CatalogEvictionReceiptV1, CommittedAdmissionFrontier, CommittedCatalogObservation,
    CommittedReadEntryV1, CompletionEffectCustodyV1, CompletionEffectObservationV1,
    CompletionReceiptV1, CompletionSettlementV1, ProtectedMutationBranchV1,
    ProtectedStoreCommitToken, ProtectedStoreSettlementReceiptV1, PublisherAdmissionColdRecoveryV1,
    PublisherAdmissionCommitOutcomeV1, PublisherAdmissionJournalErrorV1,
    PublisherAdmissionJournalRecoveryV1, PublisherAdmissionProtectedJournalV1,
    PublisherCapacityAdmissionCommitOutcomeV1, PublisherCapacityAdmissionRecoveryV1,
    PublisherCapacitySettlementCommitOutcomeV1, PublisherCapacitySettlementRecoveryV1,
    PublisherCompletionCapacityV1, ReadCatalogProjectionV1, RecoveryObservationV1,
    RecoveryPhysicalCustodyV1, RecoveryResultV1, RetainedCompletionPermit,
    StateOnlyProtectedStoreSettlementV1,
};

const SETTLEMENT_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-admission.store-settlement-transaction.v1\0";

/// Owns exactly one state-only dormant reducer-to-journal settlement.
///
/// This authority cannot be passed to permit-terminal reducer entrypoints.
pub(crate) struct PublisherStateProtectedStoreSettlementV1<'authority, 'journal> {
    authority: &'authority mut PublisherAdmissionProtectedJournalV1<'journal>,
    settled: bool,
}

/// Owns one exact capacity reservation through terminal journal settlement.
///
/// The distinct type is the only implementation accepted by completion and
/// catalog-repair reducers, preventing substitution of a state-only store.
pub(crate) struct PublisherCapacityProtectedStoreSettlementV1<'authority, 'journal> {
    authority: &'authority mut PublisherAdmissionProtectedJournalV1<'journal>,
    capacity: Option<PublisherCompletionCapacityV1>,
    settled: bool,
}

impl PublisherCapacityProtectedStoreSettlementV1<'_, '_> {
    fn reclaim_unsettled_capacity(mut self) -> PublisherCompletionCapacityV1 {
        if self.settled {
            fatal_settlement();
        }
        match self.capacity.take() {
            Some(capacity) => capacity,
            None => fatal_settlement(),
        }
    }
}

/// Owns one claimed publisher journal and every unsettled issued capacity.
///
/// This dormant owner is the compiled integration boundary for reducer RAII.
/// It retains capacity after permit issuance, recovers it after cold reopen,
/// and invokes the concrete state-only or capacity-bearing settlement type for
/// each closed operation. It performs no filesystem or catalog effect itself.
pub(crate) struct PublisherProtectedJournalOwnerV1<'journal> {
    authority: PublisherAdmissionProtectedJournalV1<'journal>,
    capacities: BTreeMap<[u8; 16], PublisherCompletionCapacityV1>,
}

/// Reports failure before a dormant owner can release reducer authority.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PublisherProtectedJournalOwnerErrorV1 {
    /// The protected publisher journal rejected planning, recovery, or readback.
    #[error(transparent)]
    Journal(#[from] PublisherAdmissionJournalErrorV1),
    /// The publisher reducer rejected the requested exact transition.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// No exact retained completion reservation matches the operation.
    #[error("publisher completion capacity is absent or duplicated")]
    Capacity,
}

impl<'journal> PublisherAdmissionProtectedJournalV1<'journal> {
    /// Borrows this authority for one state-only protected settlement.
    pub(crate) fn protected_store_settlement(
        &mut self,
    ) -> PublisherStateProtectedStoreSettlementV1<'_, 'journal> {
        PublisherStateProtectedStoreSettlementV1 {
            authority: self,
            settled: false,
        }
    }

    /// Borrows this authority for one terminal completion-capacity settlement.
    pub(crate) fn protected_store_capacity_settlement(
        &mut self,
        capacity: PublisherCompletionCapacityV1,
    ) -> PublisherCapacityProtectedStoreSettlementV1<'_, 'journal> {
        PublisherCapacityProtectedStoreSettlementV1 {
            authority: self,
            capacity: Some(capacity),
            settled: false,
        }
    }
}

impl<'journal> PublisherProtectedJournalOwnerV1<'journal> {
    /// Claims the dormant owner over one protected-open journal.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherProtectedJournalOwnerErrorV1`] for invalid limits or
    /// unhealthy protected provenance.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        limits: AdmissionLimits,
        capacity: CapacityPolicyV1,
        maximum_source_releases: usize,
        maximum_root_records: usize,
    ) -> Result<Self, PublisherProtectedJournalOwnerErrorV1> {
        Ok(Self {
            authority: PublisherAdmissionProtectedJournalV1::claim(
                journal,
                limits,
                capacity,
                maximum_source_releases,
                maximum_root_records,
            )?,
            capacities: BTreeMap::new(),
        })
    }

    /// Commits one permit-issuance branch and retains its exact capacity.
    ///
    /// Ambiguous commits are recovered internally and exact retries preserve
    /// the original transaction. The acknowledgement is returned only after
    /// the composite postcommit capability is revalidated and its capacity is
    /// installed in this owner.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherProtectedJournalOwnerErrorV1`] for planning,
    /// durability, divergence, readback, or duplicate-capacity failure.
    pub(crate) fn issue_completion_capacity(
        &mut self,
        transaction_id: [u8; 16],
        branch: &ProtectedMutationBranchV1,
    ) -> Result<ProtectedStoreCommitToken, PublisherProtectedJournalOwnerErrorV1> {
        let mut prepared = self
            .authority
            .plan_capacity_reserved_branch(transaction_id, branch)?;
        loop {
            match self.authority.commit_capacity_reserved_branch(prepared) {
                Ok(PublisherCapacityAdmissionCommitOutcomeV1::Applied(applied)) => {
                    return Ok(self.retain_applied_capacity(applied));
                }
                Ok(PublisherCapacityAdmissionCommitOutcomeV1::OutcomeUnknown {
                    pending,
                    cause: _,
                }) => match self.authority.recover_capacity_reserved_branch(pending) {
                    Ok(PublisherCapacityAdmissionRecoveryV1::Applied(applied)) => {
                        return Ok(self.retain_applied_capacity(applied));
                    }
                    Ok(PublisherCapacityAdmissionRecoveryV1::Retry(retry)) => prepared = retry,
                    Ok(PublisherCapacityAdmissionRecoveryV1::Diverged(_)) | Err(_) => {
                        fatal_settlement();
                    }
                },
                Err(_) => fatal_settlement(),
            }
        }
    }

    /// Recovers and retains one outstanding capacity after cold reopen.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherProtectedJournalOwnerErrorV1`] when the transaction
    /// is not one exact pending effect or its capacity is duplicated.
    pub(crate) fn recover_completion_capacity(
        &mut self,
        transaction_id: [u8; 16],
    ) -> Result<(), PublisherProtectedJournalOwnerErrorV1> {
        let observation = match self.authority.recover_current_transaction(transaction_id)? {
            PublisherAdmissionColdRecoveryV1::ObservePending(observation) => observation,
            PublisherAdmissionColdRecoveryV1::StateOnly
            | PublisherAdmissionColdRecoveryV1::Terminal(_) => {
                return Err(PublisherProtectedJournalOwnerErrorV1::Capacity);
            }
        };
        let mut validated = observation.consume(&self.authority)?;
        let capacity = validated
            .take_completion_capacity()
            .ok_or(PublisherProtectedJournalOwnerErrorV1::Capacity)?;
        drop(validated);
        self.retain_capacity(capacity)
    }

    /// Runs the exact terminal completion reducer through capacity settlement.
    ///
    /// The caller supplies observations only after its dormant physical and
    /// catalog adapter has completed the corresponding operation.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherProtectedJournalOwnerErrorV1`] for absent capacity,
    /// reducer mismatch, or a poison terminal branch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_completion<'authority, 'request>(
        &mut self,
        ledger: &mut AdmissionLedger,
        committed: &CommittedAdmissionFrontier,
        operation: OperationId,
        permit: RetainedCompletionPermit<'authority, 'request>,
        effect: CompletionEffectCustodyV1,
        intended_entry: CommittedReadEntryV1,
        catalog: &mut ReadCatalogProjectionV1,
        catalog_observation: CommittedCatalogObservation,
        effect_observation: CompletionEffectObservationV1,
    ) -> Result<CompletionReceiptV1, PublisherProtectedJournalOwnerErrorV1> {
        let capacity = self.take_capacity(operation)?;
        let mut store = self.authority.protected_store_capacity_settlement(capacity);
        let authority = match ledger.authorize_completion(
            committed,
            permit,
            effect,
            intended_entry,
            catalog,
            &mut store,
        ) {
            Ok(authority) => authority,
            Err(error) => {
                let capacity = store.reclaim_unsettled_capacity();
                self.retain_capacity(capacity)?;
                return Err(error.into());
            }
        };
        let settlement = CompletionSettlementV1::from_durable_adapter(
            authority,
            catalog_observation,
            effect_observation,
        );
        Ok(settlement.settle()?)
    }

    /// Runs exact catalog repair through capacity-bearing terminal settlement.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherProtectedJournalOwnerErrorV1`] for absent capacity,
    /// recovery mismatch, or protected-store failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_catalog_repair<'root>(
        &mut self,
        ledger: &mut AdmissionLedger,
        committed: &CommittedAdmissionFrontier,
        operation: OperationId,
        intended_entry: CommittedReadEntryV1,
        catalog: &mut ReadCatalogProjectionV1,
        catalog_observation: CommittedCatalogObservation,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> Result<RecoveryResultV1, PublisherProtectedJournalOwnerErrorV1> {
        let capacity = self.take_capacity(operation)?;
        let mut store = self.authority.protected_store_capacity_settlement(capacity);
        let permit = match ledger.authorize_catalog_repair(
            committed,
            operation,
            intended_entry,
            catalog,
            &mut store,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                let capacity = store.reclaim_unsettled_capacity();
                self.retain_capacity(capacity)?;
                return Err(error.into());
            }
        };
        let completion = RecoveryObservationV1::repaired_catalog_from_durable_adapter(
            permit,
            catalog_observation,
            physical_custody,
        );
        Ok(completion.settle()?)
    }

    /// Runs one durable catalog-eviction observation through state-only settlement.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherProtectedJournalOwnerErrorV1`] for reducer or
    /// protected-store failure.
    pub(crate) fn settle_catalog_eviction(
        &mut self,
        ledger: &mut AdmissionLedger,
        committed: &CommittedAdmissionFrontier,
        catalog: &mut ReadCatalogProjectionV1,
        operation: OperationId,
        eviction_catalog_generation: u64,
    ) -> Result<CatalogEvictionReceiptV1, PublisherProtectedJournalOwnerErrorV1> {
        let mut store = self.authority.protected_store_settlement();
        let authorization =
            ledger.authorize_catalog_eviction(committed, catalog, operation, &mut store)?;
        let commit = CatalogEvictionObservation::from_durable_catalog_adapter(
            authorization,
            eviction_catalog_generation,
        );
        Ok(commit.settle()?)
    }

    /// Runs one obligation-free publication-root retirement through state-only settlement.
    ///
    /// # Errors
    ///
    /// Returns [`PublisherProtectedJournalOwnerErrorV1`] for retained
    /// obligations, reducer mismatch, or protected-store failure.
    pub(crate) fn settle_root_retirement(
        &mut self,
        ledger: &mut AdmissionLedger,
        registry: &mut crate::publisher_roots::PublicationRootRegistry,
        root_id: crate::publisher_roots::PublicationRootId,
    ) -> Result<
        crate::publisher_roots::PublicationRootRecordV1,
        PublisherProtectedJournalOwnerErrorV1,
    > {
        let mut store = self.authority.protected_store_settlement();
        let retirement = ledger.retire_root(registry, root_id, &mut store)?;
        Ok(retirement.settle()?)
    }

    fn retain_applied_capacity(
        &mut self,
        mut applied: AppliedPublisherAdmissionTransactionV1,
    ) -> ProtectedStoreCommitToken {
        let acknowledgement = match applied.take_acknowledgement() {
            Some(acknowledgement) => acknowledgement,
            None => fatal_settlement(),
        };
        let postcommit = match applied.take_postcommit() {
            Some(postcommit) => postcommit,
            None => fatal_settlement(),
        };
        let mut validated = match postcommit.consume(&self.authority) {
            Ok(validated) => validated,
            Err(_) => fatal_settlement(),
        };
        let capacity = match validated.take_completion_capacity() {
            Some(capacity) => capacity,
            None => fatal_settlement(),
        };
        drop(validated);
        if self.retain_capacity(capacity).is_err() {
            fatal_settlement();
        }
        acknowledgement
    }

    fn retain_capacity(
        &mut self,
        capacity: PublisherCompletionCapacityV1,
    ) -> Result<(), PublisherProtectedJournalOwnerErrorV1> {
        let operation = capacity.operation_id();
        if self.capacities.contains_key(&operation) {
            return Err(PublisherProtectedJournalOwnerErrorV1::Capacity);
        }
        self.capacities.insert(operation, capacity);
        Ok(())
    }

    fn take_capacity(
        &mut self,
        operation: OperationId,
    ) -> Result<PublisherCompletionCapacityV1, PublisherProtectedJournalOwnerErrorV1> {
        self.capacities
            .remove(operation.as_bytes())
            .ok_or(PublisherProtectedJournalOwnerErrorV1::Capacity)
    }
}

impl StateOnlyProtectedStoreSettlementV1 for PublisherStateProtectedStoreSettlementV1<'_, '_> {
    fn settle(
        &mut self,
        primary: Option<&ProtectedMutationBranchV1>,
        poison: &ProtectedMutationBranchV1,
    ) -> ProtectedStoreSettlementReceiptV1 {
        if self.settled {
            fatal_settlement();
        }

        let (selected, selected_primary) = match primary {
            Some(primary) => (primary, true),
            None => (poison, false),
        };
        let transaction_id = match settlement_transaction_id(&selected.mutations) {
            Some(transaction_id) => transaction_id,
            None => fatal_settlement(),
        };
        let token = settle_state_only(self.authority, transaction_id, selected);

        self.settled = true;
        settlement_receipt(selected_primary, token)
    }
}

impl CapacityProtectedStoreSettlementV1 for PublisherCapacityProtectedStoreSettlementV1<'_, '_> {
    fn settle(
        &mut self,
        primary: Option<&ProtectedMutationBranchV1>,
        poison: &ProtectedMutationBranchV1,
    ) -> ProtectedStoreSettlementReceiptV1 {
        if self.settled {
            fatal_settlement();
        }

        let (selected, selected_primary) = match primary {
            Some(primary) => (primary, true),
            None => (poison, false),
        };
        let transaction_id = match settlement_transaction_id(&selected.mutations) {
            Some(transaction_id) => transaction_id,
            None => fatal_settlement(),
        };
        let capacity = match self.capacity.take() {
            Some(capacity) => capacity,
            None => fatal_settlement(),
        };
        let token = settle_completion_capacity(self.authority, transaction_id, selected, capacity);

        self.settled = true;
        settlement_receipt(selected_primary, token)
    }
}

fn settlement_receipt(
    selected_primary: bool,
    token: ProtectedStoreCommitToken,
) -> ProtectedStoreSettlementReceiptV1 {
    if selected_primary {
        ProtectedStoreSettlementReceiptV1::Primary(token)
    } else {
        ProtectedStoreSettlementReceiptV1::Poisoned(token)
    }
}

fn settle_state_only(
    authority: &mut PublisherAdmissionProtectedJournalV1<'_>,
    transaction_id: [u8; 16],
    branch: &ProtectedMutationBranchV1,
) -> ProtectedStoreCommitToken {
    let mut prepared = match authority.plan_branch(transaction_id, branch) {
        Ok(prepared) => prepared,
        Err(_) => fatal_settlement(),
    };

    loop {
        match authority.commit(prepared) {
            Ok(PublisherAdmissionCommitOutcomeV1::Applied(applied)) => {
                return applied_acknowledgement(applied);
            }
            Ok(PublisherAdmissionCommitOutcomeV1::OutcomeUnknown { pending, cause: _ }) => {
                match authority.recover(pending) {
                    Ok(PublisherAdmissionJournalRecoveryV1::Applied(applied)) => {
                        return applied_acknowledgement(applied);
                    }
                    Ok(PublisherAdmissionJournalRecoveryV1::Retry(retry)) => prepared = retry,
                    Ok(PublisherAdmissionJournalRecoveryV1::Diverged(_)) | Err(_) => {
                        fatal_settlement();
                    }
                }
            }
            Err(_) => fatal_settlement(),
        }
    }
}

fn settle_completion_capacity(
    authority: &mut PublisherAdmissionProtectedJournalV1<'_>,
    transaction_id: [u8; 16],
    branch: &ProtectedMutationBranchV1,
    capacity: PublisherCompletionCapacityV1,
) -> ProtectedStoreCommitToken {
    let mut prepared = match authority.plan_capacity_settlement(transaction_id, branch, capacity) {
        Ok(prepared) => prepared,
        Err(_) => fatal_settlement(),
    };

    loop {
        match authority.commit_capacity_settlement(prepared) {
            Ok(PublisherCapacitySettlementCommitOutcomeV1::Applied(applied)) => {
                return applied_acknowledgement(applied);
            }
            Ok(PublisherCapacitySettlementCommitOutcomeV1::OutcomeUnknown {
                pending,
                cause: _,
            }) => match authority.recover_capacity_settlement(pending) {
                Ok(PublisherCapacitySettlementRecoveryV1::Applied(applied)) => {
                    return applied_acknowledgement(applied);
                }
                Ok(PublisherCapacitySettlementRecoveryV1::Retry(retry)) => prepared = retry,
                Ok(PublisherCapacitySettlementRecoveryV1::Diverged(_)) | Err(_) => {
                    fatal_settlement();
                }
            },
            Err(_) => fatal_settlement(),
        }
    }
}

fn applied_acknowledgement(
    mut applied: AppliedPublisherAdmissionTransactionV1,
) -> ProtectedStoreCommitToken {
    match applied.take_acknowledgement() {
        Some(token) => token,
        None => fatal_settlement(),
    }
}

fn settlement_transaction_id(mutations: &[super::LedgerMutation]) -> Option<[u8; 16]> {
    let mutation_count = u64::try_from(mutations.len()).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_TRANSACTION_DOMAIN);
    hasher.update(mutation_count.to_be_bytes());
    for mutation in mutations {
        let key_length = u64::try_from(mutation.key.len()).ok()?;
        let value_length = u64::try_from(mutation.value.len()).ok()?;

        hasher.update([mutation.kind as u8]);
        hasher.update(key_length.to_be_bytes());
        hasher.update(&mutation.key);
        hasher.update(value_length.to_be_bytes());
        hasher.update(&mutation.value);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    if transaction_id == [0; 16] {
        transaction_id.copy_from_slice(&digest[16..]);
    }
    if transaction_id == [0; 16] {
        transaction_id[15] = 1;
    }
    Some(transaction_id)
}

fn fatal_settlement() -> ! {
    // Releasing retained physical or registry custody after an indeterminate
    // protected-store outcome would duplicate or suppress an effect.
    std::process::abort()
}
