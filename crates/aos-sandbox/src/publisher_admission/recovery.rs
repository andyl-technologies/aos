//! Observation-only recovery, checkpoints, and failover reducers.
//!
//! Recovery inputs describe facts observed by a trusted filesystem/catalog
//! adapter. They are not authority to create a new effect. Existing exact
//! completion permits survive holder revocation and authority-epoch failover;
//! unresolved operations remain fully charged until a terminal observation is
//! durably committed.

use aos_sandbox_core::{ObjectDigest, OperationId};

use super::decision::CompletionResult;
use super::{
    AdmissionDecisionStateV1, AdmissionError, AdmissionLedger, AuthorityCheckpointV1,
    CompletionPermitStateV1, LedgerMutation, ProtectedMutationBranchV1,
    ProtectedStoreSettlementReceiptV1, ProtectedStoreSettlementV1, RecoveryDispositionV1,
    digest_parts,
};

const OUTSTANDING_DOMAIN: &[u8] = b"aos.sandbox.publisher.outstanding-permits.v1\0";
const FENCE_DOMAIN: &[u8] = b"aos.sandbox.publisher.executor-fence.v1\0";
const RECOVERY_DOMAIN: &[u8] = b"aos.sandbox.publisher.recovery-observation.v1\0";

/// Owns a trusted adapter's exact physical and catalog recovery observation.
///
/// The closed semantic kind and all constructors are crate-private. Protocol
/// scalars therefore cannot manufacture absence, fencing, final-name custody,
/// or durable catalog visibility.
pub struct RecoveryObservationV1<'root> {
    kind: RecoveryObservationKindV1,
    physical_custody: RecoveryPhysicalCustodyV1<'root>,
}

/// Seals a trusted adapter's singular physical-observation custody.
///
/// This linear capability has no public constructor, decoder, fields, or
/// `Clone` implementation. It structurally owns a descriptor-backed root
/// authorization, so scalar digests cannot manufacture it. Creating it
/// transfers the adapter's obligation to retain that pinned root observation
/// until the recovery reducer validates it. Effect-bearing catalog repair
/// retains the value further through protected-store settlement.
#[must_use = "physical recovery custody must be consumed by a protected transition"]
pub struct RecoveryPhysicalCustodyV1<'root> {
    root: crate::publisher_roots::AuthorizedPublicationRoot<'root>,
    artifact_digest: Option<ObjectDigest>,
    observation_digest: ObjectDigest,
}

impl<'root> RecoveryPhysicalCustodyV1<'root> {
    /// Seals a pinned physical observation with its live root authorization.
    pub(crate) const fn seal_from_physical_adapter(
        root: crate::publisher_roots::AuthorizedPublicationRoot<'root>,
        artifact_digest: Option<ObjectDigest>,
        observation_digest: ObjectDigest,
    ) -> Self {
        Self {
            root,
            artifact_digest,
            observation_digest,
        }
    }

    const fn root_record_digest(&self) -> ObjectDigest {
        self.root.record_digest()
    }
}

#[derive(Debug, Eq, PartialEq)]
enum RecoveryObservationKindV1 {
    NoEffect(OperationId),
    ExactPrivateArtifact {
        operation: OperationId,
        artifact_digest: ObjectDigest,
    },
    ExactAbsentAfterFence {
        operation: OperationId,
        artifact_digest: ObjectDigest,
        executor_fence: RecoveryExecutorFenceV1,
    },
    FinalOnlyCatalogAbsent {
        operation: OperationId,
        artifact_digest: ObjectDigest,
        executor_fence: RecoveryExecutorFenceV1,
        intended_entry: super::CommittedReadEntryV1,
    },
    // Recovery-only classification of an effect already observed under the
    // retained recovery custody. Ordinary adapters cannot construct
    // `CompletionResult`; they use the sealed completion settlement instead.
    ExactCommitted(CompletionResult),
    Contradiction {
        operation: OperationId,
        evidence_digest: ObjectDigest,
    },
}

/// Proves recovery cannot race the executor that received the old permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryExecutorFenceV1 {
    publisher_instance: aos_sandbox_core::PublisherInstanceId,
    death_or_revocation_digest: ObjectDigest,
    recovery_incarnation: ObjectDigest,
}

impl RecoveryExecutorFenceV1 {
    /// Captures a protected executor-registry fence and recovery incarnation.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when either protected commitment is zero.
    pub(crate) fn from_protected_executor_registry(
        publisher_instance: aos_sandbox_core::PublisherInstanceId,
        death_or_revocation_digest: ObjectDigest,
        recovery_incarnation: ObjectDigest,
    ) -> Result<Self, AdmissionError> {
        if death_or_revocation_digest.as_bytes() == &[0; 32]
            || recovery_incarnation.as_bytes() == &[0; 32]
        {
            return Err(AdmissionError::InvalidIdentity("recovery fence"));
        }
        Ok(Self {
            publisher_instance,
            death_or_revocation_digest,
            recovery_incarnation,
        })
    }

    fn digest(&self) -> ObjectDigest {
        digest_parts(
            FENCE_DOMAIN,
            &[
                self.publisher_instance.as_bytes(),
                self.death_or_revocation_digest.as_bytes(),
                self.recovery_incarnation.as_bytes(),
            ],
        )
    }
}

impl<'root> RecoveryObservationV1<'root> {
    /// Captures complete pre-effect absence under trusted physical custody.
    pub(crate) const fn no_effect_from_physical_adapter(
        operation: OperationId,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> Self {
        Self {
            kind: RecoveryObservationKindV1::NoEffect(operation),
            physical_custody,
        }
    }

    /// Captures an exact private artifact under trusted physical custody.
    pub(crate) const fn private_artifact_from_physical_adapter(
        operation: OperationId,
        artifact_digest: ObjectDigest,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> Self {
        Self {
            kind: RecoveryObservationKindV1::ExactPrivateArtifact {
                operation,
                artifact_digest,
            },
            physical_custody,
        }
    }

    /// Captures exact post-fence physical absence.
    pub(crate) const fn absent_after_fence_from_physical_adapter(
        operation: OperationId,
        artifact_digest: ObjectDigest,
        executor_fence: RecoveryExecutorFenceV1,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> Self {
        Self {
            kind: RecoveryObservationKindV1::ExactAbsentAfterFence {
                operation,
                artifact_digest,
                executor_fence,
            },
            physical_custody,
        }
    }

    /// Captures a fenced final object whose exact catalog obligation is absent.
    pub(crate) const fn final_only_catalog_absent_from_physical_adapter(
        operation: OperationId,
        artifact_digest: ObjectDigest,
        executor_fence: RecoveryExecutorFenceV1,
        intended_entry: super::CommittedReadEntryV1,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> Self {
        Self {
            kind: RecoveryObservationKindV1::FinalOnlyCatalogAbsent {
                operation,
                artifact_digest,
                executor_fence,
                intended_entry,
            },
            physical_custody,
        }
    }

    /// Captures successful durable repair of the exact missing catalog entry.
    pub(crate) fn repaired_catalog_from_durable_adapter<'catalog>(
        permit: CatalogRepairPermitV1<'catalog>,
        catalog: super::CommittedCatalogObservation,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> CatalogRepairCompletionV1<'catalog, 'root> {
        CatalogRepairCompletionV1::prepare(permit, catalog, physical_custody)
    }

    /// Captures recovery proof for an effect observed under recovery custody.
    ///
    /// This is not an ordinary-completion ingress seam: its result type can be
    /// created only inside the publisher authority reducer from an unresolved
    /// protected permit and an exact recovery observation.
    pub(super) const fn committed_from_durable_adapter(
        result: CompletionResult,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> Self {
        Self {
            kind: RecoveryObservationKindV1::ExactCommitted(result),
            physical_custody,
        }
    }

    /// Captures a bounded contradiction observed by a trusted adapter.
    pub(crate) const fn contradiction_from_protected_adapter(
        operation: OperationId,
        evidence_digest: ObjectDigest,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> Self {
        Self {
            kind: RecoveryObservationKindV1::Contradiction {
                operation,
                evidence_digest,
            },
            physical_custody,
        }
    }
}

/// Authorizes one exact catalog repair after its absence intent is durable.
///
/// This is distinct from a completion permit: it is minted only from a
/// committed fenced-absence record and carries the exact intended entry and
/// catalog predecessor into the trusted catalog adapter. It retains the
/// protected store from issuance; dropping it before or after the catalog
/// effect durably selects poison rather than releasing ambiguous custody.
#[must_use = "catalog repair authority must be completed or durably poisoned"]
pub struct CatalogRepairPermitV1<'catalog> {
    operation: OperationId,
    artifact_digest: ObjectDigest,
    executor_instance: aos_sandbox_core::PublisherInstanceId,
    executor_fence_digest: ObjectDigest,
    absent_receipt_digest: ObjectDigest,
    prior_catalog_generation: u64,
    intended_entry: super::CommittedReadEntryV1,
    ledger: &'catalog mut AdmissionLedger,
    catalog: Option<super::read_authority::ExclusiveCatalogInsertionCustody<'catalog>>,
    poison: Option<ProtectedMutationBranchV1>,
    store: Option<&'catalog mut dyn ProtectedStoreSettlementV1>,
    settled: bool,
}

impl CatalogRepairPermitV1<'_> {
    fn settle_store(
        &mut self,
        primary: Option<&ProtectedMutationBranchV1>,
    ) -> Option<ProtectedStoreSettlementReceiptV1> {
        let poison = self.poison.as_ref()?;
        Some(self.store.as_mut()?.settle(
            primary.map(|branch| branch.mutations.as_slice()),
            &poison.mutations,
        ))
    }

    fn install_primary(
        &mut self,
        primary: &ProtectedMutationBranchV1,
        token: super::ProtectedStoreCommitToken,
    ) -> Result<(), AdmissionError> {
        primary.acknowledge(token)?;
        self.catalog
            .take()
            .ok_or(AdmissionError::Poisoned)?
            .commit();
        *self.ledger = primary.ledger.clone();
        self.settled = true;
        let _ = self.store.take();
        Ok(())
    }

    fn install_acknowledged_poison(
        &mut self,
        token: super::ProtectedStoreCommitToken,
    ) -> Result<(), AdmissionError> {
        let poison = self.poison.as_ref().ok_or(AdmissionError::Poisoned)?;
        poison.acknowledge(token)?;
        let poisoned = poison.ledger.clone();
        if let Some(catalog) = self.catalog.take() {
            catalog.poison();
        }
        *self.ledger = poisoned;
        self.settled = true;
        let _ = self.store.take();
        Ok(())
    }

    fn latch_unacknowledged_poison(&mut self) {
        self.ledger.latch_unacknowledged_poison();
        if let Some(catalog) = self.catalog.take() {
            catalog.poison();
        }
        self.settled = true;
        let _ = self.store.take();
    }
}

impl Drop for CatalogRepairPermitV1<'_> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let receipt = self.settle_store(None);
        let acknowledged = match receipt {
            Some(ProtectedStoreSettlementReceiptV1::Poisoned(token)) => {
                self.install_acknowledged_poison(token).is_ok()
            }
            Some(ProtectedStoreSettlementReceiptV1::Primary(_)) | None => false,
        };
        if !acknowledged {
            self.latch_unacknowledged_poison();
        }
    }
}

/// Retains exclusive physical, catalog, ledger, and protected-store custody.
///
/// The trusted adapter settles exactly one precomputed branch. Until its
/// checkpoint acknowledgement verifies, neither the catalog projection nor
/// the authoritative ledger advances. Dropping an unsettled value invokes the
/// same adapter with only the poison branch available.
#[must_use = "catalog repair must settle to an acknowledged success or poison branch"]
pub struct CatalogRepairCompletionV1<'catalog, 'root> {
    // Declaration order is an invariant: permit drop settles poison while the
    // descriptor-backed physical custody in the following field is still live.
    permit: CatalogRepairPermitV1<'catalog>,
    _physical_custody: RecoveryPhysicalCustodyV1<'root>,
    primary: Option<ProtectedMutationBranchV1>,
    result: Option<RecoveryResultV1>,
}

impl<'catalog, 'root> CatalogRepairCompletionV1<'catalog, 'root> {
    fn prepare(
        permit: CatalogRepairPermitV1<'catalog>,
        catalog: super::CommittedCatalogObservation,
        physical_custody: RecoveryPhysicalCustodyV1<'root>,
    ) -> Self {
        let mut staged = (*permit.ledger).clone();
        let custody_matches = permit.catalog.as_ref().is_some_and(|custody| {
            custody.prior_generation() == permit.prior_catalog_generation
                && custody.entry() == &permit.intended_entry
                && catalog.prior_generation() == permit.prior_catalog_generation
                && catalog.entry() == &permit.intended_entry
        });
        let mut result = if custody_matches {
            staged.recover_catalog_repair_in_place(
                permit.operation,
                permit.artifact_digest,
                permit.executor_instance,
                permit.executor_fence_digest,
                permit.absent_receipt_digest,
                &catalog,
                &physical_custody,
            )
        } else {
            Err(AdmissionError::CompletionMismatch)
        };
        let primary = match &mut result {
            Ok(result) => {
                let mutations = result.mutations.clone();
                result.mutations.clear();
                ProtectedMutationBranchV1::seal(staged, mutations).ok()
            }
            Err(_) => None,
        };
        CatalogRepairCompletionV1 {
            permit,
            _physical_custody: physical_custody,
            primary,
            result: result.ok(),
        }
    }

    /// Settles and acknowledges exactly one protected branch before advancing.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] only if the trusted protected-store adapter
    /// violates its exact-token settlement contract. An invalid primary or any
    /// ambiguous physical evidence selects the acknowledged poison branch.
    pub(crate) fn settle(mut self) -> Result<RecoveryResultV1, AdmissionError> {
        let receipt = self
            .permit
            .settle_store(self.primary.as_ref())
            .ok_or(AdmissionError::Poisoned)?;
        match receipt {
            ProtectedStoreSettlementReceiptV1::Primary(token) => {
                let primary = self
                    .primary
                    .as_ref()
                    .ok_or(AdmissionError::AuthorityMismatch)?;
                self.permit.install_primary(primary, token)?;
                self.result.take().ok_or(AdmissionError::Poisoned)
            }
            ProtectedStoreSettlementReceiptV1::Poisoned(token) => {
                self.permit.install_acknowledged_poison(token)?;
                Ok(RecoveryResultV1 {
                    operation: self.permit.operation,
                    disposition: RecoveryDispositionV1::Poisoned,
                    mutations: Vec::new(),
                })
            }
        }
    }
}

/// Returns a closed recovery classification plus required protected mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryResultV1 {
    /// Operation considered by the reducer.
    operation: OperationId,
    /// Closed next action; no action manufactures a fresh permit.
    disposition: RecoveryDispositionV1,
    /// Atomic protected mutations required before reporting the result.
    mutations: Vec<LedgerMutation>,
}

impl RecoveryResultV1 {
    /// Returns mutations only to the protected-store adapter.
    pub(crate) fn mutations(&self) -> &[LedgerMutation] {
        &self.mutations
    }

    /// Releases the recovery disposition only at its committed frontier.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when the synchronized frontier is stale.
    pub(crate) fn committed_disposition(
        &self,
        ledger: &AdmissionLedger,
        committed: &super::CommittedAdmissionFrontier,
    ) -> Result<(OperationId, RecoveryDispositionV1), AdmissionError> {
        ledger.require_committed(committed)?;
        Ok((self.operation, self.disposition))
    }
}

/// Returns the new durable epoch frontier and its atomic mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailoverResultV1 {
    /// Checkpoint that must be rollback-protected before authority resumes.
    checkpoint: AuthorityCheckpointV1,
    /// Uncertainty successors followed by the checkpoint record.
    mutations: Vec<LedgerMutation>,
}

impl FailoverResultV1 {
    /// Returns mutations only to the protected-store adapter.
    pub(crate) fn mutations(&self) -> &[LedgerMutation] {
        &self.mutations
    }

    /// Releases the failover checkpoint only after its exact durable commit.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when the synchronized frontier is stale.
    pub(crate) fn committed_checkpoint<'result>(
        &'result self,
        ledger: &AdmissionLedger,
        committed: &super::CommittedAdmissionFrontier,
    ) -> Result<&'result AuthorityCheckpointV1, AdmissionError> {
        ledger.require_committed(committed)?;
        if &ledger.checkpoint()? != &self.checkpoint {
            return Err(AdmissionError::AuthorityMismatch);
        }
        Ok(&self.checkpoint)
    }
}

impl AdmissionLedger {
    /// Mints catalog-repair authority from an exact committed fenced-absence record.
    ///
    /// The protected absence receipt is the pre-effect authorization. This
    /// method merely joins its retained fence/artifact/entry commitments to the
    /// current catalog predecessor and retains the protected-store settlement
    /// owner; it cannot authorize any other insert.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] unless the absence record is durably current,
    /// the completion permit remains unresolved, and the full intended entry
    /// matches the protected digest and retained publication facts.
    pub(crate) fn authorize_catalog_repair<'catalog>(
        &'catalog mut self,
        committed: &super::CommittedAdmissionFrontier,
        operation: OperationId,
        intended_entry: super::CommittedReadEntryV1,
        catalog: &'catalog mut super::ReadCatalogProjectionV1,
        store: &'catalog mut dyn ProtectedStoreSettlementV1,
    ) -> Result<CatalogRepairPermitV1<'catalog>, AdmissionError> {
        self.require_committed(committed)?;
        let artifact = self
            .artifact(operation)
            .ok_or(AdmissionError::ArtifactMismatch)?;
        let artifact_digest = artifact.artifact_digest;
        let executor_instance = artifact.publisher_instance;
        self.validate_recovery_catalog_entry(operation, artifact_digest, &intended_entry)?;
        let (absent_receipt_digest, executor_fence_digest, receipt_executor, prior_generation) = {
            let receipt = self
                .recovery_observations()
                .rev()
                .find(|receipt| {
                    receipt.operation == operation
                        && receipt.outcome
                            == super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
                        && receipt.catalog_entry_digest == Some(intended_entry.digest())
                })
                .ok_or(AdmissionError::CompletionMismatch)?;
            (
                receipt.receipt_digest,
                receipt
                    .executor_fence_digest
                    .ok_or(AdmissionError::CompletionMismatch)?,
                receipt.executor_instance,
                receipt.repair_prior_catalog_generation,
            )
        };
        let (permit_state, permit_artifact_digest) = self
            .permits()
            .find(|permit| permit.operation == operation)
            .map(|permit| (permit.state, permit.artifact_digest))
            .ok_or(AdmissionError::CompletionMismatch)?;
        if permit_state != CompletionPermitStateV1::Uncertain
            || permit_artifact_digest != artifact_digest
            || receipt_executor != Some(executor_instance)
            || self.receipt(operation).is_some()
            || self.latest_catalog_generation().unwrap_or(0) != prior_generation
            || catalog.generation() != prior_generation
            || catalog.contains_object(intended_entry.object())
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        let poison = self.sealed_poison_branch(catalog_repair_poison_digest(
            operation,
            artifact_digest,
            absent_receipt_digest,
        ))?;
        let catalog = catalog
            .begin_exclusive_insertion(prior_generation, intended_entry.clone())
            .map_err(|_| AdmissionError::CompletionMismatch)?;
        Ok(CatalogRepairPermitV1 {
            operation,
            artifact_digest,
            executor_instance,
            executor_fence_digest,
            absent_receipt_digest,
            prior_catalog_generation: prior_generation,
            intended_entry,
            ledger: self,
            catalog: Some(catalog),
            poison: Some(poison),
            store: Some(store),
            settled: false,
        })
    }

    /// Reduces one independently observed recovery fact.
    ///
    /// `NoEffect` is accepted only before an artifact or permit could exist.
    /// Private artifacts and ambiguous post-permit state remain charged and
    /// observation-only. Exact catalog completion spends the retained permit.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for absent/conflicting operations, malformed
    /// evidence, illegal transitions, poisoned state, or protected encoding.
    pub fn recover(
        &mut self,
        observation: RecoveryObservationV1<'_>,
    ) -> Result<RecoveryResultV1, AdmissionError> {
        if observation.physical_custody.observation_digest.as_bytes() == &[0; 32] {
            return Err(AdmissionError::InvalidIdentity(
                "physical recovery observation",
            ));
        }
        validate_physical_custody(self, &observation)?;
        if let Some(replayed) = self.replayed_recovery(&observation)? {
            return Ok(replayed);
        }
        if self.is_poisoned() {
            return Err(AdmissionError::Poisoned);
        }
        let mut staged = self.clone();
        let result = staged.recover_in_place(observation)?;
        *self = staged;
        Ok(result)
    }

    fn replayed_recovery(
        &self,
        observation: &RecoveryObservationV1<'_>,
    ) -> Result<Option<RecoveryResultV1>, AdmissionError> {
        let physical = &observation.physical_custody;
        let (
            operation,
            outcome,
            artifact_digest,
            catalog_digest,
            repair_prior_generation,
            executor_instance,
            fence_digest,
            disposition,
        ) = match &observation.kind {
            RecoveryObservationKindV1::NoEffect(operation) => (
                *operation,
                super::RecoveryObservationKindCodeV1::NoEffect,
                None,
                None,
                0,
                None,
                None,
                RecoveryDispositionV1::NoWork,
            ),
            RecoveryObservationKindV1::ExactPrivateArtifact {
                operation,
                artifact_digest,
            } => (
                *operation,
                super::RecoveryObservationKindCodeV1::PrivateArtifact,
                Some(*artifact_digest),
                None,
                0,
                None,
                None,
                RecoveryDispositionV1::ObserveOnly,
            ),
            RecoveryObservationKindV1::ExactAbsentAfterFence {
                operation,
                artifact_digest,
                executor_fence,
            } => (
                *operation,
                super::RecoveryObservationKindCodeV1::AbsentAfterFence,
                Some(*artifact_digest),
                None,
                0,
                Some(executor_fence.publisher_instance),
                Some(executor_fence.digest()),
                RecoveryDispositionV1::NoWork,
            ),
            RecoveryObservationKindV1::FinalOnlyCatalogAbsent {
                operation,
                artifact_digest,
                executor_fence,
                intended_entry,
            } => (
                *operation,
                super::RecoveryObservationKindCodeV1::FinalCatalogAbsent,
                Some(*artifact_digest),
                Some(intended_entry.digest()),
                self.recovery_observations()
                    .find(|receipt| {
                        receipt.outcome == super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
                            && receipt.operation == *operation
                            && receipt.artifact_digest == Some(*artifact_digest)
                            && receipt.catalog_entry_digest == Some(intended_entry.digest())
                            && receipt.physical_root_digest == physical.root_record_digest()
                            && receipt.physical_observation_digest == physical.observation_digest
                            && receipt.executor_instance == Some(executor_fence.publisher_instance)
                            && receipt.executor_fence_digest == Some(executor_fence.digest())
                    })
                    .map_or(self.latest_catalog_generation().unwrap_or(0), |receipt| {
                        receipt.repair_prior_catalog_generation
                    }),
                Some(executor_fence.publisher_instance),
                Some(executor_fence.digest()),
                RecoveryDispositionV1::Quarantine,
            ),
            RecoveryObservationKindV1::ExactCommitted(result) => {
                let operation = result.operation();
                let artifact = self
                    .artifact(operation)
                    .ok_or(AdmissionError::ArtifactMismatch)?;
                (
                    operation,
                    super::RecoveryObservationKindCodeV1::Committed,
                    Some(artifact.artifact_digest),
                    Some(result.catalog_entry_digest()),
                    0,
                    None,
                    None,
                    RecoveryDispositionV1::NoWork,
                )
            }
            RecoveryObservationKindV1::Contradiction { operation, .. } => (
                *operation,
                super::RecoveryObservationKindCodeV1::Contradiction,
                physical.artifact_digest,
                None,
                0,
                None,
                None,
                RecoveryDispositionV1::Poisoned,
            ),
        };
        let repair_authorization_digest = None;
        let receipt = recovery_receipt(
            operation,
            outcome,
            artifact_digest,
            catalog_digest,
            repair_prior_generation,
            repair_authorization_digest,
            physical.root_record_digest(),
            physical.observation_digest,
            executor_instance,
            fence_digest,
        );
        Ok(self
            .has_recovery_observation(&receipt)
            .then_some(RecoveryResultV1 {
                operation,
                disposition,
                mutations: Vec::new(),
            }))
    }

    fn recover_in_place(
        &mut self,
        observation: RecoveryObservationV1<'_>,
    ) -> Result<RecoveryResultV1, AdmissionError> {
        let physical_digest = observation.physical_custody.observation_digest;
        let physical_root_digest = observation.physical_custody.root_record_digest();
        let physical_artifact_digest = observation.physical_custody.artifact_digest;
        validate_physical_custody(self, &observation)?;
        match observation.kind {
            RecoveryObservationKindV1::NoEffect(operation) => {
                let decision = self
                    .decision(operation)
                    .ok_or(AdmissionError::OperationAbsent)?;
                if !matches!(
                    decision.state,
                    AdmissionDecisionStateV1::Admitted
                        | AdmissionDecisionStateV1::RevocationPending
                ) {
                    return Err(AdmissionError::InvalidTransition);
                }
                let receipt = recovery_receipt(
                    operation,
                    super::RecoveryObservationKindCodeV1::NoEffect,
                    None,
                    None,
                    0,
                    None,
                    physical_root_digest,
                    physical_digest,
                    None,
                    None,
                );
                let mut mutations: Vec<_> = self
                    .record_recovery_observation(receipt)?
                    .into_iter()
                    .collect();
                mutations.extend(self.abort_before_effect(operation)?);
                Ok(RecoveryResultV1 {
                    operation,
                    disposition: RecoveryDispositionV1::NoWork,
                    mutations,
                })
            }
            RecoveryObservationKindV1::ExactPrivateArtifact {
                operation,
                artifact_digest,
            } => {
                if artifact_digest.as_bytes() == &[0; 32] {
                    return Err(AdmissionError::InvalidIdentity("recovery artifact"));
                }
                let decision = self
                    .decision(operation)
                    .ok_or(AdmissionError::OperationAbsent)?;
                if self
                    .artifact(operation)
                    .is_none_or(|artifact| artifact.artifact_digest != artifact_digest)
                {
                    return Err(AdmissionError::ArtifactMismatch);
                }
                if matches!(
                    decision.state,
                    AdmissionDecisionStateV1::Completed | AdmissionDecisionStateV1::Aborted
                ) {
                    return Err(AdmissionError::InvalidTransition);
                }
                let receipt = recovery_receipt(
                    operation,
                    super::RecoveryObservationKindCodeV1::PrivateArtifact,
                    Some(artifact_digest),
                    None,
                    0,
                    None,
                    physical_root_digest,
                    physical_digest,
                    None,
                    None,
                );
                let mut mutations: Vec<_> = self
                    .record_recovery_observation(receipt)?
                    .into_iter()
                    .collect();
                mutations.extend(self.mark_uncertain(operation)?);
                Ok(RecoveryResultV1 {
                    operation,
                    disposition: RecoveryDispositionV1::ObserveOnly,
                    mutations,
                })
            }
            RecoveryObservationKindV1::ExactAbsentAfterFence {
                operation,
                artifact_digest,
                executor_fence,
            } => {
                let artifact = self
                    .artifact(operation)
                    .ok_or(AdmissionError::ArtifactMismatch)?;
                validate_fenced_artifact(artifact, artifact_digest, &executor_fence)?;
                let receipt = recovery_receipt(
                    operation,
                    super::RecoveryObservationKindCodeV1::AbsentAfterFence,
                    Some(artifact_digest),
                    None,
                    0,
                    None,
                    physical_root_digest,
                    physical_digest,
                    Some(executor_fence.publisher_instance),
                    Some(executor_fence.digest()),
                );
                let mut mutations: Vec<_> = self
                    .record_recovery_observation(receipt)?
                    .into_iter()
                    .collect();
                mutations.extend(self.retire_permit_without_effect(operation, artifact_digest)?);
                Ok(RecoveryResultV1 {
                    operation,
                    disposition: RecoveryDispositionV1::NoWork,
                    mutations,
                })
            }
            RecoveryObservationKindV1::ExactCommitted(result) => {
                let operation = result.operation();
                let catalog_entry_digest = result.catalog_entry_digest();
                let artifact_digest = self
                    .artifact(operation)
                    .ok_or(AdmissionError::ArtifactMismatch)?
                    .artifact_digest;
                let receipt = recovery_receipt(
                    operation,
                    super::RecoveryObservationKindCodeV1::Committed,
                    Some(artifact_digest),
                    Some(catalog_entry_digest),
                    0,
                    None,
                    physical_root_digest,
                    physical_digest,
                    None,
                    None,
                );
                let mut mutations: Vec<_> = self
                    .record_recovery_observation(receipt)?
                    .into_iter()
                    .collect();
                mutations.extend(self.complete_in_place(result)?.1);
                Ok(RecoveryResultV1 {
                    operation,
                    disposition: RecoveryDispositionV1::NoWork,
                    mutations,
                })
            }
            RecoveryObservationKindV1::FinalOnlyCatalogAbsent {
                operation,
                artifact_digest,
                executor_fence,
                intended_entry,
            } => {
                let artifact = self
                    .artifact(operation)
                    .ok_or(AdmissionError::ArtifactMismatch)?;
                validate_fenced_artifact(artifact, artifact_digest, &executor_fence)?;
                self.validate_recovery_catalog_entry(operation, artifact_digest, &intended_entry)?;
                let prior_catalog_generation = self.latest_catalog_generation().unwrap_or(0);
                let receipt = recovery_receipt(
                    operation,
                    super::RecoveryObservationKindCodeV1::FinalCatalogAbsent,
                    Some(artifact_digest),
                    Some(intended_entry.digest()),
                    prior_catalog_generation,
                    None,
                    physical_root_digest,
                    physical_digest,
                    Some(executor_fence.publisher_instance),
                    Some(executor_fence.digest()),
                );
                let mut mutations: Vec<_> = self
                    .record_recovery_observation(receipt)?
                    .into_iter()
                    .collect();
                mutations.extend(self.mark_uncertain(operation)?);
                Ok(RecoveryResultV1 {
                    operation,
                    disposition: RecoveryDispositionV1::Quarantine,
                    mutations,
                })
            }
            RecoveryObservationKindV1::Contradiction {
                operation,
                evidence_digest,
            } => {
                self.decision(operation)
                    .ok_or(AdmissionError::OperationAbsent)?;
                let receipt = recovery_receipt(
                    operation,
                    super::RecoveryObservationKindCodeV1::Contradiction,
                    physical_artifact_digest,
                    None,
                    0,
                    None,
                    physical_root_digest,
                    physical_digest,
                    None,
                    None,
                );
                let observation_mutation = self.record_recovery_observation(receipt)?;
                let poison_mutation = self.poison(evidence_digest)?;
                let mut mutations: Vec<_> = observation_mutation.into_iter().collect();
                mutations.push(poison_mutation);
                Ok(RecoveryResultV1 {
                    operation,
                    disposition: RecoveryDispositionV1::Poisoned,
                    mutations,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_catalog_repair_in_place(
        &mut self,
        operation: OperationId,
        artifact_digest: ObjectDigest,
        executor_instance: aos_sandbox_core::PublisherInstanceId,
        executor_fence_digest: ObjectDigest,
        absent_receipt_digest: ObjectDigest,
        catalog: &super::CommittedCatalogObservation,
        physical: &RecoveryPhysicalCustodyV1<'_>,
    ) -> Result<RecoveryResultV1, AdmissionError> {
        validate_physical_facts(self, operation, Some(artifact_digest), physical)?;
        let absent = self
            .recovery_observations()
            .find(|receipt| receipt.receipt_digest == absent_receipt_digest)
            .ok_or(AdmissionError::CompletionMismatch)?;
        let catalog_entry_digest = catalog.catalog_entry_digest();
        if absent.outcome != super::RecoveryObservationKindCodeV1::FinalCatalogAbsent
            || absent.operation != operation
            || absent.artifact_digest != Some(artifact_digest)
            || absent.catalog_entry_digest != Some(catalog_entry_digest)
            || absent.executor_fence_digest != Some(executor_fence_digest)
            || absent.executor_instance != Some(executor_instance)
            || absent.repair_prior_catalog_generation != catalog.prior_generation()
            || self
                .artifact(operation)
                .is_none_or(|artifact| artifact.publisher_instance != executor_instance)
        {
            return Err(AdmissionError::CompletionMismatch);
        }
        let receipt = recovery_receipt(
            operation,
            super::RecoveryObservationKindCodeV1::FinalCatalogRepaired,
            Some(artifact_digest),
            Some(catalog_entry_digest),
            catalog.prior_generation(),
            Some(absent_receipt_digest),
            physical.root_record_digest(),
            physical.observation_digest,
            Some(executor_instance),
            Some(executor_fence_digest),
        );
        let observation_mutation = self.record_recovery_observation(receipt)?;
        let result = CompletionResult::from_recovery_observation(self, operation, catalog.clone())?;
        let mut mutations: Vec<_> = observation_mutation.into_iter().collect();
        mutations.extend(self.complete_in_place(result)?.1);
        Ok(RecoveryResultV1 {
            operation,
            disposition: RecoveryDispositionV1::NoWork,
            mutations,
        })
    }

    /// Derives the exact rollback-protected frontier to checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if outstanding-permit count exceeds the
    /// canonical `u32` field.
    pub fn checkpoint(&self) -> Result<AuthorityCheckpointV1, AdmissionError> {
        self.checkpoint_at(self.sequence())
    }

    pub(super) fn checkpoint_at(
        &self,
        sequence: u64,
    ) -> Result<AuthorityCheckpointV1, AdmissionError> {
        let outstanding_count = u32::try_from(self.outstanding_permit_count())
            .map_err(|_| AdmissionError::LimitExceeded("checkpoint permits"))?;
        let outstanding_values: Vec<Vec<u8>> = self
            .permits()
            .filter(|permit| {
                matches!(
                    permit.state,
                    CompletionPermitStateV1::Outstanding
                        | CompletionPermitStateV1::RevocationPending
                        | CompletionPermitStateV1::Uncertain
                )
            })
            .map(|permit| {
                let mut value = permit.permit_digest.as_bytes().to_vec();
                value.push(permit_state_code(permit.state));
                value
            })
            .collect();
        let outstanding_parts: Vec<&[u8]> = outstanding_values.iter().map(Vec::as_slice).collect();
        Ok(AuthorityCheckpointV1 {
            epoch: self.authority_epoch(),
            sequence,
            state_digest: self.projection_digest()?,
            outstanding_digest: digest_parts(OUTSTANDING_DOMAIN, &outstanding_parts),
            outstanding_count,
            poisoned: self.is_poisoned(),
        })
    }

    /// Appends the terminal checkpoint required by a durable transaction.
    ///
    /// The protected-store adapter includes this mutation in the same atomic
    /// commit as preceding mutations. Authority can escape only after the
    /// adapter passes the synchronized checkpoint and chain head back through
    /// [`Self::confirm_committed`].
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when a sequence or configured record/byte
    /// bound is exhausted or canonical encoding fails.
    pub(crate) fn seal_for_commit(
        &mut self,
    ) -> Result<(AuthorityCheckpointV1, LedgerMutation), AdmissionError> {
        let sequence = self
            .sequence()
            .checked_add(1)
            .ok_or(AdmissionError::GenerationExhausted)?;
        let checkpoint = self.checkpoint_at(sequence)?;
        let mutation = self.append_checkpoint(&checkpoint)?;
        Ok((checkpoint, mutation))
    }

    /// Advances to a protected failover epoch without discarding obligations.
    ///
    /// Every nonterminal operation becomes uncertain and remains charged. Old
    /// permits retain their original epoch and exact artifact/executor binding;
    /// this method does not reissue or broaden them.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when the committed frontier differs from the
    /// complete projection or an internally derived successor epoch or
    /// uncertainty transition cannot be durably represented.
    pub fn begin_failover(
        &mut self,
        committed: &super::CommittedAdmissionFrontier,
    ) -> Result<FailoverResultV1, AdmissionError> {
        self.require_committed(committed)?;
        let checkpoint = self.checkpoint()?;
        if checkpoint.poisoned {
            return Err(AdmissionError::AuthorityMismatch);
        }
        let next_epoch = checkpoint.epoch.checked_next()?;
        let operations: Vec<OperationId> = self
            .decisions()
            .filter(|decision| {
                !matches!(
                    decision.state,
                    AdmissionDecisionStateV1::Completed | AdmissionDecisionStateV1::Aborted
                )
            })
            .map(|decision| decision.operation)
            .collect();
        let mut staged = self.clone();
        let mut mutations = Vec::new();
        for operation in operations {
            mutations.extend(staged.mark_uncertain(operation)?);
        }
        staged.set_failover_epoch(next_epoch);
        let checkpoint_sequence = staged
            .sequence()
            .checked_add(1)
            .ok_or(AdmissionError::GenerationExhausted)?;
        let next_checkpoint = staged.checkpoint_at(checkpoint_sequence)?;
        mutations.push(staged.append_checkpoint(&next_checkpoint)?);
        *self = staged;
        Ok(FailoverResultV1 {
            checkpoint: next_checkpoint,
            mutations,
        })
    }
}

fn validate_physical_custody(
    ledger: &AdmissionLedger,
    observation: &RecoveryObservationV1<'_>,
) -> Result<(), AdmissionError> {
    let (operation, expected_artifact) = match &observation.kind {
        RecoveryObservationKindV1::NoEffect(operation) => (*operation, None),
        RecoveryObservationKindV1::ExactPrivateArtifact {
            operation,
            artifact_digest,
        }
        | RecoveryObservationKindV1::ExactAbsentAfterFence {
            operation,
            artifact_digest,
            ..
        }
        | RecoveryObservationKindV1::FinalOnlyCatalogAbsent {
            operation,
            artifact_digest,
            ..
        } => (*operation, Some(*artifact_digest)),
        RecoveryObservationKindV1::ExactCommitted(result) => {
            let operation = result.operation();
            let artifact = ledger
                .artifact(operation)
                .ok_or(AdmissionError::ArtifactMismatch)?;
            (operation, Some(artifact.artifact_digest))
        }
        RecoveryObservationKindV1::Contradiction { operation, .. } => {
            (*operation, observation.physical_custody.artifact_digest)
        }
    };
    validate_physical_facts(
        ledger,
        operation,
        expected_artifact,
        &observation.physical_custody,
    )
}

fn validate_physical_facts(
    ledger: &AdmissionLedger,
    operation: OperationId,
    expected_artifact: Option<ObjectDigest>,
    physical: &RecoveryPhysicalCustodyV1<'_>,
) -> Result<(), AdmissionError> {
    let decision = ledger
        .decision(operation)
        .ok_or(AdmissionError::OperationAbsent)?;
    if physical.root_record_digest() != decision.selected_root_digest
        || physical.root_record_digest().as_bytes() == &[0; 32]
        || physical.observation_digest.as_bytes() == &[0; 32]
        || physical.artifact_digest != expected_artifact
        || physical
            .artifact_digest
            .is_some_and(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(AdmissionError::CompletionMismatch);
    }
    Ok(())
}

fn catalog_repair_poison_digest(
    operation: OperationId,
    artifact_digest: ObjectDigest,
    absent_receipt_digest: ObjectDigest,
) -> ObjectDigest {
    digest_parts(
        b"aos.sandbox.publisher.catalog-repair-poison.v1\0",
        &[
            operation.as_bytes(),
            artifact_digest.as_bytes(),
            absent_receipt_digest.as_bytes(),
        ],
    )
}

fn validate_fenced_artifact(
    artifact: &super::ArtifactCommitmentV1,
    artifact_digest: ObjectDigest,
    fence: &RecoveryExecutorFenceV1,
) -> Result<(), AdmissionError> {
    if artifact.artifact_digest != artifact_digest
        || artifact.publisher_instance != fence.publisher_instance
        || fence.death_or_revocation_digest.as_bytes() == &[0; 32]
        || fence.recovery_incarnation.as_bytes() == &[0; 32]
    {
        return Err(AdmissionError::CompletionMismatch);
    }
    Ok(())
}

fn recovery_receipt(
    operation: OperationId,
    outcome: super::RecoveryObservationKindCodeV1,
    artifact_digest: Option<ObjectDigest>,
    catalog_entry_digest: Option<ObjectDigest>,
    repair_prior_catalog_generation: u64,
    repair_authorization_digest: Option<ObjectDigest>,
    physical_root_digest: ObjectDigest,
    physical_observation_digest: ObjectDigest,
    executor_instance: Option<aos_sandbox_core::PublisherInstanceId>,
    executor_fence_digest: Option<ObjectDigest>,
) -> super::RecoveryObservationReceiptV1 {
    let outcome_code = match outcome {
        super::RecoveryObservationKindCodeV1::NoEffect => 1,
        super::RecoveryObservationKindCodeV1::PrivateArtifact => 2,
        super::RecoveryObservationKindCodeV1::AbsentAfterFence => 3,
        super::RecoveryObservationKindCodeV1::FinalCatalogAbsent => 4,
        super::RecoveryObservationKindCodeV1::FinalCatalogRepaired => 5,
        super::RecoveryObservationKindCodeV1::Committed => 6,
        super::RecoveryObservationKindCodeV1::Contradiction => 7,
    };
    let artifact = artifact_digest.map_or([0; 32], |digest| *digest.as_bytes());
    let catalog_entry = catalog_entry_digest.map_or([0; 32], |digest| *digest.as_bytes());
    let fence = executor_fence_digest.map_or([0; 32], |digest| *digest.as_bytes());
    let executor = executor_instance.map_or([0; 16], |instance| *instance.as_bytes());
    let repair = repair_authorization_digest.map_or([0; 32], |digest| *digest.as_bytes());
    let receipt_digest = digest_parts(
        RECOVERY_DOMAIN,
        &[
            operation.as_bytes(),
            &[outcome_code],
            &artifact,
            &catalog_entry,
            &repair_prior_catalog_generation.to_be_bytes(),
            &repair,
            physical_root_digest.as_bytes(),
            physical_observation_digest.as_bytes(),
            &executor,
            &fence,
        ],
    );
    super::RecoveryObservationReceiptV1 {
        operation,
        outcome,
        artifact_digest,
        catalog_entry_digest,
        repair_prior_catalog_generation,
        repair_authorization_digest,
        physical_root_digest,
        physical_observation_digest,
        executor_instance,
        executor_fence_digest,
        receipt_digest,
    }
}

fn permit_state_code(state: CompletionPermitStateV1) -> u8 {
    match state {
        CompletionPermitStateV1::Outstanding => 1,
        CompletionPermitStateV1::RevocationPending => 2,
        CompletionPermitStateV1::Spent => 3,
        CompletionPermitStateV1::RetiredWithoutEffect => 4,
        CompletionPermitStateV1::Uncertain => 5,
    }
}
