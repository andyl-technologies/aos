//! Retains one private publication action across the actual Reconciler call.
//!
//! The installed issuer constructs this owner only from its genuine admitted
//! Root/C continuation. The existing Reconciler performs atomic admission and
//! activation after the executor borrow ends; no second Journal or duplicated
//! validator is introduced. Every whole native return stays on this owner.

mod completed_child;
pub(crate) use completed_child::CompletedPublicationChildDataV1;

use std::error::Error;
use std::sync::Arc;
use sha2::{Digest as _, Sha256};

use crate::controller_resource_reservation::CreateStorageCompletedIntakeOriginalV1;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::Journal;

use aos_sandbox_model::{OperationId, ResourceDimension, ResourceVector};
use aos_sandbox_protocol::domain_ledger::provisioning_resources::{
    ProvisioningModeDataV1, ProvisioningResourceRecordsV1,
};
use crate::publication::{AuthorityPublicationActivationV1, AuthorityPublicationStore};
use crate::reconciler::{AcceptOutcome, OwnershipGateActivationOutcome, ReconcileOutcome};
use crate::{AuthorityPublicationDraftV1, AuthorityPublicationError, OperationPlan,
    PreparedAuthorityPublicationV1, Reconciler, ReconcilerError, SingleNodeEffectExecutor};

#[derive(Clone, Copy)]
enum First {
    CoreEntry,
    NativeAfter,
    RootAfter,
    Admission,
    ActivationPreparation,
    Activation,
    Reconciliation,
    ChildCapture,
    Closed,
}

/// Selects one existing Core engine phase for passive geometry only.
#[derive(Clone, Copy)]
pub(crate) enum PublicationActionPhaseV1 {
    Admission,
    Activation,
    ChildTransition,
}

/// Reports a closed action while its complete native causes remain retained.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("the original provisioning publication action is closed")]
pub struct OriginalPublicationActionClosedV1;

/// Shares only the same immutable admission inputs with the private Core scope.
///
/// This type has no public constructor and contains no Native owner or mutable
/// account. Its allocation and Arc header are charged before the issuer builds it.
pub(crate) struct PublicationActionContractV1 {
    plan: OperationPlan,
    draft: AuthorityPublicationDraftV1,
    prepared: PreparedAuthorityPublicationV1,
    records: ProvisioningResourceRecordsV1,
}

impl PublicationActionContractV1 {
    pub(crate) const fn plan_v1(&self) -> &OperationPlan { &self.plan }
    pub(crate) const fn draft_v1(&self) -> &AuthorityPublicationDraftV1 { &self.draft }
    pub(crate) const fn prepared_v1(&self) -> &PreparedAuthorityPublicationV1 { &self.prepared }
    pub(crate) const fn records_v1(&self) -> ProvisioningResourceRecordsV1 { self.records }

    // The same actual Arc survives independently owed Root-after, so its
    // immutable typed plan remains the comparison source without an Action loan.
    pub(crate) fn storage_apply_plan_expires_seconds_v1(&self)
        -> Result<i64, ResourceReservationErrorV1> {
        let [template] = self.draft.templates() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        if template.method()
            != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(template.plan().expires_seconds())
    }
}

/// Owns an exact private child admission and its atomic publication activation.
///
/// There is deliberately no public constructor or mutable plan projection.
/// Only the actual Native issuer can mint this after its same accepted parent,
/// separately admitted Root recipe, verified lease and funded same-C borrower
/// agree. Possessing historical plan or lease bytes cannot construct it.
#[doc(hidden)]
#[must_use = "return this exact action to its installed issuer on every outcome"]
pub struct OriginalPublicationActionV1 {
    parent: OperationId,
    root_admission: [u8; 32],
    contract: Arc<PublicationActionContractV1>,
    admission: Option<Result<AcceptOutcome, ReconcilerError>>,
    activation_preparation: Option<Result<AuthorityPublicationActivationV1, AuthorityPublicationError>>,
    activation: Option<Result<OwnershipGateActivationOutcome, ReconcilerError>>,
    reconciliation: Option<Result<ReconcileOutcome, ReconcilerError>>,
    completed_effect: Option<Result<Vec<u8>, ReconcilerError>>,
    core_entry_failure: Option<ResourceReservationErrorV1>,
    core_native_after_failure: Option<ResourceReservationErrorV1>,
    core_root_after_failure: Option<crate::normal_root::RootStorageApplyClientClosedV1>,
    core_entry_original_selected: bool,
    core_entry_root_selected: bool,
    first: Option<First>,
    closed: Option<OriginalPublicationActionClosedV1>,
    entered: bool,
    complete: bool,
}

/// Keeps every issued input if its exact immutable cross-links refuse.
///
/// The actual issuer stores this whole return; no fallible constructor can
/// dispose a verified lease, signed template or admitted plan on its behalf.
pub(super) struct OriginalPublicationActionConstructionFailureV1 {
    _parent: OperationId,
    _plan: OperationPlan,
    _draft: AuthorityPublicationDraftV1,
    _prepared: PreparedAuthorityPublicationV1,
    _records: ProvisioningResourceRecordsV1,
    cause: OriginalPublicationActionClosedV1,
    resources: Option<ResourceReservationErrorV1>,
    root: Option<IssuedRootComparisonErrorV1>,
}

#[derive(Debug, thiserror::Error)]
enum IssuedRootComparisonErrorV1 {
    #[error(transparent)]
    Original(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Native(#[from] crate::normal_root::RootStorageApplyClientClosedV1),
    #[error(transparent)]
    Wire(#[from] aos_sandbox_protocol::domain_ledger::provisioning_root::storage_apply::ApplyRootDataErrorV1),
    #[error(transparent)]
    Context(#[from] aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError),
    #[error(transparent)]
    Publication(#[from] aos_sandbox_protocol::publication::PublicationHistoryError),
    #[error("the issued publication differs from its actual Root admission")]
    Mismatch,
}

impl std::fmt::Debug for OriginalPublicationActionConstructionFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OriginalPublicationActionConstructionFailureV1")
            .field("cause", &self.cause).finish_non_exhaustive()
    }
}

impl std::fmt::Display for OriginalPublicationActionConstructionFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, formatter)
    }
}

impl Error for OriginalPublicationActionConstructionFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.root.as_ref().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.resources.as_ref().map(|cause| cause as &(dyn Error + 'static)))
            .or(Some(&self.cause))
    }
}

impl OriginalPublicationActionV1 {
    // This constructor remains private to the issuer module. It is not a plan,
    // signed-lease or caller-ID adopter on any role-facing API.
    pub(super) fn from_issued_plan_v1(
        completed: &CreateStorageCompletedIntakeOriginalV1<'_>,
        controller: &Journal,
        root: &crate::normal_root::RootStorageApplyAdmissionOriginalV1<'_>,
        construction: &crate::normal_root::RootStorageApplyConstructionTurnV1<'_>,
        plan: OperationPlan,
        draft: AuthorityPublicationDraftV1,
        prepared: PreparedAuthorityPublicationV1,
        records: ProvisioningResourceRecordsV1,
    ) -> Result<Self, OriginalPublicationActionConstructionFailureV1> {
        let parent = completed.operation_v1();
        let fields = records.fields_v1();
        let manifest = draft.manifest();
        if fields.mode != ProvisioningModeDataV1::CreateStopped
            || fields.parent != parent || fields.publication_operation != plan.operation_id()
            || fields.manifest != manifest.digest()
            || fields.sandbox != manifest.manifest().sandbox()
            || fields.project != manifest.manifest().project()
            || fields.epoch != manifest.manifest().epoch()
            || fields.source_draft != draft.digest()
            || prepared.source_draft_digest() != draft.digest()
        {
            return Err(OriginalPublicationActionConstructionFailureV1 {
                _parent: parent, _plan: plan, _draft: draft, _prepared: prepared,
                _records: records, cause: OriginalPublicationActionClosedV1, resources: None, root: None,
            });
        }
        // The genuine Native lender cannot be constructed from reply bytes.
        // Keep the full owned inputs on any comparison refusal; the same client
        // retains its socket, native originals and verified lease separately.
        let admitted = (|| -> Result<[u8; 32], IssuedRootComparisonErrorV1> {
            use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;
            use aos_sandbox_protocol::domain_ledger::provisioning_resources::
                provisioning_public_request_digest_v1;

            // Opening a historical admission does not extend its authority.
            // This token comes from the same client after its actual native
            // construction before and the final clock after key preparation.
            construction.require_admission_v1(root)?;
            let now = construction.actual_before_clock_v1()?;
            let (origin, _) = root.original_horizon_v1();
            if now.host_boot_id() != origin.host_boot_id()
                || now.provenance() != origin.provenance()
                || now.boottime_nanoseconds() < origin.boottime_nanoseconds()
                || now.boottime_nanoseconds() >= construction.cutoff_v1()
                || construction.cutoff_v1() != root.cutoff_v1()?
            {
                return Err(IssuedRootComparisonErrorV1::Mismatch);
            }

            if root.parent_operation_v1() != parent
                || root.original_horizon_v1() != completed.original_horizon_v1()?
            {
                return Err(IssuedRootComparisonErrorV1::Mismatch);
            }
            let (_, original_cutoff) = root.original_horizon_v1();
            let cutoff = root.cutoff_v1()?;
            if cutoff == 0 || cutoff > original_cutoff {
                return Err(IssuedRootComparisonErrorV1::Mismatch);
            }
            {
                let context = PublicMutationEffectHistoryV1::decode(completed.accepted_context_v1()?)?
                    .ok_or(IssuedRootComparisonErrorV1::Mismatch)?;
                if context.project() != fields.project
                    || provisioning_public_request_digest_v1(context.canonical_request()) != fields.public_request
                    || !matches!(context.validated_request()?,
                        aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Create(_))
                {
                    return Err(IssuedRootComparisonErrorV1::Mismatch);
                }
            }
            let reply = root.reply_v1()?;
            let mut matching = draft.templates().iter().filter(|template|
                template.method() == aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                    && template.canonical_plan() == reply.canonical_plan);
            if matching.next().is_none() || matching.next().is_some()
                || aos_sandbox_model::ObjectDigest::from_bytes(Sha256::digest(reply.canonical_plan).into())
                    != fields.root_plan
                || prepared.lease_generation() != root.lease_v1().generation()
                || prepared.lease_digest() != root.lease_v1().digest()
            {
                return Err(IssuedRootComparisonErrorV1::Mismatch);
            }
            // Reuse the sole full publication decoder and exact preimage
            // comparison. This validates no new signature or live authority.
            aos_sandbox_protocol::publication::validate_historical_output_publication_v1(
                prepared.canonical_bytes(), prepared.digest(), Some((
                    root.lease_v1().canonical_lease(), root.lease_v1().canonical_signature(),
                )),
            )?;
            Ok(reply.digest_v1()?)
        })();
        let root_admission = match admitted {
            Ok(commitment) => commitment,
            Err(root) => return Err(OriginalPublicationActionConstructionFailureV1 {
                _parent: parent, _plan: plan, _draft: draft, _prepared: prepared,
                _records: records, cause: OriginalPublicationActionClosedV1,
                resources: None, root: Some(root),
            }),
        };
        let resources = (|| -> Result<(), ResourceReservationErrorV1> {
            use aos_sandbox_protocol::domain_ledger::resource_bank::{
                AccountHead, AccountKind, Claim, ClaimPurpose, ClaimState,
            };

            // This closed borrower repeats the actual original bank/coissuance
            // relation against the SAME held C, rather than accepting digests.
            let (child_bytes, grant_bytes) = completed.resource_members_v1(controller)?;
            let child = AccountHead::decode(child_bytes)?;
            let grant = Claim::decode(grant_bytes)?;
            let head = child.native_fields();
            let claim = grant.native_fields();
            if head.kind != AccountKind::Sandbox
                || head.id != fields.sandbox.into_bytes()
                || head.project != fields.project.into_bytes()
                || claim.purpose != ClaimPurpose::InclusiveGrant
                || claim.state != ClaimState::Reserved
                || grant.operation() != parent.into_bytes()
                || head.enrollment != claim.enrollment
                || child.finite_ceilings()? != claim.amount
                || aos_sandbox_model::ObjectDigest::from_bytes(Sha256::digest(child_bytes).into())
                    != fields.child_head
                || aos_sandbox_model::ObjectDigest::from_bytes(Sha256::digest(grant_bytes).into())
                    != fields.inclusive_grant
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            child.finite_ceilings()?.checked_sub(manifest.manifest().reservations())?;
            Ok(())
        })();
        if let Err(resources) = resources {
            return Err(OriginalPublicationActionConstructionFailureV1 {
                _parent: parent, _plan: plan, _draft: draft, _prepared: prepared,
                _records: records, cause: OriginalPublicationActionClosedV1,
                resources: Some(resources), root: None,
            });
        }
        Ok(Self { parent, root_admission,
            contract: Arc::new(PublicationActionContractV1 { plan, draft, prepared, records }),
            admission: None, activation_preparation: None, activation: None,
            reconciliation: None, completed_effect: None, core_entry_failure: None,
            core_native_after_failure: None, core_root_after_failure: None, core_entry_original_selected: false, core_entry_root_selected: false, first: None, closed: None,
            entered: false, complete: false })
    }

    // Only the existing Core admission/publication engines use this immutable
    // contract to compare every proposed row. It exports no native writer or
    // constructor and cannot make unrelated Journal commits eligible.
    pub(crate) const fn contract_v1(&self) -> &Arc<PublicationActionContractV1> {
        &self.contract
    }

    /// Returns the real accepted public parent retained by this private issuer.
    #[must_use]
    pub const fn parent_operation_v1(&self) -> OperationId { self.parent }

    // Every later Core phase must match the SAME live client-owned Root turn
    // and contract identity; this immutable digest alone grants no phase entry.
    pub(crate) const fn root_admission_commitment_v1(&self) -> [u8; 32] {
        self.root_admission
    }

    /// Returns the distinct child operation used by the real atomic gate.
    #[must_use]
    pub fn publication_operation_v1(&self) -> OperationId { self.contract.plan.operation_id() }

    /// Prices the actual fixed action and its returned construction destination.
    ///
    /// Dynamic plans, templates, lease/statement bytes, complete journal models,
    /// native IO and independently owed posts require their own actual bounds.
    /// This no-allocation DATA supplier creates no receiving permission.
    #[must_use]
    pub fn fixed_receiving_demand_v1() -> Option<ResourceVector> {
        let contract = std::mem::size_of::<PublicationActionContractV1>()
            .checked_add(std::mem::size_of::<usize>().checked_mul(2)?)?
            .checked_add(std::mem::align_of::<PublicationActionContractV1>().checked_mul(2)?)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(contract.checked_mul(2)?)?
            .checked_add(std::mem::size_of::<OriginalPublicationActionConstructionFailureV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<CompletedPublicationChildDataV1<'static>>().checked_mul(2)?)?;
        Some(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes,
            u64::try_from(bytes).ok()?))
    }

    // The private Core scope records a refusal before it invokes any ordinary
    // admission engine. The whole first cause remains ahead of the owed native
    // finish; subsequent refusals cannot overwrite an earlier action failure.
    pub(crate) fn retain_core_entry_failure_v1(
        &mut self,
        cause: ResourceReservationErrorV1,
    ) {
        if self.core_entry_failure.is_none() {
            self.core_entry_failure = Some(cause);
        }
        self.first.get_or_insert(First::CoreEntry);
    }

    // Only a caller which actually invoked the same original's demand check
    // and observed its permanent cause may select that original's projection.
    pub(crate) fn retain_core_entry_original_failure_v1(
        &mut self,
        cause: ResourceReservationErrorV1,
    ) {
        if self.first.is_none() {
            self.core_entry_original_selected = true;
        }
        self.retain_core_entry_failure_v1(cause);
    }

    // Only the actual live Root-currentness gate selects its original. Later
    // Root-after failures cannot override an earlier pure or Action failure.
    pub(crate) fn retain_core_entry_root_failure_v1(
        &mut self,
        cause: ResourceReservationErrorV1,
    ) {
        if self.first.is_none() {
            self.core_entry_root_selected = true;
        }
        self.retain_core_entry_failure_v1(cause);
    }

    /// Identifies the exact invoked Root entry as this action's first cause.
    ///
    /// The installed issuer borrows the same retained client error only when
    /// this marker is selected. It conveys no entry permission or healthy reset.
    #[doc(hidden)]
    #[must_use]
    pub fn core_entry_root_failure_is_selected_v1(&self) -> bool {
        self.core_entry_root_selected && matches!(self.first, Some(First::CoreEntry))
    }

    // The canonical Core wrapper records this actual frontier before it runs
    // the independently owed Root-after. Earlier semantic/entry errors stay first.
    pub(crate) fn retain_core_native_after_failure_v1(&mut self,
        cause: ResourceReservationErrorV1,
    ) {
        self.core_native_after_failure.get_or_insert(cause);
        self.first.get_or_insert(First::NativeAfter);
    }

    pub(crate) fn retain_core_root_after_failure_v1(&mut self,
        cause: crate::normal_root::RootStorageApplyClientClosedV1,
    ) {
        self.core_root_after_failure.get_or_insert(cause);
        self.first.get_or_insert(First::RootAfter);
    }

    /// Selects the same retained C23 cause at the actual earlier native post.
    ///
    /// This diagnostic marker grants no new native turn or healthy retry.
    #[doc(hidden)]
    #[must_use]
    pub fn core_native_after_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::NativeAfter))
    }

    /// Selects the same retained Root cause only after all earlier work passed.
    ///
    /// This diagnostic marker cannot override an earlier C23 post failure.
    #[doc(hidden)]
    #[must_use]
    pub fn core_root_after_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::RootAfter))
    }

    /// Returns the retained Action and immutable contract's resident demand.
    ///
    /// This excludes future Core transaction rows and traffic. It creates no
    /// payment, native interval, semantic permission or resource capacity.
    ///
    /// # Errors
    /// Refuses checked size arithmetic or the canonical model's size bound.
    #[doc(hidden)]
    pub fn resident_receiving_demand_v1(
        &self,
        _journal: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let fixed = Self::fixed_receiving_demand_v1()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let resident = self.contract.plan.provisioning_resident_receiving_demand_v1(
            &self.contract.draft, &self.contract.prepared,
        )?;
        let retained = self.completed_effect.as_ref().and_then(|value| value.as_ref().ok())
            .map_or(0, Vec::len);
        let retained = u64::try_from(retained).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(fixed.checked_add(resident)?.checked_add(ResourceVector::ZERO
            .with(ResourceDimension::MemoryBytes, retained))?)
    }

    pub(crate) fn dynamic_complete_receiving_demand_v1(
        &self,
        journal: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let phase = if self.admission.is_none() {
            PublicationActionPhaseV1::Admission
        } else if self.activation.is_none() {
            PublicationActionPhaseV1::Activation
        } else {
            PublicationActionPhaseV1::ChildTransition
        };
        let resident = self.resident_receiving_demand_v1(journal)?;
        let phase = self.contract.plan.provisioning_phase_increment_receiving_demand_v1(
            journal, &self.contract.draft, &self.contract.prepared, phase,
        )?;
        Ok(resident.checked_add(phase)?)
    }

    /// Borrows the exact admitted typed Apply plan's expiry for live windows.
    ///
    /// This reads the same immutable constructor-validated template. It parses
    /// no bytes and cannot supply a plan, lease or native/temporal permission.
    pub(crate) fn storage_apply_plan_expires_seconds_v1(&self)
        -> Result<i64, ResourceReservationErrorV1> {
        self.contract.storage_apply_plan_expires_seconds_v1()
    }

    /// Reports whether the retained positive phase needs a fresh native turn.
    ///
    /// This passive scheduling hint grants no receiving or commit permission.
    /// The actual issuer must call the same receiver's genuine next-turn method.
    #[doc(hidden)]
    #[must_use]
    pub fn requires_next_native_turn_v1(&self) -> bool {
        self.entered && self.failure().is_none() && !self.complete
            && (self.activation.is_none()
                || self.contract.records.fields_v1().mode == ProvisioningModeDataV1::CreateStopped)
    }

    /// Runs the existing admission and activation engine exactly once.
    ///
    /// The caller moves the same action out of the executor's retained slot,
    /// invokes this while that borrow is released, and returns the whole owner
    /// before finishing its already-armed independent posts. This method does
    /// not complete the parent, a Storage effect, or a native continuation.
    ///
    /// # Errors
    /// Retains the precise original admission, publication or activation error.
    /// Reentry closes the action without replacing results or issuing IO.
    pub(crate) fn advance_core_once_v1<E: SingleNodeEffectExecutor>(
        &mut self,
        reconciler: &mut Reconciler<E>,
    ) -> Result<(), OriginalPublicationActionClosedV1> {
        if self.entered || self.first.is_some() {
            self.closed.get_or_insert(OriginalPublicationActionClosedV1);
            self.first.get_or_insert(First::Closed);
            return Err(OriginalPublicationActionClosedV1);
        }
        self.entered = true;
        if self.admission.is_none() {
            self.admission = Some(reconciler.accept(&self.contract.plan));
            if !matches!(self.admission, Some(Ok(_))) {
                self.first = Some(First::Admission);
                return Err(OriginalPublicationActionClosedV1);
            }
            return Ok(());
        }

        if self.activation.is_none() {
            self.activation_preparation = Some(AuthorityPublicationStore::new(
                reconciler.journal_mut(),
            ).prepare_gate_activation(&self.contract.draft, &self.contract.prepared));
            let activation = match self.activation_preparation.take() {
                Some(Ok(activation)) => activation,
                refused => {
                    // Preserve the actual failed preparation rather than
                    // replacing its owned lease or source-bearing error.
                    self.activation_preparation = refused;
                    return self.close_v1(First::ActivationPreparation);
                }
            };
            self.activation = Some(reconciler.activate_ownership_gate(
                self.contract.plan.operation_id(), activation,
            ));
            if !matches!(self.activation, Some(Ok(_))) {
                return self.close_v1(First::Activation);
            }
            return Ok(());
        }

        if self.contract.records.fields_v1().mode == ProvisioningModeDataV1::StartRunning {
            // Start's existing lifecycle Guardian/Host engine is the sole
            // dispatcher. Its actual validated outcome settles this child later.
            return Ok(());
        }
        self.reconciliation = Some(reconciler.reconcile_once(self.contract.plan.operation_id()));
        match self.reconciliation.as_ref() {
            Some(Ok(ReconcileOutcome::Succeeded)) => {
                // The canonical Core engine has completed and validated this
                // exact child. Capture its actual held bytes before the same
                // native original is handed back and its owed posts run.
                let key = aos_sandbox_protocol::domain_ledger::operation::effect_key(
                    self.contract.plan.operation_id(), 0,
                );
                self.completed_effect = Some(reconciler.journal_mut()
                    .get(crate::RecordNamespace::Effect, &key)
                    .map(<[u8]>::to_vec)
                    .ok_or(ReconcilerError::CorruptLedger(
                        "the succeeded provisioning child Effect is missing",
                    )));
                if !matches!(self.completed_effect, Some(Ok(_))) {
                    return self.close_v1(First::ChildCapture);
                }
                self.complete = true;
            }
            Some(Ok(ReconcileOutcome::Progressed | ReconcileOutcome::EffectApplied
                | ReconcileOutcome::RetryPending)) => {}
            Some(Ok(_)) => return self.close_v1(First::Closed),
            _ => return self.close_v1(First::Reconciliation),
        }

        Ok(())
    }

    /// Reports the stored actual activation independently of effect completion.
    #[must_use]
    pub fn publication_activated_v1(&self) -> bool {
        matches!(self.activation, Some(Ok(_))) && self.failure().is_none()
    }

    /// Returns the actual child turn outcome without interpreting activation as Apply.
    #[must_use]
    pub fn reconciliation_outcome_v1(&self) -> Option<ReconcileOutcome> {
        self.reconciliation.as_ref()?.as_ref().ok().copied()
    }

    /// Reports only actual durable child success, before outer semantic readiness.
    #[must_use]
    pub fn child_succeeded_v1(&self) -> bool {
        self.complete && self.failure().is_none()
    }

    // The closed Core handback invokes this only after it returned the SAME
    // receiver and the actual native finish plus every upper post succeeded.
    // This is not a public retry switch or a native/semantic success grant.
    pub(crate) fn begin_next_after_native_posts_v1(&mut self)
        -> Result<(), OriginalPublicationActionClosedV1>
    {
        if !self.requires_next_native_turn_v1() {
            return self.close_v1(First::Closed);
        }
        drop(self.reconciliation.take());
        self.entered = false;
        Ok(())
    }

    fn close_v1(&mut self, first: First) -> Result<(), OriginalPublicationActionClosedV1> {
        self.first.get_or_insert(first);
        self.closed.get_or_insert(OriginalPublicationActionClosedV1);
        Err(OriginalPublicationActionClosedV1)
    }

    /// Reports only a reached Core-entry demand refusal on the actual original.
    ///
    /// The installed issuer uses its own retained receiver to borrow that cause;
    /// this marker cannot grant a native turn or select another owner's error.
    #[doc(hidden)]
    #[must_use]
    pub fn core_entry_original_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::CoreEntry)) && self.core_entry_original_selected
    }

    // The issuer/Core renderer passes the same returned owner. Only the
    // reached native-demand marker selects its permanent cause; a later owed
    // native failure cannot shadow an earlier pure or semantic action error.
    pub(crate) fn failure_with_original_v1<'a>(
        &'a self,
        original: Option<&'a crate::CreateProvisioningOriginalsV1>,
    ) -> Option<&'a (dyn Error + 'static)> {
        if self.core_native_after_failure_is_selected_v1()
            || (matches!(self.first, Some(First::CoreEntry)) && self.core_entry_original_selected) {
            original.and_then(|original| original.failure()).or_else(|| self.failure())
        } else {
            self.failure()
        }
    }

    /// Borrows the first stored original without observing, copying or retrying.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::CoreEntry => self.core_entry_failure.as_ref().map(|cause| cause as _),
            First::NativeAfter => self.core_native_after_failure.as_ref().map(|cause| cause as _),
            First::RootAfter => self.core_root_after_failure.as_ref().map(|cause| cause as _),
            First::Admission => self.admission.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::ActivationPreparation => self.activation_preparation.as_ref()?.as_ref().err()
                .map(|cause| cause as _),
            First::Activation => self.activation.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Reconciliation => self.reconciliation.as_ref()?.as_ref().err()
                .map(|cause| cause as _),
            First::ChildCapture => self.completed_effect.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}
