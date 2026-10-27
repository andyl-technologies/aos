//! Returns the same scoped C23 original around one exact Storage IO crossing.
//!
//! The owned handoff solves the Journal/receiver borrow without a second payer.
//! The Journal scope stays installed and denies all append while its original
//! is away. Only its same immutable contract and native ordinal can return it.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_protocol::domain_ledger::effect_history::EffectState;

/// Retains a refused exact scope, representation or durable attempt comparison.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum CreateProvisioningStorageIoErrorV1 {
    /// The same original refused association or its full receiving requirement.
    #[error(transparent)]
    Resource(#[from] ResourceReservationErrorV1),
    /// The existing canonical Effect/dispatch validator refused supplied state.
    #[error(transparent)]
    Reconciler(#[from] ReconcilerError),
    /// The sole canonical Effect decoder retained its actual source error.
    #[error(transparent)]
    EffectHistory(#[from] aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError),
    /// The original is missing, already borrowed, returned or substituted.
    #[error("the original provisioning Storage IO crossing is closed")]
    Closed,
}

/// Owns the same C23 original outside the mutably borrowed Controller Journal.
///
/// Its private constructor requires the actual scoped child and durable Apply.
/// The caller returns this same owner before Core writes another child row.
#[doc(hidden)]
#[must_use = "return the same original to its exact Journal scope on every outcome"]
pub struct CreateProvisioningStorageIoOriginalV1 {
    original: Option<CreateProvisioningOriginalsV1>,
    contract: Arc<PublicationActionContractV1>,
    operation: OperationId,
    step: u32,
    native_turn: u64,
    complete: ResourceVector,
    association: Option<Result<(), CreateProvisioningStorageIoErrorV1>>,
    borrowed: bool,
    returned: Option<Result<(), CreateProvisioningStorageIoErrorV1>>,
    reentry: Option<CreateProvisioningStorageIoErrorV1>,
}

/// Borrows an exact current child Apply under its genuine moved C23 original.
///
/// Security may use only the finite actual Apply/Inventory stages implemented
/// on this opaque loan. It has no public constructor, raw payer or account.
#[doc(hidden)]
pub struct CreateProvisioningStorageIoLoanV1<'loan> {
    original: &'loan mut CreateProvisioningOriginalsV1,
    controller: &'loan Journal,
    contract: &'loan Arc<PublicationActionContractV1>,
    operation: OperationId,
    step: u32,
    native_turn: u64,
    complete: ResourceVector,
}

impl CreateProvisioningStorageIoOriginalV1 {
    fn receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let loan_bytes = std::mem::size_of::<CreateProvisioningStorageIoLoanV1<'static>>()
            .checked_mul(2)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(loan_bytes))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
    }

    /// Borrows the actual original once for this exact persisted Apply.
    ///
    /// # Errors
    /// Retains reentry and refuses another contract, native turn or durable
    /// dispatch. No failed borrower can be replaced by a fresh native scope.
    #[doc(hidden)]
    pub fn borrow_once_v1<'loan>(
        &'loan mut self,
        controller: &'loan Journal,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<CreateProvisioningStorageIoLoanV1<'loan>, CreateProvisioningStorageIoErrorV1> {
        if self.borrowed || self.returned.is_some() || self.reentry.is_some() {
            self.reentry.get_or_insert(CreateProvisioningStorageIoErrorV1::Closed);
            return Err(CreateProvisioningStorageIoErrorV1::Closed);
        }
        self.borrowed = true;
        self.association = Some((|| {
            require_exact_effect_v1(&self.contract, self.operation, self.step, prepared, controller)?;
            let original = self.original.as_ref().ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
            original.require_current_v1(controller)?;
            if original.native_turn_v1() != self.native_turn {
                return Err(CreateProvisioningStorageIoErrorV1::Closed);
            }
            Ok(())
        })());
        if !matches!(self.association, Some(Ok(()))) {
            return Err(CreateProvisioningStorageIoErrorV1::Closed);
        }
        let original = self.original.as_mut().ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
        Ok(CreateProvisioningStorageIoLoanV1 {
            original,
            controller,
            contract: &self.contract,
            operation: self.operation,
            step: self.step,
            native_turn: self.native_turn,
            complete: self.complete,
        })
    }

    /// Borrows the same original financial/native cause without transferring it.
    #[must_use]
    #[doc(hidden)]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.association.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.original.as_ref().and_then(CreateProvisioningOriginalsV1::failure))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
            .or_else(|| self.returned.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }
}

impl CreateProvisioningStorageIoLoanV1<'_> {
    pub(crate) fn require_prepared_v1(&self, prepared: &PreparedAuthorityEffectV1)
        -> Result<(), CreateProvisioningStorageIoErrorV1> {
        if self.original.native_turn_v1() != self.native_turn {
            return Err(CreateProvisioningStorageIoErrorV1::Closed);
        }
        self.original.require_current_v1(self.controller)?;
        require_exact_effect_v1(self.contract, self.operation, self.step, prepared, self.controller)
    }

    pub(crate) fn original_and_controller_v1(
        &mut self,
    ) -> (&mut CreateProvisioningOriginalsV1, &Journal) {
        (&mut *self.original, self.controller)
    }

    pub(crate) fn complete_for_storage_v1(&self, shape: ResourceVector)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.complete.checked_add(shape).map_err(Into::into)
    }
}

impl ProvisioningScopeV1 {
    fn take_storage_io_v1(&mut self, controller: &Journal, operation: OperationId,
        step: u32, prepared: &PreparedAuthorityEffectV1,
        post: crate::StorageProvisioningSessionPostShapeDataV1,
    ) -> Result<CreateProvisioningStorageIoOriginalV1, CreateProvisioningStorageIoErrorV1> {
        self.require_current_v1(controller)?;
        let complete = self.complete.checked_add(
            CreateProvisioningStorageIoOriginalV1::receiving_demand_v1()?,
        ).map_err(ResourceReservationErrorV1::from)?;
        // The full already-admitted Core/Root/model graph coexists with this
        // returned carrier. Its earlier highwater is not simultaneous credit.
        self.original.as_mut().ok_or(CreateProvisioningStorageIoErrorV1::Closed)?
            .prepay_storage_io_post_v1(controller, complete, post)?;
        require_exact_effect_v1(&self.contract, operation, step, prepared, controller)?;
        let original = self.original.take().ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
        let native_turn = original.native_turn_v1();
        Ok(CreateProvisioningStorageIoOriginalV1 {
            original: Some(original),
            contract: Arc::clone(&self.contract),
            operation,
            step,
            native_turn,
            complete,
            association: None,
            borrowed: false,
            returned: None,
            reentry: None,
        })
    }
}

fn require_exact_effect_v1(contract: &Arc<PublicationActionContractV1>,
    operation: OperationId, step: u32, prepared: &PreparedAuthorityEffectV1,
    controller: &Journal,
) -> Result<(), CreateProvisioningStorageIoErrorV1> {
    let plan = contract.plan_v1();
    if operation != plan.operation_id() || step != 0 || plan.effects.len() != 1 {
        return Err(CreateProvisioningStorageIoErrorV1::Closed);
    }
    let expected = &plan.effects[0];
    let binding = expected
        .authority()
        .ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
    if expected.method() != Some(BrokerMethod::BROKER_METHOD_STORAGE_APPLY)
        || prepared.binding_digest() != binding.digest()
        || prepared.publication_digest() != contract.prepared_v1().digest() {
        return Err(CreateProvisioningStorageIoErrorV1::Closed);
    }
    let bytes = controller.get(RecordNamespace::Effect, &effect_key(operation, step))
        .ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
    let (actual, gate) = decode_effect_with_q04(bytes)?;
    if gate.is_some() || actual.plan() != expected
        || !matches!(actual.state(), EffectState::Applying { .. })
        || actual.dispatch() != Some(prepared.history()) {
        return Err(CreateProvisioningStorageIoErrorV1::Closed);
    }
    Ok(())
}

impl Journal {
    /// Takes only this installed scope's exact durable Storage child original.
    ///
    /// The same closed scope is restored before returning. While its actual
    /// original is away, every ordinary or tagged child append still refuses.
    ///
    /// # Errors
    /// Returns the original representation or canonical durable comparison
    /// error without removing the C23 original on a failed entry.
    #[doc(hidden)]
    pub fn take_original_provisioning_storage_io_v1(&mut self, operation: OperationId,
        step: u32, prepared: &PreparedAuthorityEffectV1,
        post: crate::StorageProvisioningSessionPostShapeDataV1,
    ) -> Result<CreateProvisioningStorageIoOriginalV1, CreateProvisioningStorageIoErrorV1> {
        let mut scope = self.take_provisioning_scope_v1()
            .ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
        let returned = scope.take_storage_io_v1(self, operation, step, prepared, post);
        if self.install_provisioning_scope_v1(scope).is_err() {
            std::process::abort();
        }
        returned
    }

    /// Restores the same original before any child append or error transition.
    ///
    /// The whole return Result stays on the same owned header. This deliberately
    /// does not require healthy C23: a refused IO debit still owes C/Root posts.
    ///
    /// # Errors
    /// Refuses another scope/contract, missing original, ordinal substitution or
    /// repeated return, retaining the original on the refused owned header.
    #[doc(hidden)]
    pub fn return_original_provisioning_storage_io_v1(&mut self,
        owner: &mut CreateProvisioningStorageIoOriginalV1,
    ) -> Result<(), CreateProvisioningStorageIoErrorV1> {
        if owner.returned.is_some() {
            owner.reentry.get_or_insert(CreateProvisioningStorageIoErrorV1::Closed);
            return Err(CreateProvisioningStorageIoErrorV1::Closed);
        }
        let mut scope = match self.take_provisioning_scope_v1() {
            Some(scope) => scope,
            None => {
                owner.returned = Some(Err(CreateProvisioningStorageIoErrorV1::Closed));
                return Err(CreateProvisioningStorageIoErrorV1::Closed);
            }
        };
        owner.returned = Some((|| {
            let original = owner.original.as_ref().ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
            if scope.original.is_some() || !Arc::ptr_eq(&scope.contract, &owner.contract)
                || original.native_turn_v1() != owner.native_turn
                || !original.belongs_to_operation_v1(owner.contract.records_v1().fields_v1().parent) {
                return Err(CreateProvisioningStorageIoErrorV1::Closed);
            }
            scope.original = owner.original.take();
            Ok(())
        })());
        if self.install_provisioning_scope_v1(scope).is_err() {
            std::process::abort();
        }
        if matches!(owner.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(CreateProvisioningStorageIoErrorV1::Closed)
        }
    }
}

// The lower native original already refuses unfinished destruction. Moving
// that same obligation through this carrier cannot silently discard it if an
// executor unwinds or fails to return it to the exact Journal scope.
impl Drop for CreateProvisioningStorageIoOriginalV1 {
    fn drop(&mut self) {
        if self.original.is_some() {
            std::process::abort();
        }
    }
}

/// Retains one actual Core-stored dispatch that has never entered native IO.
///
/// Only the two successful canonical Core store frontiers below construct it.
/// Absence cannot be inferred from empty Runtime fields or reconstructed after
/// restart. The complete actual Effect encoding binds its full Prepared data.
pub(crate) struct UnissuedStorageApplyAttemptV1 {
    contract: Arc<PublicationActionContractV1>,
    operation: OperationId,
    step: u32,
    native_turn: u64,
    effect: aos_sandbox_model::ObjectDigest,
    consumed: bool,
}

impl UnissuedStorageApplyAttemptV1 {
    pub(crate) fn consumed_v1(&self) -> bool { self.consumed }
}

impl Journal {
    pub(in crate::reconciler) fn retain_unissued_original_provisioning_attempt_v1(
        &mut self, operation: OperationId, step: u32,
    ) -> Result<(), ReconcilerError> {
        if !self.has_provisioning_scope_v1() {
            return Ok(());
        }
        let mut scope = self.take_provisioning_scope_v1()
            .ok_or(ReconcilerError::InvalidExecutorOutput("the provisioning scope is missing"))?;
        let retained = (|| {
            scope.require_current_v1(self).map_err(|_| ReconcilerError::InvalidExecutorOutput(
                "the original provisioning dispatch is not current",
            ))?;
            let bytes = self.get(RecordNamespace::Effect, &effect_key(operation, step))
                .ok_or(ReconcilerError::CorruptLedger("the new provisioning Effect is absent"))?;
            let (record, q04) = decode_effect_with_q04(bytes).map_err(ReconcilerError::from)?;
            let prepared = record.dispatch().cloned().map(PreparedAuthorityEffectV1::from_history)
                .ok_or(ReconcilerError::CorruptLedger("the new provisioning dispatch is absent"))?;
            require_exact_effect_v1(&scope.contract, operation, step, &prepared, self)
                .map_err(|_| ReconcilerError::InvalidExecutorOutput("the new provisioning dispatch differs"))?;
            if q04.is_some() {
                return Err(ReconcilerError::CorruptLedger("the internal provisioning child has Q04 state"));
            }
            let original = scope.original.as_mut().ok_or(ReconcilerError::InvalidExecutorOutput(
                "the original provisioning receiver is missing",
            ))?;
            if original.storage_io_has_entered_v1() {
                return Err(ReconcilerError::InvalidExecutorOutput("provisioning IO already entered"));
            }
            let proof = UnissuedStorageApplyAttemptV1 {
                contract: Arc::clone(&scope.contract), operation, step,
                native_turn: original.native_turn_v1(),
                effect: aos_sandbox_protocol::domain_ledger::effect_history::
                    lifecycle_child_effect_commitment_v1(bytes),
                consumed: false,
            };
            original.retain_unissued_storage_apply_attempt_v1(proof)
                .map_err(|_| ReconcilerError::InvalidExecutorOutput("the unissued provisioning dispatch is closed"))
        })();
        if self.install_provisioning_scope_v1(scope).is_err() {
            std::process::abort();
        }
        retained
    }


}

impl CreateProvisioningStorageIoLoanV1<'_> {
    /// Observes only an actual prior-turn Core dispatch that never entered IO.
    ///
    /// # Errors
    /// Refuses a missing/cold proof, the same or an older native turn, changed
    /// contract/Effect/Prepared, reentry, or any entered/failed native IO. A
    /// refusal never adopts absence from empty executor state.
    #[doc(hidden)]
    pub fn observe_unissued_storage_apply_once_v1(&mut self,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<AuthorityEffectObservationV1, CreateProvisioningStorageIoErrorV1> {
        self.require_prepared_v1(prepared)?;
        let bytes = self.controller.get(RecordNamespace::Effect,
            &effect_key(self.operation, self.step))
            .ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
        let effect = aos_sandbox_protocol::domain_ledger::effect_history::
            lifecycle_child_effect_commitment_v1(bytes);
        if self.original.storage_io_has_entered_v1() {
            return Err(CreateProvisioningStorageIoErrorV1::Closed);
        }
        let proof = self.original.unissued_storage_apply_attempt_mut_v1()
            .ok_or(CreateProvisioningStorageIoErrorV1::Closed)?;
        if proof.consumed || !Arc::ptr_eq(&proof.contract, self.contract)
            || proof.operation != self.operation || proof.step != self.step
            || proof.effect != effect || self.native_turn <= proof.native_turn {
            return Err(CreateProvisioningStorageIoErrorV1::Closed);
        }
        proof.consumed = true;
        Ok(AuthorityEffectObservationV1::Absent)
    }
}

impl ProvisioningScopeV1 {
    pub(crate) fn storage_io_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().and_then(CreateProvisioningOriginalsV1::storage_io_original_failure_v1)
    }
}
