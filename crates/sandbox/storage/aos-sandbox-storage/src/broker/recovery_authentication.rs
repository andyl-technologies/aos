//! Holds completed persisted authority models through recovery observation.
//!
//! Ordinary and selected callers use the same historical authentication recipe.
//! Only the genuine State recovery stage can pay and enter a selected attempt.

use super::*;
use crate::workspace_catalog::DurablePortableWorkspaceMetadataV1;
use aos_sandbox_protocol::semantics::storage::StorageSemanticsError;

#[derive(Clone, Copy)]
enum Failure {
    Current,
    CurrentComparison,
    Catalog,
    FenceBytes,
    EffectBytes,
    Fence,
    FenceCurrent,
    Effect,
    Metadata,
    MetadataComparison,
    Commitment,
    GrantTarget,
    Linkage,
}

/// Orders ordinary model destruction at the original reverse-local boundaries.
pub(super) struct RecoveryAuthenticationOriginalV1 {
    linkage: Option<Result<(), ZfsHelperError>>,
    grant_target: Option<Result<BrokerGrantTarget, StorageSemanticsError>>,
    commitment: Option<Result<aos_sandbox_model::BrokerArgumentCommitment, StorageSemanticsError>>,
    metadata_comparison: Option<Result<(), ZfsHelperError>>,
    metadata: Option<Result<Option<DurablePortableWorkspaceMetadataV1>, crate::StorageStateError>>,
    effect: Option<Result<BrokerEffectIntentV1, crate::StorageAdmissionError>>,
    fence_current: Option<Result<(), crate::StorageAdmissionError>>,
    fence: Option<Result<BrokerAuthorizationFenceV1, crate::StorageAdmissionError>>,
    effect_bytes: Option<Result<Vec<u8>, crate::StorageStateError>>,
    fence_bytes: Option<Result<Vec<u8>, crate::StorageStateError>>,
    catalog: Option<Result<crate::ResolvedCatalogCommitmentV1, crate::StorageStateError>>,
    current_comparison: Option<Result<(), ZfsHelperError>>,
    current: Option<Result<crate::StorageRecoveryEntry, crate::StorageStateError>>,
    first: Option<Failure>,
    result: Option<Result<(), ()>>,
    entered: bool,
    armed: bool,
}

impl RecoveryAuthenticationOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            linkage: None,
            grant_target: None,
            commitment: None,
            metadata_comparison: None,
            metadata: None,
            effect: None,
            fence_current: None,
            fence: None,
            effect_bytes: None,
            fence_bytes: None,
            catalog: None,
            current_comparison: None,
            current: None,
            first: None,
            result: None,
            entered: false,
            armed: false,
        }
    }

    pub(super) fn run(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        entry: crate::StorageRecoveryEntry,
        retain_models: bool,
    ) {
        if self.entered {
            return;
        }
        self.entered = true;
        self.armed = retain_models;
        self.result = Some(self.run_inner(coordinator, entry, retain_models));
    }

    fn run_inner(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        entry: crate::StorageRecoveryEntry,
        retain_models: bool,
    ) -> Result<(), ()> {
        self.first = Some(Failure::Current);
        self.current = Some(coordinator.transactions.current_recovery_entry(entry.operation_id()));
        let Some(Ok(current)) = self.current.as_ref() else {
            return Err(());
        };
        self.first = Some(Failure::CurrentComparison);
        self.current_comparison = Some(if *current == entry {
            Ok(())
        } else {
            Err(crate::StorageStateError::InvalidTransition.into())
        });
        if !matches!(self.current_comparison, Some(Ok(()))) {
            return Err(());
        }

        self.first = Some(Failure::Catalog);
        self.catalog = Some(coordinator.transactions.recover_catalog(entry));
        let Some(Ok(catalog)) = self.catalog.as_ref() else {
            return Err(());
        };
        let operation = catalog.plan().operation();

        self.first = Some(Failure::FenceBytes);
        self.fence_bytes = Some(coordinator.transactions.authority_record(
            RecordNamespace::AuthorityPublication, &entry.operation_id(),
        ).and_then(|bytes| bytes.map(<[u8]>::to_vec)
            .ok_or(crate::StorageStateError::MissingAuthorityLink)));
        let Some(Ok(fence_bytes)) = self.fence_bytes.as_ref() else {
            return Err(());
        };
        self.first = Some(Failure::EffectBytes);
        self.effect_bytes = Some(coordinator.transactions.authority_record(
            RecordNamespace::Effect, &entry.request_id(),
        ).and_then(|bytes| bytes.map(<[u8]>::to_vec)
            .ok_or(crate::StorageStateError::MissingAuthorityLink)));
        let Some(Ok(effect_bytes)) = self.effect_bytes.as_ref() else {
            return Err(());
        };

        self.first = Some(Failure::Fence);
        self.fence = Some(coordinator.authority.open_operation_fence(&entry.operation_id(), fence_bytes));
        let Some(Ok(fence)) = self.fence.as_ref() else {
            return Err(());
        };
        self.first = Some(Failure::FenceCurrent);
        self.fence_current = Some(coordinator.authority.check_current_fence(fence));
        if !matches!(self.fence_current, Some(Ok(()))) {
            return Err(());
        }
        self.first = Some(Failure::Effect);
        self.effect = Some(coordinator.authority.open_admission_intent(&entry.request_id(), effect_bytes));
        let Some(Ok(effect)) = self.effect.as_ref() else {
            return Err(());
        };

        self.first = Some(Failure::Metadata);
        self.metadata = Some(coordinator.transactions.workspace_publication_intent(entry.operation_id())
            .map(|intent| intent.map(|intent| intent.portable_metadata().clone())));
        let Some(Ok(metadata)) = self.metadata.as_ref() else {
            return Err(());
        };
        self.first = Some(Failure::MetadataComparison);
        self.metadata_comparison = Some(if metadata.as_ref().is_some_and(|metadata| {
            metadata.request_id() != entry.request_id()
                || metadata.request_digest() != entry.request_digest()
                || metadata.assignment() != fence.assignment()
                || metadata.node() != fence.node()
                || catalog.root_policy() != Some(metadata.root_policy())
        }) {
            Err(ZfsHelperError::Authority)
        } else {
            Ok(())
        });
        if !matches!(self.metadata_comparison, Some(Ok(()))) {
            return Err(());
        }
        self.first = Some(Failure::Commitment);
        self.commitment = Some(match metadata {
            Some(metadata) => operation.persisted_workspace_argument_commitment(
                fence.assignment(), entry.operation_id(), catalog.binding(),
                metadata.manifest_bytes(), metadata.sandbox_spec_bytes(),
            ),
            None => operation.persisted_argument_commitment(
                fence.assignment(), entry.operation_id(), catalog.binding(),
            ),
        });
        if !retain_models {
            // The former match-local metadata ended before map_err and the
            // later grant-target/linkage checks, including commitment errors.
            drop(self.metadata.take());
        }
        let Some(Ok(commitment)) = self.commitment.as_ref() else {
            return Err(());
        };
        self.first = Some(Failure::GrantTarget);
        self.grant_target = Some(operation.grant_target());
        let Some(Ok(grant_target)) = self.grant_target.as_ref() else {
            return Err(());
        };
        self.first = Some(Failure::Linkage);
        self.linkage = Some(if fence.assignment().sandbox().as_bytes() != &entry.sandbox_id()
            || effect.status() != BrokerEffectStatusV1::Pending
            || effect.request_id() != &entry.request_id()
            || effect.transport_request_digest() != entry.request_digest()
            || effect.request_digest() != commitment.digest()
            || effect.verb() != operation.broker_verb()
            || effect.target() != *grant_target
            || effect.plan_digest() != fence.plan_digest()
            || effect.plan_expires_seconds() != fence.plan_expires_seconds()
            || effect.local_lease_record() != fence.local_lease_record()
            || effect.lease_digest() != fence.local_lease_record().lease_digest()
        {
            Err(ZfsHelperError::Authority)
        } else {
            Ok(())
        });
        if !matches!(self.linkage, Some(Ok(()))) {
            return Err(());
        }
        self.first = None;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn held_models_for_test(
        &self,
    ) -> (&[u8], Option<&BrokerAuthorizationFenceV1>, &[u8]) {
        (
            self.catalog.as_ref().unwrap().as_ref().unwrap().canonical_bytes(),
            self.fence.as_ref().and_then(|result| result.as_ref().ok()),
            self.effect_bytes.as_ref().unwrap().as_ref().unwrap(),
        )
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Current => self.current.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::CurrentComparison => self.current_comparison.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::Catalog => self.catalog.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::FenceBytes => self.fence_bytes.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::EffectBytes => self.effect_bytes.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::Fence => self.fence.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::FenceCurrent => self.fence_current.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::Effect => self.effect.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::Metadata => self.metadata.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::MetadataComparison => self.metadata_comparison.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::Commitment => self.commitment.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::GrantTarget => self.grant_target.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
            Failure::Linkage => self.linkage.as_ref()?.as_ref().err().map(|e| e as &dyn std::error::Error),
        }
    }

    pub(super) fn take_ordinary_result(&mut self)
        -> Result<(BrokerAuthorizationFenceV1, BrokerEffectIntentV1), ZfsHelperError>
    {
        if matches!(self.result, Some(Ok(()))) {
            let Some(Ok(fence)) = self.fence.take() else {
                std::process::abort();
            };
            let Some(Ok(effect)) = self.effect.take() else {
                std::process::abort();
            };
            return Ok((fence, effect));
        }
        let cause = match self.first.take() {
            Some(Failure::Current) => self.current.take().and_then(Result::err).map(ZfsHelperError::State),
            Some(Failure::CurrentComparison) => self.current_comparison.take().and_then(Result::err),
            Some(Failure::Catalog) => self.catalog.take().and_then(Result::err).map(ZfsHelperError::State),
            Some(Failure::FenceBytes) => self.fence_bytes.take().and_then(Result::err).map(ZfsHelperError::State),
            Some(Failure::EffectBytes) => self.effect_bytes.take().and_then(Result::err).map(ZfsHelperError::State),
            Some(Failure::Fence) => self.fence.take().and_then(Result::err).map(|_| ZfsHelperError::Authority),
            Some(Failure::FenceCurrent) => self.fence_current.take().and_then(Result::err).map(|_| ZfsHelperError::Authority),
            Some(Failure::Effect) => self.effect.take().and_then(Result::err).map(|_| ZfsHelperError::Authority),
            Some(Failure::Metadata) => self.metadata.take().and_then(Result::err).map(ZfsHelperError::State),
            Some(Failure::MetadataComparison) => self.metadata_comparison.take().and_then(Result::err),
            Some(Failure::Commitment) => self.commitment.take().and_then(Result::err).map(|_| ZfsHelperError::Authority),
            Some(Failure::GrantTarget) => self.grant_target.take().and_then(Result::err).map(|_| ZfsHelperError::Authority),
            Some(Failure::Linkage) => self.linkage.take().and_then(Result::err),
            None => None,
        };
        match cause {
            Some(cause) => Err(cause),
            None => std::process::abort(),
        }
    }
}

impl Drop for RecoveryAuthenticationOriginalV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

#[derive(Default)]
pub(super) struct RecoveryAuthenticationCaptureV1 {
    attempts: Vec<RecoveryAuthenticationOriginalV1>,
    shape: Option<Result<(usize, usize), aos_sandbox_model::AccountingError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    armed: bool,
}

impl RecoveryAuthenticationCaptureV1 {
    pub(super) const fn new() -> Self {
        Self {
            attempts: Vec::new(),
            shape: None,
            payment: None,
            allocation: None,
            armed: false,
        }
    }

    pub(super) fn prepare(
        &mut self,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), ZfsHelperError> {
        if self.failure().is_some() {
            return Err(crate::StorageStateError::Receiving.into());
        }
        self.shape = Some(self.shape());
        let Some((bytes, cells)) = self.shape.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            return Err(crate::StorageStateError::Receiving.into());
        };
        self.payment = Some(receiving.reserve_encoded_capacity_v1(bytes, cells));
        if !matches!(self.payment, Some(Ok(()))) {
            return Err(crate::StorageStateError::Receiving.into());
        }
        self.allocation = Some(self.attempts.try_reserve_exact(1));
        if !matches!(self.allocation, Some(Ok(()))) {
            return Err(crate::StorageStateError::Receiving.into());
        }
        self.armed = true;
        Ok(())
    }

    fn shape(&self) -> Result<(usize, usize), aos_sandbox_model::AccountingError> {
        let bytes = self.attempts.len().checked_add(1)
            .and_then(|slots| slots.checked_mul(std::mem::size_of::<RecoveryAuthenticationOriginalV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_model::ResourceDimension::MemoryBytes,
            })?;
        // Three simultaneous copies of original17 + capture5, then current
        // operation1/argument2/slot1/shape2/returned result1/destination1.
        Ok((bytes, 3 * (17 + 5) + 8))
    }

    pub(super) fn park(&mut self, attempt: RecoveryAuthenticationOriginalV1) -> bool {
        if !self.armed || self.attempts.len() == self.attempts.capacity() {
            std::process::abort();
        }
        let positive = matches!(attempt.result, Some(Ok(())));
        self.attempts.push(attempt);
        positive
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.shape.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.payment.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.allocation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.attempts.iter().find_map(RecoveryAuthenticationOriginalV1::failure))
    }

    pub(super) fn require_positive(&self) -> Result<(), crate::StorageStateError> {
        if self.failure().is_some()
            || self.attempts.iter().any(|attempt| !matches!(attempt.result, Some(Ok(()))))
        {
            return Err(crate::StorageStateError::Receiving);
        }
        Ok(())
    }

    pub(super) fn complete_positive_disposal(&mut self) {
        self.armed = false;
        for attempt in &mut self.attempts {
            attempt.armed = false;
        }
        self.attempts = Vec::new();
    }
}

impl Drop for RecoveryAuthenticationCaptureV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}
