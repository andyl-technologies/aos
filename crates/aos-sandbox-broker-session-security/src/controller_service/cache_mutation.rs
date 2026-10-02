//! Same-executor custody for selected public Cache pin mutations.
//!
//! Actual Source availability, request DATA and complete outcomes remain
//! resident through protected append, physical settlement and all bookends.
//! A failed attempt is terminal; it is not permission to reopen or retry.

use aos_sandbox::cache_residency::{CacheOwnerErrorV1, CacheResidentUnavailableV1};
use aos_sandbox::filesystem_view_state::{
    DurableFilesystemViewRevisionV1, FilesystemViewRevisionStateError,
    current_filesystem_view_revision_v1,
};
use aos_sandbox::production_operation_compiler::{
    OperationCompilationError, RecheckedCacheConsumerV1, recheck_cache_consumer_projection_v1,
};
use sha2::{Digest as _, Sha256};

use super::{
    DormantSandboxRequestKindV1, EffectFailure, Journal, OperationId, ProductionEffectExecutor,
};
use crate::cache_public_pin::{
    PublicCachePinExecutionErrorV1, ResidentPublicCacheUnpinV1,
    execute_resident_public_cache_pin_v1, execute_resident_public_cache_unpin_v1,
    public_cache_pin_transaction_id_v1,
};
use crate::cache_directory_source::{ProjectSealedViewObjectSourceV1, ProjectSealedViewSourceErrorV1};

#[derive(Clone, Copy)]
enum MutationFailureV1 {
    Closed,
    Original,
    Revision,
    Source,
    SourcePostcheck,
    Pin,
    Unpin,
    Consumer,
    Physical,
}

/// Empty DATA destination; only the real executor supplies original owners.
#[derive(Default)]
pub(super) struct ControllerCacheMutationV1 {
    operation: Option<OperationId>,
    consumer: Option<RecheckedCacheConsumerV1>,
    request: Option<DormantSandboxRequestKindV1>,
    revision: Option<
        Result<Option<DurableFilesystemViewRevisionV1>, FilesystemViewRevisionStateError>,
    >,
    source: Option<Result<ProjectSealedViewObjectSourceV1, ProjectSealedViewSourceErrorV1>>,
    pin: Option<Result<(), PublicCachePinExecutionErrorV1<ProjectSealedViewSourceErrorV1>>>,
    unpin: ResidentPublicCacheUnpinV1,
    first_failure: Option<MutationFailureV1>,
    source_postcheck: Option<ProjectSealedViewSourceErrorV1>,
    consumer_postcheck: Option<Result<RecheckedCacheConsumerV1, OperationCompilationError>>,
    physical_postcheck: Option<Result<(), CacheOwnerErrorV1>>,
    complete: bool,
}

impl ControllerCacheMutationV1 {
    pub(super) fn require_completed_or_empty(&self) -> Result<(), CacheResidentUnavailableV1> {
        if self.operation.is_some() && !self.complete {
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    fn begin(
        &mut self,
        operation: OperationId,
        consumer: &RecheckedCacheConsumerV1,
        request: &DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.operation.is_some() && !self.complete {
            self.first_failure.get_or_insert(MutationFailureV1::Closed);
            return Err(CacheResidentUnavailableV1);
        }
        // Only a fully completed prior operation may release its immutable
        // source-availability owner. Native Cache originals are not replaced.
        *self = Self::default();
        self.operation = Some(operation);
        self.consumer = Some(consumer.clone());
        self.request = Some(request.clone());
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure {
            Some(MutationFailureV1::Revision) => {
                self.revision.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            Some(MutationFailureV1::Source) => {
                self.source.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            Some(MutationFailureV1::SourcePostcheck) => {
                self.source_postcheck.as_ref().map(|cause| cause as _)
            }
            Some(MutationFailureV1::Pin) => {
                self.pin.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            Some(MutationFailureV1::Unpin) => self.unpin.failure(),
            Some(MutationFailureV1::Consumer) => {
                self.consumer_postcheck.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            Some(MutationFailureV1::Physical) => {
                self.physical_postcheck.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            _ => None,
        }
    }
}

impl ProductionEffectExecutor {
    pub(super) fn apply_resident_cache_pin(
        &mut self,
        operation: OperationId,
        consumer: &RecheckedCacheConsumerV1,
        journal: &Journal,
        request: &DormantSandboxRequestKindV1,
    ) -> Result<(), EffectFailure> {
        self.cache_mutation.begin(operation, consumer, request)
            .map_err(|_| self.resident_cache_failure())?;
        self.ensure_cache_physical_owner()?;
        let returned = self.acquire_or_reconcile_resident_pin(operation, consumer, journal, request);
        if returned.is_err() {
            self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::Original);
        }
        self.finish_resident_cache_mutation(operation, consumer, journal, request, returned.is_ok())
    }

    fn acquire_or_reconcile_resident_pin(
        &mut self,
        operation: OperationId,
        consumer: &RecheckedCacheConsumerV1,
        journal: &Journal,
        request: &DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let protected = self.cache_inventory.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let physical = self.cache_physical.as_mut().ok_or(CacheResidentUnavailableV1)?;
        if self.cache_resident_usage.reconcile_existing_public_pin(
            protected, physical, consumer, operation,
            public_cache_pin_transaction_id_v1(operation), journal, request,
        )? {
            return Ok(());
        }

        self.cache_mutation.revision = Some(current_filesystem_view_revision_v1(
            journal, consumer.view(),
        ));
        let Some(Ok(Some(revision))) = self.cache_mutation.revision.as_ref() else {
            self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::Revision);
            return Err(CacheResidentUnavailableV1);
        };
        self.cache_mutation.source = Some(ProjectSealedViewObjectSourceV1::open_fixed(consumer.project()));
        let Some(Ok(source)) = self.cache_mutation.source.as_mut() else {
            self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::Source);
            return Err(CacheResidentUnavailableV1);
        };
        let compiler_abi = Sha256::digest(b"aos.sandbox.cache.pin-compiler.v1\0").into();
        self.cache_mutation.pin = Some(execute_resident_public_cache_pin_v1(
            &mut self.cache_resident_usage, protected, physical, source, revision,
            consumer, journal, request, operation, self.node, compiler_abi,
            super::cache_pin::controller_cache_source_limits(),
        ));
        if !matches!(self.cache_mutation.pin.as_ref(), Some(Ok(()))) {
            self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::Pin);
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    pub(super) fn apply_resident_cache_unpin(
        &mut self,
        operation: OperationId,
        consumer: &RecheckedCacheConsumerV1,
        journal: &Journal,
        request: &DormantSandboxRequestKindV1,
    ) -> Result<(), EffectFailure> {
        self.cache_mutation.begin(operation, consumer, request)
            .map_err(|_| self.resident_cache_failure())?;
        self.ensure_cache_physical_owner()?;
        let protected = self.cache_inventory.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("resident protected Cache owner is absent".to_owned())
        })?;
        let physical = self.cache_physical.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("resident physical Cache owner is absent".to_owned())
        })?;
        let returned = execute_resident_public_cache_unpin_v1(
            &mut self.cache_resident_usage, protected, physical, &mut self.cache_mutation.unpin,
            consumer, journal, request, operation,
        );
        if returned.is_err() {
            self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::Unpin);
        }
        self.finish_resident_cache_mutation(operation, consumer, journal, request, returned.is_ok())
    }

    fn finish_resident_cache_mutation(
        &mut self,
        operation: OperationId,
        consumer: &RecheckedCacheConsumerV1,
        journal: &Journal,
        request: &DormantSandboxRequestKindV1,
        action_succeeded: bool,
    ) -> Result<(), EffectFailure> {
        if let Some(Ok(source)) = self.cache_mutation.source.as_ref() {
            if let Err(cause) = source.recheck_retained_cache_pin_root_v1() {
                self.cache_mutation.source_postcheck.get_or_insert(cause);
                self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::SourcePostcheck);
            }
        }
        self.cache_mutation.consumer_postcheck = Some(recheck_cache_consumer_projection_v1(
            journal, consumer.project(), request,
        ));
        if !matches!(self.cache_mutation.consumer_postcheck.as_ref(), Some(Ok(current)) if current == consumer) {
            self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::Consumer);
        }
        if let Some(physical) = self.cache_physical.as_ref() {
            self.cache_mutation.physical_postcheck = Some(physical.held_snapshot().map(|_| ()));
            if !matches!(self.cache_mutation.physical_postcheck.as_ref(), Some(Ok(()))) {
                self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::Physical);
            }
        }
        let original_current = match self.cache_inventory.as_mut() {
            Some(owner) => self.cache_resident_usage.recheck(owner).is_ok(),
            None => false,
        };
        if !action_succeeded
            || !original_current
            || self.cache_mutation.first_failure.is_some()
            || self.cache_mutation.source_postcheck.is_some()
        {
            return Err(self.resident_cache_failure());
        }
        let owner = self.cache_inventory.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("resident Cache owner is absent".to_owned())
        })?;
        let physical = self.cache_physical.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("resident physical Cache owner is absent".to_owned())
        })?;
        if self
            .cache_resident_usage
            .finish_existing_pin_operation(owner, physical, operation)
            .is_err()
        {
            self.cache_mutation.first_failure.get_or_insert(MutationFailureV1::Original);
            return Err(self.resident_cache_failure());
        }
        self.cache_mutation.complete = true;
        Ok(())
    }

    pub(super) fn resident_cache_failure(&self) -> EffectFailure {
        // Physical persistence may return an opaque ambiguity wrapper. Its
        // original native cause has priority over that short classification.
        let physical_cause = self
            .cache_physical
            .as_ref()
            .and_then(|owner| owner.resident_pin_failure())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.cache_resident_usage.failure());
        let action_is_original = matches!(self.cache_mutation.first_failure, Some(MutationFailureV1::Original))
            || matches!(self.cache_mutation.pin.as_ref(), Some(Err(PublicCachePinExecutionErrorV1::Protected(_))));
        let cause = if action_is_original {
            physical_cause.or_else(|| self.cache_mutation.failure())
        } else {
            self.cache_mutation.failure().or(physical_cause)
        };
        EffectFailure::Permanent(match cause {
            Some(cause) => format!("resident Cache mutation is terminal: {cause}"),
            None => "resident Cache mutation is incomplete; original custody remains retained".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_progress_is_nonpositive_but_does_not_fence_usage() {
        let progress = ControllerCacheMutationV1::default();

        assert!(progress.require_completed_or_empty().is_ok());
        assert!(!progress.complete);
        assert!(progress.source.is_none());
    }

    #[test]
    fn nominated_operation_remains_fenced_across_caught_unwind() {
        let mut progress = ControllerCacheMutationV1::default();
        progress.operation = Some(OperationId::from_bytes([93; 16]));

        let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            panic!("pure DATA crossing");
        }));

        assert!(returned.is_err());
        assert!(progress.require_completed_or_empty().is_err());
        assert!(progress.operation.is_some());
        assert!(!progress.complete);
    }

    #[test]
    fn completed_prior_data_does_not_hide_unresolved_next_operation() {
        let mut progress = ControllerCacheMutationV1::default();
        progress.operation = Some(OperationId::from_bytes([94; 16]));
        progress.complete = true;
        assert!(progress.require_completed_or_empty().is_ok());

        progress.complete = false;
        progress.first_failure = Some(MutationFailureV1::Closed);

        assert!(progress.require_completed_or_empty().is_err());
    }
}
