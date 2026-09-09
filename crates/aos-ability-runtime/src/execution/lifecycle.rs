//! Resource release transitions after durable operation settlement.

use std::collections::BTreeSet;

use aos_ability_model::ResourceId;
use thiserror::Error;

use crate::adapter::{MonotonicClock, TrustedAdapter, TrustedResourceCatalog};
use crate::execution::{
    AdmittedOperation, ExecutionEventKind, ExecutionTransaction, RecoveryAction, TransactionError,
};

/// Reports why held resource ownership could not be fully released.
#[derive(Debug, Error)]
pub enum ResourceReleaseError {
    /// The token no longer names the transaction's releasable durable attempt.
    #[error("admitted operation does not match releasable durable state")]
    StaleAdmission,
    /// The trusted catalog did not release one held resource.
    #[error("resource release failed for {resource:?}: {source}")]
    Catalog {
        /// Names the logical resource whose handle remains owned.
        resource: ResourceId,
        /// Retains the trusted catalog's exact failure.
        #[source]
        source: anyhow::Error,
    },
    /// The owning transaction could not persist completed release.
    #[error("execution transaction could not record resource release: {0}")]
    Transaction(#[source] TransactionError),
}

/// Retains an admitted token and any handles still owned after failed release.
#[derive(Debug)]
pub struct ResourceReleaseFailure<'plan, Request, Handle> {
    error: ResourceReleaseError,
    admitted: AdmittedOperation<'plan, Request, Handle>,
    released: BTreeSet<ResourceId>,
}

impl<'plan, Request, Handle> ResourceReleaseFailure<'plan, Request, Handle> {
    /// Returns the reason the release transition stopped.
    #[must_use]
    pub const fn error(&self) -> &ResourceReleaseError {
        &self.error
    }

    /// Returns logical resources whose process-scoped handles remain owned.
    #[must_use]
    pub fn retained_resources(&self) -> impl Iterator<Item = &ResourceId> {
        self.admitted
            .resources()
            .filter(|resource| !self.released.contains(*resource))
    }

    /// Retries remaining catalog releases and the final durable release record.
    ///
    /// # Errors
    ///
    /// Returns a replacement failure retaining the admitted token when a
    /// catalog release or the final journal append still fails.
    pub fn retry<Catalog, Clock>(
        self,
        transaction: &mut ExecutionTransaction<'plan>,
        catalog: &mut Catalog,
        clock: &Clock,
    ) -> Result<(), Self>
    where
        Catalog: TrustedResourceCatalog<Handle = Handle>,
        Clock: MonotonicClock,
    {
        release_resources(transaction, self.admitted, catalog, clock, self.released)
    }
}

impl<'plan> ExecutionTransaction<'plan> {
    /// Releases every handle after durable settlement and records the result.
    ///
    /// Actual catalog release completes before `ResourcesReleased` becomes
    /// durable. A partial or failed release returns ownership of the admitted
    /// token so callers cannot lose the remaining process-scoped handles.
    ///
    /// # Errors
    ///
    /// Returns a failure retaining the token when durable state is stale, a
    /// catalog release fails, or the final journal record cannot be persisted.
    pub fn release_admitted<Adapter, Catalog, Clock>(
        &mut self,
        admitted: AdmittedOperation<'plan, Adapter::Request, Adapter::Handle>,
        catalog: &mut Catalog,
        clock: &Clock,
    ) -> Result<(), ResourceReleaseFailure<'plan, Adapter::Request, Adapter::Handle>>
    where
        Adapter: TrustedAdapter,
        Catalog: TrustedResourceCatalog<Handle = Adapter::Handle>,
        Clock: MonotonicClock,
    {
        release_resources(self, admitted, catalog, clock, BTreeSet::new())
    }
}

fn release_resources<'plan, Request, Handle, Catalog, Clock>(
    transaction: &mut ExecutionTransaction<'plan>,
    mut admitted: AdmittedOperation<'plan, Request, Handle>,
    catalog: &mut Catalog,
    clock: &Clock,
    mut released: BTreeSet<ResourceId>,
) -> Result<(), ResourceReleaseFailure<'plan, Request, Handle>>
where
    Catalog: TrustedResourceCatalog<Handle = Handle>,
    Clock: MonotonicClock,
{
    let history = match transaction.history(&admitted.operation().key) {
        Ok(history) => history,
        Err(source) => {
            return Err(release_failure(
                ResourceReleaseError::Transaction(source),
                admitted,
                released,
            ));
        }
    };
    let expected_resources = history.admitted_resources().to_vec();
    let persisted_elapsed = history.elapsed_millis();
    let action = match transaction.next_action(&admitted.operation().key) {
        Ok(action) => action,
        Err(source) => {
            return Err(release_failure(
                ResourceReleaseError::Transaction(source),
                admitted,
                released,
            ));
        }
    };
    let empty_release_is_complete = expected_resources.is_empty()
        && history.resources_released()
        && admitted.resources().next().is_none();
    let token_matches = admitted.belongs_to_session(transaction.session())
        && admitted.plan().id() == transaction.plan().id()
        && admitted.transaction() == transaction.transaction()
        && admitted.operation_id().operation == admitted.operation().key
        && history.current_attempt() == Some(admitted.attempt())
        && admitted.resources().eq(expected_resources.iter());
    if !token_matches {
        return Err(release_failure(
            ResourceReleaseError::StaleAdmission,
            admitted,
            released,
        ));
    }
    if empty_release_is_complete {
        admitted.release_live_reservation();
        return Ok(());
    }
    if !matches!(action, RecoveryAction::ReleaseResources) {
        return Err(release_failure(
            ResourceReleaseError::StaleAdmission,
            admitted,
            released,
        ));
    }

    for resource in admitted.resource_handles_mut().iter_mut().rev() {
        let resource_id = resource.resource().clone();
        if released.contains(&resource_id) {
            continue;
        }
        if let Err(source) = catalog.release(&resource_id, resource.native_mut()) {
            return Err(release_failure(
                ResourceReleaseError::Catalog {
                    resource: resource_id,
                    source: anyhow::Error::new(source),
                },
                admitted,
                released,
            ));
        }
        released.insert(resource_id);
    }

    let observed_elapsed = admitted.elapsed_millis().saturating_add(
        clock
            .now_millis()
            .saturating_sub(admitted.clock_observed_at()),
    );
    let event = ExecutionEventKind::ResourcesReleased {
        transaction: admitted.transaction().clone(),
        operation: admitted.operation_id().clone(),
        resources: expected_resources,
        elapsed_millis: observed_elapsed.max(persisted_elapsed),
    };
    if let Err(source) = transaction.append(event) {
        return Err(release_failure(
            ResourceReleaseError::Transaction(source),
            admitted,
            released,
        ));
    }

    admitted.release_live_reservation();
    Ok(())
}

fn release_failure<'plan, Request, Handle>(
    error: ResourceReleaseError,
    admitted: AdmittedOperation<'plan, Request, Handle>,
    released: BTreeSet<ResourceId>,
) -> ResourceReleaseFailure<'plan, Request, Handle> {
    ResourceReleaseFailure {
        error,
        admitted,
        released,
    }
}
