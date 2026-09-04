//! Bounded exact-key routing across retained single-host hot-fork templates.
//!
//! A pool owns a fixed set of independent source workers. Selection uses the
//! exact lineage and paused source configuration derived from the admitted
//! attempt; it never falls back to a merely compatible template. Each returned
//! lifecycle carries the pool incarnation and stable slot index needed to route
//! recovery back to the same source. Terminal and foreign lifecycles move to a
//! dedicated nondroppable quarantine instead of being guessed into a slot.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptExecutionRuntimeBasis, AttemptWorkerFailure, CrucibleAttemptExecution,
    FixedQemuHotForkTemplateFactory, QemuHotForkAttemptLifecycle,
    QemuHotForkAttemptLifecycleFactory, QemuHotForkAttemptLifecycleRecoveryError,
    QemuHotForkFactoryQuarantine, QemuHotForkLifecycleQuarantine, QemuHotForkPooledLifecycle,
    QemuHotForkTemplateKey, QemuHotForkTemplateLauncher,
};

/// Maximum retained source workers admitted by one in-process template pool.
///
/// A retained source occupies one fixed local execution worker, so this is the
/// same static ceiling enforced by [`crate::MAX_LOCAL_EXECUTOR_WORKERS`].
pub const MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS: usize = crate::MAX_LOCAL_EXECUTOR_WORKERS;

mod sealed {
    pub trait QemuHotForkKeyedLifecycleFactory {}
}

/// Exact-key and availability view required by a retained-template pool.
///
/// This trait is sealed so production selection cannot trust a self-asserted
/// key or availability bit from outside the daemon's lifecycle implementation.
pub trait QemuHotForkKeyedLifecycleFactory:
    sealed::QemuHotForkKeyedLifecycleFactory + QemuHotForkAttemptLifecycleFactory
{
    /// Returns the immutable lineage/configuration key for this source worker.
    #[must_use]
    fn template_key(&self) -> QemuHotForkTemplateKey;

    /// Returns whether this worker can start a child immediately.
    #[must_use]
    fn template_available(&self) -> bool;
}

impl<R, X, Q> sealed::QemuHotForkKeyedLifecycleFactory for FixedQemuHotForkTemplateFactory<R, X, Q>
where
    R: crate::QemuAttemptResourceGuardFactory,
    X: QemuHotForkTemplateLauncher<R::Guard>,
    Q: QemuHotForkFactoryQuarantine<X::Template, QemuHotForkPooledLifecycle<X::Lifecycle>>,
{
}

impl<R, X, Q> QemuHotForkKeyedLifecycleFactory for FixedQemuHotForkTemplateFactory<R, X, Q>
where
    R: crate::QemuAttemptResourceGuardFactory,
    R::Guard: crate::QemuAttemptResourceGuard,
    X: QemuHotForkTemplateLauncher<R::Guard>,
    Q: QemuHotForkFactoryQuarantine<X::Template, QemuHotForkPooledLifecycle<X::Lifecycle>>,
{
    fn template_key(&self) -> QemuHotForkTemplateKey {
        FixedQemuHotForkTemplateFactory::template_key(self)
    }

    fn template_available(&self) -> bool {
        FixedQemuHotForkTemplateFactory::template_available(self)
    }
}

/// Bounded deterministic pool of exact retained-template workers.
pub struct QemuHotForkTemplatePool<F, Q>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
{
    identity: Arc<()>,
    maximum_slots: usize,
    slot_count: usize,
    slots: BTreeMap<QemuHotForkTemplateKey, Vec<Option<F>>>,
    quarantine: Q,
}

impl<F, Q> QemuHotForkTemplatePool<F, Q>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
{
    /// Creates a nonempty bounded pool around its first retained worker.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkTemplatePoolConstructionError`] with the unchanged
    /// first worker when `maximum_slots` is zero or exceeds
    /// [`MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS`].
    pub fn new(
        maximum_slots: usize,
        first: F,
        quarantine: Q,
    ) -> Result<Self, QemuHotForkTemplatePoolConstructionError<F>> {
        if maximum_slots == 0 {
            return Err(QemuHotForkTemplatePoolConstructionError::new(
                first,
                QemuHotForkTemplatePoolCapacityError::Zero,
            ));
        }
        if maximum_slots > MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS {
            return Err(QemuHotForkTemplatePoolConstructionError::new(
                first,
                QemuHotForkTemplatePoolCapacityError::AboveMaximum {
                    requested: maximum_slots,
                },
            ));
        }

        let key = first.template_key();
        Ok(Self {
            identity: Arc::new(()),
            maximum_slots,
            slot_count: 1,
            slots: BTreeMap::from([(key, vec![Some(first)])]),
            quarantine,
        })
    }

    /// Adds one stable retained worker without changing existing slot indices.
    ///
    /// Workers with the same exact key are permitted and selected in insertion
    /// order, allowing bounded parallelism for a hot configuration.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkTemplatePoolInsertionError`] with the unchanged
    /// worker when the configured pool capacity is already full.
    pub fn insert(&mut self, factory: F) -> Result<(), QemuHotForkTemplatePoolInsertionError<F>> {
        if self.slot_count >= self.maximum_slots {
            return Err(QemuHotForkTemplatePoolInsertionError {
                factory: Box::new(factory),
            });
        }
        let key = factory.template_key();
        let slots = self.slots.entry(key).or_default();
        if let Some(slot) = slots.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(factory);
        } else {
            slots.push(Some(factory));
        }
        self.slot_count += 1;
        Ok(())
    }

    /// Removes one idle source worker for orderly demotion or shutdown.
    ///
    /// The returned factory retains its exact prepared source and quarantine
    /// owner. Removing a slot leaves a tombstone, so every outstanding sibling
    /// lifecycle keeps the same recovery coordinate. A later insertion for the
    /// same key may reuse that tombstone only after this method proved the old
    /// source idle.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkTemplatePoolRetirementError::MissingSlot`] when the
    /// key or stable slot is absent, or
    /// [`QemuHotForkTemplatePoolRetirementError::Busy`] while that source owns a
    /// child lifecycle. No pool state changes on error.
    pub fn retire_idle(
        &mut self,
        key: QemuHotForkTemplateKey,
        slot: usize,
    ) -> Result<F, QemuHotForkTemplatePoolRetirementError> {
        let slots = self
            .slots
            .get_mut(&key)
            .ok_or(QemuHotForkTemplatePoolRetirementError::MissingSlot { key, slot })?;
        let factory = slots
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(QemuHotForkTemplatePoolRetirementError::MissingSlot { key, slot })?;
        if !factory.template_available() {
            return Err(QemuHotForkTemplatePoolRetirementError::Busy { key, slot });
        }
        let factory = slots
            .get_mut(slot)
            .and_then(Option::take)
            .ok_or(QemuHotForkTemplatePoolRetirementError::MissingSlot { key, slot })?;
        self.slot_count -= 1;
        let remove_key = slots.iter().all(Option::is_none);
        if remove_key {
            self.slots.remove(&key);
        }
        Ok(factory)
    }

    /// Returns the configured hard slot ceiling.
    #[must_use]
    pub const fn maximum_slots(&self) -> usize {
        self.maximum_slots
    }

    /// Returns the number of retained source workers in this pool.
    #[must_use]
    pub const fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Returns the number of exact lineage/configuration keys retained.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.slots.len()
    }

    /// Returns the number of source workers currently available for launch.
    #[must_use]
    pub fn available_slot_count(&self) -> usize {
        self.slots
            .values()
            .flat_map(|slots| slots.iter().flatten())
            .filter(|factory| factory.template_available())
            .count()
    }

    /// Returns the pool-level terminal quarantine.
    #[must_use]
    pub const fn quarantine_sink(&self) -> &Q {
        &self.quarantine
    }
}

/// Pool-qualified lifecycle carrying its stable source slot.
#[must_use = "reconcile the source slot or transfer the lifecycle to quarantine"]
pub struct QemuHotForkTemplatePoolLifecycle<L> {
    pool: Arc<()>,
    key: QemuHotForkTemplateKey,
    slot: usize,
    lifecycle: L,
}

impl<L> QemuHotForkTemplatePoolLifecycle<L> {
    /// Returns the exact lineage/configuration key selected for this child.
    #[must_use]
    pub const fn template_key(&self) -> QemuHotForkTemplateKey {
        self.key
    }

    /// Returns the stable insertion-order slot within that exact key.
    #[must_use]
    pub const fn slot_index(&self) -> usize {
        self.slot
    }
}

impl<L> QemuHotForkAttemptLifecycle for QemuHotForkTemplatePoolLifecycle<L>
where
    L: QemuHotForkAttemptLifecycle,
{
    type Live<'a>
        = L::Live<'a>
    where
        Self: 'a;
    type Error = L::Error;

    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.lifecycle.runtime_basis()
    }

    fn admit_child(&mut self) -> Result<(), Self::Error> {
        self.lifecycle.admit_child()
    }

    fn live_child(&mut self) -> Result<Self::Live<'_>, Self::Error> {
        self.lifecycle.live_child()
    }

    fn stop_before_publication(
        &mut self,
        exit_policy: crate::QemuHotForkChildExitPolicy,
    ) -> Result<(), Self::Error> {
        self.lifecycle.stop_before_publication(exit_policy)
    }

    fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.lifecycle.reconcile_execution_disposition(disposition)
    }

    fn quarantine(&mut self) {
        self.lifecycle.quarantine();
    }
}

impl<F, Q> QemuHotForkAttemptLifecycleFactory for QemuHotForkTemplatePool<F, Q>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
{
    type Lifecycle = QemuHotForkTemplatePoolLifecycle<F::Lifecycle>;
    type Error = QemuHotForkTemplatePoolError<F::Error>;

    fn start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let key = QemuHotForkTemplateKey::for_execution(input, runtime_basis);
        let factories = self.slots.get_mut(&key).ok_or_else(|| {
            AttemptWorkerFailure::Terminal(QemuHotForkTemplatePoolError::MissingTemplate { key })
        })?;
        let (slot, factory) = factories
            .iter_mut()
            .enumerate()
            .filter_map(|(slot, factory)| factory.as_mut().map(|factory| (slot, factory)))
            .find(|(_slot, factory)| factory.template_available())
            .ok_or_else(|| {
                AttemptWorkerFailure::Retryable(QemuHotForkTemplatePoolError::AllTemplatesBusy {
                    key,
                })
            })?;
        factory
            .start(input, context, runtime_basis)
            .map(|lifecycle| QemuHotForkTemplatePoolLifecycle {
                pool: Arc::clone(&self.identity),
                key,
                slot,
                lifecycle,
            })
            .map_err(map_pool_factory_failure)
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>> {
        if !Arc::ptr_eq(&self.identity, &lifecycle.pool) {
            return Err(QemuHotForkAttemptLifecycleRecoveryError::new(
                lifecycle,
                AttemptWorkerFailure::Terminal(QemuHotForkTemplatePoolError::ForeignLifecycle),
            ));
        }
        let Some(factory) = self
            .slots
            .get_mut(&lifecycle.key)
            .and_then(|factories| factories.get_mut(lifecycle.slot))
            .and_then(Option::as_mut)
        else {
            return Err(QemuHotForkAttemptLifecycleRecoveryError::new(
                lifecycle,
                AttemptWorkerFailure::Terminal(QemuHotForkTemplatePoolError::MissingSourceSlot),
            ));
        };
        let QemuHotForkTemplatePoolLifecycle {
            pool,
            key,
            slot,
            lifecycle,
        } = lifecycle;
        factory.recover(lifecycle).map_err(|error| {
            let (lifecycle, failure) = error.into_parts();
            QemuHotForkAttemptLifecycleRecoveryError::new(
                QemuHotForkTemplatePoolLifecycle {
                    pool,
                    key,
                    slot,
                    lifecycle,
                },
                map_pool_factory_failure(failure),
            )
        })
    }

    fn quarantine(&mut self, mut lifecycle: Self::Lifecycle) {
        lifecycle.quarantine();
        self.quarantine.retain_lifecycle(lifecycle);
    }
}

fn map_pool_factory_failure<E>(
    failure: AttemptWorkerFailure<E>,
) -> AttemptWorkerFailure<QemuHotForkTemplatePoolError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuHotForkTemplatePoolError::Factory(Box::new(error)))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuHotForkTemplatePoolError::Factory(Box::new(error)))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuHotForkTemplatePoolError::Factory(Box::new(error)))
        }
    }
}

/// Invalid configured hot-fork template-pool capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuHotForkTemplatePoolCapacityError {
    /// A pool must retain at least its required first worker.
    #[error("hot-fork template-pool capacity is zero")]
    Zero,
    /// The requested pool would exceed the static process bound.
    #[error(
        "hot-fork template-pool capacity {requested} exceeds {MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS}"
    )]
    AboveMaximum {
        /// Rejected requested slot count.
        requested: usize,
    },
}

/// Construction failure retaining the required first worker.
#[must_use = "recover or quarantine the retained source worker"]
pub struct QemuHotForkTemplatePoolConstructionError<F> {
    factory: Box<F>,
    error: QemuHotForkTemplatePoolCapacityError,
}

impl<F> QemuHotForkTemplatePoolConstructionError<F> {
    fn new(factory: F, error: QemuHotForkTemplatePoolCapacityError) -> Self {
        Self {
            factory: Box::new(factory),
            error,
        }
    }

    /// Consumes the error into the unchanged worker and capacity diagnostic.
    pub fn into_parts(self) -> (F, QemuHotForkTemplatePoolCapacityError) {
        (*self.factory, self.error)
    }
}

impl<F> std::fmt::Debug for QemuHotForkTemplatePoolConstructionError<F> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkTemplatePoolConstructionError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Full-pool insertion failure retaining the uninstalled worker.
#[must_use = "recover or quarantine the uninstalled retained source worker"]
pub struct QemuHotForkTemplatePoolInsertionError<F> {
    factory: Box<F>,
}

/// Failure to transfer an exact source worker out of a template pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuHotForkTemplatePoolRetirementError {
    /// The key or stable per-key slot is not installed.
    #[error("hot-fork template retirement names a missing source slot")]
    MissingSlot {
        /// Exact requested lineage/configuration key.
        key: QemuHotForkTemplateKey,
        /// Stable per-key slot index.
        slot: usize,
    },
    /// The exact slot still owns an outstanding child lifecycle.
    #[error("hot-fork template retirement requires an idle source slot")]
    Busy {
        /// Exact requested lineage/configuration key.
        key: QemuHotForkTemplateKey,
        /// Stable per-key slot index.
        slot: usize,
    },
}

impl<F> QemuHotForkTemplatePoolInsertionError<F> {
    /// Consumes the error into the unchanged worker.
    pub fn into_factory(self) -> F {
        *self.factory
    }
}

impl<F> std::fmt::Debug for QemuHotForkTemplatePoolInsertionError<F> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkTemplatePoolInsertionError")
            .finish_non_exhaustive()
    }
}

/// Exact selection or lifecycle-routing failure from a hot-fork template pool.
#[derive(Debug, thiserror::Error)]
pub enum QemuHotForkTemplatePoolError<E> {
    /// No retained source has the request's exact lineage/configuration key.
    #[error("hot-fork template pool has no source for the exact request key")]
    MissingTemplate {
        /// Exact key required by the admitted attempt.
        key: QemuHotForkTemplateKey,
    },
    /// Every exact source worker for this key already owns a child.
    #[error("all exact hot-fork templates for the request key are busy")]
    AllTemplatesBusy {
        /// Exact key whose bounded slots are occupied.
        key: QemuHotForkTemplateKey,
    },
    /// A lifecycle created by another pool was presented for recovery.
    #[error("hot-fork lifecycle belongs to another template pool")]
    ForeignLifecycle,
    /// A pool-qualified lifecycle named no retained stable source slot.
    #[error("hot-fork lifecycle names a missing retained source slot")]
    MissingSourceSlot,
    /// The selected worker rejected launch or recovery.
    #[error("selected hot-fork template worker failed")]
    Factory(Box<E>),
}

#[cfg(test)]
mod tests;
