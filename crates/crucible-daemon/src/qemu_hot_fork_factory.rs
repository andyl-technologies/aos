//! Exact retained-template selection and lifecycle ownership for hot fork.
//!
//! One factory owns one prepared source template for one fixed semantic worker.
//! It exact-binds that source to the campaign lineage and paused configuration,
//! installs a fresh attempt resource guard before each fork, and accepts the
//! source back only after the runner's durable-disposition reconciliation.
//! Failed or foreign authorities move to a process-lifetime quarantine sink;
//! they can never silently repopulate the reusable template slot.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::ContentHash;
use crucible_campaign::CampaignLineageId;
use crucible_qemu::{
    QemuHotForkChildProcessOwner, QemuHotForkLaunchError, QemuNode, QemuPreparedHotForkTemplate,
    QemuVmRealizationError,
};

use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionReconciliationStep,
    AttemptExecutionRuntimeBasis, AttemptWorkerFailure, CrucibleAttemptExecution,
    CrucibleResolvedAttemptStart, LinuxQemuHotForkAttemptLaunchError,
    LinuxQemuHotForkReconciliationBackend, QemuAttemptProcessResourceGuard,
    QemuAttemptResourceGuard, QemuAttemptResourceGuardFactory, QemuHotForkAttemptLifecycle,
    QemuHotForkAttemptLifecycleFactory, QemuHotForkAttemptLifecycleRecoveryError,
    QemuHotForkAttemptReconciliation,
};

/// Exact semantic basis of one retained source template.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct QemuHotForkTemplateKey {
    lineage: CampaignLineageId,
    configuration: ContentHash,
}

impl QemuHotForkTemplateKey {
    /// Binds one lineage to one exact paused configuration.
    #[must_use]
    pub const fn new(lineage: CampaignLineageId, configuration: ContentHash) -> Self {
        Self {
            lineage,
            configuration,
        }
    }

    /// Returns the exact compatibility lineage.
    #[must_use]
    pub const fn lineage(self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the exact paused source configuration.
    #[must_use]
    pub const fn configuration(self) -> ContentHash {
        self.configuration
    }

    pub(crate) fn for_execution(
        input: &CrucibleAttemptExecution,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Self {
        let configuration = match input.start() {
            CrucibleResolvedAttemptStart::Discover { configuration } => configuration.id(),
            CrucibleResolvedAttemptStart::Branch { parent, .. } => parent.id(),
        };
        Self::new(runtime_basis.key().lineage(), configuration)
    }
}

mod sealed {
    pub trait QemuHotForkTemplateSource {}
}

/// Prepared source capability accepted by the fixed template factory.
///
/// This trait is sealed. Production callers cannot substitute a self-asserted
/// configuration for the capability minted by QEMU realization.
pub trait QemuHotForkTemplateSource: sealed::QemuHotForkTemplateSource {
    /// Returns the exact configuration authenticated during source preparation.
    #[must_use]
    fn configuration(&self) -> ContentHash;
}

impl sealed::QemuHotForkTemplateSource for QemuPreparedHotForkTemplate<QemuNode> {}

impl QemuHotForkTemplateSource for QemuPreparedHotForkTemplate<QemuNode> {
    fn configuration(&self) -> ContentHash {
        QemuPreparedHotForkTemplate::configuration(self)
    }
}

/// One exact key paired with its non-forgeable prepared source capability.
#[must_use = "return the template to its factory or transfer it to quarantine"]
pub struct QemuHotForkBoundTemplate<T> {
    key: QemuHotForkTemplateKey,
    source: T,
}

impl<T> QemuHotForkBoundTemplate<T> {
    /// Returns the exact template key.
    #[must_use]
    pub const fn key(&self) -> QemuHotForkTemplateKey {
        self.key
    }

    /// Consumes the binding into its key and prepared source authority.
    pub fn into_parts(self) -> (QemuHotForkTemplateKey, T) {
        (self.key, self.source)
    }
}

impl<T> std::fmt::Debug for QemuHotForkBoundTemplate<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkBoundTemplate")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// Launch adapter preserving the source and target on every failure.
pub trait QemuHotForkTemplateLauncher<G> {
    /// Prepared source-template authority.
    type Template: QemuHotForkTemplateSource;
    /// Exact child lifecycle created after a successful fork.
    type Lifecycle: QemuHotForkAttemptLifecycle;
    /// Launcher or recovery failure.
    type Error;

    /// Forks one exact source into a fresh target owner.
    ///
    /// `input` is the complete repository-resolved semantic execution paired
    /// with `runtime_basis`. The lifecycle must retain or reconstruct this
    /// exact scenario/start basis before exposing modeled child execution.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkTemplateLaunchFailure`] retaining both authorities
    /// whenever launch cannot establish the complete child lifecycle.
    fn launch(
        &mut self,
        template: Self::Template,
        target: G,
        runtime_basis: AttemptExecutionRuntimeBasis,
        input: &CrucibleAttemptExecution,
    ) -> Result<Self::Lifecycle, QemuHotForkTemplateLaunchFailure<Self::Template, G, Self::Error>>;

    /// Recovers the exact source after complete lifecycle reconciliation.
    ///
    /// Implementations must return the same source identity carried into
    /// [`Self::launch`].
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkTemplateSourceRecoveryFailure`] with the unchanged
    /// lifecycle until recovery is safe or after an operational failure.
    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<
        Self::Template,
        QemuHotForkTemplateSourceRecoveryFailure<Self::Lifecycle, Self::Error>,
    >;
}

/// Launch failure retaining exact source and target ownership.
#[must_use = "recover or quarantine both retained launch authorities"]
pub struct QemuHotForkTemplateLaunchFailure<T, G, E> {
    template: T,
    target: G,
    error: E,
}

impl<T, G, E> QemuHotForkTemplateLaunchFailure<T, G, E> {
    /// Retains one failed launch's source, target, and diagnostic.
    pub const fn new(template: T, target: G, error: E) -> Self {
        Self {
            template,
            target,
            error,
        }
    }

    /// Consumes the failure into its exact authorities and diagnostic.
    pub fn into_parts(self) -> (T, G, E) {
        (self.template, self.target, self.error)
    }
}

/// Recovery failure retaining the complete exact lifecycle.
#[must_use = "retry source recovery or quarantine the retained lifecycle"]
pub struct QemuHotForkTemplateSourceRecoveryFailure<L, E> {
    lifecycle: L,
    failure: AttemptWorkerFailure<E>,
}

impl<L, E> QemuHotForkTemplateSourceRecoveryFailure<L, E> {
    /// Retains one recovery token and its classified failure.
    pub const fn new(lifecycle: L, failure: AttemptWorkerFailure<E>) -> Self {
        Self { lifecycle, failure }
    }

    /// Consumes the failure into its exact retry token and diagnostic.
    pub fn into_parts(self) -> (L, AttemptWorkerFailure<E>) {
        (self.lifecycle, self.failure)
    }
}

/// Terminal owner for template and lifecycle authorities that cannot be reused.
///
/// Implementations must not drop either authority while the daemon remains
/// alive. Each fixed factory can transfer at most its one source incarnation,
/// so a conforming sink's retained set is bounded by the configured worker
/// count rather than request volume.
pub trait QemuHotForkFactoryQuarantine<T, L> {
    /// Retains one source that never became a reusable child lifecycle.
    fn retain_template(&mut self, template: QemuHotForkBoundTemplate<T>);

    /// Retains one incomplete, foreign, or failed lifecycle.
    fn retain_lifecycle(&mut self, lifecycle: L);
}

/// Terminal owner for a lifecycle rejected by a multi-template pool.
pub trait QemuHotForkLifecycleQuarantine<L> {
    /// Retains one incomplete, foreign, or failed lifecycle.
    fn retain_lifecycle(&mut self, lifecycle: L);
}

/// Process-lifetime fail-closed quarantine for a fixed template pool.
///
/// The sink deliberately leaks each accepted authority for the remaining
/// daemon lifetime. This is a bounded terminal safety path, not normal cleanup:
/// one factory can contribute at most one authority. A later operator-facing
/// reaper may replace this sink without weakening the factory contract.
#[derive(Clone, Debug, Default)]
pub struct ProcessLifetimeQemuHotForkQuarantine {
    retained: Arc<AtomicUsize>,
}

impl ProcessLifetimeQemuHotForkQuarantine {
    /// Returns the number of exact authorities retained by this sink.
    #[must_use]
    pub fn retained(&self) -> usize {
        self.retained.load(Ordering::Acquire)
    }

    fn retain_forever<A: 'static>(&self, authority: A) {
        self.retained.fetch_add(1, Ordering::AcqRel);
        let _retained_for_process_lifetime = Box::leak(Box::new(authority));
    }
}

impl<T, L> QemuHotForkFactoryQuarantine<T, L> for ProcessLifetimeQemuHotForkQuarantine
where
    T: 'static,
    L: 'static,
{
    fn retain_template(&mut self, template: QemuHotForkBoundTemplate<T>) {
        self.retain_forever(template);
    }

    fn retain_lifecycle(&mut self, lifecycle: L) {
        self.retain_forever(lifecycle);
    }
}

impl<L> QemuHotForkLifecycleQuarantine<L> for ProcessLifetimeQemuHotForkQuarantine
where
    L: 'static,
{
    fn retain_lifecycle(&mut self, lifecycle: L) {
        self.retain_forever(lifecycle);
    }
}

/// Factory-qualified lifecycle that cannot be recovered into another slot.
#[must_use = "reconcile the lifecycle or transfer it to quarantine"]
pub struct QemuHotForkPooledLifecycle<L> {
    factory: Arc<()>,
    key: QemuHotForkTemplateKey,
    lifecycle: L,
}

impl<L> QemuHotForkPooledLifecycle<L> {
    /// Returns the exact retained-template key.
    #[must_use]
    pub const fn template_key(&self) -> QemuHotForkTemplateKey {
        self.key
    }
}

impl<L> QemuHotForkAttemptLifecycle for QemuHotForkPooledLifecycle<L>
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

/// One fixed-worker retained-template factory.
///
/// The factory never shares a source between workers. Its slot is empty while
/// one child lifecycle exists and is repopulated only by exact, factory-bound
/// recovery after durable semantic reconciliation.
pub struct FixedQemuHotForkTemplateFactory<R, X, Q>
where
    R: QemuAttemptResourceGuardFactory,
    X: QemuHotForkTemplateLauncher<R::Guard>,
    Q: QemuHotForkFactoryQuarantine<X::Template, QemuHotForkPooledLifecycle<X::Lifecycle>>,
{
    factory: Arc<()>,
    key: QemuHotForkTemplateKey,
    template: Option<QemuHotForkBoundTemplate<X::Template>>,
    resources: R,
    launcher: X,
    quarantine: Q,
}

/// Construction failure retaining the uninstalled prepared source authority.
#[must_use = "recover or quarantine the prepared source template"]
pub struct FixedQemuHotForkTemplateFactoryConstructionError<T, E> {
    template: Box<T>,
    error: Box<FixedQemuHotForkTemplateFactoryError<E>>,
}

impl<T, E> FixedQemuHotForkTemplateFactoryConstructionError<T, E> {
    /// Consumes the failure into its retained source and diagnostic.
    pub fn into_parts(self) -> (T, FixedQemuHotForkTemplateFactoryError<E>) {
        (*self.template, *self.error)
    }
}

impl<T, E> std::fmt::Debug for FixedQemuHotForkTemplateFactoryConstructionError<T, E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixedQemuHotForkTemplateFactoryConstructionError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<R, X, Q> FixedQemuHotForkTemplateFactory<R, X, Q>
where
    R: QemuAttemptResourceGuardFactory,
    X: QemuHotForkTemplateLauncher<R::Guard>,
    Q: QemuHotForkFactoryQuarantine<X::Template, QemuHotForkPooledLifecycle<X::Lifecycle>>,
{
    /// Creates one fixed factory from an exact prepared source.
    ///
    /// # Errors
    ///
    /// Returns [`FixedQemuHotForkTemplateFactoryError::TemplateConfigurationMismatch`]
    /// when the claimed key differs from the non-forgeable preparation result.
    pub fn new(
        key: QemuHotForkTemplateKey,
        template: X::Template,
        resources: R,
        launcher: X,
        quarantine: Q,
    ) -> Result<Self, FixedQemuHotForkTemplateFactoryConstructionError<X::Template, X::Error>> {
        if template.configuration() != key.configuration() {
            return Err(FixedQemuHotForkTemplateFactoryConstructionError {
                error: Box::new(
                    FixedQemuHotForkTemplateFactoryError::TemplateConfigurationMismatch {
                        expected: key.configuration(),
                        actual: template.configuration(),
                    },
                ),
                template: Box::new(template),
            });
        }
        Ok(Self {
            factory: Arc::new(()),
            key,
            template: Some(QemuHotForkBoundTemplate {
                key,
                source: template,
            }),
            resources,
            launcher,
            quarantine,
        })
    }

    /// Returns whether the source is immediately available for a new child.
    #[must_use]
    pub fn template_available(&self) -> bool {
        self.template.is_some()
    }

    /// Returns the exact immutable key assigned to this worker.
    #[must_use]
    pub const fn template_key(&self) -> QemuHotForkTemplateKey {
        self.key
    }

    /// Takes an idle template for explicit daemon-shutdown cleanup.
    ///
    /// The caller becomes responsible for orderly source-QEMU shutdown or a
    /// nondroppable quarantine transfer. `None` means a runner or quarantine
    /// owner still holds the only source incarnation.
    #[must_use]
    pub fn take_idle_template(&mut self) -> Option<QemuHotForkBoundTemplate<X::Template>> {
        self.template.take()
    }

    /// Transfers a source that failed explicit retirement into quarantine.
    ///
    /// This is intentionally crate-private: only the daemon's authenticated
    /// demotion composition may empty a managed slot and then return a
    /// partially shut down source. The source is never reinstalled as reusable.
    pub(crate) fn quarantine_failed_demotion(
        &mut self,
        template: QemuHotForkBoundTemplate<X::Template>,
    ) {
        self.quarantine.retain_template(template);
    }

    /// Rebinds and quarantines a source returned by consuming teardown.
    pub(crate) fn quarantine_failed_demotion_source(
        &mut self,
        key: QemuHotForkTemplateKey,
        source: X::Template,
    ) {
        self.quarantine
            .retain_template(QemuHotForkBoundTemplate { key, source });
    }

    /// Returns the terminal quarantine's retained-authority count when exposed
    /// by the concrete sink.
    #[must_use]
    pub const fn quarantine_sink(&self) -> &Q {
        &self.quarantine
    }
}

impl<R, X, Q> QemuHotForkAttemptLifecycleFactory for FixedQemuHotForkTemplateFactory<R, X, Q>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptResourceGuard,
    X: QemuHotForkTemplateLauncher<R::Guard>,
    Q: QemuHotForkFactoryQuarantine<X::Template, QemuHotForkPooledLifecycle<X::Lifecycle>>,
{
    type Lifecycle = QemuHotForkPooledLifecycle<X::Lifecycle>;
    type Error = FixedQemuHotForkTemplateFactoryError<X::Error>;

    fn start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let lineage = input
            .lineage()
            .id()
            .map_err(|_source| AttemptWorkerFailure::Terminal(Self::Error::InputLineageMismatch))?;
        if lineage != runtime_basis.key().lineage() {
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::InputLineageMismatch,
            ));
        }
        let expected = QemuHotForkTemplateKey::for_execution(input, runtime_basis);
        let retained = self
            .template
            .as_ref()
            .ok_or_else(|| AttemptWorkerFailure::Terminal(Self::Error::TemplateUnavailable))?;
        if retained.key != expected {
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::TemplateKeyMismatch {
                    expected,
                    actual: retained.key,
                },
            ));
        }

        let target = self
            .resources
            .begin(context.resources(), context.cancellation().clone())
            .map_err(classify_resource_failure)?;
        let retained = self
            .template
            .take()
            .ok_or_else(|| AttemptWorkerFailure::Terminal(Self::Error::TemplateUnavailable))?;
        let QemuHotForkBoundTemplate { key, source } = retained;
        match self.launcher.launch(source, target, runtime_basis, input) {
            Ok(lifecycle) => Ok(QemuHotForkPooledLifecycle {
                factory: Arc::clone(&self.factory),
                key,
                lifecycle,
            }),
            Err(error) => {
                let (source, mut target, error) = error.into_parts();
                target.quarantine();
                self.quarantine
                    .retain_template(QemuHotForkBoundTemplate { key, source });
                Err(AttemptWorkerFailure::Terminal(Self::Error::Launch(error)))
            }
        }
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>> {
        if !Arc::ptr_eq(&self.factory, &lifecycle.factory) {
            return Err(QemuHotForkAttemptLifecycleRecoveryError::new(
                lifecycle,
                AttemptWorkerFailure::Terminal(Self::Error::ForeignLifecycle),
            ));
        }
        if self.template.is_some() {
            return Err(QemuHotForkAttemptLifecycleRecoveryError::new(
                lifecycle,
                AttemptWorkerFailure::Terminal(Self::Error::TemplateSlotOccupied),
            ));
        }
        let QemuHotForkPooledLifecycle {
            factory,
            key,
            lifecycle,
        } = lifecycle;
        match self.launcher.recover(lifecycle) {
            Ok(source) => {
                self.template = Some(QemuHotForkBoundTemplate { key, source });
                Ok(())
            }
            Err(error) => {
                let (lifecycle, failure) = error.into_parts();
                Err(QemuHotForkAttemptLifecycleRecoveryError::new(
                    QemuHotForkPooledLifecycle {
                        factory,
                        key,
                        lifecycle,
                    },
                    failure.map(Self::Error::Recovery),
                ))
            }
        }
    }

    fn quarantine(&mut self, mut lifecycle: Self::Lifecycle) {
        lifecycle.quarantine();
        self.quarantine.retain_lifecycle(lifecycle);
    }
}

impl<R, X, Q> Drop for FixedQemuHotForkTemplateFactory<R, X, Q>
where
    R: QemuAttemptResourceGuardFactory,
    X: QemuHotForkTemplateLauncher<R::Guard>,
    Q: QemuHotForkFactoryQuarantine<X::Template, QemuHotForkPooledLifecycle<X::Lifecycle>>,
{
    fn drop(&mut self) {
        if let Some(template) = self.template.take() {
            self.quarantine.retain_template(template);
        }
    }
}

/// Failure from exact fixed-template selection, launch, or recovery.
#[derive(Debug, thiserror::Error)]
pub enum FixedQemuHotForkTemplateFactoryError<E> {
    /// The supplied key did not match the preparation capability.
    #[error("retained hot-fork template configuration differs from its exact key")]
    TemplateConfigurationMismatch {
        /// Configuration named by the proposed key.
        expected: ContentHash,
        /// Configuration authenticated by preparation.
        actual: ContentHash,
    },
    /// The resolved input lineage differed from the supervisor reservation.
    #[error("hot-fork input lineage differs from the supervisor reservation")]
    InputLineageMismatch,
    /// The worker's one source is active or was quarantined.
    #[error("fixed hot-fork worker has no reusable retained template")]
    TemplateUnavailable,
    /// The available source belongs to another lineage or configuration.
    #[error("retained hot-fork template does not match the requested execution")]
    TemplateKeyMismatch {
        /// Key required by the request.
        expected: QemuHotForkTemplateKey,
        /// Key owned by the source slot.
        actual: QemuHotForkTemplateKey,
    },
    /// A lifecycle from another fixed factory was presented for recovery.
    #[error("hot-fork lifecycle belongs to another fixed template factory")]
    ForeignLifecycle,
    /// Recovery would overwrite a different reusable source authority.
    #[error("fixed hot-fork template slot is already occupied")]
    TemplateSlotOccupied,
    /// Target attempt resource admission failed.
    #[error("hot-fork target resource admission failed")]
    Resource(QemuVmRealizationError),
    /// Source-to-target fork launch failed.
    #[error("retained-template hot-fork launch failed")]
    Launch(E),
    /// Reconciled source recovery failed.
    #[error("retained-template source recovery failed")]
    Recovery(E),
}

fn classify_resource_failure<E>(
    error: QemuVmRealizationError,
) -> AttemptWorkerFailure<FixedQemuHotForkTemplateFactoryError<E>> {
    let retryable = matches!(
        error,
        QemuVmRealizationError::StoreUnavailable { .. }
            | QemuVmRealizationError::ExecutorUnavailable { .. }
    );
    let canceled = matches!(error, QemuVmRealizationError::Canceled { .. });
    let error = FixedQemuHotForkTemplateFactoryError::Resource(error);
    if retryable {
        AttemptWorkerFailure::Retryable(error)
    } else if canceled {
        AttemptWorkerFailure::Canceled(error)
    } else {
        AttemptWorkerFailure::Terminal(error)
    }
}

trait AttemptWorkerFailureMap<E> {
    fn map<T>(self, map: impl FnOnce(E) -> T) -> AttemptWorkerFailure<T>;
}

impl<E> AttemptWorkerFailureMap<E> for AttemptWorkerFailure<E> {
    fn map<T>(self, map: impl FnOnce(E) -> T) -> AttemptWorkerFailure<T> {
        match self {
            Self::Retryable(error) => AttemptWorkerFailure::Retryable(map(error)),
            Self::Canceled(error) => AttemptWorkerFailure::Canceled(map(error)),
            Self::Terminal(error) => AttemptWorkerFailure::Terminal(map(error)),
        }
    }
}

/// Concrete launcher joining a prepared real QEMU source to a target guard.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxQemuHotForkTemplateLauncher;

/// Concrete launch or recovery failure for a retained Linux QEMU source.
#[derive(Debug, thiserror::Error)]
pub enum LinuxQemuHotForkTemplateLauncherError {
    /// The QEMU fork transaction did not establish complete child ownership.
    #[error(transparent)]
    Launch(#[from] QemuHotForkLaunchError),
    /// Recovery was requested before the exact lifecycle completed.
    #[error("hot-fork source recovery requires a completely reconciled lifecycle")]
    IncompleteRecovery,
}

impl<G> QemuHotForkTemplateLauncher<G> for LinuxQemuHotForkTemplateLauncher
where
    G: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<
            Authority = crucible_qemu::LinuxQemuHotForkChildProcessAuthority,
        >,
{
    type Template = QemuPreparedHotForkTemplate<QemuNode>;
    type Lifecycle = QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>;
    type Error = LinuxQemuHotForkTemplateLauncherError;

    fn launch(
        &mut self,
        template: Self::Template,
        target: G,
        runtime_basis: AttemptExecutionRuntimeBasis,
        input: &CrucibleAttemptExecution,
    ) -> Result<Self::Lifecycle, QemuHotForkTemplateLaunchFailure<Self::Template, G, Self::Error>>
    {
        QemuHotForkAttemptReconciliation::launch(runtime_basis, input, template, target).map_err(
            |error: LinuxQemuHotForkAttemptLaunchError<G>| {
                let (source, template, target) = error.into_parts();
                QemuHotForkTemplateLaunchFailure::new(
                    template,
                    target,
                    LinuxQemuHotForkTemplateLauncherError::Launch(source),
                )
            },
        )
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<
        Self::Template,
        QemuHotForkTemplateSourceRecoveryFailure<Self::Lifecycle, Self::Error>,
    > {
        match lifecycle.into_reconciled_backend() {
            Ok(backend) => Ok(backend.into_source()),
            Err(lifecycle) => Err(QemuHotForkTemplateSourceRecoveryFailure::new(
                *lifecycle,
                AttemptWorkerFailure::Terminal(
                    LinuxQemuHotForkTemplateLauncherError::IncompleteRecovery,
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
