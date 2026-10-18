//! Preserves typed retirement reports and same-Original dispatcher observations.
//!
//! Main owns one finite inline history. Each phase retains its first cause;
//! actual owners retain all physical custody and their independent closure latch.

use super::*;
use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};
use exact_pin_materializer::original_retirement::OriginalMaterializerRetirementError;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug)]
enum RetirementCause {
    Admission,
    Materializer,
    Sources,
    Controls,
    Lifecycle,
    BeforeDispatch,
    Dispatcher,
    Post,
}

/// Retains independent attached cleanup failures in the actual priced Main.
///
/// Each phase publishes at most its first typed cause. Later attempts can add
/// another phase without replacing prior failures. The first published phase
/// remains the error-chain source. These fields contain no resource owner,
/// factory, account, or cleanup reservation.
#[derive(Debug)]
pub struct PackagedQemuExecutorRetirementError {
    first: OnceLock<RetirementCause>,
    admission: OnceLock<crucible_host_resources::host_services::process_birth::ServiceBirthError>,
    materializer: OnceLock<OriginalMaterializerRetirementError>,
    sources: OnceLock<PackagedQemuHotForkSourceShutdownError>,
    controls: OnceLock<crate::campaign_process::ExecutorControlRetirementError>,
    lifecycle: OnceLock<crucible_control_api::LifecycleApiError>,
    before_dispatch: OnceLock<HostSupervisionError>,
    dispatcher: OnceLock<QemuVmRealizationError>,
    post: OnceLock<HostSupervisionError>,
}

impl PackagedQemuExecutorRetirementError {
    pub(crate) const fn new() -> Self {
        Self {
            first: OnceLock::new(),
            admission: OnceLock::new(),
            materializer: OnceLock::new(),
            sources: OnceLock::new(),
            controls: OnceLock::new(),
            lifecycle: OnceLock::new(),
            before_dispatch: OnceLock::new(),
            dispatcher: OnceLock::new(),
            post: OnceLock::new(),
        }
    }

    pub(crate) fn retain(&self, step: AttachedRetirementReport) {
        self.record(&self.admission, step.admission, RetirementCause::Admission);
        self.record(
            &self.materializer,
            step.materializer,
            RetirementCause::Materializer,
        );
        self.record(&self.sources, step.sources, RetirementCause::Sources);
        // Preserve the existing component report's first-cause precedence.
        self.record(&self.lifecycle, step.lifecycle, RetirementCause::Lifecycle);
        self.record(&self.controls, step.controls, RetirementCause::Controls);
        self.record(
            &self.before_dispatch,
            step.dispatch.before,
            RetirementCause::BeforeDispatch,
        );
        self.record(
            &self.dispatcher,
            step.dispatch.failure,
            RetirementCause::Dispatcher,
        );
        self.record(&self.post, step.dispatch.post, RetirementCause::Post);
    }

    fn record<T>(&self, cell: &OnceLock<T>, value: Option<T>, kind: RetirementCause) {
        if let Some(value) = value {
            cell.get_or_init(|| value);
            self.first.get_or_init(|| kind);
        }
    }

    pub(crate) fn has_failure(&self) -> bool {
        self.first.get().is_some()
    }

    /// Borrows the same Main's saved Cleanup admission refusal.
    #[must_use]
    pub fn admission(
        &self,
    ) -> Option<&crucible_host_resources::host_services::process_birth::ServiceBirthError> {
        self.admission.get()
    }

    /// Borrows the actual materializer retirement refusal.
    #[must_use]
    pub fn materializer(&self) -> Option<&OriginalMaterializerRetirementError> {
        self.materializer.get()
    }

    /// Borrows the retained source-world shutdown refusal.
    #[must_use]
    pub fn sources(&self) -> Option<&PackagedQemuHotForkSourceShutdownError> {
        self.sources.get()
    }

    /// Borrows the same Main's worker and lifecycle control report.
    #[must_use]
    pub fn controls(&self) -> Option<&crate::campaign_process::ExecutorControlRetirementError> {
        self.controls.get()
    }

    /// Borrows the actual lifecycle queue refusal.
    #[must_use]
    pub fn lifecycle(&self) -> Option<&crucible_control_api::LifecycleApiError> {
        self.lifecycle.get()
    }

    /// Returns the same Original's first refusal before dispatcher effects.
    #[must_use]
    pub fn before_dispatch(&self) -> Option<HostSupervisionError> {
        self.before_dispatch.get().copied()
    }

    /// Borrows the actual dispatcher refusal, independently of earlier failures.
    #[must_use]
    pub fn dispatcher(&self) -> Option<&QemuVmRealizationError> {
        self.dispatcher.get()
    }

    /// Returns the independent same-Original post retained in cleanup history.
    #[must_use]
    pub fn original_post(&self) -> Option<HostSupervisionError> {
        self.post.get().copied()
    }
}

impl std::fmt::Display for PackagedQemuExecutorRetirementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "attached cleanup: admission={:?}; materializer={:?}; sources={:?}; controls={:?}; lifecycle={:?}; before dispatcher={:?}; dispatcher={:?}; post={:?}",
            self.admission(),
            self.materializer(),
            self.sources(),
            self.controls(),
            self.lifecycle(),
            self.before_dispatch(),
            self.dispatcher(),
            self.original_post()
        )
    }
}

impl std::error::Error for PackagedQemuExecutorRetirementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first.get()? {
            RetirementCause::Admission => self
                .admission
                .get()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Materializer => self
                .materializer
                .get()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Sources => self
                .sources
                .get()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Controls => self
                .controls
                .get()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Lifecycle => self
                .lifecycle
                .get()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::BeforeDispatch => self
                .before_dispatch
                .get()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Dispatcher => self
                .dispatcher
                .get()
                .map(|error| error as &dyn std::error::Error),
            RetirementCause::Post => self.post.get().map(|error| error as &dyn std::error::Error),
        }
    }
}

/// Moves an attempt's existing diagnostics into Main without a heap carrier.
pub(crate) struct AttachedRetirementReport {
    admission: Option<crucible_host_resources::host_services::process_birth::ServiceBirthError>,
    materializer: Option<OriginalMaterializerRetirementError>,
    sources: Option<PackagedQemuHotForkSourceShutdownError>,
    controls: Option<crate::campaign_process::ExecutorControlRetirementError>,
    lifecycle: Option<crucible_control_api::LifecycleApiError>,
    dispatch: DispatcherRetirement,
}

impl AttachedRetirementReport {
    pub(crate) fn new(
        materializer: Option<OriginalMaterializerRetirementError>,
        sources: Option<PackagedQemuHotForkSourceShutdownError>,
        controls: Option<crate::campaign_process::ExecutorControlRetirementError>,
        lifecycle: Option<crucible_control_api::LifecycleApiError>,
        dispatch: DispatcherRetirement,
    ) -> Self {
        Self {
            admission: None,
            materializer,
            sources,
            controls,
            lifecycle,
            dispatch,
        }
    }

    pub(crate) fn from_admission(
        source: crucible_host_resources::host_services::process_birth::ServiceBirthError,
    ) -> Self {
        Self {
            admission: Some(source),
            ..Self::new(None, None, None, None, DispatcherRetirement::default())
        }
    }

    pub(crate) fn from_post(post: HostSupervisionError) -> Self {
        Self::new(
            None,
            None,
            None,
            None,
            DispatcherRetirement {
                post: Some(post),
                ..DispatcherRetirement::default()
            },
        )
    }

    /// Preserves the actual body's earliest post without changing phase order.
    pub(crate) fn with_first_post(mut self, first: Option<HostSupervisionError>) -> Self {
        if let Some(first) = first {
            self.dispatch.post = Some(first);
        }
        self
    }

    pub(super) fn has_failure(&self) -> bool {
        self.admission.is_some()
            || self.materializer.is_some()
            || self.sources.is_some()
            || self.controls.is_some()
            || self.lifecycle.is_some()
            || self.dispatch.before.is_some()
            || self.dispatch.failure.is_some()
            || self.dispatch.post.is_some()
    }
}

pub(crate) enum AttachedRetirementFailure {
    Pending,
    Report(AttachedRetirementReport),
}

/// Owns only actual observations; the physical latch stays with the caller.
#[derive(Debug, Default)]
pub(crate) struct DispatcherRetirement {
    pub(crate) before: Option<HostSupervisionError>,
    pub(crate) failure: Option<QemuVmRealizationError>,
    pub(crate) post: Option<HostSupervisionError>,
}

/// Runs at most one dispatcher effect under the same borrowed Original.
///
/// The effect returns its typed outcome and the actual owner's physical
/// observation together. Closure is latched before the independent post, even
/// beside a historical failure. Failed admission never invokes the effect or
/// renews time, and only an observed closure prevents a later retry.
pub(crate) fn retire_dispatcher(
    original: &HostOperationGuard,
    prerequisites_closed: bool,
    physically_closed: &mut bool,
    attempt: impl FnOnce() -> (Result<(), QemuVmRealizationError>, bool),
) -> DispatcherRetirement {
    let mut result = DispatcherRetirement::default();
    if prerequisites_closed && !*physically_closed {
        result.before = original.wait_slice().err();
        if result.before.is_none() {
            let (work, observed_closed) = attempt();
            *physically_closed = observed_closed;
            result.failure = work.err();
        }
    }
    result.post = original.wait_slice().err();
    result
}
