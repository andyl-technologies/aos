//! Retains concrete failures from native observation and assertion drivers.
//!
//! Assertions and configuration refusals carry diagnostic text. Operational
//! failures retain their original typed cause until the enclosing worker and
//! its independently retained cleanup history are disposed.

use std::borrow::Cow;
use std::sync::Arc;

/// A native observation refusal with its original operational cause.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeObservationError {
    /// An authored invariant or observation assertion was not satisfied.
    #[error("{0}")]
    Assertion(Cow<'static, str>),
    /// A bounded evidence or trace operation failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// A lifecycle operation refused its current state or authority.
    #[error("{0}")]
    Lifecycle(#[source] Box<crucible_control_api::LifecycleApiError>),
    /// The actual retained Source refused construction or observation.
    #[error("{0}")]
    Source(#[source] Box<crate::QemuAttemptProductionVmLifecycleError>),
    /// The admitted evidence catalog or backing store refused an operation.
    #[error("{0}")]
    Store(#[source] Box<crucible_store::content_store::StoreError>),
    /// The observed QEMU node returned a concrete failure.
    #[error("{0}")]
    Node(#[source] Arc<crucible_qemu_host::QemuNodeError>),
    /// The scheduler-facing backend refused an operation.
    #[error("{0}")]
    Backend(#[source] Box<crucible_engine::BackendError>),
    /// The node control or observation channel failed.
    #[error("{0}")]
    Channel(#[source] Box<crucible_qemu_host::QemuNodeChannelError>),
    /// A retained runtime trace could not be read or authenticated.
    #[error("{0}")]
    RuntimeTrace(#[source] Box<crucible_qemu_host::QemuRuntimeDeterminismTraceError>),
    /// The actual node process could not be launched.
    #[error("{0}")]
    Spawn(#[source] Box<crucible_qemu_host::QemuSpawnError>),
    /// The bounded preemption evidence could not be obtained.
    #[error("{0}")]
    Preemption(#[source] Box<crucible_qemu_host::BoundedSchedulerPreemptionEvidenceError>),
    /// The native node launch gate refused its configuration or observation.
    #[error("{0}")]
    LaunchGate(#[source] Box<crucible_qemu_host::QemuLiveNodeStepGateError>),
    /// The real hot-fork child resources could not be prepared.
    #[error("{0}")]
    HotForkPreparation(#[source] Box<crucible_qemu_host::QemuHotForkChildResourcePreparationError>),
    /// The same preclaimed Main role refused observation access.
    #[error("{0}")]
    Preclaim(#[source] Box<crate::lifecycle_cleanup::ServiceMainPreclaimError>),
    /// The protected Source retained the actual observation refusal.
    #[error("{0}")]
    PreparedSource(#[source] Box<crate::PreparedSourceFailure>),
    /// The actual process and resource realization refused observation.
    #[error("{0}")]
    Realization(#[source] Box<crucible_qemu_host::QemuVmRealizationError>),
    /// The selectable control protocol refused its record.
    #[error("{0}")]
    SelectableProtocol(#[source] Box<crucible_qemu_protocol::SelectableProtocolError>),
    /// The selectable declaration or plan was invalid.
    #[error("{0}")]
    SelectablePlan(
        #[source] Box<crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlanError>,
    ),
    /// A bounded owned trace row was not valid UTF-8.
    #[error("{0}")]
    OwnedUtf8(#[source] Box<std::string::FromUtf8Error>),
    /// A real block device refused the observed transition or read.
    #[error("{0}")]
    Block(#[source] Box<crucible_qemu_host::QemuLiveBlockIoServicerError>),
    /// An observation retained its concrete first failure with passive context.
    #[error("{0}")]
    Context(#[source] Box<NativeObservationContext>),
    /// An observation failed before separately attempted cleanup or trace reads.
    #[error("{0}")]
    Cleanup(#[source] Box<NativeObservationCleanupError>),
    /// A checked integer conversion exceeded its representation.
    #[error("{0}")]
    Integer(#[from] std::num::TryFromIntError),
    /// A bounded borrowed trace row was not valid UTF-8.
    #[error("{0}")]
    Utf8(#[from] std::str::Utf8Error),
    /// The observation callback attempted an overlapping mutable borrow.
    #[error("{0}")]
    Borrow(#[from] std::cell::BorrowMutError),
}

impl NativeObservationError {
    /// Retains independently observed outcomes without replacing the first cause.
    pub(crate) fn with_cleanup(
        self,
        context: String,
        shutdown: Option<
            Result<crucible_qemu_host::QemuShutdownReport, crucible_qemu_host::QemuNodeError>,
        >,
        finish: Option<Result<(), crate::QemuAttemptProductionVmLifecycleError>>,
        trace: Option<Result<String, Self>>,
    ) -> Self {
        Self::Cleanup(Box::new(NativeObservationCleanupError {
            first: self,
            context,
            shutdown,
            finish,
            trace,
        }))
    }
}

impl From<&'static str> for NativeObservationError {
    fn from(message: &'static str) -> Self {
        Self::Assertion(Cow::Borrowed(message))
    }
}

impl From<String> for NativeObservationError {
    fn from(message: String) -> Self {
        Self::Assertion(Cow::Owned(message))
    }
}

impl From<crate::QemuAttemptProductionVmLifecycleError> for NativeObservationError {
    fn from(source: crate::QemuAttemptProductionVmLifecycleError) -> Self {
        Self::Source(Box::new(source))
    }
}

impl From<crucible_control_api::LifecycleApiError> for NativeObservationError {
    fn from(source: crucible_control_api::LifecycleApiError) -> Self {
        Self::Lifecycle(Box::new(source))
    }
}

impl From<crucible_store::content_store::StoreError> for NativeObservationError {
    fn from(source: crucible_store::content_store::StoreError) -> Self {
        Self::Store(Box::new(source))
    }
}

impl From<crucible_qemu_host::QemuNodeError> for NativeObservationError {
    fn from(source: crucible_qemu_host::QemuNodeError) -> Self {
        Self::Node(Arc::new(source))
    }
}

impl From<crucible_engine::BackendError> for NativeObservationError {
    fn from(source: crucible_engine::BackendError) -> Self {
        Self::Backend(Box::new(source))
    }
}

impl From<crucible_qemu_host::QemuNodeChannelError> for NativeObservationError {
    fn from(source: crucible_qemu_host::QemuNodeChannelError) -> Self {
        Self::Channel(Box::new(source))
    }
}

impl From<crucible_qemu_host::QemuRuntimeDeterminismTraceError> for NativeObservationError {
    fn from(source: crucible_qemu_host::QemuRuntimeDeterminismTraceError) -> Self {
        Self::RuntimeTrace(Box::new(source))
    }
}

impl From<crucible_qemu_host::QemuSpawnError> for NativeObservationError {
    fn from(source: crucible_qemu_host::QemuSpawnError) -> Self {
        Self::Spawn(Box::new(source))
    }
}

impl From<crucible_qemu_host::BoundedSchedulerPreemptionEvidenceError> for NativeObservationError {
    fn from(source: crucible_qemu_host::BoundedSchedulerPreemptionEvidenceError) -> Self {
        Self::Preemption(Box::new(source))
    }
}

impl From<crucible_qemu_host::QemuLiveNodeStepGateError> for NativeObservationError {
    fn from(source: crucible_qemu_host::QemuLiveNodeStepGateError) -> Self {
        Self::LaunchGate(Box::new(source))
    }
}

impl From<crucible_qemu_host::QemuHotForkChildResourcePreparationError> for NativeObservationError {
    fn from(source: crucible_qemu_host::QemuHotForkChildResourcePreparationError) -> Self {
        Self::HotForkPreparation(Box::new(source))
    }
}

impl From<crate::lifecycle_cleanup::ServiceMainPreclaimError> for NativeObservationError {
    fn from(source: crate::lifecycle_cleanup::ServiceMainPreclaimError) -> Self {
        Self::Preclaim(Box::new(source))
    }
}

impl From<crucible_qemu_host::QemuVmRealizationError> for NativeObservationError {
    fn from(source: crucible_qemu_host::QemuVmRealizationError) -> Self {
        Self::Realization(Box::new(source))
    }
}

impl From<crucible_qemu_protocol::SelectableProtocolError> for NativeObservationError {
    fn from(source: crucible_qemu_protocol::SelectableProtocolError) -> Self {
        Self::SelectableProtocol(Box::new(source))
    }
}

impl From<crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlanError>
    for NativeObservationError
{
    fn from(
        source: crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlanError,
    ) -> Self {
        Self::SelectablePlan(Box::new(source))
    }
}

impl From<std::string::FromUtf8Error> for NativeObservationError {
    fn from(source: std::string::FromUtf8Error) -> Self {
        Self::OwnedUtf8(Box::new(source))
    }
}

impl From<Box<crate::PreparedSourceFailure>> for NativeObservationError {
    fn from(source: Box<crate::PreparedSourceFailure>) -> Self {
        Self::PreparedSource(source)
    }
}

impl From<crucible_qemu_host::QemuLiveBlockIoServicerError> for NativeObservationError {
    fn from(source: crucible_qemu_host::QemuLiveBlockIoServicerError) -> Self {
        Self::Block(Box::new(source))
    }
}

/// A concrete observation refusal and its passive diagnostic context.
#[derive(Debug, thiserror::Error)]
#[error(
    "production flight failed during {phase}: source={source}; idle_state={idle_state:?}; calibration={calibration:?}; timer_witness={timer_witness:?}"
)]
pub(crate) struct NativeObservationContext {
    /// Actual failure returned by the observed operation.
    #[source]
    pub(crate) source: NativeObservationError,
    /// Phase in which the initiating operation failed.
    pub(crate) phase: String,
    /// Independently observed idle state or its unchanged query failure.
    pub(crate) idle_state:
        Result<crucible_qemu_host::QemuNodeIdleState, Arc<crucible_qemu_host::QemuNodeError>>,
    /// Existing logical/raw coordinates or their unchanged query failure.
    pub(crate) calibration: Result<
        crucible_qemu_host::QemuLogicalTimeCalibration,
        Arc<crucible_qemu_host::QemuNodeError>,
    >,
    /// Existing timer witness or its unchanged query failure.
    pub(crate) timer_witness: Result<
        Option<crucible_qemu_host::QemuVirtualTimerFireWitness>,
        Arc<crucible_qemu_host::QemuNodeError>,
    >,
}

/// Keeps the first failure and the separately attempted cleanup outcomes.
#[derive(Debug, thiserror::Error)]
#[error(
    "{context}: {first}; diagnostic_shutdown={shutdown:?}; diagnostic_finish={finish:?}; retained_native_rr_trace={trace:?}"
)]
pub(crate) struct NativeObservationCleanupError {
    /// Actual initiating cause, retained independently of later operations.
    #[source]
    first: NativeObservationError,
    /// Observation phase and passive state at its failure boundary.
    context: String,
    /// Secondary shutdown outcome, absent when shutdown is the first failure.
    shutdown:
        Option<Result<crucible_qemu_host::QemuShutdownReport, crucible_qemu_host::QemuNodeError>>,
    /// Secondary finish outcome, absent when finish is the first failure.
    finish: Option<Result<(), crate::QemuAttemptProductionVmLifecycleError>>,
    /// Retained trace or its actual read failure when collection was requested.
    trace: Option<Result<String, NativeObservationError>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct RetainedCause(Arc<AtomicUsize>);

    impl std::fmt::Display for RetainedCause {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("retained observation cause")
        }
    }

    impl Error for RetainedCause {}

    impl Drop for RetainedCause {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn diagnostic_context_retains_the_original_error_until_disposal() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let io = std::io::Error::other(RetainedCause(Arc::clone(&dropped)));
        let original = io.get_ref().unwrap() as *const _;
        let passive_failures: [_; 3] = std::array::from_fn(|_| {
            Arc::new(crucible_qemu_host::QemuNodeError::CoverageEventLogRequired)
        });
        let passive_lifetimes = passive_failures.each_ref().map(Arc::downgrade);
        let [idle_state, calibration, timer_witness] = passive_failures;

        let failure = NativeObservationError::Context(Box::new(NativeObservationContext {
            source: io.into(),
            phase: String::from("passive state at the failed observation"),
            idle_state: Err(idle_state),
            calibration: Err(calibration),
            timer_witness: Err(timer_witness),
        }));

        let NativeObservationError::Context(context) = &failure else {
            panic!("passive outcomes must remain in the context owner");
        };
        for (retained, lifetime) in [
            context.idle_state.as_ref().unwrap_err(),
            context.calibration.as_ref().unwrap_err(),
            context.timer_witness.as_ref().unwrap_err(),
        ]
        .into_iter()
        .zip(&passive_lifetimes)
        {
            assert!(std::ptr::eq(Arc::as_ptr(retained), lifetime.as_ptr()));
            assert!(matches!(
                retained.as_ref(),
                crucible_qemu_host::QemuNodeError::CoverageEventLogRequired
            ));
        }

        let mut source: &(dyn Error + 'static) = &failure;
        let retained = loop {
            if let Some(io) = source.downcast_ref::<std::io::Error>() {
                break io;
            }
            source = source.source().unwrap();
        };
        assert!(std::ptr::eq(retained.get_ref().unwrap(), original));
        assert!(retained.get_ref().unwrap().is::<RetainedCause>());
        assert_eq!(dropped.load(Ordering::SeqCst), 0);

        drop(failure);

        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(
            passive_lifetimes
                .iter()
                .all(|cause| cause.upgrade().is_none())
        );
    }

    #[test]
    fn failure_carriers_keep_a_fixed_small_inline_footprint() {
        assert!(std::mem::size_of::<NativeObservationError>() <= 4 * std::mem::size_of::<usize>());
    }

    #[test]
    fn cleanup_and_trace_outcomes_do_not_replace_or_dispose_the_first_cause() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let original = std::io::Error::other(RetainedCause(Arc::clone(&dropped)));
        let original_cause = original.get_ref().unwrap() as *const _;

        let failure = NativeObservationError::from(original).with_cleanup(
            String::from("failed native observation"),
            Some(Err(
                crucible_qemu_host::QemuNodeError::CoverageEventLogRequired,
            )),
            None,
            Some(Err(std::io::Error::from_raw_os_error(5).into())),
        );

        let NativeObservationError::Cleanup(history) = &failure else {
            panic!("cleanup outcomes must remain in their owning carrier");
        };
        let NativeObservationError::Io(first) = &history.first else {
            panic!("the initiating I/O failure must retain its concrete type");
        };
        assert!(std::ptr::eq(first.get_ref().unwrap(), original_cause));
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert!(matches!(
            history.shutdown,
            Some(Err(
                crucible_qemu_host::QemuNodeError::CoverageEventLogRequired
            ))
        ));
        assert!(history.finish.is_none());
        let Some(Err(NativeObservationError::Io(trace))) = &history.trace else {
            panic!("the independent trace read must retain its concrete failure");
        };
        assert_eq!(trace.raw_os_error(), Some(5));

        drop(failure);

        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}
