//! Owns finite host collection through original publication and reclamation.
//!
//! Preparation reserves the report population before Child. The event loop then
//! drives the same collecting runtime, ticket holder and durable publishers.
//! Refusal keeps original reports and native custody; it never retries a window
//! or converts a finite fixture into ordinary behavioral acceptance.

use std::{
    rc::Rc,
    task::{Context, Poll},
};

use crucible::node_contract::{
    ActivationPublisher, ConformanceResultPublisher, ConformanceRuntime,
};
use crucible_node_contract::{ContentRef, Id};

use super::super::NodeObservedError;
use super::{
    TypedReaderCollectingDriver, TypedReaderCustodySupervisor, TypedReaderDrivingError,
    TypedReaderHostCollection, TypedReaderHostReport, TypedReaderProgramme,
    TypedReaderWitnessAuthority,
};
use crate::node_qualification::{QualificationError, QualificationLimits};

/// Borrows the exact independently installed plan before participant creation.
pub struct TypedReaderHostPreparationRequest<'a> {
    /// Borrows the same installed host/source authority used by the native driver.
    pub authority: &'a Rc<TypedReaderWitnessAuthority>,
    /// Retains the identical programme object held by that authority.
    pub programme: Rc<TypedReaderProgramme>,
    /// Selects one original node within the complete three-participant scope.
    pub node: Id,
    /// Borrows canonical complete plan bytes, including all unexecuted obligations.
    pub plan_bytes: &'a [u8],
    /// Pins those exact plan bytes.
    pub plan: &'a ContentRef,
    /// Bounds the complete original report population before Child.
    pub limits: QualificationLimits,
    /// Bounds each complete original runtime snapshot.
    pub maximum_snapshot_bytes: u64,
}

/// Retains the precredited original report holder before any native participant.
pub struct PreparedTypedReaderHostCollection<'a> {
    authority: &'a Rc<TypedReaderWitnessAuthority>,
    programme: Rc<TypedReaderProgramme>,
    collection: TypedReaderHostCollection<'a>,
}

impl<'a> PreparedTypedReaderHostCollection<'a> {
    /// Checks exact authority/programme identity and reserves all original reports.
    ///
    /// This must precede cohort launch. Package metadata or equivalent programme
    /// bytes cannot substitute another independently installed source authority.
    ///
    /// # Errors
    /// Refuses a foreign programme, changed current plan or incomplete report credit.
    pub fn prepare(
        request: TypedReaderHostPreparationRequest<'a>,
    ) -> Result<Self, QualificationError> {
        if !std::ptr::eq(request.authority.programme(), request.programme.as_ref()) {
            return Err(QualificationError::Refused(
                "typed host programme object differs",
            ));
        }
        let collection = TypedReaderHostCollection::prepare(
            request.authority.as_ref(),
            request.node,
            request.plan_bytes,
            request.plan,
            request.limits,
            request.maximum_snapshot_bytes,
        )?;
        Ok(Self {
            authority: request.authority,
            programme: request.programme,
            collection,
        })
    }

    /// Adopts the original runtime, prior custody supervisor and durable publishers.
    ///
    /// The caller has already prepared every source/session before Child and
    /// consumed its reserved world slot into this collection-only runtime. The
    /// runtime repeats actual plan/world/source checks before activation; this
    /// adoption creates no runtime or authority from scalar data.
    pub fn start<A: ActivationPublisher, R: ConformanceResultPublisher>(
        self,
        runtime: ConformanceRuntime,
        supervisor: TypedReaderCustodySupervisor,
        activation_publisher: A,
        result_publisher: R,
        maximum_initial_record_bytes: usize,
    ) -> TypedReaderHostExecution<'a, A, R> {
        let driver =
            TypedReaderCollectingDriver::new(runtime, self.programme, Rc::clone(self.authority));
        TypedReaderHostExecution {
            driver: Some(driver),
            collection: Some(self.collection),
            report: None,
            supervisor,
            activation_publisher: Some(activation_publisher),
            result_publisher: Some(result_publisher),
            maximum_initial_record_bytes,
            phase: HostPhase::Activate,
            driving_refusal: None,
            reclamation_refusal: None,
            callback_unwound: false,
        }
    }
}

#[derive(Clone, Copy)]
enum HostPhase {
    Activate,
    Begin,
    Close,
    AwaitCompletion,
    Collect,
    Reclaim,
    Finished,
}

/// Retains one actual finite driver, report holder, publishers and cleanup actor.
///
/// Each poll performs one finite transition, or forwards the original native
/// Pending unchanged. No delay, replacement token, extra deadline or ordinary
/// runtime/graph accessor is introduced. Caller cancellation drops the same
/// driver into its prior custody slots; the retained supervisor must still run.
pub struct TypedReaderHostExecution<'a, A, R> {
    driver: Option<TypedReaderCollectingDriver>,
    collection: Option<TypedReaderHostCollection<'a>>,
    report: Option<TypedReaderHostReport>,
    supervisor: TypedReaderCustodySupervisor,
    activation_publisher: Option<A>,
    result_publisher: Option<R>,
    maximum_initial_record_bytes: usize,
    phase: HostPhase,
    driving_refusal: Option<TypedReaderDrivingError>,
    reclamation_refusal: Option<NodeObservedError>,
    callback_unwound: bool,
}

/// Returns original reports and publishers only after actual custody reclamation.
pub struct ReclaimedTypedReaderHostCollection<A, R> {
    /// Retains all original attempts and full authenticated report bodies.
    pub report: TypedReaderHostReport,
    /// Retains the original authentic initial-coordinator publication journal.
    pub activation_publisher: A,
    /// Retains the original completion/body durability journal.
    pub result_publisher: R,
    /// Retains the first original driving refusal without replacing its cause.
    pub driving_refusal: Option<TypedReaderDrivingError>,
    /// Retains the first cleanup refusal even if cleanup later succeeds.
    pub reclamation_refusal: Option<NodeObservedError>,
    /// Records a callback unwind without inferring rollback or absent effects.
    pub callback_unwound: bool,
}

impl<A: ActivationPublisher, R: ConformanceResultPublisher> TypedReaderHostExecution<'_, A, R> {
    /// Borrows the same cleanup actor so cancellation cannot discard its obligation.
    pub fn supervisor(&self) -> &TypedReaderCustodySupervisor {
        &self.supervisor
    }

    /// Borrows retained original reports after collection stops, without authority.
    pub fn report(&self) -> Option<&TypedReaderHostReport> {
        self.report.as_ref()
    }

    /// Advances one original transition and services cleanup through uncertainty.
    ///
    /// Failure and unwind stop further Stage/Begin. Every attempted case remains
    /// explicit. A cleanup refusal is retained and polling continues on this
    /// original supervisor; a Ready result requires authentic complete reclamation.
    /// A second poll after yielding the result returns Pending and has no effects.
    pub fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ReclaimedTypedReaderHostCollection<A, R>> {
        if matches!(self.phase, HostPhase::Finished) {
            return Poll::Pending;
        }
        if matches!(self.phase, HostPhase::Reclaim) {
            return self.poll_reclamation(context);
        }

        let advanced =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.advance(context)));
        match advanced {
            Ok(Poll::Pending) => return Poll::Pending,
            Ok(Poll::Ready(Ok(()))) => {}
            Ok(Poll::Ready(Err(error))) => {
                self.driving_refusal = Some(error);
                self.retire_original();
            }
            Err(_) => {
                self.callback_unwound = true;
                self.retire_original();
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }

    fn advance(&mut self, context: &mut Context<'_>) -> Poll<Result<(), TypedReaderDrivingError>> {
        let Some(driver) = &mut self.driver else {
            return Poll::Ready(Err(invalid()));
        };
        let Some(collection) = &mut self.collection else {
            return Poll::Ready(Err(invalid()));
        };
        let result = match self.phase {
            HostPhase::Activate => match &mut self.activation_publisher {
                Some(publisher) => driver
                    .activate(publisher, self.maximum_initial_record_bytes)
                    .map(|()| HostPhase::Begin),
                None => Err(invalid()),
            },
            HostPhase::Begin => driver.begin_next(collection).map(|()| HostPhase::Close),
            HostPhase::Close => driver.close_original().map(|()| HostPhase::AwaitCompletion),
            HostPhase::AwaitCompletion => match driver.poll_original(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result.map(|()| HostPhase::Collect),
            },
            HostPhase::Collect => match &mut self.result_publisher {
                Some(publisher) => driver.collect_original(publisher, collection).map(|()| {
                    if driver.is_finished() {
                        HostPhase::Reclaim
                    } else {
                        HostPhase::Begin
                    }
                }),
                None => Err(invalid()),
            },
            HostPhase::Reclaim | HostPhase::Finished => Err(invalid()),
        };
        match result {
            Ok(phase) => {
                self.phase = phase;
                if matches!(phase, HostPhase::Reclaim) {
                    self.retire_original();
                }
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn retire_original(&mut self) {
        // Finish calls only fixed closed-record validation/serialization, not
        // an installed/native callback. Retain these journals before runtime
        // Drop transfers custody through its actual prior typed world slot.
        if let Some(collection) = self.collection.take() {
            self.report = Some(collection.finish());
        }
        self.phase = HostPhase::Reclaim;
        let original = self.driver.take();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(original))).is_err() {
            // The actual typed slot owns cleanup; catch alone cannot establish
            // native containment or resurrect resources from a foreign slot.
            self.callback_unwound = true;
        }
    }

    fn poll_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ReclaimedTypedReaderHostCollection<A, R>> {
        let original = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.supervisor.poll_reclamation(context)
        }));
        match original {
            Err(_) => {
                // Actual world/typed Polling guards restore the same native
                // capsule on unwind. Keep its supervisor and prior reports.
                self.callback_unwound = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(Err(error))) => {
                if self.reclamation_refusal.is_none() {
                    self.reclamation_refusal = Some(error);
                }
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(Poll::Ready(Ok(()))) => {
                let (Some(report), Some(activation_publisher), Some(result_publisher)) = (
                    self.report.take(),
                    self.activation_publisher.take(),
                    self.result_publisher.take(),
                ) else {
                    self.phase = HostPhase::Finished;
                    return Poll::Pending;
                };
                self.phase = HostPhase::Finished;
                Poll::Ready(ReclaimedTypedReaderHostCollection {
                    report,
                    activation_publisher,
                    result_publisher,
                    driving_refusal: self.driving_refusal.take(),
                    reclamation_refusal: self.reclamation_refusal.take(),
                    callback_unwound: self.callback_unwound,
                })
            }
        }
    }
}

fn invalid() -> TypedReaderDrivingError {
    TypedReaderDrivingError::Transition("original typed host execution ownership differs")
}
