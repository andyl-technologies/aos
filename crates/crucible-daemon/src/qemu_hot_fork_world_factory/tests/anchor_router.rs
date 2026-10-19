//! Hot-first routing through an anchor root before thin replay.

use std::collections::VecDeque;

use super::ancestor_runner::{Edge, SuffixLifecycle, SuffixObservations, SuffixWorld, suffix_case};
use super::*;
use crate::qemu_hot_first_router::QemuHotFirstExecutionRouterError;
use crate::{QemuAnchorRootMaterializer, QemuAnchorRootOutcome};

/// Hot factory that declines or starts at a scripted root, call by call.
struct ScriptedStartFactory {
    world: SuffixWorld,
    /// Root quanta for each successive start; `None` declines.
    starts: VecDeque<Option<u64>>,
    calls: Arc<AtomicUsize>,
    observations: SuffixObservations,
}

impl QemuHotForkWorldLifecycleFactory for ScriptedStartFactory {
    type Lifecycle = SuffixLifecycle;
    type Error = Infallible;

    fn try_start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(match self.starts.pop_front().flatten() {
            Some(quanta) => QemuHotForkWorldLifecycleStart::Started(self.world.lifecycle_at(
                quanta,
                QemuHotForkStartOrigin::Exact,
                context.runtime_basis(),
                &self.observations,
            )),
            None => QemuHotForkWorldLifecycleStart::Declined,
        })
    }

    fn recover(&mut self, _lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        self.observations.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn quarantine(&mut self, _lifecycle: Self::Lifecycle) {
        self.observations.quarantines.fetch_add(1, Ordering::SeqCst);
    }
}

/// Lower tier with a scripted anchor answer and a thin replay that only counts.
struct AnchoringFallback {
    anchor: QemuAnchorRootOutcome,
    /// Quanta the anchoring replay charges to the execution.
    anchor_quanta: u64,
    anchor_calls: Arc<AtomicUsize>,
    thin_calls: Arc<AtomicUsize>,
}

impl CrucibleExecutionRunner for AnchoringFallback {
    type Error = &'static str;

    fn execute(
        &mut self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.thin_calls.fetch_add(1, Ordering::SeqCst);
        Err(AttemptWorkerFailure::Terminal("thin replay ran"))
    }
}

impl QemuAnchorRootMaterializer for AnchoringFallback {
    fn materialize_anchor_root(
        &mut self,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuAnchorRootOutcome, AttemptWorkerFailure<Self::Error>> {
        self.anchor_calls.fetch_add(1, Ordering::SeqCst);
        for _ in 0..self.anchor_quanta {
            context
                .charge_execution_quantum()
                .map_err(|_error| AttemptWorkerFailure::Terminal("anchor budget"))?;
        }
        Ok(self.anchor)
    }
}

/// Counters a routed attempt is judged by.
struct RouteCounts {
    hot_starts: Arc<AtomicUsize>,
    anchors: Arc<AtomicUsize>,
    thin: Arc<AtomicUsize>,
}

type ScriptedRouter =
    QemuHotFirstExecutionRouter<ScriptedStartFactory, QemuFreshModeledDriver, AnchoringFallback>;

fn router(
    starts: &[Option<u64>],
    anchor: QemuAnchorRootOutcome,
    anchor_quanta: u64,
) -> (ScriptedRouter, RouteCounts, CrucibleAttemptExecution) {
    let case = suffix_case(Edge::Scheduler);
    let counts = RouteCounts {
        hot_starts: Arc::new(AtomicUsize::new(0)),
        anchors: Arc::new(AtomicUsize::new(0)),
        thin: Arc::new(AtomicUsize::new(0)),
    };
    let hot = QemuHotForkWorldExecutionRunner::new(
        ScriptedStartFactory {
            world: SuffixWorld::for_case(&case, Edge::Scheduler),
            starts: starts.iter().copied().collect(),
            calls: Arc::clone(&counts.hot_starts),
            observations: SuffixObservations::default(),
        },
        QemuFreshModeledDriver::new(),
    );
    let fallback = AnchoringFallback {
        anchor,
        anchor_quanta,
        anchor_calls: Arc::clone(&counts.anchors),
        thin_calls: Arc::clone(&counts.thin),
    };
    (
        QemuHotFirstExecutionRouter::new(hot, fallback),
        counts,
        case.input,
    )
}

fn loads(counts: &RouteCounts) -> [usize; 3] {
    [
        counts.hot_starts.load(Ordering::SeqCst),
        counts.anchors.load(Ordering::SeqCst),
        counts.thin.load(Ordering::SeqCst),
    ]
}

/// After an admitted anchor the attempt itself runs hot from the new root.
#[test]
fn router_keeps_an_anchor_then_runs_the_attempt_hot() {
    // The retry starts from a root at the attempt's parent, two quanta in.
    let (mut router, counts, input) = router(&[None, Some(2)], QemuAnchorRootOutcome::Admitted, 0);

    let outcome = router
        .execute(&input, &execution_context(&input, 0xa1))
        .expect("anchored hot execution");

    assert_eq!(
        outcome.materialization(),
        CrucibleMaterializationTier::HotFork
    );
    assert_eq!(loads(&counts), [2, 1, 0]);
}

/// Every decline replays thin, including an anchor key whose root was
/// invalidated: that is never a kept root, so it can never requeue.
#[test]
fn router_replays_thin_when_anchoring_declines() {
    for reason in [
        "anchor-parent-not-network-branch",
        "anchor-root-invalidated",
    ] {
        let (mut router, counts, input) =
            router(&[None], QemuAnchorRootOutcome::Declined(reason), 0);

        let failure = router
            .execute(&input, &execution_context(&input, 0xa2))
            .expect_err("the counting thin tier fails");

        assert!(
            matches!(
                failure,
                AttemptWorkerFailure::Terminal(QemuHotFirstExecutionRouterError::Fallback(
                    "thin replay ran"
                ))
            ),
            "{reason}"
        );
        assert_eq!(loads(&counts), [1, 1, 1], "{reason}");
    }
}

/// A hot retry that declines after anchoring falls back to thin replay
/// while the execution can still afford the anchored prefix again.
#[test]
fn router_replays_thin_after_an_anchor_when_budget_remains() {
    let (mut router, counts, input) = router(&[None, None], QemuAnchorRootOutcome::Admitted, 8);

    let failure = router
        .execute(&input, &execution_context(&input, 0xa3))
        .expect_err("the counting thin tier fails");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Terminal(QemuHotFirstExecutionRouterError::Fallback(_))
    ));
    assert_eq!(loads(&counts), [2, 1, 1]);
}

/// When anchoring spent too much of the budget for a second replay, the
/// attempt retries instead, and the retry finds the kept root.
#[test]
fn router_retries_instead_of_replaying_an_anchored_prefix_twice() {
    // The fixture context allows 64 quanta; anchoring spends 40 of them.
    let (mut router, counts, input) = router(&[None, None], QemuAnchorRootOutcome::Admitted, 40);

    let failure = router
        .execute(&input, &execution_context(&input, 0xa4))
        .expect_err("an unaffordable second replay is refused");

    assert!(matches!(
        failure,
        AttemptWorkerFailure::Retryable(QemuHotFirstExecutionRouterError::AnchorRetryUnaffordable)
    ));
    assert_eq!(loads(&counts), [2, 1, 0]);
}

/// Resumes and captures bypass hot fork, and with it anchoring.
#[test]
fn router_never_anchors_a_resumed_attempt() {
    let (mut router, counts, input) = router(&[], QemuAnchorRootOutcome::Admitted, 0);
    let checkpoint = crucible_campaign::ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.5.{}",
        "a5".repeat(32)
    ))
    .expect("exact checkpoint id");
    let context = execution_context(&input, 0xa5).with_resume_checkpoint(Some(checkpoint));

    let _thin = router.execute(&input, &context);

    assert_eq!(loads(&counts), [0, 0, 1]);
}
