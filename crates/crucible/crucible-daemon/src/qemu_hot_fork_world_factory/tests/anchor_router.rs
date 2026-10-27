//! Hot-first routing through an anchor root before thin replay.

use std::collections::VecDeque;

use super::ancestor_runner::{Edge, SuffixLifecycle, SuffixObservations, SuffixWorld, suffix_case};
use super::*;
use crate::qemu_hot_first_router::QemuHotFirstExecutionRouterError;
use crate::{QemuAnchorRootMaterializer, QemuAnchorRootOutcome};

/// One scripted hot-fork start.
#[derive(Clone, Copy)]
enum Start {
    Decline,
    /// Start from a root this many quanta in.
    At(u64),
    Fail(fn(&'static str) -> AttemptWorkerFailure<&'static str>),
}

/// Hot factory that declines, starts, or fails as scripted, call by call.
struct ScriptedStartFactory {
    world: SuffixWorld,
    /// Each successive start; an exhausted script declines.
    starts: VecDeque<Start>,
    calls: Arc<AtomicUsize>,
    observations: SuffixObservations,
}

impl QemuHotForkWorldLifecycleFactory for ScriptedStartFactory {
    type Lifecycle = SuffixLifecycle;
    type Error = &'static str;

    fn try_start(
        &mut self,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldLifecycleStart<Self::Lifecycle>, AttemptWorkerFailure<Self::Error>>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.starts.pop_front().unwrap_or(Start::Decline) {
            Start::Decline => Ok(QemuHotForkWorldLifecycleStart::Declined),
            Start::At(quanta) => Ok(QemuHotForkWorldLifecycleStart::Started(
                self.world.lifecycle_at(
                    quanta,
                    QemuHotForkStartOrigin::Exact,
                    context.runtime_basis(),
                    &self.observations,
                ),
            )),
            Start::Fail(failure) => Err(failure("scripted hot start failure")),
        }
    }

    fn recover(&mut self, _lifecycle: Self::Lifecycle) -> Result<(), Self::Lifecycle> {
        self.observations.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn quarantine(&mut self, _lifecycle: Self::Lifecycle) {
        self.observations.quarantines.fetch_add(1, Ordering::SeqCst);
    }
}

/// Lower tier with scripted anchor answers and a thin replay that only counts.
struct AnchoringFallback {
    /// Each successive anchor answer; an exhausted script declines.
    anchors: VecDeque<QemuAnchorRootOutcome>,
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
        Ok(self
            .anchors
            .pop_front()
            .unwrap_or(QemuAnchorRootOutcome::Declined("anchor-script-exhausted")))
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
    starts: &[Start],
    anchors: &[QemuAnchorRootOutcome],
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
        anchors: anchors.iter().copied().collect(),
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

/// The anchored execution ends retryable; the requeued one runs hot from
/// the kept root.
#[test]
fn router_keeps_an_anchor_then_runs_the_attempt_hot_when_requeued() {
    // The requeued start is from a root at the attempt's parent, two quanta in.
    let (mut router, counts, input) = router(
        &[Start::Decline, Start::At(2)],
        &[QemuAnchorRootOutcome::Admitted],
        0,
    );

    let anchored = router
        .execute(&input, &execution_context(&input, 0xa1))
        .expect_err("an anchored execution ends retryable");
    assert!(matches!(
        anchored,
        AttemptWorkerFailure::Retryable(QemuHotFirstExecutionRouterError::AnchorRootAdmitted)
    ));
    assert_eq!(loads(&counts), [1, 1, 0]);

    let outcome = router
        .execute(&input, &execution_context(&input, 0xa1))
        .expect("requeued hot execution");

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
        let (mut router, counts, input) = router(
            &[Start::Decline],
            &[QemuAnchorRootOutcome::Declined(reason)],
            0,
        );

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

/// An anchored execution never continues, however little of its budget the
/// anchoring replay spent, so it cannot turn a thin pass into a refusal.
/// When hot fork still declines on the requeued execution, the spent anchor
/// claim (or an invalidated root) sends the attempt to thin replay.
#[test]
fn router_never_continues_an_anchored_execution() {
    for (anchor_quanta, requeued) in [
        (8, "anchor-already-attempted"),
        (40, "anchor-root-invalidated"),
    ] {
        let (mut router, counts, input) = router(
            &[Start::Decline, Start::Decline],
            &[
                QemuAnchorRootOutcome::Admitted,
                QemuAnchorRootOutcome::Declined(requeued),
            ],
            anchor_quanta,
        );

        let anchored = router
            .execute(&input, &execution_context(&input, 0xa3))
            .expect_err("an anchored execution ends retryable");
        assert!(
            matches!(
                anchored,
                AttemptWorkerFailure::Retryable(
                    QemuHotFirstExecutionRouterError::AnchorRootAdmitted
                )
            ),
            "{requeued}"
        );
        assert_eq!(loads(&counts), [1, 1, 0], "{requeued}");

        let failure = router
            .execute(&input, &execution_context(&input, 0xa3))
            .expect_err("the counting thin tier fails");
        assert!(
            matches!(
                failure,
                AttemptWorkerFailure::Terminal(QemuHotFirstExecutionRouterError::Fallback(
                    "thin replay ran"
                ))
            ),
            "{requeued}"
        );
        assert_eq!(loads(&counts), [2, 2, 1], "{requeued}");
    }
}

/// Terminal, canceled, and retryable hot failures on the execution after an
/// admitted anchor propagate unchanged, without anchoring or thin replay.
#[test]
fn router_propagates_hot_failures_after_an_anchor_unchanged() {
    let failures: [(&str, Start); 3] = [
        ("terminal", Start::Fail(AttemptWorkerFailure::Terminal)),
        ("canceled", Start::Fail(AttemptWorkerFailure::Canceled)),
        ("retryable", Start::Fail(AttemptWorkerFailure::Retryable)),
    ];

    for (kind, start) in failures {
        let (mut router, counts, input) = router(
            &[Start::Decline, start],
            &[QemuAnchorRootOutcome::Admitted],
            40,
        );
        let _anchored = router
            .execute(&input, &execution_context(&input, 0xa4))
            .expect_err("an anchored execution ends retryable");

        let failure = router
            .execute(&input, &execution_context(&input, 0xa4))
            .expect_err("the hot failure propagates");

        let classified = match failure {
            AttemptWorkerFailure::Terminal(QemuHotFirstExecutionRouterError::HotFork(_)) => {
                "terminal"
            }
            AttemptWorkerFailure::Canceled(QemuHotFirstExecutionRouterError::HotFork(_)) => {
                "canceled"
            }
            AttemptWorkerFailure::Retryable(QemuHotFirstExecutionRouterError::HotFork(_)) => {
                "retryable"
            }
            other => panic!("{kind}: unexpected routed failure {other:?}"),
        };
        assert_eq!(classified, kind);
        assert_eq!(loads(&counts), [2, 1, 0], "{kind}");
    }
}

/// Resumes and captures bypass hot fork, and with it anchoring.
#[test]
fn router_never_anchors_a_resumed_attempt() {
    let (mut router, counts, input) = router(&[], &[QemuAnchorRootOutcome::Admitted], 0);
    let checkpoint = crucible_campaign::ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.5.{}",
        "a5".repeat(32)
    ))
    .expect("exact checkpoint id");
    let context = execution_context(&input, 0xa5).with_resume_checkpoint(Some(checkpoint));

    let _thin = router.execute(&input, &context);

    assert_eq!(loads(&counts), [0, 0, 1]);
}
