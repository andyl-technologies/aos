//! Where a hot child forked from an ancestor root fails decides its class.
//!
//! Anything that fails before the child begins applying the attempt's own
//! edge at the branch parent contradicts only the root: the child is
//! quarantined, which invalidates the root, and the failure is retryable so
//! the attempt's next execution replays thin. A failure applying the edge
//! keeps its class, as it would for a child of an exact root.

use super::ancestor_runner::{
    AncestorFactory, Edge, SuffixCase, SuffixObservations, SuffixWorld, ancestor_origin,
    ancestor_runner, suffix_case,
};
use super::*;

/// One scripted change to the suffix world and the root it forks from.
struct FailureCase {
    label: &'static str,
    edge: Edge,
    /// Whether the root sits at genesis rather than one quantum in.
    root_at_genesis: bool,
    script: fn(&mut SuffixWorld, &SuffixCase),
}

type CaseFailure = AttemptWorkerFailure<
    QemuHotForkWorldExecutionRunnerError<
        <QemuObservedFreshAttemptLifecycleFactory<AncestorFactory> as QemuHotForkWorldLifecycleFactory>::Error,
        <QemuFreshModeledDriver as QemuFreshAttemptDriver>::Error,
    >,
>;

fn run_failure_case(case: &FailureCase, byte: u8) -> (CaseFailure, SuffixObservations) {
    let suffix = suffix_case(case.edge);
    let mut world = SuffixWorld::for_case(&suffix, case.edge);
    (case.script)(&mut world, &suffix);
    let genesis = Configuration::genesis(suffix.input.scenario().scenario_def());
    let (root, root_quanta) = if case.root_at_genesis {
        (genesis, 0)
    } else {
        (suffix.anchor.clone(), 1)
    };
    let observations = SuffixObservations::default();
    let (mut runner, _evidence) =
        ancestor_runner(world, root_quanta, ancestor_origin(&root), &observations);

    let failure = runner
        .try_execute(&suffix.input, &execution_context(&suffix.input, byte))
        .err()
        .unwrap_or_else(|| panic!("{}: the scripted failure fails the hot attempt", case.label));
    (failure, observations)
}

/// Scheduler and terminal failures inside the suffix, and a guest request
/// at the parent that differs from the recorded one, are root drift.
#[test]
fn ancestor_failures_before_the_edge_are_retryable_root_drift() {
    let cases = [
        FailureCase {
            label: "suffix-scheduler-failure",
            edge: Edge::Scheduler,
            root_at_genesis: false,
            script: |world, suffix| world.drive_failure_at = Some(suffix.anchor.clone()),
        },
        FailureCase {
            label: "suffix-terminal-verdict",
            edge: Edge::Scheduler,
            root_at_genesis: true,
            script: |world, suffix| world.terminal_at = Some(suffix.anchor.clone()),
        },
        FailureCase {
            label: "parent-guest-request-mismatch",
            edge: Edge::Guest,
            root_at_genesis: false,
            script: |world, suffix| {
                // The guest asks again at the parent, but under another
                // request instance than the recorded edge selection named.
                let drifted =
                    branch_replay_guest_pending(&guest_selectable_declaration(), "drifted");
                world.guest = Some((suffix.parent.clone(), drifted));
            },
        },
    ];

    for (offset, case) in cases.iter().enumerate() {
        let byte = 0xb0 + u8::try_from(offset).expect("case index fits");
        let (failure, observations) = run_failure_case(case, byte);

        assert!(
            matches!(
                failure,
                AttemptWorkerFailure::Retryable(
                    QemuHotForkWorldExecutionRunnerError::AncestorSuffixDiverged(_)
                )
            ),
            "{}: {failure:?}",
            case.label
        );
        assert_eq!(
            observations.quarantines.load(Ordering::SeqCst),
            1,
            "{}",
            case.label
        );
    }
}

/// Applying the attempt's own guest reply at the parent belongs to the
/// attempt and keeps its terminal class.
#[test]
fn ancestor_edge_application_failure_stays_terminal() {
    let case = FailureCase {
        label: "parent-guest-reply-failure",
        edge: Edge::Guest,
        root_at_genesis: false,
        script: |world, _suffix| world.reply_failure = true,
    };

    let (failure, observations) = run_failure_case(&case, 0xbf);

    assert!(
        matches!(
            failure,
            AttemptWorkerFailure::Terminal(QemuHotForkWorldExecutionRunnerError::StartReplay(_))
        ),
        "{failure:?}"
    );
    assert_eq!(observations.quarantines.load(Ordering::SeqCst), 1);
}
