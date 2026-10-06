//! Original allocation refusal before assertion latching or trigger publication.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use crucible::{
    Action, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle, EngineError, Event,
    EventGraph, EventGraphState, EventId, LogLevel, Predicate,
};

#[derive(Debug)]
struct RefusedLeafAllocation;

impl fmt::Display for RefusedLeafAllocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixture leaf has no remaining allocation headroom")
    }
}

impl Error for RefusedLeafAllocation {}

const FIXTURE_METADATA_BYTES: u64 = 64 * 1024;

#[derive(Default)]
struct OriginalAccount {
    used: AtomicU64,
    leaf_visited: AtomicBool,
    refusals: AtomicUsize,
}

struct FiniteAuthority(Arc<OriginalAccount>);

struct Credit {
    account: Arc<OriginalAccount>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.account.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl DecodeResourceAuthority for FiniteAuthority {
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        let admitted = !self.0.leaf_visited.load(Ordering::Acquire)
            && self
                .0
                .used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes)
                        .filter(|next| *next <= FIXTURE_METADATA_BYTES)
                })
                .is_ok();
        if !admitted {
            self.0.refusals.fetch_add(1, Ordering::AcqRel);
            return Err(DecodeAdmissionError::new(RefusedLeafAllocation));
        }

        Ok(Arc::new(Credit {
            account: Arc::clone(&self.0),
            bytes,
        }))
    }
}

struct RefusingLeaf {
    budget: DecodeBudget,
    account: Arc<OriginalAccount>,
}

impl ConditionLeafOracle for RefusingLeaf {
    fn leaf_is_true(&mut self, _leaf: ConditionLeaf<'_>) -> bool {
        // Earlier graph staging succeeds under the finite original account.
        // Only this leaf exhausts it, so Not and Once see a provisional false
        // value which must never escape the enclosing fallible transaction.
        self.account.leaf_visited.store(true, Ordering::Release);
        assert!(self.budget.charge_bytes(1).is_err());
        false
    }
}

fn original_account() -> (DecodeBudget, Arc<OriginalAccount>) {
    let account = Arc::new(OriginalAccount::default());
    let budget = DecodeBudget::new(
        Arc::new(FiniteAuthority(Arc::clone(&account))),
        FIXTURE_METADATA_BYTES,
    )
    .unwrap_or_else(|error| panic!("finite original-account fixture: {error}"));
    (budget, account)
}

fn refusing_leaf(budget: &DecodeBudget, account: &Arc<OriginalAccount>) -> RefusingLeaf {
    RefusingLeaf {
        budget: budget.clone(),
        account: Arc::clone(account),
    }
}

fn assert_leaf_was_refused(account: &OriginalAccount) {
    assert!(account.leaf_visited.load(Ordering::Acquire));
    assert!(account.refusals.load(Ordering::Acquire) > 0);
}

fn assert_original_refusal<T>(result: Result<T, EngineError>) {
    let Err(EngineError::ArtifactDecodeAdmission { source }) = result else {
        panic!("allocation refusal must remain a typed infrastructure error");
    };
    assert!(
        source
            .source()
            .is_some_and(|cause| cause.is::<RefusedLeafAllocation>())
    );
}

fn negated_once() -> Predicate {
    Predicate::once(Predicate::not(Predicate::named("copied-leaf")))
}

#[test]
fn refused_assertion_copy_cannot_latch_negated_provisional_truth() {
    let predicate = negated_once();
    let (budget, account) = original_account();
    let prefix = crucible::test_support::condition_prefix_at_quantum_boundary_for_test(1);
    let mut pass =
        ConditionEvaluationPass::from_log_prefix(prefix, refusing_leaf(&budget, &account));

    let scope = budget.enter();
    assert!(budget.check().is_ok());
    assert_original_refusal(pass.evaluate_assertion_condition(&predicate));
    assert!(pass.once_latches().is_empty());
    assert_leaf_was_refused(&account);
    drop(scope);
}

#[test]
fn refused_trigger_copy_preserves_edges_one_shots_and_firings() {
    let event = EventId::from_name("copy-refused-before-publication");
    let earlier = EventId::from_name("earlier-successful-row");
    let graph = EventGraph::new(vec![
        Event::once(
            earlier.clone(),
            Some(Predicate::once(Predicate::at(crucible::VirtualTime {
                ticks: 1,
            }))),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("earlier staged firing"),
            },
        ),
        Event::once(
            event.clone(),
            Some(negated_once()),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("accepted trigger"),
            },
        ),
    ])
    .unwrap_or_else(|error| panic!("trigger fixture admission: {error}"));
    let mut state = EventGraphState::new();
    let before = state.to_compact_binary();
    let (budget, account) = original_account();
    let prefix = crucible::test_support::condition_prefix_at_quantum_boundary_for_test(1);
    let mut pass =
        ConditionEvaluationPass::from_log_prefix(prefix.clone(), refusing_leaf(&budget, &account));

    let scope = budget.enter();
    assert!(budget.check().is_ok());
    assert_original_refusal(pass.evaluate_event_graph(&graph, &mut state));
    assert!(pass.once_latches().is_empty());
    assert_leaf_was_refused(&account);
    drop(scope);
    assert_eq!(state.to_compact_binary(), before);

    let mut accepted =
        ConditionEvaluationPass::from_log_prefix(prefix, |_leaf: ConditionLeaf<'_>| false);
    let firings = accepted
        .evaluate_event_graph(&graph, &mut state)
        .unwrap_or_else(|error| panic!("independent accepted predicate: {error}"));
    assert_eq!(firings.len(), 2);
    assert_eq!(firings[0].event(), &earlier);
    assert_eq!(firings[1].event(), &event);
    assert!(state.last_firing(&earlier).is_some());
    assert!(state.last_firing(&event).is_some());

    let repeated = accepted
        .evaluate_event_graph(&graph, &mut state)
        .unwrap_or_else(|error| panic!("accepted one-shot retry: {error}"));
    assert!(repeated.is_empty());
}

#[test]
fn repeated_graph_passes_release_temporary_credit_to_the_persistent_floor() {
    let event = EventId::from_name("stable-persistent-graph-state");
    let graph = EventGraph::new(vec![Event::repeatable(
        event,
        Some(Predicate::once(Predicate::at(crucible::VirtualTime {
            ticks: 1,
        }))),
        Action::Log {
            level: LogLevel::Info,
            message: String::from("one rising edge"),
        },
    )])
    .unwrap_or_else(|error| panic!("finite graph fixture: {error}"));
    let prefix = crucible::test_support::condition_prefix_at_quantum_boundary_for_test(1);
    let (budget, account) = original_account();
    let mut state = EventGraphState::new();
    let scope = budget.enter();
    let mut first =
        ConditionEvaluationPass::from_log_prefix(prefix.clone(), |_leaf: ConditionLeaf<'_>| false);

    let firings = first
        .evaluate_event_graph(&graph, &mut state)
        .unwrap_or_else(|error| panic!("first admitted graph pass: {error}"));
    assert_eq!(firings.len(), 1);
    let with_firings = account.used.load(Ordering::Acquire);
    drop(firings);
    let persistent_floor = account.used.load(Ordering::Acquire);
    assert!(persistent_floor < with_firings);
    let published = state.to_compact_binary();

    for _ in 0..32 {
        let mut pass =
            ConditionEvaluationPass::from_log_prefix(prefix.clone(), |_leaf: ConditionLeaf<'_>| {
                false
            });
        let firings = pass
            .evaluate_event_graph(&graph, &mut state)
            .unwrap_or_else(|error| panic!("repeated admitted graph pass: {error}"));
        assert!(firings.is_empty());
        drop(firings);
        assert_eq!(account.used.load(Ordering::Acquire), persistent_floor);
        assert_eq!(state.to_compact_binary(), published);
    }

    assert!(!account.leaf_visited.load(Ordering::Acquire));
    assert_eq!(account.refusals.load(Ordering::Acquire), 0);
    drop(scope);
}
