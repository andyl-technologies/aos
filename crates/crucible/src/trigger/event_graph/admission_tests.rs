//! Reachability equivalence and original-account graph admission regressions.

use super::*;
use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority(Arc<AtomicU64>, u64);
struct Credit(Arc<AtomicU64>, u64);

impl Drop for Credit {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.1)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("original graph credit exhausted"))
            })?;
        Ok(Arc::new(Credit(self.0.clone(), bytes)))
    }
}

fn budget(bytes: u64) -> DecodeBudget {
    DecodeBudget::new(
        Arc::new(Authority(Arc::new(AtomicU64::new(0)), bytes)),
        bytes,
    )
    .expect("fixture original account")
}

fn after(name: &str) -> Condition {
    Condition::After {
        duration: SimDuration { ticks: 0 },
        of: EventId::from_name(name),
    }
}

// Keep a small independent version of the former DNF definition as an oracle.
// Its Cartesian product is intentionally used only for tiny test expressions.
fn alternatives(
    condition: &Condition,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Vec<BTreeSet<EventId>> {
    match condition {
        Condition::After { of, .. } => vec![BTreeSet::from([of.clone()])],
        Condition::Timer { name } => armers.get(name).map_or_else(Vec::new, |events| {
            events
                .iter()
                .map(|event| BTreeSet::from([event.clone()]))
                .collect()
        }),
        Condition::AnyOf { predicates } => predicates
            .iter()
            .flat_map(|predicate| alternatives(predicate, armers))
            .collect(),
        Condition::AllOf { predicates } => {
            predicates
                .iter()
                .fold(vec![BTreeSet::new()], |prior, predicate| {
                    let next = alternatives(predicate, armers);
                    prior
                        .iter()
                        .flat_map(|left| {
                            next.iter()
                                .map(|right| left.union(right).cloned().collect())
                        })
                        .collect()
                })
        }
        Condition::Once { predicate } => alternatives(predicate, armers),
        _ => vec![BTreeSet::new()],
    }
}

#[test]
fn direct_reachability_matches_dependency_alternatives() {
    let timer = TimerId {
        name: "timer".to_owned(),
    };
    let events = [
        EventId::from_name("a"),
        EventId::from_name("b"),
        EventId::from_name("c"),
    ];
    let timers = BTreeSet::from([timer.clone()]);
    let armers = BTreeMap::from([(
        timer.clone(),
        BTreeSet::from([events[1].clone(), events[2].clone()]),
    )]);
    let expressions = [
        after("a"),
        Condition::Timer { name: timer },
        Condition::AnyOf {
            predicates: vec![after("a"), after("b")],
        },
        Condition::AllOf {
            predicates: vec![
                after("a"),
                Condition::AnyOf {
                    predicates: vec![after("b"), after("c")],
                },
            ],
        },
        Condition::Once {
            predicate: Box::new(after("b")),
        },
        Condition::Not {
            predicate: Box::new(after("c")),
        },
    ];
    for mask in 0..8 {
        let reachable = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| ((mask >> index) & 1 == 1).then_some(event))
            .collect::<BTreeSet<_>>();
        for expression in &expressions {
            let expected = alternatives(expression, &armers)
                .iter()
                .any(|dependencies| dependencies.iter().all(|event| reachable.contains(event)));
            assert_eq!(
                dependencies_are_reachable(expression, &timers, &armers, &reachable),
                expected,
                "mask={mask}, expression={expression:?}"
            );
        }
    }
}

#[test]
fn wide_compound_does_not_allocate_cartesian_dependency_expansion() {
    let compound = Condition::AllOf {
        predicates: (0..26)
            .map(|_| Condition::AnyOf {
                predicates: vec![after("a"), after("b")],
            })
            .collect(),
    };
    let events = vec![
        Event::once(EventId::from_name("a"), None, Action::Pass),
        Event::once(EventId::from_name("b"), None, Action::Pass),
        Event::once(EventId::from_name("compound"), Some(compound), Action::Pass),
    ];
    let budget = budget(1024 * 1024);
    let scope = budget.enter();
    let graph = EventGraph::new(events).expect("linear compound admission");
    drop(scope);
    assert_eq!(graph.events().len(), 3);
    assert!(budget.failure().expect("account health").is_none());
}

#[test]
fn graph_indexes_refuse_original_credit_before_construction() {
    let events = vec![Event::once(EventId::from_name("entry"), None, Action::Pass)];
    let budget = budget(256);
    let _scope = budget.enter();
    assert!(matches!(
        EventGraph::new(events),
        Err(EventGraphError::OriginalAdmission(_))
    ));
    assert!(budget.failure().expect("account health").is_some());
}
