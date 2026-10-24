//! Exercises locked collection with real entered Host operations.
//!
//! Component charges retain the intrusive test memberships and publisher.
//! The fixture installs those memberships directly: it issues no authenticated
//! Source purpose, Native borrower, transport permission or physical return.

// crucible-lint: allow panic-shortcut -- causal controls localize clock, membership and lock regressions.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::host_services::{HostServiceAllocator, HostServiceLeasePair};
use std::sync::{TryLockError, mpsc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observation {
    role: Option<HostQuantumActionRole>,
    mask: u32,
    parents: [ActionParent; 4],
}

#[derive(Debug)]
struct ComponentPublisher {
    owners: [Option<Weak<Shared>>; 4],
    observed: Mutex<Option<Observation>>,
}

impl ComponentPublisher {
    fn record(&self, observation: Observation) -> Result<(), HostSupervisionError> {
        for (index, owner) in self.owners.iter().enumerate() {
            if observation.mask & (1 << index) == 0 {
                assert_eq!(observation.parents[index], ActionParent::default());
                continue;
            }
            let owner = owner.as_ref().unwrap().upgrade().unwrap();
            assert!(matches!(
                owner.state.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            assert!(matches!(
                owner.outer.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
        }

        *self.observed.lock().unwrap() = Some(observation);
        Ok(())
    }
}

impl HostActionPublisher for ComponentPublisher {
    fn retain_parent(&self, _: ActionBinding, _: u32) -> Result<(), HostSupervisionError> {
        Ok(())
    }

    fn publish_parent(
        &self,
        _: ActionBinding,
        _: u32,
        _: ActionParent,
    ) -> Result<(), HostSupervisionError> {
        Ok(())
    }

    fn publish_outer(
        &self,
        _: ActionBinding,
        _: [u8; 32],
        _: HostOuterCapBinding,
    ) -> Result<(), HostSupervisionError> {
        Ok(())
    }

    fn publish_cohort(
        &self,
        _: ActionBinding,
        parents: [ActionParent; 4],
        count: u32,
    ) -> Result<(), HostSupervisionError> {
        self.record(Observation {
            role: None,
            mask: (1 << count) - 1,
            parents,
        })
    }

    fn publish_quantum_role(
        &self,
        _: ActionBinding,
        role: HostQuantumActionRole,
        parents: [ActionParent; 4],
        mask: u32,
    ) -> Result<(), HostSupervisionError> {
        self.record(Observation {
            role: Some(role),
            mask,
            parents,
        })
    }

    fn action_return(&self, _: ActionBinding) -> Result<ActionReturn, HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    fn unpublished_return(&self, _: ActionBinding) -> Result<(), HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    fn invalidate_action(&self, _: ActionBinding) {}
}

struct ComponentRoster<'a> {
    guards: [Option<&'a HostOperationGuard>; 4],
    loans: [Option<HostActionLoan>; 4],
    publisher: FundedSourcePublisher<ComponentPublisher>,
    _credits: [Option<HostServiceLeasePair>; 4],
}

impl<'a> ComponentRoster<'a> {
    fn new(guards: [Option<&'a HostOperationGuard>; 4], links: [u32; 2]) -> Self {
        let publisher_bytes =
            FundedSourcePublisher::<ComponentPublisher>::allocation_bytes().unwrap() as u64;
        let bytes = publisher_bytes + 4 * HostActionLoan::metadata_bytes();
        let accounts: [HostServiceAllocator; 2] =
            std::array::from_fn(|_| HostServiceAllocator::new(1, 1, bytes).unwrap());
        let reserve = |bytes| {
            HostServiceLeasePair::new(
                accounts[0].reserve_resources(0, 0, bytes).unwrap(),
                accounts[1].reserve_resources(0, 0, bytes).unwrap(),
            )
        };
        let publisher = FundedSourcePublisher::component(
            ComponentPublisher {
                owners: std::array::from_fn(|index| {
                    guards[index].map(|guard| Arc::downgrade(&guard.supervisor.shared))
                }),
                observed: Mutex::new(None),
            },
            reserve(publisher_bytes),
        );
        let mut loans = std::array::from_fn(|_| None);
        let mut credits = std::array::from_fn(|_| None);

        for (index, guard) in guards.iter().enumerate() {
            let Some(guard) = guard else { continue };
            credits[index] = Some(reserve(HostActionLoan::metadata_bytes()));
            let mut state = guard.supervisor.lock().unwrap();
            let mut outer = guard.supervisor.lock_outer().unwrap();
            let operation = state.operations.get_mut(&guard.id).unwrap();
            assert!(operation.action_subscribers.is_none());
            operation.action_subscribers = Some(Box::new(OperationSubscriber {
                binding: binding(),
                row: index as u32,
                preparation: if index < 2 { links[index] } else { 0 },
                role: u32::from(index >= 2),
                publisher: publisher.action(),
                next: None,
                // Component funding stays in the fixture through node teardown.
                // It cannot construct an authenticated Source control lease.
                _credit: None,
            }));
            outer.action_subscribers = Some(Box::new(OuterSubscriber {
                binding: binding(),
                row: index as u32,
                publisher: publisher.action(),
                next: outer.action_subscribers.take(),
            }));
            loans[index] = Some(HostActionLoan {
                supervisor: guard.supervisor.clone(),
                operation: guard.id,
                binding: binding(),
                row: index as u32,
                returned: false,
            });
        }

        Self {
            guards,
            loans,
            publisher,
            _credits: credits,
        }
    }

    fn selected(&self, mask: u32) -> [Option<&HostActionLoan>; 4] {
        std::array::from_fn(|index| {
            (mask & (1 << index) != 0)
                .then_some(self.loans[index].as_ref())
                .flatten()
        })
    }

    fn observed(&self) -> Observation {
        self.publisher.observed.lock().unwrap().take().unwrap()
    }
}

impl Drop for ComponentRoster<'_> {
    fn drop(&mut self) {
        // These component nodes have never had a physical borrower. Remove the
        // seeded lists before their component metadata charges leave scope.
        for guard in self.guards.iter().flatten() {
            let mut state = guard.supervisor.lock().unwrap();
            state
                .operations
                .get_mut(&guard.id)
                .unwrap()
                .action_subscribers = None;
            guard.supervisor.lock_outer().unwrap().action_subscribers = None;
        }
    }
}

fn binding() -> ActionBinding {
    ActionBinding {
        cap: [1; 32],
        reservation: [2; 32],
        account_generation: 1,
        process_generation: 1,
        loan_sequence: 2,
        token: 0,
        capture: None,
        park_request: None,
        frontier: 7,
    }
}

fn owner() -> HostOperationSupervisor {
    HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(60)),
    )
    .unwrap()
}

#[test]
fn cleanup_collects_its_original_clock_while_terminal_work_is_locked_elsewhere() {
    let work_owner = owner();
    let cleanup_owner = owner();
    let work = work_owner
        .begin_work(HostOperationClass::Quantum, 1)
        .unwrap();
    let cleanup = cleanup_owner
        .begin_control(HostOperationClass::Cleanup)
        .unwrap();
    let roster = ComponentRoster::new([Some(&work), Some(&cleanup), None, None], [0, 0]);

    HostActionLoan::refresh_quantum_role(roster.selected(2), HostQuantumActionRole::Cleanup)
        .unwrap();
    let original = roster.observed();
    work_owner.cancel().unwrap();
    cleanup_owner.cancel().unwrap();
    assert_eq!(work.status().unwrap().state, HostOperationState::Canceled);

    std::thread::scope(|scope| {
        let state = work_owner.shared.state.lock().unwrap();
        let outer = work_owner.shared.outer.lock().unwrap();
        let (sent, received) = mpsc::sync_channel(1);
        let roster = &roster;
        let child = scope.spawn(move || {
            sent.send(HostActionLoan::refresh_quantum_role(
                roster.selected(2),
                HostQuantumActionRole::Cleanup,
            ))
            .unwrap();
        });
        let result = received.recv_timeout(Duration::from_secs(2));
        drop(outer);
        drop(state);
        child.join().unwrap();
        result.unwrap().unwrap();
    });

    let current = roster.observed();
    assert_eq!(current.role, Some(HostQuantumActionRole::Cleanup));
    assert_eq!(current.mask, 2);
    assert_eq!(current.parents[1].state, 0);
    assert_eq!(current.parents[1].outer_end_ns, 0);
    assert_eq!(current.parents[1].origin_ns, original.parents[1].origin_ns);
    assert_eq!(
        current.parents[1].started_ns,
        original.parents[1].started_ns
    );
    assert_eq!(
        current.parents[1].progress_ns,
        original.parents[1].progress_ns
    );
}

#[test]
fn each_role_collects_only_its_registered_preparation_and_keeps_all_selected_locks() {
    let owners = [owner(), owner(), owner(), owner()];
    let work = owners[0].begin(HostOperationClass::Quantum).unwrap();
    let cleanup = owners[1]
        .begin_control(HostOperationClass::Cleanup)
        .unwrap();
    let work_preparation = owners[2].begin(HostOperationClass::Preparation).unwrap();
    let cleanup_preparation = owners[3].begin(HostOperationClass::Preparation).unwrap();
    let roster = ComponentRoster::new(
        [
            Some(&work),
            Some(&cleanup),
            Some(&work_preparation),
            Some(&cleanup_preparation),
        ],
        [3, 4],
    );

    for (role, mask) in [
        (HostQuantumActionRole::Work, 5),
        (HostQuantumActionRole::Cleanup, 10),
    ] {
        HostActionLoan::refresh_quantum_role(roster.selected(mask), role).unwrap();
        let observed = roster.observed();
        assert_eq!(observed.mask, mask);
        assert_eq!(observed.role, Some(role));
        assert_eq!(
            observed.parents[role.primary()].preparation,
            if role == HostQuantumActionRole::Work {
                3
            } else {
                4
            }
        );
    }

    HostActionLoan::refresh_cohort(roster.selected(15), 4).unwrap();
    assert_eq!(roster.observed().mask, 15);
}

#[test]
fn shared_preparation_keeps_each_role_separate_under_one_actual_owner() {
    let owner = owner();
    let work = owner.begin(HostOperationClass::Quantum).unwrap();
    let cleanup = owner.begin_control(HostOperationClass::Cleanup).unwrap();
    let preparation = owner.begin(HostOperationClass::Preparation).unwrap();
    let roster = ComponentRoster::new(
        [Some(&work), Some(&cleanup), Some(&preparation), None],
        [3, 3],
    );

    for (role, mask) in [
        (HostQuantumActionRole::Work, 5),
        (HostQuantumActionRole::Cleanup, 6),
    ] {
        HostActionLoan::refresh_quantum_role(roster.selected(mask), role).unwrap();
        assert_eq!(roster.observed().mask, mask);
    }

    owner.cancel().unwrap();
    HostActionLoan::refresh_quantum_role(roster.selected(6), HostQuantumActionRole::Cleanup)
        .unwrap();
    let observed = roster.observed();
    assert_eq!(observed.parents[1].state, 0);
    assert_eq!(observed.parents[2].state, 3);
    assert_eq!(observed.parents[0], ActionParent::default());
}

#[test]
fn missing_extra_returned_or_foreign_rows_cannot_publish_a_role() {
    let owners = [owner(), owner(), owner(), owner()];
    let work = owners[0].begin(HostOperationClass::Quantum).unwrap();
    let cleanup = owners[1]
        .begin_control(HostOperationClass::Cleanup)
        .unwrap();
    let preparation = owners[2].begin(HostOperationClass::Preparation).unwrap();
    let extra = owners[3].begin(HostOperationClass::Preparation).unwrap();
    let mut roster = ComponentRoster::new(
        [
            Some(&work),
            Some(&cleanup),
            Some(&preparation),
            Some(&extra),
        ],
        [0, 3],
    );

    for mask in [0, 1, 2, 3, 7, 10, 14, 15] {
        assert!(
            HostActionLoan::refresh_quantum_role(
                roster.selected(mask),
                HostQuantumActionRole::Cleanup
            )
            .is_err(),
            "mask {mask}"
        );
        assert!(roster.publisher.observed.lock().unwrap().is_none());
    }

    roster.loans[2].as_mut().unwrap().returned = true;
    assert!(
        HostActionLoan::refresh_quantum_role(roster.selected(6), HostQuantumActionRole::Cleanup)
            .is_err()
    );
    roster.loans[2].as_mut().unwrap().returned = false;
    roster.loans[2].as_mut().unwrap().binding.process_generation += 1;
    assert!(
        HostActionLoan::refresh_quantum_role(roster.selected(6), HostQuantumActionRole::Cleanup)
            .is_err()
    );
    assert!(roster.publisher.observed.lock().unwrap().is_none());
}

#[test]
fn mismatched_outer_publisher_cannot_corroborate_a_membership() {
    let first_owner = owner();
    let second_owner = owner();
    let first = first_owner
        .begin_control(HostOperationClass::Cleanup)
        .unwrap();
    let second = second_owner
        .begin_control(HostOperationClass::Cleanup)
        .unwrap();
    let first_roster = ComponentRoster::new([None, Some(&first), None, None], [0, 0]);
    let second_roster = ComponentRoster::new([None, Some(&second), None, None], [0, 0]);
    let mut outer = first_owner.shared.outer.lock().unwrap();
    outer.action_subscribers.as_mut().unwrap().publisher = second_roster.publisher.action();
    drop(outer);

    assert!(
        HostActionLoan::refresh_quantum_role(
            first_roster.selected(2),
            HostQuantumActionRole::Cleanup
        )
        .is_err()
    );
    assert!(first_roster.publisher.observed.lock().unwrap().is_none());
    assert!(second_roster.publisher.observed.lock().unwrap().is_none());
}

#[test]
fn another_actual_operation_class_cannot_be_reclassified_as_cleanup() {
    let owner = owner();
    let setup = owner.begin_control(HostOperationClass::Setup).unwrap();
    let roster = ComponentRoster::new([None, Some(&setup), None, None], [0, 0]);

    assert!(
        HostActionLoan::refresh_quantum_role(roster.selected(2), HostQuantumActionRole::Cleanup)
            .is_err()
    );
    assert!(roster.publisher.observed.lock().unwrap().is_none());
}

fn check_collected_expiry_stays_terminal(projection: Projection) {
    let owner = owner();
    let cleanup = owner.begin_control(HostOperationClass::Cleanup).unwrap();
    let mut guards = [None; 4];
    guards[projection.first()] = Some(&cleanup);
    let roster = ComponentRoster::new(guards, [0, 0]);
    let mask = 1 << projection.first();
    let original = {
        let state = owner.shared.state.lock().unwrap();
        state.operations.get(&cleanup.id).unwrap().started
    };
    let elapsed_since_entry = owner.elapsed().checked_sub(original).unwrap();
    assert!(!elapsed_since_entry.is_zero());

    // The authored bound is already elapsed from this actual operation's
    // original start. No sleep, synthetic clock or status poll causes expiry.
    let mut shortened = HostOperationBudgets::default();
    let budget = &mut shortened.classes[HostOperationClass::Cleanup as usize];
    budget.total_timeout = Some(elapsed_since_entry);
    budget.progress_timeout = None;
    owner.update_budgets(0, shortened).unwrap();
    HostActionLoan::refresh_selected(roster.selected(mask), projection).unwrap();
    let expired = roster.observed();
    assert_eq!(expired.parents[projection.first()].state, 2);

    owner
        .update_budgets(1, HostOperationBudgets::default())
        .unwrap();
    HostActionLoan::refresh_selected(roster.selected(mask), projection).unwrap();
    let amended = roster.observed();
    assert_eq!(amended.parents[projection.first()].state, 2);
    assert_eq!(
        amended.parents[projection.first()].started_ns,
        expired.parents[projection.first()].started_ns
    );
    assert_eq!(
        amended.parents[projection.first()].progress_ns,
        expired.parents[projection.first()].progress_ns
    );
}

#[test]
fn collected_role_expiry_remains_terminal_after_a_later_policy_extension() {
    check_collected_expiry_stays_terminal(Projection::QuantumRole(HostQuantumActionRole::Cleanup));
}

#[test]
fn collected_cohort_expiry_remains_terminal_after_a_later_policy_extension() {
    check_collected_expiry_stays_terminal(Projection::Cohort(1));
}
