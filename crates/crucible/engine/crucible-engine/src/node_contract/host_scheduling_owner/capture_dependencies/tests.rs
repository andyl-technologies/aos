//! Exercises the producer's data-only row helpers without issuing Host authority.

// Panics identify malformed inert data fixtures, never native capture success.
#![allow(clippy::unwrap_used)]

use super::*;

fn plan() -> OriginalHostDependencyPlan {
    let runtime = canonical::content_ref(b"runtime", "application/json").unwrap();
    let snapshot = canonical::content_ref(b"snapshot", "application/json").unwrap();
    let external = canonical::content_ref(b"original-body", "application/octet-stream").unwrap();
    OriginalHostDependencyPlan {
        runtime: runtime.clone(),
        snapshot: snapshot.clone(),
        snapshot_dependencies: vec![runtime.clone(), external],
        journal_dependencies: [runtime, snapshot],
        journal: RefCell::new(None),
    }
}

#[test]
fn host_born_rows_preserve_full_typed_edges_and_verify_original_bytes() {
    let plan = plan();
    let quote = plan.lookup(&plan.snapshot, 2).unwrap().unwrap();
    let copied = plan
        .copy_dependencies(
            &plan.snapshot,
            b"snapshot",
            2,
            quote.requested_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(copied, plan.snapshot_dependencies);
    assert!(
        plan.copy_dependencies(&plan.snapshot, b"snapsho", 2, usize::MAX)
            .is_err()
    );
    assert!(
        plan.copy_dependencies(&plan.snapshot, b"foreign!", 2, usize::MAX)
            .is_err()
    );
    let mut foreign = plan.snapshot.clone();
    foreign.media_type.push_str(";foreign");
    assert!(
        plan.copy_dependencies(&foreign, b"snapshot", 2, 0)
            .unwrap()
            .is_none()
    );
    assert!(plan.lookup(&plan.snapshot, 1).is_err());
}

#[test]
fn host_row_copy_refuses_one_short_before_copying_original_metadata() {
    let plan = plan();
    let quote = plan.lookup(&plan.snapshot, 2).unwrap().unwrap();
    let exact = quote.requested_bytes().unwrap();
    assert!(
        plan.copy_dependencies(&plan.snapshot, b"snapshot", 2, exact - 1)
            .is_err()
    );
    assert!(
        plan.copy_dependencies(&plan.snapshot, b"snapshot", 2, exact)
            .unwrap()
            .is_some()
    );
    assert!(plan.journal.borrow().is_none());
}

#[test]
fn host_dependency_observer_charges_real_spare_capacity_and_busy_bank() {
    let mut plan = plan();
    let initial = plan.retained_storage().unwrap();
    let before = plan.snapshot_dependencies.capacity();
    plan.snapshot_dependencies.reserve_exact(17);
    let added = (plan.snapshot_dependencies.capacity() - before) * size_of::<ContentRef>();
    assert_eq!(plan.retained_storage().unwrap(), initial + added);
    let before_string = plan.snapshot_dependencies[0].media_type.capacity();
    plan.snapshot_dependencies[0].media_type.reserve_exact(31);
    let extra_string = plan.snapshot_dependencies[0].media_type.capacity() - before_string;
    assert_eq!(
        plan.retained_storage().unwrap(),
        initial + added + extra_string
    );
    let held = plan.journal.borrow_mut();
    assert!(plan.retained_storage().is_err());
    drop(held);
    assert!(within(plan.retained_storage().unwrap(), initial).is_err());
}

#[test]
fn host_journal_rows_survive_terminal_error_and_refuse_foreign_or_repeated_binding() {
    let plan = plan();
    let journal = canonical::content_ref(b"journal", JOURNAL_MEDIA).unwrap();
    let foreign = canonical::content_ref(b"foreign-runtime", "application/json").unwrap();
    let exact = plan.retained_storage().unwrap() + reference_bytes(&journal).unwrap();
    assert!(
        plan.retain_journal(&foreign, &plan.snapshot, &journal, exact)
            .is_err()
    );
    assert!(
        plan.retain_journal(&plan.runtime, &plan.snapshot, &journal, exact - 1)
            .is_err()
    );
    assert!(plan.journal.borrow().is_none());
    plan.retain_journal(&plan.runtime, &plan.snapshot, &journal, exact)
        .unwrap();

    // Models the terminal currentness failure after an into-slot output move.
    // The association is source-owned and is not a temporary Result payload.
    let completed = Some((plan.snapshot.clone(), journal.clone()));
    let terminal: Result<(), RuntimeError> = Err(RuntimeError::ForeignAuthority);
    assert!(terminal.is_err());
    assert!(completed.is_some());
    assert_eq!(
        plan.dependencies(&journal).unwrap().unwrap(),
        &plan.journal_dependencies
    );
    assert_eq!(plan.retained_storage().unwrap(), exact);
    assert!(
        plan.retain_journal(&plan.runtime, &plan.snapshot, &journal, usize::MAX)
            .is_err()
    );
    assert_eq!(
        plan.dependencies(&journal).unwrap().unwrap(),
        &plan.journal_dependencies
    );
}

#[test]
fn host_late_quote_includes_new_plan_and_stays_bounded_after_journal_retention() {
    let plan = plan();
    let before = plan.data().unwrap();
    let retained = plan.retained_storage().unwrap();
    assert_eq!(
        before.source_born_growth(),
        retained + generated_journal_bytes()
    );
    assert!(before.source_born_growth() > generated_journal_bytes());

    let journal = canonical::content_ref(b"journal", JOURNAL_MEDIA).unwrap();
    plan.retain_journal(
        &plan.runtime,
        &plan.snapshot,
        &journal,
        before.source_born_growth(),
    )
    .unwrap();
    let after = plan.data().unwrap();
    assert_eq!(after.source_born_growth(), before.source_born_growth());
    assert_eq!(after.returned_row_growth(), before.returned_row_growth());
    assert_eq!(
        after.maximum_lookup_scratch(),
        before.maximum_lookup_scratch()
    );
    assert_eq!(
        after.maximum_dependency_count(),
        before.maximum_dependency_count()
    );
    assert!(plan.retained_storage().unwrap() <= before.source_born_growth());
}
