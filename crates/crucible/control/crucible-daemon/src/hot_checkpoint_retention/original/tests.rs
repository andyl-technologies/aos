//! Checks real fresh namespace locks, alias controls and original postcuts.
//!
//! Temporary directories and the existing local catalog fixture are mechanism
//! inputs, not an authenticated workflow or physical quota entitlement.

// crucible-lint: allow panic-shortcut -- failed real ownership assertions stop these controls.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::private_measurement_runtime::catalog::tests::{GraphQuotaFixture, fixture};

#[test]
fn strong_and_weak_aliases_keep_actual_writer_and_external_credit() {
    let (_root, decoder, catalog) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("fresh");
    let quota = Arc::new(GraphQuotaFixture(decoder.budget().unwrap().clone()));
    let mut owner = OriginalHotCheckpointRetentionOwner::prepare_at(
        &path,
        catalog.supervisor().unwrap(),
        quota,
        decoder.budget().unwrap(),
    )
    .unwrap();
    let alias = owner.share().unwrap();
    let weak = Arc::downgrade(&alias);
    let inner_weak = Arc::downgrade(&alias.inner);
    let competitor = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.join("writer.lock"))
        .unwrap();

    assert!(flock(&competitor, FlockOperation::NonBlockingLockExclusive).is_err());
    assert!(matches!(
        owner.try_close().unwrap_err().source,
        OriginalRetentionCause::Aliases
    ));
    assert!(owner.credit.is_some());
    drop(alias);
    assert!(matches!(
        owner.try_close().unwrap_err().source,
        OriginalRetentionCause::Aliases
    ));
    assert!(owner.credit.is_some());
    assert!(flock(&competitor, FlockOperation::NonBlockingLockExclusive).is_err());
    drop(weak);
    assert!(matches!(
        owner.try_close().unwrap_err().source,
        OriginalRetentionCause::Aliases
    ));
    assert!(owner.credit.is_some());
    drop(inner_weak);

    owner.try_close().unwrap();
    owner.try_close().unwrap();
    assert!(owner.credit.is_none());
    assert!(owner.store.is_none());
    flock(&competitor, FlockOperation::NonBlockingLockExclusive).unwrap();
    flock(&competitor, FlockOperation::Unlock).unwrap();
    drop(competitor);
    drop(owner);
    catalog.try_close().unwrap();
    assert!(decoder.try_close().is_ok());
}

#[test]
fn already_canceled_original_refuses_before_namespace_creation() {
    let (root, decoder, catalog) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("fresh");
    let quota = Arc::new(GraphQuotaFixture(decoder.budget().unwrap().clone()));
    let supervisor = catalog.supervisor().unwrap();
    root.cancel().unwrap();

    let result = OriginalHotCheckpointRetentionOwner::prepare_at(
        &path,
        supervisor,
        quota,
        decoder.budget().unwrap(),
    );

    assert!(matches!(
        result.err().unwrap().source,
        OriginalRetentionCause::Original(_)
    ));
    assert!(!path.exists());
}

#[test]
fn successful_open_is_published_before_later_original_refusal() {
    let (root, decoder, catalog) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let quota = Arc::new(GraphQuotaFixture(decoder.budget().unwrap().clone()));
    let mut owner = OriginalHotCheckpointRetentionOwner {
        store: None,
        staged_root: None,
        staged_lock: None,
        credit: Some(quota.reserve_resources(2, 4096).unwrap()),
        catalog: catalog.supervisor().unwrap(),
        quota,
        budget: decoder.budget().unwrap().clone(),
        custody: decoder.budget().unwrap().custody(),
        closed: false,
    };
    let operation = owner
        .catalog
        .begin(SqliteCatalogOperationKind::Write)
        .unwrap();
    let opened = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(directory.path().join("writer.lock"));
    assert!(opened.is_ok());
    root.cancel().unwrap();

    let error = OriginalHotCheckpointRetentionOwner::publish_writer(
        &mut owner.staged_lock,
        &owner.budget,
        operation.as_ref(),
        opened,
    )
    .unwrap_err();

    assert!(matches!(error.source, OriginalRetentionCause::Store(_)));
    assert!(error.original_after.is_some());
    assert!(owner.staged_lock.is_some());
    assert!(owner.credit.is_some());
}

#[test]
fn kernel_refusal_stays_first_with_separate_actual_scope_refusals() {
    let (root, decoder, catalog) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let quota = Arc::new(GraphQuotaFixture(decoder.budget().unwrap().clone()));
    let mut owner = OriginalHotCheckpointRetentionOwner::prepare_at(
        &directory.path().join("fresh"),
        catalog.supervisor().unwrap(),
        quota,
        decoder.budget().unwrap(),
    )
    .unwrap();
    let operation = owner
        .catalog
        .begin(SqliteCatalogOperationKind::Write)
        .unwrap();
    let actual = File::open(directory.path().join("absent"));
    root.cancel().unwrap();

    let error = owner.kernel(operation.as_ref(), actual).unwrap_err();

    assert!(
        matches!(error.source, OriginalRetentionCause::Kernel { ref source, .. }
        if source.kind() == io::ErrorKind::NotFound)
    );
    assert!(matches!(
        error.source,
        OriginalRetentionCause::Kernel {
            operation_after: Some(_),
            ..
        }
    ));
    assert!(error.original_after.is_some());
    assert!(owner.try_close().is_err());
    assert!(owner.credit.is_some());
}

#[test]
fn unwind_keeps_real_writer_lock_in_original_containment() {
    let (_root, decoder, catalog) = fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("fresh");
    let quota = Arc::new(GraphQuotaFixture(decoder.budget().unwrap().clone()));
    let owner = OriginalHotCheckpointRetentionOwner::prepare_at(
        &path,
        catalog.supervisor().unwrap(),
        quota,
        decoder.budget().unwrap(),
    )
    .unwrap();
    let competitor = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.join("writer.lock"))
        .unwrap();

    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _actual_owner = owner;
        panic!("intentional ownership-unwind control");
    }));

    assert!(observed.is_err());
    assert!(flock(&competitor, FlockOperation::NonBlockingLockExclusive).is_err());
    // No retry or physical closure is asserted after uncertainty. The actual
    // process retains the writer and its original loans until teardown.
}
