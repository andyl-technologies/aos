//! Causal publication acceptance after a real leaf COMMIT and before facade success.

use super::*;
use crate::content_store::composition::DurabilityPolicyStore;
use crate::content_store::fixture_sqlite_connection;
use crate::content_store::physical_quota::PhysicalQuotaStore;
use crate::content_store::{BackendCapabilities, BlobStoreAdmin, ByteRange};
use std::cell::RefCell;

struct ReturnedLeaf {
    leaf: Arc<SqliteBlobBackend>,
    returned: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

impl ImmutableBlobBackend for ReturnedLeaf {
    fn name(&self) -> &str {
        self.leaf.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.leaf.capabilities()
    }

    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<crate::content_store::CheckedPublicationMetadata, StoreError> {
        self.leaf.checked_publication_metadata(kind)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.leaf.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.leaf.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.leaf.put_if_absent(id, source)
    }

    fn put_many_if_absent_with_boundary(
        &self,
        account: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let receipt = self
            .leaf
            .put_many_if_absent_with_boundary(account, objects, boundary)?;
        // Observe actual durable rows and generation only after SQL returns.
        // The late outer failure is causally separate from leaf completion.
        let connection = self.leaf.lock_connection()?;
        assert_eq!(load_metadata(&connection).expect("actual generation").1, 2);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                    .get::<_, u64>(0))
                .expect("actual committed rows"),
            2
        );
        drop(connection);
        self.returned.store(true, Ordering::SeqCst);
        Ok(receipt)
    }
}

struct OuterGuard {
    origin: Arc<Quota>,
    returned: Arc<AtomicBool>,
    fail_after_return: bool,
}

impl StorePhysicalQuotaGuard for OuterGuard {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.origin.decoded_metadata_limit()
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        self.origin.reserve_resources(descriptors, bytes)
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.origin.verify()?;
        if self.fail_after_return && self.returned.load(Ordering::SeqCst) {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }
}

fn observed_facade(
    root: &Path,
    origin: &Arc<Quota>,
    fail_after_return: bool,
) -> (
    PhysicalQuotaStore,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
    Arc<OuterGuard>,
) {
    let leaf = Arc::new(bounded_leaf("leaf", root, origin));
    let returned = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let observer: Arc<dyn ImmutableBlobBackend> = Arc::new(ReturnedLeaf {
        leaf: leaf.clone(),
        returned: returned.clone(),
        calls: calls.clone(),
    });
    let admin: Arc<dyn BlobStoreAdmin> = leaf;
    let guard = Arc::new(OuterGuard {
        origin: origin.clone(),
        returned: returned.clone(),
        fail_after_return,
    });
    let store = PhysicalQuotaStore::new("longer-outer-name", observer, admin, guard.clone())
        .expect("same original physical facade");
    (store, returned, calls, guard)
}

fn committed(error: &StoreError) {
    if let StoreError::SqliteDiagnostic { source } = error {
        return committed(source.failure());
    }
    let StoreError::SqliteScope { source } = error else {
        panic!("actual leaf outcome must survive outer failure: {error:?}");
    };
    assert_eq!(source.outcome(), busy::SqliteCommitOutcome::Committed);
    assert!(source.rollback_failure().is_none());
    assert!(source.restoration_failure().is_none());
}

#[test]
fn retained_unrelated_scope_cannot_redirect_publication_or_staging_loans() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::retained_unrelated_scope_cannot_redirect_publication_or_staging_loans",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let origin = original_quota();
    let unrelated = original_quota();
    let (physical, _, calls, _) = observed_facade(root.path(), &origin, false);
    let policy = DurabilityPolicyStore::new(
        "profile",
        Arc::new(physical),
        [(
            ObjectKind::Trace,
            crate::content_store::DurabilityRequirement::new(1, false)
                .expect("actual single-placement policy"),
        )]
        .into_iter()
        .collect(),
    );
    let account = DecodeBudget::for_store(origin.clone()).expect("actual original A");
    let other = DecodeBudget::for_store(unrelated.clone()).expect("independent finite B");
    assert!(crate::owned_decode::current_budget().is_none());
    let original_baseline = origin.0.used.load(Ordering::SeqCst);
    let unrelated_baseline = unrelated.0.used.load(Ordering::SeqCst);
    let unrelated_reservations = unrelated.0.reservations.load(Ordering::SeqCst);
    let foreign_scope = RefCell::new(None);

    let receipt = policy
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || {
            if foreign_scope.borrow().is_none() {
                *foreign_scope.borrow_mut() = Some(other.enter());
            }
            Ok(())
        })
        .expect("actual A remains the publication bank after callback installs B");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(origin.0.used.load(Ordering::SeqCst) >= original_baseline + 48 * 1024 * 1024);
    assert_eq!(unrelated.0.used.load(Ordering::SeqCst), unrelated_baseline);
    assert_eq!(
        unrelated.0.reservations.load(Ordering::SeqCst),
        unrelated_reservations
    );
    assert_eq!(
        receipt.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        objects().iter().map(|entry| entry.0).collect::<Vec<_>>()
    );
    assert!(
        receipt
            .iter()
            .all(|entry| entry.placements[0].backend == "longer-outer-name")
    );

    let receipt = receipt
        .accept_with_boundary(&mut || Ok(()))
        .expect("saved A accepts");
    drop(receipt);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), original_baseline);
    assert_eq!(unrelated.0.used.load(Ordering::SeqCst), unrelated_baseline);
    drop(foreign_scope.into_inner());
}

#[test]
fn callback_poison_refuses_before_physical_provider_or_sql_operation_start() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::callback_poison_refuses_before_physical_provider_or_sql_operation_start",
    ) {
        return;
    }
    for facade in [false, true] {
        let root = tempfile::tempdir().expect("private component catalog");
        let origin = original_quota();
        let leaf = Arc::new(bounded_leaf("leaf", root.path(), &origin));
        let store: Arc<dyn ImmutableBlobBackend> = if facade {
            Arc::new(
                PhysicalQuotaStore::new("physical", leaf.clone(), leaf.clone(), origin.clone())
                    .expect("actual original physical facade"),
            )
        } else {
            leaf.clone()
        };
        let original_baseline = origin.0.used.load(Ordering::SeqCst);
        let unrelated = original_quota();
        let other = DecodeBudget::for_store(unrelated.clone()).expect("independent finite B");
        let account = DecodeBudget::for_store(origin.clone()).expect("actual original bank");
        let _scope = account.enter();
        let reservations = origin.0.reservations.load(Ordering::SeqCst);
        let starts = origin.0.starts.load(Ordering::SeqCst);
        let mut first_refusal = None;
        let mut foreign_scope = None;

        let error = store
            .put_many_if_absent_with_boundary(&account, &objects(), &mut || {
                if first_refusal.is_none() {
                    foreign_scope = Some(other.enter());
                    let Err(error) = account.reserve_scratch_bytes(u64::MAX) else {
                        panic!("original bank must refuse impossible scratch");
                    };
                    first_refusal = Some(error);
                }
                Ok(())
            })
            .expect_err("ignored sticky refusal precedes any provider/start work");

        let StoreError::DecodeAdmission { source, .. } = &error else {
            panic!("actual original sticky cause remains inline");
        };
        assert_eq!(Some(source), first_refusal.as_ref());
        assert_eq!(origin.0.reservations.load(Ordering::SeqCst), reservations);
        assert_eq!(origin.0.starts.load(Ordering::SeqCst), starts);
        let connection = leaf.lock_connection().expect("observe unchanged database");
        assert_eq!(
            load_metadata(&connection).expect("original generation").1,
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                    .get::<_, u64>(0))
                .expect("no rows"),
            0
        );
        drop(connection);
        drop(foreign_scope);
        drop(_scope);
        drop(first_refusal);
        drop(account);
        drop(other);
        assert_eq!(unrelated.0.used.load(Ordering::SeqCst), 0);
        assert!(origin.0.used.load(Ordering::SeqCst) > original_baseline);
        drop(error);
        assert_eq!(origin.0.used.load(Ordering::SeqCst), original_baseline);
    }
}

#[test]
fn actual_admin_helpers_keep_the_original_bank_when_callbacks_retain_another_scope() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::actual_admin_helpers_keep_the_original_bank_when_callbacks_retain_another_scope",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let origin = original_quota();
    let unrelated = original_quota();
    let (physical, _, _, _) = observed_facade(root.path(), &origin, false);
    let store = Arc::new(physical);
    let account = DecodeBudget::for_store(origin.clone()).expect("actual original A");
    let other = DecodeBudget::for_store(unrelated.clone()).expect("independent finite B");
    let _scope = account.enter();
    let input = objects();
    drop(
        store
            .put_many_if_absent_with_boundary(&account, &input, &mut || Ok(()))
            .expect("actual published objects")
            .accept_with_boundary(&mut || Ok(()))
            .expect("original publication accepted"),
    );
    let original_baseline = origin.0.used.load(Ordering::SeqCst);
    let unrelated_baseline = unrelated.0.used.load(Ordering::SeqCst);
    let unrelated_reservations = unrelated.0.reservations.load(Ordering::SeqCst);
    let foreign_scope = RefCell::new(None);
    let mut callback = || {
        if foreign_scope.borrow().is_none() {
            *foreign_scope.borrow_mut() = Some(other.enter());
        }
        Ok(())
    };

    let mut fence = store
        .acquire_inventory_fence_with_boundary(&mut callback)
        .expect("same actual physical/admin pair acquires under A");
    let summary = fence
        .visit_inventory_with_boundary(&mut |_| Ok(()), &mut callback)
        .expect("original inventory helpers retain A");
    assert_eq!(summary.objects(), 2);
    let deletion = fence
        .delete_candidates_with_boundary(&[input[0].0, input[1].0], &mut callback)
        .expect("original deletion helpers retain A");

    assert_eq!(deletion.len(), 2);
    assert!(origin.0.used.load(Ordering::SeqCst) >= original_baseline + 48 * 1024 * 1024);
    assert_eq!(unrelated.0.used.load(Ordering::SeqCst), unrelated_baseline);
    assert_eq!(
        unrelated.0.reservations.load(Ordering::SeqCst),
        unrelated_reservations
    );
    drop(deletion);
    drop(summary);
    drop(fence);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), original_baseline);
    drop(foreign_scope.into_inner());
}

#[test]
fn durability_refusal_after_real_publication_retains_commit_and_original_bank() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::durability_refusal_after_real_publication_retains_commit_and_original_bank",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let origin = original_quota();
    let (physical, returned, calls, _) = observed_facade(root.path(), &origin, false);
    let policy = DurabilityPolicyStore::new(
        "profile",
        Arc::new(physical),
        [(
            ObjectKind::Trace,
            crate::content_store::DurabilityRequirement::new(2, false)
                .expect("explicit two-placement requirement"),
        )]
        .into_iter()
        .collect(),
    );
    let account = DecodeBudget::for_store(origin.clone()).expect("original finite account");
    let _scope = account.enter();
    let baseline = origin.0.used.load(Ordering::SeqCst);

    let error = policy
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || Ok(()))
        .expect_err("durability policy refuses the actual single placement");

    assert!(returned.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    committed(&error);
    assert!(matches!(
        error.original_failure(),
        StoreError::DurabilityUnsatisfied {
            minimum_durable_placements: 2,
            observed_durable_placements: 1,
            ..
        }
    ));
    assert!(origin.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);
    drop(error);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn physical_origin_refusal_after_leaf_return_retains_commit_and_both_loans() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::physical_origin_refusal_after_leaf_return_retains_commit_and_both_loans",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let origin = original_quota();
    let (store, returned, calls, guard) = observed_facade(root.path(), &origin, true);
    let account = DecodeBudget::for_store(guard).expect("original finite account");
    let _scope = account.enter();
    let baseline = origin.0.used.load(Ordering::SeqCst);

    let error = store
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || Ok(()))
        .expect_err("callback ignoring origin cannot accept a revoked facade");

    assert!(returned.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    committed(&error);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(origin.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);
    drop(error);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn outer_callback_refusal_after_leaf_return_preserves_original_failure() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::outer_callback_refusal_after_leaf_return_preserves_original_failure",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let origin = original_quota();
    let (store, returned, _, _) = observed_facade(root.path(), &origin, false);
    let account = DecodeBudget::for_store(origin.clone()).expect("original finite account");
    let _scope = account.enter();
    let baseline = origin.0.used.load(Ordering::SeqCst);

    let error = store
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || {
            if returned.load(Ordering::SeqCst) {
                Err(StoreError::Quota)
            } else {
                Ok(())
            }
        })
        .expect_err("actual outer callback refuses after committed leaf");

    committed(&error);
    assert!(matches!(error.original_failure(), StoreError::Quota));
    assert!(origin.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);
    drop(error);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn prepared_name_and_resource_refusal_precedes_the_actual_child() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::prepared_name_and_resource_refusal_precedes_the_actual_child",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let origin = original_quota();
    let (store, returned, calls, _) = observed_facade(root.path(), &origin, false);
    let account = DecodeBudget::for_store(origin.clone()).expect("original finite account");
    let _scope = account.enter();
    let baseline = origin.0.used.load(Ordering::SeqCst);
    let blocker = origin
        .reserve_resources(0, origin.0.maximum - baseline - 1)
        .expect("leave insufficient original capacity for facade resources");

    let error = store
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || Ok(()))
        .expect_err("preparation refuses before child publication");

    assert!(matches!(error.original_failure(), StoreError::Quota));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!returned.load(Ordering::SeqCst));
    drop(error);
    drop(blocker);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);
    let connection =
        fixture_sqlite_connection(root.path().join(DATABASE_FILE)).expect("actual database");
    assert_eq!(
        load_metadata(&connection.lock().expect("managed metadata connection"))
            .expect("unchanged generation")
            .1,
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                .get::<_, u64>(0))
            .expect("unchanged physical rows"),
        0
    );
    drop(connection);
    let receipt = store
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || Ok(()))
        .expect("unchanged original bank retries after competitor closes")
        .accept_with_boundary(&mut || Ok(()))
        .expect("same original operation accepts retry");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(receipt);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);
}

#[test]
fn poisoned_original_refuses_before_provider_or_child_work() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::poisoned_original_refuses_before_provider_or_child_work",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let origin = original_quota();
    let (store, _, calls, _) = observed_facade(root.path(), &origin, false);
    let account = DecodeBudget::for_store(origin.clone()).expect("original finite account");
    let _scope = account.enter();
    let refusal = match account.reserve_scratch_bytes(origin.0.maximum) {
        Ok(_) => panic!("original account control must make whole-bank request refuse"),
        Err(error) => error,
    };
    let checks = origin.0.checks.load(Ordering::SeqCst);
    let baseline = origin.0.used.load(Ordering::SeqCst);

    let error = store
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || Ok(()))
        .expect_err("ignore-origin callback cannot replace the poisoned bank");

    let StoreError::DecodeAdmission { source, .. } = error else {
        panic!("original sticky error must remain inline");
    };
    assert_eq!(source, refusal);
    assert_eq!(origin.0.checks.load(Ordering::SeqCst), checks);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unaccepted_output_retains_bank_until_same_original_acceptance_or_error_drop() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::unaccepted_output_retains_bank_until_same_original_acceptance_or_error_drop",
    ) {
        return;
    }
    let root = tempfile::tempdir().expect("private component catalog");
    let origin = original_quota();
    let backend = bounded_leaf("leaf", root.path(), &origin);
    let account = DecodeBudget::for_store(origin.clone()).expect("original finite account");
    let scope = account.enter();
    let baseline = origin.0.used.load(Ordering::SeqCst);
    let receipt = backend
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || Ok(()))
        .expect("actual committed output");
    let pending = origin.0.used.load(Ordering::SeqCst);
    assert!(pending >= baseline + 48 * 1024 * 1024);
    drop(scope);

    let mut calls = 0;
    let receipt = receipt
        .accept_with_boundary(&mut || {
            calls += 1;
            Ok(())
        })
        .expect("saved genuine account works after creating scope closes");
    assert_eq!(calls, 1);
    assert!(origin.0.used.load(Ordering::SeqCst) < pending - 48 * 1024 * 1024);
    assert_eq!(receipt.len(), 3);
    drop(receipt);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);

    let scope = account.enter();
    let receipt = backend
        .put_many_if_absent_with_boundary(&account, &objects(), &mut || Ok(()))
        .expect("same-bank original replay");
    origin.0.revoked.store(true, Ordering::SeqCst);
    drop(scope);
    let error = receipt
        .accept_with_boundary(&mut || Ok(()))
        .expect_err("ignored origin refuses acceptance without renewing a bank");
    committed(&error);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(origin.0.used.load(Ordering::SeqCst) >= baseline + 48 * 1024 * 1024);
    drop(error);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);
}

#[derive(Clone, Copy, Debug)]
enum CheckedOperation {
    Publish,
    SqlSource,
    PhysicalSource,
    Acquire,
    Visit,
    Delete,
}

fn run_checked_operation(
    account: &DecodeBudget,
    operation: CheckedOperation,
    physical: &PhysicalQuotaStore,
    leaf: &SqliteBlobBackend,
    input: &[(ContentId, BlobHandle)],
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    match operation {
        CheckedOperation::Publish => physical
            .put_many_if_absent_with_boundary(account, input, boundary)
            .map(drop),
        CheckedOperation::SqlSource | CheckedOperation::PhysicalSource => {
            let handle = match operation {
                CheckedOperation::SqlSource => leaf.read(input[0].0, None)?,
                _ => physical.read(input[0].0, None)?,
            };
            handle
                .read_all_with_boundary(account, handle.logical_length(), boundary)
                .map(drop)
        }
        CheckedOperation::Acquire => physical
            .acquire_inventory_fence_with_boundary(boundary)
            .map(drop),
        CheckedOperation::Visit | CheckedOperation::Delete => {
            let mut fence = physical.acquire_inventory_fence_with_boundary(&mut || Ok(()))?;
            match operation {
                CheckedOperation::Visit => fence
                    .visit_inventory_with_boundary(&mut |_| Ok(()), boundary)
                    .map(drop),
                _ => fence
                    .delete_candidates_with_boundary(&[input[0].0, input[1].0], boundary)
                    .map(drop),
            }
        }
    }
}

#[test]
fn later_callback_poison_stops_provider_work_in_publication_sources_and_admin() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::later_callback_poison_stops_provider_work_in_publication_sources_and_admin",
    ) {
        return;
    }
    for operation in [
        CheckedOperation::Publish,
        CheckedOperation::SqlSource,
        CheckedOperation::PhysicalSource,
        CheckedOperation::Acquire,
        CheckedOperation::Visit,
        CheckedOperation::Delete,
    ] {
        // Measure the actual successful poll sequence, then inject refusal at
        // every later poll, including post-COMMIT/final facade acceptance.
        let mut polls = 0;
        for poison_at in std::iter::once(None).chain((2..=128).map(Some)) {
            if poison_at.is_some_and(|position| position > polls) {
                break;
            }
            let root = tempfile::tempdir().expect("private component catalog");
            let origin = original_quota();
            let leaf = Arc::new(bounded_leaf("leaf", root.path(), &origin));
            let physical =
                PhysicalQuotaStore::new("physical", leaf.clone(), leaf.clone(), origin.clone())
                    .expect("actual physical pair");
            let input = objects();
            let creating_baseline = origin.0.used.load(Ordering::SeqCst);
            let account = DecodeBudget::for_store(origin.clone()).expect("original A");
            let scope = account.enter();
            if !matches!(operation, CheckedOperation::Publish) {
                drop(
                    physical
                        .put_many_if_absent_with_boundary(&account, &input, &mut || Ok(()))
                        .expect("real source rows")
                        .accept_with_boundary(&mut || Ok(()))
                        .expect("source publication accepted"),
                );
            }
            let mut calls = 0;
            let mut at_refusal = None;
            let result =
                run_checked_operation(&account, operation, &physical, &leaf, &input, &mut || {
                    calls += 1;
                    if poison_at == Some(calls) {
                        assert!(account.reserve_scratch_bytes(u64::MAX).is_err());
                        at_refusal = Some((
                            origin.0.checks.load(Ordering::SeqCst),
                            origin.0.reservations.load(Ordering::SeqCst),
                            origin.0.starts.load(Ordering::SeqCst),
                        ));
                    }
                    Ok(())
                });
            if poison_at.is_none() {
                result.expect("reference operation");
                polls = calls;
                assert!((3..=128).contains(&polls), "{operation:?}: {polls}");
                continue;
            }

            let error = result.expect_err("ignored sticky refusal must stop the operation");
            assert!(matches!(
                original_failure(&error),
                StoreError::DecodeAdmission { .. }
            ));
            assert_eq!(calls, poison_at.expect("injected poll"), "{operation:?}");
            assert_eq!(
                at_refusal.expect("actual refusal reached"),
                (
                    origin.0.checks.load(Ordering::SeqCst),
                    origin.0.reservations.load(Ordering::SeqCst),
                    origin.0.starts.load(Ordering::SeqCst),
                ),
                "{operation:?}: no later provider verification, loan, or start",
            );
            // Read the real physical outcome without invoking the poisoned
            // provider. A durable mutation requires its retained COMMIT token.
            let connection = leaf.lock_connection().expect("actual connection");
            let generation = load_metadata(&connection).expect("actual generation").1;
            if (matches!(operation, CheckedOperation::Publish) && generation == 2)
                || (matches!(operation, CheckedOperation::Delete) && generation > 2)
            {
                committed(&error);
            }
            drop(connection);
            drop(error);
            drop(scope);
            drop(account);
            assert_eq!(origin.0.used.load(Ordering::SeqCst), creating_baseline);
        }
    }
}

struct DestructionProbe {
    owner: Arc<OriginalResources>,
    _bytes: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

impl Drop for DestructionProbe {
    fn drop(&mut self) {
        assert!(
            !self.owner.watched_loan_closed.load(Ordering::SeqCst),
            "resource body must close before its prepared-node/byte credit"
        );
        self.owner.resource_drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn actual_receipt_resource_credit_outlives_error_and_unwind_destruction() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::actual_receipt_resource_credit_outlives_error_and_unwind_destruction",
    ) {
        return;
    }
    for unwind in [false, true] {
        let root = tempfile::tempdir().expect("private component catalog");
        let origin = original_quota();
        let leaf = bounded_leaf("leaf", root.path(), &origin);
        let account = DecodeBudget::for_store(origin.clone()).expect("original A");
        let _scope = account.enter();
        let baseline = origin.0.used.load(Ordering::SeqCst);
        let mut receipt = leaf
            .put_many_if_absent_with_boundary(&account, &objects(), &mut || Ok(()))
            .expect("actual committed receipt");
        let control = account
            .reserve_scratch_bytes(
                crate::owned_decode::ResourceLoan::allocation_bytes::<DestructionProbe>()
                    + (std::mem::size_of::<std::sync::Mutex<Option<Vec<u8>>>>()
                        + 2 * std::mem::size_of::<usize>()) as u64,
            )
            .expect("probe and payload controls before allocation");
        // The sealed loan hides its body. This separate prepaid slot admits
        // bytes only after the existing prepared-node/byte credit is acquired.
        let bytes = Arc::new(std::sync::Mutex::new(None));
        let resource = crate::owned_decode::ResourceLoan::new(DestructionProbe {
            owner: origin.0.clone(),
            _bytes: bytes.clone(),
        });
        let before = origin.0.used.load(Ordering::SeqCst);
        let prepared =
            crate::content_store::admin::PreparedResources::new(&account, resource, 12_345)
                .expect("actual bounded byte body and resource-node loan");
        let node_credit = origin.0.used.load(Ordering::SeqCst) - before;
        origin
            .0
            .watched_loan_bytes
            .store(node_credit, Ordering::SeqCst);
        *bytes.lock().expect("probe state") = Some(vec![0; 12_345]);
        drop(bytes);
        receipt.retain_resources(prepared);

        if unwind {
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = receipt.check(|_| panic!("intentional acceptance unwind"));
            }));
            assert!(panic.is_err());
        } else {
            let error = receipt
                .check(|_| Err(StoreError::Unauthorized))
                .expect_err("actual post-COMMIT acceptance refusal");
            committed(&error);
            assert_eq!(origin.0.resource_drops.load(Ordering::SeqCst), 1);
            assert!(origin.0.watched_loan_closed.load(Ordering::SeqCst));
            drop(error);
        }
        assert_eq!(origin.0.resource_drops.load(Ordering::SeqCst), 1);
        assert!(origin.0.watched_loan_closed.load(Ordering::SeqCst));
        // Both probe and payload controls close before their control loan.
        drop(control);
        assert_eq!(origin.0.used.load(Ordering::SeqCst), baseline);
    }
}

struct CompletedSource {
    handle: BlobHandle,
    completed: Arc<AtomicBool>,
}

impl crate::content_store::BlobSource for CompletedSource {
    fn checked_read_access(&self) -> crate::content_store::CheckedReadAccess {
        crate::content_store::CheckedReadAccess::Whole
    }

    fn logical_length(&self) -> u64 {
        self.handle.logical_length()
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        self.handle.open()
    }

    fn read_all_with_boundary(
        &self,
        account: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crate::content_store::OwnedBlobBytes, StoreError> {
        let output = self
            .handle
            .read_all_with_boundary(account, maximum, boundary)?;
        self.completed.store(true, Ordering::SeqCst);
        Ok(output)
    }
}

#[test]
fn outer_completion_poison_precedes_hashing_and_closes_the_returned_byte_owner() {
    let origin = original_quota();
    let creating_baseline = origin.0.used.load(Ordering::SeqCst);
    let account = DecodeBudget::for_store(origin.clone()).expect("caller A");
    let scope = account.enter();
    let completed = Arc::new(AtomicBool::new(false));
    let mut handle = BlobHandle::new(CompletedSource {
        handle: BlobHandle::from_bytes(b"actual returned bytes"),
        completed: completed.clone(),
    });
    // An intentionally wrong exposed identity makes the postponed hash an
    // observable competing failure, rather than merely counting callbacks.
    handle.integrity_id = Some(ContentId::for_bytes(
        ObjectKind::Trace,
        1,
        b"different bytes",
    ));
    let mut post_source_calls = 0;
    let error = handle
        .read_all_with_boundary(&account, handle.logical_length(), &mut || {
            if completed.load(Ordering::SeqCst) {
                post_source_calls += 1;
                assert!(account.reserve_scratch_bytes(u64::MAX).is_err());
            }
            Ok(())
        })
        .expect_err("caller refusal precedes competing exposed-body hash failure");
    assert!(matches!(
        original_failure(&error),
        StoreError::DecodeAdmission { .. }
    ));
    assert_eq!(post_source_calls, 1);
    drop(handle);
    drop(scope);
    drop(account);
    assert!(origin.0.used.load(Ordering::SeqCst) > creating_baseline);
    drop(error);
    assert_eq!(origin.0.used.load(Ordering::SeqCst), creating_baseline);
}

#[test]
fn existing_object_chunk_refusal_keeps_explicit_caller_custody_without_ambient_capture() {
    if isolated_heap_test(
        "content_store::sqlite::batch::tests::publication_acceptance::existing_object_chunk_refusal_keeps_explicit_caller_custody_without_ambient_capture",
    ) {
        return;
    }
    for retain_unrelated in [false, true] {
        assert!(crate::owned_decode::current_budget().is_none());
        let root = tempfile::tempdir().expect("actual component catalog");
        let origin = original_quota();
        let baseline = origin.0.used.load(Ordering::SeqCst);
        let leaf = bounded_leaf("replay", root.path(), &origin);
        // Staging reserves the whole 65537-byte body, while authenticated
        // replay independently reserves its actual 65536-byte SQL chunk.
        let bytes = vec![19; 65_537];
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let handle = BlobHandle::from_bytes(bytes);
        leaf.put_if_absent(id, &handle)
            .expect("actual existing canonical object");
        let account = DecodeBudget::for_store(origin.clone()).expect("explicit caller A");
        let unrelated = original_quota();
        let weak_unrelated = Arc::downgrade(&unrelated);
        let other = DecodeBudget::for_store(unrelated.clone()).expect("independent finite B");
        let mut foreign_scope = None;
        let mut competing_loan = None;
        let error = leaf
            .put_many_if_absent_with_boundary(&account, &[(id, handle)], &mut || {
                if retain_unrelated && foreign_scope.is_none() {
                    foreign_scope = Some(other.enter());
                }
                let used = origin.0.used.load(Ordering::SeqCst);
                if competing_loan.is_none() && used >= 48 * 1024 * 1024 {
                    competing_loan =
                        Some(origin.reserve_resources(0, origin.0.maximum - used - 16 * 1024)?);
                }
                Ok(())
            })
            .expect_err("real original bank refuses the existing-object chunk");

        assert!(competing_loan.is_some(), "actual diagnostic phase reached");
        assert_eq!(origin.0.last_refused_bytes.load(Ordering::SeqCst), 65_536);
        let StoreError::DecodeAdmission { source, custody } = original_failure(&error) else {
            panic!("original typed chunk admission failure");
        };
        assert!(custody.is_some(), "explicit A survives even with TLS None");
        assert!(matches!(
            std::error::Error::source(source).and_then(|cause| cause.downcast_ref::<StoreError>()),
            Some(StoreError::Quota)
        ));
        let connection = leaf.lock_connection().expect("real transaction unwound");
        assert_eq!(
            load_metadata(&connection).expect("unchanged generation").1,
            2
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                    .get::<_, u64>(0))
                .expect("actual unchanged rows"),
            1
        );
        drop(connection);

        drop(foreign_scope);
        drop(other);
        drop(unrelated);
        assert!(
            weak_unrelated.upgrade().is_none(),
            "error does not retain B"
        );
        drop(competing_loan);
        drop(account);
        drop(leaf);
        let resources = origin.0.clone();
        let weak_origin = Arc::downgrade(&origin);
        drop(origin);
        assert!(weak_origin.upgrade().is_some(), "error retains actual A");
        drop(error);
        assert!(weak_origin.upgrade().is_none());
        assert_eq!(resources.used.load(Ordering::SeqCst), baseline);
    }
}

#[test]
fn full_integrity_identity_still_hashes_the_exposed_synchronous_output() {
    for previously_authenticated in [false, true] {
        let origin = original_quota();
        let account = DecodeBudget::for_store(origin).expect("finite original caller");
        let completed = Arc::new(AtomicBool::new(false));
        let mut handle = BlobHandle::new(CompletedSource {
            handle: BlobHandle::from_bytes(b"actual returned bytes"),
            completed: completed.clone(),
        });
        let wrong = ContentId::for_bytes(ObjectKind::Trace, 1, b"different bytes");
        handle.integrity_id = Some(wrong);
        if previously_authenticated {
            handle.authenticated_id = Some(wrong);
        }

        let error = handle
            .read_all_with_boundary(&account, handle.logical_length(), &mut || Ok(()))
            .expect_err("both unknown and matching full IDs require exposed-output hashing");

        assert!(completed.load(Ordering::SeqCst));
        assert!(matches!(original_failure(&error), StoreError::Corrupt { id } if *id == wrong));
    }
}
