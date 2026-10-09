//! Actual bounded-read state and original failure continuation witnesses.

use super::*;
use crate::owned_decode::DecodeBudget;
use crate::ram::codec::{TreeNode, TreeRef};
use crate::ram::read_failure::RamReadContinuation;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum Reply {
    Same,
    Swallow,
    Distinct,
    CompletedCleanup,
    Double,
    Incomplete,
    EarlyFailure,
}

struct Provider {
    inner: Arc<dyn ImmutableBlobBackend>,
    reply: Reply,
    calls: AtomicUsize,
}

impl ImmutableBlobBackend for Provider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, _: ContentId, _: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        panic!("the nominal request must use only checked reads")
    }

    fn put_if_absent(&self, _: ContentId, _: &BlobHandle) -> Result<PutReceipt, StoreError> {
        panic!("a bounded read cannot publish")
    }

    fn read_bounded_with_boundary(
        &self,
        request: &mut BoundedReadRequest<'_, '_>,
    ) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.reply, Reply::Incomplete) {
            return Ok(());
        }
        if matches!(self.reply, Reply::EarlyFailure) {
            return Err(StoreError::Unavailable);
        }
        let first = self.inner.read_bounded_with_boundary(request);
        match self.reply {
            Reply::Same => first,
            Reply::Swallow => {
                assert!(first.is_err());
                Ok(())
            }
            Reply::Distinct => {
                assert!(first.is_err());
                Err(StoreError::Quota)
            }
            Reply::CompletedCleanup => {
                first?;
                Err(StoreError::Unavailable)
            }
            Reply::Double => {
                let second = self.inner.read_bounded_with_boundary(request);
                match (first, second) {
                    (
                        Err(StoreError::RamValidation { source: first }),
                        Err(StoreError::RamValidation { source: second }),
                    ) => {
                        assert_eq!(first, second, "the refused request keeps its allocation");
                        Err(StoreError::RamValidation { source: second })
                    }
                    (
                        Err(StoreError::RamReadValidation { source: first }),
                        Err(StoreError::RamReadValidation { source: second }),
                    ) => {
                        assert_eq!(first, second, "the refused request keeps its allocation");
                        assert_clean_read_scope(first.storage_failure());
                        Err(StoreError::RamReadValidation { source: second })
                    }
                    _ => panic!("a failed request must remain failed on a second execution"),
                }
            }
            Reply::Incomplete => unreachable!("incomplete provider returned before execution"),
            Reply::EarlyFailure => unreachable!("early provider failure returned before execution"),
        }
    }
}

fn original_error(error: &RamStoreError) -> &RamStoreError {
    match error {
        RamStoreError::Store(StoreError::RamValidation { source }) => source.storage_failure(),
        RamStoreError::Store(StoreError::RamReadValidation { source }) => source.first_validation(),
        RamStoreError::Store(StoreError::RamReadContinuation { source }) => source.first_failure(),
        error => error,
    }
}

fn assert_clean_read_scope(error: &RamStoreError) {
    use std::error::Error;
    let mut current: &(dyn Error + 'static) = error;
    loop {
        if let Some(scope) = current.downcast_ref::<crate::content_store::SqliteScopeError>() {
            assert_eq!(
                scope.outcome(),
                crate::content_store::SqliteCommitOutcome::NotCommitted
            );
            assert!(scope.rollback_failure().is_none());
            assert!(scope.restoration_failure().is_none());
            return;
        }
        current = current
            .source()
            .expect("the actual original read scope stays owned");
    }
}

#[test]
fn transfer_task_preserves_first_validation_cleanup_and_sticky_same_work_retry() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(128),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &original,
            &mut || Ok(()),
        )
        .unwrap();

    for reply in [Reply::Same, Reply::Swallow, Reply::Distinct, Reply::Double] {
        let operation = original.child().unwrap();
        let mut malformed = root.clone();
        operation
            .charge_bytes(crate::ram::record_account::shared_extent::<TreeRef>().unwrap())
            .unwrap();
        malformed.regions = Arc::new([TreeRef {
            pages: 0,
            ..root.regions[0]
        }]);
        let provider = Provider {
            inner: store.backend.clone(),
            reply,
            calls: AtomicUsize::new(0),
        };
        let mut polls = 0;
        let mut boundary = || {
            polls += 1;
            Ok(())
        };
        let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
        let response = operation.child().unwrap();
        let scope = response.enter();
        let first = crate::ram::bounded_read::read_canonical_tree(
            &provider,
            malformed.regions[0],
            &response,
            &mut work,
        )
        .err()
        .unwrap();
        assert!(matches!(
            original_error(&first),
            RamStoreError::Invalid("tree reference geometry")
        ));
        if let RamStoreError::Store(StoreError::RamReadValidation { source }) = &first {
            assert_clean_read_scope(source.storage_failure());
        }
        if matches!(reply, Reply::Distinct) {
            let RamStoreError::Store(StoreError::RamReadContinuation { source }) = &first else {
                panic!("distinct provider cleanup stays beside the actual first transfer failure");
            };
            assert!(matches!(source.returned_failure(), StoreError::Quota));
            assert!(source.first_boundary().is_none());
        }
        let counts = (work.visits, work.io_bytes);
        let retry = crate::ram::bounded_read::read_canonical_tree(
            &provider,
            malformed.regions[0],
            &response,
            &mut work,
        )
        .err()
        .unwrap();
        assert!(matches!(
            original_error(&retry),
            RamStoreError::Invalid("tree reference geometry")
        ));
        assert_eq!((work.visits, work.io_bytes), counts);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        drop(work);
        assert!(polls > 0);
        drop((retry, first, scope, response, malformed, operation));
        original.verify_live().unwrap();
    }
}

#[test]
fn transfer_task_never_exposes_completed_bytes_after_provider_or_incomplete_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(128),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    for reply in [
        Reply::CompletedCleanup,
        Reply::Incomplete,
        Reply::EarlyFailure,
    ] {
        let provider = Provider {
            inner: store.backend.clone(),
            reply,
            calls: AtomicUsize::new(0),
        };
        let operation = original.child().unwrap();
        let mut boundary = || Ok(());
        let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
        let response = operation.child().unwrap();
        let scope = response.enter();
        let first = crate::ram::bounded_read::read_canonical(
            &provider,
            root.object_id(),
            &response,
            &mut work,
        )
        .err()
        .unwrap();
        let RamStoreError::Store(error) = &first else {
            panic!("the actual provider refusal keeps its store category");
        };
        match reply {
            Reply::CompletedCleanup | Reply::EarlyFailure => {
                assert!(matches!(error.original_failure(), StoreError::Unavailable))
            }
            Reply::Incomplete => assert!(matches!(
                error.original_failure(),
                StoreError::Unsupported {
                    capability: "bounded-read-request-not-completed"
                }
            )),
            _ => unreachable!("only completed/incomplete controls are selected"),
        }
        let before = (work.visits, work.io_bytes);
        let retained = work.account.read_failure().unwrap();
        let retry = crate::ram::bounded_read::read_canonical(
            &provider,
            root.object_id(),
            &response,
            &mut work,
        )
        .err()
        .unwrap();
        let (
            StoreError::RamValidation { source: retained },
            RamStoreError::Store(StoreError::RamValidation { source: retry }),
        ) = (retained, retry)
        else {
            panic!("the same operation retains identical original failure custody");
        };
        assert_eq!(retained, retry);
        assert_eq!((work.visits, work.io_bytes), before);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        drop((scope, response, work));
    }
}

#[test]
fn failed_provider_cannot_erase_first_validation_or_retry_effects() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let retention = Retention::default();
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let malformed = TreeRef {
        pages: 0,
        ..root.regions[0]
    };

    for reply in [Reply::Same, Reply::Swallow, Reply::Distinct, Reply::Double] {
        let provider = Provider {
            inner: store.backend.clone(),
            reply,
            calls: AtomicUsize::new(0),
        };
        let operation = original.child().unwrap();
        let mut polls = 0;
        let mut boundary = || {
            polls += 1;
            Ok(())
        };
        let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
        let error = crate::ram::bounded_read::read_tree(&provider, malformed, &mut work)
            .err()
            .unwrap();
        assert!(matches!(
            original_error(&error),
            RamStoreError::Invalid("tree reference geometry")
        ));
        if let RamStoreError::Store(StoreError::RamReadValidation { source }) = &error {
            assert_clean_read_scope(source.storage_failure());
        }
        if let Reply::Distinct = reply {
            let RamStoreError::Store(StoreError::RamReadContinuation { source }) = &error else {
                panic!("distinct provider failure must remain owned beside the first cause");
            };
            assert!(matches!(source.returned_failure(), StoreError::Quota));
            assert!(source.first_boundary().is_none());
        }
        let before = (work.visits, work.io_bytes);
        let retried = crate::ram::bounded_read::read_tree(&provider, malformed, &mut work)
            .err()
            .unwrap();
        assert!(matches!(
            original_error(&retried),
            RamStoreError::Invalid("tree reference geometry")
        ));
        assert_eq!((work.visits, work.io_bytes), before);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        drop(work);
        assert!(polls > 0);
        drop((retried, error, operation));
        original.verify_live().unwrap();
    }
}

#[test]
fn complete_read_never_overrides_later_provider_cleanup_or_incomplete_success() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &original,
            &mut || Ok(()),
        )
        .unwrap();

    for reply in [
        Reply::CompletedCleanup,
        Reply::Incomplete,
        Reply::EarlyFailure,
    ] {
        let provider = Provider {
            inner: store.backend.clone(),
            reply,
            calls: AtomicUsize::new(0),
        };
        let operation = original.child().unwrap();
        let mut boundary = || Ok(());
        let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
        let error = crate::ram::bounded_read::read_tree(&provider, root.regions[0], &mut work)
            .err()
            .unwrap();
        let RamStoreError::Store(error) = &error else {
            panic!("provider refusal retains its complete store cause");
        };
        match reply {
            Reply::CompletedCleanup | Reply::EarlyFailure => {
                assert!(matches!(error.original_failure(), StoreError::Unavailable))
            }
            Reply::Incomplete => assert!(matches!(
                error.original_failure(),
                StoreError::Unsupported {
                    capability: "bounded-read-request-not-completed"
                }
            )),
            _ => unreachable!("only final reconciliation witnesses are selected"),
        }
        let first = work.account.read_failure().unwrap();
        let before = (work.visits, work.io_bytes);
        let retry = crate::ram::bounded_read::read_tree(&provider, root.regions[0], &mut work)
            .err()
            .unwrap();
        let (
            StoreError::RamValidation { source: first },
            RamStoreError::Store(StoreError::RamValidation { source: retry }),
        ) = (first, retry)
        else {
            panic!("provider-first failures retain the same original carrier on retry");
        };
        assert_eq!(first, retry);
        assert_eq!((work.visits, work.io_bytes), before);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn concrete_error_layout_preserves_both_existing_prepaid_extents() {
    // These declarations preserve the frozen predecessor's exact field types;
    // the comparison measures the replacement category slot, not a model size.
    // crucible-lint: allow rust-allow -- The predecessor fields are retained only to compare their exact layout.
    #[allow(dead_code)]
    struct PreviousAccount<'a> {
        original: &'a DecodeBudget,
        boundary_failure: Option<RamFailureCause<RamStoreError>>,
        validation_failure: Option<RamFailureCause<Infallible>>,
        boundary_slot: Option<PreparedRamFailure<RamStoreError>>,
        validation_slot: Option<PreparedRamFailure<Infallible>>,
    }
    // crucible-lint: allow rust-allow -- The predecessor fields are retained only to compare their exact layout.
    #[allow(dead_code)]
    struct PreviousWork<'a> {
        pending: Option<crate::ram::PendingBatch>,
        limits: RamStoreLimits,
        visits: u64,
        io_bytes: u64,
        boundary: &'a mut dyn FnMut() -> Result<(), RamStoreError>,
        account: PreviousAccount<'a>,
        destination: Option<PreviousAccount<'a>>,
    }
    assert_eq!(std::mem::size_of::<PreviousAccount<'_>>(), 120);
    assert_eq!(
        std::mem::size_of::<crate::ram::store_boundary::WorkAccount<'_>>(),
        104
    );
    assert!(std::mem::size_of::<Work<'_>>() <= std::mem::size_of::<PreviousWork<'_>>());
    assert_eq!(std::mem::size_of::<StoreError>(), 56);
    assert_eq!(std::mem::size_of::<RamStoreError>(), 56);
    assert_eq!(std::mem::size_of::<RamReadContinuation>(), 40);
    assert_eq!(std::mem::size_of::<crate::ram::RamReadValidation>(), 8);
    assert_eq!(
        std::mem::size_of::<crate::ram::read_failure::FirstReadCause>(),
        16
    );
    assert_eq!(
        PreparedRamFailure::<Infallible>::allocation_bytes().unwrap(),
        104
    );
    assert_eq!(
        PreparedRamFailure::<RamStoreError>::allocation_bytes().unwrap(),
        160
    );
    eprintln!(
        "actual_store={} actual_ram={} continuation={} result_unit_store={} result_tree_store={} request={}",
        std::mem::size_of::<StoreError>(),
        std::mem::size_of::<RamStoreError>(),
        std::mem::size_of::<RamReadContinuation>(),
        std::mem::size_of::<Result<(), StoreError>>(),
        std::mem::size_of::<Result<TreeNode, StoreError>>(),
        std::mem::size_of::<BoundedReadRequest<'_, '_>>()
    );
    eprintln!(
        "actual_account={} predecessor_account={} actual_work={} predecessor_work={}",
        std::mem::size_of::<crate::ram::store_boundary::WorkAccount<'_>>(),
        std::mem::size_of::<PreviousAccount<'_>>(),
        std::mem::size_of::<Work<'_>>(),
        std::mem::size_of::<PreviousWork<'_>>()
    );
}

#[test]
fn pending_validation_and_complete_provider_failure_keep_original_retry_custody() {
    let directory = tempfile::tempdir().unwrap();
    let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
    let namespace = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &namespace,
            &mut || Ok(()),
        )
        .unwrap();
    let original = namespace.child().unwrap();
    let mut callback = || panic!("a failed operation cannot invoke another callback");
    let mut work = Work::new(store.limits, &original, &mut callback).unwrap();
    let first = work.account.fail_validation_with_provider(
        RamStoreError::Invalid("pending pure validation"),
        StoreError::Unavailable,
    );
    let StoreError::RamReadValidation { source: alias } = first else {
        panic!("pure validation must keep its explicit category");
    };
    assert!(matches!(
        alias.first_validation(),
        RamStoreError::Invalid("pending pure validation")
    ));
    assert!(matches!(
        alias.storage_failure(),
        RamStoreError::Store(StoreError::Unavailable)
    ));
    let joined = work.account.reconcile_failed_read(StoreError::Quota);
    let StoreError::RamReadContinuation { source } = &joined else {
        panic!("the outer complete provider cause must remain owned");
    };
    assert!(source.first_boundary().is_none());
    assert!(matches!(
        source.first_failure(),
        RamStoreError::Invalid("pending pure validation")
    ));
    assert!(matches!(source.returned_failure(), StoreError::Quota));

    let provider = Provider {
        inner: store.backend.clone(),
        reply: Reply::Same,
        calls: AtomicUsize::new(0),
    };
    let counters = (work.visits, work.io_bytes);
    let credits = quota.0.usage().unwrap();
    let retry = crate::ram::bounded_read::read_tree(&provider, root.regions[0], &mut work)
        .err()
        .unwrap();
    let RamStoreError::Store(StoreError::RamReadValidation { source: retry }) = retry else {
        panic!("retry must keep the same validation category and carrier");
    };
    assert_eq!(alias, retry);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!((work.visits, work.io_bytes), counters);
    assert_eq!(quota.0.usage().unwrap(), credits);
    drop(retry);
    drop(joined);
    drop(alias);
    drop(work);
    drop(original);
    namespace.verify_live().unwrap();
}

#[test]
fn every_actual_callback_failure_keeps_category_and_original_sticky_custody() {
    let directory = tempfile::tempdir().unwrap();
    let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let mut total = 0;
    let mut healthy_boundary = || {
        total += 1;
        Ok(())
    };
    let mut healthy = Work::new(store.limits, &original, &mut healthy_boundary).unwrap();
    store.read_tree(root.regions[0], &mut healthy).unwrap();
    drop(healthy);
    let mut retained_boundaries = 0;

    for cut in 1..=total {
        let operation = original.child().unwrap();
        let provider = Provider {
            inner: store.backend.clone(),
            reply: Reply::Distinct,
            calls: AtomicUsize::new(0),
        };
        let mut polls = 0;
        let mut boundary = || {
            polls += 1;
            if polls == cut {
                Err(RamStoreError::Canceled)
            } else {
                Ok(())
            }
        };
        let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
        let error = crate::ram::bounded_read::read_tree(&provider, root.regions[0], &mut work)
            .err()
            .unwrap();
        let RamStoreError::Store(StoreError::RamReadContinuation { source }) = &error else {
            panic!("actual first failure and distinct provider cleanup must remain jointly owned");
        };
        assert!(matches!(source.first_failure(), RamStoreError::Canceled));
        assert!(matches!(source.returned_failure(), StoreError::Quota));
        retained_boundaries += usize::from(source.first_boundary().is_some());
        let first = work.account.read_failure().unwrap();
        let used = quota.0.usage().unwrap();
        let counts = (work.visits, work.io_bytes);
        let retry = crate::ram::bounded_read::read_tree(&provider, root.regions[0], &mut work)
            .err()
            .unwrap();
        let RamStoreError::Store(retry) = retry else {
            panic!("retry retains the same typed first bridge");
        };
        match (&first, &retry) {
            (
                StoreError::RamValidation { source: first },
                StoreError::RamValidation { source: retry },
            ) => assert_eq!(first, retry),
            (
                StoreError::RamReadBoundary { source: first },
                StoreError::RamReadBoundary { source: retry },
            ) => assert_eq!(first, retry),
            _ => panic!("a retry cannot change the original first cause category"),
        }
        assert_eq!(
            quota.0.usage().unwrap(),
            used,
            "retry cannot request another loan"
        );
        assert_eq!((work.visits, work.io_bytes), counts);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        drop(work);
        assert_eq!(polls, cut, "no actual callback follows the first refusal");
        drop((first, retry, error, operation));
        original.verify_live().unwrap();
    }
    assert!(
        retained_boundaries > 0,
        "real SQL scope wrappers retain adapter-evidenced boundaries"
    );
    eprintln!(
        "actual_callback_positions={total} retained_boundary_positions={retained_boundaries}"
    );
}

#[test]
fn entry_and_after_success_original_refusals_remain_sticky_before_retry_effects() {
    use crate::owned_decode::{DecodeAdmissionError, DecodeBudget};

    struct RevokingProvider<'a> {
        inner: &'a dyn ImmutableBlobBackend,
        original: &'a DecodeBudget,
        failure: DecodeAdmissionError,
        calls: AtomicUsize,
    }

    impl ImmutableBlobBackend for RevokingProvider<'_> {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn capabilities(&self) -> BackendCapabilities {
            self.inner.capabilities()
        }
        fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
            self.inner.contains(id)
        }
        fn read(&self, _: ContentId, _: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
            panic!("revocation cannot select a raw read")
        }
        fn put_if_absent(&self, _: ContentId, _: &BlobHandle) -> Result<PutReceipt, StoreError> {
            panic!("revocation cannot publish")
        }
        fn read_bounded_with_boundary(
            &self,
            request: &mut BoundedReadRequest<'_, '_>,
        ) -> Result<(), StoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.read_bounded_with_boundary(request)?;
            self.original.record_failure(self.failure.clone());
            Ok(())
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
    let namespace = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &namespace,
            &mut || Ok(()),
        )
        .unwrap();

    for after_success in [false, true] {
        let operation = namespace.child().unwrap();
        let failure = DecodeAdmissionError::new(StoreError::Unauthorized);
        let provider = RevokingProvider {
            inner: store.backend.as_ref(),
            original: &operation,
            failure: failure.clone(),
            calls: AtomicUsize::new(0),
        };
        let mut polls = 0;
        let mut boundary = || {
            polls += 1;
            Ok(())
        };
        let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
        if !after_success {
            operation.record_failure(failure.clone());
        }
        let error = crate::ram::bounded_read::read_tree(&provider, root.regions[0], &mut work)
            .err()
            .unwrap();
        let RamStoreError::Store(StoreError::RamValidation { source: first }) = &error else {
            panic!("an observed original refusal retains its prepaid first carrier");
        };
        let RamStoreError::Store(stored) = first.storage_failure() else {
            panic!("original admission stays typed");
        };
        let StoreError::DecodeAdmission { source, .. } = stored else {
            panic!("no supervision category substitution");
        };
        assert_eq!(source, &failure);
        let before = (work.visits, work.io_bytes, quota.0.usage().unwrap());
        let retry = crate::ram::bounded_read::read_tree(&provider, root.regions[0], &mut work)
            .err()
            .unwrap();
        let RamStoreError::Store(StoreError::RamValidation { source: retry }) = retry else {
            panic!("the same failed Work keeps the exact first carrier");
        };
        assert_eq!(first, &retry);
        assert_eq!(
            (work.visits, work.io_bytes, quota.0.usage().unwrap()),
            before
        );
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            usize::from(after_success)
        );
        drop(work);
        if !after_success {
            assert_eq!(polls, 0);
        }
        drop((error, retry, provider));
        drop(operation);
        namespace.verify_live().unwrap();
    }
}
