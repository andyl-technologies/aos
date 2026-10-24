//! Actual closed-record buffer refusals within their existing paid partition.
//!
//! These finite component controls inject one real fallible allocation refusal.
//! They grant no physical OOM, native resource custody or successful publication.

use super::*;
use crate::ram::codec::TREE_SCHEMA;
use crucible_host_resources::test_support::TestAllocationObserver;
use std::alloc::Layout;
use std::collections::TryReserveError;

#[derive(Clone, Copy)]
enum RecordAllocation {
    PageBody,
    PageSchema,
    TreeBody,
    TreeSchema,
    TreeRole,
}

fn actual_source<'a>(mut error: &'a (dyn Error + 'static)) -> &'a TryReserveError {
    loop {
        if let Some(source) = error.downcast_ref::<TryReserveError>() {
            return source;
        }
        error = error
            .source()
            .expect("the actual allocator source is retained");
    }
}

fn refusal_at(allocation: RecordAllocation) {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let baseline = quota.used();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let (page, digest) = store
        .put_page(&[9; 4096], &OriginalRetention, &mut work)
        .unwrap();
    assert!(store.backend.contains(page).unwrap());
    let retention = Retention::default();
    let bytes = match allocation {
        RecordAllocation::PageBody => 36 + 4096,
        RecordAllocation::PageSchema => PAGE_SCHEMA.len(),
        RecordAllocation::TreeBody => 133,
        RecordAllocation::TreeSchema => TREE_SCHEMA.len(),
        RecordAllocation::TreeRole => "page".len(),
    };
    let layout = Layout::array::<u8>(bytes).unwrap();
    let (expected, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        Vec::<u8>::new().try_reserve_exact(bytes).unwrap_err()
    })
    .unwrap();
    assert!(reached);

    let (error, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
        match allocation {
            RecordAllocation::PageBody | RecordAllocation::PageSchema => store
                .put_page(&[7; 4096], &retention, &mut work)
                .map(|_| ()),
            RecordAllocation::TreeBody | RecordAllocation::TreeSchema => store
                .put_tree(&TreeNode::Padding, 0, 0, &retention, &mut work)
                .map(|_| ()),
            RecordAllocation::TreeRole => store
                .put_tree(
                    &TreeNode::Leaf { page, digest },
                    0,
                    1,
                    &retention,
                    &mut work,
                )
                .map(|_| ()),
        }
        .unwrap_err()
    })
    .unwrap();

    assert!(reached);
    assert_eq!(actual_source(&error), &expected);
    assert!(retention.objects.lock().unwrap().is_empty());
    // Closed record partitions deliberately localize a refused codec. The
    // existing outer original remains healthy; the retained error owns the
    // failed partition's actual cause and its existing loan independently.
    original.check().unwrap();
    drop(work);
    drop(original);

    assert!(quota.used() > baseline);
    drop(error);
    assert_eq!(quota.used(), baseline);
}

#[test]
fn paid_page_body_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RecordAllocation::PageBody);
}

#[test]
fn paid_page_schema_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RecordAllocation::PageSchema);
}

#[test]
fn paid_tree_body_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RecordAllocation::TreeBody);
}

#[test]
fn paid_tree_schema_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RecordAllocation::TreeSchema);
}

#[test]
fn paid_tree_child_role_allocator_refusal_preserves_actual_partition_cause() {
    refusal_at(RecordAllocation::TreeRole);
}
