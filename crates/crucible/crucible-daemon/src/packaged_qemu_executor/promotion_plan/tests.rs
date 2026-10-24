//! Checks pure path geometry and refusal before deferred promotion construction.

use super::*;
use std::cell::Cell;

#[test]
fn refused_admission_drops_the_unbuilt_plan_without_invoking_its_builder() {
    let built = Cell::new(0usize);
    let builder = || {
        built.set(built.get() + 1);
    };
    let plan = UnbuiltPromotions::<u64, (), _>::new(2, 4096, builder);
    let queried = plan
        .control_bytes(Path::new("/actual/component-root"))
        .expect("pure query");
    let calls = Cell::new(0usize);
    let result = plan.admit(Path::new("/actual/component-root"), |bytes, count| {
        calls.set(calls.get() + 1);
        assert_eq!(count, 2);
        assert_eq!(bytes, queried);
        Err::<(), _>(
            crate::executor_pool::LocalExecutorPoolConfigError::WorkerControlGeometry.into(),
        )
    });
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(built.get(), 0);
}

#[test]
fn exact_owned_path_capacities_match_the_query_for_suffix_boundaries() {
    for base in ["", "/", "/actual/component-root", "/actual/component-root/"] {
        let base = Path::new(base);
        let root = worker_root(base).expect("owned root");
        assert_eq!(
            root.capacity(),
            path_bytes(base, ROOT_NAME.len()).expect("root query")
        );
        for slot in [0, 9, 99, 100, 255, 999, 1000, usize::MAX] {
            let path = worker_path(&root, slot).expect("owned worker path");
            assert_eq!(path, root.join(format!("worker-{slot:03}")));
            assert_eq!(
                path.capacity(),
                path_bytes(&root, worker_name_bytes(slot).expect("name query"))
                    .expect("path query")
            );
        }
    }
}

#[test]
fn excessive_count_refuses_before_any_reservation_or_builder() {
    let called = Cell::new(false);
    let plan = UnbuiltPromotions::<u64, (), _>::new(usize::MAX, 0, || ());
    assert!(
        plan.admit(Path::new("/component"), |_, _| {
            called.set(true);
            Ok(())
        })
        .is_err()
    );
    assert!(!called.get());
}
