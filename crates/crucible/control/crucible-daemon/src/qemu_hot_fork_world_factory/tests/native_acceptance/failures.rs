//! Atomic failure selectors backed by genuine accepted native ownership.

use super::*;
use crate::packaged_qemu_executor::{NativeAtomicFailureCase, run_atomic_failure_native};

fn run_case(case: NativeAtomicFailureCase) {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) =
        scenario::build_equivalence(&fixture, artifacts, &paths.kernel, &paths.root_image)
            .expect("reviewed native traffic and host-I/O scenario");
    let lifecycle = lifecycle_config(&paths, paths.run_state_root.join("atomic"), artifacts);
    run_atomic_failure_native(source, lifecycle, case);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_factory_exposes_no_world_when_second_real_fork_fails() {
    run_case(NativeAtomicFailureCase::Fork);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_source_preparation_failure_exposes_no_template() {
    run_case(NativeAtomicFailureCase::Preparation);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_factory_exposes_no_world_when_second_real_adoption_fails() {
    run_case(NativeAtomicFailureCase::Adoption);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_factory_keeps_source_private_until_target_cleanup_retries() {
    run_case(NativeAtomicFailureCase::Cleanup);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_factory_keeps_source_private_across_repository_publication_retry() {
    run_case(NativeAtomicFailureCase::Publication);
}
