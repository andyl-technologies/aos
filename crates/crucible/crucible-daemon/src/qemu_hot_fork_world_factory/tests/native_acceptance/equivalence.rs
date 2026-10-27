//! Native equivalence selectors backed by the admitted packaged actor.
//!
//! The behavioral driver lives with preparation ownership. These selectors
//! retain the reviewed traffic fixtures and explicit memory/performance cases.

use super::*;

#[path = "equivalence/siblings.rs"]
mod siblings;
use crate::packaged_qemu_executor::{NativeEquivalenceCase, run_equivalence_native};

fn run_case(case: NativeEquivalenceCase, single: bool, memory: u32, scaling: bool) {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) = if scaling {
        scenario::build_single_node_scaling(&fixture, artifacts, &paths.kernel, &paths.root_image)
    } else if single
        && matches!(
            case,
            NativeEquivalenceCase::Origins | NativeEquivalenceCase::Stress
        )
    {
        scenario::build_single_node_equivalence(
            &fixture,
            artifacts,
            &paths.kernel,
            &paths.root_image,
        )
    } else if single {
        scenario::build_single_node_equivalence_with_memory(
            &fixture,
            artifacts,
            memory,
            &paths.kernel,
            &paths.root_image,
        )
    } else {
        scenario::build_equivalence(&fixture, artifacts, &paths.kernel, &paths.root_image)
    }
    .expect("reviewed native equivalence scenario");
    let config = lifecycle_config(&paths, paths.run_state_root.join("equivalence"), artifacts);
    run_equivalence_native(source, config, case);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_hot_fork_matches_thin_and_exact_from_execution_and_exact_templates() {
    run_case(NativeEquivalenceCase::Origins, false, 64, false);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_single_node_hot_fork_matches_thin_and_exact() {
    run_case(NativeEquivalenceCase::Origins, true, 64, false);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_single_vm_child_ready_p95_is_below_100_milliseconds() {
    run_case(NativeEquivalenceCase::ReadyLatency, true, 64, false);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_hot_fork_scales_across_three_semantic_template_depths() {
    run_case(NativeEquivalenceCase::Depth, true, 64, true);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_hot_fork_scales_across_three_guest_memory_sizes() {
    for memory in [64, 256, 512] {
        run_case(NativeEquivalenceCase::Memory(memory), true, memory, false);
    }
    println!("guest_memory_profiles_mib=64,256,512");
    println!("sequential_sibling_counts=1,2,4");
    println!("ram_first_quantum_cold_reference_profiles_mib=64,256,512");
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_whole_world_survives_ten_thousand_lifecycles_without_leaks() {
    run_case(NativeEquivalenceCase::Stress, true, 64, false);
}

#[test]
#[ignore = "requires the operator-managed AOS paging environment and native traffic assets"]
fn production_hot_fork_meets_whole_world_performance_ratchets() {
    run_case(NativeEquivalenceCase::Performance, false, 64, false);
}
