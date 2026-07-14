//! Force-cache payload rehydration tests for lists, attrsets, paths, and strings.

// Some tests here are gated off under the Candidate-C variant (non-reservation
// heap geometry / fake pointers), leaving shared helpers unused on that carrier
// only; the baseline still uses them.
#![cfg_attr(feature = "candidate_c_value", allow(dead_code))]

use super::*;
use crate::heap::HeapGeneration;
use crate::runtime::alloc::{AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint};

mod context_paths;
mod part_1;
mod part_2;
mod part_3;

fn replay_allocation_subject(id: IrId, salt: &[u8]) -> ForceCacheSubject {
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(salt)),
        id,
    );
    ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: Some(EvalNodeRef::new(EvalModuleId::ROOT, id)),
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    }
}

fn assert_replay_permanent_allocation_shape(
    evaluator: &TreeWalk,
    permanent_safepoints_before: u64,
    permanent_dispatches_before: usize,
    expected_safepoints: u64,
    expected_dispatches: &[RuntimeAllocationEntryPoint],
    label: &str,
) {
    assert_eq!(
        evaluator.heap().permanent_allocation_safepoints().count(),
        permanent_safepoints_before + expected_safepoints,
        "{label} recorded an unexpected permanent safepoint count"
    );
    assert_eq!(
        &evaluator.gc_stress_permanent_root_allocation_dispatches()[permanent_dispatches_before..],
        expected_dispatches,
        "{label} recorded an unexpected permanent dispatch suffix"
    );
}
