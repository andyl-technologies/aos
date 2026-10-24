//! Checks time dominance without manufacturing native collection permission.

use super::*;
use terrane_format::gc::{GcRoot, ParentCutoff};
use terrane_format::refs::RefName;

fn snapshot(cutoff: ParentCutoff, reason: RootReason, timestamp: u64) -> GcRoots {
    GcRoots {
        cycle: 1,
        epoch: 2,
        timestamp,
        roots: vec![GcRoot {
            reference: RefName::parse("refs/heads/_/main")
                .unwrap_or_else(|error| panic!("canonical native fixture ref: {error}")),
            commit: [1; 32],
            parent_cutoff: cutoff,
            reason,
        }],
    }
}

#[test]
fn gc_current_time_advance_keeps_conservative_cutoffs_and_witness_dominance() {
    let earlier = snapshot(ParentCutoff::Since(10), RootReason::Current, 100);
    let later = snapshot(ParentCutoff::Since(20), RootReason::Current, 110);
    assert!(covered_at_later_time(&earlier, &later));
    assert!(!covered_at_later_time(&later, &earlier));

    let full = snapshot(ParentCutoff::Unbounded, RootReason::Lease, 100);
    let expired = snapshot(ParentCutoff::Unbounded, RootReason::RetentionWitness, 110);
    assert!(covered_at_later_time(&full, &expired));
    let mut revived = full.clone();
    revived.timestamp = 120;
    assert!(!covered_at_later_time(&expired, &revived));

    let mut different = later;
    different.roots[0].commit = [2; 32];
    assert!(!covered_at_later_time(&earlier, &different));
    different.roots[0].commit = [1; 32];
    different.roots[0].parent_cutoff = ParentCutoff::Unbounded;
    assert!(!covered_at_later_time(&earlier, &different));
}
