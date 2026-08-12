//! Focused tests for dynamic force-shape and suspended-work accounting.

use super::*;

/// A child force's inclusive time is subtracted from its parent's self-time.
#[test]
fn exclusive_self_time_subtracts_nested_children() {
    let parent_saved = open_force(None);
    let child_saved = open_force(None);
    close_force("child", 30, child_saved, ForceOutcomeClass::Whnf);
    close_force("parent", 100, parent_saved, ForceOutcomeClass::Whnf);

    let guard = CENSUS.lock().expect("census lock");
    let shapes = &guard.as_ref().expect("recorded census").shapes;
    assert_eq!(shapes["parent"].self_nanos, 70);
    assert_eq!(shapes["parent"].inclusive_nanos, 100);
    assert_eq!(shapes["child"].self_nanos, 30);
    assert_eq!(shapes["child"].inclusive_nanos, 30);
}

/// Self-time bucket indexing is the power-of-two floor: `[2^b, 2^(b+1))`.
#[test]
fn self_ns_bucket_is_power_of_two_floor() {
    assert_eq!(self_ns_bucket(0), 0);
    assert_eq!(self_ns_bucket(1), 0);
    assert_eq!(self_ns_bucket(127), 6);
    assert_eq!(self_ns_bucket(128), 7);
    assert_eq!(self_ns_bucket(255), 7);
    assert_eq!(self_ns_bucket(256), 8);
    assert_eq!(self_ns_bucket(u64::MAX), SELF_NS_BUCKETS - 1);
}

/// The complete modal signature requires one nested Apply and a WHNF result.
#[test]
fn modal_apply_spine_requires_one_apply_child() {
    let descriptor = ApplySpineDescriptor {
        origin: "map",
        callee: "lambda",
        pattern: "simple-formal",
        body: "local-argument",
        argument: "apply-thunk",
    };
    let outer = open_force(Some(descriptor));
    let child = open_force(Some(ApplySpineDescriptor {
        origin: "genList",
        ..descriptor
    }));
    close_force("apply", 20, child, ForceOutcomeClass::Whnf);
    close_force("apply", 50, outer, ForceOutcomeClass::Whnf);

    let guard = CENSUS.lock().expect("census lock");
    let census = guard.as_ref().expect("recorded census");
    assert!(
        census
            .apply_spines
            .keys()
            .any(|key| key.descriptor == descriptor && key.children == "one-apply")
    );
    assert!(census.apply_spine_stages["modal_complete"].forces >= 1);
}

/// A producer-site collision is explicit rather than misattributed.
#[test]
fn synthetic_apply_site_collision_becomes_ambiguous() {
    record_synthetic_apply_site("map", 991, 992, 993, 994, 1);
    record_synthetic_apply_site("genList", 991, 992, 993, 994, 1);
    assert_eq!(synthetic_apply_origin(991, 992, 993, 994), "ambiguous");
}

/// Later modal stages are not counted after an earlier prefix mismatch.
#[test]
fn modal_apply_stages_stop_at_first_mismatch() {
    let mut guard = CENSUS.lock().expect("census lock");
    let census = guard.get_or_insert_with(Census::new);
    let apply_before = census
        .apply_spine_stages
        .get("apply")
        .map_or(0, |aggregate| aggregate.forces);
    let argument_before = census
        .apply_spine_stages
        .get("argument_apply")
        .map_or(0, |aggregate| aggregate.forces);
    record_spine_stages(
        census,
        ApplySpineKey {
            descriptor: ApplySpineDescriptor {
                origin: "other",
                callee: "primop",
                pattern: "simple-formal",
                body: "local-argument",
                argument: "apply-thunk",
            },
            children: "one-apply",
            outcome: ForceOutcomeClass::Whnf,
        },
        1,
        1,
    );
    assert_eq!(census.apply_spine_stages["apply"].forces, apply_before + 1);
    assert_eq!(
        census
            .apply_spine_stages
            .get("argument_apply")
            .map_or(0, |aggregate| aggregate.forces),
        argument_before
    );
}

/// Per-shape work counts expose current, peak, and global-peak composition.
#[test]
fn suspended_work_accounting_tracks_shape_lifetime() {
    const SHAPE: &str = "work-lifetime-test";
    record_allocation(SHAPE, false, None);
    record_allocation(SHAPE, false, None);
    record_work_release(SHAPE);

    let guard = CENSUS.lock().expect("census lock");
    let aggregate = &guard.as_ref().expect("recorded census").shapes[SHAPE];
    assert_eq!(aggregate.allocations, 2);
    assert_eq!(aggregate.work_releases, 1);
    assert_eq!(aggregate.live_work, 1);
    assert_eq!(aggregate.peak_live_work, 2);
    assert!(aggregate.live_work_at_global_peak <= 2);
}
