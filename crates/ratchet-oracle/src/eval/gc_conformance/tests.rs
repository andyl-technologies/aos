use super::*;

#[test]
fn gc_conformance_manifest_covers_tier_a_tier_b_raw_bytes() {
    let manifest = validate_gc_conformance_manifest().expect("conformance manifest validates");

    assert_eq!(manifest.target_count(), 2);
    let raw_target = manifest
        .target_for(GcConformanceScope::TierATierBRawBytes)
        .expect("Tier-A/Tier-B target is present");
    assert_eq!(raw_target.package(), CONFORMANCE_PACKAGE);
    assert_eq!(raw_target.manifest_path(), CONFORMANCE_MANIFEST_PATH);
    assert_eq!(
        raw_target.test_filter(),
        "gc_conformance_tier_a_tier_b_raw_bytes_smoke"
    );
    assert!(!raw_target.rationale().is_empty());
    let drv_target = manifest
        .target_for(GcConformanceScope::TierATierBDerivationAtermBytes)
        .expect("Tier-A/Tier-B derivation target is present");
    assert_eq!(drv_target.package(), CONFORMANCE_PACKAGE);
    assert_eq!(drv_target.manifest_path(), CONFORMANCE_MANIFEST_PATH);
    assert_eq!(
        drv_target.test_filter(),
        "gc_conformance_tier_a_tier_b_drv_bytes_smoke"
    );
    assert!(!drv_target.rationale().is_empty());
}

#[test]
fn gc_conformance_invocations_pin_cargo_test_filters() {
    let invocations = gc_conformance_invocations().expect("conformance invocations validate");

    assert_eq!(invocations.len(), 2);
    let raw_invocation = invocations
        .iter()
        .find(|invocation| invocation.target().scope() == GcConformanceScope::TierATierBRawBytes)
        .expect("Tier-A/Tier-B invocation is present");
    assert_eq!(raw_invocation.cargo_program(), "cargo");
    assert_eq!(
        raw_invocation.cargo_args(),
        &[
            "test",
            "--manifest-path",
            CONFORMANCE_MANIFEST_PATH,
            "-p",
            CONFORMANCE_PACKAGE,
            "gc_conformance_tier_a_tier_b_raw_bytes_smoke",
            "--",
            "--nocapture",
        ]
    );

    let drv_invocation = invocations
        .iter()
        .find(|invocation| {
            invocation.target().scope() == GcConformanceScope::TierATierBDerivationAtermBytes
        })
        .expect("Tier-A/Tier-B derivation invocation is present");
    assert_eq!(drv_invocation.cargo_program(), "cargo");
    assert_eq!(
        drv_invocation.cargo_args(),
        &[
            "test",
            "--manifest-path",
            CONFORMANCE_MANIFEST_PATH,
            "-p",
            CONFORMANCE_PACKAGE,
            "gc_conformance_tier_a_tier_b_drv_bytes_smoke",
            "--",
            "--nocapture",
        ]
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_conformance_tier_a_tier_b_raw_bytes_smoke() {
    let report = run_gc_conformance_tier_a_tier_b_raw_bytes_smoke()
        .expect("Tier-A/Tier-B raw byte conformance smoke passes");

    assert_eq!(report.scope(), GcConformanceScope::TierATierBRawBytes);
    assert_eq!(report.case_count(), TIER_A_TIER_B_RAW_CASES.len());
    assert_eq!(
        report.checked_surface_count(),
        TIER_A_TIER_B_RAW_CASES.len() as u64
    );
    assert_eq!(
        report.tier_b_admissions(),
        TIER_A_TIER_B_RAW_CASES.len() as u64
    );
    assert!(report.tier_b_generation_rewrites() > 0);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_conformance_tier_a_tier_b_drv_bytes_smoke() {
    let report = run_gc_conformance_tier_a_tier_b_drv_bytes_smoke()
        .expect("Tier-A/Tier-B derivation byte conformance smoke passes");

    assert_eq!(
        report.scope(),
        GcConformanceScope::TierATierBDerivationAtermBytes
    );
    assert_eq!(report.case_count(), TIER_A_TIER_B_DRV_CASES.len());
    assert!(report.checked_surface_count() >= TIER_A_TIER_B_DRV_CASES.len() as u64);
    assert_eq!(
        report.tier_b_admissions(),
        TIER_A_TIER_B_DRV_CASES.len() as u64
    );
    assert!(report.tier_b_generation_rewrites() > 0);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_conformance_source_case_compares_tier_a_and_tier_b_bytes() {
    let report = compare_gc_conformance_tier_a_tier_b_raw_bytes_source("[ ({ a = 1 + 2; }) ]")
        .expect("source-level conformance case passes");

    assert_eq!(report.raw_bytes(), b"[ { a = 3; } ]");
    assert!(report.tier_b_worker_records() > 0);
    assert!(report.tier_b_generation_rewrites() > 0);
}
