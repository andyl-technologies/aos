//! Implements `gate:adversarial-determinism`.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;

use crucible_harness::adversarial::{
    AdversarialComparisonError, AdversarialGateError, AdversarialMismatchKind, AdversarialRun,
    HostileProfile, canonical_host_adversary_matrix, compare_adversarial_runs,
    representative_adversarial_corpus, run_adversarial_determinism_gate,
    run_adversarial_determinism_gate_with_observer,
};

#[test]
fn gate_adversarial_determinism_compares_canonical_bytes_under_hostile_profiles()
-> Result<(), Box<dyn Error>> {
    let corpus = representative_adversarial_corpus();
    let profiles = canonical_host_adversary_matrix();
    let report = run_adversarial_determinism_gate(&corpus, profiles)?;

    assert_eq!(report.scenario_count, corpus.len());
    assert_eq!(report.profile_count, profiles.len());
    assert_eq!(report.runs.len(), profiles.len());
    assert!(report.runs.len() >= 4);

    let profile_names = report
        .runs
        .iter()
        .map(|run| run.profile.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        profile_names,
        BTreeSet::from([
            "quiet-single-core",
            "loaded-single-core",
            "reordered-two-core",
            "loaded-many-core",
        ])
    );

    let baseline = &report.runs[0];
    assert!(!baseline.canonical_log.is_empty());
    assert_eq!(baseline.final_fingerprint.len(), 32);
    for run in &report.runs[1..] {
        assert_eq!(run.canonical_log, baseline.canonical_log);
        assert_eq!(run.final_fingerprint, baseline.final_fingerprint);
    }

    Ok(())
}

#[test]
fn gate_adversarial_determinism_rejects_profile_dependent_logs() {
    let error = compare_adversarial_runs(&[
        adversarial_run("quiet-single-core", b"canonical-log", b"fingerprint"),
        adversarial_run("loaded-many-core", b"profile-leaked-log", b"fingerprint"),
    ])
    .err();

    assert!(matches!(
        error,
        Some(AdversarialComparisonError::Mismatch(mismatch))
            if mismatch.baseline_profile == "quiet-single-core"
                && mismatch.divergent_profile == "loaded-many-core"
    ));
}

#[test]
fn gate_adversarial_determinism_rejects_profile_dependent_observer_output() {
    let corpus = representative_adversarial_corpus();
    let profiles = canonical_host_adversary_matrix();
    let error = run_adversarial_determinism_gate_with_observer(&corpus, profiles, |observation| {
        format!(
            "{}:{}:{}",
            observation.operation_index, observation.profile.name, observation.task.worker_index
        )
    })
    .err();

    assert!(matches!(
        error,
        Some(AdversarialGateError::Comparison(AdversarialComparisonError::Mismatch(mismatch)))
            if mismatch.baseline_profile == "quiet-single-core"
                && mismatch.divergent_profile == "loaded-single-core"
                && mismatch.kind == AdversarialMismatchKind::CanonicalLog
    ));
}

#[test]
fn gate_adversarial_determinism_rejects_profile_dependent_fingerprints() {
    let error = compare_adversarial_runs(&[
        adversarial_run("quiet-single-core", b"canonical-log", b"fingerprint"),
        adversarial_run(
            "loaded-many-core",
            b"canonical-log",
            b"profile-leaked-fingerprint",
        ),
    ])
    .err();

    assert!(matches!(
        error,
        Some(AdversarialComparisonError::Mismatch(mismatch))
            if mismatch.baseline_profile == "quiet-single-core"
                && mismatch.divergent_profile == "loaded-many-core"
                && mismatch.kind == AdversarialMismatchKind::FinalFingerprint
    ));
}

#[test]
fn gate_adversarial_determinism_rejects_empty_inputs() {
    let corpus = representative_adversarial_corpus();
    let profiles = canonical_host_adversary_matrix();

    assert!(matches!(
        run_adversarial_determinism_gate(&[], profiles),
        Err(AdversarialGateError::EmptyScenarioCorpus)
    ));
    assert!(matches!(
        run_adversarial_determinism_gate(&corpus, &[]),
        Err(AdversarialGateError::EmptyProfileMatrix)
    ));
}

fn adversarial_run(
    profile: &str,
    canonical_log: &[u8],
    final_fingerprint: &[u8],
) -> AdversarialRun {
    AdversarialRun {
        profile: HostileProfile {
            name: profile.to_string(),
        },
        canonical_log: canonical_log.to_vec(),
        final_fingerprint: final_fingerprint.to_vec(),
    }
}
