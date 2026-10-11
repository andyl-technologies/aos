//! Checks original-body credit before canonical allocation or signed-object reads.

// These data-only fixtures panic when a finite preflight invariant changes.
// crucible-lint: allow panic-shortcut -- These data-only tests deliberately panic on invalid fixtures or failed finite lineage invariants.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn aggregate_reference_credit_refuses_before_a_second_original_body() {
    let mut credit = BodyCredit::new(1024).unwrap();
    let mut reference = canonical::content_ref(b"{}", "application/json").unwrap();
    reference.length =
        (crucible::node_scheduling::MAXIMUM_SCHEDULING_EPOCH_BYTES as u64 - 1024).into();
    credit.reference(&reference).unwrap();
    assert_eq!(credit.remaining, 0);

    let another =
        canonical::content_ref(b"{}", "application/vnd.crucible.original-runtime+json").unwrap();
    assert!(credit.reference(&another).is_err());
}

#[test]
fn borrowed_serialization_preflight_shares_the_original_body_budget() {
    let mut credit =
        BodyCredit::new(crucible::node_scheduling::MAXIMUM_SCHEDULING_EPOCH_BYTES - 4).unwrap();
    serde_json::to_writer(&mut credit, &vec![0]).unwrap();
    assert_eq!(credit.remaining, 1);
    assert!(serde_json::to_writer(&mut credit, &vec![0]).is_err());

    let mut credit =
        BodyCredit::new(crucible::node_scheduling::MAXIMUM_SCHEDULING_EPOCH_BYTES - 3).unwrap();
    serde_json::to_writer(&mut credit, &vec![0]).unwrap();
    assert_eq!(credit.remaining, 0);
}

#[test]
fn selected_epoch_profile_regenerates_its_own_installed_world_without_native_allocation() {
    use crate::node_observed_executor::factory::{InstalledGem5ClosedProfile, measure_executable};

    let installed = InstalledGem5ClosedProfile::built_in().unwrap();
    let host = measure_executable(&std::env::current_exe().unwrap()).unwrap();
    let selected =
        MixedProfile::build_public_epoch_preserving(installed.clone(), &host, "x86_64").unwrap();
    let regenerated = selected.regenerate(&host).unwrap();
    assert!(regenerated.scheduling_epochs);
    assert_eq!(
        selected.scenario.canonical_bytes().unwrap(),
        regenerated.scenario.canonical_bytes().unwrap()
    );
    assert_eq!(selected.qualification, regenerated.qualification);

    let legacy = MixedProfile::build_public_preserving(installed.clone(), &host, "x86_64").unwrap();
    assert!(!legacy.scheduling_epochs);
    assert_ne!(selected.scenario.world, legacy.scenario.world);
    assert_eq!(
        legacy.scenario.canonical_bytes().unwrap(),
        legacy
            .regenerate(&host)
            .unwrap()
            .scenario
            .canonical_bytes()
            .unwrap()
    );
    assert!(MixedProfile::build_public_epoch_preserving(installed, &host, "aarch64").is_err());
}
