//! Exercises the actual private interval with original measured source files.
//!
//! These pre-Child fixtures select the existing DATA checks for comparison and
//! refusal controls only. They issue no Core construction member, live callback
//! permission, native process, SDK admission or completed runtime qualification.

use super::*;
use crucible_engine::node_admission::OriginalRuntimeConstructionPhase;
use std::path::PathBuf;

type Fixture = (
    crate::node_qualification::packet_collection::complete::tests::Scene,
    Rc<RefCell<PacketCompleteReportStartupHolder>>,
    Rc<InstalledPacketCompleteCollectionAuthority>,
);

fn fixture() -> Fixture {
    let (scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    let authority = Rc::clone(&original.borrow().authority);
    (scene, original, authority)
}

fn select_data_checks(
    original: &Rc<RefCell<PacketCompleteReportStartupHolder>>,
    authority: &InstalledPacketCompleteCollectionAuthority,
) {
    original
        .borrow()
        .runtime_in_flight
        .set(Some(OriginalRuntimeConstructionPhase::InactiveRuntime));
    authority.original_initial_callback_active.set(true);
}

fn disposable_source(authority: &InstalledPacketCompleteCollectionAuthority) -> (PathBuf, Vec<u8>) {
    let artifact = &authority.graph_policy.measurements()[0].sources[0];
    let bytes = std::fs::read(&artifact.path).unwrap();
    artifact.content.verify(&bytes).unwrap();
    (artifact.path.clone(), bytes)
}

fn change_same_extent(path: &std::path::Path, original: &[u8]) {
    assert!(!original.is_empty());
    let mut changed = original.to_vec();
    changed[0] ^= 1;
    std::fs::write(path, &changed).unwrap();
    assert_eq!(
        std::fs::metadata(path).unwrap().len(),
        original.len() as u64
    );
    assert_ne!(std::fs::read(path).unwrap(), original);
}

#[test]
fn actual_selected_and_ordinary_plan_checks_preserve_original_bytes_and_refusals() {
    let (_scene, original, authority) = fixture();
    let (path, source_bytes) = disposable_source(&authority);
    let plan_bytes = authority.plan_evidence().plan_bytes.to_vec();
    let refused_bytes = authority.plan_evidence().refused_bytes.to_vec();
    authority
        .authenticate_plan_view(authority.plan_evidence())
        .unwrap();
    let mut foreign_bytes = plan_bytes.clone();
    foreign_bytes.push(b' ');
    let mut foreign = authority.plan_evidence();
    foreign.plan_bytes = &foreign_bytes;
    let ordinary_error = authority.authenticate_plan_view(foreign).unwrap_err();
    assert_eq!(
        ordinary_error.message,
        "qualification refused: complete original packet collecting scope unavailable",
    );

    select_data_checks(&original, &authority);
    authority
        .authenticate_plan_view(authority.plan_evidence())
        .unwrap();
    let mut foreign = authority.plan_evidence();
    foreign.plan_bytes = &foreign_bytes;
    let selected_error = authority.authenticate_plan_view(foreign).unwrap_err();

    assert_eq!(selected_error.message, ordinary_error.message);
    assert_eq!(std::fs::read(&path).unwrap(), source_bytes);
    assert_eq!(authority.plan_evidence().plan_bytes, plan_bytes.as_slice());
    assert_eq!(
        authority.plan_evidence().refused_bytes,
        refused_bytes.as_slice()
    );
    authority
        .graph_policy
        .read_original_initial_callback_data()
        .unwrap();
    assert!(
        original
            .borrow()
            .runtime_members
            .iter()
            .all(|slot| slot.get().is_none())
    );
    assert!(!original.borrow().native_attempted.get());
}

#[test]
fn actual_terminal_source_drift_revokes_after_successful_plan_body() {
    let (_scene, original, authority) = fixture();
    let (path, bytes) = disposable_source(&authority);
    select_data_checks(&original, &authority);
    let interval = OriginalPlanViewInterval::begin(&authority, original.borrow()).unwrap();
    let checked = interval.authenticate_body_data(authority.plan_evidence());
    assert!(checked.is_ok());

    change_same_extent(&path, &bytes);
    let error = interval.finish(checked).unwrap_err();

    assert_eq!(
        error.message,
        "qualification refused: original complete host callback refused"
    );
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(
        authority
            .graph_policy
            .read_original_initial_callback_data()
            .is_err()
    );
    let error = authority
        .authenticate_plan_view(authority.plan_evidence())
        .unwrap_err();
    assert_eq!(
        error.message,
        "qualification refused: original complete host callback refused"
    );
}

#[test]
fn actual_plan_error_survives_terminal_source_drift_and_keeps_sticky_revocation() {
    let (_scene, original, authority) = fixture();
    let (path, bytes) = disposable_source(&authority);
    let mut foreign_bytes = authority.plan_evidence().plan_bytes.to_vec();
    foreign_bytes.push(b' ');
    let mut foreign = authority.plan_evidence();
    foreign.plan_bytes = &foreign_bytes;
    let expected = authority.authenticate_plan_view(foreign).unwrap_err();
    select_data_checks(&original, &authority);
    let interval = OriginalPlanViewInterval::begin(&authority, original.borrow()).unwrap();
    let mut foreign = authority.plan_evidence();
    foreign.plan_bytes = &foreign_bytes;
    let checked = interval.authenticate_body_data(foreign);
    assert_eq!(checked.as_ref().unwrap_err().message, expected.message);

    change_same_extent(&path, &bytes);
    let error = interval.finish(checked).unwrap_err();

    assert_eq!(error.message, expected.message);
    std::fs::write(&path, &bytes).unwrap();
    assert!(
        authority
            .graph_policy
            .read_original_initial_callback_data()
            .is_err()
    );
    let error = authority
        .authenticate_plan_view(authority.plan_evidence())
        .unwrap_err();
    assert_eq!(
        error.message,
        "qualification refused: original complete host callback refused"
    );
}

#[test]
fn actual_entry_drift_matches_existing_callback_refusal_without_reusing_currency() {
    let (_scene, original, authority) = fixture();
    let (path, bytes) = disposable_source(&authority);
    select_data_checks(&original, &authority);
    change_same_extent(&path, &bytes);
    let previous = authority
        .current_for_original_initial_callback()
        .unwrap_err();
    let expected = evidence_error(previous);

    let error = authority
        .authenticate_plan_view(authority.plan_evidence())
        .unwrap_err();

    assert_eq!(error.message, expected.message);
    std::fs::write(&path, &bytes).unwrap();
    assert!(
        authority
            .authenticate_plan_view(authority.plan_evidence())
            .is_err()
    );
}

#[test]
fn actual_second_selector_still_refuses_retired_holder_and_preserves_its_error() {
    let (_scene, original, authority) = fixture();
    select_data_checks(&original, &authority);
    let interval = OriginalPlanViewInterval::begin(&authority, original.borrow()).unwrap();
    // The same actual Cell changes after entry. First-body file/Source checks
    // cannot stand in for the independently repeated holder retirement guard.
    original.borrow().original_scene_retired.set(true);

    let checked = interval.authenticate_body_data(authority.plan_evidence());
    let error = interval.finish(checked).unwrap_err();

    assert_eq!(
        error.message,
        "qualification refused: complete original packet collecting scope unavailable"
    );
    original.borrow().original_scene_retired.set(false);
    authority
        .graph_policy
        .read_original_initial_callback_data()
        .unwrap();
}

#[test]
fn actual_first_selector_refuses_without_flight_and_retains_current_file_owners() {
    let (_scene, original, authority) = fixture();
    authority.original_initial_callback_active.set(true);
    let (path, bytes) = disposable_source(&authority);

    let error = authority
        .authenticate_plan_view(authority.plan_evidence())
        .unwrap_err();

    assert_eq!(
        error.message,
        "qualification refused: complete original packet collecting scope unavailable"
    );
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    authority
        .graph_policy
        .read_original_initial_callback_data()
        .unwrap();
    assert!(
        original
            .borrow()
            .runtime_members
            .iter()
            .all(|slot| slot.get().is_none())
    );
}
