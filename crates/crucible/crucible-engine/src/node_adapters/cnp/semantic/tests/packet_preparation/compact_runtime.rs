//! Checks retained compact custody using the actual generic process fixture.
//!
//! The test explicitly moves SDK ownership without issuing a production Source18
//! window. This proves custody and containment only, never native qualification.

use super::*;
use crate::node_adapters::cnp::semantic::retained_storage::preparation::PreparationCounter;

#[test]
fn compact_process_custody_keeps_source_reads_and_survives_supervisor_transfer() {
    let fixture = Fixture::new(true, true);
    let mut guard = fixture.launch_guard();
    let before = guard.custody().unwrap().original_source_read().unwrap();
    let native = guard.custody.as_mut().unwrap();
    let pid = native.provider_pid();
    let descriptors = native
        .controller
        .as_ref()
        .unwrap()
        .retained_descriptor_count_data()
        .unwrap();

    PacketRuntimeController::retain_into(&mut native.controller, &mut native.compact_runtime)
        .unwrap();

    assert!(native.controller().is_none());
    native.authenticate_process().unwrap();
    let after = native.original_source_read().unwrap();
    assert!(before.same_original(&after));
    before.ensure_current().unwrap();
    after.ensure_current().unwrap();
    let runtime = native.compact_runtime.as_ref().unwrap();
    assert_eq!(runtime.peer_pid(), pid);
    assert_eq!(
        runtime.retained_descriptor_count_data().unwrap(),
        descriptors
    );
    assert_eq!(runtime.journal_byte_reservations_data()[1..], [0, 0]);

    // The fixture installs an erased supervisor. Its unrecognized backing must
    // not become an empty compact-runtime row in the raw precredit observer.
    let mut counter = PreparationCounter::new(usize::MAX);
    assert_eq!(
        guard.charge_retained_storage_precredit_data(None, None, &mut counter),
        Err(RuntimeError::UnsupportedFacet),
    );
    assert_eq!(
        guard.original_metadata_origin_data(),
        Err(RuntimeError::UnsupportedFacet),
    );

    drop(guard);

    assert!(before.ensure_current().is_err());
    assert!(after.ensure_current().is_err());
    let mut retained = fixture.retained.borrow_mut();
    assert_eq!(retained.len(), 1);
    let native = &mut retained[0];
    assert!(native.controller().is_none());
    let runtime = native.compact_runtime.as_ref().unwrap();
    assert_eq!(runtime.peer_pid(), pid);
    assert_eq!(
        runtime.retained_descriptor_count_data().unwrap(),
        descriptors
    );
    assert_eq!(runtime.journal_byte_reservations_data()[1..], [0, 0]);
    super::super::operational_poll::original_poll(|| {
        native.poll_reclamation().unwrap().then_some(())
    });

    assert!(native.kernel_resources_reclaimed().unwrap());
    let runtime = native.compact_runtime.as_ref().unwrap();
    assert!(runtime.authority().ensure_live().is_err());
    assert_eq!(
        runtime.retained_descriptor_count_data().unwrap(),
        descriptors
    );
    assert_eq!(runtime.journal_byte_reservations_data()[1..], [0, 0]);
}

#[test]
fn conflicting_or_foreign_compact_custody_cannot_issue_a_source_read() {
    let fixture = Fixture::new(true, true);
    let foreign_fixture = Fixture::new(true, true);
    let mut guard = fixture.launch_guard();
    let mut foreign_guard = foreign_fixture.launch_guard();
    let native = guard.custody.as_mut().unwrap();
    let original_read = native.original_source_read().unwrap();
    PacketRuntimeController::retain_into(&mut native.controller, &mut native.compact_runtime)
        .unwrap();
    native.controller = foreign_guard.custody.as_mut().unwrap().controller.take();

    assert!(native.controller().is_none());
    assert!(matches!(
        native.authenticate_process(),
        Err(ProviderError::Correlation(
            "generic original control custody is ambiguous"
        ))
    ));
    assert!(native.original_source_read().is_err());

    // Restore only the deliberate test substitution. Both true process owners
    // remain in their original guarded slots for actual supervised reclamation.
    foreign_guard.custody.as_mut().unwrap().controller =
        guard.custody.as_mut().unwrap().controller.take();
    guard.custody().unwrap().authenticate_process().unwrap();
    original_read.ensure_current().unwrap();
    foreign_guard
        .custody()
        .unwrap()
        .authenticate_process()
        .unwrap();

    let native = guard.custody.as_mut().unwrap();
    let foreign = foreign_guard.custody.as_mut().unwrap();
    PacketRuntimeController::retain_into(&mut foreign.controller, &mut foreign.compact_runtime)
        .unwrap();
    std::mem::swap(&mut native.compact_runtime, &mut foreign.compact_runtime);

    assert!(matches!(
        native.authenticate_process(),
        Err(ProviderError::Correlation("generic control peer changed"))
    ));
    assert!(native.original_source_read().is_err());
    assert!(foreign.authenticate_process().is_err());

    std::mem::swap(&mut native.compact_runtime, &mut foreign.compact_runtime);
    native.authenticate_process().unwrap();
    foreign.authenticate_process().unwrap();
    original_read.ensure_current().unwrap();
    drop(foreign_guard);
    drop(guard);
}

#[test]
fn native_read_capacity_keeps_genuinely_issued_complete_byte_custody_after_revocation() {
    let fixture = Fixture::new(true, true);
    let guard = fixture.launch_guard_selected(true);
    let read = guard.custody().unwrap().original_source_read().unwrap();
    let report = read
        .retained_requested_storage_precredit_data(usize::MAX)
        .unwrap();
    assert!(!report.unknowns().executable_lease_worker);
    read.ensure_current().unwrap();

    let before = read.retained_capacity_data(None).unwrap();

    assert_eq!(before.shared_backing_views, 5);
    assert_eq!(before.vector_banks, 2);
    assert!(before.vector_capacity_bytes > 0);
    assert_eq!(before.observed_nodes, 1); // Only the SDK's saved scalar epoch.
    assert!(before.string_capacity_bytes > 0);
    assert!(
        crate::node_adapters::cnp::CnpSemanticSourceRead::retained_capacity_counter_scratch_data()
            > 0
    );
    drop(guard);

    assert!(read.ensure_current().is_err());
    assert_eq!(read.retained_capacity_data(None).unwrap(), before);
    assert_eq!(read.retained_capacity_data(None).unwrap(), before);
}
