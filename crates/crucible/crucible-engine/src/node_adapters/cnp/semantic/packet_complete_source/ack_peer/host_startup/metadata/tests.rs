//! Checks actual marker retention without constructing an SDK or lifecycle grant.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests::{
    coordinator, installation, producer, storage_selection,
};

fn marker(origin: Weak<OriginalHostSdkOrigin>) -> OriginalHostStartupMarker {
    OriginalHostStartupMarker {
        origin,
        complete: false,
        initial_lifecycle_issued: false,
        initial_lifecycle_quote: None,
        initial_lifecycle_completed: false,
        launch: None,
    }
}

#[test]
fn uninitialized_host_marker_has_no_phantom_origin_allocation() {
    let marker = marker(Weak::new());

    let facts = marker.retained_capacity_data(None).unwrap();

    assert_eq!(
        facts,
        RetainedProtocolMetadataFacts {
            observed_nodes: 4, // The four fixed marker fields.
            ..Default::default()
        }
    );
    assert_eq!(marker.retained_storage_data().unwrap(), 0);
    assert!(!marker.complete);
    assert!(!marker.initial_lifecycle_issued);
    assert!(!marker.initial_lifecycle_completed);
    assert!(marker.launch.is_none());
}

#[test]
fn expired_origin_preserves_the_actual_shell_without_renewing_host_lifecycle() {
    let origin = Rc::new(OriginalHostSdkOrigin::new());
    let marker = marker(Rc::downgrade(&origin));
    let weak_count = Rc::weak_count(&origin);
    let live = marker.retained_capacity_data(None).unwrap();
    let original = NodeRuntime::capture_shared_allocation_storage::<OriginalHostSdkOrigin>();
    assert_eq!(Rc::weak_count(&origin), weak_count);

    drop(origin);
    let expired = marker.retained_capacity_data(None).unwrap();

    assert_eq!(expired, live);
    assert_eq!(expired.shared_backing_views, 1);
    assert_eq!(
        expired.shared_value_bytes,
        size_of::<OriginalHostSdkOrigin>()
    );
    assert_eq!(
        expired.maximum_shared_value_alignment,
        std::mem::align_of::<OriginalHostSdkOrigin>()
    );
    assert_eq!(expired.capacity_records, 1);
    assert_eq!(expired.observed_nodes, 4);
    let admitted = OriginalHostStartupMarker::origin_capacity_requested_bound_data().unwrap();
    assert!(admitted >= original);
    assert_eq!(marker.retained_storage_data().unwrap(), admitted);
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &expired, admitted
        ),
        Ok(admitted)
    );
    assert!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &expired,
            admitted - 1
        )
        .is_err()
    );
    assert!(marker.origin.upgrade().is_none());
    assert!(!marker.complete);
    assert!(!marker.initial_lifecycle_issued);
    assert!(!marker.initial_lifecycle_completed);
}

#[test]
fn source_marker_census_refuses_busy_or_foreign_birth_custody() {
    let coordinator = coordinator();
    let mut source = PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&coordinator, 0),
        producer(),
        coordinator,
        storage_selection(),
    )
    .unwrap();
    assert_eq!(
        source
            .original_complete_host_startup_marker_capacity_data(None)
            .unwrap(),
        RetainedProtocolMetadataFacts::default()
    );
    let loan = source.ack_peer_birth.borrow_mut();

    assert_eq!(
        source.original_complete_host_startup_marker_capacity_data(None),
        Err(RuntimeError::OwnerBusy)
    );
    drop(loan);
    source.process = source.process.wrapping_add(1);

    assert_eq!(
        source.original_complete_host_startup_marker_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    assert!(source.ack_peer_birth.borrow().is_none());
}
