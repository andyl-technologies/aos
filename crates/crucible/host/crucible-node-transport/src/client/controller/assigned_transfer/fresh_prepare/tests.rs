//! Checks closed binding projection data without constructing query authority.

use super::*;

fn allocation() -> ContentRef {
    canonical::content_ref(b"{}", PACKET_FRESH_RESTORE_ALLOCATION_MEDIA).unwrap()
}

#[test]
fn binding_projection_covers_actual_typed_binding_and_refuses_one_short() {
    let allocation = allocation();
    let binding = PacketNativeFreshRestoreAllocationPrepareBinding {
        schema: PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.into(),
        assigned_query: Bytes::new(vec![1; 32]),
        completed_query_response: Bytes::new(vec![2; 32]),
        allocation: allocation.clone(),
    };
    binding.validate_data().unwrap();
    let projected = binding_projection(&allocation, usize::MAX).unwrap();
    let mut observer = MetadataObserver::new();
    observer.observe(&binding).unwrap();
    let actual =
        actual_serialization_storage_data(&binding, observer.finish(), usize::MAX).unwrap();
    assert!(projected.requested_total().unwrap() >= actual.requested_total().unwrap());

    let exact = projected.requested_total().unwrap();
    assert!(binding_projection(&allocation, exact).is_ok());
    assert!(binding_projection(&allocation, exact - 1).is_err());
}

#[test]
fn allocation_identity_commits_full_reference_including_media_and_extent() {
    let original = allocation();
    let identity = reference_identity(&original);
    let mut changed = original.clone();
    changed.length = U64::new(original.length.get() + 1);
    assert_ne!(identity, reference_identity(&changed));
    changed = original.clone();
    changed.media_type.push('x');
    assert_ne!(identity, reference_identity(&changed));
    changed = original.clone();
    changed.hash.domain.push('x');
    assert_ne!(identity, reference_identity(&changed));
    changed = original.clone();
    let different = if changed.hash.digest.starts_with('0') {
        "1"
    } else {
        "0"
    };
    changed.hash.digest.replace_range(0..1, different);
    assert_ne!(identity, reference_identity(&changed));
}
