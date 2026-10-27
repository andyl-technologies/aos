//! Exercises exact retained prefix comparison without issuing settlement authority.

use super::*;

#[test]
#[allow(clippy::unwrap_used)]
fn native5_original_antecedent_prefix_refuses_changed_bytes_ids_geometry_and_partial_suffix() {
    let mut current = OriginalFrameReservation::reserve(4096, 8).unwrap();
    let incoming = current.begin(FrameDirection::Incoming, 6).unwrap();
    current.append(incoming, b"\0\0\0\x02{}").unwrap();
    current
        .retain_request(incoming, &crucible_node_format::Id::new("capture").unwrap())
        .unwrap();
    current.finish(incoming).unwrap();
    let mut captured = OriginalFrameReservation::reserve(4096, 8).unwrap();
    current.copy_into_empty(&mut captured).unwrap();

    let outgoing = current.begin(FrameDirection::Outgoing, 6).unwrap();
    current.append(outgoing, b"\0\0\0\x02{}").unwrap();
    assert!(captured.authenticate_exact_prefix_of(&current).is_err());
    current.advance(outgoing, 6).unwrap();
    current.finish(outgoing).unwrap();
    captured.authenticate_exact_prefix_of(&current).unwrap();

    current.bytes[4] = b'[';
    assert!(captured.authenticate_exact_prefix_of(&current).is_err());
    current.bytes[4] = b'{';
    let request = current.slots[incoming].request;
    current.slots[incoming].request.as_mut().unwrap().0[0] = b'x';
    assert!(captured.authenticate_exact_prefix_of(&current).is_err());
    current.slots[incoming].request = request;
    let count = current.incoming;
    current.incoming = 0;
    assert!(captured.authenticate_exact_prefix_of(&current).is_err());
    current.incoming = count;
    captured.authenticate_exact_prefix_of(&current).unwrap();

    let mut different = OriginalFrameReservation::reserve(8192, 8).unwrap();
    different.bytes.extend_from_slice(&current.bytes);
    different.slots.extend_from_slice(&current.slots);
    different.incoming = current.incoming;
    different.outgoing = current.outgoing;
    assert!(captured.authenticate_exact_prefix_of(&different).is_err());
    assert_eq!(captured.incoming, 1);
    assert_eq!(captured.outgoing, 0);
    assert_eq!(captured.bytes, b"\0\0\0\x02{}");
}
