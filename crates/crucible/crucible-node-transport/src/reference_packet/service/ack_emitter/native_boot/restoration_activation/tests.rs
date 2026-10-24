//! Exercises the actual native per-axis gate without constructing authority.

use super::*;

fn row(retained: u64, transient: u64, scratch: u64) -> PacketRestorationActivationAllocationRow {
    PacketRestorationActivationAllocationRow {
        retained_requested_bytes: U64::new(retained),
        maximum_simultaneous_transient_bytes: U64::new(transient),
        declared_counter_scratch_bytes: U64::new(scratch),
    }
}

#[test]
fn signed_phase_rows_refuse_axis_substitution_and_invalid_totals() {
    let required = row(17, 23, 31);
    authenticate_row(&required, &required).unwrap();

    // Equal whole totals cannot exchange persistent, transient or scratch
    // credit. This calls the same gate used before native model/DOM work.
    for available in [row(16, 24, 31), row(18, 22, 31), row(18, 23, 30)] {
        assert_eq!(
            available.requested_bytes_data().unwrap(),
            required.requested_bytes_data().unwrap()
        );
        assert!(authenticate_row(&available, &required).is_err());
    }
    assert!(authenticate_row(&row(u64::MAX, 1, 1), &required).is_err());
    assert!(authenticate_row(&required, &row(0, 23, 31)).is_err());
}

#[test]
fn selected_upload_raw_bank_refuses_wrong_offset_and_growth_before_mutation() {
    let mut bank = Vec::with_capacity(8);
    let capacity = bank.capacity();
    assert_eq!(
        upload::append_upload_chunk_data(&mut bank, U64::new(0), &[1, 2, 3]).unwrap(),
        3
    );

    assert!(upload::append_upload_chunk_data(&mut bank, U64::new(2), &[4]).is_err());
    assert_eq!(bank, [1, 2, 3]);
    let excessive = vec![4; capacity];
    assert!(upload::append_upload_chunk_data(&mut bank, U64::new(3), &excessive).is_err());
    assert_eq!(bank, [1, 2, 3]);
    assert_eq!(bank.capacity(), capacity);

    let remainder = vec![4; capacity - 3];
    assert_eq!(
        upload::append_upload_chunk_data(&mut bank, U64::new(3), &remainder).unwrap(),
        capacity
    );
    assert_eq!(bank.capacity(), capacity);
    assert!(upload::append_upload_chunk_data(&mut bank, U64::new(capacity as u64), &[5]).is_err());
    assert_eq!(bank.len(), capacity);
}
