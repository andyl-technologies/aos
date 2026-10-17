//! Concrete 9p seed grammar, fid paths and pre-member refusal controls.

use super::*;
use crate::ninep::test_support::{device, ok, round_trip, tattach, tversion, twalk};

fn decode(
    bytes: &[u8],
    admit: &mut dyn FnMut(u64) -> Result<(), &'static str>,
) -> Result<NinepSnapshot, NinepSnapshotCodecError> {
    let mut scratch = vec![0; bytes.len()];
    NinepSnapshot::from_canonical_bytes_with_wire_decoder(
        bytes,
        MAX_NINEP_SNAPSHOT_BYTES,
        admit,
        &mut |_| Ok(()),
        |payload, seed| ciborium::de::from_reader_with_buffer_seed(seed, payload, &mut scratch),
    )
}

#[test]
fn saved_ninep_seed_preserves_live_fid_and_complete_path() {
    let mut device = device();
    round_trip(
        &mut device,
        0,
        &tversion(
            1,
            crate::ninep::MAX_MSIZE,
            crate::ninep::codec::PROTOCOL_VERSION,
        ),
    );
    round_trip(&mut device, 1, &tattach(2, 1));
    round_trip(&mut device, 2, &twalk(3, 1, 2, &["bin", "tool"]));
    let snapshot = device.snapshot();
    let bytes = ok(snapshot.to_canonical_bytes());
    let mut allocations = Vec::new();

    let actual = ok(decode(&bytes, &mut |bytes| {
        allocations.push(bytes);
        Ok(())
    }));

    assert_eq!(actual, snapshot);
    assert_eq!(actual.server.fids.len(), 2);
    assert!(allocations.contains(&(2 * std::mem::size_of::<String>() as u64)));
    assert_eq!(ok(actual.to_canonical_bytes()), bytes);
}

#[test]
fn ninep_table_refusal_precedes_malformed_first_payload_member() {
    let mut bytes = NINEP_SNAPSHOT_MAGIC.to_vec();
    bytes.extend_from_slice(&[0xa1, 0x64, b'c', b'o', b'r', b'e', 0x82, 0xff]);
    let mut allocations = Vec::new();

    let error = decode(&bytes, &mut |bytes| {
        allocations.push(bytes);
        Err("same original ninep table refusal")
    })
    .err()
    .unwrap();

    assert_eq!(allocations, [2]);
    assert_eq!(error, NinepSnapshotCodecError::Malformed);
}

#[test]
fn strict_map_rejects_order_before_any_insertion_admission() {
    let mut calls = 0;

    let result = collect_strict(
        vec![(2_u32, 5_u64), (1, 6)],
        DeviceSnapshotAllocation::NinepVirtualFid,
        &mut |_| {
            calls += 1;
            Ok(())
        },
    );

    assert_eq!(result.err(), Some(NinepSnapshotCodecError::Noncanonical));
    assert_eq!(calls, 0);
}

#[test]
fn transformed_fid_table_moves_existing_path_storage_after_admission() {
    let path = vec![String::from("bin"), String::from("tool")];
    let address = path.as_ptr();
    let entry = FidEntryWire {
        path: ok(SnapshotPath::new(path, "test fid path")),
        state: FidState::Clunked,
    };
    let wire = NinepServerWire {
        msize: crate::ninep::MAX_MSIZE,
        negotiated: true,
        fids: ok(SnapshotFids::new(vec![(4, entry)], "test fids")),
    };
    let mut requests = Vec::new();

    let actual = ok(decode_server(wire, &mut |allocation| {
        requests.push(allocation);
        Ok(())
    }));

    assert_eq!(
        requests,
        [DeviceSnapshotAllocation::NinepFidTable { entries: 1 }]
    );
    assert_eq!(actual.fids[0].0, 4);
    assert_eq!(actual.fids[0].1.path, ["bin", "tool"]);
    assert_eq!(actual.fids[0].1.path.as_ptr(), address);
}
