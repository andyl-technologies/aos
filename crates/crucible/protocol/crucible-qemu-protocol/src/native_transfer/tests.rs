//! Exercises exact prebirth transfer syntax and independently correlated artifacts.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::runtime_artifact::RuntimeArtifactIdentity;

fn runtime() -> RuntimeArtifactPair {
    RuntimeArtifactPair {
        process_generation: 4,
        account_generation: 5,
        source_assignment: [13; 32],
        libc: RuntimeArtifactIdentity {
            file_len: 2486648,
            sha256: [21; 32],
        },
        loader: RuntimeArtifactIdentity {
            file_len: 248504,
            sha256: [22; 32],
        },
    }
}

fn transfer() -> NativeTransfer {
    NativeTransfer {
        coordinates: NativeTransferCoordinates {
            issuer_epoch: 1,
            parent_epoch: 2,
            loan_epoch: 3,
            process_generation: 4,
            account_generation: 5,
            producer_request_epoch: 6,
            request_sequence: 7,
            profile_edition: 8,
            parent: [11; 32],
            issuer: [12; 32],
            recipient: [13; 32],
            launcher: [14; 32],
            loan: [15; 32],
            cleanup_holder: [16; 32],
            cleanup_epoch: 9,
        },
        runtime_pair_sha256: Sha256::digest(runtime().encode().unwrap()).into(),
        profile_manifest_sha256: [31; 32],
        process_contract_sha256: [32; 32],
        memory: NativeTransferMemory {
            gross_bytes: 45056,
            native_bytes: 40960,
            retained_bytes: 4096,
            fixed_floor_bytes: 4096,
            progress_bytes: 4096,
            physical_terminal_bytes: 4096,
            creator_history_bytes: 2048,
        },
        page_size: 4096,
        artifact_count: 2,
        paid_probe_sha256: [33; 32],
        liabilities: std::array::from_fn(|index| NativeLiability {
            kind: NativeLiabilityKind::decode(index as u32 + 1).unwrap(),
            disposition: NativeLiabilityDisposition::Required,
            memory_bytes: 4096,
            virtual_bytes: 8192,
            backing_bytes: 4096,
            maximum_tasks: 1,
            maximum_descriptors: 2,
            alignment: 64,
            producer: [index as u8 + 41; 32],
        }),
    }
}

#[test]
fn transfer_preserves_exact_fixed_layout_and_runtime_correlation() {
    let record = transfer();
    let bytes = record.encode().unwrap();

    assert_eq!(bytes.len(), 1472);
    assert_eq!(&bytes[..16], b"CRUCNPL1\0\0\0\x01\0\0\x05\xc0");
    assert_eq!(&bytes[80..112], &[11; 32]);
    assert_eq!(&bytes[144..176], &[13; 32]);
    assert_eq!(&bytes[336..368], &[16; 32]);
    assert_eq!(&bytes[456..488], &[33; 32]);
    assert_eq!(&bytes[488..512], &[0; 24]);
    assert_eq!(NativeTransfer::decode(&bytes).unwrap(), record);
    assert_eq!(
        NativeTransfer::decode(&bytes).unwrap().encode().unwrap(),
        bytes
    );
    record.corroborate_runtime(&runtime()).unwrap();

    for index in 0..NATIVE_LIABILITY_COUNT {
        let row = HEADER_BYTES + index * LIABILITY_BYTES;
        assert_eq!(read32(&bytes, row), index as u32 + 1);
        assert_eq!(read32(&bytes, row + 4), 1);
        assert_eq!(read32(&bytes, row + 8), 1);
        assert_eq!(read32(&bytes, row + 12), 0);
        assert_eq!(read64(&bytes, row + 16), 4096);
        assert_eq!(&bytes[row + 64..row + 96], &[index as u8 + 41; 32]);
    }
}

#[test]
fn transfer_refuses_every_truncation_trailing_bytes_and_reserved_octet() {
    let bytes = transfer().encode().unwrap();
    for length in 0..bytes.len() {
        assert!(
            NativeTransfer::decode(&bytes[..length]).is_err(),
            "length {length}"
        );
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert!(NativeTransfer::decode(&extended).is_err());

    let reserved = (488..512).chain((0..NATIVE_LIABILITY_COUNT).flat_map(|row| {
        let base = HEADER_BYTES + row * LIABILITY_BYTES;
        base + 12..base + 16
    }));
    for offset in reserved {
        let mut malformed = bytes;
        malformed[offset] = 1;
        assert!(
            NativeTransfer::decode(&malformed).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn transfer_refuses_absent_identities_and_exhausted_coordinates() {
    let bytes = transfer().encode().unwrap();
    for offset in [16, 24, 32, 40, 48, 56, 64, 72, 368] {
        for epoch in [0, u64::MAX] {
            let mut malformed = bytes;
            put64(&mut malformed, offset, epoch);
            assert!(
                NativeTransfer::decode(&malformed).is_err(),
                "epoch {offset}"
            );
        }
    }
    for offset in [80, 112, 144, 176, 208, 240, 272, 304, 336, 456] {
        let mut malformed = bytes;
        malformed[offset..offset + 32].fill(0);
        assert!(
            NativeTransfer::decode(&malformed).is_err(),
            "identity {offset}"
        );
    }
}

#[test]
fn transfer_refuses_mixed_layout_tags_and_liability_order() {
    let bytes = transfer().encode().unwrap();
    for (offset, tag) in [
        (8, 2),
        (12, 1471),
        (12, 1473),
        (512, 0),
        (512, 2),
        (516, 0),
        (516, 3),
        (520, 0),
        (520, 2),
    ] {
        let mut malformed = bytes;
        put32(&mut malformed, offset, tag);
        assert!(
            NativeTransfer::decode(&malformed).is_err(),
            "tag {offset}/{tag}"
        );
    }
    let mut swapped = transfer();
    swapped.liabilities.swap(0, 1);
    assert!(swapped.encode().is_err());

    for count in [0, 9, 11, u64::MAX] {
        let mut malformed = bytes;
        put64(&mut malformed, 440, count);
        assert!(NativeTransfer::decode(&malformed).is_err());
    }
}

#[test]
fn transfer_refuses_overflow_and_overlapping_purpose_accounting() {
    for offset in [376, 384, 392, 400, 408, 416, 424] {
        let mut malformed = transfer().encode().unwrap();
        let amount = read64(&malformed, offset) + 45056;
        put64(&mut malformed, offset, amount);
        assert!(
            NativeTransfer::decode(&malformed).is_err(),
            "amount {offset}"
        );
    }
    let mut overflow = transfer();
    overflow.memory.native_bytes = u64::MAX;
    overflow.memory.retained_bytes = 1;
    overflow.memory.gross_bytes = 0;
    assert!(overflow.encode().is_err());

    let mut row_overflow = transfer();
    row_overflow.liabilities[0].memory_bytes = u64::MAX;
    assert!(row_overflow.encode().is_err());

    // Other resource dimensions remain distinct; they cannot repair a missing
    // memory debit by presenting the same integer as descriptors or tasks.
    let mut substituted = transfer();
    substituted.liabilities[0].memory_bytes -= 1;
    substituted.liabilities[0].maximum_tasks += 1;
    assert!(substituted.encode().is_err());
}

#[test]
fn transfer_requires_canonical_unselected_rows_and_real_required_producers() {
    let mut record = transfer();
    let row = &mut record.liabilities[7];
    row.disposition = NativeLiabilityDisposition::Unselected;
    assert!(record.encode().is_err());

    let row = &mut record.liabilities[7];
    row.memory_bytes = 0;
    row.virtual_bytes = 0;
    row.backing_bytes = 0;
    row.maximum_tasks = 0;
    row.maximum_descriptors = 0;
    row.alignment = 1;
    row.producer = [0; 32];
    record.memory.native_bytes -= 4096;
    record.memory.gross_bytes -= 4096;
    let bytes = record.encode().unwrap();
    assert_eq!(NativeTransfer::decode(&bytes).unwrap(), record);

    for offset in [16, 24, 32, 40, 48, 56, 64] {
        let mut malformed = bytes;
        malformed[HEADER_BYTES + 7 * LIABILITY_BYTES + offset] = 2;
        assert!(
            NativeTransfer::decode(&malformed).is_err(),
            "unselected {offset}"
        );
    }
    for alignment in [0, 3, 63] {
        let mut malformed = transfer();
        malformed.liabilities[0].alignment = alignment;
        assert!(malformed.encode().is_err());
    }
    for missing_memory in [false, true] {
        let mut malformed = transfer();
        if missing_memory {
            malformed.liabilities[0].memory_bytes = 0;
        } else {
            malformed.liabilities[0].producer = [0; 32];
        }
        assert!(malformed.encode().is_err());
    }
}

#[test]
fn transfer_refuses_independently_valid_foreign_runtime_pairs() {
    let record = transfer();
    for changed in 0..6 {
        let mut pair = runtime();
        match changed {
            0 => pair.process_generation += 1,
            1 => pair.account_generation += 1,
            2 => pair.source_assignment[0] ^= 1,
            3 => pair.libc.file_len += 1,
            4 => pair.libc.sha256[0] ^= 1,
            _ => pair.loader.sha256[0] ^= 1,
        }
        assert!(pair.encode().is_ok());
        assert!(record.corroborate_runtime(&pair).is_err(), "pair {changed}");
    }
}

#[test]
fn transfer_refuses_invalid_page_geometry_and_absent_manifest() {
    for page_size in [0, 3, 4095, 8192, 65536] {
        let mut record = transfer();
        record.page_size = page_size;
        assert!(record.encode().is_err());
    }
    for count in [0, 1, 33, u64::MAX] {
        let mut record = transfer();
        record.artifact_count = count;
        assert!(record.encode().is_err());
    }
    for count in [2, 32] {
        let mut record = transfer();
        record.artifact_count = count;
        assert!(record.encode().is_ok());
    }
}

#[test]
fn transfer_retains_compulsory_reserves_and_outside_creator_history() {
    for index in [5, 8, 9] {
        let mut record = transfer();
        record.liabilities[index] = NativeLiability {
            kind: record.liabilities[index].kind,
            disposition: NativeLiabilityDisposition::Unselected,
            memory_bytes: 0,
            virtual_bytes: 0,
            backing_bytes: 0,
            maximum_tasks: 0,
            maximum_descriptors: 0,
            alignment: 1,
            producer: [0; 32],
        };
        record.memory.native_bytes -= 4096;
        record.memory.gross_bytes -= 4096;
        match index {
            5 => record.memory.fixed_floor_bytes = 0,
            8 => record.memory.progress_bytes = 0,
            _ => record.memory.physical_terminal_bytes = 0,
        }
        assert!(record.encode().is_err(), "compulsory row {index}");
    }

    let mut no_history = transfer();
    no_history.memory.creator_history_bytes = 0;
    assert!(no_history.encode().is_err());

    let mut no_outside = transfer();
    no_outside.memory.retained_bytes = 0;
    no_outside.memory.creator_history_bytes = 0;
    no_outside.memory.gross_bytes = no_outside.memory.native_bytes;
    assert!(no_outside.encode().is_err());
}
