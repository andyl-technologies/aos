//! Canonical block-fault continuation codec tests.

use super::*;

fn state() -> BlockFaultState {
    BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 1,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 64,
        cache_entries: 64,
        controller_buffer_bytes: 64,
        controller_entries: 64,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"))
}

#[test]
fn block_fault_checkpoint_codec_is_bounded_versioned_and_canonical() {
    let state = state();
    let bytes = state
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode checkpoint: {error}"));
    let restored = BlockFaultState::from_canonical_bytes(&bytes, 32)
        .unwrap_or_else(|error| panic!("decode checkpoint: {error}"));
    assert_eq!(restored, state);

    let mut unsupported_version = bytes.clone();
    let version_index = b"crucible.block-fault-state.v".len();
    assert_eq!(unsupported_version[version_index], b'4');
    unsupported_version[version_index] = b'?';
    assert_eq!(
        BlockFaultState::from_canonical_bytes(&unsupported_version, 32),
        Err(BlockFaultStateCodecError::Version)
    );

    let configured = u64::try_from(bytes.len() - 1)
        .unwrap_or_else(|error| panic!("fixture length is representable: {error}"));
    assert_eq!(
        BlockFaultState::from_canonical_bytes_with_limit(&bytes, 32, configured),
        Err(BlockFaultStateCodecError::ResourceLimit {
            field: "block fault-state bytes",
            current: 0,
            requested: bytes.len() as u64,
            configured,
            hard: MAX_BLOCK_FAULT_STATE_BYTES,
        })
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        BlockFaultState::from_canonical_bytes(&trailing, 32),
        Err(BlockFaultStateCodecError::Noncanonical)
    );
}

#[test]
fn supplied_fault_parser_preserves_canonical_state_and_input_admission() {
    let expected = state();
    let bytes = expected.to_canonical_bytes().unwrap();
    let mut calls = 0;

    let actual = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        32,
        MAX_BLOCK_FAULT_STATE_BYTES,
        &mut |_| Ok(()),
        |payload| {
            calls += 1;
            ciborium::de::from_reader(payload)
        },
    )
    .unwrap();

    assert_eq!(actual, expected);
    assert_eq!(calls, 1);

    let maximum = u64::try_from(bytes.len() - 1).unwrap();
    let result = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        32,
        maximum,
        &mut |_| Ok(()),
        |payload| {
            calls += 1;
            ciborium::de::from_reader(payload)
        },
    );

    assert!(matches!(
        result,
        Err(BlockFaultStateCodecError::ResourceLimit { .. })
    ));
    assert_eq!(calls, 1);
}

#[test]
fn supplied_fault_parser_error_precedes_restore_validation() {
    let bytes = state().to_canonical_bytes().unwrap();
    let mut calls = 0;

    let result = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        0,
        MAX_BLOCK_FAULT_STATE_BYTES,
        &mut |_| Ok(()),
        |_| {
            calls += 1;
            Err(ciborium::de::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "actual supplied fault parser failure",
            )))
        },
    );

    assert_eq!(result, Err(BlockFaultStateCodecError::Malformed));
    assert_eq!(calls, 1);
}

#[test]
fn fault_validation_output_is_admitted_before_buffer_reservation() {
    let expected = state();
    let bytes = expected.to_canonical_bytes().unwrap();
    let mut requested = Vec::new();

    let result = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        32,
        MAX_BLOCK_FAULT_STATE_BYTES,
        &mut |count| {
            requested.push(count);
            Err("original fault output refused")
        },
        |payload| ciborium::de::from_reader(payload),
    );

    assert_eq!(result, Err(BlockFaultStateCodecError::Malformed));
    assert_eq!(requested, [bytes.len() as u64]);
}
