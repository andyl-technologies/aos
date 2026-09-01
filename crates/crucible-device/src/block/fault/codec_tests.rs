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

    let mut prior_version = bytes.clone();
    let version_index = b"crucible.block-fault-state.v".len();
    assert_eq!(prior_version[version_index], b'2');
    prior_version[version_index] = b'1';
    assert_eq!(
        BlockFaultState::from_canonical_bytes(&prior_version, 32),
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
