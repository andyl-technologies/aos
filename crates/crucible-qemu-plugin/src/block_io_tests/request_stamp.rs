//! Request-header oldest-live-epoch stamping and its wire validation ([IO-35]).

use super::*;

pub(super) fn stamp(epoch: u64, request_id: u32, oldest_live_epoch: u64) -> BlockRequestStamp {
    BlockRequestStamp::new(
        BlockRequestIdentity::new(epoch, request_id),
        oldest_live_epoch,
    )
    .unwrap_or_else(|error| panic!("test stamp is well formed: {error}"))
}

fn stamped_floor(frame: &FrameEntry) -> u64 {
    let payload = frame
        .payload()
        .unwrap_or_else(|error| panic!("submitted frame has a payload: {error}"));
    let (stamp, _request) = BlockRequest::decode(payload)
        .unwrap_or_else(|error| panic!("submitted request decodes: {error}"));
    stamp.oldest_live_epoch()
}

#[test]
fn submit_stamps_the_older_of_outstanding_and_own_epoch() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let header = RingHeader::new();
    let mut entries = empty_entries(4);
    let mut ring = outbound_ring(8, 2, &header, &mut entries);
    let older = stamp(0, 7, 0);

    // With no other live identity, the request's own epoch is the floor.
    let alone = block
        .submit_request(
            &mut freeze,
            &slot,
            &mut ring,
            10,
            &BlockRequest::flush(),
            None,
        )
        .unwrap_or_else(|error| panic!("first submit enqueues: {error}"));
    // A preserved retry of an older identity lowers the floor to its epoch.
    let retry = block
        .submit_retry_request(
            &mut freeze,
            &slot,
            &mut ring,
            11,
            &BlockRequest::flush(),
            older.identity(),
            Some(0),
        )
        .unwrap_or_else(|error| panic!("preserved retry enqueues: {error}"));

    assert_eq!(alone.oldest_live_epoch(), 0);
    assert_eq!(retry.oldest_live_epoch(), 0);
    assert_eq!(stamped_floor(&ring.entries[0]), 0);
    assert_eq!(stamped_floor(&ring.entries[1]), 0);
}

#[test]
fn stamp_never_follows_the_submitted_identity() {
    let identity = BlockRequestIdentity::new(4, 1);

    let older = PluginBlockIo::stamp(identity, Some(2));
    let newer = PluginBlockIo::stamp(identity, Some(9));
    let alone = PluginBlockIo::stamp(identity, None);

    assert_eq!(older.oldest_live_epoch(), 2);
    assert_eq!(newer.oldest_live_epoch(), 4);
    assert_eq!(alone.oldest_live_epoch(), 4);
    assert_eq!(
        BlockRequestStamp::new(identity, 5),
        Err(BlockWireError::OldestLiveEpochAfterEpoch {
            epoch: 4,
            oldest_live_epoch: 5,
        })
    );
}

#[test]
fn request_decode_rejects_the_previous_version_and_a_late_floor() {
    let encoded = BlockRequest::read(4096, 512)
        .encode(stamp(3, 7, 1))
        .unwrap_or_else(|error| panic!("read request encodes: {error}"));
    assert_eq!(encoded.len(), BLOCK_REQUEST_HEADER_LEN);
    assert_eq!(encoded[1], BLOCK_REQUEST_WIRE_VERSION);
    assert_eq!(encoded[28..36], 1_u64.to_le_bytes());

    let mut previous = encoded.clone();
    previous[1] = 4;
    assert_eq!(
        BlockRequest::decode(&previous),
        Err(BlockWireError::UnsupportedVersion { version: 4 })
    );

    let mut late = encoded;
    late[28..36].copy_from_slice(&4_u64.to_le_bytes());
    assert_eq!(
        BlockRequest::decode(&late),
        Err(BlockWireError::OldestLiveEpochAfterEpoch {
            epoch: 3,
            oldest_live_epoch: 4,
        })
    );

    let response = BlockResponse::new(BlockResponseStatus::Ok, 7, Vec::new())
        .encode()
        .unwrap_or_else(|error| panic!("response encodes: {error}"));
    assert_eq!(response[1], BLOCK_RESPONSE_WIRE_VERSION);
}
