//! Shared fixtures for the 9p visibility test modules.

use super::*;

pub(super) fn key(slot: u8, generation: u64) -> NinepVisibilityUpdateKey {
    let mut update_id = [slot; 32];
    update_id[..8].copy_from_slice(&generation.to_le_bytes());
    NinepVisibilityUpdateKey {
        slot: [slot; 32],
        update_id,
        generation,
    }
}

pub(super) fn file(path: &str, version: u32, data: &[u8]) -> NinepObjectVersion {
    NinepObjectVersion {
        path: path.to_owned(),
        version,
        mode: 0o100_644,
        data: data.to_vec(),
        deleted: false,
    }
}

pub(super) fn deletion(path: &str, version: u32) -> NinepObjectVersion {
    NinepObjectVersion {
        path: path.to_owned(),
        version,
        mode: 0,
        data: Vec::new(),
        deleted: true,
    }
}

pub(super) fn atomic(scope: NinepVisibilityScope) -> NinepVisibilityPolicy {
    NinepVisibilityPolicy {
        scope,
        atomic_metadata_and_data: true,
        retain_deleted_objects: false,
    }
}

pub(super) fn split(scope: NinepVisibilityScope) -> NinepVisibilityPolicy {
    NinepVisibilityPolicy {
        scope,
        atomic_metadata_and_data: false,
        retain_deleted_objects: false,
    }
}

pub(super) fn coordinate(ticks: u64, sequence: u64) -> NinepEventCoordinate {
    NinepEventCoordinate { ticks, sequence }
}

pub(super) fn emission(event: [u8; 32], ticks: u64, sequence: u64) -> NinepEventEmission {
    NinepEventEmission {
        event,
        coordinate: coordinate(ticks, sequence),
    }
}

pub(super) fn on_event(event: [u8; 32], after: NinepEventCoordinate) -> NinepVisibilityRelease {
    NinepVisibilityRelease::OnEvent { event, after }
}

pub(super) fn latch_of(
    state: &NinepVisibilityState,
    sequence: u64,
) -> Option<NinepEventCoordinate> {
    ok(state.updates_between(sequence, sequence + 1))
        .first()
        .and_then(|update| update.event_latch)
}

pub(super) fn ok<T>(result: Result<T, DeviceError>) -> T {
    result.unwrap_or_else(|error| panic!("visibility operation failed: {error}"))
}

pub(super) fn round_trip(state: &NinepVisibilityState) -> NinepVisibilityState {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut bytes)
        .unwrap_or_else(|error| panic!("encode visibility state: {error}"));
    let decoded: NinepVisibilityState = ciborium::de::from_reader(bytes.as_slice())
        .unwrap_or_else(|error| panic!("decode visibility state: {error}"));
    let mut reencoded = Vec::new();
    ciborium::ser::into_writer(&decoded, &mut reencoded)
        .unwrap_or_else(|error| panic!("re-encode visibility state: {error}"));
    assert_eq!(reencoded, bytes, "visibility encoding is canonical");
    decoded
}
