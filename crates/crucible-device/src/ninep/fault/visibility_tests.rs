//! Compaction, session retirement, and slot-identity tests for 9p visibility.
//!
//! The randomized equivalence test drives the compacting state and an
//! uncompacted reference model through identical commit, advance, and version
//! negotiation sequences and requires identical lookups and frontiers for the
//! current session and for a freshly negotiated one.

use super::*;

fn key(slot: u8, generation: u64) -> NinepVisibilityUpdateKey {
    let mut update_id = [slot; 32];
    update_id[..8].copy_from_slice(&generation.to_le_bytes());
    NinepVisibilityUpdateKey {
        slot: [slot; 32],
        update_id,
        generation,
    }
}

fn file(path: &str, version: u32, data: &[u8]) -> NinepObjectVersion {
    NinepObjectVersion {
        path: path.to_owned(),
        version,
        mode: 0o100_644,
        data: data.to_vec(),
        deleted: false,
    }
}

fn deletion(path: &str, version: u32) -> NinepObjectVersion {
    NinepObjectVersion {
        path: path.to_owned(),
        version,
        mode: 0,
        data: Vec::new(),
        deleted: true,
    }
}

fn atomic(scope: NinepVisibilityScope) -> NinepVisibilityPolicy {
    NinepVisibilityPolicy {
        scope,
        atomic_metadata_and_data: true,
        retain_deleted_objects: false,
    }
}

fn split(scope: NinepVisibilityScope) -> NinepVisibilityPolicy {
    NinepVisibilityPolicy {
        scope,
        atomic_metadata_and_data: false,
        retain_deleted_objects: false,
    }
}

fn ok<T>(result: Result<T, DeviceError>) -> T {
    result.unwrap_or_else(|error| panic!("visibility operation failed: {error}"))
}

fn round_trip(state: &NinepVisibilityState) -> NinepVisibilityState {
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

const NO_EVENTS: &BTreeMap<[u8; 32], u64> = &BTreeMap::new();

#[test]
fn repeated_released_updates_compact_to_one_version_per_path() {
    let mut state = NinepVisibilityState::default();
    for version in 1..=64_u32 {
        ok(state.commit(
            key(1, u64::from(version)),
            file("/a", version, format!("v{version}").as_bytes()),
            atomic(NinepVisibilityScope::Global),
            NinepVisibilityRelease::AtTicks(u64::from(version)),
            0,
            0,
        ));
        ok(state.advance_visibility(0, u64::from(version), NO_EVENTS));
    }
    ok(state.advance_visibility(0, 64, NO_EVENTS));

    assert_eq!(state.committed_frontier(), 64);
    assert_eq!(state.compacted_frontier(), 64);
    assert_eq!(state.object_version_count(), 1);
    assert_eq!(
        state.visible_object(0, "/a").map(|object| object.data),
        Some(b"v64".to_vec())
    );
    assert_eq!(round_trip(&state), state);
}

#[test]
fn compacted_deletion_keeps_prior_bytes_for_split_data_visibility() {
    let mut state = NinepVisibilityState::default();
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"old"),
        atomic(NinepVisibilityScope::Global),
        NinepVisibilityRelease::AtTicks(0),
        0,
        0,
    ));
    ok(state.commit(
        key(2, 1),
        deletion("/a", 2),
        NinepVisibilityPolicy {
            retain_deleted_objects: true,
            ..atomic(NinepVisibilityScope::Global)
        },
        NinepVisibilityRelease::AtTicks(0),
        0,
        0,
    ));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    assert_eq!(state.compacted_frontier(), 2);
    assert_eq!(state.object_version_count(), 2);
    assert_eq!(state.lookup_object(0, "/a"), NinepVisibilityLookup::Deleted);

    // A later non-atomic recreation exposes metadata first and must read the
    // newest non-deleted bytes, which now live only in the compacted residue.
    ok(state.commit(
        key(3, 1),
        file("/a", 3, b"new"),
        split(NinepVisibilityScope::Global),
        NinepVisibilityRelease::AtTicks(10),
        0,
        5,
    ));
    ok(state.advance_visibility(0, 10, NO_EVENTS));
    let visible = state
        .visible_object(0, "/a")
        .unwrap_or_else(|| panic!("recreated object is visible"));
    assert_eq!((visible.version, visible.data), (3, b"old".to_vec()));
}

#[test]
fn recommit_after_compaction_returns_the_original_sequence() {
    let mut state = NinepVisibilityState::default();
    let first = key(1, 4);
    let commit = |state: &mut NinepVisibilityState, data: &[u8]| {
        state.commit(
            first,
            file("/a", 1, data),
            atomic(NinepVisibilityScope::Global),
            NinepVisibilityRelease::AtTicks(0),
            0,
            0,
        )
    };
    assert_eq!(ok(commit(&mut state, b"one")), 0);
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    assert_eq!(state.compacted_frontier(), 1);

    assert!(state.contains_update(&first));
    assert_eq!(ok(commit(&mut state, b"one")), 0);
    assert!(commit(&mut state, b"two").is_err());
    assert_eq!(state.committed_frontier(), 1);
}

#[test]
fn superseded_slot_generation_fails_closed() {
    let mut state = NinepVisibilityState::default();
    let commit = |state: &mut NinepVisibilityState, key| {
        state.commit(
            key,
            file("/a", 1, b"one"),
            atomic(NinepVisibilityScope::Global),
            NinepVisibilityRelease::AtTicks(0),
            0,
            0,
        )
    };
    assert_eq!(ok(commit(&mut state, key(1, 2))), 0);
    assert_eq!(ok(commit(&mut state, key(1, 3))), 1);

    assert!(!state.contains_update(&key(1, 2)));
    assert!(commit(&mut state, key(1, 2)).is_err());
    assert!(commit(&mut state, key(1, 1)).is_err());
    assert_eq!(state.committed_frontier(), 2);
}

#[test]
fn identity_reused_by_a_later_session_fails_closed() {
    let mut state = NinepVisibilityState::default();
    let commit = |state: &mut NinepVisibilityState, writer| {
        state.commit(
            key(1, 1),
            file("/a", 1, b"one"),
            atomic(NinepVisibilityScope::Global),
            NinepVisibilityRelease::AtTicks(0),
            writer,
            0,
        )
    };
    ok(commit(&mut state, 0));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    assert_eq!(state.compacted_frontier(), 1);

    // The writer session is part of the committed content, so reapplying the
    // same installed action from a newly negotiated session is a reuse.
    assert!(commit(&mut state, 1).is_err());
}

#[test]
fn unreleased_writer_immediate_update_stops_compaction() {
    let mut state = NinepVisibilityState::default();
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"mine"),
        atomic(NinepVisibilityScope::WriterImmediate),
        NinepVisibilityRelease::AtTicks(1_000),
        3,
        0,
    ));
    ok(state.commit(
        key(2, 1),
        file("/b", 1, b"released"),
        atomic(NinepVisibilityScope::Global),
        NinepVisibilityRelease::AtTicks(0),
        3,
        0,
    ));
    assert_eq!(ok(state.advance_visibility(3, 10, NO_EVENTS)), (2, 2));
    ok(state.advance_visibility(3, 10, NO_EVENTS));
    assert_eq!(state.compacted_frontier(), 0);

    // Another session must still wait for the writer-immediate release.
    state.retire_sessions_except(4);
    assert_eq!(ok(state.advance_visibility(4, 10, NO_EVENTS)), (0, 0));
    assert_eq!(state.visible_object(4, "/b"), None);
    assert_eq!(ok(state.advance_visibility(4, 1_000, NO_EVENTS)), (2, 2));
    ok(state.advance_visibility(4, 1_000, NO_EVENTS));
    assert_eq!(state.compacted_frontier(), 2);
}

#[test]
fn event_release_with_data_lag_is_never_compacted() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"lagged"),
        split(NinepVisibilityScope::Global),
        NinepVisibilityRelease::OnEvent(event),
        0,
        1,
    ));
    let events = BTreeMap::from([(event, 5)]);
    assert_eq!(ok(state.advance_visibility(0, 1_005, &events)), (1, 1));
    ok(state.advance_visibility(0, 50_000, &events));
    assert_eq!(state.compacted_frontier(), 0);

    // A re-emitted event moves the observed coordinate, so a new session
    // re-evaluates the data deadline exactly as the uncompacted state would.
    state.retire_sessions_except(1);
    let reemitted = BTreeMap::from([(event, 49_500)]);
    assert_eq!(ok(state.advance_visibility(1, 50_000, &reemitted)), (1, 0));
}

#[test]
fn new_session_sees_compacted_state_only_after_its_first_advance() {
    let mut state = NinepVisibilityState::default();
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"one"),
        atomic(NinepVisibilityScope::Global),
        NinepVisibilityRelease::AtTicks(0),
        0,
        0,
    ));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    assert_eq!(state.compacted_frontier(), 1);

    state.retire_sessions_except(1);
    assert_eq!(state.session_count(), 0);
    assert_eq!(state.lookup_object(1, "/a"), NinepVisibilityLookup::Base);
    assert_eq!(ok(state.advance_visibility(1, 0, NO_EVENTS)), (1, 1));
    assert!(state.visible_object(1, "/a").is_some());
}

#[test]
fn folded_updates_are_unavailable_individually() {
    let mut state = NinepVisibilityState::default();
    for slot in 1..=3 {
        ok(state.commit(
            key(slot, 1),
            file("/a", u32::from(slot), b"x"),
            atomic(NinepVisibilityScope::Global),
            NinepVisibilityRelease::AtTicks(0),
            0,
            0,
        ));
    }
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    ok(state.commit(
        key(4, 1),
        file("/a", 4, b"x"),
        atomic(NinepVisibilityScope::Global),
        NinepVisibilityRelease::AtTicks(5),
        0,
        0,
    ));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    assert_eq!(state.compacted_frontier(), 3);

    assert!(state.updates_between(2, 4).is_err());
    let live = ok(state.updates_between(3, 4));
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].sequence, 3);
}

#[test]
fn clock_regression_below_the_compaction_proof_fails_closed() {
    let mut state = NinepVisibilityState::default();
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"one"),
        atomic(NinepVisibilityScope::Global),
        NinepVisibilityRelease::AtTicks(10),
        0,
        0,
    ));
    ok(state.advance_visibility(0, 10, NO_EVENTS));
    ok(state.advance_visibility(0, 20, NO_EVENTS));
    assert_eq!(state.compacted_frontier(), 1);
    assert!(state.advance_visibility(0, 19, NO_EVENTS).is_err());
}

#[test]
fn decoded_state_rejects_inconsistent_compaction_records() {
    let mut state = NinepVisibilityState::default();
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"one"),
        atomic(NinepVisibilityScope::Global),
        NinepVisibilityRelease::AtTicks(0),
        0,
        0,
    ));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    ok(state.advance_visibility(0, 0, NO_EVENTS));
    let decoded = round_trip(&state);
    assert_eq!(decoded, state);

    let encode = |wire: &NinepVisibilityStateWire| {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(wire, &mut bytes)
            .unwrap_or_else(|error| panic!("encode wire: {error}"));
        bytes
    };
    let wire = || NinepVisibilityStateWire {
        next_sequence: state.next_sequence,
        base_sequence: state.base_sequence,
        release_tick: state.release_tick,
        session: state.session,
        updates: state.updates.clone(),
        compacted: state.compacted.clone(),
        identities: state.identities.clone(),
    };
    let decode = |bytes: Vec<u8>| {
        ciborium::de::from_reader::<NinepVisibilityState, _>(bytes.as_slice()).is_err()
    };

    let mut floor_beyond_commit = wire();
    floor_beyond_commit.base_sequence = 2;
    assert!(decode(encode(&floor_beyond_commit)));

    let mut session_below_floor = wire();
    session_below_floor.session = Some(NinepVisibilitySession {
        session: 0,
        metadata: 1,
        data: 0,
    });
    assert!(decode(encode(&session_below_floor)));

    let mut orphaned_compaction = wire();
    orphaned_compaction.base_sequence = 0;
    orphaned_compaction.release_tick = 0;
    orphaned_compaction.session = None;
    orphaned_compaction.identities.clear();
    orphaned_compaction.next_sequence = 0;
    assert!(decode(encode(&orphaned_compaction)));
}

/// Uncompacted reference model with every session's frontiers retained.
#[derive(Default)]
struct Reference {
    updates: Vec<NinepVisibilityUpdate>,
    frontiers: BTreeMap<u64, (u64, u64)>,
}

impl Reference {
    fn commit(&mut self, update: NinepVisibilityUpdate) -> u64 {
        if let Some(existing) = self
            .updates
            .iter()
            .find(|existing| existing.key.update_id == update.key.update_id)
        {
            return existing.sequence;
        }
        let sequence = self.updates.len() as u64;
        self.frontiers.entry(update.writer_session).or_default();
        self.updates
            .push(NinepVisibilityUpdate { sequence, ..update });
        sequence
    }

    fn advance(
        &mut self,
        session: u64,
        now: u64,
        events: &BTreeMap<[u8; 32], u64>,
    ) -> Result<(u64, u64), DeviceError> {
        let (mut metadata, mut data) = self.frontiers.get(&session).copied().unwrap_or_default();
        while let Some(update) = self.updates.get(metadata as usize) {
            let ready = update.policy.scope == NinepVisibilityScope::WriterImmediate
                && update.writer_session == session
                || release_coordinate(update.release, events)?.is_some_and(|tick| now >= tick);
            if !ready {
                break;
            }
            metadata += 1;
        }
        while let Some(update) = self.updates.get(data as usize) {
            let ready = update.policy.scope == NinepVisibilityScope::WriterImmediate
                && update.writer_session == session
                || data_deadline(update, events)?.is_some_and(|deadline| now >= deadline);
            if !ready {
                break;
            }
            data += 1;
        }
        self.frontiers.insert(session, (metadata, data));
        Ok((metadata, data))
    }

    fn frontier(&self, session: u64) -> (u64, u64) {
        self.frontiers.get(&session).copied().unwrap_or_default()
    }

    fn lookup(&self, session: u64, path: &str) -> NinepVisibilityLookup {
        let (metadata_frontier, data_frontier) = self.frontier(session);
        let newest_first = || {
            self.updates
                .iter()
                .rev()
                .filter(|update| update.object.path == path)
        };
        if newest_first().next().is_some_and(|update| {
            update.object.deleted
                && !update.policy.retain_deleted_objects
                && update.sequence >= metadata_frontier
        }) {
            return NinepVisibilityLookup::Deleted;
        }
        let Some(metadata) = newest_first().find(|update| update.sequence < metadata_frontier)
        else {
            return NinepVisibilityLookup::Base;
        };
        if metadata.object.deleted {
            return NinepVisibilityLookup::Deleted;
        }
        let data = newest_first()
            .find(|update| update.sequence < data_frontier && !update.object.deleted)
            .map(|update| update.object.data.clone())
            .unwrap_or_default();
        let mut visible = metadata.object.clone();
        visible.data = data;
        NinepVisibilityLookup::Object(visible)
    }
}

/// Small deterministic generator; the test needs reproducible coverage, not
/// statistical quality.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

const PATHS: [&str; 3] = ["/a", "/b", "/c"];
const EVENTS: [[u8; 32]; 2] = [[1; 32], [2; 32]];

fn random_update(
    rng: &mut SplitMix,
    key: NinepVisibilityUpdateKey,
    now: u64,
    writer_session: u64,
) -> NinepVisibilityUpdate {
    let path = PATHS[rng.below(PATHS.len() as u64) as usize];
    let version = rng.below(8) as u32;
    let object = if rng.chance(25) {
        deletion(path, version)
    } else {
        file(path, version, &[rng.below(256) as u8])
    };
    let scope = match rng.below(3) {
        0 => NinepVisibilityScope::Global,
        1 => NinepVisibilityScope::PerSession,
        _ => NinepVisibilityScope::WriterImmediate,
    };
    let data_lag_nanos = if rng.chance(50) { 0 } else { 1 + rng.below(3) };
    let release = match rng.below(3) {
        0 => NinepVisibilityRelease::AtTicks(now + rng.below(5_000)),
        1 => NinepVisibilityRelease::AtNanos(now / crucible_shmem::TICKS_PER_NS + rng.below(5)),
        _ => NinepVisibilityRelease::OnEvent(EVENTS[rng.below(EVENTS.len() as u64) as usize]),
    };
    NinepVisibilityUpdate {
        key,
        sequence: 0,
        object,
        policy: NinepVisibilityPolicy {
            scope,
            atomic_metadata_and_data: data_lag_nanos == 0,
            retain_deleted_objects: rng.chance(50),
        },
        release,
        writer_session,
        data_lag_nanos,
    }
}

fn assert_equivalent(
    state: &NinepVisibilityState,
    reference: &Reference,
    session: u64,
    context: &str,
) {
    assert_eq!(
        state.visible_frontier(session),
        reference.frontier(session),
        "{context}: frontier"
    );
    for path in PATHS {
        assert_eq!(
            state.lookup_object(session, path),
            reference.lookup(session, path),
            "{context}: lookup {path}"
        );
    }
}

#[test]
fn compacted_state_matches_the_uncompacted_reference() {
    let mut compacted_runs = 0;
    for seed in 0..256_u64 {
        let mut rng = SplitMix(seed);
        let mut state = NinepVisibilityState::default();
        let mut reference = Reference::default();
        let mut session = 0_u64;
        let mut now = 0_u64;
        let mut events = BTreeMap::new();
        let mut last_commit: Option<NinepVisibilityUpdate> = None;
        let mut generations = [0_u64; 4];

        for step in 0..300 {
            let context = format!("seed {seed} step {step}");
            match rng.below(100) {
                0..=39 => {
                    let slot = rng.below(generations.len() as u64) as usize;
                    generations[slot] += 1;
                    let update = random_update(
                        &mut rng,
                        key(slot as u8 + 1, generations[slot]),
                        now,
                        session,
                    );
                    let sequence = ok(state.commit(
                        update.key,
                        update.object.clone(),
                        update.policy,
                        update.release,
                        update.writer_session,
                        update.data_lag_nanos,
                    ));
                    assert_eq!(sequence, reference.commit(update.clone()), "{context}");
                    last_commit = Some(update);
                }
                40..=44 => {
                    // Recommitting the newest identity is idempotent whether or
                    // not its update has been compacted.
                    if let Some(update) = last_commit
                        .clone()
                        .filter(|update| update.writer_session == session)
                    {
                        let sequence = ok(state.commit(
                            update.key,
                            update.object.clone(),
                            update.policy,
                            update.release,
                            update.writer_session,
                            update.data_lag_nanos,
                        ));
                        assert_eq!(sequence, reference.commit(update), "{context}");
                    }
                }
                45..=84 => {
                    now += rng.below(3_000);
                    if rng.chance(30) {
                        events.insert(EVENTS[rng.below(EVENTS.len() as u64) as usize], now);
                    }
                    assert_eq!(
                        state.advance_visibility(session, now, &events),
                        reference.advance(session, now, &events),
                        "{context}: advance"
                    );
                }
                85..=94 => {
                    session += 1;
                    state.retire_sessions_except(session);
                }
                _ => {
                    assert_eq!(round_trip(&state), state, "{context}: round trip");
                }
            }

            ok(state.validate());
            assert!(state.object_version_count() <= reference.updates.len());
            assert_equivalent(&state, &reference, session, &context);

            // A session negotiated now must see what the reference shows it.
            let mut fresh = state.clone();
            let mut fresh_reference = Reference {
                updates: reference.updates.clone(),
                frontiers: BTreeMap::new(),
            };
            fresh.retire_sessions_except(session + 1);
            assert_eq!(
                fresh.advance_visibility(session + 1, now, &events),
                fresh_reference.advance(session + 1, now, &events),
                "{context}: fresh advance"
            );
            assert_equivalent(&fresh, &fresh_reference, session + 1, &context);
        }
        if state.compacted_frontier() > 0 {
            compacted_runs += 1;
        }
    }
    assert!(
        compacted_runs > 128,
        "compaction ran in {compacted_runs} runs"
    );
}
