//! Checks the keyed decision-stream derivation and its draws.

#![forbid(unsafe_code)]

use crucible_sim::{
    DECISION_RNG_ALGORITHM, DECISION_RNG_LEGACY_ALGORITHM, DECISION_RNG_LINK_STREAM_DOMAIN,
    DECISION_RNG_NAME_HASH_DOMAIN, DECISION_RNG_NODE_STREAM_DOMAIN, DECISION_RNG_WORLD_KEY_CONTEXT,
    DecisionRng,
};

/// Recomputes one draw straight from the published derivation, independent of
/// [`DecisionRng`], so the golden vectors pin the specification rather than the
/// implementation's internal structure.
fn reference_draw(root: u64, domain: &str, name: &str, event: Option<&[u8]>, index: u64) -> u64 {
    fn length_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    let world_key = blake3::derive_key(DECISION_RNG_WORLD_KEY_CONTEXT, &root.to_le_bytes());
    let mut stream = blake3::Hasher::new_keyed(&world_key);
    length_prefixed(&mut stream, b"stream");
    length_prefixed(&mut stream, domain.as_bytes());
    length_prefixed(&mut stream, name.as_bytes());
    let stream_key = *stream.finalize().as_bytes();

    let mut draw = blake3::Hasher::new_keyed(&stream_key);
    match event {
        None => length_prefixed(&mut draw, b"counter"),
        Some(event) => {
            length_prefixed(&mut draw, b"event");
            length_prefixed(&mut draw, event);
        }
    }
    draw.update(&index.to_le_bytes());
    let mut low = [0; 8];
    low.copy_from_slice(&draw.finalize().as_bytes()[..8]);
    u64::from_le_bytes(low)
}

#[test]
fn decision_rng_names_the_keyed_algorithm_and_refused_legacy() {
    assert_eq!(DECISION_RNG_ALGORITHM, "keyed-blake3-v2");
    assert_eq!(DECISION_RNG_LEGACY_ALGORITHM, "splitmix64-v1");
    assert_eq!(
        DECISION_RNG_WORLD_KEY_CONTEXT,
        "crucible decision-rng keyed-blake3-v2 world-key"
    );
    assert_eq!(
        DECISION_RNG_NAME_HASH_DOMAIN,
        "crucible.decision-rng.name-hash.v1"
    );
}

#[test]
fn decision_rng_matches_the_published_derivation() {
    let rng = DecisionRng::new(0x0123_4567_89ab_cdef);
    let mut counter = rng.fork_for_node("node-a");
    let mut event = rng.event_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, "a-b", b"frame-7");

    for index in 0..4 {
        assert_eq!(
            counter.next_u64(),
            reference_draw(
                0x0123_4567_89ab_cdef,
                DECISION_RNG_NODE_STREAM_DOMAIN,
                "node-a",
                None,
                index
            )
        );
        assert_eq!(
            event.next_u64(),
            reference_draw(
                0x0123_4567_89ab_cdef,
                DECISION_RNG_LINK_STREAM_DOMAIN,
                "a-b",
                Some(b"frame-7"),
                index
            )
        );
    }
}

#[test]
fn decision_rng_keeps_fixed_cross_platform_vectors() {
    let mut stream = DecisionRng::new(0).fork("known-vector");
    let mut node = DecisionRng::new(0x0123_4567_89ab_cdef).fork_for_node("shared-name");
    let mut link = DecisionRng::new(0x0123_4567_89ab_cdef).fork_for_link("shared-name");
    let mut frame = DecisionRng::new(0x0123_4567_89ab_cdef).event_in_domain(
        DECISION_RNG_LINK_STREAM_DOMAIN,
        "shared-name",
        &[1, 7, 0, 0, 0, 0, 0, 0, 0],
    );

    assert_eq!(stream.next_u64(), 0x1e76_8e32_8b90_978a);
    assert_eq!(stream.next_u64(), 0x7227_aa57_219e_8e38);
    assert_eq!(node.next_u64(), 0x4730_462d_9ff3_7498);
    assert_eq!(link.next_u64(), 0xc141_85a0_d5bb_4fc3);
    assert_eq!(frame.next_u64(), 0x7f59_57b6_03c6_dd21);
    assert_eq!(frame.next_u64(), 0xfefd_d347_3c20_7ef6);
}

#[test]
fn decision_rng_streams_are_independent_of_construction_order() {
    let rng = DecisionRng::new(0x0010_c001);

    let mut before = rng.fork("node-a");
    let _other = rng.fork("node-b");
    let mut after = rng.fork("node-a");

    assert_eq!(before.next_u64(), after.next_u64());
    assert_eq!(before.next_u64(), after.next_u64());
}

#[test]
fn decision_rng_event_draws_are_independent_of_draw_order() {
    let rng = DecisionRng::new(0x0010_c001);
    let frames: [&[u8]; 3] = [b"a-to-b/1", b"b-to-a/1", b"a-to-b/2"];

    let forward = frames
        .iter()
        .map(|frame| {
            let mut draws = rng.event_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, "a-b", frame);
            (draws.next_u64(), draws.next_u64())
        })
        .collect::<Vec<_>>();
    let mut reversed = frames
        .iter()
        .rev()
        .map(|frame| {
            let mut draws = rng.event_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, "a-b", frame);
            (draws.next_u64(), draws.next_u64())
        })
        .collect::<Vec<_>>();
    reversed.reverse();

    assert_eq!(forward, reversed);
    assert_ne!(forward[0], forward[1]);
    assert_ne!(forward[0], forward[2]);
}

#[test]
fn decision_rng_streams_change_with_name_and_seed() {
    let mut node_a = DecisionRng::new(7).fork("node-a");
    let mut node_b = DecisionRng::new(7).fork("node-b");
    let mut other_seed = DecisionRng::new(8).fork("node-a");

    assert_ne!(node_a.seed(), node_b.seed());
    assert_ne!(node_a.seed(), other_seed.seed());
    assert_ne!(node_a.next_u64(), node_b.next_u64());
    assert_ne!(
        DecisionRng::new(7).fork("node-a").next_u64(),
        other_seed.next_u64()
    );
}

#[test]
fn decision_rng_domain_separates_node_and_link_streams() {
    let rng = DecisionRng::new(0x0123_4567_89ab_cdef);
    let name = "shared-name";

    assert_ne!(
        rng.stream_seed_in_domain(DECISION_RNG_NODE_STREAM_DOMAIN, name),
        rng.stream_seed_in_domain(DECISION_RNG_LINK_STREAM_DOMAIN, name)
    );
    assert_ne!(
        rng.fork_for_node(name).next_u64(),
        rng.fork_for_link(name).next_u64()
    );
}

#[test]
fn decision_rng_length_prefixes_keep_adjacent_fields_apart() {
    let rng = DecisionRng::new(0x0123_4567_89ab_cdef);

    assert_ne!(
        rng.fork_in_domain("ab", "c").next_u64(),
        rng.fork_in_domain("a", "bc").next_u64()
    );
    assert_ne!(
        rng.event_in_domain("d", "s", b"xy").next_u64(),
        rng.event_in_domain("d", "s", b"x").next_u64()
    );
}
