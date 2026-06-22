//! Checks deterministic decision-stream forking and draws.

#![forbid(unsafe_code)]

use crucible_sim::{
    DECISION_RNG_ALGORITHM, DECISION_RNG_NAME_HASH_DOMAIN, DecisionRng, stable_name_hash,
};

#[test]
fn decision_rng_forks_by_seed_xor_stable_name_hash() {
    let rng = DecisionRng::new(0x0123_4567_89ab_cdef);
    let expected = 0x0123_4567_89ab_cdef ^ stable_name_hash("node-a/faults");

    assert_eq!(rng.stream_seed("node-a/faults"), expected);
    assert_eq!(
        DECISION_RNG_NAME_HASH_DOMAIN,
        "crucible.decision-rng.name-hash.v1"
    );
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
fn decision_rng_uses_fixed_cross_platform_algorithm() {
    let mut stream = DecisionRng::new(0).fork("known-vector");

    assert_eq!(DECISION_RNG_ALGORITHM, "splitmix64-v1");
    assert_eq!(stream.next_u64(), 0xfe32_417a_273f_d586);
    assert_eq!(stream.next_u64(), 0x44bf_2b53_3f3e_07fd);
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
