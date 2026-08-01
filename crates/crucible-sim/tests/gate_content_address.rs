//! Implements `gate:content-address` over the L0 stable hashing primitive.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::Debug;

use crucible_sim::{StableDigest, StableHasher};

#[test]
fn gate_content_address_keeps_fixed_vectors_stable() {
    assert_eq!(
        [
            ("empty", hash_hex(stable_content_hash("empty", b""))),
            (
                "scenario-component",
                hash_hex(stable_content_hash(
                    "scenario-component",
                    b"nodes=node-a,node-b\nlink=a-b\nseed=42\n",
                )),
            ),
            (
                "snapshot",
                hash_hex(stable_content_hash(
                    "snapshot",
                    b"vm=node-a\npage=0001\nbytes=0011223344556677\n",
                )),
            ),
            (
                "log-segment",
                hash_hex(stable_content_hash(
                    "log-segment",
                    b"0 delivery node-a node-b 5\n1 rng node-a 9\n",
                )),
            ),
        ],
        expected_vectors([
            (
                "empty",
                "b321d09b948f4bf5fb5b5ec0ec971c04ad3c98a139d0b2558395ce5401342761"
            ),
            (
                "scenario-component",
                "2480f5a3620054ac15cc42f253c9706560d3022bc1ae5e9f48ce3ac5c1a45045",
            ),
            (
                "snapshot",
                "f9665c16a3ead10b1bb67a01b8a0bcb84267eb19c6e291baf66c46afe872d59a",
            ),
            (
                "log-segment",
                "11854a720b7fa94a23e705305fea78c3830077f3989b8337859c413d9bfeecd5",
            ),
        ])
    );
}

#[test]
fn gate_content_address_hashes_equal_content_to_equal_ids() {
    let first = assert_twice_reduce_canonical_digest(|| {
        Ok::<_, core::convert::Infallible>(stable_content_hash(
            "scenario-component",
            b"nodes=node-a,node-b\nlink=a-b\nseed=7\n",
        ))
    });
    let second = assert_twice_reduce_canonical_digest(|| {
        Ok::<_, core::convert::Infallible>(stable_content_hash(
            "scenario-component",
            b"nodes=node-a,node-b\nlink=a-b\nseed=7\n",
        ))
    });

    assert_eq!(first, second);
}

#[test]
fn gate_content_address_changes_on_single_byte_mutations() {
    assert_ne!(
        stable_content_hash("scenario-component", b"seed=1"),
        stable_content_hash("scenario-component", b"seed=2")
    );
    assert_ne!(
        stable_content_hash("snapshot", b"page=A"),
        stable_content_hash("snapshot", b"page=B")
    );
    assert_ne!(
        stable_content_hash("log-segment", b"event=deliver"),
        stable_content_hash("log-segment", b"event=delives")
    );
    assert_ne!(
        stable_content_hash("schedule-delta", b"rng stream=a value=1"),
        stable_content_hash("schedule-delta", b"rng stream=a value=2")
    );
}

#[test]
fn gate_content_address_separates_domains_and_ordering() {
    assert_ne!(
        stable_content_hash("snapshot", b"same bytes"),
        stable_content_hash("log-segment", b"same bytes")
    );

    let first = ordered_digest(&[b"alpha".as_slice(), b"beta".as_slice()]);
    let second = ordered_digest(&[b"beta".as_slice(), b"alpha".as_slice()]);
    assert_ne!(first, second);
}

#[test]
fn gate_content_address_collision_corpus_has_unique_ids() {
    let mut seen = BTreeSet::new();

    for index in 0..512_u64 {
        let material = format!(
            "kind=sim-corpus\nindex={index}\nentity=node-{}\nseed={}\n",
            index % 19,
            index.wrapping_mul(0xd6e8_feb8_6659_fd93)
        );
        let id = stable_content_hash("sim-corpus", material.as_bytes());
        assert!(
            seen.insert(id.bytes),
            "duplicate stable digest for corpus index {index}"
        );
    }
}

fn assert_twice_reduce_canonical_digest<T, E, F>(mut reduce: F) -> T
where
    T: Debug + PartialEq,
    E: Debug,
    F: FnMut() -> Result<T, E>,
{
    let first = match reduce() {
        Ok(value) => value,
        Err(error) => panic!("first reduction failed: {error:?}"),
    };
    let second = match reduce() {
        Ok(value) => value,
        Err(error) => panic!("second reduction failed: {error:?}"),
    };
    assert_eq!(first, second);
    first
}

fn stable_content_hash(domain: &str, bytes: &[u8]) -> StableDigest {
    let mut hasher = StableHasher::new();
    hasher.write_tag("crucible-sim.content-address.v1");
    hasher.write_bytes(domain.as_bytes());
    hasher.write_bytes(bytes);
    hasher.finish()
}

fn ordered_digest(parts: &[&[u8]]) -> StableDigest {
    let mut hasher = StableHasher::new();
    hasher.write_tag("crucible-sim.content-address.ordered.v1");
    hasher.write_u64(parts.len() as u64);
    for part in parts {
        hasher.write_bytes(part);
    }
    hasher.finish()
}

fn expected_vectors(vectors: [(&'static str, &'static str); 4]) -> [(&'static str, String); 4] {
    vectors.map(|(name, hash)| (name, hash.to_owned()))
}

fn hash_hex(hash: StableDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(hash.bytes.len() * 2);
    for byte in hash.bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
