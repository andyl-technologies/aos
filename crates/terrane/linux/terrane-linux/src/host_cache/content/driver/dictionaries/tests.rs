//! Checks dependency ordering, complete verification and finite lower-read bounds.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::{collections::BTreeMap, future::ready};
use terrane_format::codec::{EncodedChunk, encode_envelope};

const MAX_BYTES: usize = 65_536;

fn identity(plaintext: &[u8]) -> Identity {
    TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .unwrap()
}

fn raw(plaintext: &[u8]) -> Vec<u8> {
    encode_envelope(EncodedChunk {
        codec: Codec::Raw,
        body: plaintext,
    })
}

fn compressed(plaintext: &[u8], dictionary: Option<&[u8]>) -> Vec<u8> {
    let encoded = terrane_sdk::codec::encode_chunk(plaintext, MAX_BYTES, 3, dictionary).unwrap();
    assert_eq!(
        parse_envelope(&encoded).unwrap().codec,
        dictionary.map_or(Codec::Zstd, |bytes| {
            Codec::ZstdDictionary(identity(bytes).terrane_v1_digest().unwrap())
        }),
    );
    encoded
}

struct Chain {
    base: Vec<u8>,
    middle: Vec<u8>,
    content: Vec<u8>,
}

impl Chain {
    fn new() -> Self {
        Self {
            base: b"base dictionary vocabulary ".repeat(32),
            middle: b"base dictionary vocabulary for the selected content ".repeat(64),
            content: b"base dictionary vocabulary for the selected content and file ".repeat(128),
        }
    }

    fn bodies(&self, compressed_base: bool) -> BTreeMap<[u8; 32], Vec<u8>> {
        BTreeMap::from([
            (
                identity(&self.base).terrane_v1_digest().unwrap(),
                if compressed_base {
                    compressed(&self.base, None)
                } else {
                    raw(&self.base)
                },
            ),
            (
                identity(&self.middle).terrane_v1_digest().unwrap(),
                compressed(&self.middle, Some(&self.base)),
            ),
        ])
    }
}

#[tokio::test]
async fn terminal_content_never_fetches_a_dictionary() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let plaintext = b"ordinary terminal content ".repeat(128);

    for body in [raw(&plaintext), compressed(&plaintext, None)] {
        let mut fetched = 0;
        let resolved = resolve(&identity(&plaintext), &body, &profile, MAX_BYTES, 0, |_| {
            fetched += 1;
            ready(Err(StoreFailure::new(StoreErrorKind::ReadOnly)))
        })
        .await
        .unwrap();

        assert!(resolved.entries.is_empty());
        assert!(resolved.plaintext.is_none());
        assert_eq!(fetched, 0);
    }
}

#[tokio::test]
async fn nested_dictionaries_verify_from_terminal_to_requested_body() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let chain = Chain::new();
    let body = compressed(&chain.content, Some(&chain.middle));

    for compressed_base in [false, true] {
        let bodies = chain.bodies(compressed_base);
        let mut fetched = Vec::new();
        let resolved = resolve(
            &identity(&chain.content),
            &body,
            &profile,
            MAX_BYTES,
            2,
            |id| {
                fetched.push(id.clone());
                ready(Ok(bodies[&id.terrane_v1_digest().unwrap()].clone()))
            },
        )
        .await
        .unwrap();

        assert_eq!(fetched, [identity(&chain.middle), identity(&chain.base)]);
        assert_eq!(resolved.plaintext.as_deref(), Some(chain.middle.as_slice()));
        assert_eq!(
            resolved
                .entries
                .iter()
                .map(|row| &row.identity)
                .collect::<Vec<_>>(),
            [&identity(&chain.base), &identity(&chain.middle)],
        );
        for dictionary in &resolved.entries {
            assert_eq!(
                dictionary.encoded,
                bodies[&dictionary.identity.terrane_v1_digest().unwrap()]
            );
        }
        assert_eq!(
            terrane_sdk::codec::decode_verified(
                &body,
                chain.content.len(),
                &profile,
                true,
                &identity(&chain.content),
                resolved.plaintext.as_deref(),
            )
            .unwrap()
            .plaintext(),
            chain.content,
        );
    }
}

#[tokio::test]
async fn corrupt_terminal_prevents_returning_a_partial_chain() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let chain = Chain::new();
    let body = compressed(&chain.content, Some(&chain.middle));
    let mut bodies = chain.bodies(false);
    bodies.insert(
        identity(&chain.base).terrane_v1_digest().unwrap(),
        raw(b"different dictionary plaintext"),
    );

    let failure = resolve(
        &identity(&chain.content),
        &body,
        &profile,
        MAX_BYTES,
        2,
        |id| ready(Ok(bodies[&id.terrane_v1_digest().unwrap()].clone())),
    )
    .await
    .err()
    .expect("corrupt dictionary must reject the complete chain");

    assert!(matches!(failure.kind(), StoreErrorKind::Corrupt(_)));
}

#[tokio::test]
async fn missing_dependency_preserves_the_lower_failure() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let chain = Chain::new();
    let body = compressed(&chain.content, Some(&chain.middle));
    let mut fetched = Vec::new();

    let failure = resolve(
        &identity(&chain.content),
        &body,
        &profile,
        MAX_BYTES,
        2,
        |id| {
            fetched.push(id.clone());
            ready(Err(StoreFailure::new(StoreErrorKind::Absent(id))))
        },
    )
    .await
    .err()
    .expect("absent dependency must reject the complete chain");

    assert_eq!(fetched, [identity(&chain.middle)]);
    assert!(matches!(failure.kind(), StoreErrorKind::Absent(id) if *id == identity(&chain.middle)));
}

#[tokio::test]
async fn cycles_refuse_before_fetching_a_repeated_dependency() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let chain = Chain::new();
    let body = compressed(&chain.content, Some(&chain.middle));
    let middle = compressed(&chain.middle, Some(&chain.content));
    let mut fetched = Vec::new();

    let failure = resolve(
        &identity(&chain.content),
        &body,
        &profile,
        MAX_BYTES,
        8,
        |id| {
            fetched.push(id);
            ready(Ok(middle.clone()))
        },
    )
    .await
    .err()
    .expect("cyclic dictionary dependency must be rejected");

    assert_eq!(fetched, [identity(&chain.middle)]);
    assert!(matches!(failure.kind(), StoreErrorKind::Corrupt(_)));
}

#[tokio::test]
async fn dependency_count_and_encoded_and_plaintext_windows_are_bounded() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let chain = Chain::new();
    let body = compressed(&chain.content, Some(&chain.middle));
    let bodies = chain.bodies(false);

    for (max_bytes, max_entries, expected_fetches) in [
        (MAX_BYTES, 0, 0),
        (MAX_BYTES, 1, 1),
        (1, 2, 1),
        (chain.middle.len() - 1, 2, 1),
    ] {
        let mut fetched = Vec::new();
        let failure = resolve(
            &identity(&chain.content),
            &body,
            &profile,
            max_bytes,
            max_entries,
            |id| {
                fetched.push(id.clone());
                ready(Ok(bodies[&id.terrane_v1_digest().unwrap()].clone()))
            },
        )
        .await
        .err()
        .expect("operator limit must reject the complete chain");

        assert_eq!(fetched.len(), expected_fetches);
        assert!(matches!(failure.kind(), StoreErrorKind::Capacity));
    }
}
