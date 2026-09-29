//! Checks canonical manifest identity, strict decoding, and inline selection.

use super::*;
use alloc::{string::ToString, vec};

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid fixture"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn fixture() -> Manifest {
    Manifest {
        size: 300_000,
        chunks: vec![
            ChunkRef {
                digest: hex("5860ee5a4a84d54950c417a0636b35e6e3fbbc1d52f8cf9efb810f0031278d67")
                    .try_into()
                    .expect("digest"),
                length: 262_144,
            },
            ChunkRef {
                digest: hex("39e1233664267460cfc8a61ceaff03ed99aa78475f4f5cb17ce2a2181c7b8746")
                    .try_into()
                    .expect("digest"),
                length: 37_856,
            },
        ],
        hashes: BTreeMap::from([
            (
                "blake3".to_string(),
                hex("6cc9dce05d4cff8c5bef5c5a24681e42b13f03e34a0bc5e66f65a91d48c944fa"),
            ),
            (
                "sha256".to_string(),
                hex("3c65ea93424a9c362fec0e3a69ea36031e8a358441479dd665cc6110eabe7b08"),
            ),
        ]),
        media_type: None,
    }
}

#[test]
fn golden_manifest_identity_requires_no_plaintext() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let manifest = fixture();
    let bytes = manifest.encode(&profile).expect("encoding");
    assert_eq!(bytes.len(), 171);
    assert_eq!(
        manifest
            .identity(&profile)
            .expect("identity")
            .terrane_v1_digest()
            .expect("digest")
            .as_slice(),
        hex("012fb6dded774e62a96a38b832da9f2f8f7eb5caa5dddefd2b405a4602b53e0c")
    );
    assert_eq!(
        Manifest::decode_verified(
            &bytes,
            &profile,
            &manifest.identity(&profile).expect("identity")
        )
        .expect("decode"),
        manifest
    );
}

#[test]
fn rejects_invalid_lengths_hashes_and_noncanonical_input() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let mut manifest = fixture();
    manifest.size += 1;
    assert!(manifest.encode(&profile).is_err());
    manifest = fixture();
    manifest.hashes.remove("blake3");
    assert!(manifest.encode(&profile).is_err());
    manifest = fixture();
    manifest.chunks[0].length = 1;
    manifest.size = 37_857;
    assert!(manifest.encode(&profile).is_err());
    let mut bytes = fixture().encode(&profile).expect("encoding");
    bytes.push(0);
    assert!(Manifest::decode(&bytes, &profile).is_err());
    assert!(
        Manifest::decode(
            &[
                0xa3, 1, 0, 2, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ],
            &profile
        )
        .is_err()
    );
}

#[test]
fn preserves_registered_hashes_media_and_chunk_order() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let mut manifest = fixture();
    manifest.media_type = Some("unknown/custom".to_string());
    manifest.hashes.insert("sha512".to_string(), vec![8; 64]);
    manifest
        .hashes
        .insert("git-blob-sha1".to_string(), vec![9; 20]);
    assert_eq!(
        Manifest::decode(&manifest.encode(&profile).expect("encoding"), &profile).expect("decode"),
        manifest
    );
    let identity = manifest.identity(&profile).expect("identity");
    manifest.chunks[1].length = 262_144;
    manifest.size = 524_288;
    let before = manifest.identity(&profile).expect("identity");
    manifest.chunks.reverse();
    assert_ne!(manifest.identity(&profile).expect("identity"), before);
    assert_ne!(before, identity);
}

#[test]
fn small_files_are_inline_including_empty_and_threshold() {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    for size in [0, 1, profile.minimum() as u64] {
        let mut manifest = fixture();
        manifest.size = size;
        manifest.chunks = vec![ChunkRef {
            digest: [7; 32],
            length: size,
        }];
        assert_eq!(
            manifest.content_ref(&profile).expect("reference"),
            ContentRef::Inline([7; 32])
        );
    }
    assert!(matches!(
        fixture().content_ref(&profile).expect("reference"),
        ContentRef::Manifest(_)
    ));
}
