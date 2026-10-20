//! Checks streamed claim verification and preservation of partial-output failures.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::collections::BTreeMap;
use terrane_format::{
    chunking::ChunkProfile,
    identity::Descriptor,
    manifest::{ChunkRef, Manifest},
};

fn manifest_claim(wrong_whole_hash: bool) -> (PublicationClaim, Vec<u8>, usize) {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let boundary = profile.minimum();
    let mut plaintext = vec![7; boundary];
    plaintext.extend_from_slice(&[9; 31]);
    let chunks = [&plaintext[..boundary], &plaintext[boundary..]]
        .into_iter()
        .map(|bytes| ChunkRef {
            digest: TERRANE_V1
                .calculate(IdentityKind::Chunk, bytes)
                .unwrap()
                .terrane_v1_digest()
                .unwrap(),
            length: bytes.len() as u64,
        })
        .collect();
    let digest = if wrong_whole_hash {
        blake3::hash(b"another whole file")
    } else {
        blake3::hash(&plaintext)
    };
    let canonical_manifest = Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes: BTreeMap::from([("blake3".into(), digest.as_bytes().to_vec())]),
        media_type: None,
    }
    .encode(&profile)
    .unwrap();
    let identity = TERRANE_V1
        .calculate(IdentityKind::Manifest, &canonical_manifest)
        .unwrap();
    let object = Descriptor::from_identity(&TERRANE_V1, &identity, &canonical_manifest).unwrap();
    let claim = PublicationClaim::new(
        "tenant:streamed-assembly".into(),
        PublicationRecipe::Manifest {
            object,
            canonical_manifest,
        },
        &profile,
    )
    .unwrap();
    (claim, plaintext, boundary)
}

struct ShortWriter {
    bytes: Vec<u8>,
    fail_after: Option<usize>,
}

impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self
            .fail_after
            .map_or(usize::MAX, |limit| limit.saturating_sub(self.bytes.len()));
        if remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "fixture quota"));
        }
        let count = bytes.len().min(3).min(remaining);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("streaming verification must leave synchronization to the owner")
    }
}

#[test]
fn streamed_manifest_handles_short_writes_without_collecting_an_output_buffer() {
    let (claim, plaintext, _) = manifest_claim(false);
    let mut source = Cursor::new(&plaintext);
    let mut output = ShortWriter {
        bytes: Vec::new(),
        fail_after: None,
    };

    let copied = copy_claim(&claim, &mut source, &mut output).unwrap();

    assert_eq!(copied, plaintext.len() as u64);
    assert_eq!(output.bytes, plaintext);
    assert_eq!(source.position(), copied);
}

#[test]
fn streamed_manifest_rejects_wrong_whole_hash_after_valid_ordered_chunks() {
    let (claim, plaintext, _) = manifest_claim(true);
    let mut output = Vec::new();

    let error = copy_claim(&claim, &mut Cursor::new(&plaintext), &mut output).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(output, plaintext);
}

#[test]
fn streamed_manifest_refuses_truncated_trailing_reordered_and_modified_input() {
    let (claim, plaintext, boundary) = manifest_claim(false);
    let truncated = plaintext[..plaintext.len() - 1].to_vec();
    let mut trailing = plaintext.clone();
    trailing.push(0);
    let reordered = [&plaintext[boundary..], &plaintext[..boundary]].concat();
    let mut modified = plaintext;
    modified[boundary] ^= 1;

    for (name, bytes, expected) in [
        ("truncated", truncated, io::ErrorKind::UnexpectedEof),
        ("trailing", trailing, io::ErrorKind::InvalidData),
        ("reordered", reordered, io::ErrorKind::InvalidData),
        ("modified", modified, io::ErrorKind::InvalidData),
    ] {
        let mut output = Vec::new();

        let error = copy_claim(&claim, &mut Cursor::new(bytes), &mut output).unwrap_err();

        assert_eq!(error.kind(), expected, "{name}");
    }
}

#[test]
fn streamed_manifest_preserves_write_failure_and_original_partial_output() {
    let (claim, plaintext, _) = manifest_claim(false);
    let mut output = ShortWriter {
        bytes: Vec::new(),
        fail_after: Some(17),
    };

    let error = copy_claim(&claim, &mut Cursor::new(&plaintext), &mut output).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert_eq!(output.bytes, plaintext[..17]);
}
