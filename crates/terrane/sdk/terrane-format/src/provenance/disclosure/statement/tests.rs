//! Checks the actual disclosure serializer using ordinary borrowed field models.

#![allow(clippy::expect_used)]

use super::*;
use alloc::{format, string::String, vec};

#[derive(Clone)]
struct Model {
    proof: DisclosureProof,
    source: EntrySource,
    original: Digest,
    reference: String,
    destination: EntryLocation,
    domain: String,
    layout: usize,
    size: u64,
    object: Digest,
    target: Vec<u8>,
    binding: Digest,
    mode: u16,
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn opaque<const N: usize>(state: &mut u64) -> [u8; N] {
    core::array::from_fn(|_| next(state) as u8)
}

fn path(length: usize) -> Vec<u8> {
    if length == 4096 {
        let mut bytes = vec![b'p'; 4096];
        for index in (240..4096).step_by(241) {
            bytes[index] = b'/';
        }
        bytes
    } else {
        vec![b'p'; length]
    }
}

fn uint(value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_uint(&mut bytes, value);
    bytes
}

fn text(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_text(&mut bytes, value);
    bytes
}

fn bytes(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_bytes(&mut bytes, value);
    bytes
}

fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, values.len());
    for value in values {
        bytes.extend_from_slice(value);
    }
    bytes
}

fn actual(model: &Model) -> Vec<u8> {
    let kind = match model.layout {
        0 | 1 => EntryKind::File {
            mode: model.mode,
            size: model.size,
            content: if model.layout == 0 {
                ContentRef::Inline(model.object)
            } else {
                ContentRef::Manifest(model.object)
            },
            link_id: None,
        },
        2 => EntryKind::Directory { mode: model.mode },
        _ => EntryKind::Symlink {
            target: &model.target,
        },
    };
    encode_statement(StatementFields {
        proof: &model.proof,
        source: &model.source,
        original: model.original,
        reference: &model.reference,
        destination: &model.destination,
        target_domain: &model.domain,
        kind: &kind,
        binding: model.binding,
    })
    .expect("supported content projection")
}

/// Constructs the registered eight-slot projection independently of the writer.
fn expected(model: &Model) -> Vec<u8> {
    let content = match model.layout {
        0 | 1 => array(&[
            uint(1),
            uint(model.size),
            array(&[uint(model.layout as u64), bytes(&model.object)]),
        ]),
        2 => array(&[uint(2)]),
        _ => array(&[uint(3), bytes(&model.target)]),
    };
    let statement = array(&[
        text(&model.proof.authority_key),
        text(&model.proof.source_domain),
        uint(model.proof.observed_at),
        array(&[
            bytes(&model.source.commit),
            bytes(&model.source.root),
            bytes(&model.source.path),
        ]),
        bytes(&model.original),
        array(&[
            text(&model.reference),
            bytes(&model.destination.root),
            bytes(&model.destination.path),
            text(&model.domain),
        ]),
        content,
        bytes(&model.binding),
    ]);
    [b"terrane-disclosure-proof-v1\0".as_slice(), &statement].concat()
}

fn different_domain(domain: &str) -> String {
    if domain == "public" {
        "private:changed"
    } else {
        "public"
    }
    .into()
}

#[test]
fn disclosure_statement_models_retain_every_registered_field() {
    let mut state = 0xa791_365d_ef42_08c3;
    let numbers = [
        0,
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        u64::MAX - 1,
        u64::MAX,
    ];
    for case in 0..192 {
        let width = [1, 23, 255, 4096][case / 4 % 4];
        let model = Model {
            proof: DisclosureProof {
                authority_key: format!("{:064x}", next(&mut state)),
                source_domain: ["public", "tenant:source", "group:source", "private:source"]
                    [case % 4]
                    .into(),
                observed_at: numbers[case / 16],
                signature: opaque(&mut state),
            },
            source: EntrySource {
                commit: opaque(&mut state),
                root: opaque(&mut state),
                path: path(width),
            },
            original: opaque(&mut state),
            reference: format!("refs/heads/model-{}", next(&mut state)),
            destination: EntryLocation {
                commit: opaque(&mut state),
                root: opaque(&mut state),
                path: path(width),
            },
            domain: ["public", "tenant:target", "group:target", "private:target"][case / 4 % 4]
                .into(),
            layout: case % 4,
            size: numbers[case / 16],
            object: opaque(&mut state),
            target: vec![b'x'; [0, 23, 255, 4096][case / 4 % 4]],
            binding: opaque(&mut state),
            mode: next(&mut state) as u16,
        };

        let bytes = actual(&model);
        assert_eq!(bytes, expected(&model), "statement model {case}");
        let body = &bytes[b"terrane-disclosure-proof-v1\0".len()..];
        let mut decoder = Decoder::new(body);
        assert_eq!(decoder.array(8).expect("statement width"), 8);
        for _ in 0..8 {
            decoder
                .skip_value(body.len())
                .expect("canonical whole field");
        }
        decoder.finish().expect("whole canonical statement");

        let mut changed = model.clone();
        changed.proof.signature = opaque(&mut state);
        changed.destination.commit[0] ^= 1;
        changed.mode ^= 1;
        assert_eq!(
            actual(&changed),
            bytes,
            "only registered slots enter the statement"
        );

        let changes: [fn(&mut Model); 12] = [
            |model| {
                model.proof.authority_key = if model.proof.authority_key.starts_with('0') {
                    "f".repeat(64)
                } else {
                    "0".repeat(64)
                }
            },
            |model| model.proof.source_domain = different_domain(&model.proof.source_domain),
            |model| model.proof.observed_at ^= 1,
            |model| model.source.commit[0] ^= 1,
            |model| model.source.root[0] ^= 1,
            |model| model.source.path[0] ^= 1,
            |model| model.original[0] ^= 1,
            |model| model.reference.push_str("-changed"),
            |model| model.destination.root[0] ^= 1,
            |model| model.destination.path[0] ^= 1,
            |model| model.domain = different_domain(&model.domain),
            |model| model.binding[0] ^= 1,
        ];
        for change in changes {
            let mut changed = model.clone();
            change(&mut changed);
            assert_ne!(actual(&changed), bytes);
        }
        match model.layout {
            0 | 1 => {
                for field in 0..3 {
                    let mut changed = model.clone();
                    match field {
                        0 => changed.size ^= 1,
                        1 => changed.object[0] ^= 1,
                        _ => changed.layout ^= 1,
                    }
                    assert_ne!(actual(&changed), bytes);
                }
            }
            3 => {
                let mut changed = model.clone();
                if changed.target.is_empty() {
                    changed.target.push(b'x');
                } else {
                    changed.target[0] ^= 1;
                }
                assert_ne!(actual(&changed), bytes);
            }
            _ => {}
        }

        let unsupported = [
            EntryKind::Tree {
                root: model.object,
                props: None,
            },
            EntryKind::Whiteout,
            EntryKind::Conflict {
                candidates: vec![],
                base: None,
            },
            EntryKind::Index { targets: vec![] },
        ];
        for kind in unsupported {
            assert!(
                encode_statement(StatementFields {
                    proof: &model.proof,
                    source: &model.source,
                    original: model.original,
                    reference: &model.reference,
                    destination: &model.destination,
                    target_domain: &model.domain,
                    kind: &kind,
                    binding: model.binding,
                })
                .is_err()
            );
        }
    }
}
