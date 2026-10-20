//! Compares inert envelope and merged-shard fields with the owning core codecs.
//!
//! TEST-1/2/3 witnesses cover CDC-7/9 envelope fields and PACK-17..20 shard
//! format only. Native decompression, admission, publication and state effects
//! remain outside these format comparisons. Embedded shard hashes are opaque.
//!
//! ```text
//! envelope = codec:u8 | dictionary:32 (codec 2 only) | body
//! shard = TRIX | count:u64le | (hash:32, pack:16, offset:u64le,
//!         body_len:u32le, plaintext_len:u32le, codec:u8, kind:u8,
//!         state:u8, reserved:5)*
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "independent reference fixture failures intentionally panic"
)]

use terrane_format::{
    codec::{Codec, EncodedChunk, encode_envelope, parse_envelope, validate_envelope_size},
    identity::{IdentityKind, TERRANE_V1},
    pack_format::{MergedRecord, Record, decode_shard, encode_shard},
};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../tests/terrane/container-reference.md"
));
const PLAINTEXT: &[u8] = b"inert\n";
const DICTIONARY: &[u8] = b"terrane inert dictionary\n";
const PREFIX: u8 = 0xab;
const PROFILE_MAXIMUM: usize = 4_194_304;

fn hexadecimal(name: &str, block: usize) -> Vec<u8> {
    let marker = format!("### container-{name}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1);
    let section = REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n##")
        .next()
        .unwrap();
    let raw = section
        .split("```hex\n")
        .nth(block + 1)
        .unwrap()
        .split_once("```")
        .unwrap()
        .0;
    let digits: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digits.len() % 2, 0);

    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

fn raw_chunk_digest(plaintext: &[u8]) -> [u8; 32] {
    let mut preimage = b"terrane-chunk-v1\0".to_vec();
    preimage.extend_from_slice(plaintext);
    *blake3::hash(&preimage).as_bytes()
}

// This constructor uses RFC 8878's raw blocks, independently of any codec.
// Every frame is single segment, has a one-byte content size and ends in
// exactly one last raw block. Empty preceding blocks exercise size bounds.
fn frame(plaintext: &[u8], empty_blocks: usize) -> Vec<u8> {
    let mut body = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20];
    body.push(u8::try_from(plaintext.len()).unwrap());
    body.resize(body.len() + empty_blocks * 3, 0);
    let block = (u32::try_from(plaintext.len()).unwrap() << 3) | 1;
    body.extend_from_slice(&block.to_le_bytes()[..3]);
    body.extend_from_slice(plaintext);
    body
}

struct EnvelopeModel {
    label: String,
    plaintext: Vec<u8>,
    codec: Codec,
    body: Vec<u8>,
    maximum: usize,
}

fn envelopes() -> Vec<EnvelopeModel> {
    let dictionary = raw_chunk_digest(DICTIONARY);
    let mut models = vec![];
    for (label, codec) in [
        ("raw", Codec::Raw),
        ("zstd", Codec::Zstd),
        ("dictionary", Codec::ZstdDictionary(dictionary)),
    ] {
        for (suffix, plaintext) in [("empty", &b""[..]), ("plain", PLAINTEXT)] {
            models.push(EnvelopeModel {
                label: format!("envelope-{label}-{suffix}"),
                plaintext: plaintext.to_vec(),
                codec,
                body: if codec == Codec::Raw {
                    plaintext.to_vec()
                } else {
                    frame(plaintext, 0)
                },
                maximum: PROFILE_MAXIMUM,
            });
        }
    }
    for (label, codec, empty_blocks) in [
        ("zstd", Codec::Zstd, 40),
        ("dictionary", Codec::ZstdDictionary(dictionary), 29),
    ] {
        let plaintext = vec![b'q'; 100];
        models.push(EnvelopeModel {
            label: format!("envelope-{label}-overhead-control"),
            body: frame(&plaintext, empty_blocks),
            plaintext,
            codec,
            // A local structural oracle exercises the exact overhead bound;
            // this 100-byte maximum does not denote a registered profile.
            maximum: 100,
        });
    }
    assert_eq!(models.len(), 8);
    models
}

#[test]
fn reference_chunk_envelope_models_preserve_codec_body_and_dictionary_fields() {
    for model in envelopes() {
        let expected = hexadecimal(&model.label, 0);
        let chunk = EncodedChunk {
            codec: model.codec,
            body: &model.body,
        };
        assert_eq!(encode_envelope(chunk), expected, "{}", model.label);
        let decoded = parse_envelope(&expected).unwrap();
        assert_eq!(decoded, chunk, "{}", model.label);
        assert_eq!(encode_envelope(decoded), expected, "{}", model.label);
        assert_eq!(
            validate_envelope_size(decoded, model.plaintext.len(), model.maximum),
            Ok(()),
            "{}",
            model.label
        );

        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, &model.plaintext)
            .unwrap();
        assert_eq!(identity.digest(), hexadecimal(&model.label, 1));
        assert_eq!(identity.digest(), raw_chunk_digest(&model.plaintext));
        if let Codec::ZstdDictionary(dictionary) = decoded.codec {
            assert!(DICTIONARY.len() <= model.maximum);
            let expected_dictionary = TERRANE_V1
                .calculate(IdentityKind::Chunk, DICTIONARY)
                .unwrap();
            assert_eq!(dictionary, expected_dictionary.digest());
            assert_ne!(dictionary, identity.digest());
        }
    }

    // The same complete plaintext has one identity across all codec envelopes;
    // no immutable-content identity is assigned to the envelope itself.
    for suffix in ["empty", "plain"] {
        let raw = format!("envelope-raw-{suffix}");
        for label in ["zstd", "dictionary"] {
            let compressed = format!("envelope-{label}-{suffix}");
            assert_ne!(hexadecimal(&raw, 0), hexadecimal(&compressed, 0));
            assert_eq!(hexadecimal(&raw, 1), hexadecimal(&compressed, 1));
        }
    }
}

fn row(ordinal: u8, kind: u8, codec: u8, state: u8) -> MergedRecord {
    let mut hash = [ordinal; 32];
    hash[0] = PREFIX;
    let plaintext_len = 10 + u32::from(kind);
    let body_len = if kind == 0 {
        [11, 20, 52][usize::from(codec)]
    } else {
        plaintext_len
    };
    MergedRecord {
        pack: [0x40 + ordinal; 16],
        record: Record {
            hash,
            offset: 0x0102_0304_0506_0708 + u64::from(ordinal),
            body_len,
            plaintext_len,
            codec,
            kind,
            dictionary_id: 0,
        },
        state,
    }
}

fn shards() -> Vec<(String, Vec<MergedRecord>)> {
    let mut models = vec![("shard-empty".into(), vec![])];
    let mut ordered = vec![];
    for kind in 0..10 {
        let codecs: &[u8] = if kind == 0 { &[0, 1, 2] } else { &[0] };
        for &codec in codecs {
            for state in 0..3 {
                let ordinal = u8::try_from(ordered.len() + 1).unwrap();
                let mut record = row(ordinal, kind, codec, state);
                if kind == 0 && codec == 2 {
                    record.record.body_len = 0x0102_0304;
                    record.record.plaintext_len = 0x0506_0708;
                }
                models.push((
                    format!("shard-kind-{kind}-codec-{codec}-state-{state}"),
                    vec![record.clone()],
                ));
                ordered.push(record);
            }
        }
    }
    assert_eq!(ordered.len(), 36);
    models.push(("shard-all-ordered".into(), ordered));
    assert_eq!(models.len(), 38);
    models
}

#[test]
fn reference_merged_shard_models_preserve_record_fields_and_states() {
    for (label, model) in shards() {
        let expected = hexadecimal(&label, 0);
        let expected_digest = hexadecimal(&label, 1);

        assert_eq!(encode_shard(&model), expected, "{label}");
        let decoded = decode_shard(&expected, PREFIX).unwrap();
        assert_eq!(decoded, model, "{label}");
        assert_eq!(encode_shard(&decoded), expected, "{label}");
        let identity = TERRANE_V1
            .calculate(IdentityKind::Index, &expected)
            .unwrap();
        assert_eq!(identity.digest(), expected_digest, "{label}");
        assert_ne!(
            identity,
            TERRANE_V1
                .calculate(IdentityKind::Chunk, &expected)
                .unwrap(),
            "registered identity kinds retain distinct domains"
        );
    }
}

// Malformed fixtures bypass encode_shard and encode_envelope. The primitive
// writer retains invalid fields and framing, without assigning an identity.
fn primitive_shard(records: &[(MergedRecord, [u8; 5])], count: u64, magic: &[u8; 4]) -> Vec<u8> {
    let mut wire = magic.to_vec();
    wire.extend_from_slice(&count.to_le_bytes());
    for (entry, reserved) in records {
        wire.extend_from_slice(&entry.record.hash);
        wire.extend_from_slice(&entry.pack);
        wire.extend_from_slice(&entry.record.offset.to_le_bytes());
        wire.extend_from_slice(&entry.record.body_len.to_le_bytes());
        wire.extend_from_slice(&entry.record.plaintext_len.to_le_bytes());
        wire.extend_from_slice(&[entry.record.codec, entry.record.kind, entry.state]);
        wire.extend_from_slice(reserved);
    }
    wire
}

struct NegativeEnvelope {
    label: String,
    wire: Vec<u8>,
    limits: Option<(usize, usize)>,
}

fn negative_envelopes() -> Vec<NegativeEnvelope> {
    let mut models = vec![];
    for (label, wire) in [
        ("missing-tag", vec![]),
        ("tag-three", vec![3]),
        ("tag-255", vec![255]),
        ("dictionary-absent", vec![2]),
        ("dictionary-short", [vec![2], vec![0; 31]].concat()),
    ] {
        models.push(NegativeEnvelope {
            label: format!("envelope-{label}"),
            wire,
            limits: None,
        });
    }
    for (label, declared) in [("short", 5), ("long", 7)] {
        let mut wire = vec![0];
        wire.extend_from_slice(PLAINTEXT);
        models.push(NegativeEnvelope {
            label: format!("envelope-raw-declaration-{label}"),
            wire,
            limits: Some((declared, 7)),
        });
    }
    for (tag, label) in [(0, "raw"), (1, "zstd"), (2, "dictionary")] {
        let mut wire = vec![tag];
        if tag == 2 {
            wire.extend(0..32);
        }
        wire.extend_from_slice(&if tag == 0 {
            PLAINTEXT.to_vec()
        } else {
            frame(PLAINTEXT, 0)
        });
        models.push(NegativeEnvelope {
            label: format!("envelope-{label}-profile-maximum"),
            wire,
            limits: Some((6, 5)),
        });
    }
    for (tag, label, empty_blocks) in [(1, "zstd", 41), (2, "dictionary", 30)] {
        let mut wire = vec![tag];
        if tag == 2 {
            wire.extend(0..32);
        }
        wire.extend_from_slice(&frame(&[b'q'; 100], empty_blocks));
        models.push(NegativeEnvelope {
            label: format!("envelope-{label}-overhead-excess"),
            wire,
            limits: Some((100, 100)),
        });
    }
    assert_eq!(models.len(), 12);
    models
}

fn negative_shards() -> Vec<(String, Vec<u8>, u8)> {
    let mut models = vec![];
    let base = row(1, 0, 0, 0);
    for label in [
        "state-three",
        "state-255",
        "kind-ten",
        "kind-255",
        "codec-three",
        "codec-255",
        "offset-before-header",
        "zero-body",
        "raw-length",
    ] {
        let mut entry = base.clone();
        match label {
            "state-three" => entry.state = 3,
            "state-255" => entry.state = 255,
            "kind-ten" => entry.record.kind = 10,
            "kind-255" => entry.record.kind = 255,
            "codec-three" => entry.record.codec = 3,
            "codec-255" => entry.record.codec = 255,
            "offset-before-header" => entry.record.offset = 23,
            "zero-body" => entry.record.body_len = 0,
            "raw-length" => entry.record.plaintext_len = 9,
            _ => unreachable!("all mutation labels are listed"),
        }
        models.push((
            format!("shard-{label}"),
            primitive_shard(&[(entry, [0; 5])], 1, b"TRIX"),
            PREFIX,
        ));
    }
    for codec in [1, 2] {
        models.push((
            format!("shard-meta-codec-{codec}"),
            primitive_shard(&[(row(1, 1, codec, 0), [0; 5])], 1, b"TRIX"),
            PREFIX,
        ));
    }
    let mut meta = row(1, 1, 0, 0);
    meta.record.body_len += 1;
    models.push((
        "shard-meta-raw-length".into(),
        primitive_shard(&[(meta, [0; 5])], 1, b"TRIX"),
        PREFIX,
    ));
    for offset in 0..5 {
        let mut reserved = [0; 5];
        reserved[offset] = 1;
        models.push((
            format!("shard-reserved-{offset}"),
            primitive_shard(&[(base.clone(), reserved)], 1, b"TRIX"),
            PREFIX,
        ));
    }
    let valid = primitive_shard(&[(base.clone(), [0; 5])], 1, b"TRIX");
    models.push(("shard-wrong-prefix".into(), valid.clone(), PREFIX + 1));
    let other = row(2, 1, 0, 1);
    let mut duplicate = other.clone();
    duplicate.record.hash = base.record.hash;
    models.push((
        "shard-duplicate".into(),
        primitive_shard(&[(base.clone(), [0; 5]), (duplicate, [0; 5])], 2, b"TRIX"),
        PREFIX,
    ));
    models.push((
        "shard-descending".into(),
        primitive_shard(&[(other, [0; 5]), (base.clone(), [0; 5])], 2, b"TRIX"),
        PREFIX,
    ));
    for count in [0, 2, u64::MAX] {
        models.push((
            format!("shard-count-{count}"),
            primitive_shard(&[(base.clone(), [0; 5])], count, b"TRIX"),
            PREFIX,
        ));
    }
    models.push((
        "shard-bad-magic".into(),
        primitive_shard(&[(base, [0; 5])], 1, b"BAD!"),
        PREFIX,
    ));
    let mut preamble = b"TRIX".to_vec();
    preamble.extend_from_slice(&[0; 7]);
    models.push(("shard-short-preamble".into(), preamble, PREFIX));
    let mut truncated = valid.clone();
    truncated.pop();
    models.push(("shard-short-record".into(), truncated, PREFIX));
    let mut trailing = valid;
    trailing.push(0);
    models.push(("shard-trailing-byte".into(), trailing, PREFIX));
    assert_eq!(models.len(), 27);
    models
}

#[test]
fn reference_negative_container_wires_require_structural_rejection() {
    for model in negative_envelopes() {
        let expected = hexadecimal(&format!("negative-{}", model.label), 0);
        assert_eq!(model.wire, expected, "{}", model.label);

        if let Some((declared, maximum)) = model.limits {
            let chunk = parse_envelope(&expected).unwrap();
            assert!(
                validate_envelope_size(chunk, declared, maximum).is_err(),
                "{}",
                model.label
            );
        } else {
            assert!(parse_envelope(&expected).is_err(), "{}", model.label);
        }
    }
    for (label, primitive, prefix) in negative_shards() {
        let expected = hexadecimal(&format!("negative-{label}"), 0);
        assert_eq!(primitive, expected, "{label}");
        assert!(decode_shard(&expected, prefix).is_err(), "{label}");
    }
}
