//! Canonical Git interoperability and bounded streaming projection regressions.

use std::io::Write as _;

use sha2::{Digest as _, Sha256};

use super::projection::*;
use super::*;
use crate::object::{hash_object, ObjectKind, Oid};

const MANIFEST: &str = include_str!("fixtures/manifest.json");

fn fixture(mode: &str) -> (String, &'static [u8], &'static [u8]) {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let path = manifest[mode]["path"].as_str().unwrap().to_owned();
    match mode {
        "ofs" => (
            path,
            include_bytes!("fixtures/ofs.idx"),
            include_bytes!("fixtures/ofs.pack"),
        ),
        "ref" => (
            path,
            include_bytes!("fixtures/ref.idx"),
            include_bytes!("fixtures/ref.pack"),
        ),
        _ => panic!("unknown fixture"),
    }
}

fn fixture_oid(name: &str) -> Oid {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    Oid::from_hex(manifest["objects"][name]["oid"].as_str().unwrap()).unwrap()
}

fn read_pair(path: &str, index: &[u8], pack: &[u8], chunk: usize) -> PairReader {
    let mut reader = PairReader::new(path).unwrap();
    for bytes in pack.chunks(chunk) {
        reader.feed_pack(bytes).unwrap();
    }
    for bytes in index.chunks(chunk) {
        reader.feed_index(bytes).unwrap();
    }
    reader
}

fn base_content() -> Vec<u8> {
    let mut content = b"[package]\nname = \"fixture\"\n".to_vec();
    for _ in 0..4096 {
        content.extend_from_slice(b"description = \"canonical registry metadata\"\n");
    }
    content
}

#[test]
fn real_git_ofs_and_ref_delta_fixtures_match_every_split() {
    let selection = Selection {
        oid: fixture_oid("changed"),
        range: Some(ContentRange {
            start: 11,
            end: 100,
        }),
    };
    let mut expected = base_content();
    expected[18..25].copy_from_slice(b"changed");

    for mode in ["ofs", "ref"] {
        let (path, index, pack) = fixture(mode);
        validate_against_pack(&path, index, pack).unwrap();
        for split in 0..=pack.len() {
            let mut reader = PairReader::new(&path).unwrap();
            reader.feed_pack(&pack[..split]).unwrap();
            reader.feed_pack(&pack[split..]).unwrap();
            for chunk in index.chunks(17) {
                reader.feed_index(chunk).unwrap();
            }
            let verified = reader.finish(std::slice::from_ref(&selection)).unwrap();
            assert_eq!(verified.objects[0].content, expected[11..100]);
            assert_eq!(verified.objects[0].object_size, expected.len() as u64);
            assert_eq!(verified.objects[0].kind, ObjectKind::Blob);
            assert_eq!(verified.pack.sha256, <[u8; 32]>::from(Sha256::digest(pack)));
            assert_eq!(
                verified.index.sha256,
                <[u8; 32]>::from(Sha256::digest(index))
            );
            assert_eq!(verified.pack.size, pack.len() as u64);
            assert_eq!(verified.index.size, index.len() as u64);
            assert!(verified.peak_decoded_graph_bytes <= MAX_DECODED_PACK_BYTES as u64);
            assert!(verified.peak_decoded_graph_bytes > verified.inflated_entry_bytes);
        }
    }
}

#[test]
fn one_byte_feeds_project_all_four_git_kinds() {
    let (path, index, pack) = fixture("ref");
    let mut selections = ["small", "tree", "commit", "tag"]
        .map(|name| Selection {
            oid: fixture_oid(name),
            range: None,
        })
        .to_vec();
    selections.sort_by_key(|selection| selection.oid);
    let result = read_pair(&path, index, pack, 1)
        .finish(&selections)
        .unwrap();

    assert_eq!(result.objects.len(), 4);
    for object in result.objects {
        assert_eq!(hash_object(object.kind, &object.content), object.oid);
        assert_eq!(
            object.range,
            ContentRange {
                start: 0,
                end: object.object_size
            }
        );
    }
}

#[test]
fn every_index_split_preserves_exact_companion_semantics() {
    let (path, index, pack) = fixture("ofs");
    for split in 0..=index.len() {
        let mut reader = PairReader::new(&path).unwrap();
        reader.feed_pack(pack).unwrap();
        reader.feed_index(&index[..split]).unwrap();
        reader.feed_index(&index[split..]).unwrap();
        assert!(reader.finish(&[]).is_ok());
    }
}

#[test]
fn rejects_corruption_truncation_trailing_input_and_wrong_source_path() {
    let (path, index, pack) = fixture("ofs");
    for length in [0, 1, 11, 12, 100, pack.len() - 1] {
        assert!(read_pair(&path, index, &pack[..length], 13)
            .finish(&[])
            .is_err());
    }
    let mut reader = read_pair(&path, index, pack, 31);
    assert!(reader.feed_pack(&[0]).is_err());
    assert!(reader.finish(&[]).is_err());

    let mut corrupted = pack.to_vec();
    corrupted[20] ^= 1;
    let mut reader = PairReader::new(&path).unwrap();
    let result = reader.feed_pack(&corrupted);
    assert!(result.is_err() || reader.finish(&[]).is_err());

    let wrong_path = format!("objects/pack/pack-{}.idx", "a1".repeat(32));
    let mut reader = PairReader::new(&wrong_path).unwrap();
    assert!(reader.feed_pack(pack).is_err());
    assert!(PairReader::new("objects/pack/pack-not-a-checksum.idx").is_err());
}

#[test]
fn refuses_self_consistent_index_crc_offset_and_oid_substitution() {
    let (path, index, pack) = fixture("ref");
    let count = read_u32(index, HEADER_BYTES + FANOUT_BYTES - 4).unwrap() as usize;
    let crc_start = HEADER_BYTES + FANOUT_BYTES + count * OBJECT_ID_BYTES;
    let offset_start = crc_start + count * 4;
    for changed_position in [
        HEADER_BYTES + FANOUT_BYTES + 31,
        crc_start,
        offset_start + 3,
    ] {
        let mut changed = index.to_vec();
        changed[changed_position] ^= 1;
        let checksum_at = changed.len() - 32;
        let checksum = Sha256::digest(&changed[..checksum_at]);
        changed[checksum_at..].copy_from_slice(&checksum);
        // CRC/offset changes retain a valid index; an OID change also preserves
        // its first byte/fanout and sorting in this canonical fixture.
        validate(&path, &changed).unwrap();
        assert!(read_pair(&path, &changed, pack, 19).finish(&[]).is_err());
    }
}

#[test]
fn refuses_absent_unordered_duplicate_and_excessive_selections() {
    let (path, index, pack) = fixture("ofs");
    let small = Selection {
        oid: fixture_oid("small"),
        range: None,
    };
    let absent = Selection {
        oid: Oid::from_bytes(&[0; 32]).unwrap(),
        range: None,
    };
    for selections in [
        vec![absent],
        vec![small.clone(), small.clone()],
        vec![small; 9],
    ] {
        assert!(read_pair(&path, index, pack, 7)
            .finish(&selections)
            .is_err());
    }
    let selections = vec![
        Selection {
            oid: fixture_oid("small"),
            range: None,
        },
        Selection {
            oid: fixture_oid("tree"),
            range: None,
        },
    ];
    assert!(read_pair(&path, index, pack, 7)
        .finish(&selections)
        .is_err());
}

#[test]
fn ranges_are_exact_and_whole_large_objects_do_not_cross_projection_boundary() {
    let (path, index, pack) = fixture("ofs");
    let base = fixture_oid("base");
    for range in [
        None,
        Some(ContentRange {
            start: 0,
            end: 128 * 1024 + 1,
        }),
        Some(ContentRange { start: 10, end: 9 }),
        Some(ContentRange {
            start: 0,
            end: u64::MAX,
        }),
        Some(ContentRange {
            start: 180252,
            end: 180252,
        }),
    ] {
        assert!(read_pair(&path, index, pack, 7)
            .finish(&[Selection { oid: base, range }])
            .is_err());
    }
    let result = read_pair(&path, index, pack, 7)
        .finish(&[Selection {
            oid: base,
            range: Some(ContentRange {
                start: 180251,
                end: 180251,
            }),
        }])
        .unwrap();
    assert!(result.objects[0].content.is_empty());

    let mut selections = vec![
        Selection {
            oid: base,
            range: Some(ContentRange {
                start: 0,
                end: 128 * 1024,
            }),
        },
        Selection {
            oid: fixture_oid("small"),
            range: None,
        },
    ];
    selections.sort_by_key(|selection| selection.oid);
    assert!(read_pair(&path, index, pack, 7)
        .finish(&selections)
        .is_err());
}

#[test]
fn failed_feeds_poison_a_previously_valid_pair() {
    let (path, index, pack) = fixture("ofs");
    for pack_failure in [false, true] {
        let mut reader = read_pair(&path, index, pack, 3);
        let too_large = vec![0; MAX_FEED_BYTES + 1];
        let failed = if pack_failure {
            reader.feed_pack(&too_large)
        } else {
            reader.feed_index(&too_large)
        };
        assert!(failed.is_err());
        assert!(reader.finish(&[]).is_err());
    }
    let mut reader = PairReader::new(&path).unwrap();
    for _ in 0..MAX_PUBLISHED_PACK_INDEX_BYTES as usize / MAX_FEED_BYTES {
        reader.feed_index(&vec![0; MAX_FEED_BYTES]).unwrap();
    }
    assert!(reader.feed_index(&[0]).is_err());
    assert!(reader.finish(&[]).is_err());
}

fn blob_pack(count: usize, object_size: usize, incompressible: bool) -> (String, Vec<u8>) {
    let mut pack = b"PACK".to_vec();
    pack.extend_from_slice(&2_u32.to_be_bytes());
    pack.extend_from_slice(&(count as u32).to_be_bytes());
    for _ in 0..count {
        let mut rest = object_size >> 4;
        pack.push(0x30 | (object_size & 15) as u8 | if rest > 0 { 0x80 } else { 0 });
        while rest > 0 {
            let byte = (rest & 127) as u8;
            rest >>= 7;
            pack.push(byte | if rest > 0 { 0x80 } else { 0 });
        }
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut data = vec![b'x'; object_size];
        if incompressible {
            let mut state = 0x1234_5678_u32;
            for byte in &mut data {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
        }
        encoder.write_all(&data).unwrap();
        pack.extend_from_slice(&encoder.finish().unwrap());
    }
    let checksum = Sha256::digest(&pack);
    pack.extend_from_slice(&checksum);
    (
        format!("objects/pack/pack-{}.idx", hex::encode(checksum)),
        pack,
    )
}

#[test]
fn enforces_decoded_object_graph_and_encoded_stream_bounds() {
    for (count, size) in [(1, MAX_PACK_OBJECT_BYTES + 1), (4, MAX_PACK_OBJECT_BYTES)] {
        let (path, pack) = blob_pack(count, size, false);
        let mut reader = PairReader::new(&path).unwrap();
        assert!(pack
            .chunks(8192)
            .any(|chunk| reader.feed_pack(chunk).is_err()));
        assert!(reader.finish(&[]).is_err());
    }
    let (path, pack) = blob_pack(3, 3 * 1024 * 1024, true);
    assert!(pack.len() as u64 > MAX_PUBLISHED_PACK_BYTES);
    let mut reader = PairReader::new(&path).unwrap();
    let failed_at = pack
        .chunks(MAX_FEED_BYTES)
        .position(|chunk| reader.feed_pack(chunk).is_err())
        .unwrap();
    assert_eq!(
        failed_at,
        MAX_PUBLISHED_PACK_BYTES as usize / MAX_FEED_BYTES
    );
    assert!(reader.finish(&[]).is_err());
}

#[test]
fn delta_output_budget_is_checked_before_copy_or_allocation() {
    let delta = vec![5, 6, 0x90, 5, 1, b'!'];
    assert!(apply_delta(b"hello", &delta, 5).is_err());
    assert_eq!(apply_delta(b"hello", &delta, 6).unwrap(), b"hello!");
    let lies_about_output_size = vec![5, 1, 0x90, 5];
    assert!(apply_delta(b"hello", &lies_about_output_size, 6).is_err());

    let mut overflowing_size = vec![0x80; (usize::BITS as usize - 1) / 7];
    overflowing_size.push(0x7f);
    assert!(read_delta_varint(&overflowing_size, &mut 0).is_err());
}

#[test]
fn delta_depth_cycles_and_missing_bases_never_produce_projections() {
    let a = *hash_object(ObjectKind::Blob, b"a").as_bytes();
    let b = *hash_object(ObjectKind::Blob, b"b").as_bytes();
    let expected = vec![
        IndexEntry {
            oid: a,
            crc: 0,
            offset: 12,
        },
        IndexEntry {
            oid: b,
            crc: 0,
            offset: 20,
        },
    ];
    let cyclic = vec![
        PackedEntry {
            offset: 12,
            crc: 0,
            kind: PackedKind::ReferenceDelta(b),
            data: vec![1, 1, 1, b'a'],
        },
        PackedEntry {
            offset: 20,
            crc: 0,
            kind: PackedKind::ReferenceDelta(a),
            data: vec![1, 1, 1, b'b'],
        },
    ];
    assert!(resolve_pack_entries(cyclic, &expected).is_err());
    for kind in [
        PackedKind::ReferenceDelta([0; 32]),
        PackedKind::OffsetDelta(13),
    ] {
        let entries = vec![PackedEntry {
            offset: 12,
            crc: 0,
            kind,
            data: vec![1, 1, 1, b'a'],
        }];
        assert!(resolve_pack_entries(entries, &expected[..1]).is_err());
    }

    let mut entries = Vec::new();
    let mut expected = Vec::new();
    let oids = (0..=MAX_DELTA_DEPTH)
        .map(|index| *hash_object(ObjectKind::Blob, &index.to_be_bytes()).as_bytes())
        .collect::<Vec<_>>();
    for index in 0..=MAX_DELTA_DEPTH {
        let offset = 12 + index as u64;
        let kind = if index == MAX_DELTA_DEPTH {
            PackedKind::Base(ObjectKind::Blob)
        } else {
            PackedKind::ReferenceDelta(oids[index + 1])
        };
        entries.push(PackedEntry {
            offset,
            crc: 0,
            kind,
            data: Vec::new(),
        });
        expected.push(IndexEntry {
            oid: oids[index],
            crc: 0,
            offset,
        });
    }
    let error = resolve_pack_entries(entries, &expected).unwrap_err();
    assert!(error.to_string().contains("delta-depth limit"));
}

fn absent_oid(byte: u8) -> Oid {
    Oid::from_bytes(&[byte; 32]).unwrap()
}

#[test]
fn available_selection_returns_an_exact_ordered_partition_and_keeps_strict_finish() {
    let mut selections = vec![
        Selection {
            oid: fixture_oid("small"),
            range: None,
        },
        Selection {
            oid: absent_oid(0),
            range: None,
        },
        Selection {
            oid: fixture_oid("changed"),
            range: Some(ContentRange { start: 0, end: 32 }),
        },
        Selection {
            oid: absent_oid(255),
            range: None,
        },
    ];
    selections.sort_by_key(|selection| selection.oid);

    for mode in ["ofs", "ref"] {
        let (path, index, pack) = fixture(mode);
        let available = read_pair(&path, index, pack, 1)
            .finish_available(&selections)
            .unwrap();
        assert_eq!(available.missing_oids, vec![absent_oid(0), absent_oid(255)]);
        let present = selections
            .iter()
            .filter(|selection| !available.missing_oids.contains(&selection.oid))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            available
                .pair
                .objects
                .iter()
                .map(|object| object.oid)
                .collect::<Vec<_>>(),
            present
                .iter()
                .map(|selection| selection.oid)
                .collect::<Vec<_>>()
        );
        let strict = read_pair(&path, index, pack, 17).finish(&present).unwrap();
        assert_eq!(available.pair, strict);
        assert!(read_pair(&path, index, pack, 19)
            .finish(&selections)
            .is_err());
    }
}

#[test]
fn wholly_absent_or_empty_selections_still_require_the_complete_verified_pair() {
    let (path, index, pack) = fixture("ref");
    let selections = vec![
        Selection {
            oid: absent_oid(0),
            range: None,
        },
        Selection {
            oid: absent_oid(255),
            range: None,
        },
    ];
    let available = read_pair(&path, index, pack, 7)
        .finish_available(&selections)
        .unwrap();
    assert_eq!(available.missing_oids, vec![absent_oid(0), absent_oid(255)]);
    assert!(available.pair.objects.is_empty());
    assert_eq!(
        available.pair,
        read_pair(&path, index, pack, 13).finish(&[]).unwrap()
    );
    let empty = read_pair(&path, index, pack, 3)
        .finish_available(&[])
        .unwrap();
    assert!(empty.missing_oids.is_empty());
    assert_eq!(empty.pair, available.pair);

    let count = read_u32(index, HEADER_BYTES + FANOUT_BYTES - 4).unwrap() as usize;
    let mut changed = index.to_vec();
    changed[HEADER_BYTES + FANOUT_BYTES + count * OBJECT_ID_BYTES] ^= 1;
    let checksum_at = changed.len() - 32;
    let checksum = Sha256::digest(&changed[..checksum_at]);
    changed[checksum_at..].copy_from_slice(&checksum);
    validate(&path, &changed).unwrap();
    assert!(read_pair(&path, &changed, pack, 31)
        .finish_available(&selections)
        .is_err());
}

#[test]
fn available_selection_never_turns_incomplete_or_failed_input_into_absence() {
    let (path, index, pack) = fixture("ofs");
    let selections = [Selection {
        oid: absent_oid(0),
        range: None,
    }];
    assert!(read_pair(&path, index, &pack[..pack.len() - 1], 13)
        .finish_available(&selections)
        .is_err());
    assert!(read_pair(&path, &index[..index.len() - 1], pack, 13)
        .finish_available(&selections)
        .is_err());
    let mut reader = read_pair(&path, index, pack, 5);
    assert!(reader.feed_pack(&[0]).is_err());
    assert!(reader.finish_available(&selections).is_err());
    let mut reader = read_pair(&path, index, pack, 5);
    assert!(reader.feed_index(&vec![0; MAX_FEED_BYTES + 1]).is_err());
    assert!(reader.finish_available(&selections).is_err());
}

#[test]
fn absent_selections_do_not_relax_batch_range_or_present_output_bounds() {
    let (path, index, pack) = fixture("ofs");
    let absent = Selection {
        oid: absent_oid(0),
        range: None,
    };
    assert!(read_pair(&path, index, pack, 19)
        .finish_available(&vec![absent.clone(); MAX_SELECTED_OBJECTS + 1])
        .is_err());
    assert!(read_pair(&path, index, pack, 19)
        .finish_available(&[absent.clone(), absent])
        .is_err());
    for range in [
        ContentRange {
            start: 0,
            end: MAX_SELECTED_CONTENT_BYTES as u64 + 1,
        },
        ContentRange { start: 10, end: 9 },
        ContentRange {
            start: MAX_PACK_OBJECT_BYTES as u64 + 1,
            end: MAX_PACK_OBJECT_BYTES as u64 + 1,
        },
    ] {
        let selection = Selection {
            oid: absent_oid(0),
            range: Some(range),
        };
        assert!(read_pair(&path, index, pack, 19)
            .finish_available(&[selection])
            .is_err());
    }
    let selections = [
        Selection {
            oid: absent_oid(0),
            range: Some(ContentRange {
                start: 0,
                end: MAX_SELECTED_CONTENT_BYTES as u64,
            }),
        },
        Selection {
            oid: fixture_oid("small"),
            range: Some(ContentRange { start: 0, end: 1 }),
        },
    ];
    assert!(read_pair(&path, index, pack, 19)
        .finish_available(&selections)
        .is_err());
    let selections = [
        Selection {
            oid: absent_oid(0),
            range: None,
        },
        Selection {
            oid: fixture_oid("small"),
            range: Some(ContentRange { start: 0, end: 29 }),
        },
    ];
    assert!(read_pair(&path, index, pack, 19)
        .finish_available(&selections)
        .is_err());
}
