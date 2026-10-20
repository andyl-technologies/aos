//! Tests borrowed pack views, detached and merged indexes, and verified bundles.

use super::support::{Generator, byte_properties, cbor_properties};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_format::pack_format::{self, BundleRecord, Header, MergedRecord, PackView, Record};

#[test]
fn generated_packs_indexes_and_shards_preserve_models_and_reject_bad_extents() {
    let mut generator = Generator::new(0x187a_ee2d_9873_082d);
    for count in [0, 1, 2, 17, 64] {
        for meta in [false, true] {
            let header = Header::new(generator.bytes(), meta, false);
            byte_properties("pack header", &header.encode(), |input| {
                // Header::decode is a prefix parser used on whole packs. Its
                // canonical prefix is fixed-width; following body bytes survive.
                let mut canonical = Header::decode(input)?.encode();
                canonical.extend_from_slice(&input[pack_format::HEADER_SIZE..]);
                Ok::<_, pack_format::Error>(canonical)
            });
            let mut records = vec![];
            let mut bodies = vec![];
            for index in 0..count {
                let plaintext: Vec<_> = (0..(index % 31 + usize::from(meta)))
                    .map(|_| generator.next() as u8)
                    .collect();
                let mut hash = generator.bytes::<32>();
                hash[0] = 7;
                hash[1] = index as u8;
                let mut body = if meta { vec![] } else { vec![0] };
                body.extend_from_slice(&plaintext);
                records.push(Record {
                    hash,
                    offset: (pack_format::HEADER_SIZE + bodies.len()) as u64,
                    body_len: body.len() as u32,
                    plaintext_len: plaintext.len() as u32,
                    codec: 0,
                    kind: u8::from(meta),
                    dictionary_id: 0,
                });
                bodies.extend_from_slice(&body);
            }
            let bytes = pack_format::encode_pack(header, &bodies, &records).unwrap();
            let view = PackView::decode(&bytes).unwrap();
            assert_eq!(view.header(), header);
            assert_eq!(view.records(), records);
            byte_properties("pack", &bytes, |input| {
                let view = PackView::decode(input)?;
                pack_format::encode_pack(
                    view.header(),
                    &input[pack_format::HEADER_SIZE..view.index_offset()],
                    view.records(),
                )
            });

            let index_bytes = pack_format::encode_index(&records);
            assert_eq!(
                pack_format::decode_index(&index_bytes, header).unwrap(),
                records
            );
            byte_properties("per-pack index", &index_bytes, |input| {
                Ok::<_, pack_format::Error>(pack_format::encode_index(&pack_format::decode_index(
                    input, header,
                )?))
            });
            let detached = view.index_object();
            assert_eq!(
                pack_format::decode_detached_index(&detached).unwrap(),
                (header, records.clone())
            );
            byte_properties("detached index", &detached, |input| {
                let (header, records) = pack_format::decode_detached_index(input)?;
                Ok::<_, pack_format::Error>(
                    [header.encode(), pack_format::encode_index(&records)].concat(),
                )
            });

            for state in 0..=2 {
                let merged: Vec<_> = records
                    .iter()
                    .cloned()
                    .map(|record| MergedRecord {
                        pack: generator.bytes(),
                        record,
                        state,
                    })
                    .collect();
                let shard = pack_format::encode_shard(&merged);
                assert_eq!(pack_format::decode_shard(&shard, 7).unwrap(), merged);
                byte_properties("merged shard", &shard, |input| {
                    Ok::<_, pack_format::Error>(pack_format::encode_shard(
                        &pack_format::decode_shard(input, 7)?,
                    ))
                });
                if !merged.is_empty() {
                    assert!(pack_format::decode_shard(&shard, 8).is_err());
                    let mut invalid = shard.clone();
                    invalid[pack_format::PREAMBLE_SIZE + 67] = 1;
                    assert!(pack_format::decode_shard(&invalid, 7).is_err());
                }
            }
            if count > 0 {
                for offset in [0, 23, u64::MAX] {
                    let mut invalid = records.clone();
                    invalid[0].offset = offset;
                    assert!(pack_format::encode_pack(header, &bodies, &invalid).is_err());
                }
                let mut invalid = records.clone();
                invalid[0].body_len = u32::MAX;
                assert!(pack_format::encode_pack(header, &bodies, &invalid).is_err());
            }
        }
    }
    for width in [56, 72] {
        let mut claimed = b"TRIX".to_vec();
        claimed.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(pack_format::index_count(&claimed, width).is_err());
        assert!(pack_format::decode_index(&claimed, Header::new([0; 16], false, false)).is_err());
        assert!(pack_format::decode_shard(&claimed, 0).is_err());
    }
}

#[test]
fn generated_bundles_verify_content_identity_and_nested_metadata() {
    let mut generator = Generator::new(0x28c6_fed3_e41a_3219);
    for count in [0, 1, 2, 9] {
        let bodies: Vec<Vec<u8>> = (0..count)
            .map(|index| {
                if index % 2 == 0 {
                    generator.bytes::<32>()[..index].to_vec()
                } else {
                    vec![0xa1, 0, index as u8]
                }
            })
            .collect();
        let objects: Vec<_> = bodies
            .iter()
            .enumerate()
            .map(|(index, body)| BundleRecord {
                kind: if index % 2 == 0 { 0 } else { 2 },
                hash: TERRANE_V1
                    .calculate(
                        if index % 2 == 0 {
                            IdentityKind::Chunk
                        } else {
                            IdentityKind::Node
                        },
                        body,
                    )
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap(),
                bytes: body,
            })
            .collect();
        let root = generator.bytes();
        let bytes = pack_format::encode_bundle(&root, &objects);
        assert_eq!(pack_format::bundle_size(&objects).unwrap(), bytes.len());
        let decoded = pack_format::decode_bundle(&bytes).unwrap();
        assert_eq!(decoded.root_commit(), &root);
        assert_eq!(decoded.objects(), objects);
        cbor_properties("bundle", &bytes, |input| {
            let view = pack_format::decode_bundle(input)?;
            Ok::<_, pack_format::Error>(pack_format::encode_bundle(
                view.root_commit(),
                view.objects(),
            ))
        });
        if let Some(first) = objects.first() {
            let mut invalid = objects.clone();
            invalid[0].hash[0] ^= 1;
            assert!(
                pack_format::decode_bundle(&pack_format::encode_bundle(&root, &invalid)).is_err()
            );
            let mut invalid = objects.clone();
            invalid[0] = BundleRecord {
                kind: 255,
                ..*first
            };
            assert!(
                pack_format::decode_bundle(&pack_format::encode_bundle(&root, &invalid)).is_err()
            );
        }
    }
    let mut excessive_count = vec![0xa2, 1, 0x58, 32];
    excessive_count.extend_from_slice(&[0; 32]);
    excessive_count.extend_from_slice(&[2, 0x9b]);
    excessive_count.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(pack_format::decode_bundle(&excessive_count).is_err());
}

#[test]
fn pack_flags_codecs_metadata_kinds_and_bundle_index_alternatives_roundtrip() {
    let mut generator = Generator::new(0x7d8b_84f1_025a_7ce9);
    for meta in [false, true] {
        for compressed in [false, true] {
            for discriminator in if meta { 1..=9 } else { 0..=2 } {
                let header = Header::new(generator.bytes(), meta, compressed);
                let body = if meta {
                    vec![0xa1, 0, discriminator]
                } else {
                    let mut body = vec![discriminator];
                    if discriminator == 2 {
                        body.extend_from_slice(&generator.bytes::<32>());
                    }
                    body.extend_from_slice(&generator.bytes::<17>());
                    body
                };
                let record = Record {
                    hash: generator.bytes(),
                    offset: 24,
                    body_len: body.len() as u32,
                    plaintext_len: if meta { body.len() as u32 } else { 17 },
                    codec: if meta { 0 } else { discriminator },
                    kind: if meta { discriminator } else { 0 },
                    dictionary_id: 0,
                };
                let bytes =
                    pack_format::encode_pack(header, &body, std::slice::from_ref(&record)).unwrap();
                let view = PackView::decode(&bytes).unwrap();
                assert_eq!(view.header(), header);
                assert_eq!(view.records(), std::slice::from_ref(&record));
                let mut reserved = record.clone();
                reserved.dictionary_id = u16::MAX;
                assert!(pack_format::validate_record(&reserved, meta).is_err());
                byte_properties("pack variant", &bytes, |input| {
                    let view = PackView::decode(input)?;
                    pack_format::encode_pack(
                        view.header(),
                        &input[24..view.index_offset()],
                        view.records(),
                    )
                });
                let index = pack_format::encode_index(std::slice::from_ref(&record));
                assert_eq!(
                    pack_format::decode_index(&index, header)
                        .unwrap()
                        .as_slice(),
                    std::slice::from_ref(&record)
                );
                let detached = [header.encode(), index].concat();
                assert_eq!(
                    pack_format::decode_detached_index(&detached).unwrap(),
                    (header, vec![record.clone()])
                );
                let merged = vec![MergedRecord {
                    pack: generator.bytes(),
                    record,
                    state: discriminator % 3,
                }];
                let shard = merged[0].record.hash[0];
                let encoded = pack_format::encode_shard(&merged);
                assert_eq!(pack_format::decode_shard(&encoded, shard).unwrap(), merged);
            }
        }
    }

    let kinds = [
        IdentityKind::Chunk,
        IdentityKind::Manifest,
        IdentityKind::Node,
        IdentityKind::Commit,
        IdentityKind::Bundle,
        IdentityKind::Filter,
        IdentityKind::Index,
        IdentityKind::Attribute,
        IdentityKind::Policy,
        IdentityKind::Memo,
    ];
    for merged in [false, true] {
        let bodies: Vec<_> = (0..10)
            .map(|kind| {
                if kind == 6 {
                    if merged {
                        pack_format::encode_shard(&[])
                    } else {
                        [
                            Header::new(generator.bytes(), true, true).encode(),
                            pack_format::encode_index(&[]),
                        ]
                        .concat()
                    }
                } else if kind == 0 {
                    generator.bytes::<23>().to_vec()
                } else {
                    vec![0xa1, 0, kind]
                }
            })
            .collect();
        let objects: Vec<_> = bodies
            .iter()
            .enumerate()
            .map(|(kind, bytes)| BundleRecord {
                kind: kind as u8,
                hash: TERRANE_V1
                    .calculate(kinds[kind], bytes)
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap(),
                bytes,
            })
            .collect();
        let root = generator.bytes();
        let bytes = pack_format::encode_bundle(&root, &objects);
        assert_eq!(
            pack_format::decode_bundle(&bytes).unwrap().objects(),
            objects
        );
        cbor_properties("all bundle kinds", &bytes, |input| {
            let view = pack_format::decode_bundle(input)?;
            Ok::<_, pack_format::Error>(pack_format::encode_bundle(
                view.root_commit(),
                view.objects(),
            ))
        });
        for object in &objects[1..] {
            pack_format::validate_metadata(object.kind, object.bytes).unwrap();
        }
        for kind in [0, 10, 255] {
            assert!(pack_format::validate_metadata(kind, &[0]).is_err());
        }
        assert!(pack_format::validate_metadata(6, b"TRIX").is_err());
    }
}
