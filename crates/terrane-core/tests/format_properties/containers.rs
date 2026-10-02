//! Tests borrowed pack views, detached and merged indexes, and verified bundles.

use super::support::{Generator, byte_properties, cbor_properties};
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::pack_format::{self, BundleRecord, Header, MergedRecord, PackView, Record};

#[test]
fn generated_packs_indexes_and_shards_preserve_models_and_reject_bad_extents() {
    let mut generator = Generator::new(0x187a_ee2d_9873_082d);
    for count in [0, 1, 2, 17, 64] {
        for meta in [false, true] {
            let header = Header::new(generator.bytes(), meta, false);
            byte_properties("pack header", &header.encode(), |input| {
                Ok::<_, pack_format::Error>(Header::decode(input)?.encode())
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
