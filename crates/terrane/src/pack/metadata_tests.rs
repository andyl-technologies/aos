//! Checks D-47 metadata domains through packs, index shards, and bundles.

use super::*;
use std::collections::BTreeSet;
use terrane_core::cbor::{write_array, write_bytes, write_map, write_text, write_uint};
use terrane_core::pack_format::{self, BundleRecord, Header, PackView};

fn metadata_objects() -> [(EntryKind, IdentityKind, Vec<u8>); 3] {
    let mut attribute = Vec::new();
    write_map(&mut attribute, 5);
    write_uint(&mut attribute, 1);
    write_bytes(&mut attribute, &[1; 32]);
    write_uint(&mut attribute, 2);
    write_text(&mut attribute, "hash.sha256");
    write_uint(&mut attribute, 3);
    write_bytes(&mut attribute, &[2; 32]);
    write_uint(&mut attribute, 4);
    write_text(&mut attribute, "hash.sha256/1");
    write_uint(&mut attribute, 5);
    write_bytes(&mut attribute, &[3; 32]);

    let mut policy = Vec::new();
    write_map(&mut policy, 4);
    write_uint(&mut policy, 1);
    write_uint(&mut policy, 1);
    write_uint(&mut policy, 3);
    write_array(&mut policy, 0);
    write_uint(&mut policy, 4);
    write_map(&mut policy, 0);
    write_uint(&mut policy, 5);
    write_map(&mut policy, 0);

    let mut memo = Vec::new();
    write_map(&mut memo, 2);
    write_uint(&mut memo, 1);
    write_bytes(&mut memo, &[4; 32]);
    write_uint(&mut memo, 2);
    write_bytes(&mut memo, &[5; 32]);

    [
        (EntryKind::Attribute, IdentityKind::Attribute, attribute),
        (EntryKind::Policy, IdentityKind::Policy, policy),
        (EntryKind::Memo, IdentityKind::Memo, memo),
    ]
}

#[test]
fn metadata_kinds_roundtrip_pack_detached_index_and_merged_shard() -> Result<(), PackError> {
    let mut writer = PackWriter::new(PackId::from_random_bytes([25; 16]), PackClass::Meta, false);
    let objects = metadata_objects();
    for (kind, domain, bytes) in &objects {
        assert_eq!(kind.identity_kind(), *domain);
        assert_eq!(EntryKind::try_from(*kind as u8)?, *kind);
        let hash = writer.append_raw(*kind, bytes)?;
        assert_eq!(
            hash,
            TERRANE_V1.calculate(*domain, bytes)?.terrane_v1_digest()?
        );
    }

    let pack = writer.seal()?;
    let reader = PackReader::open(pack.bytes())?;
    reader.check_index_object(pack.index_object())?;
    let snapshot = PackIndexSnapshot::decode(pack.index_object(), 1)?;
    for (kind, domain, bytes) in objects {
        let hash = TERRANE_V1.calculate(domain, &bytes)?.terrane_v1_digest()?;
        assert_eq!(reader.read(kind, &hash, &RawBodyDecoder)?, bytes);
        assert!(matches!(
            reader.read(EntryKind::Node, &hash, &RawBodyDecoder),
            Err(PackError::Kind)
        ));

        let shard = MergedShard::rebuild(
            hash[0],
            1,
            std::slice::from_ref(&snapshot),
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
        )?;
        let decoded = MergedShard::decode(&shard.encode(), 1, hash[0])?;
        let entry = decoded
            .entries()
            .iter()
            .find(|entry| entry.entry().hash() == &hash)
            .ok_or(PackError::Missing)?;
        assert_eq!(entry.entry().kind(), kind);
        assert_eq!(entry.state(), RecordState::Live);
    }
    Ok(())
}

#[test]
fn metadata_kinds_reject_wrong_domains_and_data_class() -> Result<(), PackError> {
    for (kind, _, bytes) in metadata_objects() {
        let mut data = PackWriter::new(PackId::from_random_bytes([26; 16]), PackClass::Data, false);
        assert!(matches!(
            data.append_raw(kind, &bytes),
            Err(PackError::Format(pack_format::Error::Kind))
        ));

        let mut writer =
            PackWriter::new(PackId::from_random_bytes([27; 16]), PackClass::Meta, false);
        let hash = writer.append_raw(kind, &bytes)?;
        let pack = writer.seal()?;
        let view = PackView::decode(pack.bytes())?;
        let wrong_kind = if kind == EntryKind::Attribute {
            EntryKind::Policy
        } else {
            EntryKind::Attribute
        };
        let mut records = view.records().to_vec();
        records[0].kind = wrong_kind as u8;
        let forged = pack_format::encode_pack(
            Header::decode(pack.bytes())?,
            &pack.bytes()[HEADER_SIZE..view.index_offset()],
            &records,
        )?;
        let reader = PackReader::open(&forged)?;
        assert!(matches!(
            reader.read(wrong_kind, &hash, &RawBodyDecoder),
            Err(PackError::Identity(_))
        ));
    }

    for reserved in 10..=u8::MAX {
        assert!(matches!(
            EntryKind::try_from(reserved),
            Err(PackError::Kind)
        ));
    }
    Ok(())
}

#[test]
fn metadata_bundle_verifies_all_three_domains_before_exposure() -> Result<(), PackError> {
    let commit = BundleObject::new(EntryKind::Commit, vec![0xa1, 1, 0])?;
    let mut objects = vec![commit.clone()];
    for (kind, _, bytes) in metadata_objects() {
        objects.push(BundleObject::new(kind, bytes)?);
    }
    let bundle = Bundle::new(*commit.hash(), objects.clone(), &[])?;
    assert_eq!(Bundle::decode(&bundle.encode())?, bundle);

    for position in 1..objects.len() {
        let mut records = objects
            .iter()
            .map(|object| BundleRecord {
                kind: object.kind() as u8,
                hash: *object.hash(),
                bytes: object.bytes(),
            })
            .collect::<Vec<_>>();
        records[position].kind = if records[position].kind == 7 { 8 } else { 7 };
        let forged = pack_format::encode_bundle(commit.hash(), &records);
        assert!(matches!(
            Bundle::decode(&forged),
            Err(PackError::Format(pack_format::Error::Identity(_)))
        ));

        records[position].kind = 10;
        let reserved = pack_format::encode_bundle(commit.hash(), &records);
        assert!(matches!(
            Bundle::decode(&reserved),
            Err(PackError::Format(pack_format::Error::Kind))
        ));
    }
    Ok(())
}
