//! Exercises pack-format corruption, private sealing, bundles, and merged indexes.

use super::binary::{crc32c, encode_index};
use super::*;

macro_rules! assert_error {
    ($result:expr, $expected:pat $(,)?) => {
        match $result {
            $expected => {}
            other => panic!("unexpected result: {other:?}"),
        }
    };
}
use std::collections::{BTreeMap, BTreeSet};

fn data_pack(id: u8, bodies: &[&[u8]]) -> Result<SealedPack, PackError> {
    let mut writer = PackWriter::new(PackId::from_random_bytes([id; 16]), PackClass::Data, false);
    for body in bodies {
        writer.append_raw(EntryKind::Chunk, body)?;
    }
    writer.seal()
}

fn replace_index(pack: &SealedPack, entries: &[IndexEntry]) -> Vec<u8> {
    let reader = PackReader::open(pack.bytes()).expect("valid fixture pack");
    let index_start = usize::try_from(u64::from_le_bytes(
        pack.bytes()[pack.bytes().len() - 16..pack.bytes().len() - 8]
            .try_into()
            .expect("footer offset"),
    ))
    .expect("small fixture offset");
    let mut bytes = pack.bytes()[..index_start].to_vec();
    let index = encode_index(entries);
    bytes.extend_from_slice(&index);
    bytes.extend_from_slice(&(index_start as u64).to_le_bytes());
    bytes.extend_from_slice(&crc32c(&index).to_le_bytes());
    bytes.extend_from_slice(b"TRPE");
    assert_eq!(reader.header(), pack.header());
    bytes
}

#[test]
fn pack_header_rejects_unknown_version_magic_and_flags() -> Result<(), PackError> {
    let pack = data_pack(1, &[b"one"])?;
    for (offset, byte) in [(0, b'X'), (4, 2), (6, 4), (7, 1)] {
        let mut corrupted = pack.bytes().to_vec();
        corrupted[offset] = byte;
        assert!(PackReader::open(&corrupted).is_err(), "offset {offset}");
    }
    assert_eq!(
        PackReader::open(pack.bytes())?.header().id(),
        pack.header().id()
    );
    for length in 0..40 {
        assert!(PackReader::open(&pack.bytes()[..length]).is_err());
    }
    Ok(())
}

#[test]
fn pack_id_round_trips_exactly_and_keys_share_identifier() -> Result<(), PackError> {
    let id = PackId::from_random_bytes([0xab; 16]);
    assert_eq!(id.to_string(), "abababababababababababababababab");
    assert_eq!(
        id.pack_key(),
        "objects/pack/ab/abababababababababababababababab.pack"
    );
    assert_eq!(
        id.index_key(),
        "objects/pack/ab/abababababababababababababababab.idx"
    );
    let writer = PackWriter::new(id, PackClass::Data, false);
    assert_eq!(PackReader::open(writer.seal()?.bytes())?.header().id(), id);
    Ok(())
}

#[test]
fn pack_index_is_sorted_while_bodies_remain_in_tree_order() -> Result<(), PackError> {
    let pack = data_pack(
        2,
        &[
            b"directory a file chunk 1",
            b"directory a file chunk 2",
            b"directory b file",
        ],
    )?;
    let reader = PackReader::open(pack.bytes())?;
    assert!(
        reader
            .entries()
            .windows(2)
            .all(|pair| pair[0].hash < pair[1].hash)
    );
    let mut physical: Vec<_> = reader.entries().iter().collect();
    physical.sort_by_key(|entry| entry.offset);
    let expected = [
        b"directory a file chunk 1".as_slice(),
        b"directory a file chunk 2",
        b"directory b file",
    ];
    for (entry, expected) in physical.iter().zip(expected) {
        assert_eq!(
            reader.read(EntryKind::Chunk, entry.hash(), &RawBodyDecoder)?,
            expected
        );
    }
    Ok(())
}

#[test]
fn pack_index_rejects_bad_coverage_duplicates_lengths_and_reserved_bytes() -> Result<(), PackError>
{
    let pack = data_pack(3, &[b"one", b"two"])?;
    let reader = PackReader::open(pack.bytes())?;
    let entries = reader.entries();
    let mut cases = Vec::new();
    let mut overlap = entries.to_vec();
    overlap[1].offset = overlap[0].offset;
    cases.push(overlap);
    let mut duplicate = entries.to_vec();
    duplicate[1].hash = duplicate[0].hash;
    cases.push(duplicate);
    let mut bad_length = entries.to_vec();
    bad_length[0].body_len += 1;
    cases.push(bad_length);
    let mut header_overlap = entries.to_vec();
    header_overlap[0].offset = 0;
    cases.push(header_overlap);
    let mut unsorted = entries.to_vec();
    unsorted.reverse();
    cases.push(unsorted);
    cases.push(entries[..1].to_vec());
    for entries in cases {
        assert!(PackReader::open(&replace_index(&pack, &entries)).is_err());
    }
    let mut reserved = pack.index_object().to_vec();
    reserved[HEADER_SIZE + 12 + 52] = 1;
    assert_error!(
        PackIndexSnapshot::decode(&reserved, 1),
        Err(PackError::Format(
            terrane_core::pack_format::Error::Reserved
        ))
    );
    Ok(())
}

#[test]
fn pack_footer_crc_and_body_identity_are_independent() -> Result<(), PackError> {
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    let pack = data_pack(4, &[b"hello"])?;
    let mut crc_bad = pack.bytes().to_vec();
    let crc_position = crc_bad.len() - 8;
    crc_bad[crc_position] ^= 1;
    assert!(matches!(
        PackReader::open(&crc_bad),
        Err(PackError::Format(terrane_core::pack_format::Error::Crc))
    ));

    let mut body_bad = pack.bytes().to_vec();
    body_bad[HEADER_SIZE + 1] ^= 1;
    let reader = PackReader::open(&body_bad)?;
    assert!(matches!(
        reader.read(
            EntryKind::Chunk,
            reader.entries()[0].hash(),
            &RawBodyDecoder
        ),
        Err(PackError::Identity(_))
    ));
    assert!(reader.verified_admissions(&[], &RawBodyDecoder).is_err());
    Ok(())
}

#[test]
fn pack_self_describing_rebuild_and_idx_disagreement_use_embedded_authority()
-> Result<(), PackError> {
    let pack = data_pack(5, &[b"alpha", b"beta"])?;
    let reader = PackReader::open(pack.bytes())?;
    assert_eq!(reader.index_object(), pack.index_object());
    let mut corrupt_copy = pack.index_object().to_vec();
    corrupt_copy[8] ^= 1;
    assert_error!(
        reader.check_index_object(&corrupt_copy),
        Err(PackError::DetachedIndex)
    );
    for entry in reader.entries() {
        assert_eq!(
            digest(
                entry.kind,
                &reader.read(entry.kind, &entry.hash, &RawBodyDecoder)?
            )?,
            entry.hash
        );
    }
    assert_eq!(
        PackIndexSnapshot::decode(&reader.index_object(), 1)?.entries(),
        reader.entries()
    );
    Ok(())
}

#[test]
fn pack_single_writer_sealing_duplicates_and_size_threshold() -> Result<(), PackError> {
    let mut writer = PackWriter::new(PackId::from_random_bytes([6; 16]), PackClass::Data, false);
    let hash = writer.append_raw(EntryKind::Chunk, b"one")?;
    assert_error!(
        writer.append_raw(EntryKind::Chunk, b"one"),
        Err(PackError::Duplicate)
    );
    assert!(!writer.seal_due(29, 30));
    assert!(writer.seal_due(30, 30));
    let sealed = writer.seal()?;
    assert_eq!(
        PackReader::open(sealed.bytes())?.read(EntryKind::Chunk, &hash, &RawBodyDecoder)?,
        b"one"
    );

    let mut large = PackWriter::new(PackId::from_random_bytes([7; 16]), PackClass::Data, false);
    large.append_raw(EntryKind::Chunk, &vec![42; DATA_PACK_LIMIT - 1])?;
    assert!(large.seal_required());
    assert_error!(
        large.append_raw(EntryKind::Chunk, b"next"),
        Err(PackError::SealRequired)
    );
    PackReader::open(large.seal()?.bytes())?;
    Ok(())
}

#[test]
fn pack_meta_separation_and_kind_domain_are_strict() -> Result<(), PackError> {
    let mut data = PackWriter::new(PackId::from_random_bytes([8; 16]), PackClass::Data, false);
    assert_error!(
        data.append_raw(EntryKind::Node, &[0xa0]),
        Err(PackError::Format(terrane_core::pack_format::Error::Kind))
    );
    let mut meta = PackWriter::new(PackId::from_random_bytes([9; 16]), PackClass::Meta, false);
    assert_error!(
        meta.append_raw(EntryKind::Chunk, b"data"),
        Err(PackError::Format(terrane_core::pack_format::Error::Kind))
    );
    let hash = meta.append_raw(EntryKind::Node, &[0xa0])?;
    let pack = meta.seal()?;
    let reader = PackReader::open(pack.bytes())?;
    assert_eq!(reader.header().class(), PackClass::Meta);
    assert_error!(
        reader.read(EntryKind::Commit, &hash, &RawBodyDecoder),
        Err(PackError::Kind)
    );
    let mut forged = reader.entries().to_vec();
    forged[0].kind = EntryKind::Commit;
    let bytes = replace_index(&pack, &forged);
    let reader = PackReader::open(&bytes)?;
    assert!(matches!(
        reader.read(EntryKind::Commit, &hash, &RawBodyDecoder),
        Err(PackError::Identity(_))
    ));
    Ok(())
}

#[test]
fn whole_pack_verifies_bystanders_without_pinning() -> Result<(), PackError> {
    let pack = data_pack(10, &[b"abc", b"def"])?;
    let reader = PackReader::open(pack.bytes())?;
    let requested = [(EntryKind::Chunk, reader.entries()[0].hash)];
    assert!(reader.prefer_whole_pack(&requested, 50)?);
    assert!(!reader.prefer_whole_pack(&requested, 51)?);
    assert_error!(
        reader.prefer_whole_pack(&requested, 101),
        Err(PackError::Limit)
    );
    let admissions = reader.verified_admissions(&requested, &RawBodyDecoder)?;
    assert_eq!(admissions.iter().filter(|body| body.requested).count(), 1);
    assert!(admissions.iter().all(|body| !body.pinned()));
    Ok(())
}

#[test]
fn bundle_verify_rejects_one_bad_triple_and_canonical_schema_errors() -> Result<(), PackError> {
    let object = BundleObject::new(EntryKind::Node, vec![0xa0])?;
    let commit = BundleObject::new(EntryKind::Commit, vec![0xa1, 1, 0])?;
    let bundle = Bundle::new(*commit.hash(), vec![object.clone(), commit.clone()], &[])?;
    assert_eq!(bundle.objects()[0], commit);
    assert_eq!(Bundle::decode(&bundle.encode())?, bundle);
    assert_eq!(
        bundle.identity()?,
        digest(EntryKind::Bundle, &bundle.encode())?
    );
    let omitted = Bundle::new(
        *commit.hash(),
        vec![object.clone(), commit.clone()],
        &[(object.kind(), *object.hash())],
    )?;
    assert_eq!(omitted.objects(), &[commit]);

    let mut corrupted = bundle.encode();
    let last = corrupted.len() - 1;
    corrupted[last] = 0xa1;
    assert!(Bundle::decode(&corrupted).is_err());
    let mut hash_bad = bundle.encode();
    hash_bad[44] ^= 1;
    assert!(Bundle::decode(&hash_bad).is_err());
    let mut unknown_key = bundle.encode();
    unknown_key[36] = 3;
    assert!(Bundle::decode(&unknown_key).is_err());
    let mut trailing = bundle.encode();
    trailing.push(0);
    assert!(Bundle::decode(&trailing).is_err());
    let repeated = Bundle::new([0; 32], vec![object.clone(), object], &[])?;
    assert_eq!(Bundle::decode(&repeated.encode())?, repeated);
    Ok(())
}

#[test]
fn index_rebuild_round_trips_all_shards_from_per_pack_indexes() -> Result<(), PackError> {
    let packs = [data_pack(11, &[b"a", b"b"])?, data_pack(12, &[b"c", b"d"])?];
    let snapshots: Vec<_> = packs
        .iter()
        .map(|pack| PackIndexSnapshot::decode(pack.index_object(), 1))
        .collect::<Result<_, _>>()?;
    let mut records = 0;
    for shard in 0..=255 {
        let merged = MergedShard::rebuild(
            shard,
            1,
            &snapshots,
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
        )?;
        assert_eq!(MergedShard::decode(&merged.encode(), 1, shard)?, merged);
        assert!(
            merged
                .entries()
                .windows(2)
                .all(|pair| pair[0].entry().hash() < pair[1].entry().hash())
        );
        records += merged.entries().len();
    }
    assert_eq!(records, 4);
    Ok(())
}

#[test]
fn index_shard_generations_refresh_atomically_and_fall_back_to_newer_packs() -> Result<(), PackError>
{
    let first = data_pack(13, &[b"old"])?;
    let newer = data_pack(14, &[b"new"])?;
    let old_snapshot = PackIndexSnapshot::decode(first.index_object(), 1)?;
    let new_snapshot = PackIndexSnapshot::decode(newer.index_object(), 2)?;
    let old_hash = *old_snapshot.entries()[0].hash();
    let new_hash = *new_snapshot.entries()[0].hash();
    let shard = MergedShard::rebuild(
        old_hash[0],
        1,
        &[old_snapshot],
        &BTreeSet::new(),
        None,
        &BTreeSet::new(),
    )?;
    let mut catalog = IndexCatalog::new();
    catalog.refresh(vec![shard.clone()])?;
    catalog.add_pack(new_snapshot)?;
    assert!(matches!(
        catalog.lookup(EntryKind::Chunk, &old_hash),
        Lookup::Live(_)
    ));
    assert!(matches!(
        catalog.lookup(EntryKind::Chunk, &new_hash),
        Lookup::Live(_)
    ));
    catalog.refresh(vec![shard.clone()])?;
    let older = MergedShard::decode(&shard.encode(), 0, old_hash[0])?;
    assert_error!(catalog.refresh(vec![older]), Err(PackError::Generation));
    assert_error!(
        catalog.refresh(vec![shard.clone(), shard]),
        Err(PackError::Generation)
    );
    let published = BTreeMap::from([(old_hash[0], 2)]);
    assert_eq!(catalog.delta_needed(&published), vec![(old_hash[0], 2)]);
    assert!(matches!(
        catalog.lookup(EntryKind::Chunk, &old_hash),
        Lookup::Live(_)
    ));
    Ok(())
}

#[test]
fn index_tombstones_block_stale_fallback_and_persist_until_confirmed_deletion()
-> Result<(), PackError> {
    let pack = data_pack(15, &[b"gone"])?;
    let snapshot = PackIndexSnapshot::decode(pack.index_object(), 1)?;
    let hash = *snapshot.entries()[0].hash();
    let tombstoned = BTreeSet::from([pack.header().id()]);
    let first = MergedShard::rebuild(
        hash[0],
        1,
        std::slice::from_ref(&snapshot),
        &tombstoned,
        None,
        &BTreeSet::new(),
    )?;
    assert_eq!(first.entries()[0].state(), RecordState::Tombstone);
    let next = MergedShard::rebuild(hash[0], 2, &[], &tombstoned, Some(&first), &BTreeSet::new())?;
    assert_eq!(next.entries()[0].state(), RecordState::Tombstone);
    let mut catalog = IndexCatalog::new();
    catalog.add_pack(snapshot)?;
    catalog.refresh(vec![next.clone()])?;
    assert_eq!(
        catalog.lookup(EntryKind::Chunk, &hash),
        Lookup::Tombstone(pack.header().id())
    );
    let deleted = MergedShard::rebuild(hash[0], 3, &[], &tombstoned, Some(&next), &tombstoned)?;
    assert!(deleted.entries().is_empty());
    Ok(())
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn pack_id_secure_generator_has_no_repeated_identifiers()
-> Result<(), Box<dyn std::error::Error>> {
    let mut seen = BTreeSet::new();
    for _ in 0..1024 {
        assert!(seen.insert(PackId::generate(&crate::store::TokioLocalFs).await?));
    }
    Ok(())
}

#[cfg(feature = "std")]
struct RandomBinding {
    length: usize,
    fail: bool,
}

#[cfg(feature = "std")]
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl crate::store::LocalFs for RandomBinding {
    type Lock = ();

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        assert_eq!(length, 16);
        if self.fail {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "entropy unavailable",
            ));
        }
        Ok(vec![0xab; self.length])
    }

    async fn lock_exclusive(&self, _path: &std::path::Path) -> std::io::Result<Self::Lock> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn read(&self, _path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn read_range(
        &self,
        _path: &std::path::Path,
        _range: crate::store::ByteRange,
    ) -> std::io::Result<Vec<u8>> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn write_new(&self, _path: &std::path::Path, _bytes: &[u8]) -> std::io::Result<()> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn create_dir_all(&self, _path: &std::path::Path) -> std::io::Result<()> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn read_dir(&self, _path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn metadata(&self, _path: &std::path::Path) -> std::io::Result<std::fs::Metadata> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn symlink_metadata(
        &self,
        _path: &std::path::Path,
    ) -> std::io::Result<std::fs::Metadata> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn remove_file(&self, _path: &std::path::Path) -> std::io::Result<()> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn rename(&self, _from: &std::path::Path, _to: &std::path::Path) -> std::io::Result<()> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn rename_no_replace(
        &self,
        _from: &std::path::Path,
        _to: &std::path::Path,
    ) -> std::io::Result<()> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn sync_file(&self, _path: &std::path::Path) -> std::io::Result<()> {
        panic!("pack identifier generation must only request entropy")
    }

    async fn sync_directory(&self, _path: &std::path::Path) -> std::io::Result<()> {
        panic!("pack identifier generation must only request entropy")
    }
}

#[cfg(feature = "std")]
#[test]
fn pack_id_secure_generator_validates_binding_results() -> std::io::Result<()> {
    let binding = RandomBinding {
        length: 16,
        fail: false,
    };
    assert_eq!(
        run_ready(PackId::generate(&binding))?.as_bytes(),
        &[0xab; 16]
    );

    for length in [0, 15, 17] {
        let binding = RandomBinding {
            length,
            fail: false,
        };
        assert_eq!(
            run_ready(PackId::generate(&binding))
                .expect_err("wrong entropy width")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    let binding = RandomBinding {
        length: 16,
        fail: true,
    };
    assert_eq!(
        run_ready(PackId::generate(&binding))
            .expect_err("unavailable entropy")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    Ok(())
}

struct RecordingPublisher {
    writes: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    fail_index: bool,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl PackPublisher for RecordingPublisher {
    type Error = PackError;

    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<(), PackError> {
        if self.fail_index && key.ends_with(".idx") {
            return Err(PackError::Missing);
        }
        let mut writes = self.writes.lock().expect("test mutex");
        if let Some((_, existing)) = writes.iter().find(|(stored, _)| stored == key) {
            return if existing == bytes {
                Ok(())
            } else {
                Err(PackError::Generation)
            };
        }
        writes.push((key.to_string(), bytes.to_vec()));
        Ok(())
    }
}

fn run_ready<F: std::future::Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("fixture publisher unexpectedly waited"),
    }
}

#[test]
fn pack_single_writer_publication_receipt_requires_pack_then_identical_index()
-> Result<(), PackError> {
    let pack = data_pack(16, &[b"durable"])?;
    let publisher = RecordingPublisher {
        writes: std::sync::Mutex::new(Vec::new()),
        fail_index: false,
    };
    let receipt = run_ready(pack.publish(&publisher))?;
    assert_eq!(receipt.id(), pack.header().id());
    assert_eq!(run_ready(pack.publish(&publisher))?, receipt);
    let writes = publisher.writes.lock().expect("test mutex");
    assert_eq!(
        writes.as_slice(),
        &[
            (pack.header().id().pack_key(), pack.bytes().to_vec()),
            (pack.header().id().index_key(), pack.index_object().to_vec())
        ]
    );

    let failing = RecordingPublisher {
        writes: std::sync::Mutex::new(Vec::new()),
        fail_index: true,
    };
    assert_error!(run_ready(pack.publish(&failing)), Err(PackError::Missing));
    assert_eq!(failing.writes.lock().expect("test mutex").len(), 1);
    Ok(())
}

#[test]
fn pack_tree_locality_omits_held_chunks_and_keeps_object_chunks_consecutive()
-> Result<(), PackError> {
    let held_hash = digest(EntryKind::Chunk, b"already held")?;
    let held = BTreeSet::from([held_hash]);
    let mut writer = PackWriter::new(PackId::from_random_bytes([17; 16]), PackClass::Data, false);
    let first = writer.append_object(
        b"a/first",
        [b"first".as_slice(), b"already held", b"second"],
        &held,
    )?;
    assert_eq!(first[1], held_hash);
    writer.append_object(b"a/second", [b"third".as_slice(), b"first"], &held)?;
    assert_error!(
        writer.append_object(b"a/first", [b"wrong".as_slice()], &held),
        Err(PackError::Index)
    );
    writer.append_object(b"b/first", [b"fourth".as_slice()], &held)?;
    let pack = writer.seal()?;
    let reader = PackReader::open(pack.bytes())?;
    assert_eq!(reader.entries().len(), 4);
    assert_error!(
        reader.read(EntryKind::Chunk, &held_hash, &RawBodyDecoder),
        Err(PackError::Missing)
    );
    let mut physical: Vec<_> = reader.entries().iter().collect();
    physical.sort_by_key(|entry| entry.offset());
    for (entry, expected) in
        physical
            .iter()
            .zip([b"first".as_slice(), b"second", b"third", b"fourth"])
    {
        assert_eq!(
            reader.read(entry.kind(), entry.hash(), &RawBodyDecoder)?,
            expected
        );
    }
    Ok(())
}

#[test]
fn index_tombstones_allow_only_a_newly_published_replacement_pack() -> Result<(), PackError> {
    let old = data_pack(18, &[b"same"])?;
    let replacement = data_pack(19, &[b"same"])?;
    let old_index = PackIndexSnapshot::decode(old.index_object(), 1)?;
    let hash = *old_index.entries()[0].hash();
    let tombstone = MergedShard::rebuild(
        hash[0],
        2,
        &[old_index],
        &BTreeSet::from([old.header().id()]),
        None,
        &BTreeSet::new(),
    )?;
    let mut catalog = IndexCatalog::new();
    catalog.refresh(vec![tombstone])?;
    let replacement_index = PackIndexSnapshot::decode(replacement.index_object(), 3)?;
    catalog.add_pack(replacement_index)?;
    match catalog.lookup(EntryKind::Chunk, &hash) {
        Lookup::Live(record) => assert_eq!(record.pack(), replacement.header().id()),
        other => panic!("replacement must be live, got {other:?}"),
    }
    Ok(())
}

#[test]
fn pack_scan_recovery_quarantines_unframed_damage_without_serving_guessed_bodies()
-> Result<(), PackError> {
    let pack = data_pack(20, &[b"unframed one", b"unframed two"])?;
    assert_eq!(
        PackReader::recover(pack.bytes())?.index_object(),
        pack.index_object()
    );
    let mut bad_footer = pack.bytes().to_vec();
    let last = bad_footer.len() - 1;
    bad_footer[last] ^= 1;
    let mut bad_index = pack.bytes().to_vec();
    let index_start = usize::try_from(u64::from_le_bytes(
        pack.bytes()[pack.bytes().len() - 16..pack.bytes().len() - 8]
            .try_into()
            .expect("fixture footer"),
    ))
    .expect("fixture offset");
    bad_index[index_start + 12] ^= 1;
    let missing_footer = pack.bytes()[..pack.bytes().len() - FOOTER_SIZE].to_vec();
    let missing_index = pack.bytes()[..index_start].to_vec();
    for damaged in [bad_footer, bad_index, missing_footer, missing_index] {
        assert!(matches!(
            PackReader::recover(&damaged),
            Err(PackError::RecoveryUnsupported(_))
        ));
    }
    Ok(())
}

#[test]
fn index_rebuild_rejects_conflicting_pack_ids_and_malformed_shard_records() -> Result<(), PackError>
{
    let first = data_pack(21, &[b"first"])?;
    let conflicting = data_pack(21, &[b"second"])?;
    let first_index = PackIndexSnapshot::decode(first.index_object(), 1)?;
    let conflicting_index = PackIndexSnapshot::decode(conflicting.index_object(), 1)?;
    let hash = *first_index.entries()[0].hash();
    assert_error!(
        MergedShard::rebuild(
            hash[0],
            1,
            &[first_index.clone(), conflicting_index],
            &BTreeSet::new(),
            None,
            &BTreeSet::new()
        ),
        Err(PackError::Generation)
    );
    let shard = MergedShard::rebuild(
        hash[0],
        1,
        &[first_index],
        &BTreeSet::new(),
        None,
        &BTreeSet::new(),
    )?;
    for (offset, byte) in [(12 + 64, 3), (12 + 65, 7), (12 + 66, 2), (12 + 67, 1)] {
        let mut malformed = shard.encode();
        malformed[offset] = byte;
        assert!(MergedShard::decode(&malformed, 1, hash[0]).is_err());
    }
    assert!(MergedShard::decode(&shard.encode(), 1, hash[0].wrapping_add(1)).is_err());
    let mut huge_count = shard.encode();
    huge_count[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(MergedShard::decode(&huge_count, 1, hash[0]).is_err());
    Ok(())
}

#[test]
fn pack_native_codecs_verify_raw_zstd_and_authoritative_dictionary_digest() -> Result<(), PackError>
{
    let profile = terrane_core::chunking::ChunkProfile::cdc_1m([0; 32]);
    let raw = b"raw chunk".to_vec();
    let zstd_plaintext = vec![b'z'; 8192];
    let dictionary = b"dictionary words shared across independently compressed chunks".repeat(64);
    let dictionary_plaintext =
        b"dictionary words shared across independently compressed chunks".repeat(128);
    let dictionary_hash = digest(EntryKind::Chunk, &dictionary)?;
    let dictionaries = BTreeMap::from([(dictionary_hash, dictionary)]);
    let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
    let mut raw_encoded = vec![0];
    raw_encoded.extend_from_slice(&raw);
    let zstd_encoded = crate::codec::encode_chunk(&zstd_plaintext, profile.maximum(), 3, None)?;
    let dictionary_encoded = crate::codec::encode_chunk(
        &dictionary_plaintext,
        profile.maximum(),
        3,
        dictionaries.get(&dictionary_hash).map(Vec::as_slice),
    )?;
    assert_eq!(zstd_encoded[0], 1);
    assert_eq!(dictionary_encoded[0], 2);
    assert_eq!(&dictionary_encoded[1..33], &dictionary_hash);
    let bodies = [
        (raw, raw_encoded),
        (zstd_plaintext, zstd_encoded),
        (dictionary_plaintext, dictionary_encoded),
    ];
    let mut writer = PackWriter::new(PackId::from_random_bytes([22; 16]), PackClass::Data, true);
    for (plaintext, encoded) in &bodies {
        writer.append_chunk(
            digest(EntryKind::Chunk, plaintext)?,
            encoded,
            plaintext.len() as u32,
            0,
            &decoder,
        )?;
    }
    let pack = writer.seal()?;
    let reader = PackReader::open(pack.bytes())?;
    for (plaintext, _) in &bodies {
        assert_eq!(
            reader.read(
                EntryKind::Chunk,
                &digest(EntryKind::Chunk, plaintext)?,
                &decoder
            )?,
            *plaintext
        );
    }
    let dictionary_chunk_hash = digest(EntryKind::Chunk, &bodies[2].0)?;
    assert!(matches!(
        reader.read(
            EntryKind::Chunk,
            &dictionary_chunk_hash,
            &NativeBodyDecoder::without_dictionaries(&profile)
        ),
        Err(PackError::Native(
            crate::codec::FrameError::MissingDictionary
        ))
    ));
    let wrong_dictionary = BTreeMap::from([(dictionary_hash, b"wrong dictionary".to_vec())]);
    assert!(matches!(
        reader.read(
            EntryKind::Chunk,
            &dictionary_chunk_hash,
            &NativeBodyDecoder::new(&profile, &wrong_dictionary)
        ),
        Err(PackError::Native(crate::codec::FrameError::WrongDictionary))
    ));
    Ok(())
}

#[test]
fn pack_native_codecs_reject_frame_length_identity_and_reserved_field_corruption()
-> Result<(), PackError> {
    let profile = terrane_core::chunking::ChunkProfile::cdc_1m([0; 32]);
    let decoder = NativeBodyDecoder::without_dictionaries(&profile);
    let plaintext = vec![0x2a; 8192];
    let hash = digest(EntryKind::Chunk, &plaintext)?;
    let encoded = crate::codec::encode_chunk(&plaintext, profile.maximum(), 3, None)?;
    let mut writer = PackWriter::new(PackId::from_random_bytes([23; 16]), PackClass::Data, true);
    assert!(matches!(
        writer.append_chunk([0; 32], &encoded, plaintext.len() as u32, 0, &decoder),
        Err(PackError::Native(crate::codec::FrameError::Identity(_)))
    ));
    assert_error!(
        writer.append_chunk(hash, &encoded, plaintext.len() as u32, 1, &decoder),
        Err(PackError::Reserved)
    );
    assert!(
        writer
            .append_chunk(hash, &encoded, profile.maximum() as u32 + 1, 0, &decoder)
            .is_err()
    );
    let mut concatenated = encoded.clone();
    concatenated.extend_from_slice(&encoded[1..]);
    assert!(matches!(
        writer.append_chunk(hash, &concatenated, plaintext.len() as u32, 0, &decoder),
        Err(PackError::Native(crate::codec::FrameError::InvalidFrame))
    ));
    writer.append_chunk(hash, &encoded, plaintext.len() as u32, 0, &decoder)?;
    let pack = writer.seal()?;
    let reader = PackReader::open(pack.bytes())?;
    let mut entries = reader.entries().to_vec();
    entries[0].plaintext_len += 1;
    let forged = replace_index(&pack, &entries);
    let forged_reader = PackReader::open(&forged)?;
    assert!(matches!(
        forged_reader.read(EntryKind::Chunk, &hash, &decoder),
        Err(PackError::Native(
            crate::codec::FrameError::ContentSizeMismatch
        ))
    ));
    Ok(())
}

#[cfg(not(feature = "send"))]
#[test]
fn pack_single_writer_publication_accepts_thread_local_runtime() -> Result<(), PackError> {
    struct LocalPublisher(std::rc::Rc<std::cell::RefCell<Vec<String>>>);

    #[async_trait::async_trait(?Send)]
    impl PackPublisher for LocalPublisher {
        type Error = PackError;

        async fn put_immutable(&self, key: &str, _bytes: &[u8]) -> Result<(), Self::Error> {
            self.0.borrow_mut().push(key.to_owned());
            Ok(())
        }
    }

    let pack = data_pack(24, &[b"thread-local publication"])?;
    let writes = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let publisher = LocalPublisher(writes.clone());
    let receipt = run_ready(pack.publish(&publisher))?;

    assert_eq!(receipt.id(), pack.header().id());
    assert_eq!(
        *writes.borrow(),
        [receipt.id().pack_key(), receipt.id().index_key()]
    );
    Ok(())
}
