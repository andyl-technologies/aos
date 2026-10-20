//! Checks bounded parsers and real positioned-file reads, not native recovery proof.
//!
//! These tests never fabricate a preparation, publisher session, quota receipt
//! or repaired/adopted object. Native recovery acceptance needs the separately
//! composed real owner, registered publisher and quota helper in its VM fixture.

use super::{
    ContentCustody,
    files::{invalid, read_bounded, same_file, verify_read_hash},
    manifest::{
        check_key, manifest_from_pack, manifest_residences, verify_file_plaintext, verify_plaintext,
    },
    verification::{bounded_pack, bounded_standalone_length, dictionary_from_pack},
};
use crate::publisher_local::wire::{BodyKey, BodyKind};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    os::unix::fs::{FileExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Descriptor, IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_sdk::{
    host::{
        cache::{HostReadLimits, reconstruct_pack_index},
        publication::{PublicationClaim, PublicationRecipe},
    },
    pack::{EntryKind, NativeBodyDecoder, PackClass, PackId, PackWriter},
    repository::MetadataValidator,
    store::ByteRange,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn retained_manifest_inspection_requires_the_complete_manifest_key() -> TestResult {
    let (_, _, claim) = manifest_claim()?;
    let key = BodyKey {
        kind: BodyKind::Sealed as i32,
        descriptor: claim.descriptor().encode(),
        ..Default::default()
    };
    check_key(&key, &claim)?;
    for changed in [
        BodyKey {
            codec: 1,
            ..key.clone()
        },
        BodyKey {
            pack_id: vec![0; 16],
            ..key.clone()
        },
        BodyKey {
            kind: BodyKind::Pack as i32,
            ..key.clone()
        },
        BodyKey {
            descriptor: Vec::new(),
            ..key.clone()
        },
    ] {
        assert!(check_key(&changed, &claim).is_err());
    }
    Ok(())
}

#[test]
fn actual_metadata_pack_requires_the_exact_original_manifest_record_range() -> TestResult {
    let (profile, _, claim) = manifest_claim()?;
    let canonical = claim
        .canonical_manifest()
        .ok_or("missing canonical fixture")?;
    let id = PackId::from_random_bytes([63; 16]);
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    writer.append_raw(EntryKind::Manifest, canonical)?;
    let pack = writer.seal()?;
    let limits = HostReadLimits {
        max_allocation_bytes: 4096,
    };
    let reader = bounded_pack(pack.bytes(), limits)?;
    let record = &reader.entries()[0];
    let range = ByteRange {
        start: record.offset(),
        length: u64::from(record.body_len()),
    };

    let verified = manifest_from_pack(pack.bytes(), &claim, range, &profile, limits)?;

    assert_eq!(verified.descriptor(), claim.descriptor());
    assert_eq!(verified.canonical_manifest(), Some(canonical));
    assert!(
        manifest_from_pack(
            pack.bytes(),
            &claim,
            ByteRange {
                start: range.start + 1,
                ..range
            },
            &profile,
            limits
        )
        .is_err()
    );
    assert!(
        manifest_from_pack(
            pack.bytes(),
            &claim,
            ByteRange {
                length: range.length - 1,
                ..range
            },
            &profile,
            limits
        )
        .is_err()
    );
    assert!(
        manifest_from_pack(
            pack.bytes(),
            &claim,
            range,
            &profile,
            HostReadLimits {
                max_allocation_bytes: pack.bytes().len() - 1
            }
        )
        .is_err()
    );

    let mut changed = pack.bytes().to_vec();
    changed[usize::try_from(range.start)?] ^= 1;
    assert!(manifest_from_pack(&changed, &claim, range, &profile, limits).is_err());
    Ok(())
}

#[test]
fn retained_manifest_plaintext_limit_is_checked_before_any_body_read() -> TestResult {
    struct NoRead;

    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("oversized manifest chunk reached plaintext IO")
        }
    }

    let (_, _, claim) = manifest_claim()?;
    assert!(
        claim
            .canonical_manifest()
            .ok_or("missing canonical fixture")?
            .len()
            < 1024
    );

    let error = verify_plaintext(&claim, &mut NoRead, 1024)
        .err()
        .ok_or("oversized plaintext accepted")?;

    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    Ok(())
}

#[test]
fn retained_manifest_verifies_full_plaintext_and_preserves_its_metadata_identity() -> TestResult {
    let (profile, plaintext, claim) = manifest_claim()?;
    verify_plaintext(&claim, &mut Cursor::new(&plaintext), plaintext.len())?;
    assert_ne!(
        claim.descriptor().digest(),
        TERRANE_V1
            .calculate(IdentityKind::Chunk, &plaintext)?
            .digest()
    );

    let mut changed = plaintext.clone();
    changed[0] ^= 1;
    assert!(verify_plaintext(&claim, &mut Cursor::new(&changed), changed.len()).is_err());
    let mut reordered = plaintext.clone();
    reordered.rotate_left(profile.minimum());
    assert!(verify_plaintext(&claim, &mut Cursor::new(&reordered), reordered.len()).is_err());
    let mut trailing = plaintext.clone();
    trailing.push(0);
    assert!(verify_plaintext(&claim, &mut Cursor::new(&trailing), trailing.len()).is_err());
    assert!(
        verify_plaintext(
            &claim,
            &mut Cursor::new(&plaintext[..plaintext.len() - 1]),
            plaintext.len()
        )
        .is_err()
    );

    let mut wrong_hash = Manifest::decode(
        claim
            .canonical_manifest()
            .ok_or("missing canonical fixture")?,
        &profile,
    )?;
    wrong_hash.hashes.insert("blake3".into(), vec![0; 32]);
    let canonical = wrong_hash.encode(&profile)?;
    let identity = TERRANE_V1.calculate(IdentityKind::Manifest, &canonical)?;
    let object = Descriptor::from_identity(&TERRANE_V1, &identity, &canonical)?;
    let wrong_hash = PublicationClaim::new(
        "public".into(),
        PublicationRecipe::Manifest {
            object,
            canonical_manifest: canonical,
        },
        &profile,
    )?;
    assert!(verify_plaintext(&wrong_hash, &mut Cursor::new(&plaintext), plaintext.len()).is_err());
    Ok(())
}

#[test]
fn retained_manifest_plaintext_uses_positioned_reads_without_changing_shared_cursor() -> TestResult
{
    let (_, plaintext, claim) = manifest_claim()?;
    let scratch = Scratch::new()?;
    let mut writer = &scratch.file;
    writer.write_all(&plaintext)?;
    writer.seek(SeekFrom::Start(17))?;

    verify_file_plaintext(&claim, &scratch.file, plaintext.len())?;

    assert_eq!(writer.stream_position()?, 17);
    Ok(())
}

#[test]
fn retained_manifest_residences_preserve_order_offsets_and_manifest_identity() -> TestResult {
    let (profile, plaintext, claim) = manifest_claim()?;
    let records = manifest_residences(&claim, 4096)?;

    assert_eq!(records.len(), 2);
    assert_eq!(
        (records[0].offset, records[0].length),
        (0, profile.minimum() as u64)
    );
    assert_eq!(
        (records[1].offset, records[1].length),
        (profile.minimum() as u64, 37)
    );
    assert_eq!(records[0].object, records[1].object);
    let object: String = claim
        .descriptor()
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(records[0].object, object);
    assert_ne!(records[0].chunk, records[1].chunk);
    assert_eq!(
        records[1].offset + records[1].length,
        plaintext.len() as u64
    );
    assert_eq!(
        manifest_residences(&claim, 1)
            .err()
            .ok_or("over-budget residences accepted")?
            .kind(),
        io::ErrorKind::OutOfMemory
    );
    Ok(())
}

/// Uses real canonical bytes to test pure verification, never native custody.
fn manifest_claim() -> Result<(ChunkProfile, Vec<u8>, PublicationClaim), Box<dyn std::error::Error>>
{
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let mut plaintext = vec![73; profile.minimum() + 37];
    plaintext[profile.minimum()..].fill(81);
    let chunks = plaintext
        .chunks(profile.minimum())
        .map(|bytes| {
            Ok::<_, Box<dyn std::error::Error>>(ChunkRef {
                digest: TERRANE_V1
                    .calculate(IdentityKind::Chunk, bytes)?
                    .terrane_v1_digest()?,
                length: bytes.len() as u64,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes: BTreeMap::from([(
            "blake3".into(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    };
    let canonical = manifest.encode(&profile)?;
    let identity = TERRANE_V1.calculate(IdentityKind::Manifest, &canonical)?;
    let object = Descriptor::from_identity(&TERRANE_V1, &identity, &canonical)?;
    let claim = PublicationClaim::new(
        "public".into(),
        PublicationRecipe::Manifest {
            object,
            canonical_manifest: canonical,
        },
        &profile,
    )?;
    Ok((profile, plaintext, claim))
}

#[test]
fn compressed_standalone_plaintext_is_bounded_before_decode() -> TestResult {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let plaintext = vec![b'x'; 65536];
    let budget = 1024;
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &plaintext)?;
    for dictionary in [None, Some(b"independent recovery dictionary".as_slice())] {
        let encoded =
            terrane_sdk::codec::encode_chunk(&plaintext, profile.maximum(), 3, dictionary)?;
        assert_eq!(encoded[0], if dictionary.is_some() { 2 } else { 1 });
        assert!(encoded.len() < budget);

        let error = bounded_standalone_length(&encoded, &profile, budget)
            .err()
            .ok_or("oversized compressed plaintext was accepted")?;

        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(
            bounded_standalone_length(&encoded, &profile, plaintext.len())?,
            plaintext.len()
        );
        assert_eq!(
            terrane_sdk::codec::decode_verified(
                &encoded,
                plaintext.len(),
                &profile,
                true,
                &identity,
                dictionary
            )?
            .plaintext(),
            plaintext
        );
    }
    Ok(())
}

#[test]
fn compressed_pack_dictionary_respects_remaining_plaintext_budget() -> TestResult {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let plaintext = vec![b'd'; 65536];
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, &plaintext)?;
    let digest = identity.terrane_v1_digest()?;
    let encoded = terrane_sdk::codec::encode_chunk(&plaintext, profile.maximum(), 3, None)?;
    let mut writer = PackWriter::new(PackId::from_random_bytes([45; 16]), PackClass::Data, true);
    writer.append_chunk(
        digest,
        &encoded,
        plaintext.len() as u32,
        0,
        &NativeBodyDecoder::without_dictionaries(&profile),
    )?;
    let pack = writer.seal()?;
    let budget = 1024;
    assert!(pack.bytes().len() < budget);
    let reader = bounded_pack(
        pack.bytes(),
        HostReadLimits {
            max_allocation_bytes: budget,
        },
    )?;

    let error = dictionary_from_pack(&profile, &reader, &digest, budget)
        .err()
        .ok_or("oversized packed dictionary was decoded")?;

    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(
        dictionary_from_pack(&profile, &reader, &digest, plaintext.len())?,
        Some(plaintext)
    );
    Ok(())
}

#[test]
fn configured_custody_rejects_rebased_owner_and_group() -> TestResult {
    let scratch = Scratch::new()?;
    let metadata = scratch.file.metadata()?;
    let custody = ContentCustody {
        uid: metadata.uid(),
        gid: metadata.gid(),
        directory_mode: 0o2770,
    };
    custody.check(&metadata, false)?;

    let changed_owner = ContentCustody {
        uid: custody.uid.wrapping_add(1),
        ..custody
    };
    let changed_group = ContentCustody {
        gid: custody.gid.wrapping_add(1),
        ..custody
    };

    assert!(changed_owner.check(&metadata, false).is_err());
    assert!(changed_group.check(&metadata, false).is_err());
    Ok(())
}

#[test]
fn configured_directory_mode_is_not_rebased_to_current_metadata() -> TestResult {
    let directory = Directory::new()?;
    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o2770))?;
    let metadata = fs::metadata(&directory.path)?;
    let custody = ContentCustody {
        uid: metadata.uid(),
        gid: metadata.gid(),
        directory_mode: 0o2770,
    };
    custody.check(&metadata, true)?;

    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o2750))?;

    assert!(
        custody
            .check(&fs::metadata(&directory.path)?, true)
            .is_err()
    );
    Ok(())
}

#[test]
fn unresolved_verification_failure_preserves_its_typed_source() -> TestResult {
    let original = io::Error::new(io::ErrorKind::NotFound, "missing actual dependency");
    let error = invalid(original);

    let source = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<io::Error>())
        .ok_or("typed verification source was discarded")?;
    assert_eq!(source.kind(), io::ErrorKind::NotFound);
    Ok(())
}

#[test]
fn positioned_recovery_read_preserves_the_actual_open_description_cursor() -> TestResult {
    let scratch = Scratch::new()?;
    let mut writer = &scratch.file;
    writer.write_all(b"actual retained source bytes")?;
    writer.seek(SeekFrom::Start(7))?;
    let before = scratch.file.metadata()?;

    let bytes = read_bounded(&scratch.file, 128)?;

    assert_eq!(bytes, b"actual retained source bytes");
    assert_eq!(writer.stream_position()?, 7);
    assert!(same_file(&before, &scratch.file.metadata()?));
    Ok(())
}

#[test]
fn oversized_actual_inode_is_rejected_before_encoded_allocation() -> TestResult {
    let scratch = Scratch::new()?;
    scratch.file.set_len(1024 * 1024)?;

    let error = read_bounded(&scratch.file, 1024)
        .err()
        .ok_or("oversized read succeeded")?;

    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    Ok(())
}

#[test]
fn equal_sized_path_replacement_does_not_match_retained_inode() -> TestResult {
    let scratch = Scratch::new()?;
    let mut writer = &scratch.file;
    writer.write_all(b"same length")?;
    let retained = scratch.file.metadata()?;
    fs::remove_file(&scratch.path)?;
    fs::write(&scratch.path, b"same length")?;

    assert!(!same_file(&retained, &fs::metadata(&scratch.path)?));
    assert_eq!(read_bounded(&scratch.file, 128)?, b"same length");
    Ok(())
}

#[test]
fn equal_sized_in_place_change_fails_actual_encoded_hash_recheck() -> TestResult {
    let scratch = Scratch::new()?;
    let original = b"verified encoded bytes";
    let replacement = b"modified encoded bytes";
    let mut writer = &scratch.file;
    writer.write_all(original)?;
    let expected = blake3::hash(original);
    verify_read_hash(&scratch.file, 128, expected)?;

    scratch.file.write_all_at(replacement, 0)?;

    assert_eq!(scratch.file.metadata()?.len(), original.len() as u64);
    assert_eq!(
        verify_read_hash(&scratch.file, 128, expected)
            .err()
            .ok_or("modified source revalidated")?
            .kind(),
        io::ErrorKind::InvalidData
    );
    Ok(())
}

#[test]
fn actual_pack_bytes_derive_exact_index_but_corrupt_body_never_does() -> TestResult {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let id = PackId::from_random_bytes([19; 16]);
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    writer.append_raw(EntryKind::Chunk, b"first independent recovery body")?;
    writer.append_raw(EntryKind::Chunk, b"second independent recovery body")?;
    let pack = writer.seal()?;
    let scratch = Scratch::new()?;
    let mut file_writer = &scratch.file;
    file_writer.write_all(pack.bytes())?;
    let actual = read_bounded(&scratch.file, 4096)?;
    let limits = HostReadLimits {
        max_allocation_bytes: 4096,
    };
    let reader = bounded_pack(&actual, limits)?;
    let derived = reconstruct_pack_index(
        &actual,
        id,
        &profile,
        &MetadataValidator::new(profile.clone()),
        &BTreeMap::new(),
        limits,
    )?;

    assert_eq!(derived.bytes(), pack.index_object());
    assert_eq!(
        derived.pack_identity(),
        &TERRANE_V1.calculate(IdentityKind::Pack, &actual)?
    );

    let offset = usize::try_from(reader.entries()[0].offset())?;
    let mut corrupt = actual;
    corrupt[offset + 1] ^= 1;
    assert!(bounded_pack(&corrupt, limits).is_ok());
    assert!(
        reconstruct_pack_index(
            &corrupt,
            id,
            &profile,
            &MetadataValidator::new(profile.clone()),
            &BTreeMap::new(),
            limits
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn structural_pack_allocation_is_bounded_before_decoded_records() -> TestResult {
    let id = PackId::from_random_bytes([23; 16]);
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    writer.append_raw(EntryKind::Chunk, b"bounded structural fixture")?;
    let pack = writer.seal()?;

    let failure = bounded_pack(
        pack.bytes(),
        HostReadLimits {
            max_allocation_bytes: pack.bytes().len() - 1,
        },
    )
    .err()
    .ok_or("over-budget pack parsed")?;
    assert_eq!(failure.kind(), io::ErrorKind::OutOfMemory);
    assert!(bounded_pack(&pack.bytes()[..20], HostReadLimits::default()).is_err());
    Ok(())
}

struct Scratch {
    path: PathBuf,
    file: File,
}

impl Scratch {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::var_os("TERRANE_HOST_CACHE_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        for _ in 0..128 {
            let path = base.join(format!(
                "terrane-recovery-inspection-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "recovery parser fixture names exhausted",
        ))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct Directory {
    path: PathBuf,
    _marker: Scratch,
}

impl Directory {
    fn new() -> io::Result<Self> {
        let marker = Scratch::new()?;
        let path = marker.path.with_extension("directory");
        fs::create_dir(&path)?;
        Ok(Self {
            path,
            _marker: marker,
        })
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}
