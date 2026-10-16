//! Checks bounded parsers and real positioned-file reads, not native recovery proof.
//!
//! These tests never fabricate a preparation, publisher session, quota receipt
//! or repaired/adopted object. Native recovery acceptance needs the separately
//! composed real owner, registered publisher and quota helper in its VM fixture.

use super::{
    files::{read_bounded, same_file, verify_read_hash},
    verification::bounded_pack,
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use terrane::{
    host::cache::{HostReadLimits, reconstruct_pack_index},
    pack::{EntryKind, PackClass, PackId, PackWriter},
    repository::MetadataValidator,
};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
            &MetadataValidator::new(profile),
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
