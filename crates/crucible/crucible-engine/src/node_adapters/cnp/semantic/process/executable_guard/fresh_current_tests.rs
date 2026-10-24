//! Checks complete positional hashing independently of native custody grants.
//!
//! File fixtures exercise only the actual byte-measurement helper. They never
//! authenticate a kernel identity or create a current native reservation.

use super::*;
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

struct DataFile {
    path: PathBuf,
    file: File,
}

impl DataFile {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "crucible-complete-hash-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut fixture = Self { path, file };
        fixture.file.write_all(bytes).unwrap();
        fixture
    }
}

impl Drop for DataFile {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_file(&self.path);
    }
}

fn byte_measurement_fixture(path: &Path, expected: ContentRef) -> OriginalExecutable {
    let original = LinuxReadLeaseFile::open(path, None).unwrap();
    let revision = FileRevision::read(original.file().metadata().unwrap()).unwrap();
    OriginalExecutable {
        creator: std::process::id(),
        thread: std::thread::current().id(),
        process_path: path.to_owned(),
        original_target: path.to_owned(),
        original,
        revision,
        expected,
        revoked: Cell::new(false),
        bounded_birth: true,
    }
}

#[test]
fn complete_hash_matches_canonical_across_banks_and_rejects_changed_tail() {
    let bytes: Vec<u8> = (0..(256 * 1024 + 17))
        .map(|offset| (offset % 251) as u8)
        .collect();
    let expected = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
    let mut fixture = DataFile::new(&bytes);
    let executable = byte_measurement_fixture(&fixture.path, expected.clone());

    for size in [1, 8192, EXECUTABLE_STREAM_BYTES] {
        let mut bank = vec![0; size];
        executable.measure_fresh_bytes_in_bank(&mut bank).unwrap();
    }
    assert_eq!(executable.expected, expected);

    // A change beyond both complete chunk boundaries must be observed, even
    // though the file's identity and total length remain unchanged.
    fixture.file.seek(SeekFrom::End(-1)).unwrap();
    fixture
        .file
        .write_all(&[bytes[bytes.len() - 1] ^ 1])
        .unwrap();
    for size in [8192, EXECUTABLE_STREAM_BYTES] {
        let mut bank = vec![0; size];
        assert_eq!(
            executable.measure_fresh_bytes_in_bank(&mut bank),
            Err(RuntimeError::ForeignAuthority),
        );
    }
}

#[test]
fn selected_stream_heap_capacity_is_fully_quoted() {
    let scratch = FreshCurrentScratch::for_original_native_startup().unwrap();
    assert_eq!(scratch.bytes.len(), EXECUTABLE_STREAM_BYTES);
    assert_eq!(scratch.bytes.capacity(), EXECUTABLE_STREAM_BYTES);
    assert!(
        FreshCurrentScratch::declared_scratch_data()
            >= size_of::<FreshCurrentScratch>() + scratch.bytes.capacity(),
    );
    assert_eq!(
        scratch.link.len(),
        OriginalExecutable::original_native_startup_link_bytes(),
    );
}

/// Runs explicitly against a caller-selected local image; all samples go to stdout.
#[test]
#[ignore = "requires CRUCIBLE_EXECUTABLE_STREAM_BENCHMARK_INPUT"]
fn complete_hash_bank_benchmark() {
    let path = PathBuf::from(
        std::env::var_os("CRUCIBLE_EXECUTABLE_STREAM_BENCHMARK_INPUT")
            .expect("set a local image path for the explicit component benchmark"),
    );
    let input = std::fs::read(&path).unwrap();
    assert!(!input.is_empty());
    let expected = canonical::content_ref(&input, "application/octet-stream").unwrap();
    drop(input);
    let executable = byte_measurement_fixture(&path, expected);
    let mut baseline = vec![0; 8192];
    let mut candidate = vec![0; EXECUTABLE_STREAM_BYTES];

    // Warm both paths equally; allocate neither bank inside the measured call.
    executable
        .measure_fresh_bytes_in_bank(&mut baseline)
        .unwrap();
    executable
        .measure_fresh_bytes_in_bank(&mut candidate)
        .unwrap();
    println!(
        "component=complete-positional-hash bytes={} baseline_bank={} candidate_bank={} digest={} excludes=construction,kernel,namespace,startup",
        executable.revision.length,
        baseline.len(),
        candidate.len(),
        executable.expected.hash.digest,
    );

    for pair in 0..30 {
        let order = if pair % 2 == 0 { [0, 1] } else { [1, 0] };
        for selected in order {
            let bank = if selected == 0 {
                &mut baseline
            } else {
                &mut candidate
            };
            let started = Instant::now();
            executable.measure_fresh_bytes_in_bank(bank).unwrap();
            let elapsed = started.elapsed();
            println!(
                "pair={pair} bank={} nanoseconds={}",
                bank.len(),
                elapsed.as_nanos(),
            );
        }
    }
}
