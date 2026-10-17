//! Direct source admission and streamed byte-identity regressions.

use std::io::{Seek, SeekFrom, Write};

use futures_util::{StreamExt, TryStreamExt};
use sha2::Digest as _;

use super::*;

fn source_file(bytes: &[u8]) -> std::fs::File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

async fn collect_part(part: &PartSource) -> Vec<u8> {
    part.stream()
        .try_fold(Vec::new(), |mut collected, bytes| async move {
            assert!(bytes.len() <= SOURCE_CHUNK_BYTES);
            collected.extend_from_slice(&bytes);
            Ok(collected)
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn source_stream_uses_bounded_chunks_and_replays_exact_range() {
    let bytes: Vec<u8> = (0..5 * SOURCE_CHUNK_BYTES + 113)
        .map(|index| ((index * 13 + index / 263) % 251) as u8)
        .collect();
    let part_size = (2 * SOURCE_CHUNK_BYTES + 31) as u64;
    let source = AdmittedSource::admit(
        source_file(&bytes),
        bytes.len() as u64,
        &sha256(&bytes),
        part_size,
    )
    .await
    .unwrap();
    let part = source
        .prepare_part(2, part_size, part_size, PartChecksumAlgorithm::Sha256)
        .await
        .unwrap();

    assert_eq!(source.byte_size(), bytes.len() as u64);
    assert_eq!(source.sha256(), sha256(&bytes));
    assert_eq!(
        collect_part(&part).await,
        bytes[part_size as usize..2 * part_size as usize]
    );
    assert_eq!(
        collect_part(&part).await,
        bytes[part_size as usize..2 * part_size as usize]
    );
    let final_part = source
        .prepare_part(
            3,
            2 * part_size,
            bytes.len() as u64 - 2 * part_size,
            PartChecksumAlgorithm::Md5,
        )
        .await
        .unwrap();
    assert_eq!(
        collect_part(&final_part).await,
        bytes[2 * part_size as usize..]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_parallel_parts_and_retries_do_not_share_offsets() {
    let bytes: Vec<u8> = (0..12 * SOURCE_CHUNK_BYTES)
        .map(|index| ((index * 7 + index / 127) % 251) as u8)
        .collect();
    let source = AdmittedSource::admit(
        source_file(&bytes),
        bytes.len() as u64,
        &sha256(&bytes),
        SOURCE_CHUNK_BYTES as u64,
    )
    .await
    .unwrap();
    let mut prepared = Vec::new();
    for index in 0..12 {
        prepared.push(
            source
                .prepare_part(
                    index + 1,
                    u64::from(index) * SOURCE_CHUNK_BYTES as u64,
                    SOURCE_CHUNK_BYTES as u64,
                    PartChecksumAlgorithm::Md5,
                )
                .await
                .unwrap(),
        );
    }
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(25));
    let mut tasks = Vec::new();
    for (index, part) in prepared.into_iter().enumerate() {
        for _ in 0..2 {
            let part = part.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                (index, collect_part(&part).await)
            }));
        }
    }

    barrier.wait().await;
    for task in tasks {
        let (index, actual) = task.await.unwrap();
        assert_eq!(
            actual,
            bytes[index * SOURCE_CHUNK_BYTES..(index + 1) * SOURCE_CHUNK_BYTES]
        );
    }
}

#[tokio::test]
async fn source_provider_checksums_match_independent_known_vectors() {
    let source = AdmittedSource::admit(source_file(b"abc"), 3, &sha256(b"abc"), 8)
        .await
        .unwrap();
    let md5 = source
        .prepare_part(1, 0, 3, PartChecksumAlgorithm::Md5)
        .await
        .unwrap();
    let sha = source
        .prepare_part(1, 0, 3, PartChecksumAlgorithm::Sha256)
        .await
        .unwrap();

    assert_eq!(md5.identity().checksum.value, "kAFQmDzST7DWlj99KOF/cg==");
    assert_eq!(
        sha.identity().checksum.value,
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(collect_part(&md5).await, b"abc");
    assert_eq!(collect_part(&sha).await, b"abc");
}

#[tokio::test]
async fn source_change_after_grant_identity_refuses_final_chunk_without_value_leak() {
    const SECRET: &[u8] = b"private-provider-credential-content";
    let original = vec![b'a'; SECRET.len()];
    let file = source_file(&original);
    let mut writer = file.try_clone().unwrap();
    let source = AdmittedSource::admit(file, original.len() as u64, &sha256(&original), 1024)
        .await
        .unwrap();
    let part = source
        .prepare_part(1, 0, original.len() as u64, PartChecksumAlgorithm::Md5)
        .await
        .unwrap();

    writer.seek(SeekFrom::Start(0)).unwrap();
    writer.write_all(SECRET).unwrap();
    let error = source
        .prepare_part(1, 0, original.len() as u64, PartChecksumAlgorithm::Md5)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SourceError::IdentityConflict | SourceError::DigestConflict
    ));
    let error = part.stream().next().await.unwrap().unwrap_err();
    let rendered = format!("{error:?} {error} {part:?} {source:?}");
    assert!(!rendered.contains(std::str::from_utf8(SECRET).unwrap()));
    assert!(rendered.contains("identity changed") || rendered.contains("digest conflicts"));
}

#[tokio::test]
async fn source_truncation_refuses_stream_and_prepare() {
    let file = source_file(b"abcdefgh");
    let writer = file.try_clone().unwrap();
    let source = AdmittedSource::admit(file, 8, &sha256(b"abcdefgh"), 8)
        .await
        .unwrap();
    let part = source
        .prepare_part(1, 0, 8, PartChecksumAlgorithm::Sha256)
        .await
        .unwrap();

    writer.set_len(3).unwrap();
    assert!(part.stream().next().await.unwrap().is_err());
    assert_eq!(
        source
            .prepare_part(1, 0, 8, PartChecksumAlgorithm::Sha256)
            .await
            .unwrap_err(),
        SourceError::SizeConflict
    );
}

#[tokio::test]
async fn source_admission_and_geometry_reject_before_transfer() {
    assert_eq!(
        AdmittedSource::admit(source_file(b"abc"), 4, &sha256(b"abc"), 8)
            .await
            .unwrap_err(),
        SourceError::SizeConflict
    );
    assert_eq!(
        AdmittedSource::admit(source_file(b"abc"), 3, &sha256(b"def"), 8)
            .await
            .unwrap_err(),
        SourceError::DigestConflict
    );
    assert_eq!(
        AdmittedSource::admit(
            source_file(b""),
            16 * 1024 * 1024 * 1024 + 1,
            &sha256(b""),
            8 * 1024 * 1024
        )
        .await
        .unwrap_err(),
        SourceError::InvalidDeclaration
    );
    let source = AdmittedSource::admit(source_file(b"abc"), 3, &sha256(b"abc"), 8)
        .await
        .unwrap();

    for (number, offset, length) in [
        (0, 0, 1),
        (10_001, 0, 1),
        (1, 0, 0),
        (1, 2, 2),
        (1, u64::MAX, 1),
    ] {
        assert_eq!(
            source
                .prepare_part(number, offset, length, PartChecksumAlgorithm::Md5)
                .await
                .unwrap_err(),
            SourceError::InvalidRange
        );
    }
}

#[test]
fn source_wave_counts_catalogues_and_descriptors_without_serializing_large_files() {
    let mut wave = SourceWaveBudget::default();
    let maximum_size = 16 * 1024 * 1024 * 1024;
    for _ in 0..64 {
        assert!(wave.reserve(maximum_size, 8 * 1024 * 1024).unwrap());
    }
    assert_eq!(wave.catalogue_bytes(), 64 * 2048 * 48);
    assert!(wave.catalogue_bytes() < 32 * 1024 * 1024);
    assert!(!wave.reserve(1, 8 * 1024 * 1024).unwrap());
    let unchanged = wave.catalogue_bytes();
    assert!(wave.reserve(maximum_size, 1).is_err());
    assert_eq!(wave.catalogue_bytes(), unchanged);

    let mut maximum_parts = SourceWaveBudget::default();
    for _ in 0..64 {
        assert!(maximum_parts.reserve(10_000 * 1024, 1024).unwrap());
    }
    assert_eq!(maximum_parts.catalogue_bytes(), 64 * 10_000 * 48);
    assert!(maximum_parts.catalogue_bytes() < 32 * 1024 * 1024);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_large_descriptor_sources_stream_concurrently_with_bounded_chunks() {
    const BYTES: usize = 17 * 1024 * 1024;
    let mut wave = SourceWaveBudget::default();
    let mut parts = Vec::new();
    for index in 0..8_u8 {
        assert!(wave.reserve(BYTES as u64, BYTES as u64).unwrap());
        let mut file = tempfile::tempfile().unwrap();
        let buffer = [index; SOURCE_CHUNK_BYTES];
        let mut expected = sha2::Sha256::new();
        for _ in 0..BYTES / SOURCE_CHUNK_BYTES {
            file.write_all(&buffer).unwrap();
            expected.update(buffer);
        }
        let sha = hex::encode(expected.finalize());
        let source = AdmittedSource::admit(file, BYTES as u64, &sha, BYTES as u64)
            .await
            .unwrap();
        parts.push((
            source
                .prepare_part(1, 0, BYTES as u64, PartChecksumAlgorithm::Sha256)
                .await
                .unwrap(),
            sha,
        ));
    }
    assert_eq!(wave.catalogue_bytes(), 8 * 48);
    // All eight descriptors exceed the old128 MiB total-source wave limit.
    assert!(8 * BYTES > 128 * 1024 * 1024);
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for (part, expected) in parts {
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let mut stream = part.stream();
            let first = stream.next().await.unwrap().unwrap();
            assert_eq!(first.len(), SOURCE_CHUNK_BYTES);
            // Every file reaches its first chunk before any consumes its rest.
            barrier.wait().await;
            let mut digest = sha2::Sha256::new();
            digest.update(&first);
            let mut count = first.len();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.unwrap();
                assert!(chunk.len() <= SOURCE_CHUNK_BYTES);
                digest.update(&chunk);
                count += chunk.len();
            }
            assert_eq!(count, BYTES);
            assert_eq!(hex::encode(digest.finalize()), expected);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn descriptor_inode_replacement_and_midstream_mutation_never_adopt_new_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    let mut original = std::fs::File::create(&path).unwrap();
    let buffer = vec![b'a'; 2 * SOURCE_CHUNK_BYTES];
    original.write_all(&buffer).unwrap();
    drop(original);
    let file = std::fs::File::open(&path).unwrap();
    let source = AdmittedSource::admit(
        file,
        buffer.len() as u64,
        &sha256(&buffer),
        buffer.len() as u64,
    )
    .await
    .unwrap();
    let part = source
        .prepare_part(1, 0, buffer.len() as u64, PartChecksumAlgorithm::Md5)
        .await
        .unwrap();
    let mut stream = part.stream();
    assert_eq!(
        stream.next().await.unwrap().unwrap().as_ref(),
        &buffer[..SOURCE_CHUNK_BYTES]
    );
    let mut writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    writer
        .seek(SeekFrom::Start(SOURCE_CHUNK_BYTES as u64))
        .unwrap();
    writer.write_all(&vec![b'b'; SOURCE_CHUNK_BYTES]).unwrap();
    assert!(stream.next().await.unwrap().is_err());
    assert_eq!(
        source
            .prepare_part(1, 0, buffer.len() as u64, PartChecksumAlgorithm::Md5)
            .await
            .unwrap_err(),
        SourceError::IdentityConflict
    );

    std::fs::rename(&path, directory.path().join("old-inode")).unwrap();
    std::fs::write(&path, vec![b'c'; buffer.len()]).unwrap();
    assert_eq!(
        source
            .prepare_part(1, 0, buffer.len() as u64, PartChecksumAlgorithm::Md5)
            .await
            .unwrap_err(),
        SourceError::IdentityConflict
    );
    assert_eq!(source.sha256(), sha256(&buffer));
}

#[cfg(unix)]
#[test]
fn source_opener_refuses_fifo_without_a_writer_and_preserves_selected_symlinks() {
    use std::os::unix::fs::OpenOptionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("source.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let selected = fifo.clone();
    let worker = std::thread::spawn(move || {
        send.send(open_regular_source_file(&selected)).unwrap();
    });

    let result = receive.recv_timeout(std::time::Duration::from_secs(1));
    if result.is_err() {
        // Unblock the old defective implementation so a failing regression
        // cannot leave the test process waiting on its reader thread.
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(&fifo);
    }
    worker.join().unwrap();
    assert!(matches!(result.unwrap(), Err(SourceError::SizeConflict)));

    let original = directory.path().join("original");
    let selected = directory.path().join("selected");
    std::fs::write(&original, b"original selected bytes").unwrap();
    std::os::unix::fs::symlink(&original, &selected).unwrap();
    let file = open_regular_source_file(&selected).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 23);
    assert!(matches!(
        open_regular_source_file(directory.path()),
        Err(SourceError::SizeConflict)
    ));
}
