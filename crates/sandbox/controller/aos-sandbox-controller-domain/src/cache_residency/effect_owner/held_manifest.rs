//! Rechecks an original replayable physical owner with fixed streaming scratch.
//!
//! The caller retains its actual owner, original flock and previously validated
//! state. This module compares its original generation and complete manifest
//! head; it does not decode an unknown manifest or construct an owner from DATA.

use super::*;

// Buffering changes syscall count, never the admitted manifest extent. Every
// existing bounded manifest still streams through the same fixed allocation.
const STREAM_BYTES: usize = 64 * 1024;
const HEADER_BYTES: usize = 20;
const CHECKSUM_BYTES: usize = 32;

struct ManifestStream {
    buffer: [u8; STREAM_BYTES],
    header: [u8; HEADER_BYTES],
    checksum: [u8; CHECKSUM_BYTES],
    complete: Sha256,
    payload: Sha256,
    position: usize,
    payload_bytes: usize,
}

/// Prices the actual fixed streaming state; this supplies no currentness grant.
pub(crate) const fn original_recheck_scratch_bytes() -> usize {
    // The immediate ordinary adapter owns its retained layout while the
    // current stream is constructed. Selected persistent layouts are already
    // included in Runtime's actual inline worker; this also conservatively
    // covers their current stream/hash construction peak.
    std::mem::size_of::<(ManifestStreamOriginalsV1, ManifestStream, [u8; 1], Sha256)>()
}

// Only validate_held_snapshot calls this with its original validated owner
// after replayable-state refusal and native lock/name/root checks. Initial
// unknown-file opening retains decode_manifest and its complete recovery.
// A different complete file with a valid header, nonzero generation and
// checksum is Stale, without decoding its records as malformed, over-capacity
// or staged. Invalid framing/header/checksum retains InvalidManifest.
// This compares the original held cut; it does not adopt the replacement.
pub(super) fn require_original(
    root: &OwnedFd,
    identity: Option<ManifestIdentity>,
    expected: CacheOwnerCurrentnessV1,
) -> Result<(), CacheOwnerErrorV1> {
    let mut original = ManifestStreamOriginalsV1::default();
    original.capture_once(root, identity, expected);
    original.into_result()
}

#[derive(Default)]
pub(super) struct ManifestStreamOriginalsV1 {
    // Preserve ordinary local Drop order: streaming state before its File.
    stream: Option<ManifestStream>,
    file: Option<Result<File, rustix::io::Errno>>,
    absent_genesis: bool,
    before: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    read: Option<Result<usize, CacheOwnerErrorV1>>,
    after: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    result: Option<Result<(), CacheOwnerErrorV1>>,
}

impl ManifestStreamOriginalsV1 {
    pub(super) fn capture_once(&mut self, root: &OwnedFd,
        identity: Option<ManifestIdentity>, expected: CacheOwnerCurrentnessV1) {
        if self.result.is_some() { return; }
        self.result = Some(self.capture_inner(root, identity, expected));
    }

    fn capture_inner(&mut self, root: &OwnedFd,
        identity: Option<ManifestIdentity>, expected: CacheOwnerCurrentnessV1)
        -> Result<(), CacheOwnerErrorV1>
    {
        require_manifest_identity(root, identity)?;
        self.file = Some(rustix::fs::openat(root, MANIFEST_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map(File::from));
        match self.file.as_ref() {
            Some(Ok(_)) => {}
            Some(Err(rustix::io::Errno::NOENT))
                if identity.is_none() && expected.generation == 0 && expected.digest.as_bytes() == &[0; 32] =>
            {
                self.absent_genesis = true;
                return require_manifest_identity(root, identity);
            }
            Some(Err(rustix::io::Errno::NOENT)) => return Err(CacheOwnerErrorV1::Stale),
            Some(Err(_)) | None => return Err(CacheOwnerErrorV1::InvalidManifest),
        }
        let file = self.file.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheOwnerErrorV1::InvalidManifest)?;
        self.before = Some(rustix::fs::fstat(file));
        let before = self.before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheOwnerErrorV1::InvalidManifest)?;
        let length = usize::try_from(before.st_size).map_err(|_| CacheOwnerErrorV1::InvalidManifest)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_nlink != 1
            || before.st_uid != rustix::process::geteuid().as_raw()
            || before.st_mode & 0o7777 != 0o600
            || identity
                != Some(ManifestIdentity {
                    device: before.st_dev,
                    inode: before.st_ino,
                })
            || !(56..=MAXIMUM_MANIFEST_BYTES).contains(&length)
        {
            return Err(CacheOwnerErrorV1::InvalidManifest);
        }

        self.stream = Some(ManifestStream {
            buffer: [0; STREAM_BYTES],
            header: [0; HEADER_BYTES],
            checksum: [0; CHECKSUM_BYTES],
            complete: Sha256::new(),
            payload: Sha256::new(),
            position: 0,
            payload_bytes: length - CHECKSUM_BYTES,
        });
        let stream = self.stream.as_mut().ok_or(CacheOwnerErrorV1::InvalidManifest)?;
        let file = self.file.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(CacheOwnerErrorV1::InvalidManifest)?;
        while stream.position < length {
            let wanted = stream.buffer.len().min(length - stream.position);
            self.read = Some(read_retry(file, &mut stream.buffer[..wanted]));
            let count = *self.read.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CacheOwnerErrorV1::InvalidManifest)?;
            if count == 0 {
                return Err(CacheOwnerErrorV1::InvalidManifest);
            }
            let end = stream
                .position
                .checked_add(count)
                .filter(|end| *end <= length)
                .ok_or(CacheOwnerErrorV1::InvalidManifest)?;
            let bytes = &stream.buffer[..count];
            stream.complete.update(bytes);
            if stream.position < HEADER_BYTES {
                let header_end = end.min(HEADER_BYTES);
                stream.header[stream.position..header_end]
                    .copy_from_slice(&bytes[..header_end - stream.position]);
            }
            if stream.position < stream.payload_bytes {
                stream
                    .payload
                    .update(&bytes[..count.min(stream.payload_bytes - stream.position)]);
            }
            if end > stream.payload_bytes {
                let start = stream.position.max(stream.payload_bytes);
                stream.checksum[start - stream.payload_bytes..end - stream.payload_bytes]
                    .copy_from_slice(&bytes[start - stream.position..]);
            }
            stream.position = end;
        }

        // An exact EOF probe catches growth even if metadata changed after open.
        let mut tail = [0; 1];
        self.read = Some(read_retry(file, &mut tail));
        if *self.read.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheOwnerErrorV1::InvalidManifest)? != 0 {
            return Err(CacheOwnerErrorV1::InvalidManifest);
        }
        self.after = Some(rustix::fs::fstat(file));
        let after = self.after.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CacheOwnerErrorV1::InvalidManifest)?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || before.st_nlink != after.st_nlink
            || before.st_uid != after.st_uid
            || before.st_mode != after.st_mode
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || before.st_ctime != after.st_ctime
            || before.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(CacheOwnerErrorV1::Stale);
        }
        require_manifest_identity(root, identity)?;

        let generation = decode_generation(&stream.header)?;
        if generation == 0 || stream.payload.clone().finalize().as_slice() != stream.checksum.as_slice() {
            return Err(CacheOwnerErrorV1::InvalidManifest);
        }
        let actual = CacheOwnerCurrentnessV1 {
            generation,
            digest: ObjectDigest::from_bytes(stream.complete.clone().finalize().into()),
        };
        if actual != expected {
            return Err(CacheOwnerErrorV1::Stale);
        }
        Ok(())
    }

    pub(super) fn is_complete(&self) -> bool { matches!(self.result, Some(Ok(()))) }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.is_complete() { return None; }
        self.file.as_ref().and_then(|result| result.as_ref().err())
            .filter(|_| !self.absent_genesis).map(|error| error as _)
            .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.read.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
    }

    fn into_result(mut self) -> Result<(), CacheOwnerErrorV1> {
        let result = self.result.take().ok_or(CacheOwnerErrorV1::InvalidManifest)?;
        if result.is_ok() || self.absent_genesis { return result; }
        if let Some(Err(error)) = self.file.as_ref() {
            // A missing manifest at non-genesis originally projects Stale.
            if *error == rustix::io::Errno::NOENT { return Err(CacheOwnerErrorV1::Stale); }
            return Err((*error).into());
        }
        if let Some(Err(error)) = self.before.as_ref() { return Err((*error).into()); }
        if matches!(self.read, Some(Err(_))) {
            if let Some(Err(error)) = self.read.take() { return Err(error); }
        }
        if let Some(Err(error)) = self.after.as_ref() { return Err((*error).into()); }
        result
    }
}

fn read_retry(
    file: &mut impl std::io::Read,
    output: &mut [u8],
) -> Result<usize, CacheOwnerErrorV1> {
    loop {
        match file.read(output) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result.map_err(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn limits() -> CacheOwnerLimitsV1 {
        CacheOwnerLimitsV1 {
            maximum_memory_bytes: 1024,
            maximum_disk_bytes: 1024,
            disk_low_water_bytes: 0,
            maximum_positive_entries: 4,
            maximum_negative_entries: 4,
            maximum_pins: 4,
            maximum_pinned_bytes: 1024,
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        OwnedFd,
        OwnedFd,
        Option<ManifestIdentity>,
        CacheOwnerCurrentnessV1,
    ) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = encode_manifest(1, &BTreeMap::new(), &BTreeMap::new()).unwrap();
        let named = directory.path().join(MANIFEST_NAME);
        fs::write(&named, bytes).unwrap();
        fs::set_permissions(&named, fs::Permissions::from_mode(0o600)).unwrap();
        let root = rustix::fs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let lock = open_owner_lock(&root).unwrap();
        let identity = inspect_manifest_identity(&root).unwrap();
        // Initial unknown bytes still pass the complete canonical replay.
        let original = replayed_manifest_head(&root, limits()).unwrap();
        (directory, root, lock, identity, original)
    }

    fn check(
        root: &OwnedFd,
        lock: &OwnedFd,
        identity: Option<ManifestIdentity>,
        original: CacheOwnerCurrentnessV1,
    ) -> Result<(), CacheOwnerErrorV1> {
        ensure_held_lock(root, lock)?;
        require_original(root, identity, original)?;
        ensure_held_lock(root, lock)?;
        require_manifest_identity(root, identity)
    }

    #[test]
    fn failed_retained_stream_keeps_its_file_scratch_and_original_cause_through_posts() {
        let (directory, root, _lock, identity, original) = fixture();
        let path = directory.path().join(MANIFEST_NAME);
        let mut bytes = fs::read(&path).unwrap();
        bytes[24] ^= 1;
        fs::write(&path, &bytes).unwrap();
        let mut primary = ManifestStreamOriginalsV1::default();

        primary.capture_once(&root, identity, original);

        assert!(!primary.is_complete());
        assert!(matches!(primary.file, Some(Ok(_))));
        assert!(primary.stream.is_some());
        let cause = primary.failure().unwrap().downcast_ref::<CacheOwnerErrorV1>().unwrap()
            as *const CacheOwnerErrorV1;
        let mut independent_post = ManifestStreamOriginalsV1::default();
        independent_post.capture_once(&root, identity, original);
        assert!(independent_post.failure().is_some());
        primary.capture_once(&root, identity, original);
        assert!(std::ptr::eq(primary.failure().unwrap().downcast_ref::<CacheOwnerErrorV1>().unwrap(), cause));
        assert!(matches!(primary.file, Some(Ok(_))));
        assert!(primary.stream.is_some());
    }

    #[test]
    fn original_canonical_native_head_rechecks_with_fixed_scratch() {
        let (_directory, root, lock, identity, original) = fixture();
        assert!(check(&root, &lock, identity, original).is_ok());
        assert!(original_recheck_scratch_bytes() >= 2 * STREAM_BYTES);
        assert!(original_recheck_scratch_bytes() < 2 * STREAM_BYTES + 2048);
    }

    #[test]
    fn checksum_generation_truncation_and_authenticated_tails_are_refused() {
        for case in 0..6 {
            let (directory, root, lock, identity, original) = fixture();
            let named = directory.path().join(MANIFEST_NAME);
            let mut bytes = fs::read(&named).unwrap();
            match case {
                0 => {
                    bytes[24] ^= 1;
                }
                1 => {
                    bytes = encode_manifest(2, &BTreeMap::new(), &BTreeMap::new()).unwrap();
                }
                2 => {
                    bytes.truncate(bytes.len() - 1);
                }
                3 => {
                    bytes.push(0);
                }
                4 => {
                    bytes.truncate(bytes.len() - CHECKSUM_BYTES);
                    bytes.push(0);
                    let checksum = Sha256::digest(&bytes);
                    bytes.extend_from_slice(&checksum);
                }
                _ => {
                    bytes.truncate(bytes.len() - CHECKSUM_BYTES);
                    bytes[0] ^= 1;
                    let checksum = Sha256::digest(&bytes);
                    bytes.extend_from_slice(&checksum);
                }
            }
            fs::write(named, bytes).unwrap();
            assert!(check(&root, &lock, identity, original).is_err());
        }
    }

    #[test]
    fn identical_named_manifest_and_lock_replacements_are_refused() {
        for name in [MANIFEST_NAME, ".owner.lock"] {
            let (directory, root, lock, identity, original) = fixture();
            let named = directory.path().join(name);
            let retained = directory.path().join(format!("{name}.retained"));
            fs::rename(&named, &retained).unwrap();
            fs::copy(&retained, &named).unwrap();
            assert!(check(&root, &lock, identity, original).is_err());
        }
    }

    #[test]
    fn over_extent_file_is_refused_before_streaming_unknown_records() {
        let (directory, root, lock, identity, original) = fixture();
        let file = fs::OpenOptions::new()
            .write(true)
            .open(directory.path().join(MANIFEST_NAME))
            .unwrap();
        file.set_len((MAXIMUM_MANIFEST_BYTES as u64) + 1).unwrap();
        assert!(check(&root, &lock, identity, original).is_err());
    }

    #[test]
    fn existing_canonical_negative_map_streams_across_the_checksum_boundary() {
        let (directory, root, lock, identity, _) = fixture();
        // Empty header/footer60, each complete negative row48. This puts the
        // checksum across the second fixed buffer boundary.
        let count = (2 * STREAM_BYTES - 60) / 48 + 1;
        let negatives = (1..=count)
            .map(|index| {
                let mut digest = [0; 32];
                digest[..8].copy_from_slice(&(index as u64).to_be_bytes());
                let key =
                    AuthorizedLookupKey::from_digest(ObjectDigest::from_bytes(digest)).unwrap();
                (
                    key,
                    NegativeEntry {
                        valid_until: 2,
                        last_used: 1,
                    },
                )
            })
            .collect();
        let bytes = encode_manifest(1, &BTreeMap::new(), &negatives).unwrap();
        fs::write(directory.path().join(MANIFEST_NAME), &bytes).unwrap();
        let original = replayed_manifest_head(
            &root,
            CacheOwnerLimitsV1 {
                maximum_negative_entries: count,
                ..limits()
            },
        )
        .unwrap();

        assert!(bytes.len() > 2 * STREAM_BYTES);
        assert!(bytes.len() % STREAM_BYTES < CHECKSUM_BYTES);
        assert!(check(&root, &lock, identity, original).is_ok());
    }

    #[test]
    fn interrupted_reads_retry_and_other_io_errors_keep_their_cause() {
        struct InterruptOnce(bool);

        impl std::io::Read for InterruptOnce {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                output[0] = 7;
                Ok(1)
            }
        }

        struct Refuse;

        impl std::io::Read for Refuse {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        }

        let mut output = [0; 1];
        assert_eq!(
            read_retry(&mut InterruptOnce(false), &mut output).unwrap(),
            1
        );
        assert_eq!(output, [7]);
        assert!(matches!(read_retry(&mut Refuse, &mut output),
            Err(CacheOwnerErrorV1::Io(cause))
                if cause.kind() == std::io::ErrorKind::PermissionDenied));
    }

    #[test]
    fn checksum_valid_foreign_payloads_are_stale_for_the_original_held_cut() {
        for case in 0..3 {
            let (directory, root, lock, identity, original) = fixture();
            let named = directory.path().join(MANIFEST_NAME);
            let mut bytes = fs::read(&named).unwrap();
            if case < 2 {
                bytes.truncate(bytes.len() - CHECKSUM_BYTES);
                if case == 0 {
                    // Claims a negative row whose required bytes are absent.
                    bytes[24..28].copy_from_slice(&1_u32.to_be_bytes());
                } else {
                    // The original decoder checks this limit before rows.
                    bytes[20..24].copy_from_slice(&5_u32.to_be_bytes());
                }
                let checksum = Sha256::digest(&bytes);
                bytes.extend_from_slice(&checksum);
            } else {
                let descriptor = ObjectDescriptor::new(
                    MediaType::new(aos_sandbox_model::PortableMediaType::Content.as_str()).unwrap(),
                    ObjectDigest::from_bytes([1; 32]),
                    3,
                );
                let key = ObjectKey {
                    partition: ObjectDigest::from_bytes([2; 32]),
                    descriptor,
                };
                let entry = DiskEntry {
                    file_name: "object".to_owned(),
                    staging_name: Some("staging".to_owned()),
                    deleting_name: None,
                    bytes: 3,
                    device: 1,
                    inode: 2,
                    verity: [3; 32],
                    canonical_name: ObjectDigest::from_bytes([4; 32]),
                    root_custody: ObjectDigest::from_bytes([5; 32]),
                    last_used: 1,
                    pins: BTreeSet::new(),
                };
                bytes =
                    encode_manifest(1, &BTreeMap::from([(key, entry)]), &BTreeMap::new()).unwrap();
            }
            fs::write(named, bytes).unwrap();

            let old_classification = replayed_manifest_head(&root, limits());
            match case {
                0 => assert!(matches!(
                    old_classification,
                    Err(CacheOwnerErrorV1::InvalidManifest)
                )),
                1 => assert!(matches!(
                    old_classification,
                    Err(CacheOwnerErrorV1::CapacityExhausted)
                )),
                _ => assert!(matches!(
                    old_classification,
                    Err(CacheOwnerErrorV1::UnsafeRelease)
                )),
            }
            assert!(matches!(
                check(&root, &lock, identity, original),
                Err(CacheOwnerErrorV1::Stale)
            ));
        }
    }
}
