//! Reads one bounded physical manifest through shared native custody.
//!
//! Ordinary consumers move their exact error and dispose local partials. The
//! selected receiving owner keeps the same File, metadata, partial bytes and
//! native Result in place. This private disposition grants no receiving budget
//! or authority and performs no extra metadata scan/reopen.

use super::*;

#[derive(Default)]
pub(super) struct PhysicalManifestReadV1 {
    name: Option<Result<(), CacheOwnerErrorV1>>,
    file: Option<Result<File, CacheOwnerErrorV1>>,
    stat: Option<Result<rustix::fs::Stat, CacheOwnerErrorV1>>,
    kind: Option<Result<(), CacheOwnerErrorV1>>,
    bytes: Option<Vec<u8>>,
    read: Option<std::io::Result<usize>>,
    extent: Option<Result<(), CacheOwnerErrorV1>>,
    completed: bool,
}

// This one operation order serves both dispositions. RETAINED changes only
// error/partial custody; it cannot admit a grant or skip any native check.
macro_rules! read_outcome {
    ($retained:ident, $slot:expr, $native:expr) => {{
        let slot = &mut $slot;
        *slot = Some($native);
        if slot.as_ref().is_some_and(Result::is_err) {
            if $retained {
                return Err(CacheOwnerErrorV1::Fenced);
            }
            if let Some(Err(cause)) = slot.take() {
                return Err(cause.into());
            }
        }
        slot.as_mut().and_then(|returned| returned.as_mut().ok())
            .ok_or(CacheOwnerErrorV1::Fenced)?
    }};
}

impl PhysicalManifestReadV1 {
    pub(super) fn capture<const RETAINED: bool>(
        &mut self,
        root: &OwnedFd,
        name: &str,
        maximum: usize,
    ) -> Result<(), CacheOwnerErrorV1> {
        if self.name.is_some() || self.completed {
            return Err(CacheOwnerErrorV1::Fenced);
        }
        read_outcome!(RETAINED, self.name, validate_basename(name));
        let file = read_outcome!(RETAINED, self.file, rustix::fs::openat(
            root, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty(),
        ).map(File::from).map_err(CacheOwnerErrorV1::from));
        let stat = read_outcome!(RETAINED, self.stat,
            rustix::fs::fstat(&*file).map_err(CacheOwnerErrorV1::from));
        read_outcome!(RETAINED, self.kind,
            if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_nlink == 1 {
                Ok(())
            } else { Err(CacheOwnerErrorV1::InvalidManifest) });
        self.bytes = Some(Vec::new());
        let bytes = self.bytes.as_mut().ok_or(CacheOwnerErrorV1::Fenced)?;
        read_outcome!(RETAINED, self.read, std::io::Read::by_ref(file)
            .take((maximum + 1) as u64).read_to_end(bytes));
        read_outcome!(RETAINED, self.extent, if bytes.len() <= maximum {
            Ok(())
        } else { Err(CacheOwnerErrorV1::InvalidManifest) });
        self.completed = true;
        Ok(())
    }

    pub(super) fn take_bytes(&mut self) -> Option<Vec<u8>> {
        if self.completed { self.bytes.take() } else { None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        retained_error(self.name.as_ref())
            .or_else(|| retained_error(self.file.as_ref()))
            .or_else(|| retained_error(self.stat.as_ref()))
            .or_else(|| retained_error(self.kind.as_ref()))
            .or_else(|| retained_error(self.read.as_ref()))
            .or_else(|| retained_error(self.extent.as_ref()))
    }
}

fn retained_error<T, E: std::error::Error + 'static>(
    returned: Option<&Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    returned.and_then(|returned| returned.as_ref().err())
        .map(|cause| cause as &(dyn std::error::Error + 'static))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(path: &Path) -> OwnedFd {
        rustix::fs::open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).unwrap()
    }

    #[test]
    fn same_oversize_read_keeps_partial_file_and_extent_cause_only_when_retained() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("owner-state"), b"hello").unwrap();
        let root = root(directory.path());
        let mut ordinary = PhysicalManifestReadV1::default();
        let mut retained = PhysicalManifestReadV1::default();

        assert!(matches!(ordinary.capture::<false>(&root, "owner-state", 2),
            Err(CacheOwnerErrorV1::InvalidManifest)));
        assert!(matches!(retained.capture::<true>(&root, "owner-state", 2),
            Err(CacheOwnerErrorV1::Fenced)));

        assert_eq!(ordinary.bytes.as_deref(), Some(b"hel".as_slice()));
        assert_eq!(retained.bytes.as_deref(), Some(b"hel".as_slice()));
        assert!(ordinary.extent.is_none());
        assert!(matches!(retained.failure().unwrap().downcast_ref::<CacheOwnerErrorV1>(),
            Some(CacheOwnerErrorV1::InvalidManifest)));
        assert!(matches!(retained.read, Some(Ok(3))));
        let file = retained.file.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(rustix::fs::fstat(file).unwrap().st_size, 5);
        assert!(retained.take_bytes().is_none());
    }

    #[test]
    fn actual_missing_file_cause_survives_reentry_without_a_new_open() {
        let directory = tempfile::tempdir().unwrap();
        let root = root(directory.path());
        let mut ordinary = PhysicalManifestReadV1::default();
        let mut retained = PhysicalManifestReadV1::default();

        assert!(matches!(ordinary.capture::<false>(&root, "absent", 4),
            Err(CacheOwnerErrorV1::Rustix(error)) if error == rustix::io::Errno::NOENT));
        assert!(matches!(retained.capture::<true>(&root, "absent", 4),
            Err(CacheOwnerErrorV1::Fenced)));
        let first = retained.failure().unwrap()
            .downcast_ref::<CacheOwnerErrorV1>().unwrap() as *const CacheOwnerErrorV1;
        assert!(matches!(retained.failure().unwrap().downcast_ref::<CacheOwnerErrorV1>(),
            Some(CacheOwnerErrorV1::Rustix(error)) if *error == rustix::io::Errno::NOENT));

        std::fs::write(directory.path().join("absent"), b"new").unwrap();
        assert!(retained.capture::<true>(&root, "absent", 4).is_err());
        assert!(std::ptr::eq(first, retained.failure().unwrap()
            .downcast_ref::<CacheOwnerErrorV1>().unwrap()));
        assert!(retained.bytes.is_none());
    }

    #[test]
    fn successful_dispositions_return_identical_bytes_and_keep_one_original_file() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("owner-state"), b"ready").unwrap();
        let root = root(directory.path());
        let mut ordinary = PhysicalManifestReadV1::default();
        let mut retained = PhysicalManifestReadV1::default();

        ordinary.capture::<false>(&root, "owner-state", 5).unwrap();
        retained.capture::<true>(&root, "owner-state", 5).unwrap();

        assert_eq!(ordinary.take_bytes(), retained.take_bytes());
        assert!(retained.file.as_ref().unwrap().is_ok());
        assert!(retained.take_bytes().is_none());
        assert!(retained.failure().is_none());
    }

    fn short_disk_row(pin: bool) -> (ObjectKey, DiskEntry) {
        let key = ObjectKey {
            partition: ObjectDigest::from_bytes([1; 32]),
            descriptor: ObjectDescriptor::new(
                MediaType::new("a/b".to_owned()).unwrap(),
                ObjectDigest::from_bytes([2; 32]), 1,
            ),
        };
        let entry = DiskEntry {
            file_name: "x".to_owned(), staging_name: None, deleting_name: None,
            bytes: 1, device: 1, inode: 1, verity: [3; 32],
            canonical_name: ObjectDigest::from_bytes([4; 32]),
            root_custody: ObjectDigest::from_bytes([5; 32]), last_used: 1,
            pins: if pin {
                BTreeSet::from([CacheOwnerPinIdV1::from_bytes([6; 16]).unwrap()])
            } else { BTreeSet::new() },
        };
        (key, entry)
    }

    fn decoding_limits() -> CacheOwnerLimitsV1 {
        CacheOwnerLimitsV1 {
            maximum_memory_bytes: 1, maximum_disk_bytes: 1,
            disk_low_water_bytes: 1, maximum_positive_entries: 1,
            maximum_negative_entries: 1, maximum_pins: 1,
            maximum_pinned_bytes: 1,
        }
    }

    #[test]
    fn reached_manifest_grammar_materializes_short_rows_and_sixteen_byte_pins() {
        // These short but syntactically accepted names are rejected only by
        // later physical-object checks, after decode has already grown maps.
        let empty = encode_manifest(1, &BTreeMap::new(), &BTreeMap::new()).unwrap();
        let unpinned = encode_manifest(1, &BTreeMap::from([short_disk_row(false)]),
            &BTreeMap::new()).unwrap();
        let pinned = encode_manifest(1, &BTreeMap::from([short_disk_row(true)]),
            &BTreeMap::new()).unwrap();

        let (_, disk, _) = decode_manifest(&unpinned, decoding_limits()).unwrap();
        let (_, pinned_disk, _) = decode_manifest(&pinned, decoding_limits()).unwrap();

        assert_eq!(unpinned.len() - empty.len(), 216);
        assert_eq!(pinned.len() - unpinned.len(), 16);
        assert_eq!(disk.len(), 1);
        assert_eq!(disk.values().next().unwrap().file_name, "x");
        assert_eq!(pinned_disk.values().next().unwrap().pins.len(), 1);
        assert!(ResidentCachePhysicalOpenV1::selected_receiving_demand_v1(1, pinned.len()).is_ok());
    }

    #[test]
    fn captured_small_manifest_pays_its_own_models_after_fixed_raw_admission() {
        use aos_sandbox_model::ResourceDimension as D;

        let bytes = encode_manifest(1, &BTreeMap::new(), &BTreeMap::new()).unwrap();
        let payload_pool = 64 * 1024 * 1024;
        let fixed = ResidentCachePhysicalOpenV1::selected_preparation_demand_v1(payload_pool).unwrap();
        let captured = ResidentCachePhysicalOpenV1::selected_receiving_demand_v1(
            payload_pool, bytes.len(),
        ).unwrap();
        let ceiling = ResidentCachePhysicalOpenV1::selected_receiving_demand_v1(
            payload_pool, MAXIMUM_MANIFEST_BYTES,
        ).unwrap();

        // The same raw16MiB read allowance/payload pool remain funded. Only
        // typed carriers follow the real captured bytes before their decode.
        assert!(captured.get(D::MemoryBytes) >= fixed.get(D::MemoryBytes));
        assert!(captured.get(D::MemoryBytes) < 512 * 1024 * 1024);
        assert!(captured.get(D::MemoryBytes) < ceiling.get(D::MemoryBytes));
        assert!(decode_manifest(&bytes, decoding_limits()).is_ok());
    }
}
