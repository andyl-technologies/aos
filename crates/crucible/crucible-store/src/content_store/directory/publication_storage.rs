//! Prices the concrete two-object directory publication call tree as DATA.
//!
//! The quote opens no path and performs no backend callback. It includes both
//! initial/final reconciliation, puts and CASes, including failure paths. Roots
//! and source bytes remain caller-owned. Unknown instrumentation refuses before
//! any publication, rather than assuming an empty environment or zero work.

use super::*;
use std::mem::{align_of, size_of, size_of_val};

/// Borrows an actual validated ref name or its checked namespace replacement.
///
/// This projection describes path allocation only. It cannot be used as a ref
/// name, acquire a lock, read a ref or authorize namespace mutation.
#[derive(Clone, Copy)]
pub struct DirectoryRefNameConstructionData<'a> {
    prefix: &'a str,
    suffix: &'a str,
}

impl<'a> DirectoryRefNameConstructionData<'a> {
    /// Borrows the complete original name without allocating another String.
    pub fn original(name: &'a RefName) -> Self {
        Self {
            prefix: "",
            suffix: name.as_str(),
        }
    }

    /// Replaces one complete namespace prefix for path-sizing purposes only.
    ///
    /// # Errors
    /// Refuses absent/nonsegment prefixes, unsafe replacement components or a
    /// complete future name exceeding the defining RefName's 1,024-byte bound.
    pub fn replace_namespace(
        name: &'a RefName,
        original_prefix: &str,
        replacement_prefix: &'a str,
    ) -> Result<Self, StoreError> {
        if !original_prefix.ends_with('/') || !replacement_prefix.ends_with('/') {
            return Err(StoreError::InvalidComposition {
                reason: "publication namespace prefix lacks separator",
            });
        }
        let suffix = name
            .as_str()
            .strip_prefix(original_prefix)
            .filter(|suffix| !suffix.is_empty())
            .ok_or(StoreError::InvalidComposition {
                reason: "publication namespace prefix differs",
            })?;
        let prefix = replacement_prefix
            .strip_suffix('/')
            .ok_or(StoreError::InvalidId)?;
        if prefix.split('/').any(invalid_namespace_component)
            || replacement_prefix
                .len()
                .checked_add(suffix.len())
                .filter(|n| *n <= 1024)
                .is_none()
        {
            return Err(StoreError::InvalidComposition {
                reason: "publication replacement namespace is invalid",
            });
        }
        Ok(Self {
            prefix: replacement_prefix,
            suffix,
        })
    }

    fn bytes(self) -> Result<usize, StoreError> {
        self.prefix
            .len()
            .checked_add(self.suffix.len())
            .ok_or(StoreError::Quota)
    }

    fn components(self) -> Result<usize, StoreError> {
        self.prefix
            .bytes()
            .chain(self.suffix.bytes())
            .filter(is_separator as fn(&u8) -> bool)
            .count()
            .checked_add(1)
            .ok_or(StoreError::Quota)
    }
}

fn is_separator(byte: &u8) -> bool {
    *byte == b'/'
}

fn invalid_namespace_component(part: &str) -> bool {
    part.is_empty()
        || part.len() > 255
        || part == "."
        || part == ".."
        || !part.bytes().all(namespace_byte)
}

fn namespace_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

/// Retains fixed concrete callback storage and descriptor extents as DATA.
///
/// Each getter describes additional construction work, never an admission or
/// filesystem permission. This fixed record itself owns no heap or descriptor.
#[derive(Clone, Copy)]
pub struct DirectoryPublicationConstructionStorageData {
    requested: usize,
    scratch: usize,
    descriptors: usize,
}

impl DirectoryPublicationConstructionStorageData {
    /// Returns the largest complete callback-local heap request conjunction.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Returns separately precredited fixed I/O, conversion and result views.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the maximum additional simultaneously open descriptor slots.
    pub fn maximum_simultaneous_transient_descriptors_data(&self) -> usize {
        self.descriptors
    }
}

#[derive(Clone, Copy)]
struct PathExtent {
    bytes: usize,
    components: usize,
}

impl PathExtent {
    fn root(path: &Path) -> Self {
        Self {
            bytes: path.as_os_str().as_bytes().len(),
            components: path.components().count(),
        }
    }

    fn child(self, bytes: usize, components: usize) -> Result<Self, StoreError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(1)
                .and_then(|n| n.checked_add(bytes))
                .ok_or(StoreError::Quota)?,
            components: self
                .components
                .checked_add(components)
                .ok_or(StoreError::Quota)?,
        })
    }
}

struct Requested {
    bytes: usize,
    maximum: usize,
}

impl Requested {
    fn add(&mut self, value: usize) -> Result<(), StoreError> {
        self.bytes = self
            .bytes
            .checked_add(value)
            .filter(|n| *n <= self.maximum)
            .ok_or(StoreError::Quota)?;
        Ok(())
    }

    fn slots<T>(&mut self, count: usize) -> Result<(), StoreError> {
        self.add(count.checked_mul(size_of::<T>()).ok_or(StoreError::Quota)?)
    }

    fn growth(&mut self, length: usize) -> Result<(), StoreError> {
        // Pinned Vec/OsString doubling: retain the old and replacement banks,
        // minimum capacity and bounded formatting spare, not allocator/RSS size.
        self.add(
            length
                .checked_mul(4)
                .and_then(|n| n.checked_add(256))
                .ok_or(StoreError::Quota)?,
        )
    }

    fn path(&mut self, path: PathExtent) -> Result<(), StoreError> {
        self.growth(path.bytes)?; // actual PathBuf join/clone bank.
        self.growth(path.bytes.checked_add(1).ok_or(StoreError::Quota)?)?; // syscall CString/NUL error bank.
        self.growth(path.bytes)?; // independent StoreError::Io path clone.
        self.io_error()
    }

    fn io_error(&mut self) -> Result<(), StoreError> {
        // std io::Error::new boxes Custom(kind, boxed Error), then a String
        // error wrapper for the two literal messages in this concrete call tree.
        // OS errno errors themselves need no owned diagnostic String. Nothing
        // here formats an arbitrary Display implementation or a pathname.
        let alignment =
            align_of::<io::ErrorKind>().max(align_of::<Box<dyn std::error::Error + Send + Sync>>());
        self.add(
            size_of::<io::ErrorKind>()
                .checked_add(size_of::<Box<dyn std::error::Error + Send + Sync>>())
                .and_then(|n| n.checked_add(2 * (alignment - 1)))
                .ok_or(StoreError::Quota)?,
        )?;
        self.add(size_of::<String>())?;
        self.growth(
            "path component is not a directory"
                .len()
                .max("content authentication failed".len()),
        )
    }

    fn durable_directory(&mut self, path: PathExtent) -> Result<(), StoreError> {
        // create_dir_all_durable can retain every missing ancestor PathBuf.
        // std DirBuilder::create_dir_all separately retains Vec<&Path> ancestors.
        let ancestors = path.components.checked_add(2).ok_or(StoreError::Quota)?;
        self.slots::<PathBuf>(ancestors.checked_mul(4).ok_or(StoreError::Quota)?)?;
        self.slots::<&Path>(ancestors)?;
        for _ in 0..ancestors {
            self.path(path)?;
        }
        self.path(path) // existing parent sync and final error path.
    }

    fn lock(&mut self, path: PathExtent) -> Result<(), StoreError> {
        self.durable_directory(path)?;
        self.path(path)
    }

    fn inventory(&mut self, root: PathExtent, administration: &str) -> Result<(), StoreError> {
        let directory = root.child(administration.len(), 1)?;
        self.path(directory)?;
        self.lock(directory.child("lock".len(), 1)?)?;
        let state = directory.child("state-v1".len(), 1)?;
        self.path(state)?;
        self.growth(MAX_INVENTORY_STATE_BYTES as usize + 1)?; // bounded state read including sentinel.
        // The parser's first material remains beside the second material and
        // final bytes from canonical re-encoding. Each independent digest text
        // is named as well; equality of contents never aliases these banks.
        self.growth(MAX_INVENTORY_STATE_BYTES as usize)?;
        self.growth(64)?;
        self.growth(MAX_INVENTORY_STATE_BYTES as usize)?;
        self.growth(64)?;
        self.growth(64)?;
        self.growth(MAX_INVENTORY_STATE_BYTES as usize)?;
        self.path(PathExtent {
            bytes: "/dev/urandom".len(),
            components: 3,
        })?;
        self.persist_state(directory)?;
        self.persist_state(directory)
    }

    fn persist_state(&mut self, directory: PathExtent) -> Result<(), StoreError> {
        self.growth(MAX_INVENTORY_STATE_BYTES as usize)?;
        self.growth(MAX_INVENTORY_STATE_BYTES as usize)?;
        self.growth(64)?; // independently encoded instance digest.
        self.growth(64)?; // independently encoded checksum digest.
        let staging = ".ref-inventory-state-staging-"
            .len()
            .checked_add(10 + 1 + 20)
            .ok_or(StoreError::Quota)?;
        self.growth(staging)?;
        self.path(directory.child(staging, 1)?)?;
        self.path(directory) // sync File and retained error path.
    }

    fn read_ref(
        &mut self,
        root: PathExtent,
        name: DirectoryRefNameConstructionData<'_>,
    ) -> Result<(), StoreError> {
        self.lock(root.child(".ref-admin/lock".len(), 2)?)?;
        self.path(root.child("locks".len(), 1)?)?; // chained join's intermediate bank.
        self.lock(root.child("locks/".len() + 64, 2)?)?;
        self.path(root.child("refs".len(), 1)?)?;
        self.path(
            root.child(
                "refs/"
                    .len()
                    .checked_add(name.bytes()?)
                    .ok_or(StoreError::Quota)?,
                name.components()?.checked_add(1).ok_or(StoreError::Quota)?,
            )?,
        )?;
        self.growth(MAX_REF_RECORD_BYTES as usize + 1)
    }

    fn compare_exchange(
        &mut self,
        root: PathExtent,
        name: DirectoryRefNameConstructionData<'_>,
    ) -> Result<(), StoreError> {
        self.inventory(root, ".ref-admin")?;
        self.path(root.child("locks".len(), 1)?)?;
        self.lock(root.child("locks/".len() + 64, 2)?)?;
        self.path(root.child("refs".len(), 1)?)?;
        let path = root.child(
            "refs/"
                .len()
                .checked_add(name.bytes()?)
                .ok_or(StoreError::Quota)?,
            name.components()?.checked_add(1).ok_or(StoreError::Quota)?,
        )?;
        self.path(path)?;
        self.growth(MAX_REF_RECORD_BYTES as usize + 1)?;
        self.durable_directory(path)?;
        let staging = ".ref-staging-"
            .len()
            .checked_add(10 + 1 + 20)
            .ok_or(StoreError::Quota)?;
        self.growth(staging)?;
        self.path(path.child(staging, 1)?)?;
        self.growth(MAX_REF_RECORD_BYTES as usize)?; // next.encode + newline String.
        self.growth(MAX_REF_RECORD_BYTES as usize)?;
        self.path(path)
    }

    fn read_object(&mut self, root: PathExtent, ceiling: usize) -> Result<(), StoreError> {
        self.object_path(root)?;
        self.add(shared::<File>())?;
        self.add(shared::<DirectoryBlobSource>())?;
        self.add(size_of::<AuthenticatingFileReader>())?;
        // read_all reserves actual stat length only after checking the literal
        // callback ceiling. Unknown existing content can still reach that bound.
        if ceiling != 0 {
            self.growth(ceiling)?;
        }
        self.io_error()
    }

    fn object_path(&mut self, root: PathExtent) -> Result<PathExtent, StoreError> {
        self.growth(64)?; // object_path's standalone digest encoder.
        self.growth(64)?; // ContentId::encode's independent digest String.
        self.growth(MAX_REF_RECORD_BYTES as usize)?; // bounded kind/u32 schema/digest ContentId::encode.
        let objects = root.child(OBJECT_DIRECTORY.len(), 1)?;
        self.path(objects)?;
        let shard = objects.child(2, 1)?;
        self.path(shard)?;
        let path = shard.child(MAX_REF_RECORD_BYTES as usize, 1)?;
        self.path(path)?;
        Ok(path)
    }

    fn put_object(
        &mut self,
        root: PathExtent,
        bytes: usize,
        backend_name: usize,
    ) -> Result<(), StoreError> {
        self.inventory(root, INVENTORY_ADMIN_DIRECTORY)?;
        let path = self.object_path(root)?;
        self.durable_directory(path)?;
        let staging = ".staging-"
            .len()
            .checked_add(10 + 1 + 20)
            .ok_or(StoreError::Quota)?;
        self.growth(staging)?;
        self.path(path.child(staging, 1)?)?;
        // value.to_vec and Arc<[u8]>::from(Vec) coexist at conversion. Opening
        // the known BytesBlobSource creates only a Cursor alias, no new payload.
        self.add(bytes)?;
        self.add(bytes)?;
        self.add(shared_header(align_of::<u8>())?)?;
        self.add(shared::<super::super::BytesBlobSource>())?;
        self.add(size_of::<io::Cursor<Arc<[u8]>>>())?;
        // Existing-object and hard-link collision validation read a Directory
        // source independently while inventory/staging custody remains held.
        self.read_object(root, 0)?;
        self.slots::<PlacementReceipt>(1)?;
        self.add(backend_name)?;
        self.path(path)
    }
}

fn shared_header(alignment: usize) -> Result<usize, StoreError> {
    let header = 2usize
        .checked_mul(size_of::<usize>())
        .ok_or(StoreError::Quota)?;
    header
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
        .ok_or(StoreError::Quota)
}

fn shared<T>() -> usize {
    // sized Arc payload layout; these concrete private types are compiled here.
    let alignment = align_of::<T>();
    ((2 * size_of::<usize>() + alignment - 1) & !(alignment - 1)) + size_of::<T>()
}

struct DirectoryCallViews<'a> {
    object_path: PathBuf,
    object_staging: PathBuf,
    blob_inventory_directory: PathBuf,
    blob_inventory_path: PathBuf,
    blob_lock_directory: PathBuf,
    blob_lock_path: PathBuf,
    blob_state_staging: PathBuf,
    ref_inventory_directory: PathBuf,
    ref_inventory_path: PathBuf,
    ref_lock_directory: PathBuf,
    ref_lock_path: PathBuf,
    ref_state_staging: PathBuf,
    ref_path: PathBuf,
    ref_staging: PathBuf,
    object_directory: &'a Path,
    ref_directory: &'a Path,
    missing_ancestors: Vec<PathBuf>,
    standard_mkdir_ancestors: Vec<&'a Path>,
    digest: String,
    encoded_id: String,
    state_material: String,
    state_bytes: Vec<u8>,
    ref_record: String,
    staging_name: String,
    blob_source: Arc<DirectoryBlobSource>,
    file: Arc<File>,
    reader: Box<AuthenticatingFileReader>,
    bytes_source: Arc<super::super::BytesBlobSource>,
    memory_reader: Box<io::Cursor<Arc<[u8]>>>,
}

impl DirectoryBlobBackend {
    /// Quotes the fixed directory call tree for two immutable objects and refs.
    ///
    /// `object_bytes` and `readback_ceilings` are DATA from the actual producer's
    /// serializer and literal read_all calls. They never authorize store effects.
    ///
    /// # Errors
    /// Refuses unsupported platform/instrumentation, arithmetic overflow or a
    /// heap-plus-scratch conjunction above `maximum`. No filesystem call runs.
    pub fn original_two_object_publication_construction_data(
        &self,
        refs: &DirectoryRefBackend,
        names: [DirectoryRefNameConstructionData<'_>; 2],
        object_bytes: [usize; 2],
        readback_ceilings: [usize; 2],
        maximum: usize,
    ) -> Result<DirectoryPublicationConstructionStorageData, StoreError> {
        if !cfg!(target_os = "linux") || cfg!(feature = "destructive-recovery-faults") {
            return Err(StoreError::Unsupported {
                capability: "bounded directory publication without destructive environment instrumentation",
            });
        }
        let blob_root = PathExtent::root(&self.root);
        let ref_root = PathExtent::root(&refs.root);
        // Returned read/put/CAS temporaries drop before the next call. Only
        // the publication guard Box survives across these callback boundaries;
        // caller-owned encoded activation/coordinator banks stay outside here.
        let mut guard = Requested { bytes: 0, maximum };
        guard.lock(ref_root.child(".ref-admin/publication-lock".len(), 2)?)?;
        guard.add(size_of::<refs::DirectoryRefPublicationGuard>())?;
        let mut callback_peak = 0usize;
        for name in names {
            let mut callback = Requested { bytes: 0, maximum };
            callback.read_ref(ref_root, name)?;
            callback_peak = callback_peak.max(callback.bytes);
        }
        for ceiling in readback_ceilings {
            let mut callback = Requested { bytes: 0, maximum };
            callback.read_object(blob_root, ceiling)?;
            callback_peak = callback_peak.max(callback.bytes);
        }
        for bytes in object_bytes {
            let mut callback = Requested { bytes: 0, maximum };
            callback.put_object(blob_root, bytes, self.name.len())?;
            callback_peak = callback_peak.max(callback.bytes);
        }
        for name in names {
            let mut callback = Requested { bytes: 0, maximum };
            callback.compare_exchange(ref_root, name)?;
            callback_peak = callback_peak.max(callback.bytes);
        }
        let guarded_callbacks = callback_peak
            .checked_add(size_of::<refs::DirectoryRefPublicationGuard>())
            .ok_or(StoreError::Quota)?;
        let requested = guard.bytes.max(guarded_callbacks);
        let scratch = Self::original_two_object_publication_counter_scratch_data()?;
        requested
            .checked_add(scratch)
            .filter(|n| *n <= maximum)
            .ok_or(StoreError::Quota)?;
        Ok(DirectoryPublicationConstructionStorageData {
            requested,
            scratch,
            // guard + inventory lock + per-ref lock + staging + sync directory.
            // Arc<File> reader aliases do not duplicate the original descriptor.
            descriptors: 5,
        })
    }

    /// Names the concrete private reader, filesystem and counter fixed views.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow. Performs no store/environment read.
    pub fn original_two_object_publication_counter_scratch_data() -> Result<usize, StoreError> {
        let rows = [
            size_of::<DirectoryPublicationConstructionStorageData>(),
            size_of::<Result<DirectoryPublicationConstructionStorageData, StoreError>>(),
            2 * size_of::<Requested>(),
            size_of::<[PathExtent; 2]>(),
            size_of::<Result<PathExtent, StoreError>>(),
            size_of::<Result<usize, StoreError>>(),
            size_of::<std::array::IntoIter<usize, 2>>(),
            size_of::<std::array::IntoIter<DirectoryRefNameConstructionData<'_>, 2>>(),
            size_of::<[DirectoryRefNameConstructionData<'_>; 2]>(),
            size_of::<Result<DirectoryRefNameConstructionData<'_>, StoreError>>(),
            // Defining borrowed-name scans: both byte inputs coexist in the
            // Chain/Filter; namespace validation borrows Split and Bytes only.
            size_of::<std::str::Bytes<'_>>(),
            size_of::<std::str::Bytes<'_>>(),
            size_of::<std::iter::Chain<std::str::Bytes<'_>, std::str::Bytes<'_>>>(),
            size_of::<
                std::iter::Filter<
                    std::iter::Chain<std::str::Bytes<'_>, std::str::Bytes<'_>>,
                    fn(&u8) -> bool,
                >,
            >(),
            size_of::<std::str::Split<'_, char>>(),
            size_of::<std::str::Bytes<'_>>(),
            size_of::<fn(&str) -> bool>(),
            size_of::<fn(u8) -> bool>(),
            size_of::<Option<&str>>(),
            size_of::<Option<u8>>(),
            size_of::<u8>(),
            size_of::<bool>(),
            size_of::<std::path::Components<'_>>(),
            size_of::<std::path::Ancestors<'_>>(),
            size_of::<Vec<PathBuf>>(),
            size_of::<Vec<&Path>>(),
            size_of::<File>(),
            size_of::<[File; 5]>(),
            size_of::<OpenOptions>(),
            size_of::<Result<File, StoreError>>(),
            size_of::<Result<File, io::Error>>(),
            size_of::<Result<(PathBuf, File), StoreError>>(),
            size_of::<Result<(Arc<File>, u64), StoreError>>(),
            size_of::<Result<[u8; 32], StoreError>>(),
            size_of::<std::fs::Metadata>(),
            size_of::<Result<std::fs::Metadata, io::Error>>(),
            size_of::<DirectoryInventoryState>(),
            size_of::<ref_admin::DirectoryRefInventoryState>(),
            size_of::<Result<DirectoryInventoryState, StoreError>>(),
            size_of::<Result<ref_admin::DirectoryRefInventoryState, StoreError>>(),
            size_of::<BlobHandle>(),
            size_of::<Result<BlobHandle, StoreError>>(),
            size_of::<Result<Vec<u8>, StoreError>>(),
            size_of::<Result<Option<ContentId>, StoreError>>(),
            size_of::<Result<RefCasOutcome, StoreError>>(),
            size_of::<Result<PutReceipt, StoreError>>(),
            size_of::<Result<Box<dyn RefPublicationGuard>, StoreError>>(),
            size_of::<Result<Box<dyn Read + Send>, StoreError>>(),
            size_of::<Result<u64, StoreError>>(),
            size_of::<Result<usize, io::Error>>(),
            size_of::<Result<(), io::Error>>(),
            size_of::<Option<ContentId>>(),
            size_of::<io::Take<File>>(),
            size_of::<io::Take<&mut Box<dyn Read + Send>>>(),
            size_of::<io::Error>(),
            size_of::<StoreError>(),
            size_of::<Result<(), StoreError>>(),
            size_of::<[u8; 64 * 1024]>(),
            size_of::<[u8; 64 * 1024]>(),
            // rename/link's two simultaneous std small_c_string stack banks.
            size_of::<[u8; 384]>(),
            size_of::<[u8; 384]>(),
            size_of::<[u8; 32]>(),
            size_of::<[u8; 32]>(),
            size_of::<[u8; 1]>(),
            size_of::<[u8; 64]>(),
            size_of::<[u8; 20]>(),
            size_of::<[u8; 10]>(),
            // to_hex returns a fixed inline ArrayString, not an owned String.
            size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex()),
            size_of::<blake3::Hasher>(),
            size_of::<blake3::Hasher>(),
            size_of::<Vec<u8>>(),
            // Sum actual independently declared path/header views across
            // object_path, lock, state load/persist, ref read/publish and sync.
            size_of::<DirectoryCallViews<'_>>(),
            size_of::<String>(),
            size_of::<std::ffi::CString>(),
            size_of::<Result<std::ffi::CString, std::ffi::NulError>>(),
            size_of::<std::str::Lines<'_>>(),
            size_of::<std::num::ParseIntError>(),
        ];
        let header = size_of_val(&rows)
            .checked_add(size_of::<std::slice::Iter<'_, usize>>())
            .ok_or(StoreError::Quota)?;
        rows.iter().try_fold(header, |sum, row| {
            sum.checked_add(*row).ok_or(StoreError::Quota)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_publication_namespace_keeps_original_suffix_and_refuses_escapes() {
        let name = RefName::new("node-world-activations/run/source-7").unwrap();
        let projected = DirectoryRefNameConstructionData::replace_namespace(
            &name,
            "node-world-activations/",
            "node-world-coordinators/",
        )
        .unwrap();
        let actual = RefName::new(format!(
            "node-world-coordinators/{}",
            name.as_str()
                .strip_prefix("node-world-activations/")
                .unwrap()
        ))
        .unwrap();
        assert_eq!(projected.bytes().unwrap(), actual.as_str().len());
        assert_eq!(
            projected.components().unwrap(),
            actual.as_str().split('/').count()
        );
        assert_eq!(
            format!("{}{}", projected.prefix, projected.suffix),
            actual.as_str()
        );
        assert_eq!(name.as_str(), "node-world-activations/run/source-7");
        for replacement in [
            "/absolute/",
            "../escape/",
            "x//y/",
            "x/./",
            "no-final-separator",
        ] {
            assert!(
                DirectoryRefNameConstructionData::replace_namespace(
                    &name,
                    "node-world-activations/",
                    replacement
                )
                .is_err()
            );
        }
        assert!(
            DirectoryRefNameConstructionData::replace_namespace(
                &name,
                "different/",
                "node-world-coordinators/"
            )
            .is_err()
        );
    }

    #[test]
    fn actual_directory_path_cstring_and_ancestor_capacities_fit_prospective_rows() {
        // Path constructors and C strings are DATA only: no path is opened or
        // created, and no filesystem backend method is invoked by this control.
        let root = PathBuf::from(format!("/unopened/{}/{}", "a".repeat(200), "b".repeat(200)));
        let backend = DirectoryBlobBackend::new("closed-leaf", root);
        let id = ContentId::for_bytes(ObjectKind::Trace, 2, b"immutable object");
        let path = backend.object_path(id);
        let extent = PathExtent {
            bytes: path.as_os_str().as_bytes().len(),
            components: path.components().count(),
        };
        let cloned_error_path = path.clone();
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .unwrap()
            .into_bytes_with_nul();
        let actual = path.capacity() + cloned_error_path.capacity() + c_path.capacity();
        let mut quoted = Requested {
            bytes: 0,
            maximum: usize::MAX,
        };
        quoted.path(extent).unwrap();
        assert!(quoted.bytes >= actual);

        let ancestors: Vec<PathBuf> = path.ancestors().map(Path::to_path_buf).collect();
        let borrowed: Vec<&Path> = path.ancestors().collect();
        let actual_ancestors = ancestors.capacity() * size_of::<PathBuf>()
            + ancestors.iter().map(PathBuf::capacity).sum::<usize>()
            + borrowed.capacity() * size_of::<&Path>();
        let mut quote = Requested {
            bytes: 0,
            maximum: usize::MAX,
        };
        quote.durable_directory(extent).unwrap();
        assert!(quote.bytes >= actual_ancestors);
        let mut exact = Requested {
            bytes: 0,
            maximum: quote.bytes,
        };
        exact.durable_directory(extent).unwrap();
        assert!(matches!(
            Requested {
                bytes: 0,
                maximum: quote.bytes - 1
            }
            .durable_directory(extent),
            Err(StoreError::Quota)
        ));
        assert!(matches!(
            Requested {
                bytes: 0,
                maximum: usize::MAX
            }
            .growth(usize::MAX),
            Err(StoreError::Quota)
        ));
    }

    #[test]
    fn directory_publication_requires_full_total_or_explicit_instrumentation_refusal() {
        let blobs = DirectoryBlobBackend::new("closed-leaf", "/unopened/blob-root");
        let refs = DirectoryRefBackend::new("/unopened/ref-root");
        let name = RefName::new("node-world-activations/data-only").unwrap();
        let names = [
            DirectoryRefNameConstructionData::original(&name),
            DirectoryRefNameConstructionData::replace_namespace(
                &name,
                "node-world-activations/",
                "node-world-coordinators/",
            )
            .unwrap(),
        ];
        let result = blobs.original_two_object_publication_construction_data(
            &refs,
            names,
            [31, 73],
            [4096, 8192],
            usize::MAX,
        );
        if cfg!(feature = "destructive-recovery-faults") || !cfg!(target_os = "linux") {
            assert!(matches!(result, Err(StoreError::Unsupported { .. })));
            return;
        }
        let data = result.unwrap();
        let total = data.requested_bytes_data() + data.counter_scratch_bytes_data();
        assert!(data.requested_bytes_data() >= 8192);
        assert_eq!(data.maximum_simultaneous_transient_descriptors_data(), 5);
        blobs
            .original_two_object_publication_construction_data(
                &refs,
                names,
                [31, 73],
                [4096, 8192],
                total,
            )
            .unwrap();
        assert!(matches!(
            blobs.original_two_object_publication_construction_data(
                &refs,
                names,
                [31, 73],
                [4096, 8192],
                total - 1
            ),
            Err(StoreError::Quota)
        ));
        assert!(matches!(
            blobs.original_two_object_publication_construction_data(
                &refs,
                names,
                [usize::MAX, 73],
                [4096, 8192],
                usize::MAX
            ),
            Err(StoreError::Quota)
        ));
    }
}
