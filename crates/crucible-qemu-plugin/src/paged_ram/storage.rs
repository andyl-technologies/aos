//! Immutable, authenticated host-side preservation records.
//!
//! This is an operational spill file, not publication into the durable CAS.
//! A returned record identifies bytes that were completely written and verified.
//! A slot cannot be overwritten while any logical page, fork stage, or reader
//! retains its immutable lease. Expired slots are reused instead of accumulating
//! the guest write history indefinitely.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

use crucible_ram::{MetadataBudget, MetadataReservation, PageDigest};
use std::sync::{Arc, Weak};

use super::PAGE_BYTES;
use super::performance::{IoWork, MeasuredIo, PerformanceBank};
use super::source::SourceFetchError;
use crucible_protocol::ram_control::{RamControlIoClass, RamControlPerformance};

/// Retains one immutable disk slot until every logical reader releases it.
#[derive(Clone, Debug)]
pub(crate) struct PageRecord(Arc<PreservationLease>);

#[derive(Debug)]
struct PreservationLease {
    offset: u64,
    valid_length: u32,
    page_version: u64,
    digest: [u8; 32],
}

impl PageRecord {
    /// Returns the authenticated logical content length.
    pub(crate) fn valid_length(&self) -> u32 {
        self.0.valid_length
    }
    /// Returns the independently mutable writer generation.
    pub(crate) fn page_version(&self) -> u64 {
        self.0.page_version
    }
}

/// Bounded disk slots with immutable leased versions and an admitted quota.
#[derive(Debug)]
pub(crate) struct PreservedPages {
    file: Option<File>,
    slots: Vec<Weak<PreservationLease>>,
    next_slot: usize,
    metadata: Option<MetadataReservation>,
    quota_bytes: u64,
    performance: Option<Arc<PerformanceBank>>,
}

impl PreservedPages {
    /// Takes custody of an empty, private spill file and its storage quota.
    ///
    /// # Errors
    /// Refuses an invalid quota, nonempty file, unqualified reservation
    /// filesystem, failed metadata reads, or filesystem capacity reservation.
    /// Existing preserved versions cannot be silently rebound through this constructor.
    pub(crate) fn new(file: File, quota_bytes: u64) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if quota_bytes < PAGE_BYTES as u64
            || quota_bytes > i64::MAX as u64
            || metadata.len() != 0
            || !metadata.is_file()
            || metadata.nlink() != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid private spill file",
            ));
        }
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: fstatfs writes a complete initialized output structure for
        // this owned descriptor; no guest pointer or pathname is involved.
        if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful syscall initialized the entire output.
        let filesystem = unsafe { filesystem.assume_init() };
        // Match the independently qualified project-quota backend. Generic
        // fallocate success is insufficient: some COW filesystems only check
        // currently available space without reserving future write capacity.
        if filesystem.f_type != libc::EXT4_SUPER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "RAM spill requires a qualified ext4 reservation filesystem",
            ));
        }
        // Reserve actual filesystem capacity before any page may be discarded.
        // KEEP_SIZE preserves an empty logical file, while failed reservation
        // remains a host setup failure rather than a later guest substitution.
        // SAFETY: the descriptor is owned and the checked quota fits off_t.
        if unsafe {
            libc::fallocate(
                file.as_raw_fd(),
                libc::FALLOC_FL_KEEP_SIZE,
                0,
                quota_bytes as i64,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file: Some(file),
            slots: Vec::new(),
            next_slot: 0,
            metadata: None,
            quota_bytes,
            performance: None,
        })
    }

    /// Writes, rereads and authenticates an immutable version before publication.
    ///
    /// # Errors
    /// Returns exhausted quota, arithmetic overflow, invalid valid length,
    /// write/read failure, or corruption. Failed writes never publish a lease;
    /// their slot becomes reusable after all temporary references expire.
    pub(crate) fn preserve(
        &mut self,
        bytes: &[u8; PAGE_BYTES],
        valid_length: u32,
        page_version: u64,
    ) -> io::Result<PageRecord> {
        let bank = self.performance.clone();
        self.preserve_measured(
            bytes,
            valid_length,
            page_version,
            bank.as_deref(),
            RamControlIoClass::PreservationWrite,
        )
    }

    /// Copies a parent version into independent backing, charged to the parent interval.
    ///
    /// # Errors
    /// Refuses unavailable leases or propagates actual write, sync or verification errors.
    pub(crate) fn preserve_for_fork(
        &mut self,
        bytes: &[u8; PAGE_BYTES],
        valid_length: u32,
        page_version: u64,
        bank: Option<&PerformanceBank>,
    ) -> io::Result<PageRecord> {
        self.preserve_measured(
            bytes,
            valid_length,
            page_version,
            bank,
            RamControlIoClass::ForkWrite,
        )
    }

    fn preserve_measured(
        &mut self,
        bytes: &[u8; PAGE_BYTES],
        valid_length: u32,
        page_version: u64,
        bank: Option<&PerformanceBank>,
        class: RamControlIoClass,
    ) -> io::Result<PageRecord> {
        let valid = checked_valid_length(valid_length)?;
        if page_version == 0 || self.metadata.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spill metadata/version not admitted",
            ));
        }
        // A rotating cursor avoids rescanning the retained prefix for every
        // initial page. The weak lease remains the sole reuse authority; the
        // cursor is only an access-order hint and cannot retire live versions.
        let slot = (0..self.slots.len())
            .map(|step| (self.next_slot + step) % self.slots.len())
            .find(|slot| self.slots[*slot].strong_count() == 0)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::StorageFull, "all RAM spill slots retained")
            })?;
        self.next_slot = (slot + 1) % self.slots.len();
        let offset = slot as u64 * PAGE_BYTES as u64;
        let digest = *PageDigest::hash(&bytes[..valid])
            .map_err(io::Error::other)?
            .as_bytes();
        let record = PageRecord(Arc::new(PreservationLease {
            offset,
            valid_length,
            page_version,
            digest,
        }));
        // This weak slot never permits reuse while a page, fork stage, or
        // in-flight reader owns any clone of the immutable preservation lease.
        self.slots[slot] = Arc::downgrade(&record.0);
        self.write_data(&bytes[..valid], record.0.offset, bank, class)?;
        let file = self.file()?;
        let measurement = MeasuredIo::begin(bank, RamControlIoClass::Sync);
        let result = file.sync_data();
        measurement.finish(
            IoWork {
                bytes: 0,
                syscalls: 1,
                ..IoWork::default()
            },
            &result,
        );
        result?;

        // Verification happens before the resident copy can be discarded.
        // Tail padding is supplied locally on population, never read as content.
        let mut verified = [0_u8; PAGE_BYTES];
        self.read_measured(
            &record,
            &mut verified,
            bank,
            RamControlIoClass::VerificationRead,
        )?;
        Ok(record)
    }

    /// Reads an exact preserved version into independent resident staging.
    ///
    /// # Errors
    /// Returns invalid references, truncation, I/O failure, or a digest mismatch.
    /// A failed read never permits zero substitution or guest fault resolution.
    pub(crate) fn read(&self, record: &PageRecord, bytes: &mut [u8; PAGE_BYTES]) -> io::Result<()> {
        self.read_measured(
            record,
            bytes,
            self.performance.as_deref(),
            RamControlIoClass::PageRead,
        )
    }

    /// Verifies private observation bytes with the borrowed native page hasher.
    ///
    /// # Errors
    /// Returns invalid custody, truncation, I/O, hashing, or digest errors.
    pub(super) fn read_with_borrowed_hasher(
        &self,
        record: &PageRecord,
        bytes: &mut [u8; PAGE_BYTES],
        hasher: Option<&super::source::NativePageHasher>,
    ) -> Result<(), SourceFetchError> {
        self.read_with_hasher::<true>(
            record,
            bytes,
            self.performance.as_deref(),
            RamControlIoClass::PageRead,
            hasher,
        )
    }

    /// Reads parent backing as actual fork-copy I/O, including canonical tails.
    pub(crate) fn read_for_fork(
        &self,
        record: &PageRecord,
        bytes: &mut [u8; PAGE_BYTES],
    ) -> io::Result<()> {
        self.read_measured(
            record,
            bytes,
            self.performance.as_deref(),
            RamControlIoClass::ForkRead,
        )
    }

    fn read_measured(
        &self,
        record: &PageRecord,
        bytes: &mut [u8; PAGE_BYTES],
        bank: Option<&PerformanceBank>,
        class: RamControlIoClass,
    ) -> io::Result<()> {
        self.read_with_hasher::<false>(record, bytes, bank, class, None)
            .map_err(SourceFetchError::into_io)
    }

    fn read_with_hasher<const BORROWED: bool>(
        &self,
        record: &PageRecord,
        bytes: &mut [u8; PAGE_BYTES],
        bank: Option<&PerformanceBank>,
        class: RamControlIoClass,
        hasher: Option<&super::source::NativePageHasher>,
    ) -> Result<(), SourceFetchError> {
        let valid = if BORROWED {
            if record.0.valid_length == 0 || record.0.valid_length as usize > PAGE_BYTES {
                return Err(SourceFetchError::storage::<true>(
                    io::ErrorKind::InvalidInput,
                    "invalid logical page length",
                ));
            }
            record.0.valid_length as usize
        } else {
            checked_valid_length(record.0.valid_length)?
        };
        let end = record
            .0
            .offset
            .checked_add(PAGE_BYTES as u64)
            .ok_or_else(|| {
                SourceFetchError::storage::<BORROWED>(
                    io::ErrorKind::Other,
                    "spill reference overflow",
                )
            })?;
        if !record.0.offset.is_multiple_of(PAGE_BYTES as u64) || end > self.quota_bytes {
            return Err(SourceFetchError::storage::<BORROWED>(
                io::ErrorKind::InvalidData,
                "spill reference exceeds ownership",
            ));
        }
        let slot = (record.0.offset / PAGE_BYTES as u64) as usize;
        if !self
            .slots
            .get(slot)
            .and_then(Weak::upgrade)
            .is_some_and(|owner| Arc::ptr_eq(&owner, &record.0))
        {
            return Err(SourceFetchError::storage::<BORROWED>(
                io::ErrorKind::InvalidData,
                "spill lease belongs to another store",
            ));
        }
        bytes.fill(0);
        let file = self.file_for_read::<BORROWED>()?;
        if bank.is_some() {
            if BORROWED {
                let measurement = MeasuredIo::begin_observation(bank, class);
                let (work, result) = super::performance::read_exact_at_observation(
                    &mut bytes[..valid],
                    record.0.offset,
                    |bytes, offset| file.read_at(bytes, offset),
                );
                measurement.finish_observation(work, result.is_ok());
                result.map_err(SourceFetchError::from_storage)?;
            } else {
                let measurement = MeasuredIo::begin(bank, class);
                let (work, result) = super::performance::read_exact_at(
                    &mut bytes[..valid],
                    record.0.offset,
                    |bytes, offset| file.read_at(bytes, offset),
                );
                measurement.finish(work, &result);
                result?;
            }
        } else {
            file.read_exact_at(&mut bytes[..valid], record.0.offset)?;
        }
        if BORROWED {
            self.release_cache_for_read::<true>(record.0.offset)?;
        } else {
            self.release_cache(record.0.offset)?;
        }
        let digest = if BORROWED && let Some(hasher) = hasher {
            *hasher.hash(&bytes[..valid])?.as_bytes()
        } else {
            *PageDigest::hash(&bytes[..valid])
                .map_err(|error| {
                    if BORROWED {
                        SourceFetchError::Core(error)
                    } else {
                        SourceFetchError::Io(io::Error::other(error))
                    }
                })?
                .as_bytes()
        };
        if digest != record.0.digest {
            return Err(SourceFetchError::storage::<BORROWED>(
                io::ErrorKind::InvalidData,
                "preserved RAM digest mismatch",
            ));
        }
        Ok(())
    }

    fn write_data(
        &self,
        bytes: &[u8],
        offset: u64,
        bank: Option<&PerformanceBank>,
        class: RamControlIoClass,
    ) -> io::Result<()> {
        let file = self.file()?;
        if bank.is_some() {
            let measurement = MeasuredIo::begin(bank, class);
            let (work, result) =
                super::performance::write_all_at(bytes, offset, |bytes, offset| {
                    file.write_at(bytes, offset)
                });
            measurement.finish(work, &result);
            result
        } else {
            file.write_all_at(bytes, offset)
        }
    }

    /// Starts one diagnostic interval using the same retained metadata authority.
    ///
    /// # Errors
    /// Refuses an existing interval, absent admitted storage or insufficient metadata.
    pub(crate) fn start_performance(&mut self, budget: &MetadataBudget) -> io::Result<()> {
        if self.metadata.is_none() || self.performance.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "performance interval unavailable",
            ));
        }
        self.performance = Some(Arc::new(PerformanceBank::new(budget)?));
        Ok(())
    }

    pub(crate) fn performance(&self, stop: bool) -> io::Result<Option<RamControlPerformance>> {
        self.performance
            .as_ref()
            .map(|bank| bank.snapshot(stop))
            .transpose()
    }

    pub(super) fn performance_bank(&self) -> Option<Arc<PerformanceBank>> {
        self.performance.clone()
    }

    /// Charges all slot and lease capacity before any preservation can run.
    ///
    /// # Errors
    /// Returns arithmetic overflow, metadata admission failure, or failed allocation.
    pub(crate) fn admit_metadata(&mut self, budget: &MetadataBudget) -> io::Result<()> {
        if self.metadata.is_some() {
            return Ok(());
        }
        let slots =
            usize::try_from(self.quota_bytes / PAGE_BYTES as u64).map_err(io::Error::other)?;
        let required = (slots as u64)
            .checked_mul(256)
            .and_then(|bytes| bytes.checked_add(1024))
            .ok_or_else(|| io::Error::other("spill metadata overflow"))?;
        let reservation = budget.reserve_bytes(required).map_err(io::Error::other)?;
        self.slots
            .try_reserve_exact(slots)
            .map_err(io::Error::other)?;
        self.slots.resize_with(slots, Weak::new);
        self.metadata = Some(reservation);
        Ok(())
    }

    /// Compares storage identity before admitting an independent child writer.
    ///
    /// # Errors
    /// Returns missing custody or failed inode metadata reads.
    pub(crate) fn shares_backing_file(&self, candidate: &File) -> io::Result<bool> {
        let current = self.file()?.metadata()?;
        let candidate = candidate.metadata()?;
        Ok(current.dev() == candidate.dev() && current.ino() == candidate.ino())
    }

    /// Exposes an owned descriptor solely for checked child custody manifests.
    ///
    /// # Errors
    /// Returns an error after inherited ownership has already been disarmed.
    pub(crate) fn descriptor(&self) -> io::Result<RawFd> {
        Ok(self.file()?.as_raw_fd())
    }

    /// Disarms a copied child wrapper before native descriptor disposition.
    ///
    /// # Errors
    /// Refuses repeated disarm or missing descriptor custody.
    pub(crate) fn disarm_inherited(&mut self) -> io::Result<RawFd> {
        self.file
            .take()
            .map(IntoRawFd::into_raw_fd)
            .ok_or_else(|| io::Error::other("spill descriptor already disarmed"))
    }

    fn file_for_read<const BORROWED: bool>(&self) -> Result<&File, SourceFetchError> {
        self.file.as_ref().ok_or_else(|| {
            SourceFetchError::storage::<BORROWED>(io::ErrorKind::Other, "spill authority disarmed")
        })
    }

    fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("spill authority disarmed"))
    }

    fn release_cache(&self, offset: u64) -> io::Result<()> {
        self.release_cache_for_read::<false>(offset)
            .map_err(SourceFetchError::into_io)
    }

    fn release_cache_for_read<const BORROWED: bool>(
        &self,
        offset: u64,
    ) -> Result<(), SourceFetchError> {
        // DONTNEED requests reduced retention; success does not prove eviction.
        // Spill page cache remains resident memory charged to the node's hard
        // cgroup memory limit, alongside guest pages and admitted host buffers.
        // Backing quota accounts disk extents and cannot substitute for that
        // resident limit or an independent memory.current observation.
        // SAFETY: the fd is owned, and offsets are admitted aligned extents.
        let status = unsafe {
            libc::posix_fadvise(
                self.file_for_read::<BORROWED>()?.as_raw_fd(),
                offset as i64,
                PAGE_BYTES as i64,
                libc::POSIX_FADV_DONTNEED,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status).into());
        }
        Ok(())
    }
}

fn checked_valid_length(valid_length: u32) -> io::Result<usize> {
    if valid_length == 0 || valid_length as usize > PAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid logical page length",
        ));
    }
    Ok(valid_length as usize)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temporary_file() -> File {
        let name = std::env::temp_dir().join(format!(
            "crucible-pager-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&name)
            .unwrap();
        std::fs::remove_file(name).unwrap();
        file
    }

    // Exercises record integrity and lease reuse independently of allocation
    // qualification. This fixture never creates an admitted paging owner and
    // cannot be compiled into the production constructor or activation path.
    fn unreserved_record_store(file: File, quota_bytes: u64) -> PreservedPages {
        PreservedPages {
            file: Some(file),
            slots: Vec::new(),
            next_slot: 0,
            metadata: None,
            quota_bytes,
            performance: None,
        }
    }

    #[test]
    fn actual_inventory_quota_extends_bootstrap_capacity_on_the_same_private_inode() {
        let file = temporary_file();
        let witness = file.try_clone().unwrap();
        let identity = witness.metadata().unwrap();
        let bootstrap = match PreservedPages::new(file.try_clone().unwrap(), PAGE_BYTES as u64) {
            Ok(store) => store,
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                assert_eq!(witness.metadata().unwrap().len(), 0);
                // This is the negative filesystem-admission branch, not a
                // successful reservation or a substituted test allocator.
                return;
            }
        };
        assert_eq!(witness.metadata().unwrap().len(), 0);
        drop(bootstrap);

        let actual_quota = 4 * PAGE_BYTES as u64;
        let mut storage = PreservedPages::new(file, actual_quota).unwrap();
        let allocated = witness.metadata().unwrap();
        assert_eq!(
            (allocated.dev(), allocated.ino()),
            (identity.dev(), identity.ino())
        );
        assert_eq!(allocated.len(), 0);
        assert!(allocated.blocks() * 512 >= actual_quota);
        storage
            .admit_metadata(&MetadataBudget::new(1024 * 1024))
            .unwrap();

        let retained: Vec<_> = (1..=4)
            .map(|version| {
                storage
                    .preserve(&[version as u8; PAGE_BYTES], PAGE_BYTES as u32, version)
                    .unwrap()
            })
            .collect();
        let mut bytes = [0_u8; PAGE_BYTES];
        for (index, record) in retained.iter().enumerate() {
            storage.read(record, &mut bytes).unwrap();
            assert_eq!(bytes, [index as u8 + 1; PAGE_BYTES]);
        }
        assert_eq!(retained[3].0.offset, 3 * PAGE_BYTES as u64);
        assert_eq!(
            storage
                .preserve(&bytes, PAGE_BYTES as u32, 5)
                .unwrap_err()
                .kind(),
            io::ErrorKind::StorageFull
        );
    }

    #[test]
    fn preserved_versions_survive_later_writes_and_detect_corruption() {
        let file = temporary_file();
        let adversary = file.try_clone().unwrap();
        let mut storage = unreserved_record_store(file, 2 * PAGE_BYTES as u64);
        assert!(storage.shares_backing_file(&adversary).unwrap());
        assert!(!storage.shares_backing_file(&temporary_file()).unwrap());
        storage
            .admit_metadata(&MetadataBudget::new(1024 * 1024))
            .unwrap();
        let first = storage
            .preserve(&[0x31; PAGE_BYTES], PAGE_BYTES as u32, 1)
            .unwrap();
        let second = storage
            .preserve(&[0x52; PAGE_BYTES], PAGE_BYTES as u32, 2)
            .unwrap();
        let mut bytes = [0; PAGE_BYTES];

        storage.read(&first, &mut bytes).unwrap();
        assert_eq!(bytes, [0x31; PAGE_BYTES]);
        storage.read(&second, &mut bytes).unwrap();
        assert_eq!(bytes, [0x52; PAGE_BYTES]);

        adversary.write_all_at(&[0x99], first.0.offset).unwrap();
        assert_eq!(
            storage.read(&first, &mut bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        storage.read(&second, &mut bytes).unwrap();
        assert!(storage.preserve(&bytes, PAGE_BYTES as u32, 3).is_err());
    }

    #[test]
    fn tails_are_logical_content_and_truncation_never_becomes_zeroes() {
        let file = temporary_file();
        let adversary = file.try_clone().unwrap();
        let mut storage = unreserved_record_store(file, PAGE_BYTES as u64);
        storage
            .admit_metadata(&MetadataBudget::new(1024 * 1024))
            .unwrap();
        let record = storage.preserve(&[0x77; PAGE_BYTES], 17, 4).unwrap();
        let mut bytes = [0xff; PAGE_BYTES];

        storage.read(&record, &mut bytes).unwrap();
        assert_eq!(&bytes[..17], &[0x77; 17]);
        assert!(bytes[17..].iter().all(|byte| *byte == 0));

        adversary.set_len(16).unwrap();
        assert_eq!(
            storage.read(&record, &mut bytes).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn churn_reuses_only_expired_leases_and_preserves_retained_versions() {
        let mut storage = unreserved_record_store(temporary_file(), 3 * PAGE_BYTES as u64);
        storage
            .admit_metadata(&MetadataBudget::new(1024 * 1024))
            .unwrap();
        let retained = storage
            .preserve(&[0x42; PAGE_BYTES], PAGE_BYTES as u32, 1)
            .unwrap();
        let mut current = storage
            .preserve(&[0x10; PAGE_BYTES], PAGE_BYTES as u32, 2)
            .unwrap();
        let mut scratch = [0; PAGE_BYTES];
        storage.read(&current, &mut scratch).unwrap();
        assert_eq!(scratch, [0x10; PAGE_BYTES]);

        for version in 3..259 {
            current = storage
                .preserve(&[version as u8; PAGE_BYTES], PAGE_BYTES as u32, version)
                .unwrap();
            storage.read(&current, &mut scratch).unwrap();
            assert_eq!(scratch, [version as u8; PAGE_BYTES]);
            storage.read(&retained, &mut scratch).unwrap();
            assert_eq!(scratch, [0x42; PAGE_BYTES]);
        }
        assert_eq!(storage.slots.len(), 3);
        assert!(storage.file().unwrap().metadata().unwrap().len() <= 3 * PAGE_BYTES as u64);
    }

    #[test]
    fn full_io_completion_does_not_claim_digest_verification_success() {
        let budget = MetadataBudget::new(128 * 1024);
        let file = temporary_file();
        let adversary = file.try_clone().unwrap();
        let mut storage = unreserved_record_store(file, PAGE_BYTES as u64);
        storage.admit_metadata(&budget).unwrap();
        let record = storage.preserve(&[0x77; PAGE_BYTES], 17, 1).unwrap();
        storage.start_performance(&budget).unwrap();
        adversary.write_all_at(&[0x66], 0).unwrap();

        let mut scratch = [0; PAGE_BYTES];
        assert_eq!(
            storage.read(&record, &mut scratch).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let observed = storage.performance(true).unwrap().unwrap();
        let read = observed.io[RamControlIoClass::PageRead as usize];
        assert_eq!(read.transferred_bytes, 17);
        assert_eq!(read.completed, 1);
        assert_eq!(read.failed, 0);
        assert!(observed.complete);
    }

    #[test]
    fn measured_tails_include_verification_and_fork_copy_without_padding() {
        let budget = MetadataBudget::new(128 * 1024);
        let file = temporary_file();
        let adversary = file.try_clone().unwrap();
        let mut parent = unreserved_record_store(file, PAGE_BYTES as u64);
        parent.admit_metadata(&budget).unwrap();
        assert!(parent.performance(false).unwrap().is_none());
        parent.start_performance(&budget).unwrap();
        assert!(parent.start_performance(&budget).is_err());
        let record = parent.preserve(&[0x77; PAGE_BYTES], 17, 1).unwrap();
        let mut scratch = [0; PAGE_BYTES];
        parent.read_for_fork(&record, &mut scratch).unwrap();
        let mut child = unreserved_record_store(temporary_file(), PAGE_BYTES as u64);
        child.admit_metadata(&budget).unwrap();
        child
            .preserve_for_fork(&scratch, 17, 1, parent.performance_bank().as_deref())
            .unwrap();
        adversary.set_len(16).unwrap();
        assert_eq!(
            parent.read(&record, &mut scratch).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let observed = parent.performance(true).unwrap().unwrap();
        let bytes = |class: RamControlIoClass| observed.io[class as usize].transferred_bytes;
        assert_eq!(bytes(RamControlIoClass::PreservationWrite), 17);
        assert_eq!(bytes(RamControlIoClass::VerificationRead), 34);
        assert_eq!(bytes(RamControlIoClass::ForkRead), 17);
        assert_eq!(bytes(RamControlIoClass::ForkWrite), 17);
        assert_eq!(bytes(RamControlIoClass::PageRead), 16);
        assert_eq!(bytes(RamControlIoClass::Sync), 0);
        assert_eq!(observed.io[RamControlIoClass::Sync as usize].completed, 2);
        assert_eq!(observed.io[RamControlIoClass::PageRead as usize].failed, 1);
        assert!(observed.complete);
        assert_eq!(observed.pending_operations, 0);
        assert!(child.performance(false).unwrap().is_none());
    }

    #[test]
    fn borrowed_spill_preserves_static_digest_and_raw_io_without_custom_errors() {
        let file = temporary_file();
        let witness = file.try_clone().unwrap();
        let mut storage = unreserved_record_store(file, 2 * PAGE_BYTES as u64);
        storage
            .admit_metadata(&MetadataBudget::new(128 * 1024))
            .unwrap();
        let record = storage
            .preserve(&[3; PAGE_BYTES], PAGE_BYTES as u32, 1)
            .unwrap();
        let mut output = [0; PAGE_BYTES];
        assert!(
            storage
                .read_with_borrowed_hasher(&record, &mut output, None)
                .is_ok()
        );
        assert_eq!(output, [3; PAGE_BYTES]);

        witness.write_all_at(&[4], record.0.offset).unwrap();
        let borrowed = storage.read_with_borrowed_hasher(&record, &mut output, None);
        assert!(matches!(
            borrowed,
            Err(SourceFetchError::Diagnostic(
                super::super::source::SourceDiagnostic::Storage {
                    kind: io::ErrorKind::InvalidData,
                    message: "preserved RAM digest mismatch",
                }
            ))
        ));
        let ordinary = storage.read(&record, &mut output).unwrap_err();
        assert_eq!(ordinary.kind(), io::ErrorKind::InvalidData);
        assert_eq!(ordinary.to_string(), "preserved RAM digest mismatch");

        witness.set_len(0).unwrap();
        assert!(
            matches!(storage.read_with_borrowed_hasher(&record, &mut output, None),
            Err(SourceFetchError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof && error.get_ref().is_none())
        );
        assert_eq!(
            storage.read(&record, &mut output).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let _held_file = storage.file.take();
        assert!(matches!(
            storage.read_with_borrowed_hasher(&record, &mut output, None),
            Err(SourceFetchError::Diagnostic(
                super::super::source::SourceDiagnostic::Storage {
                    message: "spill authority disarmed",
                    ..
                }
            ))
        ));
    }
}
