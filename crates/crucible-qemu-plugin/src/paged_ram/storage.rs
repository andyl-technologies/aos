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
        self.file()?
            .write_all_at(&bytes[..valid], record.0.offset)?;
        self.file()?.sync_data()?;

        // Verification happens before the resident copy can be discarded.
        // Tail padding is supplied locally on population, never read as content.
        let mut verified = [0_u8; PAGE_BYTES];
        self.read(&record, &mut verified)?;
        Ok(record)
    }

    /// Reads an exact preserved version into independent resident staging.
    ///
    /// # Errors
    /// Returns invalid references, truncation, I/O failure, or a digest mismatch.
    /// A failed read never permits zero substitution or guest fault resolution.
    pub(crate) fn read(&self, record: &PageRecord, bytes: &mut [u8; PAGE_BYTES]) -> io::Result<()> {
        let valid = checked_valid_length(record.0.valid_length)?;
        let end = record
            .0
            .offset
            .checked_add(PAGE_BYTES as u64)
            .ok_or_else(|| io::Error::other("spill reference overflow"))?;
        if !record.0.offset.is_multiple_of(PAGE_BYTES as u64) || end > self.quota_bytes {
            return Err(io::Error::new(
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "spill lease belongs to another store",
            ));
        }
        bytes.fill(0);
        self.file()?
            .read_exact_at(&mut bytes[..valid], record.0.offset)?;
        self.release_cache(record.0.offset)?;
        let digest = *PageDigest::hash(&bytes[..valid])
            .map_err(io::Error::other)?
            .as_bytes();
        if digest != record.0.digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "preserved RAM digest mismatch",
            ));
        }
        Ok(())
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

    fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("spill authority disarmed"))
    }

    fn release_cache(&self, offset: u64) -> io::Result<()> {
        // DONTNEED requests reduced retention; success does not prove eviction.
        // Spill page cache remains resident memory charged to the node's hard
        // cgroup memory limit, alongside guest pages and admitted host buffers.
        // Backing quota accounts disk extents and cannot substitute for that
        // resident limit or an independent memory.current observation.
        // SAFETY: the fd is owned, and offsets are admitted aligned extents.
        let status = unsafe {
            libc::posix_fadvise(
                self.file()?.as_raw_fd(),
                offset as i64,
                PAGE_BYTES as i64,
                libc::POSIX_FADV_DONTNEED,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
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
}
