//! Anonymous evidence files retained by the admitted catalog and original operation.
//!
//! The file closes before descriptor and metadata credits are returned. Callers
//! can stream comparisons without exposing a cloneable file or escaping its
//! logical byte limit; its extents remain subject to the catalog's kernel quota.

use super::*;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Retains bounded evidence bytes through writing and subsequent comparison.
pub(crate) struct CatalogEvidenceSpool {
    file: Option<File>,
    _descriptors: HostServiceLease,
    _metadata: Arc<dyn Send + Sync>,
    operation: HostOperationGuard,
    authority: Arc<CatalogAuthority>,
    maximum_bytes: u64,
    position: u64,
    length: u64,
}

struct CatalogEvidenceCredit {
    _metadata: Arc<dyn Send + Sync>,
    _authority: Arc<CatalogAuthority>,
}

impl CatalogService {
    pub(in crate::packaged_qemu_executor::ram_catalog) fn reserve_evidence_resident(
        &self,
        bytes: u64,
        supervisor: &HostOperationSupervisor,
    ) -> Result<Arc<dyn Send + Sync>, StoreError> {
        if bytes == 0 {
            return Err(StoreError::Quota);
        }
        let operation = supervisor
            .begin(HostOperationClass::Writeback)
            .map_err(sqlite_supervision_error)?;
        operation.wait_slice().map_err(sqlite_supervision_error)?;
        self.authority.verify()?;

        let charged = bytes
            .checked_add(std::mem::size_of::<CatalogEvidenceCredit>() as u64)
            .and_then(|bytes| bytes.checked_add((2 * std::mem::size_of::<usize>()) as u64))
            .ok_or(StoreError::Quota)?;
        let metadata = reserve_metadata_credit(
            &self.authority.allocator,
            &self.authority.metadata_allocator,
            charged,
        )?;
        operation.complete().map_err(sqlite_supervision_error)?;

        Ok(Arc::new(CatalogEvidenceCredit {
            _metadata: metadata,
            _authority: self.authority.clone(),
        }))
    }

    pub(in crate::packaged_qemu_executor::ram_catalog) fn create_evidence_spool(
        &self,
        directory: &Path,
        maximum_bytes: u64,
        supervisor: &HostOperationSupervisor,
    ) -> Result<CatalogEvidenceSpool, StoreError> {
        if maximum_bytes == 0
            || maximum_bytes > self.authority.policy.resources().backing_peak_bytes
            || maximum_bytes > i64::MAX as u64
        {
            return Err(StoreError::Quota);
        }
        let operation = supervisor
            .begin(HostOperationClass::Writeback)
            .map_err(sqlite_supervision_error)?;
        operation.wait_slice().map_err(sqlite_supervision_error)?;
        self.authority.prepare(directory)?;
        let descriptors = self
            .authority
            .allocator
            .reserve_resources(0, 1, 0)
            .map_err(|_| StoreError::Quota)?;
        let metadata_bytes = std::mem::size_of::<CatalogEvidenceSpool>()
            .checked_add(directory.as_os_str().len())
            .and_then(|bytes| bytes.checked_add(self.authority.policy.root().as_os_str().len()))
            .ok_or(StoreError::Quota)?;
        let metadata = reserve_metadata_credit(
            &self.authority.allocator,
            &self.authority.metadata_allocator,
            u64::try_from(metadata_bytes).map_err(|_| StoreError::Quota)?,
        )?;
        self.authority.verify()?;
        operation.wait_slice().map_err(sqlite_supervision_error)?;

        // The exclusive operator namespace has authenticated every ancestor's
        // inherited project. NOFOLLOW also refuses replacement of this leaf.
        let descriptor = rustix::fs::open(
            directory,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::TMPFILE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|source| StoreError::Io {
            operation: "create quota-bound evidence spool",
            path: directory.to_owned(),
            source: source.into(),
        })?;
        let file = File::from(descriptor);
        self.authority.verify()?;
        operation.wait_slice().map_err(sqlite_supervision_error)?;
        Ok(CatalogEvidenceSpool {
            file: Some(file),
            _descriptors: descriptors,
            _metadata: metadata,
            operation,
            authority: self.authority.clone(),
            maximum_bytes,
            position: 0,
            length: 0,
        })
    }
}

impl CatalogEvidenceSpool {
    /// Closes its actual file before completing the original supervised operation.
    ///
    /// # Errors
    /// Refuses expired or canceled original supervision, failed quota
    /// authentication, or a filesystem synchronization error.
    pub(crate) fn finish(mut self) -> Result<(), StoreError> {
        self.operation
            .wait_slice()
            .map_err(sqlite_supervision_error)?;
        self.authority.verify()?;
        self.file
            .as_ref()
            .ok_or(StoreError::Unauthorized)?
            .sync_all()
            .map_err(|source| StoreError::Io {
                operation: "synchronize evidence spool",
                path: self.authority.policy.root().to_owned(),
                source,
            })?;
        drop(self.file.take());
        self.operation
            .complete()
            .map_err(sqlite_supervision_error)?;
        Ok(())
    }

    fn check(&self) -> io::Result<()> {
        self.operation.wait_slice().map_err(io::Error::other)?;
        self.authority.verify().map_err(io::Error::other)?;
        self.operation.wait_slice().map_err(io::Error::other)?;
        Ok(())
    }

    fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("evidence spool is closed"))
    }
}

impl Read for CatalogEvidenceSpool {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let read = self.file_mut()?.read(buffer)?;
        self.position = self
            .position
            .checked_add(u64::try_from(read).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("evidence spool read position overflow"))?;
        self.check()?;
        Ok(read)
    }
}

impl Write for CatalogEvidenceSpool {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        let requested = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        self.position
            .checked_add(requested)
            .filter(|end| *end <= self.maximum_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::StorageFull,
                    "evidence spool byte limit exceeded",
                )
            })?;
        let written = self.file_mut()?.write(bytes)?;
        self.position = self
            .position
            .checked_add(u64::try_from(written).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("evidence spool write position overflow"))?;
        self.length = self.length.max(self.position);
        self.check()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.file_mut()?.flush()?;
        self.check()
    }
}

impl Seek for CatalogEvidenceSpool {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.check()?;
        let target = bounded_seek_target(position, self.position, self.length, self.maximum_bytes)?;
        let actual = self.file_mut()?.seek(SeekFrom::Start(target))?;
        if actual != target {
            return Err(io::Error::other(
                "evidence spool seek returned another position",
            ));
        }
        self.position = actual;
        self.check()?;
        Ok(actual)
    }
}

fn bounded_seek_target(
    position: SeekFrom,
    current: u64,
    length: u64,
    maximum: u64,
) -> io::Result<u64> {
    let target = match position {
        SeekFrom::Start(target) => Some(target),
        SeekFrom::End(offset) => length.checked_add_signed(offset),
        SeekFrom::Current(offset) => current.checked_add_signed(offset),
    };
    target.filter(|target| *target <= maximum).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "evidence spool seek exceeds byte bounds",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_seek_refuses_negative_overflow_and_out_of_budget_positions() {
        assert_eq!(
            bounded_seek_target(SeekFrom::End(-1), 0, 4, 8).ok(),
            Some(3)
        );
        assert_eq!(
            bounded_seek_target(SeekFrom::Start(8), 0, 4, 8).ok(),
            Some(8)
        );
        assert!(bounded_seek_target(SeekFrom::Start(9), 0, 4, 8).is_err());
        assert!(bounded_seek_target(SeekFrom::Current(-1), 0, 4, 8).is_err());
        assert!(bounded_seek_target(SeekFrom::End(1), 0, u64::MAX, u64::MAX).is_err());
    }
}
