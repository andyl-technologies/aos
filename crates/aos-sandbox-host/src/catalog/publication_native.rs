//! Retains the sole catalog lock, canonical read, and atomic write recipes.
//!
//! Ordinary callers use the same owners locally. Authenticated publication
//! keeps them on the broker through its independent Host and root posts.

use std::error::Error;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::path::BeneathRoot;

use super::{CATALOG_FILE, CATALOG_NEXT_FILE, HostCatalogSnapshot, MAXIMUM_HOST_CATALOG_BYTES};
use crate::{HostError, Result};

pub(super) fn ordinary_error(cause: Option<&(dyn Error + 'static)>) -> HostError {
    if let Some(HostError::Catalog(message)) = cause.and_then(|cause| cause.downcast_ref::<HostError>()) {
        return HostError::Catalog(message.clone());
    }
    HostError::Catalog(cause.map(ToString::to_string)
        .unwrap_or_else(|| "Host catalog original is incomplete".to_owned()))
}

pub(super) fn closed() -> HostError {
    HostError::Fence("Host catalog native original refused; cause retained")
}

fn positive<T, E>(value: &Option<std::result::Result<T, E>>) -> Result<&T> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or_else(closed)
}

fn cause<T, E: Error + 'static>(
    value: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

/// Selects only the ordinary path or the actual private catalog borrower.
pub(super) enum Receiving<'loan, 'original, 'clock> {
    Ordinary,
    Original(&'loan mut crate::plan::HostCatalogReceivingV2<'original, 'clock>),
}

impl Receiving<'_, '_, '_> {
    pub(super) fn admit(&mut self, amount: ResourceVector) -> Result<()> {
        match self {
            Self::Ordinary => Ok(()),
            Self::Original(loan) => loan.admit_additional_v2(amount),
        }
    }

    pub(super) fn before_rename(&mut self) -> Result<()> {
        match self {
            Self::Ordinary => Ok(()),
            Self::Original(loan) => loan.require_rename_clock_v2(),
        }
    }

    pub(super) fn before_write(&mut self) -> Result<()> {
        match self {
            Self::Ordinary => Ok(()),
            Self::Original(loan) => loan.require_write_clock_v2(),
        }
    }
}

#[derive(Default)]
pub(super) struct LockOriginal {
    opening: Option<rustix::io::Result<OwnedFd>>,
    metadata: Option<rustix::io::Result<rustix::fs::Stat>>,
    comparison: Option<Result<()>>,
    locking: Option<rustix::io::Result<()>>,
}

impl LockOriginal {
    pub(super) fn acquire(&mut self, root: &BeneathRoot) -> Result<()> {
        if self.opening.is_some() {
            return Err(closed());
        }
        // The independent open-file description also serializes calls through
        // one publisher instance. It stays live through exact readback.
        self.opening = Some(rustix::fs::openat(
            root.as_fd(),
            ".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ));
        self.metadata = Some(rustix::fs::fstat(positive(&self.opening)?));
        self.comparison = Some((|| {
            let metadata = positive(&self.metadata)?;
            if metadata.st_dev != root.identity().device || metadata.st_ino != root.identity().inode
            {
                return Err(HostError::Catalog(
                    "catalog root identity changed before publication".to_owned(),
                ));
            }
            Ok(())
        })());
        positive(&self.comparison)?;
        self.locking = Some(rustix::fs::flock(
            positive(&self.opening)?,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        ));
        positive(&self.locking).copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.opening)
            .or_else(|| cause(&self.metadata))
            .or_else(|| cause(&self.comparison))
            .or_else(|| cause(&self.locking))
    }
}

#[derive(Default)]
pub(super) struct ReadOriginal {
    file: aos_sandbox_linux::path::BeneathRegularFileReadOriginalV2,
    capture: Option<aos_sandbox_linux::Result<()>>,
    root_metadata: Option<rustix::io::Result<rustix::fs::Stat>>,
    extent: Option<Result<usize>>,
    funding: Option<Result<()>>,
    reading: Option<aos_sandbox_linux::Result<()>>,
    comparison: Option<Result<()>>,
    snapshot: Option<
        std::result::Result<
            HostCatalogSnapshot,
            aos_sandbox_protocol::host_catalog_snapshot::HostCatalogSnapshotError,
        >,
    >,
    post: Option<aos_sandbox_linux::Result<()>>,
    body: Option<Result<()>>,
    absent: bool,
}

impl ReadOriginal {
    pub(super) fn observe(
        &mut self,
        root: &BeneathRoot,
        receiving: &mut Receiving<'_, '_, '_>,
    ) -> Result<()> {
        if self.capture.is_some() {
            return Err(closed());
        }
        self.capture = Some(
            self.file
                .capture_once_v2(root, std::path::Path::new(CATALOG_FILE)),
        );
        self.absent = matches!(self.file.failure(), Some(aos_sandbox_linux::Error::Syscall { source, .. })
            if source.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()));
        if self.absent {
            return Ok(());
        }
        self.body = Some((|| {
            positive(&self.capture)?;
            self.root_metadata = Some(rustix::fs::fstat(root.as_fd()));
            self.extent = Some((|| {
                let metadata = self.file.captured_metadata_data_v2().ok_or_else(closed)?;
                let root_metadata = positive(&self.root_metadata)?;
                if metadata.st_uid != root_metadata.st_uid
                    || metadata.st_nlink != 1
                    || metadata.st_mode & 0o7777 != 0o600
                {
                    return Err(HostError::Catalog(
                        "host catalog is not a protected owner-only regular file".to_owned(),
                    ));
                }
                self.file
                    .captured_bytes_v2()
                    .filter(|bytes| *bytes != 0 && *bytes <= MAXIMUM_HOST_CATALOG_BYTES)
                    .ok_or_else(|| HostError::Catalog("host catalog size is invalid".to_owned()))
            })());
            let extent = *positive(&self.extent)?;
            // The common bounded reader permits only extent+1 native bytes.
            // Growth after fstat cannot allocate an unpriced sixteen-MiB tail.
            let read_bound = extent.checked_add(1).ok_or(HostError::ResourceExhausted)?;
            self.funding = Some(receiving.admit(model_demand(read_bound)?));
            positive(&self.funding)?;
            self.reading = Some(self.file.read_once_v2(extent));
            positive(&self.reading)?;
            let bytes = self.file.bytes_v2().ok_or_else(closed)?;
            self.comparison = Some(if bytes.len() == extent {
                Ok(())
            } else {
                Err(HostError::Catalog(
                    "host catalog changed while being read".to_owned(),
                ))
            });
            positive(&self.comparison)?;
            self.snapshot = Some(HostCatalogSnapshot::decode_canonical(bytes));
            positive(&self.snapshot).map(|_| ())
        })());
        // Reached raw/type/read/decode failures never suppress either common
        // independent fixed-name and same-file native post.
        self.post = Some(
            self.file
                .finish_once_v2(root, std::path::Path::new(CATALOG_FILE)),
        );
        positive(&self.body)?;
        positive(&self.post).copied()
    }

    pub(super) fn value(&self) -> Result<Option<(&HostCatalogSnapshot, &[u8])>> {
        if self.absent {
            return Ok(None);
        }
        positive(&self.body)?;
        positive(&self.post)?;
        Ok(Some((
            positive(&self.snapshot)?,
            self.file.bytes_v2().ok_or_else(closed)?,
        )))
    }

    pub(super) fn take_value(&mut self) -> Result<Option<(HostCatalogSnapshot, Vec<u8>)>> {
        if self.absent {
            return Ok(None);
        }
        positive(&self.body)?;
        positive(&self.post)?;
        let snapshot = self
            .snapshot
            .take()
            .and_then(std::result::Result::ok)
            .ok_or_else(closed)?;
        Ok(Some((
            snapshot,
            self.file.take_completed_bytes_v2().ok_or_else(closed)?,
        )))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.absent {
            return None;
        }
        if matches!(self.capture, Some(Err(_))) {
            return self.file.failure().map(|cause| cause as _);
        }
        cause(&self.root_metadata)
            .or_else(|| cause(&self.extent))
            .or_else(|| cause(&self.funding))
            .or_else(|| {
                if matches!(self.reading, Some(Err(_))) {
                    self.file.failure().map(|cause| cause as _)
                } else {
                    None
                }
            })
            .or_else(|| cause(&self.comparison))
            .or_else(|| cause(&self.snapshot))
            .or_else(|| cause(&self.body))
            .or_else(|| self.file.failure().map(|cause| cause as _))
            .or_else(|| cause(&self.post))
    }

    fn retire_positive_file(&mut self) -> Result<()> {
        if self.absent {
            return Ok(());
        }
        self.file.retire_positive_native_v2().map_err(|_| closed())
    }
}

/// Prices canonical decode, retained input, re-encoding and transition vectors.
/// These byte/model planes create no authority or declared resource capacity.
pub(super) fn model_demand(bytes: usize) -> Result<ResourceVector> {
    let memory = aos_sandbox_protocol::host_catalog_snapshot::
        host_catalog_canonical_decode_receiving_bytes_v2(bytes)
        .and_then(|value| value.checked_add(bytes.checked_mul(4)?))
        .ok_or(HostError::ResourceExhausted)?;
    Ok(ResourceVector::ZERO
        .with(
            D::MemoryBytes,
            u64::try_from(memory).map_err(|_| HostError::ResourceExhausted)?,
        )
        .with(
            D::MetadataEntries,
            u64::try_from(bytes.checked_mul(4).ok_or(HostError::ResourceExhausted)?)
                .map_err(|_| HostError::ResourceExhausted)?,
        ))
}

#[derive(Default)]
pub(super) struct WriteOriginal {
    unlinking: Option<rustix::io::Result<()>>,
    opening: Option<rustix::io::Result<File>>,
    mode: Option<rustix::io::Result<()>>,
    writing: Option<std::io::Result<()>>,
    syncing: Option<std::io::Result<()>>,
    renaming: Option<rustix::io::Result<()>>,
    directory_sync: Option<rustix::io::Result<()>>,
    cleanup: Option<rustix::io::Result<()>>,
    returned: Option<Result<()>>,
}

impl WriteOriginal {
    pub(super) fn publish(
        &mut self,
        root: &BeneathRoot,
        bytes: &[u8],
        receiving: &mut Receiving<'_, '_, '_>,
    ) -> Result<()> {
        if self.unlinking.is_some() {
            return Err(closed());
        }
        // This is the actual final write frontier under the original header.
        // No native pathname mutation precedes it on the authenticated branch.
        receiving.before_write()?;
        self.returned = Some((|| {
            self.unlinking = Some(rustix::fs::unlinkat(
                root.as_fd(),
                CATALOG_NEXT_FILE,
                rustix::fs::AtFlags::empty(),
            ));
            match self.unlinking.as_ref() {
                Some(Ok(())) | Some(Err(rustix::io::Errno::NOENT)) => {}
                _ => return Err(closed()),
            }
            self.opening = Some(
                rustix::fs::openat(
                    root.as_fd(),
                    CATALOG_NEXT_FILE,
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::EXCL
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .map(File::from),
            );
            self.mode = Some(rustix::fs::fchmod(
                positive(&self.opening)?,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            ));
            positive(&self.mode)?;
            let file = self
                .opening
                .as_mut()
                .and_then(|value| value.as_mut().ok())
                .ok_or_else(closed)?;
            self.writing = Some(file.write_all(bytes));
            positive(&self.writing)?;
            self.syncing = Some(file.sync_all());
            positive(&self.syncing)?;
            receiving.before_rename()?;
            self.renaming = Some(rustix::fs::renameat(
                root.as_fd(),
                CATALOG_NEXT_FILE,
                root.as_fd(),
                CATALOG_FILE,
            ));
            positive(&self.renaming)?;
            self.directory_sync = Some(rustix::fs::fsync(root.as_fd()));
            positive(&self.directory_sync).copied()
        })());
        if !matches!(self.returned, Some(Ok(()))) {
            // Cleanup is independently retained and never replaces body-first.
            self.cleanup = Some(rustix::fs::unlinkat(
                root.as_fd(),
                CATALOG_NEXT_FILE,
                rustix::fs::AtFlags::empty(),
            ));
        }
        positive(&self.returned).copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        (match &self.unlinking {
            Some(Err(rustix::io::Errno::NOENT)) => None,
            _ => cause(&self.unlinking),
        })
        .or_else(|| cause(&self.opening))
        .or_else(|| cause(&self.mode))
        .or_else(|| cause(&self.writing))
        .or_else(|| cause(&self.syncing))
        .or_else(|| cause(&self.renaming))
        .or_else(|| cause(&self.directory_sync))
        .or_else(|| cause(&self.returned))
        .or_else(|| cause(&self.cleanup))
    }
}

#[derive(Default)]
pub(super) struct PublicationNativeOriginal {
    pub(super) lock: LockOriginal,
    pub(super) reads: [ReadOriginal; 2],
    pub(super) write: WriteOriginal,
    pub(super) sync: [Option<rustix::io::Result<()>>; 2],
    pub(super) encoded: Option<
        std::result::Result<
            Vec<u8>,
            aos_sandbox_protocol::host_catalog_snapshot::HostCatalogSnapshotError,
        >,
    >,
    pub(super) transition: Option<Result<()>>,
    pub(super) returned: Option<Result<super::HostCatalogPublicationOutcome>>,
    pub(super) recovery: Option<Result<super::HostCatalogPublicationReadback>>,
}

impl PublicationNativeOriginal {
    pub(super) fn retire_positive_files(&mut self) -> Result<()> {
        if !matches!(self.returned, Some(Ok(_))) || self.failure().is_some() {
            return Err(closed());
        }
        // Native Results, canonical bytes and metadata remain. Only complete
        // local descriptors retire, using the ordinary File/OwnedFd teardown.
        drop(self.write.opening.take());
        for read in &mut self.reads {
            read.retire_positive_file()?;
        }
        drop(self.lock.opening.take());
        Ok(())
    }

    pub(super) fn ordinary_error(&self) -> HostError {
        ordinary_error(self.failure())
    }

    pub(super) fn publish(
        &mut self,
        root: &BeneathRoot,
        snapshot: &HostCatalogSnapshot,
        receiving: &mut Receiving<'_, '_, '_>,
    ) -> Result<super::HostCatalogPublicationOutcome> {
        if self.returned.is_some() || self.recovery.is_some() {
            return Err(closed());
        }
        self.returned = Some((|| {
            self.encoded = Some(snapshot.encode());
            let encoded = positive(&self.encoded)?;
            self.lock.acquire(root)?;
            self.reads[0].observe(root, receiving)?;
            if let Some((current, bytes)) = self.reads[0].value()? {
                if current.generation() == snapshot.generation() && bytes == encoded {
                    return Ok(super::HostCatalogPublicationOutcome::Replay);
                }
                self.transition = Some(super::validate_catalog_transition(current, snapshot));
                positive(&self.transition)?;
            }
            self.write.publish(root, encoded, receiving)?;
            self.reads[1].observe(root, receiving)?;
            let (_, visible) = self.reads[1].value()?.ok_or_else(|| {
                HostError::Catalog("published host catalog disappeared during readback".to_owned())
            })?;
            if visible != encoded {
                return Err(HostError::Catalog(
                    "published host catalog failed exact readback".to_owned(),
                ));
            }
            Ok(super::HostCatalogPublicationOutcome::Published)
        })());
        positive(&self.returned).copied()
    }

    pub(super) fn resolve(
        &mut self,
        root: &BeneathRoot,
        intended: &HostCatalogSnapshot,
        receiving: &mut Receiving<'_, '_, '_>,
    ) -> Result<super::HostCatalogPublicationReadback> {
        use super::HostCatalogPublicationReadback as Readback;
        if self.returned.is_some() || self.recovery.is_some() {
            return Err(closed());
        }
        self.recovery = Some((|| {
            self.encoded = Some(intended.encode());
            let intended_bytes = positive(&self.encoded)?;
            self.lock.acquire(root)?;
            self.sync[0] = Some(rustix::fs::fsync(root.as_fd()));
            positive(&self.sync[0])?;
            self.reads[0].observe(root, receiving)?;
            self.sync[1] = Some(rustix::fs::fsync(root.as_fd()));
            positive(&self.sync[1])?;
            self.reads[1].observe(root, receiving)?;
            let first = self.reads[0].value()?;
            if first != self.reads[1].value()? {
                return Err(HostError::Catalog(
                    "host catalog changed during ambiguity readback".to_owned(),
                ));
            }
            let Some((visible, bytes)) = first else {
                return Ok(Readback::Absent);
            };
            if visible.generation() == intended.generation() && bytes == intended_bytes {
                return Ok(Readback::Committed);
            }
            self.transition = Some(super::validate_catalog_transition(visible, intended));
            Ok(if matches!(self.transition, Some(Ok(()))) {
                Readback::Absent
            } else {
                Readback::Conflicting
            })
        })());
        positive(&self.recovery).copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.encoded)
            .or_else(|| self.lock.failure())
            .or_else(|| cause(&self.sync[0]))
            .or_else(|| self.reads[0].failure())
            .or_else(|| self.write.failure())
            .or_else(|| cause(&self.sync[1]))
            .or_else(|| self.reads[1].failure())
            .or_else(|| cause(&self.transition))
            .or_else(|| cause(&self.returned))
            .or_else(|| cause(&self.recovery))
    }
}
