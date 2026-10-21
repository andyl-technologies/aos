//! Retains the once-created Setup6 publisher session beneath the paid Source.
//!
//! The canonical holder exists before region, event or mapping birth. Its
//! physical journal survives every refused Original post and ambiguous return;
//! copied purpose bytes are only corroboration for the actual receiver.
// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};

use crucible_host_resources::host_services::process_birth::{ServiceBirthError, SourceHostControlLease};
use crucible_host_resources::host_supervision::HostSupervisionError;
use crucible_qemu_protocol::publisher_subscription::{
    PUBLISHER_HEADER_BYTES, PUBLISHER_REGION_BYTES, PublisherHeader, PublisherPurpose,
};

use super::InstalledSourceAdmission;
use crate::launch_cleanup::LaunchCleanup;
use crate::spawn::OriginalPluginStartup;

const FDINFO_SCRATCH_BYTES: usize = 4097;

mod command;

/// Keeps the containing Source's unique session and its once-attempt history.
#[derive(Debug, Default)]
pub(super) struct PublisherSession {
    attempted: bool,
    body: Option<ManuallyDrop<Box<SessionBody>>>,
}

#[derive(Debug)]
struct SessionBody<Custody = SessionCustody> {
    roles: [Option<OwnedFd>; 3],
    closing_roles: [Option<i32>; 3],
    fdinfo: Option<std::fs::File>,
    closing_fdinfo: Option<i32>,
    mapping: Option<usize>,
    mapping_return_uncertain: bool,
    exported: bool,
    purpose: Option<PublisherPurpose>,
    failure: Option<OperationFailure>,
    original_after: Option<HostSupervisionError>,
    command: command::CommandJournal,
    _custody: Custody,
}

#[derive(Debug)]
struct SessionCustody {
    cleanup: LaunchCleanup,
    // Physical role and mapping return precede this actual account's credit.
    _control: SourceHostControlLease,
}

/// Retains the initiating session refusal and its independent Original post.
#[derive(Debug, thiserror::Error)]
#[error("publisher session refused: {cause}; Original post: {original_after:?}")]
pub(crate) struct PublisherSessionError {
    #[source]
    cause: SessionCause,
    original_after: Option<HostSupervisionError>,
    // A successful reservation followed by a negative post cannot fund birth.
    _control: Option<SourceHostControlLease>,
}

#[derive(Debug, thiserror::Error)]
enum SessionCause {
    #[error("the actual startup owner refused: {0}")]
    Startup(#[source] crate::spawn::PluginStartupError),
    #[error("publisher funding refused: {0}")]
    Funding(#[source] ServiceBirthError),
    #[error(transparent)]
    Operation(#[from] OperationFailure),
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum OperationFailure {
    #[error("the retained Setup Original refused: {0}")]
    Original(#[source] HostSupervisionError),
    #[error("publisher kernel operation failed: {0}")]
    Kernel(#[source] rustix::io::Errno),
    #[error("publisher physical observation failed: {kind:?}, errno {raw:?}")]
    Observation {
        kind: std::io::ErrorKind,
        raw: Option<i32>,
    },
    #[error("publisher session custody or geometry differs")]
    Geometry,
}

impl PublisherSession {
    /// Prices the real allocation, page-rounded backing and concurrent scratch.
    pub(super) fn host_allocation_extent() -> Option<u64> {
        let fixed = size_of::<SessionBody>()
            .checked_mul(2)?
            .checked_add(size_of::<PublisherSessionError>())?
            .checked_add(size_of::<PublisherHeader>())?
            .checked_add(PUBLISHER_HEADER_BYTES)?
            .checked_add(FDINFO_SCRATCH_BYTES)?
            .checked_add(command::CommandJournal::encoding_extent()?)?;
        (fixed as u64).checked_add(backing_bytes()?)
    }

    pub(super) fn prepare(
        &mut self,
        admission: &InstalledSourceAdmission,
        startup: &OriginalPluginStartup,
        cleanup: LaunchCleanup,
        node_index: u32,
        node_count: u32,
    ) -> Result<(), PublisherSessionError> {
        if self.attempted {
            return Err(self.refusal(OperationFailure::Geometry));
        }
        self.attempted = true;
        startup
            .check()
            .map_err(|cause| self.refusal(OperationFailure::Original(cause)))?;
        let bytes = Self::host_allocation_extent()
            .ok_or_else(|| self.refusal(OperationFailure::Geometry))?;

        // Three persistent roles overlap one real /proc fdinfo descriptor.
        let reservation = admission
            .host_purpose()
            .reserve_controls(super::PUBLISHER_DESCRIPTOR_PEAK, bytes);
        let original_after = startup.check().err();
        let control = match (reservation, original_after) {
            (Ok(control), None) => control,
            (Ok(control), Some(cause)) => {
                return Err(PublisherSessionError {
                    cause: OperationFailure::Original(cause).into(),
                    original_after: None,
                    _control: Some(control),
                });
            }
            (Err(cause), original_after) => {
                return Err(PublisherSessionError {
                    cause: SessionCause::Funding(cause),
                    original_after,
                    _control: None,
                });
            }
        };

        // This complete allocation is prepaid before its Box is born. Store it
        // in the canonical holder before observing post or creating any role.
        self.body = Some(ManuallyDrop::new(Box::new(SessionBody {
            roles: std::array::from_fn(|_| None),
            closing_roles: [None; 3],
            fdinfo: None,
            closing_fdinfo: None,
            mapping: None,
            mapping_return_uncertain: false,
            exported: false,
            purpose: None,
            failure: None,
            original_after: None,
            command: command::CommandJournal::default(),
            _custody: SessionCustody {
                cleanup,
                _control: control,
            },
        })));
        let subject = admission.subject();
        let header = PublisherHeader {
            // This canonical once holder admits no second construction or
            // rearm. The constant describes its actual first incarnation.
            lender_generation: 1,
            account_generation: subject.account_generation,
            process_generation: subject.process_generation,
            capability: subject.containing_cap,
            reservation: subject.reservation,
            node_index,
            node_count,
        };
        let body = self.body.as_mut().ok_or_else(|| geometry_error())?;
        body.observe_allocation_post(startup)?;
        body.construct(startup, header)
    }

    pub(super) fn export(
        &mut self,
        startup: &OriginalPluginStartup,
        aliases: &mut [Option<OwnedFd>],
    ) -> Result<PublisherPurpose, PublisherSessionError> {
        let body = self.body.as_mut().ok_or_else(geometry_error)?;
        body.observe(startup)?;
        if aliases.len() != 3 || aliases.iter().any(Option::is_some) || body.exported {
            return Err(geometry_error());
        }
        let purpose = body.purpose.ok_or_else(geometry_error)?;
        body.exported = true;
        let result = (|| {
            for (index, alias) in aliases.iter_mut().enumerate() {
                startup.check().map_err(OperationFailure::Original)?;
                let role = body.roles[index]
                    .as_ref()
                    .ok_or(OperationFailure::Geometry)?;
                *alias = Some(
                    rustix::io::fcntl_dupfd_cloexec(role, crate::spawn::CHILD_SOURCE_FD_MIN)
                        .map_err(OperationFailure::Kernel)?,
                );
                startup.check().map_err(OperationFailure::Original)?;
            }
            Ok(())
        })();
        body.finish(result, startup.check().err())?;
        Ok(purpose)
    }

    fn refusal(&self, fallback: OperationFailure) -> PublisherSessionError {
        let body = self.body.as_ref();
        PublisherSessionError {
            cause: body
                .and_then(|body| body.failure)
                .unwrap_or(fallback)
                .into(),
            original_after: body.and_then(|body| body.original_after),
            _control: None,
        }
    }
}

impl<Custody> SessionBody<Custody> {
    fn observe_allocation_post(
        &mut self,
        startup: &OriginalPluginStartup,
    ) -> Result<(), PublisherSessionError> {
        self.finish(Ok(()), startup.check().err())
    }

    fn observe(&mut self, startup: &OriginalPluginStartup) -> Result<(), PublisherSessionError> {
        if let Some(cause) = self.failure {
            return Err(self.error(cause));
        }
        let result = startup.check().map_err(OperationFailure::Original);
        self.finish(result, None)
    }

    fn construct(
        &mut self,
        startup: &OriginalPluginStartup,
        header: PublisherHeader,
    ) -> Result<(), PublisherSessionError> {
        self.construct_with(|| startup.check(), header)
    }

    // The production caller captures only its actual retained Setup Original.
    // The private physical seam lets controls exercise syscalls without issuing
    // a Source, funding, selected process or Native service authority.
    fn construct_with(
        &mut self,
        mut original: impl FnMut() -> Result<(), HostSupervisionError>,
        header: PublisherHeader,
    ) -> Result<(), PublisherSessionError> {
        if let Some(cause) = self.failure {
            return Err(self.error(cause));
        }
        if self.roles.iter().any(Option::is_some) || self.mapping.is_some() {
            return Err(geometry_error());
        }
        let result = (|| {
            let bytes = header.encode().map_err(|_| OperationFailure::Geometry)?;
            let mut check = || original().map_err(OperationFailure::Original);
            check()?;
            self.roles[0] = Some(
                rustix::fs::memfd_create(
                    c"crucible-publisher-session",
                    rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
                )
                .map_err(OperationFailure::Kernel)?,
            );
            check()?;
            let region = self.roles[0].as_ref().ok_or(OperationFailure::Geometry)?;
            rustix::fs::ftruncate(region, PUBLISHER_REGION_BYTES as u64)
                .map_err(OperationFailure::Kernel)?;
            check()?;
            let mut offset = 0;
            while offset < bytes.len() {
                check()?;
                let count = rustix::io::pwrite(region, &bytes[offset..], offset as u64)
                    .map_err(OperationFailure::Kernel)?;
                check()?;
                if count == 0 {
                    return Err(OperationFailure::Geometry);
                }
                offset += count;
            }
            let seals = rustix::fs::SealFlags::SEAL
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW;
            check()?;
            rustix::fs::fcntl_add_seals(region, seals).map_err(OperationFailure::Kernel)?;
            check()?;
            if rustix::fs::fcntl_get_seals(region).map_err(OperationFailure::Kernel)? != seals {
                return Err(OperationFailure::Geometry);
            }
            check()?;
            // SAFETY: the retained regular memfd has the exact fixed extent.
            // Record the output before any independent Original observation.
            let pointer = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PUBLISHER_REGION_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    region.as_raw_fd(),
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                return Err(observation_error(std::io::Error::last_os_error()));
            }
            self.mapping = Some(pointer as usize);
            check()?;
            // SAFETY: this exact new mapping is still retained in the journal.
            if unsafe { libc::madvise(pointer, PUBLISHER_REGION_BYTES, libc::MADV_DONTFORK) } != 0 {
                return Err(observation_error(std::io::Error::last_os_error()));
            }
            check()?;
            let stat = rustix::fs::fstat(region).map_err(OperationFailure::Kernel)?;
            check()?;
            for index in 1..3 {
                self.roles[index] = Some(
                    rustix::event::eventfd(
                        0,
                        rustix::event::EventfdFlags::CLOEXEC
                            | rustix::event::EventfdFlags::NONBLOCK,
                    )
                    .map_err(OperationFailure::Kernel)?,
                );
                check()?;
            }
            let producer_event = self.event_identity(&mut original, 1)?;
            let receiver_event = self.event_identity(&mut original, 2)?;
            let purpose = PublisherPurpose {
                lender_generation: header.lender_generation,
                account_generation: header.account_generation,
                process_generation: header.process_generation,
                capability: header.capability,
                reservation: header.reservation,
                device: stat.st_dev,
                inode: stat.st_ino,
                producer_event,
                receiver_event,
                backing_bytes: backing_bytes().ok_or(OperationFailure::Geometry)?,
            };
            purpose.encode().map_err(|_| OperationFailure::Geometry)?;
            self.purpose = Some(purpose);
            Ok(())
        })();
        self.finish(result, original().err())
    }

    fn event_identity(
        &mut self,
        original: &mut impl FnMut() -> Result<(), HostSupervisionError>,
        index: usize,
    ) -> Result<u64, OperationFailure> {
        if self.fdinfo.is_some() || self.closing_fdinfo.is_some() {
            return Err(OperationFailure::Geometry);
        }
        original().map_err(OperationFailure::Original)?;
        let descriptor = self.roles[index]
            .as_ref()
            .ok_or(OperationFailure::Geometry)?;
        let (path, length) =
            crate::spawn::plugin_startup::event_identity_path(descriptor.as_raw_fd())
                .map_err(observation_error)?;
        let path = std::str::from_utf8(&path[..length]).map_err(|_| OperationFailure::Geometry)?;
        self.fdinfo = Some(std::fs::File::open(path).map_err(observation_error)?);
        original().map_err(OperationFailure::Original)?;
        let mut bytes = [0; FDINFO_SCRATCH_BYTES];
        let mut length = 0;
        while length < bytes.len() {
            original().map_err(OperationFailure::Original)?;
            let result = self
                .fdinfo
                .as_mut()
                .ok_or(OperationFailure::Geometry)?
                .read(&mut bytes[length..])
                .map_err(observation_error);
            let post = original().err();
            let count = match (result, post) {
                (Ok(count), None) => count,
                (Err(cause), post) => {
                    self.failure = Some(cause);
                    self.original_after = post;
                    return Err(cause);
                }
                (Ok(_), Some(cause)) => return Err(OperationFailure::Original(cause)),
            };
            if count == 0 {
                break;
            }
            length += count;
        }
        if length == bytes.len() {
            return Err(OperationFailure::Geometry);
        }
        let identity = crate::spawn::plugin_startup::decode_event_identity(&bytes[..length])
            .map_err(observation_error)?;
        original().map_err(OperationFailure::Original)?;
        let descriptor = self
            .fdinfo
            .take()
            .ok_or(OperationFailure::Geometry)?
            .into_raw_fd();
        self.closing_fdinfo = Some(descriptor);
        crate::spawn::close_child_source_fd(descriptor).map_err(observation_error)?;
        self.closing_fdinfo = None;
        original().map_err(OperationFailure::Original)?;
        Ok(identity)
    }

    fn finish(
        &mut self,
        result: Result<(), OperationFailure>,
        post: Option<HostSupervisionError>,
    ) -> Result<(), PublisherSessionError> {
        if self.failure.is_none() {
            self.failure = result.err().or(post.map(OperationFailure::Original));
            self.original_after = result.err().and(post);
        }
        self.failure.map_or(Ok(()), |cause| Err(self.error(cause)))
    }

    fn error(&self, cause: OperationFailure) -> PublisherSessionError {
        PublisherSessionError {
            cause: cause.into(),
            original_after: self.original_after,
            _control: None,
        }
    }

    fn return_physical(&mut self, cleanup_proven: bool) -> bool {
        if self.mapping_return_uncertain
            || self.closing_roles.iter().any(Option::is_some)
            || self.closing_fdinfo.is_some()
            || (self.exported && !cleanup_proven)
        {
            return false;
        }
        if let Some(address) = self.mapping.take() {
            // SAFETY: the exact journaled mapping has no remaining host users.
            // Failure keeps its address and complete paid body without retry.
            if unsafe { libc::munmap(address as *mut libc::c_void, PUBLISHER_REGION_BYTES) } != 0 {
                self.mapping = Some(address);
                self.mapping_return_uncertain = true;
                return false;
            }
        }
        if let Some(file) = self.fdinfo.take() {
            let descriptor = file.into_raw_fd();
            self.closing_fdinfo = Some(descriptor);
            if crate::spawn::close_child_source_fd(descriptor).is_err() {
                return false;
            }
            self.closing_fdinfo = None;
        }
        for (index, role) in self.roles.iter_mut().enumerate() {
            if let Some(role) = role.take() {
                let descriptor = role.into_raw_fd();
                self.closing_roles[index] = Some(descriptor);
                if crate::spawn::close_child_source_fd(descriptor).is_err() {
                    return false;
                }
                self.closing_roles[index] = None;
            }
        }
        true
    }
}

impl Drop for PublisherSession {
    fn drop(&mut self) {
        if let Some(body) = self.body.as_mut() {
            let cleanup_proven = body._custody.cleanup.cleanup_proven();
            if body.return_physical(cleanup_proven) {
                // SAFETY: this unique Box is destroyed only after its entire
                // physical journal is closed. Otherwise ManuallyDrop retains
                // the same complete body, cleanup owner and actual account.
                unsafe { ManuallyDrop::drop(body) };
            }
        }
    }
}

fn backing_bytes() -> Option<u64> {
    let page = u64::try_from(rustix::param::page_size()).ok()?;
    if page == 0 {
        return None;
    }
    (PUBLISHER_REGION_BYTES as u64)
        .checked_add(page - 1)?
        .checked_div(page)?
        .checked_mul(page)
}

fn geometry_error() -> PublisherSessionError {
    PublisherSessionError {
        cause: OperationFailure::Geometry.into(),
        original_after: None,
        _control: None,
    }
}

pub(super) fn unavailable() -> PublisherSessionError {
    geometry_error()
}

pub(super) fn startup_refusal(cause: crate::spawn::PluginStartupError) -> PublisherSessionError {
    PublisherSessionError {
        cause: SessionCause::Startup(cause),
        original_after: None,
        _control: None,
    }
}

fn observation_error(error: std::io::Error) -> OperationFailure {
    OperationFailure::Observation {
        kind: error.kind(),
        raw: error.raw_os_error(),
    }
}

#[cfg(test)]
mod tests;
