//! Owns detached Capture preparation prefixes on the sole existing native engine.
//!
//! This child consumes only the private authenticated writer attempt. Its
//! failed result keeps every reached mount/directory/file owner until the
//! enclosing genuine Storage worker chooses terminal disposition. ZFS command
//! and boot/clock acquisition subprefixes still need their retained providers;
//! this child does not claim that those provider-local windows are closed.

use std::os::fd::OwnedFd;

use aos_sandbox_linux::mount::{
    CreatedFileSystem, FileSystemCreateFailureV1, FileSystemMountFailureV1,
};

use super::*;
use crate::catalog_transition::execution_capture::readback::CaptureZfsReadbackV1;
use crate::execution_capture_files::{
    CaptureDirectoryPinFailureV2, CaptureFileClaimFailureV2, CaptureFilesWriterFailureV2,
    ClaimedCaptureFilesV1,
};

// Fields follow ordinary reverse-local disposal. Failed inner consuming calls
// dispose their own inputs first through the exact inner ordinary adapter.
pub(crate) struct CaptureWriterPreparationFailureV2 {
    before_process: crate::process::CaptureZfsObservationOriginalV3,
    mounted_process: crate::process::CaptureZfsObservationOriginalV3,
    guard: Option<CaptureWriterDirectoryGuardV1>,
    writer: Option<DetachedCaptureWriterV1>,
    files: Option<ClaimedCaptureFilesV1>,
    pin: Option<PinnedCaptureDirectoryV1>,
    mounted: Option<CaptureZfsReadbackV1>,
    after_root: Option<rustix::fs::Stat>,
    before_root: Option<rustix::fs::Stat>,
    directory: Option<OwnedFd>,
    detached: Option<DetachedMount>,
    created: Option<CreatedFileSystem>,
    filesystem: Option<FileSystemContext>,
    before: Option<CaptureZfsReadbackV1>,
    plan: Option<CaptureZfsReadbackPlanV1>,
    authority: Option<AuthorizedCaptureWriterAttemptV1>,
    native_clock: Option<super::clock::CaptureWorkerClockOriginalV3<15>>,
    cause: Option<PreparationCauseV2>,
}

#[derive(Debug)]
enum PreparationCauseV2 {
    Observation,
    Clock(usize),
    Worker(CaptureWriterWorkerErrorV1),
    Create(FileSystemCreateFailureV1),
    Mount(FileSystemMountFailureV1),
    Pin(CaptureDirectoryPinFailureV2),
    Claim(CaptureFileClaimFailureV2),
    Writer(CaptureFilesWriterFailureV2),
}

impl From<CaptureWriterWorkerErrorV1> for PreparationCauseV2 {
    fn from(error: CaptureWriterWorkerErrorV1) -> Self {
        Self::Worker(error)
    }
}

impl CaptureWriterPreparationFailureV2 {
    fn new(authority: AuthorizedCaptureWriterAttemptV1) -> Self {
        Self {
            before_process: crate::process::CaptureZfsObservationOriginalV3::new(),
            mounted_process: crate::process::CaptureZfsObservationOriginalV3::new(),
            guard: None,
            writer: None,
            files: None,
            pin: None,
            mounted: None,
            after_root: None,
            before_root: None,
            directory: None,
            detached: None,
            created: None,
            filesystem: None,
            before: None,
            plan: None,
            authority: Some(authority), native_clock: None,
            cause: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn retained_binding_for_test(&self)
        -> Option<([u8; 16], ObjectDigest, ObjectDigest, ObjectDigest, ObjectDigest)>
    {
        self.authority.as_ref().map(AuthorizedCaptureWriterAttemptV1::file_custody_binding)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.cause.as_ref()? {
            PreparationCauseV2::Clock(index) => self.native_clock.as_ref()?.failure_at_v3(*index),
            PreparationCauseV2::Observation => self.before_process.failure()
                .or_else(|| self.mounted_process.failure()),
            PreparationCauseV2::Worker(error) => Some(error),
            PreparationCauseV2::Create(error) => Some(error),
            PreparationCauseV2::Mount(error) => Some(error),
            PreparationCauseV2::Pin(error) => Some(error),
            PreparationCauseV2::Claim(error) => error.native_io_failure_v3().or(Some(error)),
            PreparationCauseV2::Writer(error) => Some(error),
        }
    }

    #[cfg(test)]
    pub(super) fn into_ordinary_error(mut self) -> CaptureWriterWorkerErrorV1 {
        let error = match self.cause.take() {
            Some(PreparationCauseV2::Observation | PreparationCauseV2::Clock(_)) => std::process::abort(),
            Some(PreparationCauseV2::Worker(error)) => error,
            Some(PreparationCauseV2::Create(error)) => error.into_ordinary_error().into(),
            Some(PreparationCauseV2::Mount(error)) => error.into_ordinary_error().into(),
            Some(PreparationCauseV2::Pin(error)) => error.into_ordinary_error().into(),
            Some(PreparationCauseV2::Claim(error)) => error.into_ordinary_error().into(),
            Some(PreparationCauseV2::Writer(error)) => error.into_ordinary_error().into(),
            None => std::process::abort(),
        };
        drop(self);
        error
    }
}

impl std::fmt::Debug for CaptureWriterPreparationFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CaptureWriterPreparationFailureV2")
            .field("cause", &self.cause).finish_non_exhaustive()
    }
}

impl std::fmt::Display for CaptureWriterPreparationFailureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.failure() {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("detached Capture preparation is incomplete"),
        }
    }
}

impl std::error::Error for CaptureWriterPreparationFailureV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure()
    }
}

fn held<T>(slot: &Option<T>) -> &T {
    match slot {
        Some(value) => value,
        None => std::process::abort(),
    }
}

fn take<T>(slot: &mut Option<T>) -> T {
    match slot.take() {
        Some(value) => value,
        None => std::process::abort(),
    }
}

#[cfg(test)]
pub(super) fn prepare_retaining_v2(
    authority: AuthorizedCaptureWriterAttemptV1,
    zfs: &ZfsHelperContract,
) -> Result<PreparedDetachedCaptureWriterV1, CaptureWriterPreparationFailureV2> {
    prepare_with_retention_v3(authority, zfs, true, None)
}

#[cfg(test)]
pub(super) fn prepare_ordinary_v3(
    authority: AuthorizedCaptureWriterAttemptV1,
    zfs: &ZfsHelperContract,
) -> Result<PreparedDetachedCaptureWriterV1, CaptureWriterWorkerErrorV1> {
    prepare_with_retention_v3(authority, zfs, false, None)
        .map_err(CaptureWriterPreparationFailureV2::into_ordinary_error)
}

pub(super) fn prepare_in_scope_v3(
    authority: AuthorizedCaptureWriterAttemptV1,
    zfs: &ZfsHelperContract,
    execution: &mut crate::process::worker_aggregate::WorkerExecutionScopeV1<'_>,
    context: &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>,
) -> Result<PreparedDetachedCaptureWriterV1, CaptureWriterPreparationFailureV2> {
    prepare_with_retention_v3(authority, zfs, true, Some((execution, context)))
}

fn prepare_with_retention_v3(
    authority: AuthorizedCaptureWriterAttemptV1,
    zfs: &ZfsHelperContract,
    retain_process: bool,
    selected: Option<(&mut crate::process::worker_aggregate::WorkerExecutionScopeV1<'_>,
        &crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>)>,
) -> Result<PreparedDetachedCaptureWriterV1, CaptureWriterPreparationFailureV2> {
    let mut original = CaptureWriterPreparationFailureV2::new(authority);
    let context = selected.as_ref().map(|(_, context)| *context);
    let execution = selected.map(|(execution, context)| {
        let authority = held(&original.authority);
        original.native_clock = Some(super::clock::CaptureWorkerClockOriginalV3::from_worker_v3(
            context, authority.kernel_boot_id, authority.deadline_boottime_nanoseconds,
        ));
        execution
    });
    let result = prepare_body_v2(&mut original, zfs, retain_process, execution, context);
    // The distinct fifth native sample is armed by the real selected caller's
    // compiled preparation recipe and remains owed after every primary error.
    let owed = original.native_clock.as_mut().map(|clock| clock.observe_once_v3(4));
    if let Err(cause) = result {
        original.cause = Some(cause);
        return Err(original);
    }

    if matches!(owed, Some(Err(()))) {
        original.cause = Some(PreparationCauseV2::Clock(4));
        return Err(original);
    }

    if let Some(context) = context {
        let authority = held(&original.authority);
        let writer = match original.writer.as_mut() {
            Some(writer) => writer,
            None => std::process::abort(),
        };
        if let Err(error) = writer.install_native_io_once_v3(
            context, authority.kernel_boot_id, authority.deadline_boottime_nanoseconds,
        ) {
            original.cause = Some(PreparationCauseV2::Worker(CaptureWriterWorkerErrorV1::Writer(error)));
            return Err(original);
        }
    }

    Ok(PreparedDetachedCaptureWriterV1 {
        authority: take(&mut original.authority),
        detached: take(&mut original.detached),
        writer: take(&mut original.writer),
        guard: take(&mut original.guard),
        before_observation_digest: held(&original.before).observation_digest,
        mounted_observation_digest: held(&original.mounted).observation_digest,
    })
}

fn prepare_body_v2(
    original: &mut CaptureWriterPreparationFailureV2,
    zfs: &ZfsHelperContract,
    retain_process: bool,
    mut execution: Option<&mut crate::process::worker_aggregate::WorkerExecutionScopeV1<'_>>,
    context: Option<&crate::process::capture_worker::AuthenticatedCaptureWorkerContextV3<'_>>,
) -> Result<(), PreparationCauseV2> {
    let authority = held(&original.authority);
    check_live_v3(authority, original.native_clock.as_mut(), 0)?;
    original.plan = Some(CaptureZfsReadbackPlanV1::new(
        &authority.verified,
        &authority.retained,
        authority.metadata_headroom_bytes,
        authority.minimum_remaining_bytes,
    ).map_err(CaptureWriterWorkerErrorV1::from)?);
    original.before = Some(if let Some(execution) = execution.as_deref_mut() {
        crate::process::observe_capture_zfs_in_scope_v3(
            zfs, held(&original.plan), &mut original.before_process, execution,
            authority.deadline_boottime_nanoseconds,
        ).map_err(|()| PreparationCauseV2::Observation)?
    } else if retain_process {
        crate::process::observe_capture_zfs_retaining_v3(
            zfs, held(&original.plan), &mut original.before_process,
        ).map_err(|()| PreparationCauseV2::Observation)?
    } else {
        crate::process::observe_capture_zfs_for(zfs, held(&original.plan))
            .map_err(CaptureWriterWorkerErrorV1::from)?
    });
    check_live_v3(authority, original.native_clock.as_mut(), 1)?;

    check_selected_live_v3(original.native_clock.as_mut(), 5)?;
    original.filesystem = Some(FileSystemContext::open("zfs")
        .map_err(CaptureWriterWorkerErrorV1::from)?);
    check_selected_live_v3(original.native_clock.as_mut(), 6)?;
    match original.filesystem.as_mut() {
        Some(filesystem) => filesystem.set_string("source", authority.verified.dataset_name())
            .map_err(CaptureWriterWorkerErrorV1::from)?,
        None => std::process::abort(),
    }
    check_selected_live_v3(original.native_clock.as_mut(), 7)?;
    original.created = Some(take(&mut original.filesystem).create_retaining_v1()
        .map_err(PreparationCauseV2::Create)?);
    check_selected_live_v3(original.native_clock.as_mut(), 8)?;
    original.detached = Some(take(&mut original.created).mount_retaining_v1()
        .map_err(PreparationCauseV2::Mount)?);
    let detached = held(&original.detached);
    check_selected_live_v3(original.native_clock.as_mut(), 9)?;
    detached.set_attributes(
        false,
        MountAttributes::secure_writable().with_no_exec(true),
        None,
    ).map_err(CaptureWriterWorkerErrorV1::from)?;
    check_selected_live_v3(original.native_clock.as_mut(), 10)?;
    original.directory = Some(rustix::fs::openat(
        detached.as_fd(),
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ).map_err(CaptureWriterWorkerErrorV1::from)?);
    let directory = held(&original.directory);
    check_selected_live_v3(original.native_clock.as_mut(), 11)?;
    original.before_root = Some(rustix::fs::fstat(directory)
        .map_err(CaptureWriterWorkerErrorV1::from)?);
    let before = held(&original.before_root);
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Directory
        || before.st_uid != 0 || before.st_dev == 0 || before.st_ino == 0
    {
        return Err(CaptureWriterWorkerErrorV1::InvalidAttempt.into());
    }
    check_selected_live_v3(original.native_clock.as_mut(), 12)?;
    rustix::fs::fchmod(directory, rustix::fs::Mode::from_raw_mode(0o700))
        .map_err(CaptureWriterWorkerErrorV1::from)?;
    check_selected_live_v3(original.native_clock.as_mut(), 13)?;
    rustix::fs::fsync(directory).map_err(CaptureWriterWorkerErrorV1::from)?;
    check_selected_live_v3(original.native_clock.as_mut(), 14)?;
    original.after_root = Some(rustix::fs::fstat(directory)
        .map_err(CaptureWriterWorkerErrorV1::from)?);
    let after = held(&original.after_root);
    if after.st_dev != before.st_dev || after.st_ino != before.st_ino
        || after.st_uid != 0 || after.st_mode & 0o7777 != 0o700
    {
        return Err(CaptureWriterWorkerErrorV1::InvalidAttempt.into());
    }

    // Keep the same before-mount and mounted readback frontiers. The selected
    // process provider must retain its own native subprefix on refusal.
    original.mounted = Some(if let Some(execution) = execution.as_deref_mut() {
        crate::process::observe_capture_zfs_in_scope_v3(
            zfs, held(&original.plan), &mut original.mounted_process, execution,
            authority.deadline_boottime_nanoseconds,
        ).map_err(|()| PreparationCauseV2::Observation)?
    } else if retain_process {
        crate::process::observe_capture_zfs_retaining_v3(
            zfs, held(&original.plan), &mut original.mounted_process,
        ).map_err(|()| PreparationCauseV2::Observation)?
    } else {
        crate::process::observe_capture_zfs_for(zfs, held(&original.plan))
            .map_err(CaptureWriterWorkerErrorV1::from)?
    });
    check_live_v3(authority, original.native_clock.as_mut(), 2)?;
    original.pin = Some(PinnedCaptureDirectoryV1::from_authorized_detached_root_retaining_v2(
        authority, detached, take(&mut original.directory),
    ).map_err(PreparationCauseV2::Pin)?);
    let pin = take(&mut original.pin);
    original.files = Some(match context {
        Some(context) => pin.claim_files_retaining_in_scope_v3(
            context, authority.kernel_boot_id, authority.deadline_boottime_nanoseconds,
        ),
        None => pin.claim_files_retaining_v2(),
    }.map_err(PreparationCauseV2::Claim)?);
    let (writer, guard) = take(&mut original.files).into_writer_retaining_v2(&authority.retained)
        .map_err(PreparationCauseV2::Writer)?;
    original.writer = Some(writer);
    original.guard = Some(guard);
    check_live_v3(authority, original.native_clock.as_mut(), 3)?;
    Ok(())
}


fn check_live_v3(
    authority: &AuthorizedCaptureWriterAttemptV1,
    clock: Option<&mut super::clock::CaptureWorkerClockOriginalV3<15>>,
    index: usize,
) -> Result<(), PreparationCauseV2> {
    match clock {
        Some(clock) => clock.observe_once_v3(index).map_err(|()| PreparationCauseV2::Clock(index)),
        None => authority.check_live().map_err(Into::into),
    }
}


fn check_selected_live_v3(
    clock: Option<&mut super::clock::CaptureWorkerClockOriginalV3<15>>,
    index: usize,
) -> Result<(), PreparationCauseV2> {
    match clock {
        Some(clock) => clock.observe_once_v3(index).map_err(|()| PreparationCauseV2::Clock(index)),
        None => Ok(()),
    }
}
