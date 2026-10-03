//! Actual cap-empty Storage startup custody for original-cutoff worker dispatch.
//!
//! The sole admission consumes the real complete inherited capture. Names and
//! PID1 properties are comparisons, not portable authority. It retains the
//! original image, own process and fixed cgroup through every later recheck.
//! Failure closes the owner before returning and keeps partial originals in
//! the typed admission error. No runtime, floor or all-owner drain is proved.

use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox::immutable_image::{
    ImmutableImageErrorV1, RetainedImmutableFileV1, retain_original_backend_pid1_v1,
};
use aos_sandbox::normal_root::{
    NormalRootStartupErrorV1, StorageWorkerParentDataV3, observe_fixed_storage_worker_parent_v3,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};

use super::{CapturedStorageStartupV1, StorageSystemdListenersV1};
use crate::process::open_cgroup_root;
use crate::service::StorageServiceError;

const STORAGE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const MAXIMUM_EXECUTABLE_BYTES: u64 = 16 * 1024 * 1024;

/// Preserves the first concrete startup failure; it is not a recovery permit.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageOriginalWorkerStartupCauseV3 {
    #[error(transparent)]
    Service(#[from] StorageServiceError),
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    #[error(transparent)]
    Image(#[from] ImmutableImageErrorV1),
    #[error(transparent)]
    Observation(#[from] NormalRootStartupErrorV1),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("original Storage worker startup is unavailable or differs")]
    Binding,
    #[error("original Storage worker startup is permanently closed")]
    Closed,
}

/// Owns rejected original startup custody and its first typed cause.
///
/// This cannot be converted into admitted startup or retried with new facts.
pub struct StorageOriginalWorkerStartupErrorV3 {
    cause: StorageOriginalWorkerStartupCauseV3,
    captured: Option<CapturedStorageStartupV1>,
    partial: Option<Box<StartupCustody>>,
    admitted: Option<StorageOriginalWorkerStartupV3>,
}

impl std::fmt::Debug for StorageOriginalWorkerStartupErrorV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StorageOriginalWorkerStartupErrorV3")
            .field("cause", &self.cause)
            .field("retained_capture", &self.captured.is_some())
            .field("retained_partial", &self.partial.is_some())
            .field("retained_startup", &self.admitted.is_some())
            .finish()
    }
}

impl std::fmt::Display for StorageOriginalWorkerStartupErrorV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(formatter)
    }
}

impl std::error::Error for StorageOriginalWorkerStartupErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl From<StorageServiceError> for StorageOriginalWorkerStartupErrorV3 {
    fn from(error: StorageServiceError) -> Self {
        Self {
            cause: error.into(),
            captured: None,
            partial: None,
            admitted: None,
        }
    }
}

impl StorageOriginalWorkerStartupErrorV3 {
    /// Keeps real startup custody after a later legacy Security admission error.
    ///
    /// This is failure ownership only; it constructs no admitted owner or grant.
    #[must_use]
    pub fn retain_service_failure(
        error: StorageServiceError,
        mut startup: Option<StorageOriginalWorkerStartupV3>,
    ) -> Self {
        if let Some(startup) = startup.as_mut() {
            startup.open = false;
        }
        Self {
            cause: error.into(),
            captured: None,
            partial: None,
            admitted: startup,
        }
    }

    pub(crate) fn retain_closed(
        cause: StorageOriginalWorkerStartupCauseV3,
        mut startup: StorageOriginalWorkerStartupV3,
    ) -> Self {
        startup.open = false;
        Self {
            cause,
            captured: None,
            partial: None,
            admitted: Some(startup),
        }
    }
}

// Optional slots park each acquired original before its first postcheck. A
// failed admission retains this same structure rather than rebuilding a DTO.
#[derive(Default)]
struct StartupCustody {
    original_pid1: Option<File>,
    original_executable: Option<File>,
    process: Option<PidFd>,
    identity: Option<PidFdProcessIdentity>,
    cgroup: Option<RetainedCgroupAnchor>,
    manager: Option<RetainedImmutableFileV1>,
    executable: Option<RetainedImmutableFileV1>,
    fragment: Option<RetainedImmutableFileV1>,
    observed: Option<StorageWorkerParentDataV3>,
    boot: Option<[u8; 16]>,
}

/// Retains genuine fixed Storage startup without floor or effect authority.
///
/// It has no caller FD, PID, path, scalar, profile, or observation constructor.
/// It is move-only; only its same original runtime may borrow it for rechecks.
pub struct StorageOriginalWorkerStartupV3 {
    custody: StartupCustody,
    open: bool,
}

impl StorageOriginalWorkerStartupV3 {
    /// Pre-arms before any observation; Err, unwind, drop and forget stay closed.
    pub(crate) fn recheck(&mut self) -> Result<(), StorageOriginalWorkerStartupCauseV3> {
        let observation = StartupObservation::begin(&mut self.open)?;
        self.custody.recheck()?;
        observation.finish();
        Ok(())
    }
}

struct StartupObservation<'owner> {
    open: &'owner mut bool,
}

impl<'owner> StartupObservation<'owner> {
    fn begin(open: &'owner mut bool) -> Result<Self, StorageOriginalWorkerStartupCauseV3> {
        if !*open {
            return Err(StorageOriginalWorkerStartupCauseV3::Closed);
        }
        *open = false;
        Ok(Self { open })
    }

    fn finish(self) {
        *self.open = true;
    }
}

pub(super) fn admit_captured(
    captured: CapturedStorageStartupV1,
) -> Result<
    (
        StorageSystemdListenersV1,
        Option<OwnedFd>,
        Option<StorageOriginalWorkerStartupV3>,
    ),
    StorageOriginalWorkerStartupErrorV3,
> {
    let Some(original) = captured.pid1_image.as_ref() else {
        return Ok((captured.listeners, None, None));
    };
    let mut custody = Box::new(StartupCustody::default());
    let result = custody.capture(original);
    if let Err(cause) = result {
        return Err(StorageOriginalWorkerStartupErrorV3 {
            cause,
            captured: Some(captured),
            partial: Some(custody),
            admitted: None,
        });
    }
    Ok((
        captured.listeners,
        captured.pid1_image,
        Some(StorageOriginalWorkerStartupV3 {
            custody: *custody,
            open: true,
        }),
    ))
}

impl StartupCustody {
    fn capture(&mut self, original: &OwnedFd) -> Result<(), StorageOriginalWorkerStartupCauseV3> {
        self.original_pid1 = Some(File::from(original.try_clone()?));
        self.manager = Some(retain_original_backend_pid1_v1(
            self.original_pid1
                .as_ref()
                .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?,
        )?);

        self.process = Some(PidFd::open(
            NonZeroU32::new(std::process::id()).ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?,
        )?);
        self.identity = Some(
            self.process
                .as_ref()
                .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?
                .process_identity()?,
        );
        self.cgroup = Some(
            open_cgroup_root()
                .map_err(|error| match error {
                    crate::ZfsWorkerError::Linux(error) => StorageOriginalWorkerStartupCauseV3::Linux(error),
                    other => StorageOriginalWorkerStartupCauseV3::Service(StorageServiceError::Runtime(
                        crate::StorageRuntimeError::Worker(other),
                    )),
                })?
                .resolve(Path::new(STORAGE_CGROUP))?,
        );
        self.observed = Some(observe_fixed_storage_worker_parent_v3()?);

        let observed = self
            .observed
            .as_ref()
            .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?;
        let mut arguments = std::env::args_os();
        for expected in observed.arguments() {
            if arguments
                .next()
                .is_none_or(|actual| std::ffi::OsStr::new(expected) != actual.as_os_str())
            {
                return Err(StorageOriginalWorkerStartupCauseV3::Binding);
            }
        }
        if arguments.next().is_some()
            || observed
                .executable()
                .file_name()
                .is_none_or(|name| name != "aos-storaged")
            || observed
                .executable()
                .parent()
                .is_none_or(|path| path.file_name().is_none_or(|name| name != "bin"))
        {
            return Err(StorageOriginalWorkerStartupCauseV3::Binding);
        }
        self.original_executable = Some(File::open("/proc/self/exe")?);
        self.executable = Some(RetainedImmutableFileV1::retain_with_profile(
            observed.executable().to_path_buf(),
            self.original_executable
                .as_ref()
                .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?
                .try_clone()?,
            None,
            MAXIMUM_EXECUTABLE_BYTES,
            true,
        )?);
        self.fragment = Some(RetainedImmutableFileV1::observe_fragment(
            observed.fragment().to_path_buf(),
        )?);
        self.boot = Some(KernelBootId::current()?.into_bytes());
        self.recheck()
    }

    fn recheck(&self) -> Result<(), StorageOriginalWorkerStartupCauseV3> {
        let manager = self
            .manager
            .as_ref()
            .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?;
        let executable = self
            .executable
            .as_ref()
            .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?;
        let fragment = self
            .fragment
            .as_ref()
            .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?;
        let process = self
            .process
            .as_ref()
            .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?;
        let cgroup = self
            .cgroup
            .as_ref()
            .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?;
        let observed = self
            .observed
            .as_ref()
            .ok_or(StorageOriginalWorkerStartupCauseV3::Binding)?;

        manager.revalidate()?;
        manager.require_executed(1)?;
        executable.revalidate()?;
        executable.require_executed(std::process::id())?;
        fragment.revalidate()?;
        if Some(process.process_identity()?) != self.identity
            || Some(KernelBootId::current()?.into_bytes()) != self.boot
        {
            return Err(StorageOriginalWorkerStartupCauseV3::Binding);
        }
        cgroup.verify_exact_membership(process)?;
        if observe_fixed_storage_worker_parent_v3()? != *observed {
            return Err(StorageOriginalWorkerStartupCauseV3::Binding);
        }
        cgroup.verify_exact_membership(process)?;
        if Some(process.process_identity()?) != self.identity || !process.is_alive()? {
            return Err(StorageOriginalWorkerStartupCauseV3::Binding);
        }
        fragment.revalidate()?;
        manager.revalidate()?;
        manager.require_executed(1)?;
        executable.revalidate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_startup_observation_reopens_only_same_success() {
        let mut open = true;
        StartupObservation::begin(&mut open).unwrap().finish();
        assert!(open);

        drop(StartupObservation::begin(&mut open).unwrap());
        assert!(!open);
        assert!(StartupObservation::begin(&mut open).is_err());
        assert!(!open);
    }

    #[test]
    fn original_startup_unwind_and_forget_remain_closed() {
        let mut open = true;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _observation = StartupObservation::begin(&mut open).unwrap();
            panic!("pure unwind vector");
        }));
        assert!(result.is_err());
        assert!(!open);

        let mut forgotten = true;
        std::mem::forget(StartupObservation::begin(&mut forgotten).unwrap());
        assert!(!forgotten);
    }
}
