//! Sole fixed Storage V3 launch capture, original custody and cgroup opener.
//!
//! Names and PID1 properties remain comparisons, not portable authority. This
//! engine retains the original image, own process and fixed cgroup through the
//! same observations. Rejected custody cannot be converted back into a capture.
//! It proves no floor, backend readiness, resource admission or native effect.

use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inherited_fd::duplicate_initial_activation_table;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use aos_sandbox_protocol::operator_storage_repair_transport_v3::OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V3;

use crate::immutable_image::{
    ImmutableImageErrorV1, RetainedImmutableFileV1, retain_original_backend_pid1_v1,
};
use super::{
    NormalRootStartupErrorV1, StorageWorkerParentDataV3, observe_fixed_storage_worker_parent_v3,
};

const STORAGE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const MAXIMUM_EXECUTABLE_BYTES: u64 = 16 * 1024 * 1024;

/// Reports the actual failure of the fixed launch-table capture.
#[derive(Debug, thiserror::Error)]
pub enum StorageLaunchCaptureErrorV3 {
    /// The fixed names, count or process correlation differs.
    #[error("Storage service activation is invalid: {0}")]
    Activation(String),
    /// Duplication of the original inherited table failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A fixed record-subject listener failed validation.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
}

/// Reports the actual failure of the fixed cgroup-root opener.
#[derive(Debug, thiserror::Error)]
pub enum StorageCgroupRootErrorV3 {
    /// Opening the fixed native directory failed.
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
    /// Adoption of the actual cgroup descriptor failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
}

/// Preserves a concrete original-custody failure without Storage dependencies.
#[derive(Debug, thiserror::Error)]
pub enum StorageWorkerOriginCauseV3 {
    /// A retained Linux original or observation failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The fixed cgroup open syscall failed.
    #[error(transparent)]
    CgroupKernel(rustix::io::Errno),
    /// An immutable image observation failed.
    #[error(transparent)]
    Image(#[from] ImmutableImageErrorV1),
    /// The genuine fixed-unit observation failed.
    #[error(transparent)]
    Observation(#[from] NormalRootStartupErrorV1),
    /// An original file operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Required custody is unavailable or differs.
    #[error("original Storage worker startup is unavailable or differs")]
    Binding,
    /// A prior observation permanently closed the owner.
    #[error("original Storage worker startup is permanently closed")]
    Closed,
}

const EXPECTED_FD_NAME: &str = "aos-storaged";
const EXPORT_FD_NAME: &str = "aos-storaged-root-export";
const LIVE_EXPORT_FD_NAME: &str = "aos-storaged-live-export-request";
const ZFS_HOLD_FD_NAME: &str = "aos-storaged-zfs-hold-request";
const OPERATOR_REPAIR_FD_NAME: &str = "aos-storaged-operator-repair";
const EXISTING_OUTPUT_FD_NAME: &str = "aos-storaged-existing-output";

/// Names the parent-only original PID 1 image delivered by fixed-unit OpenFile.
pub const PID1_LAUNCH_IMAGE_FD_NAME: &str = "aos-method46-pid1-image";

/// The fixed Storage listener roles, without any TPM or image authorization.
pub type StorageLaunchListenersV3 = (
    RecordSubjectListener,
    RecordSubjectListener,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
);

/// Owns an observed complete startup table, not authenticated image custody.
pub struct CapturedStorageLaunchV3 {
    listeners: StorageLaunchListenersV3,
    pid1_image: Option<OwnedFd>,
}

impl CapturedStorageLaunchV3 {
    /// Returns observed roles and the unverified original launch image.
    #[must_use]
    pub fn into_parts(self) -> (StorageLaunchListenersV3, Option<OwnedFd>) {
        (self.listeners, self.pid1_image)
    }

    /// Admits custody only from this actual fixed launch capture.
    ///
    /// # Errors
    ///
    /// Rejects changed process, unit, image or confinement while retaining this
    /// same capture and the acquired partial originals in a negative owner.
    pub fn into_original_worker_parts(
        self,
    ) -> Result<
        (StorageLaunchListenersV3, Option<OwnedFd>, Option<StorageWorkerOriginV3>),
        StorageWorkerOriginAdmissionErrorV3,
    > {
        admit_captured(self)
    }
}

/// Owns a rejected original table followed by its partial observations.
///
/// No method returns descriptors or permits this prefix to be admitted again.
pub struct RejectedStorageWorkerOriginV3 {
    captured: Option<CapturedStorageLaunchV3>,
    partial: Option<Box<StartupCustody>>,
}

impl RejectedStorageWorkerOriginV3 {
    /// Describes negative custody occupancy for the existing error formatter.
    #[must_use]
    pub fn retained_prefix_presence(&self) -> (bool, bool) {
        (self.captured.is_some(), self.partial.is_some())
    }
}

/// Owns the actual admission cause before its rejected custody prefix.
pub struct StorageWorkerOriginAdmissionErrorV3 {
    cause: StorageWorkerOriginCauseV3,
    captured: Option<CapturedStorageLaunchV3>,
    partial: Option<Box<StartupCustody>>,
}

impl std::fmt::Debug for StorageWorkerOriginAdmissionErrorV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StorageWorkerOriginAdmissionErrorV3")
            .field("cause", &self.cause)
            .field("retained_capture", &self.captured.is_some())
            .field("retained_partial", &self.partial.is_some())
            .finish()
    }
}

impl std::fmt::Display for StorageWorkerOriginAdmissionErrorV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(formatter)
    }
}

impl std::error::Error for StorageWorkerOriginAdmissionErrorV3 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl StorageWorkerOriginAdmissionErrorV3 {
    /// Transfers the typed cause and opaque negative prefix without new I/O.
    #[must_use]
    pub fn into_failure(self) -> (StorageWorkerOriginCauseV3, RejectedStorageWorkerOriginV3) {
        (
            self.cause,
            RejectedStorageWorkerOriginV3 {
                captured: self.captured,
                partial: self.partial,
            },
        )
    }
}

/// Captures fixed listeners and at most one observed parent-only image FD.
///
/// Every numeric entry is copied before opening any other retained descriptor.
/// Names and environment are correlation hints only. The security owner must
/// independently authenticate the fixed unit, image mode, and actual image.
///
/// # Errors
///
/// Rejects malformed names/counts, a nonclosed startup table, invalid listeners,
/// or an unknown descriptor. This single-shot operation cannot be retried.
pub fn capture_storage_launch_v3() -> Result<CapturedStorageLaunchV3, StorageLaunchCaptureErrorV3> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| activation_error("current PID does not fit u32"))?;
    let descriptor_count = environment_u32("LISTEN_FDS")?;
    if listen_pid != current_pid || !(2..=7).contains(&descriptor_count) {
        return Err(activation_error(
            "two to seven named startup entries are required",
        ));
    }

    let names = std::env::var("LISTEN_FDNAMES")
        .map_err(|_| activation_error("activated descriptor names are absent"))?;
    if names.len() > 7 * 256
        || !names.is_ascii()
        || names.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(activation_error(
            "activated descriptor names exceed fixed bounds",
        ));
    }
    let names: Vec<_> = names.split(':').collect();
    if !valid_startup_names(&names, descriptor_count) {
        return Err(activation_error("activated descriptor names are invalid"));
    }

    // Duplicate every inherited entry before a new descriptor can reuse a slot.
    let descriptors = duplicate_initial_activation_table(descriptor_count as usize)?;
    let mut controller = None;
    let mut export = None;
    let mut live_export = None;
    let mut zfs_hold = None;
    let mut operator_repair = None;
    let mut existing_output = None;
    let mut pid1_image = None;
    for (name, descriptor) in names.into_iter().zip(descriptors) {
        match name {
            EXPECTED_FD_NAME => controller = Some(descriptor),
            EXPORT_FD_NAME => export = Some(descriptor),
            LIVE_EXPORT_FD_NAME => live_export = Some(descriptor),
            ZFS_HOLD_FD_NAME => zfs_hold = Some(descriptor),
            OPERATOR_REPAIR_FD_NAME => operator_repair = Some(descriptor),
            EXISTING_OUTPUT_FD_NAME => existing_output = Some(descriptor),
            PID1_LAUNCH_IMAGE_FD_NAME => pid1_image = Some(descriptor),
            _ => return Err(activation_error("activated descriptor name is unknown")),
        }
    }
    let controller = controller.ok_or_else(|| activation_error("controller listener is absent"))?;
    let export = export.ok_or_else(|| activation_error("root-export listener is absent"))?;
    let controller = RecordSubjectListener::from_owned(controller)?;
    let export = RecordSubjectListener::from_owned(export)?;
    let live_export = live_export
        .map(RecordSubjectListener::from_owned)
        .transpose()?;
    let zfs_hold = zfs_hold
        .map(RecordSubjectListener::from_owned)
        .transpose()?;
    let operator_repair = operator_repair
        .map(RecordSubjectListener::from_owned)
        .transpose()?;
    let existing_output = existing_output
        .map(RecordSubjectListener::from_owned)
        .transpose()?;
    controller.require_local_filesystem_path(std::path::Path::new(
        "/run/aos/sandbox-storage/control.sock",
    ))?;
    export.require_local_filesystem_path(std::path::Path::new(
        "/run/aos/sandbox-storage/root-export.sock",
    ))?;
    if let Some(listener) = &live_export {
        listener.require_local_filesystem_path(std::path::Path::new(
            "/run/aos/sandbox-storage/live-export-request.sock",
        ))?;
    }
    if let Some(listener) = &zfs_hold {
        listener.require_local_filesystem_path(std::path::Path::new(
            "/run/aos/sandbox-storage/zfs-hold-request.sock",
        ))?;
    }
    if let Some(listener) = &operator_repair {
        listener.require_local_filesystem_path(std::path::Path::new(
            OPERATOR_STORAGE_REPAIR_SOCKET_PATH_V3,
        ))?;
    }
    if let Some(listener) = &existing_output {
        listener.require_local_filesystem_path(std::path::Path::new(
            "/run/aos/sandbox-storage/existing-output.sock",
        ))?;
    }
    Ok(CapturedStorageLaunchV3 {
        listeners: (
            controller,
            export,
            live_export,
            zfs_hold,
            operator_repair,
            existing_output,
        ),
        pid1_image,
    })
}

fn valid_startup_names(names: &[&str], descriptor_count: u32) -> bool {
    let images = names
        .iter()
        .filter(|name| **name == PID1_LAUNCH_IMAGE_FD_NAME)
        .count();
    let listeners = names
        .iter()
        .copied()
        .filter(|name| *name != PID1_LAUNCH_IMAGE_FD_NAME)
        .collect::<Vec<_>>();
    (2..=7).contains(&descriptor_count)
        && names.len() == descriptor_count as usize
        && images <= 1
        && valid_listener_names(&listeners, descriptor_count - images as u32)
}

fn valid_listener_names(names: &[&str], descriptor_count: u32) -> bool {
    (2..=6).contains(&descriptor_count)
        && names.len() == descriptor_count as usize
        && names.contains(&EXPECTED_FD_NAME)
        && names.contains(&EXPORT_FD_NAME)
        && names
            .iter()
            .filter(|name| **name == EXPECTED_FD_NAME)
            .count()
            == 1
        && names.iter().filter(|name| **name == EXPORT_FD_NAME).count() == 1
        && names
            .iter()
            .filter(|name| **name == LIVE_EXPORT_FD_NAME)
            .count()
            <= 1
        && names
            .iter()
            .filter(|name| **name == ZFS_HOLD_FD_NAME)
            .count()
            <= 1
        && names
            .iter()
            .filter(|name| **name == OPERATOR_REPAIR_FD_NAME)
            .count()
            <= 1
        && names
            .iter()
            .filter(|name| **name == EXISTING_OUTPUT_FD_NAME)
            .count()
            <= 1
        && names.iter().all(|name| {
            matches!(
                *name,
                EXPECTED_FD_NAME
                    | EXPORT_FD_NAME
                    | LIVE_EXPORT_FD_NAME
                    | ZFS_HOLD_FD_NAME
                    | OPERATOR_REPAIR_FD_NAME
                    | EXISTING_OUTPUT_FD_NAME
            )
        })
}

fn environment_u32(name: &'static str) -> Result<u32, StorageLaunchCaptureErrorV3> {
    std::env::var(name)
        .map_err(|_| activation_error(format!("{name} is absent")))?
        .parse()
        .map_err(|_| activation_error(format!("{name} is not a decimal u32")))
}

fn activation_error(message: impl Into<String>) -> StorageLaunchCaptureErrorV3 {
    StorageLaunchCaptureErrorV3::Activation(message.into())
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
pub struct StorageWorkerOriginV3 {
    custody: StartupCustody,
    open: bool,
}

impl StorageWorkerOriginV3 {
    /// Permanently closes later observation without releasing retained originals.
    pub fn close(&mut self) {
        self.open = false;
    }

    /// Pre-arms before any observation; Err, unwind, drop and forget stay closed.
    ///
    /// # Errors
    ///
    /// Rejects a closed owner or changed original process, unit or image.
    pub fn recheck(&mut self) -> Result<(), StorageWorkerOriginCauseV3> {
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
    fn begin(open: &'owner mut bool) -> Result<Self, StorageWorkerOriginCauseV3> {
        if !*open {
            return Err(StorageWorkerOriginCauseV3::Closed);
        }
        *open = false;
        Ok(Self { open })
    }

    fn finish(self) {
        *self.open = true;
    }
}

fn admit_captured(
    captured: CapturedStorageLaunchV3,
) -> Result<
    (
        StorageLaunchListenersV3,
        Option<OwnedFd>,
        Option<StorageWorkerOriginV3>,
    ),
    StorageWorkerOriginAdmissionErrorV3,
> {
    let Some(original) = captured.pid1_image.as_ref() else {
        return Ok((captured.listeners, None, None));
    };
    let mut custody = Box::new(StartupCustody::default());
    let result = custody.capture(original);
    if let Err(cause) = result {
        return Err(StorageWorkerOriginAdmissionErrorV3 {
            cause,
            captured: Some(captured),
            partial: Some(custody),
        });
    }
    Ok((
        captured.listeners,
        captured.pid1_image,
        Some(StorageWorkerOriginV3 {
            custody: *custody,
            open: true,
        }),
    ))
}

impl StartupCustody {
    fn capture(&mut self, original: &OwnedFd) -> Result<(), StorageWorkerOriginCauseV3> {
        self.original_pid1 = Some(File::from(original.try_clone()?));
        self.manager = Some(retain_original_backend_pid1_v1(
            self.original_pid1
                .as_ref()
                .ok_or(StorageWorkerOriginCauseV3::Binding)?,
        )?);

        self.process = Some(PidFd::open(
            NonZeroU32::new(std::process::id()).ok_or(StorageWorkerOriginCauseV3::Binding)?,
        )?);
        self.identity = Some(
            self.process
                .as_ref()
                .ok_or(StorageWorkerOriginCauseV3::Binding)?
                .process_identity()?,
        );
        self.cgroup = Some(
            open_storage_cgroup_root_v3()
                .map_err(|error| match error {
                    StorageCgroupRootErrorV3::Linux(error) => {
                        StorageWorkerOriginCauseV3::Linux(error)
                    }
                    StorageCgroupRootErrorV3::Kernel(error) => {
                        StorageWorkerOriginCauseV3::CgroupKernel(error)
                    }
                })?
                .resolve(Path::new(STORAGE_CGROUP))?,
        );
        self.observed = Some(observe_fixed_storage_worker_parent_v3()?);

        let observed = self
            .observed
            .as_ref()
            .ok_or(StorageWorkerOriginCauseV3::Binding)?;
        let mut arguments = std::env::args_os();
        for expected in observed.arguments() {
            if arguments
                .next()
                .is_none_or(|actual| std::ffi::OsStr::new(expected) != actual.as_os_str())
            {
                return Err(StorageWorkerOriginCauseV3::Binding);
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
            return Err(StorageWorkerOriginCauseV3::Binding);
        }
        self.original_executable = Some(File::open("/proc/self/exe")?);
        self.executable = Some(RetainedImmutableFileV1::retain_with_profile(
            observed.executable().to_path_buf(),
            self.original_executable
                .as_ref()
                .ok_or(StorageWorkerOriginCauseV3::Binding)?
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

    fn recheck(&self) -> Result<(), StorageWorkerOriginCauseV3> {
        let manager = self
            .manager
            .as_ref()
            .ok_or(StorageWorkerOriginCauseV3::Binding)?;
        let executable = self
            .executable
            .as_ref()
            .ok_or(StorageWorkerOriginCauseV3::Binding)?;
        let fragment = self
            .fragment
            .as_ref()
            .ok_or(StorageWorkerOriginCauseV3::Binding)?;
        let process = self
            .process
            .as_ref()
            .ok_or(StorageWorkerOriginCauseV3::Binding)?;
        let cgroup = self
            .cgroup
            .as_ref()
            .ok_or(StorageWorkerOriginCauseV3::Binding)?;
        let observed = self
            .observed
            .as_ref()
            .ok_or(StorageWorkerOriginCauseV3::Binding)?;

        manager.revalidate()?;
        manager.require_executed(1)?;
        executable.revalidate()?;
        executable.require_executed(std::process::id())?;
        fragment.revalidate()?;
        if Some(process.process_identity()?) != self.identity
            || Some(KernelBootId::current()?.into_bytes()) != self.boot
        {
            return Err(StorageWorkerOriginCauseV3::Binding);
        }
        cgroup.verify_exact_membership(process)?;
        if observe_fixed_storage_worker_parent_v3()? != *observed {
            return Err(StorageWorkerOriginCauseV3::Binding);
        }
        cgroup.verify_exact_membership(process)?;
        if Some(process.process_identity()?) != self.identity || !process.is_alive()? {
            return Err(StorageWorkerOriginCauseV3::Binding);
        }
        fragment.revalidate()?;
        manager.revalidate()?;
        manager.require_executed(1)?;
        executable.revalidate()?;
        Ok(())
    }
}

/// Opens only the fixed cgroup root with the original no-follow/path flags.
///
/// # Errors
///
/// Retains the syscall or cgroup-descriptor adoption error without redaction.
pub fn open_storage_cgroup_root_v3() -> Result<CgroupV2Root, StorageCgroupRootErrorV3> {
    let descriptor: OwnedFd = rustix::fs::open(
        "/sys/fs/cgroup",
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    Ok(CgroupV2Root::from_owned(descriptor)?)
}

#[cfg(test)]
mod activation_tests {
    use super::*;

    #[test]
    fn activation_accepts_only_exact_named_tables() {
        assert!(valid_listener_names(&[EXPECTED_FD_NAME, EXPORT_FD_NAME], 2));
        assert!(valid_listener_names(
            &[LIVE_EXPORT_FD_NAME, EXPECTED_FD_NAME, EXPORT_FD_NAME],
            3,
        ));
        assert!(valid_listener_names(
            &[ZFS_HOLD_FD_NAME, EXPECTED_FD_NAME, EXPORT_FD_NAME],
            3,
        ));
        assert!(!valid_listener_names(
            &[
                ZFS_HOLD_FD_NAME,
                ZFS_HOLD_FD_NAME,
                EXPECTED_FD_NAME,
                EXPORT_FD_NAME
            ],
            4,
        ));
        assert!(valid_listener_names(
            &[OPERATOR_REPAIR_FD_NAME, EXPECTED_FD_NAME, EXPORT_FD_NAME],
            3,
        ));
        assert!(valid_listener_names(
            &[
                OPERATOR_REPAIR_FD_NAME,
                LIVE_EXPORT_FD_NAME,
                EXPECTED_FD_NAME,
                EXPORT_FD_NAME,
            ],
            4,
        ));
        assert!(!valid_listener_names(
            &[EXPECTED_FD_NAME, LIVE_EXPORT_FD_NAME],
            2
        ));
        assert!(!valid_listener_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, EXPORT_FD_NAME],
            3,
        ));
        assert!(!valid_listener_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, "foreign"],
            3,
        ));
        assert!(valid_listener_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, EXISTING_OUTPUT_FD_NAME],
            3,
        ));
        assert!(!valid_listener_names(
            &[
                EXPECTED_FD_NAME,
                EXPORT_FD_NAME,
                EXISTING_OUTPUT_FD_NAME,
                EXISTING_OUTPUT_FD_NAME
            ],
            4,
        ));
    }

    #[test]
    fn activation_pid1_image_is_unique_and_separate_from_listener_roles() {
        assert!(valid_startup_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, PID1_LAUNCH_IMAGE_FD_NAME],
            3
        ));
        assert!(valid_startup_names(&[EXPECTED_FD_NAME, EXPORT_FD_NAME], 2));
        assert!(!valid_listener_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, PID1_LAUNCH_IMAGE_FD_NAME],
            3
        ));
        assert!(!valid_startup_names(
            &[
                EXPECTED_FD_NAME,
                EXPORT_FD_NAME,
                PID1_LAUNCH_IMAGE_FD_NAME,
                PID1_LAUNCH_IMAGE_FD_NAME
            ],
            4
        ));
        assert!(!valid_startup_names(
            &[EXPECTED_FD_NAME, PID1_LAUNCH_IMAGE_FD_NAME],
            2
        ));
        assert!(!valid_startup_names(
            &[EXPECTED_FD_NAME, EXPORT_FD_NAME, "wrong-image"],
            3
        ));
    }
}

#[cfg(test)]
mod observation_tests {
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
