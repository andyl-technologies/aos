//! Descriptor-bound storage arguments for guarded QEMU launches and setup probes.
//!
//! Physical names are checked against the retained generation directory before
//! replacement. The production VM receives distinct read/write file descriptions;
//! the stopped, plugin-free setup probe receives only a read-only description.

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use super::{
    QEMU_ROOT_OVERLAY_READ_LAUNCH_FD, QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD, QEMU_VMSTATE_LAUNCH_FD,
    QemuPreparedRunDirectory, QemuSpawnError, duplicate_cloexec_fd, invalid_input,
};

pub(super) struct GuardedLaunchImagePins {
    pub(super) vmstate: OwnedFd,
    pub(super) overlay: Option<GuardedOverlayImagePins>,
}

pub(super) struct GuardedOverlayImagePins {
    pub(super) read: OwnedFd,
    pub(super) write: OwnedFd,
}

impl GuardedLaunchImagePins {
    pub(super) fn new(run_directory: &QemuPreparedRunDirectory) -> Result<Self, QemuSpawnError> {
        // QEMU's OFD locks must not remain owned by the retained authority.
        let vmstate_file = run_directory.open_vmstate_for_launch()?;
        let vmstate = duplicate_cloexec_fd(
            vmstate_file.as_raw_fd(),
            "pin guarded VMState launch descriptor",
        )?;
        let overlay = match run_directory.open_direct_root_overlay_for_launch()? {
            Some((read, write)) => Some(GuardedOverlayImagePins {
                read: duplicate_cloexec_fd(
                    read.as_raw_fd(),
                    "pin read-only guarded root-overlay launch descriptor",
                )?,
                write: duplicate_cloexec_fd(
                    write.as_raw_fd(),
                    "pin read-write guarded root-overlay launch descriptor",
                )?,
            }),
            None => None,
        };
        Ok(Self { vmstate, overlay })
    }
}

pub(super) struct GuardedSetupProbeCommand<'a> {
    pub(super) args: &'a [String],
    pub(super) root_overlay: Option<&'a OwnedFd>,
}

pub(super) fn guarded_launch_args(
    args: &[String],
    has_overlay: bool,
    run_directory: &Path,
) -> Result<Vec<String>, QemuSpawnError> {
    let mut rewritten = vec![
        String::from("-add-fd"),
        format!("fd={QEMU_VMSTATE_LAUNCH_FD},set=1,opaque=crucible-vmstate"),
    ];
    if has_overlay {
        rewritten.extend([
            String::from("-add-fd"),
            format!(
                "fd={QEMU_ROOT_OVERLAY_READ_LAUNCH_FD},set=2,opaque=crucible-root-overlay-read"
            ),
            String::from("-add-fd"),
            format!(
                "fd={QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD},set=2,opaque=crucible-root-overlay-write"
            ),
        ]);
    }
    let (bound, vmstate_count, overlay_count) = bind_storage_arguments(args, run_directory, true)?;
    if vmstate_count != 1 || overlay_count != usize::from(has_overlay) {
        return Err(invalid_storage_arguments());
    }
    rewritten.extend(bound);
    Ok(rewritten)
}

pub(super) fn guarded_probe_args(
    args: &[String],
    has_overlay: bool,
    run_directory: &Path,
) -> Result<Vec<String>, QemuSpawnError> {
    let (bound, _, overlay_count) = bind_storage_arguments(args, run_directory, false)?;
    if overlay_count != usize::from(has_overlay) {
        return Err(invalid_storage_arguments());
    }
    let mut rewritten = Vec::with_capacity(bound.len() + 2);
    if has_overlay {
        rewritten.extend([
            String::from("-add-fd"),
            format!(
                "fd={QEMU_ROOT_OVERLAY_READ_LAUNCH_FD},set=2,opaque=crucible-root-overlay-read"
            ),
        ]);
    }
    rewritten.extend(bound);
    Ok(rewritten)
}

fn bind_storage_arguments(
    args: &[String],
    run_directory: &Path,
    bind_vmstate: bool,
) -> Result<(Vec<String>, usize, usize), QemuSpawnError> {
    let absolute_overlay = run_directory.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    let absolute_overlay = absolute_overlay
        .to_str()
        .ok_or_else(invalid_storage_arguments)?;
    let mut vmstate_count = 0;
    let mut overlay_count = 0;
    let mut bound = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let option = &args[index];
        bound.push(option.clone());
        index += 1;
        if option != "-blockdev" && option != "-drive" {
            continue;
        }
        let value = args.get(index).ok_or_else(invalid_storage_arguments)?;
        let fields: Vec<_> = value.split(',').collect();
        let vmstate = option == "-blockdev"
            && bind_vmstate
            && fields.contains(&format!("node-name={}", crate::DEFAULT_VMSTATE_NODE_NAME).as_str());
        let overlay =
            option == "-drive" && fields.contains(&format!("id={}", crate::ROOT_DRIVE_ID).as_str());
        if overlay
            && !fields.contains(&format!("node-name={}", crate::ROOT_OVERLAY_NODE_NAME).as_str())
        {
            return Err(invalid_storage_arguments());
        }
        let mut rebound = Vec::with_capacity(fields.len());
        for field in fields {
            if vmstate && field.starts_with("file.filename=") {
                if field != format!("file.filename={}", crate::DEFAULT_VMSTATE_FILE_NAME) {
                    return Err(invalid_storage_arguments());
                }
                vmstate_count += 1;
                rebound.push("file.filename=/dev/fdset/1");
            } else if overlay && field.starts_with("file=") {
                let path = field
                    .strip_prefix("file=")
                    .ok_or_else(invalid_storage_arguments)?;
                if path != crate::DEFAULT_ROOT_OVERLAY_FILE_NAME
                    && (path != absolute_overlay || !run_directory.is_absolute())
                {
                    return Err(invalid_storage_arguments());
                }
                overlay_count += 1;
                rebound.push("file=/dev/fdset/2");
            } else {
                rebound.push(field);
            }
        }
        bound.push(rebound.join(","));
        index += 1;
    }
    Ok((bound, vmstate_count, overlay_count))
}

fn invalid_storage_arguments() -> QemuSpawnError {
    invalid_input(
        "bind guarded QEMU block roots",
        "canonical VMState or root-overlay launch path is missing, duplicated, or outside its pinned generation",
    )
}
