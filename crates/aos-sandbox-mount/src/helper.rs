//! Single-threaded namespace-helper process and its fixed launcher.

use std::os::fd::{FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use aos_sandbox_linux::mount::{DetachedMount, detach_relative};
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, SingleThreadedProcess};
use aos_sandbox_protocol::ValidatedMountRequest;

use crate::catalog::ResolvedMountResources;
use crate::plan::{
    DescriptorRoles, ExpectedFileIdentity, ExpectedNamespaceIdentity, HelperAction, HelperPlan,
    SealedHelperPlan,
};
use crate::spawn::{
    DETACHED_MOUNT_FD, DescriptorMapping, MOUNT_NAMESPACE_FD, PLAN_FD, TARGET_ROOT_FD,
    TARGET_SLOT_FD, run_helper, run_helper_status,
};
use crate::worker::NamespaceHelper;
use crate::{MountError, Result};

const ABSENT_STATUS: i32 = 3;
const ABSENT_EXIT_CODE: u8 = 3;
const CONFLICT_STATUS: u8 = 4;

/// Launches the fixed helper executable through a sealed exact-FD plan.
#[derive(Clone, Debug)]
pub struct PosixSpawnNamespaceHelper {
    executable: PathBuf,
}

impl PosixSpawnNamespaceHelper {
    /// Selects the immutable helper executable installed by the system module.
    ///
    /// # Errors
    ///
    /// Returns an error unless `executable` is a normalized absolute path in
    /// the Nix store. Existence is checked atomically by `posix_spawn` later.
    pub fn new(executable: impl Into<PathBuf>) -> Result<Self> {
        let executable = executable.into();
        let bytes = executable.as_os_str().as_encoded_bytes();
        if !executable.is_absolute()
            || !bytes.starts_with(b"/nix/store/")
            || bytes.len() > 4096
            || bytes.contains(&0)
            || executable
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(MountError::Worker(
                "mount helper must be a normalized Nix-store path".to_owned(),
            ));
        }
        Ok(Self { executable })
    }

    fn invoke(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        action: HelperAction,
        detached: Option<&DetachedMount>,
    ) -> Result<i32> {
        let plan = compile_plan(request, request_digest, resources, action);
        let sealed = SealedHelperPlan::create(&plan)?;
        let mut mappings = vec![
            DescriptorMapping {
                target: PLAN_FD,
                source: sealed.as_fd(),
            },
            DescriptorMapping {
                target: MOUNT_NAMESPACE_FD,
                source: resources.mount_namespace.as_fd(),
            },
            DescriptorMapping {
                target: TARGET_ROOT_FD,
                source: resources.target_root.as_fd(),
            },
            DescriptorMapping {
                target: TARGET_SLOT_FD,
                source: resources.target_slot.as_fd(),
            },
        ];
        if let Some(mount) = detached {
            mappings.push(DescriptorMapping {
                target: DETACHED_MOUNT_FD,
                source: mount.as_fd(),
            });
        }
        if action == HelperAction::Observe {
            run_helper_status(&self.executable, &mappings)
        } else {
            run_helper(&self.executable, &mappings).map(|()| 0)
        }
    }
}

impl NamespaceHelper for PosixSpawnNamespaceHelper {
    fn is_installed(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
    ) -> Result<bool> {
        match self.invoke(
            request,
            request_digest,
            resources,
            HelperAction::Observe,
            None,
        )? {
            0 => Ok(true),
            ABSENT_STATUS => Ok(false),
            status => Err(MountError::Worker(format!(
                "mount observation helper exited with status {status}"
            ))),
        }
    }

    fn install(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        mount: &DetachedMount,
        beneath: bool,
    ) -> Result<()> {
        let action = if beneath {
            HelperAction::Replace
        } else {
            HelperAction::Install
        };
        self.invoke(request, request_digest, resources, action, Some(mount))?;
        Ok(())
    }

    fn detach(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
    ) -> Result<()> {
        self.invoke(
            request,
            request_digest,
            resources,
            HelperAction::Detach,
            None,
        )?;
        Ok(())
    }
}

/// Adopts fixed inherited descriptors, applies one plan, and returns an exit code.
///
/// Status zero means success. Observe uses status three for an exact absent
/// pre-effect target and status four for conflicting target identity.
///
/// # Errors
///
/// Returns an error for arguments/environment, plan seals or decoding, an
/// inexact descriptor table, identity mismatch, multiple threads, namespace
/// entry, root confinement, mount mutation, or post-effect verification.
pub fn run_inherited() -> Result<u8> {
    if std::env::args_os().count() != 1 || std::env::vars_os().next().is_some() {
        return Err(MountError::Worker(
            "mount helper accepts no arguments or environment".to_owned(),
        ));
    }
    ensure_descriptor(PLAN_FD, true)?;
    // SAFETY: the fixed spawn contract proves descriptor 3 is open and
    // transfers unique child-side ownership to this helper.
    let plan_fd = unsafe { OwnedFd::from_raw_fd(PLAN_FD) };
    let plan = SealedHelperPlan::read_inherited(plan_fd)?;
    let needs_detached = plan.roles.contains(DescriptorRoles::DETACHED_MOUNT);
    ensure_descriptor(DETACHED_MOUNT_FD, needs_detached)?;
    for fd in [MOUNT_NAMESPACE_FD, TARGET_ROOT_FD, TARGET_SLOT_FD] {
        ensure_descriptor(fd, true)?;
    }

    let mount_namespace = NamespaceFd::from_owned(adopt(MOUNT_NAMESPACE_FD)?, NamespaceKind::Mount)
        .map_err(helper_linux_error)?;
    verify_namespace(
        mount_namespace.identity(),
        plan.mount_namespace,
        "mount namespace",
    )?;
    let target_root = ResolvedPath::from_inherited(adopt(TARGET_ROOT_FD)?)
        .and_then(BeneathRoot::from_resolved)
        .map_err(helper_linux_error)?;
    verify_file(target_root.identity(), plan.target_root, "target root")?;
    let target_slot =
        ResolvedPath::from_inherited(adopt(TARGET_SLOT_FD)?).map_err(helper_linux_error)?;
    verify_file(target_slot.identity(), plan.target_slot, "target slot")?;

    let single = SingleThreadedProcess::verify().map_err(helper_linux_error)?;
    mount_namespace.enter(&single).map_err(helper_linux_error)?;
    target_root
        .confine_helper_root(&single)
        .map_err(helper_linux_error)?;
    let current = resolve_target(&target_root, &plan.target_relative_path)?;

    match plan.action {
        HelperAction::Observe => Ok(classify_target(current.identity(), &plan)),
        HelperAction::Install => {
            verify_file(current.identity(), plan.target_slot, "pre-install target")?;
            let mount = DetachedMount::from_inherited(adopt(DETACHED_MOUNT_FD)?)
                .map_err(helper_linux_error)?;
            mount.attach(&current).map_err(helper_linux_error)?;
            verify_published(&target_root, &plan)?;
            Ok(0)
        }
        HelperAction::Replace => {
            verify_file(current.identity(), plan.target_slot, "pre-replace target")?;
            let mount = DetachedMount::from_inherited(adopt(DETACHED_MOUNT_FD)?)
                .map_err(helper_linux_error)?;
            mount.attach_beneath(&current).map_err(helper_linux_error)?;
            detach_relative(&plan.target_relative_path, &single).map_err(helper_linux_error)?;
            verify_published(&target_root, &plan)?;
            Ok(0)
        }
        HelperAction::Detach => {
            verify_file(current.identity(), plan.source, "pre-detach target")?;
            detach_relative(&plan.target_relative_path, &single).map_err(helper_linux_error)?;
            let revealed = resolve_target(&target_root, &plan.target_relative_path)?;
            if revealed.identity() == current.identity() {
                return Err(MountError::Worker(
                    "detached mount remains topmost at target".to_owned(),
                ));
            }
            Ok(0)
        }
    }
}

fn compile_plan(
    request: &ValidatedMountRequest,
    request_digest: [u8; 32],
    resources: &ResolvedMountResources,
    action: HelperAction,
) -> HelperPlan {
    HelperPlan {
        action,
        roles: DescriptorRoles::for_action(action),
        source_generation: request.source_generation(),
        namespace_generation: request.namespace_generation(),
        attachment_id: *request.attachment_id(),
        destination_slot_id: *request.destination_slot_id(),
        request_digest,
        source: resources.source.identity().into(),
        mount_namespace: resources.mount_namespace.identity().into(),
        target_root: resources.target_root.identity().into(),
        target_slot: resources.target_slot.identity().into(),
        target_relative_path: resources.target_relative_path.clone(),
    }
}

fn resolve_target(root: &BeneathRoot, relative: &Path) -> Result<ResolvedPath> {
    root.resolve(
        relative,
        ResolveOptions {
            no_mount_crossing: false,
            require_directory: true,
        },
    )
    .map_err(helper_linux_error)
}

fn verify_published(root: &BeneathRoot, plan: &HelperPlan) -> Result<()> {
    let published = resolve_target(root, &plan.target_relative_path)?;
    verify_file(published.identity(), plan.source, "published target")
}

fn classify_target(identity: FileIdentity, plan: &HelperPlan) -> u8 {
    if same_file(identity, plan.source) {
        0
    } else if same_file(identity, plan.target_slot) {
        ABSENT_EXIT_CODE
    } else {
        CONFLICT_STATUS
    }
}

fn verify_file(actual: FileIdentity, expected: ExpectedFileIdentity, label: &str) -> Result<()> {
    if !same_file(actual, expected) {
        return Err(MountError::Worker(format!(
            "helper {label} descriptor identity changed"
        )));
    }
    Ok(())
}

const fn same_file(actual: FileIdentity, expected: ExpectedFileIdentity) -> bool {
    actual.device == expected.device && actual.inode == expected.inode
}

fn verify_namespace(
    actual: aos_sandbox_linux::pidfd::NamespaceIdentity,
    expected: ExpectedNamespaceIdentity,
    label: &str,
) -> Result<()> {
    if actual.device != expected.device || actual.inode != expected.inode {
        return Err(MountError::Worker(format!(
            "helper {label} descriptor identity changed"
        )));
    }
    Ok(())
}

fn ensure_descriptor(fd: i32, expected: bool) -> Result<()> {
    // SAFETY: `fcntl(F_GETFD)` only inspects the numeric descriptor and does
    // not borrow or transfer ownership.
    let present = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
    if present != expected {
        return Err(MountError::Worker(
            "helper inherited descriptor table differs from sealed roles".to_owned(),
        ));
    }
    Ok(())
}

fn adopt(fd: i32) -> Result<OwnedFd> {
    ensure_descriptor(fd, true)?;
    // SAFETY: presence was checked immediately above and each fixed role is
    // adopted exactly once along one closed action path.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn helper_linux_error(error: aos_sandbox_linux::Error) -> MountError {
    let message = error.to_string();
    drop(error);
    MountError::Worker(message)
}
