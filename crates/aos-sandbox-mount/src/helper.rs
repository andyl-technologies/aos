//! Single-threaded namespace-helper process and its fixed launcher.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::{MountId, MountNamespace, MountObservation};
use aos_sandbox_linux::mount::{DetachedMount, detach_child};
use aos_sandbox_linux::path::{BeneathRoot, FileIdentity, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, SingleThreadedProcess};
use aos_sandbox_protocol::ValidatedMountRequest;

use crate::catalog::{
    ResolvedMountResources, ResolvedMountTopology, digest_idmaps, observe_mount_topology,
};
use crate::destination_slot::{payload_slot_component, payload_slot_relative_path};
use crate::plan::{
    DescriptorRoles, ExpectedFileIdentity, ExpectedNamespaceIdentity, HelperAction, HelperPlan,
    SealedHelperPlan,
};
use crate::spawn::{
    ATTACHMENT_ANCHOR_FD, DETACHED_MOUNT_FD, DescriptorMapping, MOUNT_NAMESPACE_FD, OBSERVATION_FD,
    PLAN_FD, TARGET_ROOT_FD, TARGET_SLOT_FD, run_helper,
};
use crate::worker::{
    EffectDeadlineV1, InstalledMountObservation, MountTargetObservation, NamespaceHelper,
};
use crate::{KERNEL_CLOCK_PROVENANCE, MountError, Result};

const REPORT_MAGIC: &[u8; 8] = b"AOSMOBS1";
const MAXIMUM_REPORT_BYTES: usize = 131_072;
const REPORT_ABSENT: u8 = 1;
const REPORT_INSTALLED: u8 = 2;
const REPORT_CONFLICT: u8 = 3;
const REPORT_PREDECESSOR: u8 = 4;

#[derive(Clone, Copy)]
struct ExpectedMounts {
    successor: MountId,
    predecessor: Option<MountId>,
}

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

    #[allow(clippy::too_many_arguments)]
    fn invoke(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        action: HelperAction,
        detached: Option<&DetachedMount>,
        expected: ExpectedMounts,
        deadline: Option<EffectDeadlineV1>,
    ) -> Result<MountTargetObservation> {
        let plan = compile_plan(
            request,
            request_digest,
            resources,
            action,
            expected.successor,
            expected.predecessor,
            deadline,
        )?;
        let sealed = SealedHelperPlan::create(&plan)?;
        let report = rustix::fs::memfd_create(
            "aos-sandbox-mount-observation",
            rustix::fs::MemfdFlags::CLOEXEC,
        )
        .map_err(|error| MountError::Worker(error.to_string()))?;
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
            DescriptorMapping {
                target: ATTACHMENT_ANCHOR_FD,
                source: resources.attachment_anchor.as_fd(),
            },
            DescriptorMapping {
                target: OBSERVATION_FD,
                source: report.as_fd(),
            },
        ];
        if let Some(mount) = detached {
            mappings.push(DescriptorMapping {
                target: DETACHED_MOUNT_FD,
                source: mount.as_fd(),
            });
        }
        run_helper(&self.executable, &mappings)?;
        decode_report(report, resources.mount_namespace.identity())
    }
}

impl NamespaceHelper for PosixSpawnNamespaceHelper {
    fn observe(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        expected_mount_id: MountId,
        expected_predecessor_mount_id: Option<MountId>,
    ) -> Result<MountTargetObservation> {
        self.invoke(
            request,
            request_digest,
            resources,
            HelperAction::Observe,
            None,
            ExpectedMounts {
                successor: expected_mount_id,
                predecessor: expected_predecessor_mount_id,
            },
            None,
        )
    }

    fn install(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        mount: &DetachedMount,
        beneath: bool,
        expected_predecessor_mount_id: Option<MountId>,
        deadline: EffectDeadlineV1,
    ) -> Result<InstalledMountObservation> {
        let action = if beneath {
            HelperAction::Replace
        } else {
            HelperAction::Install
        };
        match self.invoke(
            request,
            request_digest,
            resources,
            action,
            Some(mount),
            ExpectedMounts {
                successor: mount.mount_id(),
                predecessor: expected_predecessor_mount_id,
            },
            Some(deadline),
        )? {
            MountTargetObservation::Installed(observation) => Ok(*observation),
            _ => Err(MountError::Worker(
                "publication helper did not report the exact mount".to_owned(),
            )),
        }
    }

    fn detach(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        expected_mount_id: MountId,
        deadline: EffectDeadlineV1,
    ) -> Result<()> {
        self.invoke(
            request,
            request_digest,
            resources,
            HelperAction::Detach,
            None,
            ExpectedMounts {
                successor: expected_mount_id,
                predecessor: None,
            },
            Some(deadline),
        )?;
        Ok(())
    }
}

/// Adopts fixed inherited descriptors, applies one plan, and returns an exit code.
///
/// Status zero means success; the exact bounded observation is returned on the
/// dedicated report descriptor.
///
/// # Errors
///
/// Returns an error for arguments/environment, plan seals or decoding, an
/// inexact descriptor table, identity mismatch, multiple threads, namespace
/// entry, root confinement, mount mutation, or post-effect verification.
#[allow(clippy::too_many_lines)]
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
    validate_effect_clock_identity(&plan)?;
    let needs_detached = plan.roles.contains(DescriptorRoles::DETACHED_MOUNT);
    ensure_descriptor(DETACHED_MOUNT_FD, needs_detached)?;
    for fd in [
        MOUNT_NAMESPACE_FD,
        TARGET_ROOT_FD,
        TARGET_SLOT_FD,
        ATTACHMENT_ANCHOR_FD,
        OBSERVATION_FD,
    ] {
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
    let attachment_anchor = ResolvedPath::from_inherited(adopt(ATTACHMENT_ANCHOR_FD)?)
        .and_then(BeneathRoot::from_resolved)
        .map_err(helper_linux_error)?;
    verify_file(
        attachment_anchor.identity(),
        plan.attachment_anchor,
        "attachment anchor",
    )?;
    verify_descriptor_mount_ids(&target_root, &target_slot, &attachment_anchor, &plan)?;

    let single = SingleThreadedProcess::verify().map_err(helper_linux_error)?;
    mount_namespace.enter(&single).map_err(helper_linux_error)?;
    target_root
        .confine_helper_root(&single)
        .map_err(helper_linux_error)?;
    verify_namespace_topology(&target_root, &attachment_anchor, &target_slot, &plan)?;
    let slot_component = payload_slot_component(&plan.destination_slot_id);
    let slot_path = Path::new(&slot_component);
    let current = resolve_target(&attachment_anchor, slot_path)?;

    let observation = match plan.action {
        HelperAction::Observe => classify_target(&current, &plan)?,
        HelperAction::Install => {
            if !matches!(
                classify_target(&current, &plan)?,
                HelperReport {
                    kind: REPORT_ABSENT,
                    ..
                }
            ) {
                return Err(MountError::Worker(
                    "install target is not the exact destination slot".to_owned(),
                ));
            }
            let mount = adopt_expected_detached(&plan)?;
            validate_effect_deadline(&plan)?;
            mount.attach(&current).map_err(helper_linux_error)?;
            observe_published(&attachment_anchor, slot_path, &plan)?
        }
        HelperAction::Replace => {
            let predecessor = MountId::from_fd(current.as_fd()).map_err(helper_linux_error)?;
            if predecessor.get() != plan.expected_predecessor_mount_id
                || current.identity() == target_slot.identity()
            {
                return Err(MountError::Worker(
                    "replacement target is not the authorized predecessor".to_owned(),
                ));
            }
            let predecessor_observation = validate_slot_mount_location(
                MountNamespace::current()
                    .observe(predecessor)
                    .map_err(helper_linux_error)?,
                predecessor,
                &plan,
            )?;
            let inventory = MountNamespace::current()
                .inventory(
                    65_536,
                    aos_sandbox_linux::inventory::MountListOrder::Forward,
                )
                .map_err(helper_linux_error)?;
            match classify_replacement_stack(
                &inventory.mounts,
                MountId::new(plan.expected_mount_id).map_err(helper_linux_error)?,
                predecessor,
                MountId::new(plan.attachment_anchor_mount_id).map_err(helper_linux_error)?,
                plan.target_mount_namespace_id,
                predecessor_observation.mount_point.as_os_str().as_bytes(),
            )? {
                ReplacementStackState::NeedsAttach => {
                    let mount = adopt_expected_detached(&plan)?;
                    validate_effect_deadline(&plan)?;
                    mount.attach_beneath(&current).map_err(helper_linux_error)?;
                }
                ReplacementStackState::AlreadyAttached => {
                    drop(adopt_expected_detached(&plan)?);
                }
            }
            validate_effect_deadline(&plan)?;
            detach_child(&attachment_anchor, slot_path, &single).map_err(helper_linux_error)?;
            observe_published(&attachment_anchor, slot_path, &plan)?
        }
        HelperAction::Detach => {
            if !matches!(
                classify_target(&current, &plan)?,
                HelperReport {
                    kind: REPORT_INSTALLED,
                    ..
                }
            ) {
                return Err(MountError::Worker(
                    "refusing to detach a different exact mount generation".to_owned(),
                ));
            }
            validate_effect_deadline(&plan)?;
            detach_child(&attachment_anchor, slot_path, &single).map_err(helper_linux_error)?;
            let revealed = resolve_target(&attachment_anchor, slot_path)?;
            if !matches!(
                classify_target(&revealed, &plan)?,
                HelperReport {
                    kind: REPORT_ABSENT,
                    ..
                }
            ) {
                return Err(MountError::Worker(
                    "detached mount did not reveal the exact protected slot".to_owned(),
                ));
            }
            HelperReport::absent()
        }
    };
    verify_namespace_topology(&target_root, &attachment_anchor, &target_slot, &plan)?;
    write_report(adopt(OBSERVATION_FD)?, &observation)?;
    Ok(0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementStackState {
    NeedsAttach,
    AlreadyAttached,
}

/// Classifies replacement membership with exact parentage but without list order.
///
/// The caller has proven `predecessor` is topmost and serializes namespace
/// mutations. The exclusive slot invariant plus a complete inventory means
/// exactly one additional broker mount at the target must be immediately
/// beneath the predecessor. Before insertion the predecessor is a direct
/// child of the anchor. After `MOVE_MOUNT_BENEATH`, the successor is the
/// anchor child and the kernel reparents the predecessor over the successor.
fn classify_replacement_stack(
    mounts: &[MountObservation],
    successor: MountId,
    predecessor: MountId,
    attachment_anchor: MountId,
    target_mount_namespace_id: u64,
    mount_point: &[u8],
) -> Result<ReplacementStackState> {
    let explicit = mounts
        .iter()
        .filter(|mount| mount.mount_point.as_os_str().as_bytes() == mount_point)
        .collect::<Vec<_>>();
    if explicit
        .iter()
        .any(|mount| mount.mount_namespace_id != target_mount_namespace_id)
    {
        return Err(MountError::Worker(
            "replacement target mounts are outside the target namespace".to_owned(),
        ));
    }
    let predecessor_observation = explicit
        .iter()
        .find(|mount| mount.mount_id == predecessor)
        .copied();
    let successor_observation = explicit
        .iter()
        .find(|mount| mount.mount_id == successor)
        .copied();
    let expected_mount_is_elsewhere = mounts.iter().any(|mount| {
        (mount.mount_id == successor || mount.mount_id == predecessor)
            && mount.mount_point.as_os_str().as_bytes() != mount_point
    });
    if explicit.len() == 1
        && predecessor_observation.is_some_and(|mount| mount.parent_mount_id == attachment_anchor)
        && !expected_mount_is_elsewhere
    {
        Ok(ReplacementStackState::NeedsAttach)
    } else if explicit.len() == 2
        && successor_observation.is_some_and(|mount| mount.parent_mount_id == attachment_anchor)
        && predecessor_observation.is_some_and(|mount| mount.parent_mount_id == successor)
        && !expected_mount_is_elsewhere
    {
        Ok(ReplacementStackState::AlreadyAttached)
    } else {
        Err(MountError::Worker(
            "replacement target stack is not exclusively broker-owned".to_owned(),
        ))
    }
}

fn compile_plan(
    request: &ValidatedMountRequest,
    request_digest: [u8; 32],
    resources: &ResolvedMountResources,
    action: HelperAction,
    expected_mount_id: MountId,
    expected_predecessor_mount_id: Option<MountId>,
    deadline: Option<EffectDeadlineV1>,
) -> Result<HelperPlan> {
    let (clock_provenance, host_boot_id, effect_deadline_boottime_nanoseconds) = deadline
        .map(|value| {
            (
                value.clock_provenance,
                value.host_boot_id,
                value.boottime_nanoseconds,
            )
        })
        .unwrap_or(([0; 16], [0; 16], 0));
    Ok(HelperPlan {
        action,
        roles: DescriptorRoles::for_action(action),
        source_generation: request.source_generation(),
        namespace_generation: request.namespace_generation(),
        desired_attachment_generation: request.desired_attachment_generation(),
        resource_attachment_generation: request.resource_attachment_generation(),
        attachment_id: *request.attachment_id(),
        destination_slot_id: *request.destination_slot_id(),
        request_digest,
        expected_mount_id: expected_mount_id.get(),
        expected_predecessor_mount_id: expected_predecessor_mount_id.map_or(0, MountId::get),
        protected_anchor_mount_id: resources.topology.protected_anchor_mount_id,
        target_root_mount_id: resources.topology.target_root_mount_id,
        run_mount_id: resources.topology.run_mount_id,
        attachment_anchor_mount_id: resources.topology.attachment_anchor_mount_id,
        target_mount_namespace_id: resources.topology.target_mount_namespace_id,
        attachment_anchor_mount_attributes: resources.topology.attachment_anchor_mount_attributes,
        clock_provenance,
        host_boot_id,
        effect_deadline_boottime_nanoseconds,
        source: resources.source.identity().into(),
        mount_namespace: resources.mount_namespace.identity().into(),
        target_root: resources.target_root.identity().into(),
        target_slot: resources.target_slot.identity().into(),
        attachment_anchor: resources.attachment_anchor.identity().into(),
        attachment_anchor_idmap_digest: resources.topology.attachment_anchor_idmap_digest,
    })
}

fn validate_effect_clock_identity(plan: &HelperPlan) -> Result<()> {
    if plan.action == HelperAction::Observe {
        return Ok(());
    }
    let boot_id = KernelBootId::current()
        .map_err(|error| MountError::Worker(error.to_string()))?
        .into_bytes();
    if plan.clock_provenance != KERNEL_CLOCK_PROVENANCE || plan.host_boot_id != boot_id {
        return Err(MountError::Fence(
            "mount helper effect clock identity changed",
        ));
    }
    Ok(())
}

fn validate_effect_deadline(plan: &HelperPlan) -> Result<()> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| MountError::State("CLOCK_BOOTTIME returned negative seconds".to_owned()))?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| {
        MountError::State("CLOCK_BOOTTIME returned negative nanoseconds".to_owned())
    })?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| MountError::State("CLOCK_BOOTTIME overflowed u64".to_owned()))?;
    validate_effect_deadline_at(plan.effect_deadline_boottime_nanoseconds, now)
}

fn validate_effect_deadline_at(deadline: u64, now: u64) -> Result<()> {
    if now >= deadline {
        return Err(MountError::Fence("mount helper effect authority expired"));
    }
    Ok(())
}

fn verify_descriptor_mount_ids(
    target_root: &BeneathRoot,
    target_slot: &ResolvedPath,
    attachment_anchor: &BeneathRoot,
    plan: &HelperPlan,
) -> Result<()> {
    let actual = [
        MountId::from_fd(target_root.as_fd())
            .map_err(helper_linux_error)?
            .get(),
        MountId::from_fd(target_slot.as_fd())
            .map_err(helper_linux_error)?
            .get(),
        MountId::from_fd(attachment_anchor.as_fd())
            .map_err(helper_linux_error)?
            .get(),
    ];
    let expected = [
        plan.target_root_mount_id,
        plan.protected_anchor_mount_id,
        plan.attachment_anchor_mount_id,
    ];
    if actual != expected {
        return Err(MountError::Worker(
            "helper descriptor mount identities changed".to_owned(),
        ));
    }
    Ok(())
}

fn adopt_expected_detached(plan: &HelperPlan) -> Result<DetachedMount> {
    let mount =
        DetachedMount::from_inherited(adopt(DETACHED_MOUNT_FD)?).map_err(helper_linux_error)?;
    if mount.mount_id().get() != plan.expected_mount_id {
        return Err(MountError::Worker(
            "helper detached mount differs from the sealed successor".to_owned(),
        ));
    }
    Ok(mount)
}

fn verify_namespace_topology(
    target_root: &BeneathRoot,
    attachment_anchor: &BeneathRoot,
    target_slot: &ResolvedPath,
    plan: &HelperPlan,
) -> Result<()> {
    let protected_anchor_mount_id =
        MountId::from_fd(target_slot.as_fd()).map_err(helper_linux_error)?;
    let actual = observe_mount_topology(
        MountNamespace::current(),
        target_root,
        attachment_anchor,
        protected_anchor_mount_id,
    )?;
    if actual != topology_from_plan(plan) {
        return Err(MountError::Worker(
            "helper attachment-anchor topology changed after authorization".to_owned(),
        ));
    }
    Ok(())
}

const fn topology_from_plan(plan: &HelperPlan) -> ResolvedMountTopology {
    ResolvedMountTopology {
        protected_anchor_mount_id: plan.protected_anchor_mount_id,
        target_root_mount_id: plan.target_root_mount_id,
        run_mount_id: plan.run_mount_id,
        attachment_anchor_mount_id: plan.attachment_anchor_mount_id,
        target_mount_namespace_id: plan.target_mount_namespace_id,
        attachment_anchor_mount_attributes: plan.attachment_anchor_mount_attributes,
        attachment_anchor_idmap_digest: plan.attachment_anchor_idmap_digest,
    }
}

fn resolve_target(anchor: &BeneathRoot, slot_component: &Path) -> Result<ResolvedPath> {
    anchor
        .resolve(
            slot_component,
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(helper_linux_error)
}

fn observe_published(
    anchor: &BeneathRoot,
    slot_component: &Path,
    plan: &HelperPlan,
) -> Result<HelperReport> {
    let published = resolve_target(anchor, slot_component)?;
    verify_file(published.identity(), plan.source, "published target")?;
    let mount_id = MountId::from_fd(published.as_fd()).map_err(helper_linux_error)?;
    if mount_id.get() != plan.expected_mount_id {
        return Err(MountError::Worker(
            "published mount identity differs from detached mount".to_owned(),
        ));
    }
    let observation = MountNamespace::current()
        .observe(mount_id)
        .map_err(helper_linux_error)?;
    Ok(HelperReport::installed(validate_slot_mount(
        observation,
        mount_id,
        plan,
    )?))
}

fn classify_target(target: &ResolvedPath, plan: &HelperPlan) -> Result<HelperReport> {
    let identity = target.identity();
    let current_mount_id = MountId::from_fd(target.as_fd()).map_err(helper_linux_error)?;
    let state = classify_target_identity(identity, current_mount_id, plan)?;

    match state {
        TargetIdentityState::Absent => Ok(HelperReport::absent()),
        TargetIdentityState::Expected | TargetIdentityState::Predecessor => {
            let observation = MountNamespace::current()
                .observe(current_mount_id)
                .map_err(helper_linux_error)?;
            report_for_mounted_target(state, observation, current_mount_id, plan)
        }
        TargetIdentityState::Conflict => Ok(HelperReport::conflict()),
    }
}

fn report_for_mounted_target(
    state: TargetIdentityState,
    observation: MountObservation,
    current_mount_id: MountId,
    plan: &HelperPlan,
) -> Result<HelperReport> {
    match state {
        TargetIdentityState::Expected => Ok(HelperReport::installed(validate_slot_mount(
            observation,
            current_mount_id,
            plan,
        )?)),
        TargetIdentityState::Predecessor => {
            validate_slot_mount_location(observation, current_mount_id, plan)?;
            Ok(HelperReport::predecessor())
        }
        TargetIdentityState::Absent | TargetIdentityState::Conflict => Err(MountError::Worker(
            "unmounted target state cannot produce a mounted report".to_owned(),
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetIdentityState {
    Absent,
    Expected,
    Predecessor,
    Conflict,
}

fn classify_target_identity(
    identity: FileIdentity,
    current_mount_id: MountId,
    plan: &HelperPlan,
) -> Result<TargetIdentityState> {
    if same_file(identity, plan.target_slot) {
        if current_mount_id.get() == plan.attachment_anchor_mount_id {
            return Ok(TargetIdentityState::Absent);
        }
        return Err(MountError::Worker(
            "destination slot is covered by a same-inode mount alias".to_owned(),
        ));
    }
    if current_mount_id.get() == plan.expected_mount_id {
        verify_file(identity, plan.source, "installed target")?;
        return Ok(TargetIdentityState::Expected);
    }
    if plan.expected_predecessor_mount_id != 0
        && current_mount_id.get() == plan.expected_predecessor_mount_id
    {
        return Ok(TargetIdentityState::Predecessor);
    }
    Ok(TargetIdentityState::Conflict)
}

fn validate_slot_mount(
    observation: MountObservation,
    expected_mount_id: MountId,
    plan: &HelperPlan,
) -> Result<MountObservation> {
    let observation = validate_slot_mount_location(observation, expected_mount_id, plan)?;
    if observation.parent_mount_id.get() != plan.attachment_anchor_mount_id {
        return Err(MountError::Worker(
            "slot mount does not descend directly from the attachment anchor".to_owned(),
        ));
    }
    Ok(observation)
}

fn validate_slot_mount_location(
    observation: MountObservation,
    expected_mount_id: MountId,
    plan: &HelperPlan,
) -> Result<MountObservation> {
    let expected_mount_point = payload_slot_mount_point(&plan.destination_slot_id);
    if observation.mount_id != expected_mount_id
        || observation.mount_namespace_id != plan.target_mount_namespace_id
        || observation.mount_point.as_os_str().as_bytes() != expected_mount_point
    {
        return Err(MountError::Worker(
            "slot mount identity, mountpoint, or namespace is invalid".to_owned(),
        ));
    }
    Ok(observation)
}

fn payload_slot_mount_point(slot_id: &[u8; 16]) -> Vec<u8> {
    let path = payload_slot_relative_path(slot_id);
    let mut mount_point = Vec::with_capacity(path.as_os_str().as_bytes().len() + 1);
    mount_point.push(b'/');
    mount_point.extend_from_slice(path.as_os_str().as_bytes());
    mount_point
}

#[derive(Clone)]
struct HelperReport {
    kind: u8,
    mount: Option<MountObservation>,
}

impl HelperReport {
    const fn absent() -> Self {
        Self {
            kind: REPORT_ABSENT,
            mount: None,
        }
    }
    const fn conflict() -> Self {
        Self {
            kind: REPORT_CONFLICT,
            mount: None,
        }
    }
    const fn predecessor() -> Self {
        Self {
            kind: REPORT_PREDECESSOR,
            mount: None,
        }
    }
    const fn installed(mount: MountObservation) -> Self {
        Self {
            kind: REPORT_INSTALLED,
            mount: Some(mount),
        }
    }
}

fn write_report(fd: OwnedFd, report: &HelperReport) -> Result<()> {
    let mut file = std::fs::File::from(fd);
    let wire = WireReport::from_helper(report);
    let bytes = serde_json::to_vec(&wire)
        .map_err(|error| MountError::Worker(format!("encode helper observation: {error}")))?;
    if bytes.len() > MAXIMUM_REPORT_BYTES {
        return Err(MountError::Worker(
            "helper observation exceeds the report bound".to_owned(),
        ));
    }
    file.write_all(&bytes)
        .and_then(|()| file.sync_data())
        .map_err(|error| MountError::Worker(error.to_string()))
}

fn decode_report(
    fd: OwnedFd,
    namespace: aos_sandbox_linux::pidfd::NamespaceIdentity,
) -> Result<MountTargetObservation> {
    let mut file = std::fs::File::from(fd);
    file.seek(SeekFrom::Start(0))
        .map_err(|error| MountError::Worker(error.to_string()))?;
    let mut bytes = Vec::new();
    file.take(
        u64::try_from(MAXIMUM_REPORT_BYTES + 1).map_err(|_| {
            MountError::Worker("helper observation bound does not fit u64".to_owned())
        })?,
    )
    .read_to_end(&mut bytes)
    .map_err(|error| MountError::Worker(format!("read helper observation: {error}")))?;
    if bytes.len() > MAXIMUM_REPORT_BYTES {
        return Err(MountError::Worker(
            "helper observation exceeds the report bound".to_owned(),
        ));
    }
    let wire: WireReport = serde_json::from_slice(&bytes)
        .map_err(|error| MountError::Worker(format!("decode helper observation: {error}")))?;
    if wire.schema != String::from_utf8_lossy(REPORT_MAGIC) {
        return Err(malformed_report());
    }
    match (wire.kind, wire.mount) {
        (REPORT_ABSENT, None) => Ok(MountTargetObservation::Absent),
        (REPORT_CONFLICT, None) => Ok(MountTargetObservation::Conflict),
        (REPORT_PREDECESSOR, None) => Ok(MountTargetObservation::PredecessorInstalled),
        (REPORT_INSTALLED, Some(wire_mount)) => {
            let (mount, idmap_digest) = wire_mount.into_mount()?;
            Ok(MountTargetObservation::Installed(Box::new(
                InstalledMountObservation {
                    mount,
                    mount_namespace: namespace,
                    idmap_digest,
                },
            )))
        }
        _ => Err(MountError::Worker(
            "helper observation is malformed".to_owned(),
        )),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReport {
    schema: String,
    kind: u8,
    mount: Option<WireMountObservation>,
}

impl WireReport {
    fn from_helper(report: &HelperReport) -> Self {
        Self {
            schema: String::from_utf8_lossy(REPORT_MAGIC).into_owned(),
            kind: report.kind,
            mount: report.mount.as_ref().map(WireMountObservation::from_mount),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMountObservation {
    mount_id: u64,
    parent_mount_id: u64,
    mount_namespace_id: u64,
    device_major: u32,
    device_minor: u32,
    superblock_magic: u64,
    superblock_flags: u32,
    mount_attributes: u64,
    propagation: u64,
    supported_mask: Option<u64>,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    filesystem_type: Vec<u8>,
    superblock_source: Vec<u8>,
    idmap_digest: [u8; 32],
}

impl WireMountObservation {
    fn from_mount(mount: &MountObservation) -> Self {
        Self {
            mount_id: mount.mount_id.get(),
            parent_mount_id: mount.parent_mount_id.get(),
            mount_namespace_id: mount.mount_namespace_id,
            device_major: mount.device_major,
            device_minor: mount.device_minor,
            superblock_magic: mount.superblock_magic,
            superblock_flags: mount.superblock_flags,
            mount_attributes: mount.mount_attributes,
            propagation: mount.propagation,
            supported_mask: mount.supported_mask,
            root: mount.root.as_os_str().as_bytes().to_vec(),
            mount_point: mount.mount_point.as_os_str().as_bytes().to_vec(),
            filesystem_type: mount.filesystem_type.as_os_str().as_bytes().to_vec(),
            superblock_source: mount.superblock_source.as_os_str().as_bytes().to_vec(),
            idmap_digest: digest_idmaps(mount),
        }
    }

    fn into_mount(self) -> Result<(MountObservation, [u8; 32])> {
        let mount = MountObservation {
            mount_id: MountId::new(self.mount_id).map_err(helper_linux_error)?,
            parent_mount_id: MountId::new(self.parent_mount_id).map_err(helper_linux_error)?,
            mount_namespace_id: self.mount_namespace_id,
            device_major: self.device_major,
            device_minor: self.device_minor,
            superblock_magic: self.superblock_magic,
            superblock_flags: self.superblock_flags,
            mount_attributes: self.mount_attributes,
            propagation: self.propagation,
            supported_mask: self.supported_mask,
            root: std::ffi::OsString::from_vec(self.root),
            mount_point: std::ffi::OsString::from_vec(self.mount_point),
            filesystem_type: std::ffi::OsString::from_vec(self.filesystem_type),
            superblock_source: std::ffi::OsString::from_vec(self.superblock_source),
            uid_map: None,
            gid_map: None,
        };
        Ok((mount, self.idmap_digest))
    }
}

fn malformed_report() -> MountError {
    MountError::Worker("helper observation is malformed".to_owned())
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use aos_sandbox_linux::pidfd::NamespaceIdentity;

    #[test]
    fn helper_effect_deadline_is_exclusive() {
        assert!(validate_effect_deadline_at(101, 100).is_ok());
        assert!(validate_effect_deadline_at(100, 100).is_err());
        assert!(validate_effect_deadline_at(100, 101).is_err());
    }

    fn mount_at(mount_id: u64, parent_mount_id: u64, mount_point: &[u8]) -> MountObservation {
        MountObservation {
            mount_id: MountId::new(mount_id).unwrap(),
            parent_mount_id: MountId::new(parent_mount_id).unwrap(),
            mount_namespace_id: 39,
            device_major: 8,
            device_minor: 1,
            superblock_magic: 0xef53,
            superblock_flags: 7,
            mount_attributes: 11,
            propagation: 13,
            supported_mask: Some(17),
            root: std::ffi::OsString::from_vec(b"/root".to_vec()),
            mount_point: std::ffi::OsString::from_vec(mount_point.to_vec()),
            filesystem_type: std::ffi::OsString::from_vec(b"ext4".to_vec()),
            superblock_source: std::ffi::OsString::from_vec(b"/dev/vda".to_vec()),
            uid_map: None,
            gid_map: None,
        }
    }

    fn helper_plan() -> HelperPlan {
        HelperPlan {
            action: HelperAction::Replace,
            roles: DescriptorRoles::for_action(HelperAction::Replace),
            source_generation: 1,
            namespace_generation: 1,
            desired_attachment_generation: 2,
            resource_attachment_generation: 2,
            attachment_id: [1; 16],
            destination_slot_id: [2; 16],
            request_digest: [3; 32],
            expected_mount_id: 40,
            expected_predecessor_mount_id: 41,
            protected_anchor_mount_id: 38,
            target_root_mount_id: 30,
            run_mount_id: 30,
            attachment_anchor_mount_id: 39,
            target_mount_namespace_id: 39,
            attachment_anchor_mount_attributes: 0x0f,
            clock_provenance: [4; 16],
            host_boot_id: [5; 16],
            effect_deadline_boottime_nanoseconds: 1,
            source: ExpectedFileIdentity {
                device: 1,
                inode: 10,
            },
            mount_namespace: ExpectedNamespaceIdentity {
                device: 1,
                inode: 20,
            },
            target_root: ExpectedFileIdentity {
                device: 1,
                inode: 30,
            },
            target_slot: ExpectedFileIdentity {
                device: 1,
                inode: 11,
            },
            attachment_anchor: ExpectedFileIdentity {
                device: 1,
                inode: 12,
            },
            attachment_anchor_idmap_digest: [6; 32],
        }
    }

    #[test]
    fn target_identity_classification_keeps_protected_slot_and_anchor_distinct() {
        let plan = helper_plan();
        let directory = |inode| FileIdentity {
            device: 1,
            inode,
            file_type: aos_sandbox_linux::path::FileType::Directory,
        };
        assert_eq!(
            classify_target_identity(directory(11), MountId::new(39).unwrap(), &plan).unwrap(),
            TargetIdentityState::Absent
        );
        assert_eq!(
            classify_target_identity(directory(10), MountId::new(40).unwrap(), &plan).unwrap(),
            TargetIdentityState::Expected
        );
        assert_eq!(
            classify_target_identity(directory(13), MountId::new(41).unwrap(), &plan).unwrap(),
            TargetIdentityState::Predecessor
        );
        assert!(classify_target_identity(directory(11), MountId::new(40).unwrap(), &plan).is_err());
        assert_eq!(
            classify_target_identity(directory(10), MountId::new(42).unwrap(), &plan).unwrap(),
            TargetIdentityState::Conflict
        );
    }

    #[test]
    fn successor_and_predecessor_require_exact_slot_parent_path_and_namespace() {
        let plan = helper_plan();
        let mount_point = payload_slot_mount_point(&plan.destination_slot_id);
        for mount_id in [plan.expected_mount_id, plan.expected_predecessor_mount_id] {
            let expected_mount_id = MountId::new(mount_id).unwrap();
            assert!(
                validate_slot_mount(
                    mount_at(mount_id, plan.attachment_anchor_mount_id, &mount_point),
                    expected_mount_id,
                    &plan,
                )
                .is_ok()
            );
            assert!(
                validate_slot_mount(
                    mount_at(mount_id, plan.attachment_anchor_mount_id - 1, &mount_point),
                    expected_mount_id,
                    &plan,
                )
                .is_err()
            );
            let mut wrong_namespace =
                mount_at(mount_id, plan.attachment_anchor_mount_id, &mount_point);
            wrong_namespace.mount_namespace_id += 1;
            assert!(validate_slot_mount(wrong_namespace, expected_mount_id, &plan).is_err());
            assert!(
                validate_slot_mount(
                    mount_at(mount_id, plan.attachment_anchor_mount_id, b"/wrong"),
                    expected_mount_id,
                    &plan,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn replacement_precheck_admits_only_the_beneath_parent_exception() {
        let plan = helper_plan();
        let predecessor = MountId::new(plan.expected_predecessor_mount_id).unwrap();
        let mount_point = payload_slot_mount_point(&plan.destination_slot_id);
        let beneath = mount_at(predecessor.get(), plan.expected_mount_id, &mount_point);

        assert!(
            validate_slot_mount_location(beneath.clone(), predecessor, &plan).is_ok(),
            "the stack classifier must inspect the successor-parent relationship"
        );
        assert!(validate_slot_mount(beneath, predecessor, &plan).is_err());

        let mut wrong_namespace = mount_at(predecessor.get(), plan.expected_mount_id, &mount_point);
        wrong_namespace.mount_namespace_id += 1;
        assert!(validate_slot_mount_location(wrong_namespace, predecessor, &plan).is_err());
        assert!(
            validate_slot_mount_location(
                mount_at(predecessor.get(), plan.expected_mount_id, b"/wrong"),
                predecessor,
                &plan,
            )
            .is_err()
        );
    }

    #[test]
    fn predecessor_observation_accepts_partial_replacement_but_expected_requires_anchor() {
        let plan = helper_plan();
        let predecessor = MountId::new(plan.expected_predecessor_mount_id).unwrap();
        let mount_point = payload_slot_mount_point(&plan.destination_slot_id);
        let partial = mount_at(predecessor.get(), plan.expected_mount_id, &mount_point);

        let report = report_for_mounted_target(
            TargetIdentityState::Predecessor,
            partial.clone(),
            predecessor,
            &plan,
        )
        .unwrap();
        assert_eq!(report.kind, REPORT_PREDECESSOR);
        assert!(
            report_for_mounted_target(TargetIdentityState::Expected, partial, predecessor, &plan,)
                .is_err()
        );

        let installed = mount_at(
            plan.expected_mount_id,
            plan.attachment_anchor_mount_id,
            &mount_point,
        );
        assert!(
            report_for_mounted_target(
                TargetIdentityState::Expected,
                installed,
                MountId::new(plan.expected_mount_id).unwrap(),
                &plan,
            )
            .is_ok()
        );
    }

    #[test]
    fn replacement_stack_accepts_only_an_uninserted_predecessor_on_the_anchor() {
        let predecessor = MountId::new(40).unwrap();
        let successor = MountId::new(41).unwrap();
        let attachment_anchor = MountId::new(39).unwrap();
        let mounts = vec![mount_at(70, 1, b"/elsewhere"), mount_at(40, 39, b"/target")];
        assert_eq!(
            classify_replacement_stack(
                &mounts,
                successor,
                predecessor,
                attachment_anchor,
                39,
                b"/target"
            )
            .unwrap(),
            ReplacementStackState::NeedsAttach
        );

        let wrong_parent = vec![mount_at(40, 38, b"/target")];
        assert!(
            classify_replacement_stack(
                &wrong_parent,
                successor,
                predecessor,
                attachment_anchor,
                39,
                b"/target"
            )
            .is_err()
        );
        let successor_elsewhere = vec![
            mount_at(40, 39, b"/target"),
            mount_at(41, 39, b"/elsewhere"),
        ];
        assert!(
            classify_replacement_stack(
                &successor_elsewhere,
                successor,
                predecessor,
                attachment_anchor,
                39,
                b"/target"
            )
            .is_err()
        );
    }

    #[test]
    fn replacement_stack_accepts_only_the_kernel_beneath_parent_chain() {
        let predecessor = MountId::new(40).unwrap();
        let successor = MountId::new(41).unwrap();
        let attachment_anchor = MountId::new(39).unwrap();
        let mounts = vec![mount_at(40, 41, b"/target"), mount_at(41, 39, b"/target")];
        assert_eq!(
            classify_replacement_stack(
                &mounts,
                successor,
                predecessor,
                attachment_anchor,
                39,
                b"/target"
            )
            .unwrap(),
            ReplacementStackState::AlreadyAttached
        );

        let predecessor_still_on_anchor =
            vec![mount_at(40, 39, b"/target"), mount_at(41, 39, b"/target")];
        assert!(
            classify_replacement_stack(
                &predecessor_still_on_anchor,
                successor,
                predecessor,
                attachment_anchor,
                39,
                b"/target"
            )
            .is_err()
        );
        let reversed_chain = vec![mount_at(40, 39, b"/target"), mount_at(41, 40, b"/target")];
        assert!(
            classify_replacement_stack(
                &reversed_chain,
                successor,
                predecessor,
                attachment_anchor,
                39,
                b"/target"
            )
            .is_err()
        );
        let extra_mount = vec![
            mount_at(40, 41, b"/target"),
            mount_at(41, 39, b"/target"),
            mount_at(42, 41, b"/target"),
        ];
        assert!(
            classify_replacement_stack(
                &extra_mount,
                successor,
                predecessor,
                attachment_anchor,
                39,
                b"/target"
            )
            .is_err()
        );
        let mut wrong_namespace = mounts;
        wrong_namespace[0].mount_namespace_id += 1;
        assert!(
            classify_replacement_stack(
                &wrong_namespace,
                successor,
                predecessor,
                attachment_anchor,
                39,
                b"/target"
            )
            .is_err()
        );
    }

    #[test]
    fn rich_observation_report_round_trips_and_preserves_idmap_evidence() {
        let mount = MountObservation {
            mount_id: MountId::new(41).unwrap(),
            parent_mount_id: MountId::new(40).unwrap(),
            mount_namespace_id: 39,
            device_major: 8,
            device_minor: 1,
            superblock_magic: 0xef53,
            superblock_flags: 7,
            mount_attributes: 11,
            propagation: 13,
            supported_mask: Some(17),
            root: std::ffi::OsString::from_vec(b"/root".to_vec()),
            mount_point: std::ffi::OsString::from_vec(b"/target".to_vec()),
            filesystem_type: std::ffi::OsString::from_vec(b"ext4".to_vec()),
            superblock_source: std::ffi::OsString::from_vec(b"/dev/vda".to_vec()),
            uid_map: Some(vec!["0 1000 1".to_owned()]),
            gid_map: None,
        };
        let expected_digest = digest_idmaps(&mount);
        let fd =
            rustix::fs::memfd_create("observation-test", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
        let read_fd = rustix::io::dup(&fd).unwrap();
        write_report(fd, &HelperReport::installed(mount)).unwrap();
        let namespace = NamespaceIdentity {
            device: 19,
            inode: 23,
        };

        let MountTargetObservation::Installed(observed) =
            decode_report(read_fd, namespace).unwrap()
        else {
            panic!("expected installed observation");
        };
        assert_eq!(observed.mount.mount_id.get(), 41);
        assert_eq!(observed.mount.parent_mount_id.get(), 40);
        assert_eq!(observed.mount.mount_namespace_id, 39);
        assert_eq!(
            observed.mount.mount_point.as_os_str().as_bytes(),
            b"/target"
        );
        assert_eq!(observed.mount_namespace, namespace);
        assert_eq!(observed.idmap_digest, expected_digest);
    }

    #[test]
    fn observation_report_rejects_unknown_fields() {
        let fd =
            rustix::fs::memfd_create("observation-test", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
        let read_fd = rustix::io::dup(&fd).unwrap();
        let mut file = std::fs::File::from(fd);
        file.write_all(br#"{"schema":"AOSMOBS1","kind":1,"mount":null,"extra":true}"#)
            .unwrap();
        assert!(
            decode_report(
                read_fd,
                NamespaceIdentity {
                    device: 1,
                    inode: 2
                }
            )
            .is_err()
        );
    }
}
