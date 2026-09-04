//! Single-threaded namespace-helper process and its fixed launcher.

use std::collections::BTreeSet;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use aos_sandbox_linux::inventory::{MountId, MountNamespace, MountObservation};
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
    DETACHED_MOUNT_FD, DescriptorMapping, MOUNT_NAMESPACE_FD, OBSERVATION_FD, PLAN_FD,
    TARGET_ROOT_FD, TARGET_SLOT_FD, run_helper,
};
use crate::worker::{InstalledMountObservation, MountTargetObservation, NamespaceHelper};
use crate::{MountError, Result};

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

    fn invoke(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        action: HelperAction,
        detached: Option<&DetachedMount>,
        expected: ExpectedMounts,
    ) -> Result<MountTargetObservation> {
        let plan = compile_plan(
            request,
            request_digest,
            resources,
            action,
            expected.successor,
            expected.predecessor,
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
    let needs_detached = plan.roles.contains(DescriptorRoles::DETACHED_MOUNT);
    ensure_descriptor(DETACHED_MOUNT_FD, needs_detached)?;
    for fd in [
        MOUNT_NAMESPACE_FD,
        TARGET_ROOT_FD,
        TARGET_SLOT_FD,
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

    let single = SingleThreadedProcess::verify().map_err(helper_linux_error)?;
    mount_namespace.enter(&single).map_err(helper_linux_error)?;
    target_root
        .confine_helper_root(&single)
        .map_err(helper_linux_error)?;
    let current = resolve_target(&target_root, &plan.target_relative_path)?;

    let observation = match plan.action {
        HelperAction::Observe => classify_target(&current, &plan)?,
        HelperAction::Install => {
            verify_file(current.identity(), plan.target_slot, "pre-install target")?;
            if MountId::from_fd(current.as_fd())
                .map_err(helper_linux_error)?
                .get()
                != plan.target_slot_mount_id
            {
                return Err(MountError::Worker(
                    "install target is not the exact destination slot".to_owned(),
                ));
            }
            let mount = DetachedMount::from_inherited(adopt(DETACHED_MOUNT_FD)?)
                .map_err(helper_linux_error)?;
            mount.attach(&current).map_err(helper_linux_error)?;
            observe_published(&target_root, &plan)?
        }
        HelperAction::Replace => {
            let predecessor = MountId::from_fd(current.as_fd()).map_err(helper_linux_error)?;
            if predecessor.get() != plan.expected_predecessor_mount_id {
                return Err(MountError::Worker(
                    "replacement target is not the authorized predecessor".to_owned(),
                ));
            }
            let inventory = MountNamespace::current()
                .inventory(
                    65_536,
                    aos_sandbox_linux::inventory::MountListOrder::Forward,
                )
                .map_err(helper_linux_error)?;
            let expected_mount_point = inventory
                .mounts
                .iter()
                .find(|mount| mount.mount_id == predecessor)
                .map(|mount| mount.mount_point.as_os_str().as_bytes())
                .ok_or_else(|| {
                    MountError::Worker(
                        "complete inventory omitted the topmost predecessor".to_owned(),
                    )
                })?;
            match classify_replacement_stack(
                &inventory.mounts,
                MountId::new(plan.expected_mount_id).map_err(helper_linux_error)?,
                predecessor,
                MountId::new(plan.target_slot_mount_id).map_err(helper_linux_error)?,
                expected_mount_point,
            )? {
                ReplacementStackState::NeedsAttach => {
                    let mount = DetachedMount::from_inherited(adopt(DETACHED_MOUNT_FD)?)
                        .map_err(helper_linux_error)?;
                    mount.attach_beneath(&current).map_err(helper_linux_error)?;
                }
                ReplacementStackState::AlreadyAttached => {
                    ensure_descriptor(DETACHED_MOUNT_FD, true)?;
                }
            }
            detach_relative(&plan.target_relative_path, &single).map_err(helper_linux_error)?;
            observe_published(&target_root, &plan)?
        }
        HelperAction::Detach => {
            verify_file(current.identity(), plan.source, "pre-detach target")?;
            let current_mount_id = MountId::from_fd(current.as_fd()).map_err(helper_linux_error)?;
            if current_mount_id.get() != plan.expected_mount_id {
                return Err(MountError::Worker(
                    "refusing to detach a different exact mount generation".to_owned(),
                ));
            }
            detach_relative(&plan.target_relative_path, &single).map_err(helper_linux_error)?;
            let revealed = resolve_target(&target_root, &plan.target_relative_path)?;
            if revealed.identity() == current.identity() {
                return Err(MountError::Worker(
                    "detached mount remains topmost at target".to_owned(),
                ));
            }
            HelperReport::absent()
        }
    };
    write_report(adopt(OBSERVATION_FD)?, &observation)?;
    Ok(0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementStackState {
    NeedsAttach,
    AlreadyAttached,
}

/// Classifies replacement membership without using parent IDs or list order.
///
/// The caller has proven `predecessor` is topmost and serializes namespace
/// mutations. The exclusive slot invariant plus a complete inventory means
/// exactly one additional broker mount at the target must be immediately
/// beneath the predecessor. `mount_point` is copied from that predecessor's
/// own `statmount(2)` observation, avoiding any path-representation guess.
fn classify_replacement_stack(
    mounts: &[MountObservation],
    successor: MountId,
    predecessor: MountId,
    target_slot: MountId,
    mount_point: &[u8],
) -> Result<ReplacementStackState> {
    let explicit: BTreeSet<_> = mounts
        .iter()
        .filter(|mount| mount.mount_point.as_os_str().as_bytes() == mount_point)
        .map(|mount| mount.mount_id)
        .filter(|mount_id| *mount_id != target_slot)
        .collect();
    let successor_is_elsewhere = mounts.iter().any(|mount| {
        mount.mount_id == successor && mount.mount_point.as_os_str().as_bytes() != mount_point
    });
    if explicit == BTreeSet::from([predecessor]) && !successor_is_elsewhere {
        Ok(ReplacementStackState::NeedsAttach)
    } else if explicit == BTreeSet::from([predecessor, successor]) {
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
) -> Result<HelperPlan> {
    Ok(HelperPlan {
        action,
        roles: DescriptorRoles::for_action(action),
        source_generation: request.source_generation(),
        namespace_generation: request.namespace_generation(),
        attachment_id: *request.attachment_id(),
        destination_slot_id: *request.destination_slot_id(),
        request_digest,
        expected_mount_id: expected_mount_id.get(),
        expected_predecessor_mount_id: expected_predecessor_mount_id.map_or(0, MountId::get),
        target_slot_mount_id: MountId::from_fd(resources.target_slot.as_fd())
            .map_err(helper_linux_error)?
            .get(),
        source: resources.source.identity().into(),
        mount_namespace: resources.mount_namespace.identity().into(),
        target_root: resources.target_root.identity().into(),
        target_slot: resources.target_slot.identity().into(),
        target_relative_path: resources.target_relative_path.clone(),
    })
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

fn observe_published(root: &BeneathRoot, plan: &HelperPlan) -> Result<HelperReport> {
    let published = resolve_target(root, &plan.target_relative_path)?;
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
    Ok(HelperReport::installed(observation))
}

fn classify_target(target: &ResolvedPath, plan: &HelperPlan) -> Result<HelperReport> {
    let identity = target.identity();
    let current_mount_id = MountId::from_fd(target.as_fd()).map_err(helper_linux_error)?;
    if same_file(identity, plan.target_slot) && current_mount_id.get() == plan.target_slot_mount_id
    {
        Ok(HelperReport::absent())
    } else if current_mount_id.get() == plan.expected_mount_id {
        let mount_id = MountId::new(plan.expected_mount_id).map_err(helper_linux_error)?;
        let observation = MountNamespace::current()
            .observe(mount_id)
            .map_err(helper_linux_error)?;
        Ok(HelperReport::installed(observation))
    } else if plan.expected_predecessor_mount_id != 0
        && current_mount_id.get() == plan.expected_predecessor_mount_id
    {
        Ok(HelperReport::predecessor())
    } else {
        Ok(HelperReport::conflict())
    }
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

fn digest_idmaps(mount: &MountObservation) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.idmaps.v1\0");
    for map in [&mount.uid_map, &mount.gid_map] {
        match map {
            None => digest.update([0]),
            Some(extents) => {
                digest.update([1]);
                digest.update(
                    u64::try_from(extents.len())
                        .unwrap_or(u64::MAX)
                        .to_le_bytes(),
                );
                for extent in extents {
                    digest.update(
                        u64::try_from(extent.len())
                            .unwrap_or(u64::MAX)
                            .to_le_bytes(),
                    );
                    digest.update(extent.as_bytes());
                }
            }
        }
    }
    digest.finalize().into()
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

    #[test]
    fn replacement_stack_uses_complete_membership_not_parent_or_list_order() {
        let predecessor = MountId::new(40).unwrap();
        let successor = MountId::new(41).unwrap();
        let target_slot = MountId::new(39).unwrap();
        let mut mounts = vec![
            mount_at(70, 1, b"/elsewhere"),
            mount_at(40, 2, b"/target"),
            mount_at(39, 3, b"/target"),
        ];
        assert_eq!(
            classify_replacement_stack(&mounts, successor, predecessor, target_slot, b"/target")
                .unwrap(),
            ReplacementStackState::NeedsAttach
        );

        // Parent IDs and list order carry no stack semantics.
        mounts.insert(0, mount_at(41, 999, b"/target"));
        assert_eq!(
            classify_replacement_stack(&mounts, successor, predecessor, target_slot, b"/target")
                .unwrap(),
            ReplacementStackState::AlreadyAttached
        );
        mounts.push(mount_at(42, 40, b"/target"));
        assert!(
            classify_replacement_stack(&mounts, successor, predecessor, target_slot, b"/target")
                .is_err()
        );
        let successor_elsewhere = vec![
            mount_at(40, 2, b"/target"),
            mount_at(41, 999, b"/elsewhere"),
        ];
        assert!(
            classify_replacement_stack(
                &successor_elsewhere,
                successor,
                predecessor,
                target_slot,
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
