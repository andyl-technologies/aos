//! Retains post-export launch compilation's actual native originals.
//!
//! Ordinary and selected callers enter one compiler. The ordinary disposition
//! keeps its local destruction boundaries; the selected disposition parks each
//! reached value in this already-paid owner before the next fallible frontier.

use std::os::fd::OwnedFd;

use std::os::fd::{AsFd as _, BorrowedFd};
use std::sync::Arc;
use std::time::Duration;
use rustix::fs::fstat;
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};
use aos_systemd_client::{SandboxDescriptorPath, SandboxResolvedPaths, SandboxUnitName, SandboxUnitSpec};
use super::{NspawnConfig, PayloadLaunchSnapshot, PinnedObjectSnapshot,
    PreparedLaunch, LaunchPins, validate_backend_features, validate_resolved_identity,
    validate_published_pin, validate_attachment_anchor_path,
    WORKSPACE_PIN_PREFIX, NETWORK_PIN_PREFIX, optional_limit,
    MEMORY, PROCESSES, CPU_WEIGHT, OPEN_FILES, CPU_QUOTA, IO_WEIGHT};
use crate::{HostError, Result};

use aos_sandbox_linux::mount::DetachedMount;
use aos_sandbox_linux::pidfd::NamespaceFd;

use super::{readiness, ResolvedLaunchResources, ResolvedWorkspace, ResolvedNetwork,
    ResolvedAttachmentAnchor};

pub(crate) struct HostLaunchCompilationOriginalV2 {
    pub(crate) resolved: Option<ResolvedLaunchResources>,
    pub(crate) root_mount: Option<DetachedMount>,
    pub(super) workspace: Option<ResolvedWorkspace>,
    pub(super) network: Option<ResolvedNetwork>,
    pub(super) anchor: Option<ResolvedAttachmentAnchor>,
    pub(super) revalidation: Option<readiness::NspawnRevalidationOriginalV2>,
    pub(super) revalidation_result: Option<crate::Result<()>>,
    pub(super) root_identity: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    pub(super) transferred_root: Option<std::io::Result<OwnedFd>>,
    pub(super) path_0: Option<std::io::Result<aos_systemd_client::SandboxDescriptorPath>>,
    pub(super) path_1: Option<std::io::Result<aos_systemd_client::SandboxDescriptorPath>>,
    pub(super) path_2: Option<std::io::Result<aos_systemd_client::SandboxDescriptorPath>>,
    pub(super) path_3: Option<std::io::Result<aos_systemd_client::SandboxDescriptorPath>>,
    pub(super) path_4: Option<std::io::Result<aos_systemd_client::SandboxDescriptorPath>>,
    pub(super) namespace_open: Option<std::result::Result<OwnedFd, rustix::io::Errno>>,
    pub(super) namespace: Option<NamespaceFd>,
    pub(super) namespace_failure: Option<aos_sandbox_linux::pidfd::NamespaceAdoptionFailureV2>,
    pub(super) spec: Option<aos_systemd_client::SandboxUnitSpec>,
    pub(super) nspawn_identity: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    pub(super) nspawn_mount: Option<aos_sandbox_linux::Result<aos_sandbox_linux::inventory::MountId>>,
    pub(super) workspace_mount: Option<aos_sandbox_linux::Result<aos_sandbox_linux::inventory::MountId>>,
    pub(super) entered: bool,
    pub(super) returned: Option<crate::Result<()>>,
}

/// Records completed local native disposal on one original Launch.
pub(crate) struct HostLaunchCompilationDisposedV2 {
    request: ([u8; 16], [u8; 32], [u8; 32]),
    before: aos_sandbox_model::ResourceVector,
    after: aos_sandbox_model::ResourceVector,
}

impl HostLaunchCompilationDisposedV2 {
    /// Returns the same Launch's current liability after physical disposal.
    pub(crate) fn current_demand_v2(&self) -> aos_sandbox_model::ResourceVector {
        self.after
    }

    /// Compares the original request and its complete pre-disposal liability.
    pub(crate) fn matches_v2(
        &self,
        request: ([u8; 16], [u8; 32], [u8; 32]),
        before: aos_sandbox_model::ResourceVector,
    ) -> bool {
        self.request == request && self.before == before
    }
}

impl HostLaunchCompilationOriginalV2 {
    /// Consumes completed local collectors while the parent retains the payload.
    ///
    /// # Errors
    /// Refuses incomplete handoff, any retained failure, or invalid arithmetic.
    /// Every refusal preserves both actual collector owners.
    pub(crate) fn dispose_completed_v2(
        catalog: &mut Option<super::HostLaunchCatalogOriginalV2>,
        compilation: &mut Option<Self>,
        _prepared: &super::PreparedLaunch,
        request: ([u8; 16], [u8; 32], [u8; 32]),
        before: aos_sandbox_model::ResourceVector,
    ) -> Result<HostLaunchCompilationDisposedV2> {
        use aos_sandbox_model::ResourceDimension as D;

        let original = compilation.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
        if !original.entered || !matches!(original.returned, Some(Ok(())))
            || original.failure().is_some()
            || original.resolved.is_some() || original.workspace.is_some()
            || original.network.is_some() || original.anchor.is_some()
            || original.transferred_root.is_some() || original.spec.is_some()
        {
            return Err(HostError::Fence("Launch compiler has no completed owning handoff"));
        }
        // Five descriptor-path pins and the transferred-root duplicate belong
        // to the returned payload. Only namespace and revalidation temporaries
        // from the compiler's eight-FD supplier can retire here.
        let compiler_files = Self::receiving_demand_v2()
            .ok_or(HostError::ResourceExhausted)?.get(D::OpenFiles)
            .checked_sub(6).ok_or(HostError::ResourceExhausted)?;
        let disposed = catalog.as_ref().ok_or(HostError::AgentLaunchQuarantined)?
            .completed_temporary_files_v2()?.checked_add(compiler_files)
            .ok_or(HostError::ResourceExhausted)?;
        let current_files = before.get(D::OpenFiles).checked_sub(disposed)
            .ok_or(HostError::ResourceExhausted)?;
        let after = before.with(D::OpenFiles, current_files);

        // No fallible step follows until both whole successful native owners
        // are physically dropped. Failed owners never enter this branch.
        drop((catalog.take(), compilation.take()));
        Ok(HostLaunchCompilationDisposedV2 { request, before, after })
    }

    pub(crate) fn new() -> Self {
        Self {
            resolved: None,
            root_mount: None,
            workspace: None,
            network: None,
            anchor: None,
            revalidation: None,
            revalidation_result: None,
            root_identity: None,
            transferred_root: None,
            path_0: None,
            path_1: None,
            path_2: None,
            path_3: None,
            path_4: None,
            namespace_open: None,
            namespace: None,
            namespace_failure: None,
            spec: None,
            nspawn_identity: None,
            nspawn_mount: None,
            workspace_mount: None,
            entered: false, returned: None,
        }
    }

    pub(crate) fn receiving_demand_v2() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(readiness::NspawnRevalidationOriginalV2::requested_bytes_v2()?)?
            .checked_add(aos_systemd_client::SandboxUnitSpec::construction_receiving_bytes_v2()?)?
            .checked_add(aos_systemd_client::SandboxDescriptorPath::construction_receiving_bytes_v2()?.checked_mul(5)?)?;
        // Five owned descriptor paths, one exported-root duplicate, one mount
        // namespace original and one retained boot-ID reader. Input catalog
        // descriptors/export mount were separately paid before their return.
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, 8))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<std::result::Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        self.revalidation.as_ref().and_then(readiness::NspawnRevalidationOriginalV2::failure)
            .or_else(|| error(&self.revalidation_result))
            .or_else(|| error(&self.root_identity)).or_else(|| error(&self.transferred_root))
            .or_else(|| error(&self.path_0)).or_else(|| error(&self.path_1)).or_else(|| error(&self.path_2))
            .or_else(|| error(&self.path_3)).or_else(|| error(&self.namespace_open))
            .or_else(|| self.namespace_failure.as_ref().map(|failure| failure.cause() as _))
            .or_else(|| error(&self.path_4)).or_else(|| error(&self.nspawn_identity))
            .or_else(|| error(&self.nspawn_mount)).or_else(|| error(&self.workspace_mount))
            .or_else(|| error(&self.returned))
    }
}

// A successful native result moves only at a checked positive frontier. The
// same exclusive local/retained borrow prevents any intervening replacement.
pub(super) fn take_positive<T, E>(
    value: aos_sandbox_model::retained::CaptureValueV1<'_, Option<std::result::Result<T, E>>>,
) -> T {
    match value.take() {
        Some(Ok(value)) => value,
        _ => std::process::abort(),
    }
}

pub(super) enum LaunchRecipeV1<'a> {
    Ready(&'a NspawnConfig),
    Canary(&'a super::deployment::canary::CanaryNspawnConfigV1),
    Component(&'a super::deployment::HostComponentBackendPreparationV2),
}

impl LaunchRecipeV1<'_> {
    fn revalidate(&self) -> Result<()> {
        match self {
            Self::Ready(config) => config.revalidate(),
            Self::Canary(config) => config.revalidate_executable(),
            Self::Component(config) => config.revalidate_compilation_v2(None),
        }
    }

    fn executable_pin(&self) -> Result<BorrowedFd<'_>> {
        match self {
            Self::Ready(config) => Ok(config.readiness.executable_pin()),
            Self::Canary(config) => Ok(config.executable_pin()),
            Self::Component(config) => config.executable_pin(),
        }
    }

    fn executable_pin_arc(&self) -> Result<&Arc<OwnedFd>> {
        match self {
            Self::Ready(config) => Ok(config.readiness.executable_pin_arc()),
            Self::Canary(config) => Ok(config.executable_pin_arc()),
            Self::Component(config) => config.executable_pin_arc(),
        }
    }

    fn timeouts(&self) -> (Duration, Duration) {
        match self {
            Self::Ready(config) => (config.timeout_start, config.timeout_stop),
            Self::Canary(config) => config.timeouts(),
            Self::Component(_) => (Duration::from_secs(30), Duration::from_secs(30)),
        }
    }
}


pub(super) fn compile_resolved_recipe(
    recipe: LaunchRecipeV1<'_>,
    fence: &ValidatedAssignmentFence,
    plan: &ValidatedRuntimePlan,
    resolved: ResolvedLaunchResources,
    root_mount: DetachedMount,
    original: Option<&mut HostLaunchCompilationOriginalV2>,
) -> Result<PreparedLaunch> {
    use aos_sandbox_model::retained::CaptureValueV1;
    let retained = original.is_some();
    let (
        resolved_destination,
        root_mount_destination,
        workspace_destination,
        network_destination,
        anchor_destination,
        revalidation_destination,
        revalidation_result_destination,
        root_identity_destination,
        transferred_root_destination,
        path_0_destination,
        path_1_destination,
        path_2_destination,
        path_3_destination,
        path_4_destination,
        namespace_open_destination,
        namespace_destination,
        namespace_failure_destination,
        spec_destination,
        nspawn_identity_destination,
        nspawn_mount_destination,
        workspace_mount_destination,
    ) = match original {
        Some(original) => (
            Some(&mut original.resolved),
            Some(&mut original.root_mount),
            Some(&mut original.workspace),
            Some(&mut original.network),
            Some(&mut original.anchor),
            Some(&mut original.revalidation),
            Some(&mut original.revalidation_result),
            Some(&mut original.root_identity),
            Some(&mut original.transferred_root),
            Some(&mut original.path_0),
            Some(&mut original.path_1),
            Some(&mut original.path_2),
            Some(&mut original.path_3),
            Some(&mut original.path_4),
            Some(&mut original.namespace_open),
            Some(&mut original.namespace),
            Some(&mut original.namespace_failure),
            Some(&mut original.spec),
            Some(&mut original.nspawn_identity),
            Some(&mut original.nspawn_mount),
            Some(&mut original.workspace_mount),
        ),
        None => (
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
    };
    let resolved = CaptureValueV1::new(Some(resolved), resolved_destination);
    let root_mount = CaptureValueV1::new(Some(root_mount), root_mount_destination);
    let root_mount = root_mount.as_ref().ok_or(HostError::Fence("launch export is absent"))?;
    let revalidation = match (&recipe, revalidation_destination) {
        (LaunchRecipeV1::Ready(config), Some(destination)) => config.readiness
            .revalidate_for_nspawn_engine_v2(destination.as_mut()),
        (LaunchRecipeV1::Component(config), Some(destination)) =>
            config.revalidate_compilation_v2(destination.as_mut()),
        (recipe, _) => recipe.revalidate(),
    };
    let revalidation = CaptureValueV1::new(Some(revalidation), revalidation_result_destination);
    if revalidation.as_ref().is_some_and(Result::is_err) {
        if retained {
            return Err(HostError::Fence("nspawn retained executable revalidation failed"));
        }
        return match revalidation.take() {
            Some(Err(error)) => Err(error),
            _ => std::process::abort(),
        };
    }
    validate_backend_features(plan)?;
    let ResolvedLaunchResources { workspace, network, identity, attachment_anchor } =
        resolved.take().ok_or(HostError::Fence("resolved launch inputs are absent"))?;
    let workspace_original = CaptureValueV1::new(Some(workspace), workspace_destination);
    let workspace = workspace_original.as_ref().ok_or(HostError::Fence("launch workspace is absent"))?;
    let guest_package_binding = workspace
        .guest_root_publication()
        .map(|proof| proof.package_binding);
    let guest_feature_mask = workspace
        .guest_root_publication()
        .map(|proof| proof.feature_mask);
    let network_original = CaptureValueV1::new(Some(network), network_destination);
    let network = network_original.as_ref().ok_or(HostError::Fence("launch network is absent"))?;
    let anchor_original = CaptureValueV1::new(Some(attachment_anchor), anchor_destination);
    let attachment_anchor = anchor_original.as_ref().ok_or(HostError::Fence("launch anchor is absent"))?;
    let root_identity_original = CaptureValueV1::new(Some(fstat(root_mount.as_fd())), root_identity_destination);
    let root_identity = match root_identity_original.as_ref() {
        Some(Ok(identity)) => identity,
        Some(Err(error)) => return Err(HostError::InvalidPlan(error.to_string())),
        None => return Err(HostError::Fence("exported-root metadata is absent")),
    };
    if (root_identity.st_dev, root_identity.st_ino) != (workspace.device, workspace.inode) {
        return Err(HostError::InvalidPlan(
            "exported root mount differs from the resolved workspace".to_owned(),
        ));
    }
    // Build the systemd descriptor path from the owned FD retained in
    // LaunchPins, not the temporary export wrapper dropped on return.
    let transferred_root_original = CaptureValueV1::new(
        Some(root_mount.as_fd().try_clone_to_owned()), transferred_root_destination);
    let transferred_root = match transferred_root_original.as_ref() {
        Some(Ok(descriptor)) => descriptor,
        Some(Err(error)) => return Err(HostError::InvalidPlan(error.to_string())),
        None => return Err(HostError::Fence("exported-root duplicate is absent")),
    };
    validate_resolved_identity(&identity, plan)?;
    validate_published_pin(
        &workspace.root_directory,
        WORKSPACE_PIN_PREFIX,
        "workspace root",
    )?;
    validate_published_pin(
        &network.namespace_path,
        NETWORK_PIN_PREFIX,
        "network namespace",
    )?;

    let resources = aos_systemd_client::SandboxResourceRecipeV1 {
        memory_max_bytes: optional_limit(plan, MEMORY),
        tasks_max: optional_limit(plan, PROCESSES),
        cpu_weight: optional_limit(plan, CPU_WEIGHT),
        open_files: optional_limit(plan, OPEN_FILES),
        cpu_quota_micros_per_second: optional_limit(plan, CPU_QUOTA),
        io_weight: optional_limit(plan, IO_WEIGHT),
    }.compile_v1().map_err(|error| HostError::InvalidPlan(error.to_string()))?;

    let executable_path_original = CaptureValueV1::new(
        Some(SandboxDescriptorPath::for_current_process(recipe.executable_pin()?)), path_0_destination);
    if let Some(Err(error)) = executable_path_original.as_ref() {
        return Err(HostError::InvalidPlan(error.to_string()));
    }
    let executable_path = if retained {
        executable_path_original.as_ref().and_then(|result| result.as_ref().ok()).cloned()
            .ok_or(HostError::Fence("launch descriptor path is absent"))?
    } else { take_positive(executable_path_original) };
    let root_path_original = CaptureValueV1::new(
        Some(SandboxDescriptorPath::for_current_process(transferred_root.as_fd())), path_1_destination);
    if let Some(Err(error)) = root_path_original.as_ref() {
        return Err(HostError::InvalidPlan(error.to_string()));
    }
    let root_path = if retained {
        root_path_original.as_ref().and_then(|result| result.as_ref().ok()).cloned()
            .ok_or(HostError::Fence("launch descriptor path is absent"))?
    } else { take_positive(root_path_original) };
    let network_path_original = CaptureValueV1::new(
        Some(SandboxDescriptorPath::for_current_process(network.pin.as_fd())), path_2_destination);
    if let Some(Err(error)) = network_path_original.as_ref() {
        return Err(HostError::InvalidPlan(error.to_string()));
    }
    let network_path = if retained {
        network_path_original.as_ref().and_then(|result| result.as_ref().ok()).cloned()
            .ok_or(HostError::Fence("launch descriptor path is absent"))?
    } else { take_positive(network_path_original) };
    let command = aos_systemd_client::SandboxNspawnCommand::private_user_descriptor_v1(
        executable_path,
        *fence.incarnation_id(),
        identity.range_start,
        identity.range_size,
    )
    .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
    validate_attachment_anchor_path(&attachment_anchor.directory)?;
    let attachment_anchor_path_original = CaptureValueV1::new(
        Some(SandboxDescriptorPath::for_current_process(attachment_anchor.pin.as_fd())), path_3_destination);
    if let Some(Err(error)) = attachment_anchor_path_original.as_ref() {
        return Err(HostError::InvalidPlan(error.to_string()));
    }
    let attachment_anchor_path = if retained {
        attachment_anchor_path_original.as_ref().and_then(|result| result.as_ref().ok()).cloned()
            .ok_or(HostError::Fence("launch descriptor path is absent"))?
    } else { take_positive(attachment_anchor_path_original) };

    // The anchor is attached in this mount namespace. Pass that exact
    // namespace alongside it so nspawn can clone the validated mount in a
    // short-lived child without granting mount authority to Host itself.
    let namespace_open_original = CaptureValueV1::new(Some(rustix::fs::open(
        "/proc/self/ns/mnt",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )), namespace_open_destination);
    if let Some(Err(error)) = namespace_open_original.as_ref() {
        return Err(HostError::InvalidPlan(error.to_string()));
    }
    let namespace_descriptor = take_positive(namespace_open_original);
    let attachment_anchor_namespace = if let Some(destination) = namespace_failure_destination {
        match NamespaceFd::from_owned_retaining_v2(namespace_descriptor,
            aos_sandbox_linux::pidfd::NamespaceKind::Mount)
        {
            Ok(namespace) => namespace,
            Err(failure) => {
                *destination = Some(failure);
                return Err(HostError::Fence("launch Mount namespace adoption failed; original retained"));
            }
        }
    } else {
        NamespaceFd::from_owned(namespace_descriptor, aos_sandbox_linux::pidfd::NamespaceKind::Mount)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?
    };
    let namespace_original = CaptureValueV1::new(Some(attachment_anchor_namespace), namespace_destination);
    let attachment_anchor_namespace = namespace_original.as_ref()
        .ok_or(HostError::Fence("launch Mount namespace is absent"))?;
    let attachment_anchor_namespace_path_original = CaptureValueV1::new(
        Some(SandboxDescriptorPath::for_current_process(attachment_anchor_namespace.as_fd())), path_4_destination);
    if let Some(Err(error)) = attachment_anchor_namespace_path_original.as_ref() {
        return Err(HostError::InvalidPlan(error.to_string()));
    }
    let attachment_anchor_namespace_path = if retained {
        attachment_anchor_namespace_path_original.as_ref().and_then(|result| result.as_ref().ok()).cloned()
            .ok_or(HostError::Fence("launch descriptor path is absent"))?
    } else { take_positive(attachment_anchor_namespace_path_original) };
    let paths = SandboxResolvedPaths::from_descriptors(root_path, network_path)
        .with_attachment_anchor(attachment_anchor_path, attachment_anchor_namespace_path);
    let spec = SandboxUnitSpec::new_nspawn(
        SandboxUnitName::from_incarnation(*fence.incarnation_id()),
        command,
        paths,
        resources,
        recipe.timeouts().0,
        recipe.timeouts().1,
    )
    .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
    let spec_original = CaptureValueV1::new(Some(spec), spec_destination);
    let spec = spec_original.as_ref().ok_or(HostError::Fence("launch unit spec is absent"))?;
    let nspawn_identity_original = CaptureValueV1::new(Some(fstat(recipe.executable_pin()?)), nspawn_identity_destination);
    let nspawn_identity = match nspawn_identity_original.as_ref() {
        Some(Ok(identity)) => identity,
        Some(Err(error)) => return Err(HostError::InvalidPlan(error.to_string())),
        None => return Err(HostError::Fence("nspawn metadata is absent")),
    };
    let nspawn_mount_id_original = CaptureValueV1::new(
        Some(aos_sandbox_linux::inventory::MountId::from_fd(recipe.executable_pin()?)), nspawn_mount_destination);
    let nspawn_mount_id = match nspawn_mount_id_original.as_ref() {
        Some(Ok(identity)) => identity.get(),
        Some(Err(error)) => return Err(HostError::InvalidPlan(error.to_string())),
        None => return Err(HostError::Fence("launch mount identity is absent")),
    };
    // A detached clone receives a new mount ID on each export. Durable
    // replay must bind the stable catalog source, while the exact exported
    // descriptor stays live in the transient launch specification.
    let workspace_mount_id_original = CaptureValueV1::new(
        Some(aos_sandbox_linux::inventory::MountId::from_fd(workspace.pin.as_fd())), workspace_mount_destination);
    let workspace_mount_id = match workspace_mount_id_original.as_ref() {
        Some(Ok(identity)) => identity.get(),
        Some(Err(error)) => return Err(HostError::InvalidPlan(error.to_string())),
        None => return Err(HostError::Fence("launch mount identity is absent")),
    };
    let snapshot = PayloadLaunchSnapshot {
        nspawn: PinnedObjectSnapshot {
            device: nspawn_identity.st_dev,
            inode: nspawn_identity.st_ino,
            mount_id: nspawn_mount_id,
        },
        workspace: PinnedObjectSnapshot {
            device: workspace.device,
            inode: workspace.inode,
            mount_id: workspace_mount_id,
        },
        network_device: network.device,
        network_inode: network.inode,
        identity_range_start: identity.range_start,
        identity_range_size: identity.range_size,
        identity_catalog_generation: identity.catalog_generation,
        attachment_anchor: PinnedObjectSnapshot {
            device: attachment_anchor.device,
            inode: attachment_anchor.inode,
            mount_id: attachment_anchor.mount_id,
        },
        spec_semantic_digest: spec.semantic_digest_v1(),
        agent_required: false,
    };
    // Every native check is positive under these same exclusive borrows.
    // Move the actual pins/spec, with no syscall or later fallible work.
    let workspace = workspace_original.take().ok_or(HostError::Fence("launch workspace disappeared"))?;
    let network = network_original.take().ok_or(HostError::Fence("launch network disappeared"))?;
    let attachment_anchor = anchor_original.take().ok_or(HostError::Fence("launch anchor disappeared"))?;
    let transferred_root = take_positive(transferred_root_original);
    let spec = spec_original.take().ok_or(HostError::Fence("launch unit spec disappeared"))?;
    Ok(PreparedLaunch {
        spec,
        snapshot,
        guest_package_binding,
        guest_feature_mask,
        pins: LaunchPins {
            executable: Arc::clone(recipe.executable_pin_arc()?),
            workspace: workspace.pin,
            transferred_root,
            network: network.pin,
            attachment_anchor: attachment_anchor.pin,
        },
    })
}
