//! Closed mount-effect interface and descriptor-backed worker.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{MountAction, MountState};
use aos_sandbox_linux::inventory::{MountId, MountObservation};
use aos_sandbox_linux::mount::{DetachedMount, MountAttributes};
use aos_sandbox_linux::pidfd::NamespaceIdentity;
use aos_sandbox_protocol::ValidatedMountRequest;

use crate::catalog::{MountCatalog, ResolvedMountResources};
use crate::keeper::{KernelMountName, KernelMountStore};
use crate::{MountError, Result};

/// Supplies broker-minted handles for one admitted mount effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectHandles {
    /// Handle naming the prepared detached mount, when one exists.
    pub detached: Option<[u8; 32]>,
    /// Handle naming the published mount generation, when one exists.
    pub installed: Option<[u8; 32]>,
}

/// Reports the kernel-verified result of one fixed mount effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerObservation {
    /// Closed protocol state observed after the effect.
    pub state: MountState,
    /// Broker handles whose resources remain live after the effect.
    pub handles: EffectHandles,
    /// Exact detached identity after preparation, only for create.
    pub detached_mount_id: Option<MountId>,
    /// Full exact target-side evidence, only while installed.
    pub installed: Option<InstalledMountObservation>,
}

/// Proves that one exact mount is absent and no longer held by the keeper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasedMountObservation {
    /// Kernel-lifetime identity of the mount that was released.
    pub mount_id: MountId,
}

/// Identifies one exact published mount in one exact namespace incarnation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledMountObservation {
    /// Complete bounded `statmount(2)` evidence for the published mount.
    pub mount: MountObservation,
    /// Stable identity of the pinned target mount namespace descriptor.
    pub mount_namespace: NamespaceIdentity,
    /// Domain-separated digest of the optional UID and GID idmap extents.
    pub idmap_digest: [u8; 32],
}

/// Classifies the exact destination relative to an expected mount identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MountTargetObservation {
    /// The catalogued destination slot is topmost.
    Absent,
    /// The expected exact mount is topmost.
    Installed(Box<InstalledMountObservation>),
    /// The exact predecessor authorized for replacement is topmost.
    PredecessorInstalled,
    /// Another mount or object is topmost; callers must fail closed.
    Conflict,
}

/// Applies one idempotent, descriptor-only mount transaction.
pub trait MountWorker {
    /// Applies or reconciles the validated action and verifies its result.
    ///
    /// The worker must resolve all resources through its trusted catalog. It
    /// must never interpret a caller path, mount option, descriptor number, or
    /// namespace PID. Repeating the exact request after a crash must return the
    /// same semantic observation.
    ///
    /// # Errors
    ///
    /// Returns an error when catalog resolution, helper execution, the mount
    /// mutation, or post-effect kernel observation fails.
    fn execute(
        &mut self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handles: EffectHandles,
    ) -> Result<WorkerObservation>;
}

/// Performs the sole namespace-local mutation in a short-lived process.
pub trait NamespaceHelper {
    /// Observes whether the exact requested generation is already installed.
    ///
    /// # Errors
    ///
    /// Returns an error when namespace entry or bounded mount inventory fails.
    fn observe(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        expected_mount_id: MountId,
        expected_predecessor_mount_id: Option<MountId>,
    ) -> Result<MountTargetObservation>;

    /// Installs one detached mount, optionally beneath the current generation.
    ///
    /// # Errors
    ///
    /// Returns an error when helper launch, descriptor validation, namespace
    /// entry, publication, or post-publication verification fails.
    fn install(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        mount: &DetachedMount,
        beneath: bool,
        expected_predecessor_mount_id: Option<MountId>,
    ) -> Result<InstalledMountObservation>;

    /// Detaches the exact catalogued installed generation if present.
    ///
    /// # Errors
    ///
    /// Returns an error when helper launch, descriptor validation, namespace
    /// entry, identity verification, or unmount fails.
    fn detach(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        expected_mount_id: MountId,
    ) -> Result<()>;
}

/// Resolves broker-owned descriptors and delegates namespace mutations.
pub struct DescriptorMountWorker<C, H, K> {
    catalog: C,
    helper: H,
    keeper: K,
    detached: BTreeMap<[u8; 32], DetachedMount>,
}

impl<C, H, K> DescriptorMountWorker<C, H, K> {
    /// Constructs a worker after validating all restart-restored mounts.
    ///
    /// # Errors
    ///
    /// Returns an error if two retained names alias the same exact kernel
    /// mount or decode to the same broker handle.
    pub fn new(
        catalog: C,
        helper: H,
        keeper: K,
        retained: BTreeMap<KernelMountName, DetachedMount>,
    ) -> Result<Self> {
        let mut detached = BTreeMap::new();
        let mut identities = std::collections::BTreeSet::new();
        for (name, mount) in retained {
            if !identities.insert(mount.mount_id())
                || detached.insert(name.digest(), mount).is_some()
            {
                return Err(MountError::State(
                    "retained mount descriptor table contains an alias".to_owned(),
                ));
            }
        }
        Ok(Self {
            catalog,
            helper,
            keeper,
            detached,
        })
    }
}

impl<C: MountCatalog, H: NamespaceHelper, K: KernelMountStore> DescriptorMountWorker<C, H, K> {
    /// Reconciles detach from a durable identity without requiring FD custody.
    ///
    /// The durable state layer may call this after a prior helper mutation and
    /// descriptor-store removal. A missing local descriptor is never treated
    /// as permission to recreate the mount.
    ///
    /// # Errors
    ///
    /// Returns an error for catalog failure, a conflicting target generation,
    /// helper failure, or unacknowledged descriptor-store removal.
    pub fn reconcile_detach(
        &mut self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handle: [u8; 32],
        expected_mount_id: MountId,
    ) -> Result<ReleasedMountObservation> {
        let resources = self.catalog.resolve(request)?;
        match self
            .helper
            .observe(request, request_digest, &resources, expected_mount_id, None)?
        {
            MountTargetObservation::Installed(_) => {
                self.helper
                    .detach(request, request_digest, &resources, expected_mount_id)?;
            }
            MountTargetObservation::Absent => {}
            MountTargetObservation::PredecessorInstalled => {
                return Err(MountError::Worker(
                    "detach unexpectedly matched a replacement predecessor".to_owned(),
                ));
            }
            MountTargetObservation::Conflict => {
                return Err(MountError::Worker(
                    "refusing to detach a different mount generation".to_owned(),
                ));
            }
        }
        self.keeper.remove(&KernelMountName::from_digest(handle))?;
        self.detached.remove(&handle);
        Ok(ReleasedMountObservation {
            mount_id: expected_mount_id,
        })
    }
}

impl<C: MountCatalog, H: NamespaceHelper, K: KernelMountStore> MountWorker
    for DescriptorMountWorker<C, H, K>
{
    #[allow(clippy::too_many_lines)]
    fn execute(
        &mut self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handles: EffectHandles,
    ) -> Result<WorkerObservation> {
        if request.action() == MountAction::MOUNT_ACTION_RELEASE {
            let handle = request.detached_mount_handle().copied().ok_or_else(|| {
                MountError::Worker("release operation lost its staged handle".to_owned())
            })?;
            self.keeper.remove(&KernelMountName::from_digest(handle))?;
            self.detached.remove(&handle);
            return Ok(WorkerObservation {
                state: MountState::MOUNT_STATE_ABSENT,
                handles,
                detached_mount_id: None,
                installed: None,
            });
        }

        let resources = self.catalog.resolve(request)?;
        match request.action() {
            MountAction::MOUNT_ACTION_CREATE_DETACHED => {
                let handle = handles.detached.ok_or_else(|| {
                    MountError::Worker("create operation has no minted detached handle".to_owned())
                })?;
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    self.detached.entry(handle)
                {
                    let mount = prepare_mount(request, &resources)?;
                    let mount_id = mount.mount_id();
                    self.keeper
                        .store(&KernelMountName::from_digest(handle), mount.as_fd())?;
                    entry.insert(mount);
                    return Ok(WorkerObservation {
                        state: MountState::MOUNT_STATE_DETACHED,
                        handles,
                        detached_mount_id: Some(mount_id),
                        installed: None,
                    });
                }
                let mount_id = self
                    .detached
                    .get(&handle)
                    .map(DetachedMount::mount_id)
                    .ok_or_else(|| {
                        MountError::Worker("prepared mount disappeared from custody".to_owned())
                    })?;
                Ok(WorkerObservation {
                    state: MountState::MOUNT_STATE_DETACHED,
                    handles,
                    detached_mount_id: Some(mount_id),
                    installed: None,
                })
            }
            MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => {
                let requested = request.detached_mount_handle().copied().ok_or_else(|| {
                    MountError::Worker("install operation lost its detached handle".to_owned())
                })?;
                let mount = self.detached.get(&requested).ok_or_else(|| {
                    MountError::Worker(
                        "detached mount handle is not retained by this broker".to_owned(),
                    )
                })?;
                let predecessor = match request.action() {
                    MountAction::MOUNT_ACTION_REPLACE => Some(
                        request
                            .replacement_mount_handle()
                            .and_then(|handle| self.detached.get(handle))
                            .map(DetachedMount::mount_id)
                            .ok_or_else(|| {
                                MountError::Worker(
                                    "replacement predecessor is not retained".to_owned(),
                                )
                            })?,
                    ),
                    _ => None,
                };
                let installed = match self.helper.observe(
                    request,
                    request_digest,
                    &resources,
                    mount.mount_id(),
                    predecessor,
                )? {
                    MountTargetObservation::Installed(observation) => *observation,
                    MountTargetObservation::Absent => {
                        if predecessor.is_some() {
                            return Err(MountError::Worker(
                                "replacement predecessor is absent".to_owned(),
                            ));
                        }
                        self.helper.install(
                            request,
                            request_digest,
                            &resources,
                            mount,
                            false,
                            None,
                        )?
                    }
                    MountTargetObservation::PredecessorInstalled => self.helper.install(
                        request,
                        request_digest,
                        &resources,
                        mount,
                        true,
                        predecessor,
                    )?,
                    MountTargetObservation::Conflict => {
                        return Err(MountError::Worker(
                            "destination contains a different mount generation".to_owned(),
                        ));
                    }
                };
                if installed.mount.mount_id != mount.mount_id() {
                    return Err(MountError::Worker(
                        "publication changed the detached mount identity".to_owned(),
                    ));
                }
                Ok(WorkerObservation {
                    state: MountState::MOUNT_STATE_INSTALLED,
                    handles,
                    detached_mount_id: None,
                    installed: Some(installed),
                })
            }
            MountAction::MOUNT_ACTION_DETACH => {
                let handle = request.detached_mount_handle().copied().ok_or_else(|| {
                    MountError::Worker("detach operation lost its mount handle".to_owned())
                })?;
                let mount = self.detached.get(&handle).ok_or_else(|| {
                    MountError::Worker(
                        "installed mount handle is not retained by this broker".to_owned(),
                    )
                })?;
                let expected_mount_id = mount.mount_id();
                let _ = resources;
                let _released =
                    self.reconcile_detach(request, request_digest, handle, expected_mount_id)?;
                Ok(WorkerObservation {
                    state: MountState::MOUNT_STATE_REVOKED,
                    handles,
                    detached_mount_id: None,
                    installed: None,
                })
            }
            MountAction::MOUNT_ACTION_RELEASE => Err(MountError::Worker(
                "release reached catalog-backed dispatch".to_owned(),
            )),
            MountAction::MOUNT_ACTION_UNSPECIFIED => Err(MountError::Worker(
                "validated worker received an unspecified action".to_owned(),
            )),
        }
    }
}

fn prepare_mount(
    request: &ValidatedMountRequest,
    resources: &ResolvedMountResources,
) -> Result<DetachedMount> {
    let attributes = request.attributes().ok_or_else(|| {
        MountError::Worker("prepare operation lost validated attributes".to_owned())
    })?;
    let mut linux_attributes = if attributes.read_only() {
        MountAttributes::secure_read_only()
    } else {
        MountAttributes::secure_writable()
    };
    linux_attributes = linux_attributes
        .with_no_exec(attributes.no_exec())
        .with_no_atime(attributes.no_atime());
    DetachedMount::clone_with_attributes(
        &resources.source,
        false,
        linux_attributes,
        Some(&resources.user_namespace),
    )
    .map_err(|error| MountError::Worker(error.to_string()))
}

pub(crate) fn expected_handles(
    action: MountAction,
    request_digest: [u8; 32],
    supplied_detached: Option<[u8; 32]>,
) -> Result<EffectHandles> {
    let handles = match action {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => EffectHandles {
            detached: Some(derive_handle(b"detached", request_digest)),
            installed: None,
        },
        MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => EffectHandles {
            detached: None,
            installed: Some(supplied_detached.ok_or_else(|| {
                MountError::Worker("install operation has no detached handle".to_owned())
            })?),
        },
        MountAction::MOUNT_ACTION_DETACH
        | MountAction::MOUNT_ACTION_RELEASE
        | MountAction::MOUNT_ACTION_UNSPECIFIED => EffectHandles {
            detached: None,
            installed: None,
        },
    };
    Ok(handles)
}

fn derive_handle(label: &[u8], request_digest: [u8; 32]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.handle.v1\0");
    digest.update(label);
    digest.update(request_digest);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn publication_preserves_the_broker_owned_resource_handle() {
        let handle = [7; 32];
        for action in [
            MountAction::MOUNT_ACTION_INSTALL,
            MountAction::MOUNT_ACTION_REPLACE,
        ] {
            assert_eq!(
                expected_handles(action, [9; 32], Some(handle)).unwrap(),
                EffectHandles {
                    detached: None,
                    installed: Some(handle),
                }
            );
            assert!(expected_handles(action, [9; 32], None).is_err());
        }
    }
}
