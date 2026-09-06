//! Closed mount-effect interface and descriptor-backed worker.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{MountAction, MountState};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::inventory::{MountId, MountNamespace, MountObservation};
use aos_sandbox_linux::mount::{DetachedMount, MountAttributes};
use aos_sandbox_linux::pidfd::NamespaceIdentity;
use aos_sandbox_protocol::{ValidatedMountRequest, detached_mount_handle_v1};

use crate::catalog::{MountCatalog, ResolvedMountResources};
use crate::host_scope::ObservedMountScope;
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

/// Reports one broker-owned descriptor retained across service restarts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedMountObservation {
    /// Stable broker resource handle encoded in the descriptor-store name.
    pub handle: [u8; 32],
    /// Exact kernel-lifetime mount identity carried by the descriptor.
    pub mount_id: MountId,
}

/// Reports the exact read-only target disposition before publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationPreflight {
    /// Exact kernel mount-namespace identity returned by `statmount(2)`.
    pub target_mount_namespace_id: u64,
    /// Closed target classification relative to persisted mount identities.
    pub disposition: MountTargetObservation,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationEffect {
    AlreadyInstalled,
    AttachToEmptySlot,
    ReplacePredecessor,
}

/// Carries the sealed fail-stop clock facts delegated to a namespace helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectDeadlineV1 {
    /// Protected paired-clock reader identity used by the broker.
    pub clock_provenance: [u8; 16],
    /// Host boot identity under which the deadline is valid.
    pub host_boot_id: [u8; 16],
    /// Exclusive absolute `CLOCK_BOOTTIME` deadline.
    pub boottime_nanoseconds: u64,
}

fn validate_catalog_commitment(
    resources: &ResolvedMountResources,
    expected: ObjectDigest,
) -> Result<()> {
    if resources.authorization_commitment.digest() != expected {
        return Err(MountError::Fence(
            "mount catalog changed after authorization admission",
        ));
    }
    Ok(())
}

/// Applies one idempotent, descriptor-only mount transaction.
pub trait MountWorker {
    /// Retains one authenticated Host scope and returns its catalog commitment.
    ///
    /// This read-only step neither admits a Mount fence nor performs a mount
    /// mutation. Implementations without a live Host-backed catalog reject it.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported preparation or an invalid, conflicting,
    /// expired, or unresolvable scope.
    fn prepare_catalog(
        &mut self,
        _request: &ValidatedMountRequest,
        _scope: ObservedMountScope,
    ) -> Result<ObjectDigest> {
        Err(MountError::Worker(
            "mount worker does not accept Host scope preparation".to_owned(),
        ))
    }

    /// Resolves the exact catalog behavior commitment used for authorization.
    ///
    /// Release is the sole action that returns no catalog commitment. Every
    /// other action must recheck this digest when resolving resources for an
    /// effect, closing catalog replacement between admission and execution.
    ///
    /// # Errors
    ///
    /// Returns an error when the trusted catalog cannot resolve and verify the
    /// exact request generation.
    fn catalog_commitment(&self, request: &ValidatedMountRequest) -> Result<Option<ObjectDigest>>;

    /// Returns the complete bounded set of restart-retained mount descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error if custody contains aliases or exceeds its fixed bound.
    fn custody_inventory(&self) -> Result<Vec<RetainedMountObservation>>;

    /// Removes one retained descriptor without performing a namespace effect.
    ///
    /// # Errors
    ///
    /// Returns an error unless descriptor-store removal is acknowledged.
    fn discard_retained(&mut self, handle: [u8; 32]) -> Result<()>;

    /// Performs a read-only publication preflight against persisted identities.
    ///
    /// # Errors
    ///
    /// Returns an error for missing custody, catalog failure, namespace
    /// observation failure, or a target that cannot be classified exactly.
    fn preflight_publication(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handle: [u8; 32],
        expected_mount_id: MountId,
        predecessor: Option<([u8; 32], MountId)>,
        expected_catalog_commitment: ObjectDigest,
    ) -> Result<PublicationPreflight>;

    /// Reconciles an uncertain detach from durable identity alone.
    ///
    /// # Errors
    ///
    /// Returns an error for catalog failure, a conflicting target, helper
    /// failure, or unacknowledged descriptor-store removal.
    fn reconcile_detach(
        &mut self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handle: [u8; 32],
        expected_mount_id: MountId,
        expected_catalog_commitment: ObjectDigest,
        before_effect: &mut dyn FnMut() -> Result<EffectDeadlineV1>,
    ) -> Result<ReleasedMountObservation>;

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
        expected_catalog_commitment: Option<ObjectDigest>,
        before_effect: &mut dyn FnMut() -> Result<EffectDeadlineV1>,
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
    #[allow(clippy::too_many_arguments)]
    fn install(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
        mount: &DetachedMount,
        beneath: bool,
        expected_predecessor_mount_id: Option<MountId>,
        deadline: EffectDeadlineV1,
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
        deadline: EffectDeadlineV1,
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
        expected_catalog_commitment: ObjectDigest,
        before_effect: &mut dyn FnMut() -> Result<EffectDeadlineV1>,
    ) -> Result<ReleasedMountObservation> {
        let resources = self.catalog.resolve(request)?;
        validate_catalog_commitment(&resources, expected_catalog_commitment)?;
        match self
            .helper
            .observe(request, request_digest, &resources, expected_mount_id, None)?
        {
            MountTargetObservation::Installed(_) => {
                let deadline = before_effect()?;
                self.helper.detach(
                    request,
                    request_digest,
                    &resources,
                    expected_mount_id,
                    deadline,
                )?;
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
        let _deadline = before_effect()?;
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
    fn prepare_catalog(
        &mut self,
        request: &ValidatedMountRequest,
        scope: ObservedMountScope,
    ) -> Result<ObjectDigest> {
        self.catalog.prepare(request, scope)
    }

    fn catalog_commitment(&self, request: &ValidatedMountRequest) -> Result<Option<ObjectDigest>> {
        if request.action() == MountAction::MOUNT_ACTION_RELEASE {
            return Ok(None);
        }
        self.catalog
            .resolve(request)
            .map(|resources| Some(resources.authorization_commitment.digest()))
    }

    fn custody_inventory(&self) -> Result<Vec<RetainedMountObservation>> {
        Ok(self
            .detached
            .iter()
            .map(|(handle, mount)| RetainedMountObservation {
                handle: *handle,
                mount_id: mount.mount_id(),
            })
            .collect())
    }

    fn discard_retained(&mut self, handle: [u8; 32]) -> Result<()> {
        self.keeper.remove(&KernelMountName::from_digest(handle))?;
        self.detached.remove(&handle);
        Ok(())
    }

    fn preflight_publication(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handle: [u8; 32],
        expected_mount_id: MountId,
        predecessor: Option<([u8; 32], MountId)>,
        expected_catalog_commitment: ObjectDigest,
    ) -> Result<PublicationPreflight> {
        let mount = self.detached.get(&handle).ok_or_else(|| {
            MountError::Worker("publication mount is not retained by this broker".to_owned())
        })?;
        if mount.mount_id() != expected_mount_id {
            return Err(MountError::Worker(
                "publication custody differs from durable mount identity".to_owned(),
            ));
        }
        if let Some((predecessor_handle, predecessor_id)) = predecessor {
            let retained = self.detached.get(&predecessor_handle).ok_or_else(|| {
                MountError::Worker("replacement predecessor is not retained".to_owned())
            })?;
            if retained.mount_id() != predecessor_id {
                return Err(MountError::Worker(
                    "predecessor custody differs from durable mount identity".to_owned(),
                ));
            }
        }

        let resources = self.catalog.resolve(request)?;
        validate_catalog_commitment(&resources, expected_catalog_commitment)?;
        let namespace = MountNamespace::pinned(&resources.mount_namespace)
            .map_err(|error| MountError::Worker(error.to_string()))?;
        let root = namespace
            .list(None, None, 1)
            .map_err(|error| MountError::Worker(error.to_string()))?;
        let target_mount_namespace_id = root
            .mounts
            .first()
            .copied()
            .map(|mount_id| namespace.observe(mount_id))
            .transpose()
            .map_err(|error| MountError::Worker(error.to_string()))?
            .map(|observation| observation.mount_namespace_id)
            .filter(|identity| *identity != 0)
            .ok_or_else(|| {
                MountError::Worker("target mount namespace has no observable root".to_owned())
            })?;
        let disposition = self.helper.observe(
            request,
            request_digest,
            &resources,
            expected_mount_id,
            predecessor.map(|(_, mount_id)| mount_id),
        )?;
        Ok(PublicationPreflight {
            target_mount_namespace_id,
            disposition,
        })
    }

    fn reconcile_detach(
        &mut self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handle: [u8; 32],
        expected_mount_id: MountId,
        expected_catalog_commitment: ObjectDigest,
        before_effect: &mut dyn FnMut() -> Result<EffectDeadlineV1>,
    ) -> Result<ReleasedMountObservation> {
        DescriptorMountWorker::reconcile_detach(
            self,
            request,
            request_digest,
            handle,
            expected_mount_id,
            expected_catalog_commitment,
            before_effect,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn execute(
        &mut self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handles: EffectHandles,
        expected_catalog_commitment: Option<ObjectDigest>,
        before_effect: &mut dyn FnMut() -> Result<EffectDeadlineV1>,
    ) -> Result<WorkerObservation> {
        if request.action() == MountAction::MOUNT_ACTION_RELEASE {
            let handle = request.detached_mount_handle().copied().ok_or_else(|| {
                MountError::Worker("release operation lost its staged handle".to_owned())
            })?;
            let _deadline = before_effect()?;
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
        let expected_catalog_commitment = expected_catalog_commitment.ok_or_else(|| {
            MountError::Worker("catalogued effect lost its authorization commitment".to_owned())
        })?;
        validate_catalog_commitment(&resources, expected_catalog_commitment)?;
        match request.action() {
            MountAction::MOUNT_ACTION_CREATE_DETACHED => {
                let handle = handles.detached.ok_or_else(|| {
                    MountError::Worker("create operation has no minted detached handle".to_owned())
                })?;
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    self.detached.entry(handle)
                {
                    let name = KernelMountName::from_digest(handle);
                    if self.keeper.contains(&name)? {
                        return Err(MountError::State(
                            "descriptor store contains an unadopted mount name".to_owned(),
                        ));
                    }
                    let _deadline = before_effect()?;
                    let mount = prepare_mount(request, &resources)?;
                    let mount_id = mount.mount_id();
                    let _deadline = before_effect()?;
                    self.keeper.store(&name, mount.as_fd())?;
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
                let disposition = self.helper.observe(
                    request,
                    request_digest,
                    &resources,
                    mount.mount_id(),
                    predecessor,
                )?;
                let installed = match publication_effect(&disposition, predecessor.is_some())? {
                    PublicationEffect::AlreadyInstalled => {
                        let MountTargetObservation::Installed(observation) = disposition else {
                            return Err(MountError::State(
                                "publication classification changed".to_owned(),
                            ));
                        };
                        *observation
                    }
                    PublicationEffect::AttachToEmptySlot => {
                        let deadline = before_effect()?;
                        self.helper.install(
                            request,
                            request_digest,
                            &resources,
                            mount,
                            false,
                            None,
                            deadline,
                        )?
                    }
                    PublicationEffect::ReplacePredecessor => {
                        let deadline = before_effect()?;
                        self.helper.install(
                            request,
                            request_digest,
                            &resources,
                            mount,
                            true,
                            predecessor,
                            deadline,
                        )?
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
                let _released = self.reconcile_detach(
                    request,
                    request_digest,
                    handle,
                    expected_mount_id,
                    expected_catalog_commitment,
                    before_effect,
                )?;
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

fn publication_effect(
    disposition: &MountTargetObservation,
    is_replacement: bool,
) -> Result<PublicationEffect> {
    match disposition {
        MountTargetObservation::Installed(_) => Ok(PublicationEffect::AlreadyInstalled),
        MountTargetObservation::Absent if !is_replacement => {
            Ok(PublicationEffect::AttachToEmptySlot)
        }
        MountTargetObservation::PredecessorInstalled if is_replacement => {
            Ok(PublicationEffect::ReplacePredecessor)
        }
        MountTargetObservation::Absent
        | MountTargetObservation::PredecessorInstalled
        | MountTargetObservation::Conflict => Err(MountError::Worker(
            "destination contains a different mount generation".to_owned(),
        )),
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
            detached: Some(detached_mount_handle_v1(request_digest)),
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

    #[test]
    fn replacement_requires_predecessor_or_completed_successor() {
        assert!(publication_effect(&MountTargetObservation::Absent, true).is_err());
        assert_eq!(
            publication_effect(&MountTargetObservation::PredecessorInstalled, true).unwrap(),
            PublicationEffect::ReplacePredecessor
        );
    }
}
