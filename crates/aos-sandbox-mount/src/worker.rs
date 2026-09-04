//! Closed mount-effect interface and descriptor-backed worker.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{MountAction, MountState};
use aos_sandbox_linux::mount::{DetachedMount, MountAttributes};
use aos_sandbox_protocol::ValidatedMountRequest;

use crate::catalog::{MountCatalog, ResolvedMountResources};
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerObservation {
    /// Closed protocol state observed after the effect.
    pub state: MountState,
    /// Broker handles whose resources remain live after the effect.
    pub handles: EffectHandles,
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
    fn is_installed(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        resources: &ResolvedMountResources,
    ) -> Result<bool>;

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
    ) -> Result<()>;

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
    ) -> Result<()>;
}

/// Resolves broker-owned descriptors and delegates namespace mutations.
pub struct DescriptorMountWorker<C, H> {
    catalog: C,
    helper: H,
    detached: BTreeMap<[u8; 32], DetachedMount>,
}

impl<C, H> DescriptorMountWorker<C, H> {
    /// Constructs an empty descriptor table around trusted fixed components.
    #[must_use]
    pub const fn new(catalog: C, helper: H) -> Self {
        Self {
            catalog,
            helper,
            detached: BTreeMap::new(),
        }
    }
}

impl<C: MountCatalog, H: NamespaceHelper> MountWorker for DescriptorMountWorker<C, H> {
    fn execute(
        &mut self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        handles: EffectHandles,
    ) -> Result<WorkerObservation> {
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
                    entry.insert(mount);
                }
                Ok(WorkerObservation {
                    state: MountState::MOUNT_STATE_DETACHED,
                    handles,
                })
            }
            MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => {
                if !self
                    .helper
                    .is_installed(request, request_digest, &resources)?
                {
                    let requested = request.detached_mount_handle().copied().ok_or_else(|| {
                        MountError::Worker("install operation lost its detached handle".to_owned())
                    })?;
                    let mount = self.detached.remove(&requested).ok_or_else(|| {
                        MountError::Worker(
                            "detached mount handle is not owned by this broker".to_owned(),
                        )
                    })?;
                    let beneath = request.action() == MountAction::MOUNT_ACTION_REPLACE;
                    if let Err(error) =
                        self.helper
                            .install(request, request_digest, &resources, &mount, beneath)
                    {
                        self.detached.insert(requested, mount);
                        return Err(error);
                    }
                }
                Ok(WorkerObservation {
                    state: MountState::MOUNT_STATE_INSTALLED,
                    handles,
                })
            }
            MountAction::MOUNT_ACTION_DETACH => {
                if self
                    .helper
                    .is_installed(request, request_digest, &resources)?
                {
                    self.helper.detach(request, request_digest, &resources)?;
                }
                Ok(WorkerObservation {
                    state: MountState::MOUNT_STATE_REVOKED,
                    handles,
                })
            }
            MountAction::MOUNT_ACTION_RELEASE => {
                let handle = request.detached_mount_handle().copied().ok_or_else(|| {
                    MountError::Worker("release operation lost its staged handle".to_owned())
                })?;
                self.detached.remove(&handle);
                Ok(WorkerObservation {
                    state: MountState::MOUNT_STATE_ABSENT,
                    handles,
                })
            }
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
