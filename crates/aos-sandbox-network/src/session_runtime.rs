//! Production ownership for authenticated Network broker sessions.
//!
//! The runtime opens the protected Network authority and every durable catalog
//! before exposing a request callsite. This keeps journal locks, authenticated
//! policy, and namespace inventory alive for the full service lifetime.

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity};

use crate::{
    ActivatedNetworkDescriptors, DormantResolvedNetworkBrokerCompositionV1, DurableNetworkPhase,
    NetworkAuthorityConfigError, NetworkAuthorityV1, NetworkLifecycleAdmissionCoordinator,
    NetworkLifecycleStateError, NetworkLifecycleStateStore, NetworkNamespaceCatalogError,
    NetworkNamespaceCatalogV1, NetworkNamespaceCustodyRequirementV1, NetworkNamespaceStoreError,
    NetworkPolicyCatalogV1, NetworkPreparationCatalogError, NetworkPreparationCatalogV1,
    NetworkStateError, NetworkStateStore, SystemdNetworkNamespaceStore, validate_activation_replay,
};

/// Reports failure while opening the protected Network session runtime.
#[derive(Debug, thiserror::Error)]
pub enum NetworkBrokerSessionRuntimeErrorV1 {
    /// The protected Network authority configuration is unsafe or invalid.
    #[error("network authority configuration failed: {0}")]
    Authority(#[from] NetworkAuthorityConfigError),
    /// The creation journal could not be authenticated and locked.
    #[error("network creation state failed: {0}")]
    CreationState(#[from] NetworkStateError),
    /// The lifecycle journal could not be authenticated and locked.
    #[error("network lifecycle state failed: {0}")]
    LifecycleState(#[from] NetworkLifecycleStateError),
    /// The preparation catalog could not be authenticated and locked.
    #[error("network preparation catalog failed: {0}")]
    PreparationCatalog(#[from] NetworkPreparationCatalogError),
    /// The namespace catalog could not be authenticated and locked.
    #[error("network namespace catalog failed: {0}")]
    NamespaceCatalog(#[from] NetworkNamespaceCatalogError),
    /// Restart-retained namespace custody disagreed with protected state.
    #[error("network namespace descriptor store failed: {0}")]
    NamespaceStore(#[from] NetworkNamespaceStoreError),
    /// The current Linux boot identity could not be read.
    #[error("network boot identity is unavailable")]
    BootIdentity,
}

/// Owns protected state needed to serve authenticated Network requests.
pub struct NetworkBrokerSessionRuntimeV1 {
    coordinator: NetworkLifecycleAdmissionCoordinator,
    preparations: NetworkPreparationCatalogV1,
    namespaces: NetworkNamespaceCatalogV1,
    _activation: ActivatedNetworkDescriptors,
    _namespace_store: SystemdNetworkNamespaceStore,
    _host_namespace: NamespaceFd,
}

impl NetworkBrokerSessionRuntimeV1 {
    /// Opens every protected Network authority, journal, and live namespace pin.
    ///
    /// The supplied policy is a trusted node-local input. The state directory
    /// must be an exact root-owned mode-0700 directory; all journals are opened
    /// relative to retained descriptors and fail closed on rollback or damage.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkBrokerSessionRuntimeErrorV1`] when authority material,
    /// durable state, policy history, or live namespace custody is invalid.
    pub fn open_root_owned(
        authority_directory: &Path,
        state_directory: &Path,
        policy: NetworkPolicyCatalogV1,
        minimum_generation: u64,
        activation: ActivatedNetworkDescriptors,
        host_namespace: NamespaceFd,
    ) -> Result<Self, NetworkBrokerSessionRuntimeErrorV1> {
        let authority = NetworkAuthorityV1::from_protected_directory(authority_directory)?;
        let creation_state =
            NetworkStateStore::open_root_owned(state_directory, &authority, minimum_generation)?;
        let lifecycle_state =
            NetworkLifecycleStateStore::open_root_owned(state_directory, &authority)?;
        let preparations = NetworkPreparationCatalogV1::open_root_owned(
            state_directory,
            policy,
            minimum_generation,
        )?;
        let namespaces = NetworkNamespaceCatalogV1::open_root_owned(state_directory)?;
        let requirements = restart_custody_requirements(&creation_state, &namespaces)?;
        validate_activation_replay(&activation, &requirements)?;
        let namespace_store = SystemdNetworkNamespaceStore::from_environment(&activation)?;
        let coordinator =
            NetworkLifecycleAdmissionCoordinator::new(authority, creation_state, lifecycle_state);

        Ok(Self {
            coordinator,
            preparations,
            namespaces,
            _activation: activation,
            _namespace_store: namespace_store,
            _host_namespace: host_namespace,
        })
    }

    /// Borrows the authenticated request callsite and authoritative inventory.
    ///
    /// The returned objects share one lifetime so the service cannot retain a
    /// callsite after its namespace inventory or protected journals are closed.
    #[must_use]
    pub fn callsite_and_catalog(
        &mut self,
    ) -> (
        DormantResolvedNetworkBrokerCompositionV1<'_>,
        &NetworkNamespaceCatalogV1,
    ) {
        let Self {
            coordinator,
            preparations,
            namespaces,
            _activation: _,
            _namespace_store: _,
            _host_namespace: _,
        } = self;
        let callsite =
            DormantResolvedNetworkBrokerCompositionV1::new(coordinator, preparations, namespaces);

        (callsite, namespaces)
    }
}

fn restart_custody_requirements(
    creation_state: &NetworkStateStore,
    namespaces: &NetworkNamespaceCatalogV1,
) -> Result<Vec<NetworkNamespaceCustodyRequirementV1>, NetworkBrokerSessionRuntimeErrorV1> {
    let current_boot_id = KernelBootId::current()
        .map_err(|_| NetworkBrokerSessionRuntimeErrorV1::BootIdentity)?
        .into_bytes();
    let mut requirements = namespaces
        .current_custody_requirements()?
        .into_iter()
        .map(|requirement| (requirement.network_handle(), requirement))
        .collect::<BTreeMap<_, _>>();

    for entry in creation_state.recovery_entries()? {
        let Some(custody) = entry.custody().filter(|custody| {
            custody.kernel_boot_id() == current_boot_id
                && matches!(
                    entry.phase(),
                    DurableNetworkPhase::Ambiguous | DurableNetworkPhase::Committed
                )
        }) else {
            continue;
        };
        let identity = NamespaceIdentity {
            device: custody.namespace_device(),
            inode: custody.namespace_inode(),
        };
        let requirement =
            NetworkNamespaceCustodyRequirementV1::new(entry.network_handle(), identity)?;
        if requirements
            .insert(entry.network_handle(), requirement.clone())
            .is_some_and(|existing| existing != requirement)
        {
            return Err(NetworkNamespaceStoreError::ReplayConflict.into());
        }
    }

    Ok(requirements.into_values().collect())
}
