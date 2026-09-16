//! Production ownership for authenticated Network broker sessions.
//!
//! The runtime opens the protected Network authority and every durable catalog
//! before exposing a request callsite. This keeps journal locks, authenticated
//! policy, and namespace inventory alive for the full service lifetime.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};

use crate::worker_runtime::open_cgroup_root;
use crate::{
    ActivatedNetworkDescriptors, DurableNetworkPhase, NetworkAuthorityConfigError,
    NetworkAuthorityV1, NetworkLifecycleAdmissionCoordinator, NetworkLifecycleStateError,
    NetworkLifecycleStateStore, NetworkNamespaceCatalogError, NetworkNamespaceCatalogV1,
    NetworkNamespaceCustodyRequirementV1, NetworkNamespaceStoreError,
    NetworkObservationWorkerError, NetworkPolicyCatalogV1, NetworkPreparationCatalogError,
    NetworkPreparationCatalogV1, NetworkStateError, NetworkStateStore, NetworkWorkerRuntimeError,
    ProductionNetworkBrokerCompositionV1, SystemdNetworkNamespaceStore,
    SystemdNetworkObservationExecutor, SystemdNetworkPrepareExecutor, validate_activation_replay,
};

const PREPARATION_WORKER_SOCKET: &str = "/run/aos/sandbox-network-worker/control.sock";
const OBSERVATION_WORKER_SOCKET: &str = "/run/aos/sandbox-network-observation-worker/control.sock";

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
    /// The preparation effect executor could not be constructed.
    #[error("network preparation worker failed: {0}")]
    PreparationWorker(#[from] NetworkWorkerRuntimeError),
    /// The postcondition observer could not be constructed.
    #[error("network observation worker failed: {0}")]
    ObservationWorker(#[from] NetworkObservationWorkerError),
    /// A retained namespace descriptor could not be duplicated safely.
    #[error("network namespace descriptor duplication failed: {0}")]
    Descriptor(#[from] std::io::Error),
    /// A retained namespace descriptor failed kernel revalidation.
    #[error("network namespace descriptor validation failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
}

/// Owns protected state needed to serve authenticated Network requests.
pub struct NetworkBrokerSessionRuntimeV1 {
    coordinator: NetworkLifecycleAdmissionCoordinator,
    preparations: NetworkPreparationCatalogV1,
    namespaces: NetworkNamespaceCatalogV1,
    _activation: ActivatedNetworkDescriptors,
    namespace_store: SystemdNetworkNamespaceStore,
    prepare_executor: SystemdNetworkPrepareExecutor,
    observation_executor: SystemdNetworkObservationExecutor,
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
        let prepare_executor = SystemdNetworkPrepareExecutor::new(
            PathBuf::from(PREPARATION_WORKER_SOCKET),
            open_cgroup_root()?,
            duplicate_network_namespace(&host_namespace)?,
        )?;
        let observation_executor = SystemdNetworkObservationExecutor::new(
            PathBuf::from(OBSERVATION_WORKER_SOCKET),
            open_cgroup_root()?,
            host_namespace,
        )?;
        let coordinator =
            NetworkLifecycleAdmissionCoordinator::new(authority, creation_state, lifecycle_state);

        Ok(Self {
            coordinator,
            preparations,
            namespaces,
            _activation: activation,
            namespace_store,
            prepare_executor,
            observation_executor,
        })
    }

    /// Borrows the authenticated request callsite and authoritative inventory.
    ///
    /// The returned objects share one lifetime so the service cannot retain a
    /// callsite after its namespace inventory or protected journals are closed.
    #[must_use]
    pub fn callsite(&mut self) -> ProductionNetworkBrokerCompositionV1<'_> {
        let Self {
            coordinator,
            preparations,
            namespaces,
            _activation: _,
            namespace_store,
            prepare_executor,
            observation_executor,
        } = self;
        ProductionNetworkBrokerCompositionV1::new(
            coordinator,
            preparations,
            namespaces,
            namespace_store,
            prepare_executor,
            observation_executor,
        )
    }
}

fn duplicate_network_namespace(
    namespace: &NamespaceFd,
) -> Result<NamespaceFd, NetworkBrokerSessionRuntimeErrorV1> {
    let descriptor = namespace.as_fd().try_clone_to_owned()?;
    NamespaceFd::from_owned(descriptor, NamespaceKind::Network).map_err(Into::into)
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
