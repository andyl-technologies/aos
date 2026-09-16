//! Production ownership for authenticated Network broker sessions.
//!
//! The runtime opens the protected Network authority and every durable catalog
//! before exposing a request callsite. This keeps journal locks, authenticated
//! policy, and namespace inventory alive for the full service lifetime.

use std::path::Path;

use crate::{
    DormantResolvedNetworkBrokerCompositionV1, NetworkAuthorityConfigError, NetworkAuthorityV1,
    NetworkLifecycleAdmissionCoordinator, NetworkLifecycleStateError, NetworkLifecycleStateStore,
    NetworkNamespaceCatalogError, NetworkNamespaceCatalogV1, NetworkPolicyCatalogV1,
    NetworkPreparationCatalogError, NetworkPreparationCatalogV1, NetworkStateError,
    NetworkStateStore,
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
}

/// Owns protected state needed to serve authenticated Network requests.
pub struct NetworkBrokerSessionRuntimeV1 {
    coordinator: NetworkLifecycleAdmissionCoordinator,
    preparations: NetworkPreparationCatalogV1,
    namespaces: NetworkNamespaceCatalogV1,
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
        let coordinator =
            NetworkLifecycleAdmissionCoordinator::new(authority, creation_state, lifecycle_state);

        Ok(Self {
            coordinator,
            preparations,
            namespaces,
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
        } = self;
        let callsite =
            DormantResolvedNetworkBrokerCompositionV1::new(coordinator, preparations, namespaces);

        (callsite, namespaces)
    }
}
