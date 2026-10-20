//! Owns the genuine image-enrolled Network service and all startup prefixes.
//!
//! The service consumes the shared fixed-role F entrance, actual protected
//! configuration and policy, four captured catalog writers, the same retained
//! worker/FDStore engines and stdin listener. Session cold opening remains a
//! distinct same-F interval; its private Journal stays inert until the installer.

pub(crate) mod journal;
mod startup;
mod cold;
mod receiving;
mod preissue;
mod prepare_selected;
mod destroy_selected;
mod destroy_programme;
pub use destroy_programme::NetworkServiceDestroyProgrammeOriginalV2;
mod worker_programme;
pub use worker_programme::NetworkServiceWorkersOriginalV2;
pub use destroy_selected::NetworkServiceDestroyOriginalV4;
pub use prepare_selected::NetworkServicePrepareOriginalV4;
mod finalization;
mod callsite;
mod inventory;
mod inventory_history;
pub use callsite::{NetworkServiceDomainCallsiteV4, NetworkServiceObservationV4, NetworkServiceRequestMethodV5};
pub use inventory::NetworkServiceInventoryOriginalV4;
pub use cold::NetworkServiceSessionInputsV4;

use aos_sandbox_broker::canonical_journal::network_opening::NetworkBrokerSessionCapturedJournalOpenV4;
use aos_sandbox_broker::{ProtectedBrokerAuthorityConfiguration, ProtectedBrokerPublicCredentials,
    ProtectedNetworkBrokerConfigurationOriginalV4};
use aos_sandbox_broker::receiving::{FixedServiceListenerOriginalV4,
    FixedServiceOperationClosedV4 as Closed, FixedServiceReceivingCaptureV1 as Common};
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{CgroupRootOriginalV2, CgroupV2Root};
use aos_sandbox_linux::pidfd::{CurrentNetworkNamespaceOriginalV4, NamespaceFd};
use std::error::Error;
use std::os::fd::OwnedFd;

use crate::authorization::NetworkAuthorityV1;
use crate::protected_policy::ProtectedNetworkPolicyOriginalV4;
use crate::state::{NetworkCreationStateOpeningOriginalV4, NetworkStateStore};
use crate::lifecycle_state::{NetworkLifecycleOpeningOriginalV4, NetworkLifecycleStateStore};
use crate::preparation_catalog::{NetworkPreparationOpeningOriginalV4, NetworkPreparationCatalogV1};
use crate::namespace_catalog::{NetworkNamespaceCatalogOpeningOriginalV4, NetworkNamespaceCatalogV1};
use crate::namespace_store::{NetworkNamespaceStoreOpeningOriginalV4, NetworkNamespaceStoreFailureV4,
    SystemdNetworkNamespaceStore};
use crate::worker_runtime::{NetworkPrepareExecutorOpeningOriginalV4,
    NetworkObservationExecutorOpeningOriginalV4, SystemdNetworkPrepareExecutor};
use crate::observation_worker_runtime::SystemdNetworkObservationExecutor;
use crate::NetworkLifecycleAdmissionCoordinator;

/// Reports an unfinished or refused selected Network service boundary.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the genuine fixed Network service remains closed")]
pub struct NetworkServiceClosedV4;

type Result<T> = std::result::Result<T, NetworkServiceClosedV4>;

#[derive(Clone, Copy)]
enum First {
    Layout, Entrance, Geometry, Funding, Before, Configuration, Policy,
    Creation, Lifecycle, Preparations, Namespaces, Store, Inputs(usize),
    PrepareExecutor, ObserveExecutor, Listener, After, Transfer, Order,
}

/// Borrows the actual selected startup cause, including retained systemd sources.
pub enum NetworkServiceFailureV4<'held> {
    /// Preserves an actual native, accounting, decoder or stage error.
    Cause(&'held (dyn Error + 'static)),
    /// Preserves the same retained FDStore driver's rich typed failure view.
    Store(NetworkNamespaceStoreFailureV4<'held>),
}

impl std::fmt::Display for NetworkServiceFailureV4<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cause(cause) => std::fmt::Display::fmt(cause, formatter),
            Self::Store(cause) => std::fmt::Display::fmt(cause, formatter),
        }
    }
}

/// Retains the actual same-role startup, native sources, journals and workers.
///
/// Construction is inert and allocation-free. The installed caller supplies
/// its complete compiled runtime header before this same object's first F
/// admission. All failed owners stay resident through the independent after.
#[must_use]
pub struct NetworkServiceOriginalV4 {
    common: Common<Closed>,
    configuration: ProtectedNetworkBrokerConfigurationOriginalV4,
    policy: ProtectedNetworkPolicyOriginalV4,
    creation_opening: NetworkCreationStateOpeningOriginalV4,
    lifecycle_opening: NetworkLifecycleOpeningOriginalV4,
    preparation_opening: NetworkPreparationOpeningOriginalV4,
    namespace_opening: NetworkNamespaceCatalogOpeningOriginalV4,
    session_opening: NetworkBrokerSessionCapturedJournalOpenV4,
    listener_opening: FixedServiceListenerOriginalV4,
    store_opening: NetworkNamespaceStoreOpeningOriginalV4,
    prepare_opening: NetworkPrepareExecutorOpeningOriginalV4,
    observe_opening: NetworkObservationExecutorOpeningOriginalV4,
    cgroup_opened: [Option<std::result::Result<OwnedFd, rustix::io::Errno>>; 2],
    cgroup_originals: [CgroupRootOriginalV2; 2],
    host_originals: [CurrentNetworkNamespaceOriginalV4; 2],
    cgroups: [Option<CgroupV2Root>; 2],
    hosts: [Option<NamespaceFd>; 2],
    authority: Option<NetworkAuthorityV1>,
    credentials: Option<ProtectedBrokerPublicCredentials>,
    creation: Option<NetworkStateStore>,
    lifecycle: Option<NetworkLifecycleStateStore>,
    coordinator: Option<NetworkLifecycleAdmissionCoordinator>,
    preparations: Option<NetworkPreparationCatalogV1>,
    namespaces: Option<NetworkNamespaceCatalogV1>,
    namespace_store: Option<SystemdNetworkNamespaceStore>,
    prepare_executor: Option<SystemdNetworkPrepareExecutor>,
    observation_executor: Option<SystemdNetworkObservationExecutor>,
    runtime_layout: Option<std::result::Result<usize, AccountingError>>,
    geometry: Option<std::result::Result<ResourceVector, AccountingError>>,
    entrance: Option<std::result::Result<(), Closed>>,
    funding: [Option<std::result::Result<(), Closed>>; 3],
    native_before: Option<std::result::Result<(), Closed>>,
    configuration_result: Option<std::result::Result<(), aos_sandbox_broker::BrokerAuthorityConfigError>>,
    policy_native: Option<std::result::Result<(), crate::protected_policy::ProtectedNetworkPolicyErrorV1>>,
    policy_typed: Option<std::result::Result<(), crate::protected_policy::ProtectedNetworkPolicyErrorV1>>,
    stage_results: [Option<Result<()>>; 9],
    listener_result: Option<std::result::Result<(), Closed>>,
    listener_original_selected: bool,
    body: Option<Result<()>>,
    after: Option<std::result::Result<(), Closed>>,
    first: Option<First>,
    entered: bool,
    ready: bool,
    cold_borrowed: bool,
}

impl NetworkServiceOriginalV4 {
    /// Creates the compiled inert destinations under the actual runtime header.
    ///
    /// The caller first constructs its inert runtime with an empty inline
    /// service slot, calls this on that same header, then stores the returned
    /// service there. Dynamic models and native work remain separately paid.
    #[must_use]
    pub fn new_with_runtime_header_v4<T: Sized>(header: &T) -> Self {
        let layout = std::mem::size_of_val(header).checked_mul(2)
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes });
        let bytes = layout.as_ref().copied().unwrap_or(usize::MAX);
        Self {
            common: Common::new_network_v4(bytes),
            configuration: ProtectedNetworkBrokerConfigurationOriginalV4::new(),
            policy: ProtectedNetworkPolicyOriginalV4::new(),
            creation_opening: NetworkCreationStateOpeningOriginalV4::new(),
            lifecycle_opening: NetworkLifecycleOpeningOriginalV4::new(),
            preparation_opening: NetworkPreparationOpeningOriginalV4::new(),
            namespace_opening: NetworkNamespaceCatalogOpeningOriginalV4::new(),
            session_opening: NetworkBrokerSessionCapturedJournalOpenV4::new(),
            listener_opening: FixedServiceListenerOriginalV4::new(),
            store_opening: NetworkNamespaceStoreOpeningOriginalV4::new(),
            prepare_opening: NetworkPrepareExecutorOpeningOriginalV4::new(),
            observe_opening: NetworkObservationExecutorOpeningOriginalV4::new(),
            cgroup_opened: std::array::from_fn(|_| None),
            cgroup_originals: std::array::from_fn(|_| CgroupRootOriginalV2::new()),
            host_originals: std::array::from_fn(|_| CurrentNetworkNamespaceOriginalV4::new()),
            cgroups: [None, None], hosts: [None, None], authority: None, credentials: None,
            creation: None, lifecycle: None, coordinator: None, preparations: None,
            namespaces: None, namespace_store: None, prepare_executor: None, observation_executor: None,
            runtime_layout: Some(layout), geometry: None, entrance: None,
            funding: std::array::from_fn(|_| None), native_before: None,
            configuration_result: None, policy_native: None, policy_typed: None,
            stage_results: std::array::from_fn(|_| None), listener_result: None, listener_original_selected: false, body: None, after: None,
            first: None, entered: false, ready: false, cold_borrowed: false,
        }
    }

    /// Captures the image-enrolled startup and always closes its entered native interval.
    ///
    /// # Errors
    /// Retains every reached configuration, policy, Journal, worker, FDStore,
    /// financial and independent-after cause. Reentry replaces no original.
    pub fn capture_startup_once_v4(&mut self, maximum_retained_namespaces: usize) -> Result<()> {
        if self.entered { self.first.get_or_insert(First::Order); return Err(NetworkServiceClosedV4); }
        self.entered = true;
        if self.runtime_layout.as_ref().is_some_and(|result| result.is_err()) {
            self.first.get_or_insert(First::Layout);
            return Err(NetworkServiceClosedV4);
        }
        self.entrance = Some(self.common.capture_once());
        if !matches!(self.entrance, Some(Ok(()))) {
            self.first.get_or_insert(First::Entrance);
            return Err(NetworkServiceClosedV4);
        }
        self.capture_startup_v4(maximum_retained_namespaces)
    }

    fn require_ready_v4(&self) -> Result<()> {
        if !self.ready || self.first.is_some() { Err(NetworkServiceClosedV4) } else { Ok(()) }
    }

    /// Borrows the actual first cause without sampling or replacing a native owner.
    #[must_use]
    pub fn failure_view_v4(&self) -> Option<NetworkServiceFailureV4<'_>> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Layout => self.runtime_layout.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Entrance => self.common.failure(),
            First::Geometry => self.geometry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Funding | First::Before | First::After => self.common.service_startup_failure_v4(),
            First::Configuration => self.configuration.failure(),
            First::Policy => self.policy.failure(),
            First::Creation => if self.creation_opening.original_failure_selected_v4() {
                self.common.service_startup_failure_v4()
            } else { self.creation_opening.failure() },
            First::Lifecycle => if self.lifecycle_opening.original_failure_selected_v4() {
                self.common.service_startup_failure_v4()
            } else { self.lifecycle_opening.failure() },
            First::Preparations => if self.preparation_opening.original_failure_selected_v4() {
                self.common.service_startup_failure_v4()
            } else { self.preparation_opening.failure() },
            First::Namespaces => if self.namespace_opening.original_failure_selected_v4() {
                self.common.service_startup_failure_v4()
            } else { self.namespace_opening.failure() },
            First::Store => {
                if self.store_opening.original_failure_selected_v4() {
                    self.common.service_startup_failure_v4()
                } else { return self.store_opening.failure_view_v4().map(NetworkServiceFailureV4::Store); }
            }
            First::Inputs(index) => self.cgroup_opened[index].as_ref()
                .and_then(|value| value.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.cgroup_originals[index].failure().map(|cause| cause as _))
                .or_else(|| self.host_originals[index].failure().map(|cause| cause as _)),
            First::PrepareExecutor => if self.prepare_opening.original_failure_selected_v4() {
                self.common.service_startup_failure_v4()
            } else { self.prepare_opening.failure() },
            First::ObserveExecutor => if self.observe_opening.original_failure_selected_v4() {
                self.common.service_startup_failure_v4()
            } else { self.observe_opening.failure() },
            First::Listener => if self.listener_original_selected { self.common.service_startup_failure_v4() }
                else { self.listener_opening.failure() },
            First::Transfer | First::Order => None,
        };
        cause.map(NetworkServiceFailureV4::Cause)
            .or(Some(NetworkServiceFailureV4::Cause(&NetworkServiceClosedV4)))
    }
}

impl Drop for NetworkServiceOriginalV4 {
    fn drop(&mut self) {
        if self.entered {
            // The installed process retains the entire startup/native/key
            // owner through its lifetime. No failed path disposes it early.
            std::process::abort();
        }
    }
}
