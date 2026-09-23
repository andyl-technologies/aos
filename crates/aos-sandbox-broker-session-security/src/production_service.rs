//! Complete one production request on an authenticated broker session.
//!
//! These entry points join bounded receipt to the method-closed domain
//! dispatcher and bounded response delivery. Each operation consumes the
//! session on failure, so a daemon cannot accidentally continue traffic after
//! uncertain admission, effect, commit, or transport state.

use std::time::Duration;

use crate::{
    DormantAuthenticatedBrokerSessionV1, ProductionBrokerReceiveErrorV1,
    ProductionBrokerResponseErrorV1,
};

/// Reports failure while deriving an absolute broker-session deadline.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerDeadlineErrorV1 {
    /// The kernel returned a boottime value outside the supported range.
    #[error("kernel boottime is outside the supported range")]
    Kernel,
    /// The duration cannot be represented as an absolute nanosecond deadline.
    #[error("broker-session deadline overflowed")]
    Overflow,
}

/// Derives an absolute `CLOCK_BOOTTIME` deadline after `duration`.
///
/// # Errors
///
/// Returns an error when the kernel clock is invalid or the duration cannot be
/// represented without overflow.
pub fn production_deadline_after(
    duration: Duration,
) -> Result<u64, ProductionBrokerDeadlineErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| ProductionBrokerDeadlineErrorV1::Kernel)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| ProductionBrokerDeadlineErrorV1::Kernel)?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(ProductionBrokerDeadlineErrorV1::Overflow)?;
    let duration = u64::try_from(duration.as_nanos())
        .map_err(|_| ProductionBrokerDeadlineErrorV1::Overflow)?;
    now.checked_add(duration)
        .ok_or(ProductionBrokerDeadlineErrorV1::Overflow)
}

/// Reports a fail-closed production request-cycle failure.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerServiceErrorV1 {
    /// Authenticated request receipt or protected admission failed.
    #[error("broker request receipt failed: {0}")]
    Receive(#[from] ProductionBrokerReceiveErrorV1),
    /// Domain completion, protected commit, replay, or response delivery failed.
    #[error("broker request completion failed: {0}")]
    Response(#[from] ProductionBrokerResponseErrorV1),
}

/// Borrows the external SourceProvider graph used by Mount source methods.
///
/// RootMount and SourceProvider have independent protected process identities.
/// A Mount daemon supplies this bundle only after a dedicated provider service
/// has established those roles; its absence leaves source methods fail-closed
/// without disabling descriptor-only Mount operations.
pub struct ProductionMountSourceOwnersV1<'owners> {
    /// The durable Mount source-acquisition owner.
    pub source_owner:
        &'owners mut aos_sandbox_mount::source_acquisition::FixedMountSourceAcquisitionOwnerV2,
    /// The protected RootMount source-provider session owner.
    pub root_session:
        &'owners mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    /// The fixed source-provider state owner.
    pub provider: &'owners mut aos_sandbox_source_provider::FixedProviderOwnerV1,
    /// The physical source-provider backend transport.
    pub backend: &'owners mut dyn aos_sandbox_source_provider::SourceProviderBackendTransportV1,
    /// The canonical catalog publication bound to source acquisition.
    pub canonical_catalog_publication: &'owners [u8],
}

/// Borrows the complete Mount-owned production composition for one request.
pub struct ProductionMountBrokerOwnersV1<'owners> {
    /// The sealed Mount effect and inventory callsite.
    pub mount: &'owners mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
    /// The optional Host-sealed catalog scope for catalog preparation.
    pub catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
    /// The external source graph, present only after its separate service is current.
    pub source: Option<ProductionMountSourceOwnersV1<'owners>>,
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Receives and completes one Host request or exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when any receive,
    /// admission, Host effect, recovery, commit, or response step fails.
    pub async fn serve_production_host_request(
        self,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
        agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerServiceErrorV1> {
        let (session, event) =
            self.receive_production_host_request(deadline_boottime_nanoseconds)?;
        session
            .complete_host_request_event(
                event,
                host,
                publisher,
                agent,
                deadline_boottime_nanoseconds,
            )
            .await
            .map_err(Into::into)
    }

    /// Receives and completes one Storage request or exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when any receive,
    /// admission, Storage effect, recovery, commit, or response step fails.
    pub fn serve_production_storage_request(
        self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerServiceErrorV1> {
        let (session, event) = self.receive_production_request(deadline_boottime_nanoseconds)?;
        session
            .complete_storage_request_event(event, storage, deadline_boottime_nanoseconds)
            .map_err(Into::into)
    }

    /// Receives and completes one Network request or exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when any receive,
    /// admission, Network effect, recovery, commit, or response step fails.
    pub fn serve_production_network_request(
        self,
        network: &mut dyn aos_sandbox_network::DormantNetworkBrokerCallsiteV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerServiceErrorV1> {
        let (session, event) = self.receive_production_request(deadline_boottime_nanoseconds)?;
        session
            .complete_network_request_event(event, network, deadline_boottime_nanoseconds)
            .map_err(Into::into)
    }

    /// Receives and completes one Mount request or exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when any receive,
    /// admission, Mount/source effect, recovery, commit, or response step fails.
    pub fn serve_production_mount_request(
        self,
        owners: ProductionMountBrokerOwnersV1<'_>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerServiceErrorV1> {
        let (session, event) = self.receive_production_request(deadline_boottime_nanoseconds)?;
        session
            .complete_mount_request_event(
                event,
                owners.mount,
                owners.catalog_scope,
                owners.source,
                deadline_boottime_nanoseconds,
            )
            .map_err(Into::into)
    }
}
