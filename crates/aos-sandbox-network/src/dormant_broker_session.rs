//! Dormant authenticated-session callsite for Network Apply.
//!
//! This adapter enters the real creation or existing-resource durable
//! admission coordinator after rechecking the live kernel boot. It registers
//! no route, listener, worker, or advertised method.

use aos_proto::aos::sandbox::local::v1::{NetworkResult, NetworkState};
use aos_sandbox_core::{ObjectDigest, ProtocolVersion, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::semantics::network::{CanonicalNetworkSemanticsV1, NetworkOperation};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::authorization::decode_assignment;
use crate::{
    AuthenticatedNetworkPreparationV1, NetworkAdmissionOutcome, NetworkBrokerError,
    NetworkKernelPlanV1, NetworkLifecycleAdmissionCoordinator, NetworkLifecycleAdmissionOutcome,
    NetworkNamespaceCatalogV1, NetworkPreparationCatalogV1,
};

mod sealed {
    pub trait Sealed {}
}

/// Reports rejection at the dormant broker-session-to-Network boundary.
#[derive(Debug, thiserror::Error)]
pub enum DormantNetworkBrokerCallErrorV1 {
    /// The request or live kernel boot no longer matches the protected handoff.
    #[error("authenticated Network handoff has stale kernel evidence")]
    StaleKernel,
    /// The existing Network admission path rejected the exact request.
    #[error("authenticated Network Apply failed: {0}")]
    Broker(#[from] NetworkBrokerError),
}

/// Classifies the real Network coordinator entered by the dormant callsite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantNetworkBrokerAdmissionV1 {
    /// New-namespace preparation entered creation admission.
    Preparation(NetworkAdmissionOutcome),
    /// Existing-handle mutation entered lifecycle admission.
    Lifecycle(NetworkLifecycleAdmissionOutcome),
}

/// Seals one result produced by the real Network durable admission path.
pub struct DormantNetworkBrokerObservationV1 {
    request_id: [u8; 16],
    admission: DormantNetworkBrokerAdmissionV1,
    commitment: ObjectDigest,
}

impl DormantNetworkBrokerObservationV1 {
    /// Returns a success body only for an already committed preparation replay.
    ///
    /// # Errors
    ///
    /// Returns an error while Network admission has not produced a committed
    /// physical namespace observation; pending admission never becomes success.
    pub fn response(&self) -> Result<Vec<u8>, DormantNetworkBrokerCallErrorV1> {
        let DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::Replay(
            committed,
        )) = self.admission
        else {
            return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
        };
        Ok(NetworkResult {
            network_handle: committed.network_handle().to_vec(),
            state: NetworkState::NETWORK_STATE_DEFAULT_DROP.into(),
            ..Default::default()
        }
        .encode_to_vec())
    }

    /// Returns the exact request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the durable Network admission classification.
    #[must_use]
    pub const fn admission(&self) -> DormantNetworkBrokerAdmissionV1 {
        self.admission
    }

    /// Returns the domain-separated observation commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Defines the closed Network call surface accepted by session security.
#[doc(hidden)]
pub trait DormantNetworkBrokerCallsiteV1: sealed::Sealed {
    /// Admits one exact authenticated Network Apply operation.
    ///
    /// # Errors
    ///
    /// Returns an error when request or kernel evidence is stale, or when the
    /// durable Network admission coordinator rejects the call.
    fn consume_authenticated_apply(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1>;
}

/// Retains the exact protected preparation, kernel plan, catalog, and clock.
pub struct DormantNetworkBrokerCompositionV1<'a> {
    coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
    preparation: &'a AuthenticatedNetworkPreparationV1,
    kernel_plan: &'a NetworkKernelPlanV1,
    namespaces: &'a NetworkNamespaceCatalogV1,
    last_boottime_nanoseconds: Option<u64>,
}

impl<'a> DormantNetworkBrokerCompositionV1<'a> {
    /// Constructs a dormant callsite with a fixed kernel clock owner.
    #[must_use]
    pub const fn new(
        coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
        preparation: &'a AuthenticatedNetworkPreparationV1,
        kernel_plan: &'a NetworkKernelPlanV1,
        namespaces: &'a NetworkNamespaceCatalogV1,
    ) -> Self {
        Self {
            coordinator,
            preparation,
            kernel_plan,
            namespaces,
            last_boottime_nanoseconds: None,
        }
    }
}

impl sealed::Sealed for DormantNetworkBrokerCompositionV1<'_> {}

impl DormantNetworkBrokerCallsiteV1 for DormantNetworkBrokerCompositionV1<'_> {
    fn consume_authenticated_apply(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1> {
        let (semantics, current_clock) = validate_authenticated_request(
            request_body,
            request_id,
            request_body_digest,
            peer,
            policy,
            protocol_version,
            protected_boot_id,
            &mut self.last_boottime_nanoseconds,
        )?;
        admit_authenticated_request(
            self.coordinator,
            self.preparation,
            self.kernel_plan,
            self.namespaces,
            request_body,
            request_id,
            request_body_digest,
            artifacts,
            peer,
            policy,
            protocol_version,
            &semantics,
            &current_clock,
        )
    }
}

/// Resolves each authenticated request against protected preparation history.
///
/// Unlike [`DormantNetworkBrokerCompositionV1`], this composition does not pin
/// one assignment at construction. It derives the assignment and optional
/// handle from the authenticated body, then requires the protected preparation
/// catalog to reproduce one exact authenticated resolution and kernel plan.
pub struct DormantResolvedNetworkBrokerCompositionV1<'a> {
    coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
    preparations: &'a NetworkPreparationCatalogV1,
    namespaces: &'a NetworkNamespaceCatalogV1,
    last_boottime_nanoseconds: Option<u64>,
}

impl<'a> DormantResolvedNetworkBrokerCompositionV1<'a> {
    /// Constructs the multi-assignment Network broker-session callsite.
    #[must_use]
    pub const fn new(
        coordinator: &'a mut NetworkLifecycleAdmissionCoordinator,
        preparations: &'a NetworkPreparationCatalogV1,
        namespaces: &'a NetworkNamespaceCatalogV1,
    ) -> Self {
        Self {
            coordinator,
            preparations,
            namespaces,
            last_boottime_nanoseconds: None,
        }
    }
}

impl sealed::Sealed for DormantResolvedNetworkBrokerCompositionV1<'_> {}

impl DormantNetworkBrokerCallsiteV1 for DormantResolvedNetworkBrokerCompositionV1<'_> {
    fn consume_authenticated_apply(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1> {
        let (semantics, current_clock) = validate_authenticated_request(
            request_body,
            request_id,
            request_body_digest,
            peer,
            policy,
            protocol_version,
            protected_boot_id,
            &mut self.last_boottime_nanoseconds,
        )?;
        let assignment = decode_assignment(request_body)
            .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
        let requested_handle = semantics.operation().network_handle().copied();
        let (preparation, kernel_plan) = self.coordinator.resolve_session_request_preparation(
            self.preparations,
            assignment,
            requested_handle,
        )?;

        admit_authenticated_request(
            self.coordinator,
            &preparation,
            &kernel_plan,
            self.namespaces,
            request_body,
            request_id,
            request_body_digest,
            artifacts,
            peer,
            policy,
            protocol_version,
            &semantics,
            &current_clock,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_authenticated_request(
    request_body: &[u8],
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol_version: ProtocolVersion,
    protected_boot_id: [u8; 16],
    last_boottime_nanoseconds: &mut Option<u64>,
) -> Result<(CanonicalNetworkSemanticsV1, RawPairedClockSample), DormantNetworkBrokerCallErrorV1> {
    let current_boot_id = KernelBootId::current()
        .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?
        .into_bytes();
    if current_boot_id != protected_boot_id
        || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
    {
        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
    }

    let current_clock = protected_paired_clock_sample()?;
    if current_clock.host_boot_id() != protected_boot_id
        || last_boottime_nanoseconds
            .is_some_and(|floor| current_clock.boottime_nanoseconds() < floor)
    {
        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
    }
    *last_boottime_nanoseconds = Some(current_clock.boottime_nanoseconds());
    let semantics = CanonicalNetworkSemanticsV1::decode(
        request_body,
        peer,
        policy,
        current_clock.boottime_nanoseconds(),
    )
    .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    if semantics.header().request_id() != &request_id
        || semantics.header().protocol_version() != protocol_version
    {
        return Err(DormantNetworkBrokerCallErrorV1::StaleKernel);
    }

    Ok((semantics, current_clock))
}

#[allow(clippy::too_many_arguments)]
fn admit_authenticated_request(
    coordinator: &mut NetworkLifecycleAdmissionCoordinator,
    preparation: &AuthenticatedNetworkPreparationV1,
    kernel_plan: &NetworkKernelPlanV1,
    namespaces: &NetworkNamespaceCatalogV1,
    request_body: &[u8],
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protocol_version: ProtocolVersion,
    semantics: &CanonicalNetworkSemanticsV1,
    current_clock: &RawPairedClockSample,
) -> Result<DormantNetworkBrokerObservationV1, DormantNetworkBrokerCallErrorV1> {
    let admission = match semantics.operation() {
        NetworkOperation::Prepare { .. } => {
            DormantNetworkBrokerAdmissionV1::Preparation(coordinator.admit_apply_intent(
                request_body,
                artifacts,
                preparation,
                protocol_version,
                peer,
                policy,
                current_clock,
            )?)
        }
        NetworkOperation::ArmLease { .. }
        | NetworkOperation::RenewLease { .. }
        | NetworkOperation::Disarm { .. }
        | NetworkOperation::Destroy { .. } => {
            DormantNetworkBrokerAdmissionV1::Lifecycle(coordinator.admit_lifecycle_intent(
                request_body,
                artifacts,
                preparation,
                kernel_plan,
                namespaces,
                protocol_version,
                peer,
                policy,
                current_clock,
            )?)
        }
    };
    let commitment = network_observation_commitment(request_id, request_body_digest, admission);
    Ok(DormantNetworkBrokerObservationV1 {
        request_id,
        admission,
        commitment,
    })
}

fn protected_paired_clock_sample() -> Result<RawPairedClockSample, DormantNetworkBrokerCallErrorV1>
{
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds =
        u64::try_from(boottime.tv_sec).map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    let nanoseconds = u64::try_from(boottime.tv_nsec)
        .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    let boottime_nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
        .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        KernelBootId::current()
            .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)?
            .into_bytes(),
        wall.tv_sec,
        boottime_nanoseconds,
    )
    .map_err(|_| DormantNetworkBrokerCallErrorV1::StaleKernel)
}

fn network_observation_commitment(
    request_id: [u8; 16],
    request_body_digest: ObjectDigest,
    admission: DormantNetworkBrokerAdmissionV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-network-broker-observation-v1\0");
    digest.update(request_id);
    digest.update(request_body_digest.as_bytes());
    let (tag, outcome_digest) = match admission {
        DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::Prepared {
            effect_digest,
        }) => (1, effect_digest),
        DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::ObserveOnly {
            effect_digest,
            ..
        }) => (2, effect_digest),
        DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::Aborted {
            effect_digest,
        }) => (3, effect_digest),
        DormantNetworkBrokerAdmissionV1::Preparation(NetworkAdmissionOutcome::Replay(result)) => {
            (4, result.result_digest())
        }
        DormantNetworkBrokerAdmissionV1::Lifecycle(
            NetworkLifecycleAdmissionOutcome::Prepared { effect_digest },
        ) => (5, effect_digest),
        DormantNetworkBrokerAdmissionV1::Lifecycle(
            NetworkLifecycleAdmissionOutcome::ObserveOnly { effect_digest, .. },
        ) => (6, effect_digest),
        DormantNetworkBrokerAdmissionV1::Lifecycle(NetworkLifecycleAdmissionOutcome::Replay(
            result,
        )) => (7, result.observation_digest()),
    };
    digest.update([tag]);
    digest.update(outcome_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}
