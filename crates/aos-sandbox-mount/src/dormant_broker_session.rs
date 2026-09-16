//! Dormant authenticated-session callsite for Mount Apply.
//!
//! The adapter is intentionally absent from the mount service. It consumes an
//! exact body only through the existing durable [`crate::MountBroker`] path and
//! returns a privately constructible observation for broker-session sealing.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_core::{ObjectDigest, ProtocolVersion};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, decode_destination_slot_inventory_request,
    decode_mount_catalog_preparation, decode_mount_inventory_request,
};
use sha2::{Digest as _, Sha256};

use crate::MountError;
use crate::broker::MountBroker;
use crate::host_scope::ObservedMountScope;
use crate::worker::MountWorker;

mod sealed {
    pub trait Sealed {}
}

/// Reports rejection at the dormant broker-session-to-Mount boundary.
#[derive(Debug, thiserror::Error)]
pub enum DormantMountBrokerCallErrorV1 {
    /// The protected session and live kernel or request identities differ.
    #[error("authenticated Mount handoff has stale kernel evidence")]
    StaleKernel,
    /// The existing durable Mount operation rejected the request.
    #[error("authenticated Mount Apply failed: {0}")]
    Broker(#[from] MountError),
}

/// Seals one response emitted by the real Mount broker operation.
pub struct DormantMountBrokerObservationV1 {
    request_id: [u8; 16],
    response: Vec<u8>,
    commitment: ObjectDigest,
}

impl DormantMountBrokerObservationV1 {
    /// Returns the exact request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the bounded Mount response body.
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// Returns the domain-separated observation commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Defines the closed Mount call surface accepted by session security.
#[doc(hidden)]
pub trait DormantMountBrokerCallsiteV1: sealed::Sealed {
    /// Executes one exact authenticated Mount Apply operation.
    ///
    /// # Errors
    ///
    /// Returns an error when request or kernel evidence is stale, or when the
    /// durable Mount broker rejects the call.
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
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1>;

    /// Reads one exact authenticated Mount inventory from the real broker.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-inventory method, stale request or kernel
    /// evidence, or an unavailable authoritative inventory.
    fn consume_authenticated_inventory(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1>;

    /// Executes one exact authenticated destination-slot mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for any other method, stale request/kernel evidence,
    /// or rejection by the durable destination-slot owner.
    fn consume_authenticated_destination_slot(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1>;

    /// Resolves one exact Mount catalog preparation with a Host-sealed scope.
    ///
    /// # Errors
    ///
    /// Returns an error for stale request/kernel evidence or when the scope
    /// and protected Mount catalog do not resolve the same resource tuple.
    fn consume_authenticated_catalog_preparation(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        scope: ObservedMountScope,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1>;
}

/// Retains the concrete Mount broker and kernel clock.
///
/// Creating this value registers no listener and does not change advertised
/// methods. Only explicit consumption can enter the existing durable broker.
pub struct DormantMountBrokerCompositionV1<'a, W>
where
    W: MountWorker,
{
    broker: &'a mut MountBroker<W>,
    last_boottime_nanoseconds: Option<u64>,
}

impl<'a, W> DormantMountBrokerCompositionV1<'a, W>
where
    W: MountWorker,
{
    /// Constructs an explicit dormant callsite with a fixed kernel clock owner.
    #[must_use]
    pub const fn new(broker: &'a mut MountBroker<W>) -> Self {
        Self {
            broker,
            last_boottime_nanoseconds: None,
        }
    }
}

impl<W> sealed::Sealed for DormantMountBrokerCompositionV1<'_, W> where W: MountWorker {}

impl<W> DormantMountBrokerCallsiteV1 for DormantMountBrokerCompositionV1<'_, W>
where
    W: MountWorker,
{
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
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1> {
        let current_boot_id = KernelBootId::current()
            .map_err(|_| DormantMountBrokerCallErrorV1::StaleKernel)?
            .into_bytes();
        if current_boot_id != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantMountBrokerCallErrorV1::StaleKernel);
        }

        let last_boottime = &mut self.last_boottime_nanoseconds;
        let mut checked_clock = || {
            let sample = crate::service::trusted_paired_clock_sample()?;
            if sample.host_boot_id() != protected_boot_id
                || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
            {
                return Err(MountError::Fence(
                    "broker-session kernel boot changed before Mount effect",
                ));
            }
            *last_boottime = Some(sample.boottime_nanoseconds());
            Ok(sample)
        };
        let response = self.broker.apply_mount(
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            &mut checked_clock,
        )?;
        let mut digest = Sha256::new();
        digest.update(b"aos-sandbox-mount-broker-observation-v1\0");
        digest.update(request_id);
        digest.update(request_body_digest.as_bytes());
        digest.update(Sha256::digest(&response));
        Ok(DormantMountBrokerObservationV1 {
            request_id,
            response,
            commitment: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }

    fn consume_authenticated_inventory(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1> {
        let current_boot_id = KernelBootId::current()
            .map_err(|_| DormantMountBrokerCallErrorV1::StaleKernel)?
            .into_bytes();
        if current_boot_id != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantMountBrokerCallErrorV1::StaleKernel);
        }

        let sample = crate::service::trusted_paired_clock_sample()?;
        if sample.host_boot_id() != protected_boot_id
            || self
                .last_boottime_nanoseconds
                .is_some_and(|floor| sample.boottime_nanoseconds() < floor)
        {
            return Err(DormantMountBrokerCallErrorV1::StaleKernel);
        }
        self.last_boottime_nanoseconds = Some(sample.boottime_nanoseconds());
        let response = match method {
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES => {
                let header = decode_mount_inventory_request(
                    request_body,
                    peer,
                    policy,
                    sample.boottime_nanoseconds(),
                )
                .map_err(|_| DormantMountBrokerCallErrorV1::StaleKernel)?;
                if header.request_id() != &request_id
                    || header.protocol_version() != protocol_version
                {
                    return Err(DormantMountBrokerCallErrorV1::StaleKernel);
                }
                self.broker.inventory_resources()?
            }
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS => {
                let header = decode_destination_slot_inventory_request(
                    request_body,
                    peer,
                    policy,
                    sample.boottime_nanoseconds(),
                )
                .map_err(|_| DormantMountBrokerCallErrorV1::StaleKernel)?;
                if header.request_id() != &request_id
                    || header.protocol_version() != protocol_version
                {
                    return Err(DormantMountBrokerCallErrorV1::StaleKernel);
                }
                self.broker.inventory_destination_slots()?
            }
            _ => return Err(DormantMountBrokerCallErrorV1::StaleKernel),
        };

        let mut digest = Sha256::new();
        digest.update(b"aos-sandbox-mount-broker-observation-v1\0");
        digest.update((method as i32).to_be_bytes());
        digest.update(request_id);
        digest.update(request_body_digest.as_bytes());
        digest.update(Sha256::digest(&response));
        Ok(DormantMountBrokerObservationV1 {
            request_id,
            response,
            commitment: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }

    fn consume_authenticated_destination_slot(
        &mut self,
        method: BrokerMethod,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1> {
        if method != BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
            || KernelBootId::current()
                .map_err(|_| DormantMountBrokerCallErrorV1::StaleKernel)?
                .into_bytes()
                != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantMountBrokerCallErrorV1::StaleKernel);
        }

        let last_boottime = &mut self.last_boottime_nanoseconds;
        let checked_clock = || {
            let sample = crate::service::trusted_paired_clock_sample()?;
            if sample.host_boot_id() != protected_boot_id
                || last_boottime.is_some_and(|floor| sample.boottime_nanoseconds() < floor)
            {
                return Err(MountError::Fence(
                    "broker-session kernel boot changed before Mount destination-slot effect",
                ));
            }
            *last_boottime = Some(sample.boottime_nanoseconds());
            Ok(sample)
        };
        let response = self.broker.apply_destination_slot(
            request_body,
            artifacts,
            protocol_version,
            peer,
            policy,
            checked_clock,
        )?;
        let mut digest = Sha256::new();
        digest.update(b"aos-sandbox-mount-broker-observation-v1\0");
        digest.update((method as i32).to_be_bytes());
        digest.update(request_id);
        digest.update(request_body_digest.as_bytes());
        digest.update(Sha256::digest(&response));
        Ok(DormantMountBrokerObservationV1 {
            request_id,
            response,
            commitment: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }

    fn consume_authenticated_catalog_preparation(
        &mut self,
        request_body: &[u8],
        request_id: [u8; 16],
        request_body_digest: ObjectDigest,
        scope: ObservedMountScope,
        peer: PeerCredentials,
        policy: PeerPolicy,
        protocol_version: ProtocolVersion,
        protected_boot_id: [u8; 16],
    ) -> Result<DormantMountBrokerObservationV1, DormantMountBrokerCallErrorV1> {
        if KernelBootId::current()
            .map_err(|_| DormantMountBrokerCallErrorV1::StaleKernel)?
            .into_bytes()
            != protected_boot_id
            || ObjectDigest::from_bytes(Sha256::digest(request_body).into()) != request_body_digest
        {
            return Err(DormantMountBrokerCallErrorV1::StaleKernel);
        }
        let sample = crate::service::trusted_paired_clock_sample()?;
        if sample.host_boot_id() != protected_boot_id
            || self
                .last_boottime_nanoseconds
                .is_some_and(|floor| sample.boottime_nanoseconds() < floor)
        {
            return Err(DormantMountBrokerCallErrorV1::StaleKernel);
        }
        self.last_boottime_nanoseconds = Some(sample.boottime_nanoseconds());
        let preparation = decode_mount_catalog_preparation(
            request_body,
            peer,
            policy,
            sample.boottime_nanoseconds(),
        )
        .map_err(|_| DormantMountBrokerCallErrorV1::StaleKernel)?;
        if preparation.header().request_id() != &request_id
            || preparation.header().protocol_version() != protocol_version
        {
            return Err(DormantMountBrokerCallErrorV1::StaleKernel);
        }
        let response = self.broker.prepare_catalog(&preparation, scope)?;
        let mut digest = Sha256::new();
        digest.update(b"aos-sandbox-mount-broker-observation-v1\0");
        digest.update((BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG as i32).to_be_bytes());
        digest.update(request_id);
        digest.update(request_body_digest.as_bytes());
        digest.update(Sha256::digest(&response));
        Ok(DormantMountBrokerObservationV1 {
            request_id,
            response,
            commitment: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }
}
