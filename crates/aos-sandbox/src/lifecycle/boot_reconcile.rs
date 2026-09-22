//! LIFE-06 complete boot inventory aggregation and exact recovery planning.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, InventoryRuntimeResponse, InventoryStorageResourcesResponse, RuntimeState,
    StorageLifecycleInventoryRecord, StorageLifecycleTransitionRecord,
};
use aos_sandbox_core::{ObjectDigest, OperationId, ResourceId, SandboxId};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use buffa::Message as _;
#[cfg(target_os = "linux")]
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

#[cfg(target_os = "linux")]
const BROKER_SESSION_MANIFEST_BYTES: usize = 920;
#[cfg(target_os = "linux")]
const CLIENT_RECORD_PIN_OFFSET: usize = 184 + (2 * 184);

use super::{
    CurrentLifecycleBootInventoryV1, CurrentLifecycleEffectV1, CurrentLifecycleOperationV1,
    LifecycleBootInventoryV1, LifecycleDeletionActionV1, LifecycleDeletionObservationV1,
    LifecycleEffectDomainV1, LifecycleEffectObservationV1, LifecyclePhase6ErrorV1,
    LifecycleResourceV1,
};

/// Names one mandatory LIFE-06 inventory domain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleBootDomainV1 {
    /// Runtime processes and live incarnations.
    Runtime = 1,
    /// Mount namespaces and attachment custody.
    Mount = 2,
    /// Datasets, snapshots, holds, and clones.
    Storage = 3,
    /// Network namespaces and endpoint allocations.
    Network = 4,
    /// Cache publications, leases, and pins.
    Cache = 5,
    /// Incomplete resumable snapshot transfers.
    Transfer = 6,
}

/// Selects one fixed controller-side broker endpoint during boot genesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleBootBootstrapEndpointV1 {
    /// The fixed controller-to-Host authenticated endpoint.
    Host = 1,
    /// The fixed controller-to-Storage authenticated endpoint.
    Storage = 2,
    /// The fixed controller-to-Mount authenticated endpoint.
    Mount = 3,
    /// The fixed controller-to-Network authenticated endpoint.
    Network = 4,
}

impl LifecycleBootBootstrapEndpointV1 {
    #[cfg(target_os = "linux")]
    const fn protected_root(self) -> &'static str {
        match self {
            Self::Host => "/var/lib/aos/sandboxd/broker-session/host",
            Self::Storage => "/var/lib/aos/sandboxd/broker-session/storage",
            Self::Mount => "/var/lib/aos/sandboxd/broker-session/mount",
            Self::Network => "/var/lib/aos/sandboxd/broker-session/network",
        }
    }

    const fn method(self) -> BrokerMethod {
        match self {
            Self::Host => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            Self::Storage => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            Self::Mount => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES,
            Self::Network => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        }
    }
}

/// Carries a protected lifecycle challenge for boot publication or recheck.
///
/// The type has no public constructor. It is minted only while the requested
/// lifecycle owner binds it to the current operation projection and kernel
/// boot. It grants no append authority by itself.
#[derive(Clone, Copy)]
pub struct LifecycleBootInventoryBootstrapChallengeV1 {
    nonce: [u8; 32],
    operation: OperationId,
    operation_record: super::LifecycleRecordDigestV1,
    projection_root: ObjectDigest,
    host_boot: [u8; 16],
}

impl LifecycleBootInventoryBootstrapChallengeV1 {
    pub(super) fn from_protected_absence(
        nonce: [u8; 32],
        operation: OperationId,
        operation_record: super::LifecycleRecordDigestV1,
        projection_root: ObjectDigest,
        host_boot: [u8; 16],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if nonce == [0; 32] || host_boot == [0; 16] {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            nonce,
            operation,
            operation_record,
            projection_root,
            host_boot,
        })
    }

    /// Returns the current kernel boot bound by the protected challenge.
    #[must_use]
    pub const fn host_boot(&self) -> [u8; 16] {
        self.host_boot
    }

    /// Derives the exact endpoint-specific message that protected BSA signs.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the outcomes are an exact
    /// adjacent pair for the endpoint selected by `endpoint`.
    pub fn endpoint_signing_message(
        &self,
        endpoint: LifecycleBootBootstrapEndpointV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<[u8; 32], LifecyclePhase6ErrorV1> {
        let (initial_commitment, current_commitment) = match endpoint {
            LifecycleBootBootstrapEndpointV1::Host => {
                let initial = LifecycleAuthenticatedRuntimeInventoryV1::from_authenticated_outcome(
                    initial,
                    self.host_boot,
                )?;
                let current = LifecycleAuthenticatedRuntimeInventoryV1::from_authenticated_outcome(
                    current,
                    self.host_boot,
                )?;
                initial.require_current_successor(&current)?;
                (initial.commitment(), current.commitment())
            }
            LifecycleBootBootstrapEndpointV1::Storage => {
                let initial =
                    LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(initial)?;
                let current =
                    LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(current)?;
                initial.require_current_successor(&current)?;
                (initial.commitment(), current.commitment())
            }
            LifecycleBootBootstrapEndpointV1::Mount | LifecycleBootBootstrapEndpointV1::Network => {
                let initial =
                    LifecycleAuthenticatedBrokerDomainInventoryV1::from_authenticated_outcome(
                        endpoint,
                        initial,
                        self.host_boot,
                    )?;
                let current =
                    LifecycleAuthenticatedBrokerDomainInventoryV1::from_authenticated_outcome(
                        endpoint,
                        current,
                        self.host_boot,
                    )?;
                initial.require_current_successor(&current)?;
                (initial.commitment(), current.commitment())
            }
        };
        if initial.method() != endpoint.method() || current.method() != endpoint.method() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.boot-bootstrap-attestation.v1\0")
            .chain_update([endpoint as u8])
            .chain_update(self.nonce)
            .chain_update(self.operation.as_bytes())
            .chain_update(self.operation_record.digest().as_bytes())
            .chain_update(self.projection_root.as_bytes())
            .chain_update(self.host_boot)
            .chain_update(Sha256::digest(initial.canonical_packet()))
            .chain_update(Sha256::digest(current.canonical_packet()))
            .chain_update(initial_commitment.as_bytes())
            .chain_update(current_commitment.as_bytes())
            .finalize()
            .into())
    }

    /// Derives a signed message for one exact adjacent Storage state change.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless both outcomes are complete
    /// Storage inventories from one session with exact next traffic sequences
    /// and unchanged catalog generation/source.
    pub fn storage_transition_signing_message(
        &self,
        previous: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<[u8; 32], LifecyclePhase6ErrorV1> {
        let previous_packet_digest = Sha256::digest(previous.canonical_packet());
        let current_packet_digest = Sha256::digest(current.canonical_packet());
        let previous =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(previous)?;
        let current =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(current)?;
        let expected_client = previous
            .client_generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_broker = previous
            .broker_generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_catalog = previous
            .generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if current.session != previous.session
            || current.client_generation != expected_client
            || current.broker_generation != expected_broker
            || current.generation != expected_catalog
            || current.source != previous.source
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.boot-storage-transition-attestation.v1\0")
            .chain_update(self.nonce)
            .chain_update(self.operation.as_bytes())
            .chain_update(self.operation_record.digest().as_bytes())
            .chain_update(self.projection_root.as_bytes())
            .chain_update(self.host_boot)
            .chain_update(previous_packet_digest)
            .chain_update(current_packet_digest)
            .chain_update(previous.commitment.as_bytes())
            .chain_update(current.commitment.as_bytes())
            .finalize()
            .into())
    }

    /// Derives a challenge-bound message for one Storage Apply and readback.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the second outcome is a
    /// canonical complete Storage inventory in the Apply session.
    pub fn storage_effect_signing_message(
        &self,
        apply: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<[u8; 32], LifecyclePhase6ErrorV1> {
        let inventory_value =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(inventory)?;
        if ObjectDigest::from_bytes(apply.request().session_binding()) != inventory_value.session()
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.boot-storage-effect-attestation.v1\0")
            .chain_update(self.nonce)
            .chain_update(self.operation.as_bytes())
            .chain_update(self.operation_record.digest().as_bytes())
            .chain_update(self.projection_root.as_bytes())
            .chain_update(self.host_boot)
            .chain_update(Sha256::digest(apply.canonical_packet()))
            .chain_update(Sha256::digest(inventory.canonical_packet()))
            .finalize()
            .into())
    }

    /// Derives the fixed-endpoint signature message for a Mount or Network effect.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the exact lifecycle request,
    /// successful result, and immediately adjacent complete inventory agree.
    pub fn broker_effect_signing_message(
        &self,
        endpoint: LifecycleBootBootstrapEndpointV1,
        effect: &CurrentLifecycleEffectV1<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<[u8; 32], LifecyclePhase6ErrorV1> {
        if endpoint == LifecycleBootBootstrapEndpointV1::Storage {
            if effect.domain() != LifecycleEffectDomainV1::Storage
                || effect.operation() != self.operation
            {
                return Err(LifecyclePhase6ErrorV1::StaleAuthority);
            }
            let authenticated = effect.authenticated_broker_effect(outcome.request())?;
            authenticated.require_storage_readback_handoff(outcome, inventory)?;
            return self.storage_effect_signing_message(outcome, inventory);
        }
        let expected_domain = match endpoint {
            LifecycleBootBootstrapEndpointV1::Host => LifecycleEffectDomainV1::Runtime,
            LifecycleBootBootstrapEndpointV1::Mount => LifecycleEffectDomainV1::Mount,
            LifecycleBootBootstrapEndpointV1::Network => LifecycleEffectDomainV1::Network,
            LifecycleBootBootstrapEndpointV1::Storage => {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        };
        if effect.domain() != expected_domain || effect.operation() != self.operation {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let authenticated = effect.authenticated_broker_effect(outcome.request())?;
        authenticated.require_broker_readback_handoff(outcome, inventory)?;
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.boot-domain-effect-attestation.v1\0")
            .chain_update([endpoint as u8])
            .chain_update(self.nonce)
            .chain_update(self.operation.as_bytes())
            .chain_update(self.operation_record.digest().as_bytes())
            .chain_update(self.projection_root.as_bytes())
            .chain_update(self.host_boot)
            .chain_update(effect.canonical_body())
            .chain_update(Sha256::digest(outcome.canonical_packet()))
            .chain_update(Sha256::digest(inventory.canonical_packet()))
            .finalize()
            .into())
    }

    pub(super) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(super) const fn operation_record(&self) -> super::LifecycleRecordDigestV1 {
        self.operation_record
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }
}

/// Retains one complete fixed-session Mount or Network physical inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAuthenticatedBrokerDomainInventoryV1 {
    endpoint: LifecycleBootBootstrapEndpointV1,
    host_boot: [u8; 16],
    session: ObjectDigest,
    client_sequence: u64,
    broker_sequence: u64,
    generation: u64,
    source: ObjectDigest,
    entries: Vec<LifecycleBootDomainEntryV1>,
    commitment: ObjectDigest,
}

impl LifecycleAuthenticatedBrokerDomainInventoryV1 {
    fn from_authenticated_outcome(
        endpoint: LifecycleBootBootstrapEndpointV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        host_boot: [u8; 16],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if !matches!(
            endpoint,
            LifecycleBootBootstrapEndpointV1::Mount | LifecycleBootBootstrapEndpointV1::Network
        ) || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || outcome.method() != endpoint.method()
            || host_boot == [0; 16]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        };
        let (generation, source, mut entries) = match endpoint {
            LifecycleBootBootstrapEndpointV1::Mount => {
                let inventory = aos_sandbox_protocol::decode_mount_inventory_response(
                    exact_body,
                    aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES,
                )
                .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
                if inventory.kernel_boot_id() != &host_boot {
                    return Err(LifecyclePhase6ErrorV1::StaleAuthority);
                }
                let entries = inventory
                    .mounts()
                    .iter()
                    .map(|mount| LifecycleBootDomainEntryV1 {
                        resource: LifecycleResourceV1::Attachment(ResourceId::from_bytes(
                            *mount.recipe().attachment_id(),
                        )),
                        identity: ObjectDigest::from_bytes(*mount.mount_handle()),
                    })
                    .collect::<Vec<_>>();
                (
                    inventory.journal_sequence(),
                    ObjectDigest::from_bytes(Sha256::digest(exact_body).into()),
                    entries,
                )
            }
            LifecycleBootBootstrapEndpointV1::Network => {
                let inventory = aos_sandbox_protocol::decode_network_resource_inventory_response(
                    exact_body,
                    aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES,
                )
                .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
                if inventory.kernel_boot_id() != &host_boot {
                    return Err(LifecyclePhase6ErrorV1::StaleAuthority);
                }
                let entries = inventory
                    .networks()
                    .iter()
                    .map(|network| LifecycleBootDomainEntryV1 {
                        resource: LifecycleResourceV1::Sandbox(SandboxId::from_bytes(
                            *network.fence().sandbox_id(),
                        )),
                        identity: ObjectDigest::from_bytes(*network.resource_digest()),
                    })
                    .collect::<Vec<_>>();
                (
                    inventory.catalog_generation(),
                    ObjectDigest::from_bytes(Sha256::digest(exact_body).into()),
                    entries,
                )
            }
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        let session = ObjectDigest::from_bytes(outcome.request().session_binding());
        let client_sequence = outcome.request().client_sequence();
        let broker_sequence = outcome.broker_sequence();
        entries.sort_unstable();
        if generation == 0
            || session.as_bytes() == &[0; 32]
            || client_sequence == 0
            || broker_sequence == 0
            || entries.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !entries.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.complete-broker-domain-inventory.v1\0")
            .chain_update([endpoint as u8])
            .chain_update(host_boot)
            .chain_update(generation.to_be_bytes())
            .chain_update(source.as_bytes())
            .chain_update((entries.len() as u32).to_be_bytes());
        for entry in &entries {
            hasher = hasher
                .chain_update([entry.resource.code()])
                .chain_update(entry.resource.as_bytes())
                .chain_update(entry.identity.as_bytes());
        }
        Ok(Self {
            endpoint,
            host_boot,
            session,
            client_sequence,
            broker_sequence,
            generation,
            source,
            entries,
            commitment: ObjectDigest::from_bytes(hasher.finalize().into()),
        })
    }

    fn require_current_successor(&self, current: &Self) -> Result<(), LifecyclePhase6ErrorV1> {
        let client_sequence = self
            .client_sequence
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let broker_sequence = self
            .broker_sequence
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if current.endpoint != self.endpoint
            || current.host_boot != self.host_boot
            || current.session != self.session
            || current.client_sequence != client_sequence
            || current.broker_sequence != broker_sequence
            || current.generation != self.generation
            || current.source != self.source
            || current.entries != self.entries
            || current.commitment != self.commitment
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(())
    }

    /// Returns the fixed broker endpoint that authenticated this inventory.
    #[must_use]
    pub const fn endpoint(&self) -> LifecycleBootBootstrapEndpointV1 {
        self.endpoint
    }

    /// Borrows the complete stable-sorted physical rows, including empty state.
    #[must_use]
    pub fn entries(&self) -> &[LifecycleBootDomainEntryV1] {
        &self.entries
    }

    /// Returns the exact whole-inventory commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Carries a fixed-endpoint Mount or Network pair for boot genesis.
pub struct LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1 {
    initial: LifecycleAuthenticatedBrokerDomainInventoryV1,
    current: LifecycleAuthenticatedBrokerDomainInventoryV1,
    operation: OperationId,
    operation_record: super::LifecycleRecordDigestV1,
    projection_root: ObjectDigest,
    host_boot: [u8; 16],
}

impl LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1 {
    /// Verifies a fixed-endpoint challenge signature over an adjacent pair.
    ///
    /// # Errors
    ///
    /// Returns an error unless Mount or Network authenticated the exact pair.
    #[cfg(target_os = "linux")]
    pub fn from_fixed_endpoint_attestation(
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: LifecycleBootBootstrapEndpointV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        signature: [u8; 64],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(endpoint, initial, current)?;
        verify_fixed_bootstrap_signature(endpoint, &message, signature)?;
        let initial = LifecycleAuthenticatedBrokerDomainInventoryV1::from_authenticated_outcome(
            endpoint,
            initial,
            challenge.host_boot(),
        )?;
        let current = LifecycleAuthenticatedBrokerDomainInventoryV1::from_authenticated_outcome(
            endpoint,
            current,
            challenge.host_boot(),
        )?;
        initial.require_current_successor(&current)?;
        Ok(Self {
            initial,
            current,
            operation: challenge.operation(),
            operation_record: challenge.operation_record(),
            projection_root: challenge.projection_root(),
            host_boot: challenge.host_boot(),
        })
    }

    pub(crate) const fn binding(
        &self,
    ) -> (
        OperationId,
        super::LifecycleRecordDigestV1,
        ObjectDigest,
        [u8; 16],
    ) {
        (
            self.operation,
            self.operation_record,
            self.projection_root,
            self.host_boot,
        )
    }

    pub(crate) const fn initial(&self) -> &LifecycleAuthenticatedBrokerDomainInventoryV1 {
        &self.initial
    }

    pub(crate) const fn current(&self) -> &LifecycleAuthenticatedBrokerDomainInventoryV1 {
        &self.current
    }
}

/// Carries a boot-root-bound adjacent Mount or Network currentness pair.
pub struct LifecycleAuthenticatedBrokerDomainInventorySuccessorV1 {
    initial: LifecycleAuthenticatedBrokerDomainInventoryV1,
    current: LifecycleAuthenticatedBrokerDomainInventoryV1,
    operation: OperationId,
    projection_root: ObjectDigest,
}

impl LifecycleAuthenticatedBrokerDomainInventorySuccessorV1 {
    /// Verifies a boot-root-bound fixed-endpoint adjacent inventory pair.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign root, endpoint, state, or sequence.
    #[cfg(target_os = "linux")]
    pub fn from_fixed_endpoint_attestation(
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
        endpoint: LifecycleBootBootstrapEndpointV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        signature: [u8; 64],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let bootstrap = LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1::from_fixed_endpoint_attestation(
            challenge,
            endpoint,
            initial,
            current,
            signature,
        )?;
        let expected = match endpoint {
            LifecycleBootBootstrapEndpointV1::Mount => boot.inventory().domains().mounts(),
            LifecycleBootBootstrapEndpointV1::Network => boot.inventory().domains().network(),
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        if bootstrap.initial.commitment() != expected
            || challenge.operation() != boot.inventory().operation()
            || challenge.operation_record() != boot.inventory().operation_record()
            || challenge.projection_root() != boot.projection_root()
            || challenge.host_boot() != boot.inventory().host_boot()
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(Self {
            initial: bootstrap.initial,
            current: bootstrap.current,
            operation: boot.inventory().operation(),
            projection_root: boot.projection_root(),
        })
    }

    /// Borrows the boot-root-anchored inventory.
    #[must_use]
    pub const fn initial(&self) -> &LifecycleAuthenticatedBrokerDomainInventoryV1 {
        &self.initial
    }

    /// Borrows the immediately rechecked inventory.
    #[must_use]
    pub const fn current(&self) -> &LifecycleAuthenticatedBrokerDomainInventoryV1 {
        &self.current
    }

    pub(crate) const fn boot_binding(&self) -> (OperationId, ObjectDigest) {
        (self.operation, self.projection_root)
    }
}

/// Names every physical object family required in a complete Storage snapshot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleStorageInventoryKindV1 {
    /// A mutable dataset, including a launchable workspace root.
    Dataset = 1,
    /// An immutable dataset snapshot.
    Snapshot = 2,
    /// A clone and its origin correlation.
    Clone = 3,
    /// A durable hold on an exact snapshot.
    Hold = 4,
    /// Dataset quota and reservation state.
    Quota = 5,
}

/// Identifies one exact object in a complete Storage-owner readback.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleStorageInventoryEntryV1 {
    kind: LifecycleStorageInventoryKindV1,
    resource: LifecycleResourceV1,
    effect_subject: ObjectDigest,
    effect_request: ObjectDigest,
    lifecycle_operation: Option<OperationId>,
    hold_id: Option<ResourceId>,
    identity: ObjectDigest,
}

impl LifecycleStorageInventoryEntryV1 {
    fn from_authenticated_record(
        record: &StorageLifecycleInventoryRecord,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let kind = storage_inventory_kind(record.kind)?;
        let resource = storage_resource(record.resource_kind, &record.resource_id)?;
        let effect_subject = exact_digest(&record.effect_subject)?;
        let effect_request = exact_digest(&record.effect_request)?;
        let lifecycle_operation = optional_operation(&record.lifecycle_operation)?;
        let hold_id = optional_resource(&record.hold_id)?;
        let identity = exact_digest(&record.identity)?;
        if resource.as_bytes() == &[0; 16]
            || effect_subject.as_bytes() == &[0; 32]
            || effect_request.as_bytes() == &[0; 32]
            || lifecycle_operation.is_some_and(|operation| operation.as_bytes() == &[0; 16])
            || hold_id.is_some_and(|hold| hold.as_bytes() == &[0; 16])
            || identity.as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            kind,
            resource,
            effect_subject,
            effect_request,
            lifecycle_operation,
            hold_id,
            identity,
        })
    }

    /// Returns the exact Storage object family.
    #[must_use]
    pub const fn kind(self) -> LifecycleStorageInventoryKindV1 {
        self.kind
    }

    /// Returns the semantic resource correlated by protected lifecycle intent.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the complete physical-row identity.
    #[must_use]
    pub const fn identity(self) -> ObjectDigest {
        self.identity
    }

    /// Returns the exact physical handle used by the creating effect.
    #[must_use]
    pub const fn effect_subject(self) -> ObjectDigest {
        self.effect_subject
    }

    /// Returns the exact creating request commitment.
    #[must_use]
    pub const fn effect_request(self) -> ObjectDigest {
        self.effect_request
    }

    /// Returns the exact hold identity for Hold rows.
    #[must_use]
    pub const fn hold_id(self) -> Option<ResourceId> {
        self.hold_id
    }

    /// Returns the protected Storage operation correlation when one exists.
    #[must_use]
    pub const fn lifecycle_operation(self) -> Option<OperationId> {
        self.lifecycle_operation
    }
}

/// Names an exact catalog transition retained with a Storage-owner readback.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleStorageTransitionKindV1 {
    /// Creates one workspace dataset.
    CreateWorkspace = 1,
    /// Creates one immutable snapshot.
    Snapshot = 2,
    /// Acquires one exact hold.
    HoldSnapshot = 3,
    /// Releases one exact hold.
    ReleaseHold = 4,
    /// Creates one clone.
    Clone = 5,
    /// Changes one dataset quota.
    SetQuota = 6,
    /// Destroys one dataset.
    DestroyDataset = 7,
    /// Destroys one snapshot.
    DestroySnapshot = 8,
}

/// Retains authenticated action identity without treating history as physical state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleStorageTransitionEntryV1 {
    kind: LifecycleStorageTransitionKindV1,
    resource: LifecycleResourceV1,
    effect_subject: ObjectDigest,
    effect_request: ObjectDigest,
    hold_id: Option<ResourceId>,
    identity: ObjectDigest,
}

impl LifecycleStorageTransitionEntryV1 {
    fn from_authenticated_record(
        record: &StorageLifecycleTransitionRecord,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let kind = storage_transition_kind(record.kind)?;
        let resource = storage_resource(record.resource_kind, &record.resource_id)?;
        let effect_subject = exact_digest(&record.effect_subject)?;
        let effect_request = exact_digest(&record.effect_request)?;
        let hold_id = optional_resource(&record.hold_id)?;
        let identity = exact_digest(&record.identity)?;
        if resource.as_bytes() == &[0; 16]
            || effect_subject.as_bytes() == &[0; 32]
            || effect_request.as_bytes() == &[0; 32]
            || hold_id.is_some_and(|hold| hold.as_bytes() == &[0; 16])
            || identity.as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            kind,
            resource,
            effect_subject,
            effect_request,
            hold_id,
            identity,
        })
    }

    /// Returns the exact committed catalog action.
    #[must_use]
    pub const fn kind(self) -> LifecycleStorageTransitionKindV1 {
        self.kind
    }

    /// Returns the semantic resource named by the transition.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the complete transition identity.
    #[must_use]
    pub const fn identity(self) -> ObjectDigest {
        self.identity
    }

    /// Returns the physical handle named by the transition.
    #[must_use]
    pub const fn effect_subject(self) -> ObjectDigest {
        self.effect_subject
    }

    /// Returns the exact request commitment retained with the transition.
    #[must_use]
    pub const fn effect_request(self) -> ObjectDigest {
        self.effect_request
    }

    /// Returns the exact hold identity for hold transitions.
    #[must_use]
    pub const fn hold_id(self) -> Option<ResourceId> {
        self.hold_id
    }
}

/// Retains a complete authenticated Storage physical inventory, including empty families.
#[derive(Debug, Eq, PartialEq)]
pub struct LifecycleAuthenticatedStorageInventoryV1 {
    generation: u64,
    source: ObjectDigest,
    session: ObjectDigest,
    request: ObjectDigest,
    client_generation: u64,
    broker_generation: u64,
    entries: Vec<LifecycleStorageInventoryEntryV1>,
    transitions: Vec<LifecycleStorageTransitionEntryV1>,
    commitment: ObjectDigest,
}

/// Carries an exact adjacent pair of protected Storage inventory outcomes.
pub struct LifecycleAuthenticatedStorageInventorySuccessorV1 {
    initial: LifecycleAuthenticatedStorageInventoryV1,
    current: LifecycleAuthenticatedStorageInventoryV1,
    boot_operation: OperationId,
    boot_projection: ObjectDigest,
}

/// Carries a fixed-endpoint authenticated Storage pair for first-root publication.
pub struct LifecycleAuthenticatedStorageInventoryBootstrapV1 {
    initial: LifecycleAuthenticatedStorageInventoryV1,
    current: LifecycleAuthenticatedStorageInventoryV1,
    operation: OperationId,
    operation_record: super::LifecycleRecordDigestV1,
    projection_root: ObjectDigest,
    host_boot: [u8; 16],
}

impl LifecycleAuthenticatedStorageInventoryBootstrapV1 {
    /// Verifies a challenge-bound signature from the fixed Storage client endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the adjacent inventory pair,
    /// challenge, fixed protected manifest, and client-record signature agree.
    #[cfg(target_os = "linux")]
    pub fn from_fixed_endpoint_attestation(
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        signature: [u8; 64],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Storage,
            initial,
            current,
        )?;
        verify_fixed_bootstrap_signature(
            LifecycleBootBootstrapEndpointV1::Storage,
            &message,
            signature,
        )?;
        let initial =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(initial)?;
        let current =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(current)?;
        initial.require_current_successor(&current)?;
        Ok(Self {
            initial,
            current,
            operation: challenge.operation(),
            operation_record: challenge.operation_record(),
            projection_root: challenge.projection_root(),
            host_boot: challenge.host_boot(),
        })
    }

    pub(crate) const fn initial(&self) -> &LifecycleAuthenticatedStorageInventoryV1 {
        &self.initial
    }

    pub(crate) const fn current(&self) -> &LifecycleAuthenticatedStorageInventoryV1 {
        &self.current
    }

    pub(crate) const fn binding(
        &self,
    ) -> (
        OperationId,
        super::LifecycleRecordDigestV1,
        ObjectDigest,
        [u8; 16],
    ) {
        (
            self.operation,
            self.operation_record,
            self.projection_root,
            self.host_boot,
        )
    }
}

impl LifecycleAuthenticatedStorageInventorySuccessorV1 {
    /// Verifies a fixed-endpoint-attested adjacent Storage inventory pair.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the pair retains the same
    /// protected catalog, complete five-family rows, and session while both
    /// broker traffic sequences advance by exactly one.
    #[cfg(target_os = "linux")]
    pub fn from_fixed_endpoint_attestation(
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &super::CurrentLifecycleBootInventoryV1<'_>,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        signature: [u8; 64],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Storage,
            initial,
            current,
        )?;
        verify_fixed_bootstrap_signature(
            LifecycleBootBootstrapEndpointV1::Storage,
            &message,
            signature,
        )?;
        let initial =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(initial)?;
        let current =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(current)?;
        initial.require_current_successor(&current)?;
        if initial.commitment() != boot.inventory().domains().storage()
            || challenge.operation() != boot.inventory().operation()
            || challenge.operation_record() != boot.inventory().operation_record()
            || challenge.projection_root() != boot.projection_root()
            || challenge.host_boot() != boot.inventory().host_boot()
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(Self {
            initial,
            current,
            boot_operation: boot.inventory().operation(),
            boot_projection: boot.projection_root(),
        })
    }

    /// Borrows the boot-root-bound pre-effect Storage inventory.
    #[must_use]
    pub const fn initial(&self) -> &LifecycleAuthenticatedStorageInventoryV1 {
        &self.initial
    }

    /// Borrows the exact adjacent current Storage inventory.
    #[must_use]
    pub const fn current(&self) -> &LifecycleAuthenticatedStorageInventoryV1 {
        &self.current
    }

    pub(crate) const fn boot_binding(&self) -> (OperationId, ObjectDigest) {
        (self.boot_operation, self.boot_projection)
    }
}

/// Retains one authenticated complete Storage inventory produced by an exchange.
pub struct LifecycleAuthenticatedStorageReadbackV1 {
    pub(super) inventory: LifecycleAuthenticatedStorageInventoryV1,
    pub(super) effect_request: ObjectDigest,
    pub(super) effect_result: ObjectDigest,
    pub(super) session: ObjectDigest,
}

/// Carries one exact protected Storage inventory change for an atomic group.
pub struct LifecycleAuthenticatedAtomicStorageSuccessorV1 {
    current: LifecycleAuthenticatedStorageInventoryV1,
    program: ObjectDigest,
    observation: ObjectDigest,
}

impl LifecycleAuthenticatedAtomicStorageSuccessorV1 {
    /// Verifies an exact adjacent whole-inventory transition for one group.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the predecessor is anchored by
    /// the current boot root and the successor contains exactly one committed
    /// Snapshot transition for every protected plan member.
    #[cfg(target_os = "linux")]
    pub fn from_fixed_endpoint_attestation(
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &super::CurrentLifecycleBootInventoryV1<'_>,
        plan: &super::LifecycleAtomicDatasetSnapshotPlanV1,
        program: ObjectDigest,
        observation: ObjectDigest,
        previous: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        signature: [u8; 64],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if program.as_bytes() == &[0; 32] || observation.as_bytes() == &[0; 32] {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let message = challenge.storage_transition_signing_message(previous, current)?;
        verify_fixed_bootstrap_signature(
            LifecycleBootBootstrapEndpointV1::Storage,
            &message,
            signature,
        )?;
        if challenge.operation() != boot.inventory().operation()
            || challenge.operation_record() != boot.inventory().operation_record()
            || challenge.projection_root() != boot.projection_root()
            || challenge.host_boot() != boot.inventory().host_boot()
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let previous =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(previous)?;
        let current =
            LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(current)?;
        let expected_client = previous
            .client_generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_broker = previous
            .broker_generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_catalog = previous
            .generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if previous.commitment != boot.inventory().domains().storage()
            || previous.commitment != plan.inventory()
            || previous.generation != plan.inventory_generation()
            || previous.source != plan.inventory_source()
            || current.session != previous.session
            || current.client_generation != expected_client
            || current.broker_generation != expected_broker
            || current.generation != expected_catalog
            || current.source != previous.source
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let snapshot = LifecycleResourceV1::Snapshot(plan.snapshot());
        let matching = current
            .transitions
            .iter()
            .filter(|transition| {
                transition.kind == LifecycleStorageTransitionKindV1::Snapshot
                    && transition.resource == snapshot
                    && transition.effect_request == plan.effect_commitment()
            })
            .collect::<Vec<_>>();
        if matching.len() != plan.members().len()
            || plan.members().iter().any(|member| {
                let expected_identity = ObjectDigest::from_bytes(
                    Sha256::new()
                        .chain_update(b"aos.sandbox.storage.atomic-snapshot-transition.v1\0")
                        .chain_update(program.as_bytes())
                        .chain_update(member.physical_identity().as_bytes())
                        .chain_update([3])
                        .chain_update(observation.as_bytes())
                        .finalize()
                        .into(),
                );
                !matching.iter().any(|transition| {
                    transition.effect_subject == member.storage_handle()
                        && transition.identity == expected_identity
                }) || !current.entries.iter().any(|entry| {
                    entry.kind == LifecycleStorageInventoryKindV1::Snapshot
                        && entry.resource == snapshot
                        && entry.effect_request == plan.effect_commitment()
                        && entry.lifecycle_operation == Some(plan.operation())
                        && entry.effect_subject == member.storage_handle()
                })
            })
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        Ok(Self {
            current,
            program,
            observation,
        })
    }

    pub(super) const fn current(&self) -> &LifecycleAuthenticatedStorageInventoryV1 {
        &self.current
    }

    pub(super) const fn program(&self) -> ObjectDigest {
        self.program
    }

    pub(super) const fn observation(&self) -> ObjectDigest {
        self.observation
    }
}

impl LifecycleAuthenticatedStorageReadbackV1 {
    /// Decodes a complete Storage readback bound to one current lifecycle effect.
    ///
    /// The effect capability is minted only while the protected lifecycle
    /// journal owns the exact persisted request. Consequently an arbitrary
    /// self-signed broker exchange cannot be retyped as lifecycle evidence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless `apply` is the exact compiled
    /// lifecycle effect and `outcome` is its immediate same-session complete
    /// Storage inventory successor.
    #[cfg(target_os = "linux")]
    pub fn from_fixed_endpoint_attestation(
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        effect: &super::LifecycleAuthenticatedBrokerEffectV1,
        apply: &AuthenticatedBrokerMethodOutcomeV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        signature: [u8; 64],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let message = challenge.storage_effect_signing_message(apply, outcome)?;
        verify_fixed_bootstrap_signature(
            LifecycleBootBootstrapEndpointV1::Storage,
            &message,
            signature,
        )?;
        if challenge.operation() != effect.lifecycle_request().operation() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        effect.require_storage_readback_handoff(apply, outcome)?;
        Ok(Self {
            inventory: LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(
                outcome,
            )?,
            effect_request: ObjectDigest::from_bytes(apply.request().signed_request_digest()),
            effect_result: ObjectDigest::from_bytes(apply.semantic_commitment()),
            session: ObjectDigest::from_bytes(apply.request().session_binding()),
        })
    }

    pub(crate) const fn inventory(&self) -> &LifecycleAuthenticatedStorageInventoryV1 {
        &self.inventory
    }
}

impl LifecycleAuthenticatedStorageInventoryV1 {
    /// Decodes a complete provider-signed Storage inventory outcome.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the signed outcome contains a
    /// canonical, bounded, complete five-family projection.
    pub(crate) fn from_authenticated_outcome(
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || outcome.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        };
        aos_sandbox_protocol::decode_storage_resource_inventory_response(
            exact_body,
            aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES,
        )
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        let inventory = InventoryStorageResourcesResponse::decode_from_slice(exact_body)
            .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        if inventory.encode_to_vec().as_slice() != exact_body.as_slice() {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let generation = inventory.catalog_generation;
        let source = exact_digest(&inventory.lifecycle_source)?;
        let session = ObjectDigest::from_bytes(outcome.request().session_binding());
        let request = ObjectDigest::from_bytes(outcome.request().signed_request_digest());
        let client_generation = outcome.request().client_sequence();
        let broker_generation = outcome.broker_sequence();
        let mut entries = inventory
            .lifecycle_resources
            .iter()
            .map(LifecycleStorageInventoryEntryV1::from_authenticated_record)
            .collect::<Result<Vec<_>, _>>()?;
        let mut transitions = inventory
            .lifecycle_transitions
            .iter()
            .map(LifecycleStorageTransitionEntryV1::from_authenticated_record)
            .collect::<Result<Vec<_>, _>>()?;
        if generation == 0
            || source.as_bytes() == &[0; 32]
            || session.as_bytes() == &[0; 32]
            || request.as_bytes() == &[0; 32]
            || client_generation == 0
            || broker_generation == 0
            || entries.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
            || transitions.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        entries.sort_unstable();
        if !entries.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        transitions.sort_unstable();
        if !transitions.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.complete-storage-inventory.v1\0")
            .chain_update(generation.to_be_bytes())
            .chain_update(source.as_bytes());
        // All five family discriminators are committed even when their count
        // is zero; absence is therefore authenticated rather than inferred
        // from the launch-only workspace list.
        for kind in [
            LifecycleStorageInventoryKindV1::Dataset,
            LifecycleStorageInventoryKindV1::Snapshot,
            LifecycleStorageInventoryKindV1::Clone,
            LifecycleStorageInventoryKindV1::Hold,
            LifecycleStorageInventoryKindV1::Quota,
        ] {
            let family = entries.iter().filter(|entry| entry.kind == kind);
            let count = family.clone().count();
            hasher = hasher
                .chain_update([kind as u8])
                .chain_update((count as u32).to_be_bytes());
            for entry in family {
                hasher = hasher
                    .chain_update([entry.resource.code()])
                    .chain_update(entry.resource.as_bytes())
                    .chain_update(entry.effect_subject.as_bytes())
                    .chain_update(entry.effect_request.as_bytes())
                    .chain_update(
                        entry
                            .lifecycle_operation
                            .map_or([0; 16], OperationId::into_bytes),
                    )
                    .chain_update(entry.hold_id.map_or([0; 16], |id| id.into_bytes()))
                    .chain_update(entry.identity.as_bytes());
            }
        }
        hasher = hasher.chain_update((transitions.len() as u32).to_be_bytes());
        for transition in &transitions {
            hasher = hasher
                .chain_update([transition.kind as u8, transition.resource.code()])
                .chain_update(transition.resource.as_bytes())
                .chain_update(transition.effect_subject.as_bytes())
                .chain_update(transition.effect_request.as_bytes())
                .chain_update(transition.hold_id.map_or([0; 16], |id| id.into_bytes()))
                .chain_update(transition.identity.as_bytes());
        }
        Ok(Self {
            generation,
            source,
            session,
            request,
            client_generation,
            broker_generation,
            entries,
            transitions,
            commitment: ObjectDigest::from_bytes(hasher.finalize().into()),
        })
    }

    /// Returns the protected source generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact whole-inventory commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }

    /// Borrows every Storage row in canonical family/resource/identity order.
    #[must_use]
    pub fn entries(&self) -> &[LifecycleStorageInventoryEntryV1] {
        &self.entries
    }

    /// Borrows every authenticated transition in canonical order.
    #[must_use]
    pub fn transitions(&self) -> &[LifecycleStorageTransitionEntryV1] {
        &self.transitions
    }

    /// Returns the protected Storage catalog source commitment.
    #[must_use]
    pub const fn source(&self) -> ObjectDigest {
        self.source
    }

    /// Returns the authenticated provider-session binding.
    #[must_use]
    pub const fn session(&self) -> ObjectDigest {
        self.session
    }

    pub(crate) const fn client_generation(&self) -> u64 {
        self.client_generation
    }

    pub(crate) const fn broker_generation(&self) -> u64 {
        self.broker_generation
    }

    pub(crate) fn require_current_successor(
        &self,
        successor: &Self,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let expected_client_generation = self
            .client_generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_broker_generation = self
            .broker_generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if successor.session != self.session
            || successor.request == self.request
            || successor.client_generation != expected_client_generation
            || successor.broker_generation != expected_broker_generation
            || successor.generation != self.generation
            || successor.source != self.source
            || successor.entries != self.entries
            || successor.transitions != self.transitions
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(())
    }

    pub(crate) fn recheck_launch_snapshot(
        &self,
        launch: &crate::DurableStorageResourceInventorySnapshotV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let launch_rows = launch
            .inventory()
            .workspaces()
            .iter()
            .map(|workspace| {
                (
                    LifecycleResourceV1::Sandbox(SandboxId::from_bytes(
                        *workspace.fence().sandbox_id(),
                    )),
                    ObjectDigest::from_bytes(*workspace.workspace_handle()),
                )
            })
            .collect::<BTreeSet<_>>();
        let physical_rows = self
            .entries
            .iter()
            .filter_map(|entry| match (entry.kind, entry.resource) {
                (LifecycleStorageInventoryKindV1::Dataset, LifecycleResourceV1::Sandbox(_)) => {
                    Some((entry.resource, entry.effect_subject))
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if launch.inventory().catalog_generation() != self.generation
            || launch_rows != physical_rows
            || self.session.as_bytes() == &[0; 32]
            || self.commitment.as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

fn storage_inventory_kind(
    value: u32,
) -> Result<LifecycleStorageInventoryKindV1, LifecyclePhase6ErrorV1> {
    match value {
        1 => Ok(LifecycleStorageInventoryKindV1::Dataset),
        2 => Ok(LifecycleStorageInventoryKindV1::Snapshot),
        3 => Ok(LifecycleStorageInventoryKindV1::Clone),
        4 => Ok(LifecycleStorageInventoryKindV1::Hold),
        5 => Ok(LifecycleStorageInventoryKindV1::Quota),
        _ => Err(LifecyclePhase6ErrorV1::InvalidInput),
    }
}

fn storage_transition_kind(
    value: u32,
) -> Result<LifecycleStorageTransitionKindV1, LifecyclePhase6ErrorV1> {
    match value {
        1 => Ok(LifecycleStorageTransitionKindV1::CreateWorkspace),
        2 => Ok(LifecycleStorageTransitionKindV1::Snapshot),
        3 => Ok(LifecycleStorageTransitionKindV1::HoldSnapshot),
        4 => Ok(LifecycleStorageTransitionKindV1::ReleaseHold),
        5 => Ok(LifecycleStorageTransitionKindV1::Clone),
        6 => Ok(LifecycleStorageTransitionKindV1::SetQuota),
        7 => Ok(LifecycleStorageTransitionKindV1::DestroyDataset),
        8 => Ok(LifecycleStorageTransitionKindV1::DestroySnapshot),
        _ => Err(LifecyclePhase6ErrorV1::InvalidInput),
    }
}

fn storage_resource(
    kind: u32,
    bytes: &[u8],
) -> Result<LifecycleResourceV1, LifecyclePhase6ErrorV1> {
    let identity = exact_array::<16>(bytes)?;
    LifecycleResourceV1::from_code(
        u8::try_from(kind).map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?,
        identity,
    )
    .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
}

fn exact_digest(bytes: &[u8]) -> Result<ObjectDigest, LifecyclePhase6ErrorV1> {
    let value = ObjectDigest::from_bytes(exact_array(bytes)?);
    (value.as_bytes() != &[0; 32])
        .then_some(value)
        .ok_or(LifecyclePhase6ErrorV1::InvalidInput)
}

#[cfg(target_os = "linux")]
pub(super) fn verify_fixed_bootstrap_signature(
    endpoint: LifecycleBootBootstrapEndpointV1,
    message: &[u8; 32],
    signature: [u8; 64],
) -> Result<(), LifecyclePhase6ErrorV1> {
    let directory = rustix::fs::open(
        endpoint.protected_root(),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    require_protected_bootstrap_directory(&directory)?;
    let manifest = rustix::fs::openat(
        &directory,
        "broker-session-manifest",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let metadata = require_protected_bootstrap_manifest(&manifest)?;
    let before = read_exact_bootstrap_manifest(&manifest)?;
    let key = bootstrap_manifest_client_record_key(endpoint, &before)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key).map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    verifying_key
        .verify(message, &Signature::from_bytes(&signature))
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let after = read_exact_bootstrap_manifest(&manifest)?;
    let metadata_after =
        rustix::fs::fstat(&manifest).map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    if before != after || !same_bootstrap_manifest_metadata(&metadata, &metadata_after) {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    require_protected_bootstrap_directory(&directory)
}

#[cfg(target_os = "linux")]
fn same_bootstrap_manifest_metadata(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

#[cfg(target_os = "linux")]
fn require_protected_bootstrap_directory(
    directory: &OwnedFd,
) -> Result<(), LifecyclePhase6ErrorV1> {
    let stat = rustix::fs::fstat(directory).map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o500
    {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_protected_bootstrap_manifest(
    manifest: &OwnedFd,
) -> Result<rustix::fs::Stat, LifecyclePhase6ErrorV1> {
    let stat = rustix::fs::fstat(manifest).map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o400
        || stat.st_size != BROKER_SESSION_MANIFEST_BYTES as i64
    {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(stat)
}

#[cfg(target_os = "linux")]
fn read_exact_bootstrap_manifest(
    manifest: &OwnedFd,
) -> Result<[u8; BROKER_SESSION_MANIFEST_BYTES], LifecyclePhase6ErrorV1> {
    let mut bytes = [0; BROKER_SESSION_MANIFEST_BYTES];
    let mut offset = 0;
    while offset < bytes.len() {
        let read = rustix::io::pread(manifest, &mut bytes[offset..], offset as u64)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        if read == 0 {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        offset += read;
    }
    let mut trailing = [0];
    if rustix::io::pread(
        manifest,
        &mut trailing,
        BROKER_SESSION_MANIFEST_BYTES as u64,
    )
    .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
        != 0
    {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn bootstrap_manifest_client_record_key(
    endpoint: LifecycleBootBootstrapEndpointV1,
    manifest: &[u8; BROKER_SESSION_MANIFEST_BYTES],
) -> Result<[u8; 32], LifecyclePhase6ErrorV1> {
    let pin = &manifest[CLIENT_RECORD_PIN_OFFSET..CLIENT_RECORD_PIN_OFFSET + 184];
    let expected_protocol = match endpoint {
        LifecycleBootBootstrapEndpointV1::Host => 1,
        LifecycleBootBootstrapEndpointV1::Storage => 2,
        LifecycleBootBootstrapEndpointV1::Mount => 3,
        LifecycleBootBootstrapEndpointV1::Network => 4,
    };
    let key: [u8; 32] = pin[120..152]
        .try_into()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let public_key_digest: [u8; 32] = pin[80..112]
        .try_into()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    let computed_public_key_digest: [u8; 32] = Sha256::digest(key).into();
    if &manifest[..8] != b"AOSBSC01"
        || manifest[8..10] != 1_u16.to_be_bytes()
        || manifest[10] != expected_protocol
        || manifest[11] != 1
        || pin[112] != 3
        || pin[113..120].iter().any(|byte| *byte != 0)
        || pin[152..160] == [0; 8]
        || pin[160..168] == [0; 8]
        || pin[168] != 0
        || pin[169] != 0
        || pin[170..184].iter().any(|byte| *byte != 0)
        || key == [0; 32]
        || public_key_digest != computed_public_key_digest
    {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(key)
}

fn optional_operation(bytes: &[u8]) -> Result<Option<OperationId>, LifecyclePhase6ErrorV1> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let value = OperationId::from_bytes(exact_array(bytes)?);
    (value.as_bytes() != &[0; 16])
        .then_some(Some(value))
        .ok_or(LifecyclePhase6ErrorV1::InvalidInput)
}

fn optional_resource(bytes: &[u8]) -> Result<Option<ResourceId>, LifecyclePhase6ErrorV1> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let value = ResourceId::from_bytes(exact_array(bytes)?);
    (value.as_bytes() != &[0; 16])
        .then_some(Some(value))
        .ok_or(LifecyclePhase6ErrorV1::InvalidInput)
}

fn exact_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], LifecyclePhase6ErrorV1> {
    bytes
        .try_into()
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)
}

/// Identifies one row in a complete authenticated domain inventory.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleBootDomainEntryV1 {
    resource: LifecycleResourceV1,
    identity: ObjectDigest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LifecyclePhysicalBootRowV1 {
    domain: LifecycleBootDomainV1,
    entry: LifecycleBootDomainEntryV1,
    authority: Option<OperationId>,
    quarantined: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LifecycleBootResourceKeyV1 {
    domain: LifecycleBootDomainV1,
    resource: LifecycleResourceV1,
}

/// Retains fresh complete physical rows independently from semantic desire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleFreshPhysicalInventoryV1 {
    domains: [ObjectDigest; 6],
    runtime_generation: u64,
    runtime_source: ObjectDigest,
    runtime_session: ObjectDigest,
    rows: Vec<LifecyclePhysicalBootRowV1>,
    commitment: ObjectDigest,
}

impl LifecycleFreshPhysicalInventoryV1 {
    fn new(
        domains: [ObjectDigest; 6],
        runtime_generation: u64,
        runtime_source: ObjectDigest,
        runtime_session: ObjectDigest,
        mut rows: Vec<LifecyclePhysicalBootRowV1>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if domains.iter().any(|value| value.as_bytes() == &[0; 32])
            || runtime_generation == 0
            || runtime_source.as_bytes() == &[0; 32]
            || runtime_session.as_bytes() == &[0; 32]
            || rows.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        rows.sort_unstable();
        if !rows.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let commitment = physical_inventory_commitment(domains, &rows);
        Ok(Self {
            domains,
            runtime_generation,
            runtime_source,
            runtime_session,
            rows,
            commitment,
        })
    }

    pub(super) fn resolve_storage_resources(
        &mut self,
        desired: &LifecycleAuthenticatedBootDesiredV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        for row in &mut self.rows {
            if row.domain != LifecycleBootDomainV1::Storage || !row.quarantined {
                continue;
            }
            let Some(authority) = row.authority else {
                continue;
            };
            if let Some(resource) = desired.storage_resources.get(&authority) {
                row.entry.resource = *resource;
                row.quarantined = false;
            }
        }
        self.rows.sort_unstable();
        if !self.rows.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        self.commitment = physical_inventory_commitment(self.domains, &self.rows);
        Ok(())
    }

    pub(super) fn storage_authorities(&self) -> BTreeSet<OperationId> {
        self.rows
            .iter()
            .filter(|row| row.domain == LifecycleBootDomainV1::Storage && row.quarantined)
            .filter_map(|row| row.authority)
            .collect()
    }

    pub(super) const fn domain_commitments(&self) -> [ObjectDigest; 6] {
        self.domains
    }

    pub(super) fn resources(&self) -> Result<Vec<LifecycleResourceV1>, LifecyclePhase6ErrorV1> {
        let mut resources = self
            .rows
            .iter()
            .map(|row| row.entry.resource)
            .collect::<Vec<_>>();
        resources.sort_unstable();
        resources.dedup();
        if resources.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(resources)
    }
}

fn physical_inventory_commitment(
    domains: [ObjectDigest; 6],
    rows: &[LifecyclePhysicalBootRowV1],
) -> ObjectDigest {
    let mut hasher =
        Sha256::new().chain_update(b"aos.sandbox.lifecycle.fresh-physical-inventory.v1\0");
    for domain in domains {
        hasher = hasher.chain_update(domain.as_bytes());
    }
    hasher = hasher.chain_update((rows.len() as u64).to_be_bytes());
    for row in rows {
        hasher = hasher
            .chain_update([row.domain as u8, row.entry.resource.code()])
            .chain_update(row.entry.resource.as_bytes())
            .chain_update(row.entry.identity.as_bytes())
            .chain_update(row.authority.map_or([0; 16], OperationId::into_bytes))
            .chain_update([u8::from(row.quarantined)]);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleAuthenticatedBootDesiredV1 {
    resources: Vec<LifecycleBootResourceKeyV1>,
    storage_resources: BTreeMap<OperationId, LifecycleResourceV1>,
    commitment: ObjectDigest,
}

impl LifecycleAuthenticatedBootDesiredV1 {
    pub(super) fn from_protected_operation(
        operation: &super::LifecycleOperationV1,
        operation_record: super::LifecycleRecordDigestV1,
        projection_root: ObjectDigest,
        fence_resource: LifecycleResourceV1,
        storage_resources: BTreeMap<OperationId, LifecycleResourceV1>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let mut resources = Vec::new();
        for resource in operation
            .expectations()
            .iter()
            .filter(|expectation| {
                matches!(
                    expectation.expected(),
                    super::ResourceExpectedStateV1::Present { .. }
                )
            })
            .map(super::ResourceExpectationV1::resource)
            .chain([fence_resource])
        {
            resources.extend(
                desired_domains(resource)
                    .map(|domain| LifecycleBootResourceKeyV1 { domain, resource }),
            );
        }
        resources.sort_unstable();
        resources.dedup();
        if resources.is_empty() || resources.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        if storage_resources.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
            || storage_resources
                .keys()
                .any(|operation| operation.as_bytes() == &[0; 16])
            || storage_resources
                .values()
                .any(|resource| !matches!(resource, LifecycleResourceV1::Snapshot(_)))
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.authenticated-boot-desired.v1\0")
            .chain_update(operation.operation_id().as_bytes())
            .chain_update(operation_record.digest().as_bytes())
            .chain_update(projection_root.as_bytes())
            .chain_update((resources.len() as u64).to_be_bytes());
        for resource in &resources {
            hasher = hasher
                .chain_update([resource.domain as u8, resource.resource.code()])
                .chain_update(resource.resource.as_bytes());
        }
        hasher = hasher.chain_update((storage_resources.len() as u64).to_be_bytes());
        for (operation, resource) in &storage_resources {
            hasher = hasher
                .chain_update(operation.as_bytes())
                .chain_update([resource.code()])
                .chain_update(resource.as_bytes());
        }
        Ok(Self {
            resources,
            storage_resources,
            commitment: ObjectDigest::from_bytes(hasher.finalize().into()),
        })
    }

    pub(super) fn logical_resources(&self) -> Vec<LifecycleResourceV1> {
        let mut resources = self
            .resources
            .iter()
            .map(|key| key.resource)
            .collect::<Vec<_>>();
        resources.sort_unstable();
        resources.dedup();
        resources
    }
}

impl LifecycleBootDomainEntryV1 {
    pub(crate) fn from_protected_cache(
        resource: LifecycleResourceV1,
        identity: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if resource.as_bytes() == &[0; 16] || identity.as_bytes() == &[0; 32] {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self { resource, identity })
    }

    /// Returns the logical resource represented by this physical row.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the complete protected row commitment used for stable order.
    #[must_use]
    pub const fn identity(self) -> ObjectDigest {
        self.identity
    }
}

/// Retains a complete authenticated Host runtime inventory, including empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAuthenticatedRuntimeInventoryV1 {
    host_boot: [u8; 16],
    session_binding: ObjectDigest,
    request: ObjectDigest,
    client_generation: u64,
    broker_sequence: u64,
    generation: u64,
    source: ObjectDigest,
    entries: Vec<LifecycleBootDomainEntryV1>,
    runtime_facts: Vec<LifecycleAuthenticatedRuntimeFactV1>,
    commitment: ObjectDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleAuthenticatedRuntimeFactV1 {
    sandbox: [u8; 16],
    incarnation: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    runtime_handle: ObjectDigest,
    state: RuntimeState,
    observation_sequence: u64,
}

/// Carries an exact adjacent pair of protected Host inventory outcomes.
pub struct LifecycleAuthenticatedRuntimeInventorySuccessorV1 {
    initial: LifecycleAuthenticatedRuntimeInventoryV1,
    current: LifecycleAuthenticatedRuntimeInventoryV1,
    boot_operation: OperationId,
    boot_projection: ObjectDigest,
}

/// Carries a fixed-endpoint authenticated Host pair for first-root publication.
pub struct LifecycleAuthenticatedRuntimeInventoryBootstrapV1 {
    initial: LifecycleAuthenticatedRuntimeInventoryV1,
    current: LifecycleAuthenticatedRuntimeInventoryV1,
    operation: OperationId,
    operation_record: super::LifecycleRecordDigestV1,
    projection_root: ObjectDigest,
    host_boot: [u8; 16],
}

impl LifecycleAuthenticatedRuntimeInventoryBootstrapV1 {
    /// Verifies a challenge-bound signature from the fixed Host client endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the adjacent inventory pair,
    /// challenge, fixed protected manifest, and client-record signature agree.
    #[cfg(target_os = "linux")]
    pub fn from_fixed_endpoint_attestation(
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        signature: [u8; 64],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            initial,
            current,
        )?;
        verify_fixed_bootstrap_signature(
            LifecycleBootBootstrapEndpointV1::Host,
            &message,
            signature,
        )?;
        let initial = LifecycleAuthenticatedRuntimeInventoryV1::from_authenticated_outcome(
            initial,
            challenge.host_boot(),
        )?;
        let current = LifecycleAuthenticatedRuntimeInventoryV1::from_authenticated_outcome(
            current,
            challenge.host_boot(),
        )?;
        initial.require_current_successor(&current)?;
        Ok(Self {
            initial,
            current,
            operation: challenge.operation(),
            operation_record: challenge.operation_record(),
            projection_root: challenge.projection_root(),
            host_boot: challenge.host_boot(),
        })
    }

    pub(crate) const fn initial(&self) -> &LifecycleAuthenticatedRuntimeInventoryV1 {
        &self.initial
    }

    pub(crate) const fn current(&self) -> &LifecycleAuthenticatedRuntimeInventoryV1 {
        &self.current
    }

    pub(crate) const fn binding(
        &self,
    ) -> (
        OperationId,
        super::LifecycleRecordDigestV1,
        ObjectDigest,
        [u8; 16],
    ) {
        (
            self.operation,
            self.operation_record,
            self.projection_root,
            self.host_boot,
        )
    }

    pub(crate) fn frozen_runtime_liveness(
        &self,
        fence: super::LiveRuntimeFenceV1,
    ) -> Result<ObjectDigest, LifecyclePhase6ErrorV1> {
        self.current.frozen_runtime_liveness(fence)
    }
}

impl LifecycleAuthenticatedRuntimeInventorySuccessorV1 {
    /// Verifies two exact adjacent Host inventory outcomes under one live boot.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless both outcomes are canonical
    /// Host inventories and the second advances both traffic sequences by
    /// exactly one without changing session, boot, or complete runtime rows.
    #[cfg(target_os = "linux")]
    pub fn from_fixed_endpoint_attestation(
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &super::CurrentLifecycleBootInventoryV1<'_>,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        host_boot: [u8; 16],
        signature: [u8; 64],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            initial,
            current,
        )?;
        verify_fixed_bootstrap_signature(
            LifecycleBootBootstrapEndpointV1::Host,
            &message,
            signature,
        )?;
        let initial = LifecycleAuthenticatedRuntimeInventoryV1::from_authenticated_outcome(
            initial, host_boot,
        )?;
        let current = LifecycleAuthenticatedRuntimeInventoryV1::from_authenticated_outcome(
            current, host_boot,
        )?;
        initial.require_current_successor(&current)?;
        if initial.commitment() != boot.inventory().domains().runtime()
            || host_boot != boot.inventory().host_boot()
            || challenge.operation() != boot.inventory().operation()
            || challenge.operation_record() != boot.inventory().operation_record()
            || challenge.projection_root() != boot.projection_root()
            || challenge.host_boot() != host_boot
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(Self {
            initial,
            current,
            boot_operation: boot.inventory().operation(),
            boot_projection: boot.projection_root(),
        })
    }

    pub(crate) const fn initial(&self) -> &LifecycleAuthenticatedRuntimeInventoryV1 {
        &self.initial
    }

    pub(crate) const fn current(&self) -> &LifecycleAuthenticatedRuntimeInventoryV1 {
        &self.current
    }

    pub(crate) const fn boot_binding(&self) -> (OperationId, ObjectDigest) {
        (self.boot_operation, self.boot_projection)
    }
}

impl LifecycleAuthenticatedRuntimeInventoryV1 {
    /// Decodes one completely authenticated Host InventoryRuntime success.
    ///
    /// Empty and multiple-runtime bodies remain explicit signed inventory
    /// states. Rows are retained in the Host protocol's strict handle order;
    /// no caller supplies identities, count, generation, or a root digest.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the outcome is the exact
    /// client-received Host inventory method with a canonical successful body.
    pub(crate) fn from_authenticated_outcome(
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        host_boot: [u8; 16],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        };
        let inventory = InventoryRuntimeResponse::decode_from_slice(exact_body)
            .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
        if inventory.encode_to_vec().as_slice() != exact_body.as_slice()
            || inventory.runtimes.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }

        let mut entries = Vec::new();
        let mut runtime_facts = Vec::new();
        entries
            .try_reserve_exact(inventory.runtimes.len())
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        runtime_facts
            .try_reserve_exact(inventory.runtimes.len())
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        for runtime in &inventory.runtimes {
            let fence = runtime
                .fence
                .as_option()
                .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
            let sandbox_bytes: [u8; 16] = fence
                .sandbox_id
                .as_slice()
                .try_into()
                .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
            let identity = ObjectDigest::from_bytes(
                runtime
                    .runtime_handle
                    .as_slice()
                    .try_into()
                    .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?,
            );
            entries.push(LifecycleBootDomainEntryV1 {
                resource: LifecycleResourceV1::Sandbox(SandboxId::from_bytes(sandbox_bytes)),
                identity,
            });
            runtime_facts.push(LifecycleAuthenticatedRuntimeFactV1 {
                sandbox: sandbox_bytes,
                incarnation: fence
                    .incarnation_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?,
                assignment_epoch: fence.assignment_epoch,
                desired_generation: fence.desired_generation,
                assignment_digest: fence
                    .assignment_digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?,
                runtime_handle: identity,
                state: runtime
                    .state
                    .as_known()
                    .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?,
                observation_sequence: runtime.observation_sequence,
            });
        }
        if !entries
            .windows(2)
            .all(|pair| pair[0].identity < pair[1].identity)
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let session_binding = ObjectDigest::from_bytes(outcome.request().session_binding());
        let request = ObjectDigest::from_bytes(outcome.request().signed_request_digest());
        let client_generation = outcome.request().client_sequence();
        // Host increments observation_sequence on every inventory call. The
        // physical-state source excludes that counter, while the adjacent pair
        // below verifies that it advanced. Other Host readers may interleave.
        let mut stable_inventory = inventory.clone();
        for runtime in &mut stable_inventory.runtimes {
            runtime.observation_sequence = 0;
        }
        let source =
            ObjectDigest::from_bytes(Sha256::digest(stable_inventory.encode_to_vec()).into());
        let mut generation_bytes = [0_u8; 8];
        generation_bytes.copy_from_slice(&source.as_bytes()[..8]);
        let generation = u64::from_be_bytes(generation_bytes).max(1);
        let broker_sequence = outcome.broker_sequence();
        if host_boot == [0; 16]
            || generation == 0
            || client_generation == 0
            || broker_sequence == 0
            || session_binding.as_bytes() == &[0; 32]
            || request.as_bytes() == &[0; 32]
            || source.as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let commitment = runtime_inventory_digest(
            host_boot,
            session_binding,
            request,
            client_generation,
            broker_sequence,
            generation,
            source,
            &entries,
        );
        Ok(Self {
            host_boot,
            session_binding,
            request,
            client_generation,
            broker_sequence,
            generation,
            source,
            entries,
            runtime_facts,
            commitment,
        })
    }

    fn frozen_runtime_liveness(
        &self,
        fence: super::LiveRuntimeFenceV1,
    ) -> Result<ObjectDigest, LifecyclePhase6ErrorV1> {
        let desired = fence.desired();
        let mut matching = self.runtime_facts.iter().filter(|runtime| {
            runtime.sandbox == *fence.sandbox().as_bytes()
                && runtime.incarnation == *fence.incarnation().as_bytes()
                && runtime.assignment_epoch == fence.assignment_epoch().get()
                && runtime.desired_generation == desired.expected_generation().get()
                && runtime.assignment_digest == *desired.resource_state().digest().as_bytes()
                && runtime.state == RuntimeState::RUNTIME_STATE_FROZEN
        });
        let runtime = matching
            .next()
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if matching.next().is_some() {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }

        Ok(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.authenticated-runtime-liveness.v1\0")
                .chain_update(self.source.as_bytes())
                .chain_update(runtime.runtime_handle.as_bytes())
                .finalize()
                .into(),
        ))
    }

    /// Returns the stable physical-state generation of this complete set.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrows all current runtimes in strict physical-identity order.
    #[must_use]
    pub fn entries(&self) -> &[LifecycleBootDomainEntryV1] {
        &self.entries
    }

    /// Returns the exact whole-inventory commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }

    pub(crate) const fn source(&self) -> ObjectDigest {
        self.source
    }

    pub(crate) fn recheck_boot(&self, host_boot: [u8; 16]) -> Result<(), LifecyclePhase6ErrorV1> {
        if host_boot != self.host_boot
            || self.commitment
                != runtime_inventory_digest(
                    self.host_boot,
                    self.session_binding,
                    self.request,
                    self.client_generation,
                    self.broker_sequence,
                    self.generation,
                    self.source,
                    &self.entries,
                )
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(())
    }

    pub(crate) fn require_current_successor(
        &self,
        successor: &Self,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let expected_client_generation = self
            .client_generation
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_broker_generation = self
            .broker_sequence
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if successor.host_boot != self.host_boot
            || successor.session_binding != self.session_binding
            || successor.client_generation != expected_client_generation
            || successor.broker_sequence != expected_broker_generation
            || successor.generation != self.generation
            || successor.source != self.source
            || successor.entries != self.entries
            || successor.runtime_facts.len() != self.runtime_facts.len()
            || !self
                .runtime_facts
                .iter()
                .zip(&successor.runtime_facts)
                .all(|(before, after)| {
                    before.sandbox == after.sandbox
                        && before.incarnation == after.incarnation
                        && before.assignment_epoch == after.assignment_epoch
                        && before.desired_generation == after.desired_generation
                        && before.assignment_digest == after.assignment_digest
                        && before.runtime_handle == after.runtime_handle
                        && before.state == after.state
                        && after.observation_sequence > before.observation_sequence
                })
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

fn runtime_inventory_digest(
    host_boot: [u8; 16],
    _session_binding: ObjectDigest,
    _request: ObjectDigest,
    _client_generation: u64,
    _broker_sequence: u64,
    generation: u64,
    source: ObjectDigest,
    entries: &[LifecycleBootDomainEntryV1],
) -> ObjectDigest {
    let domain = complete_domain_inventory_digest(
        LifecycleBootDomainV1::Runtime,
        generation,
        source,
        entries,
    );
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.runtime-inventory-state.v1\0")
            .chain_update(host_boot)
            .chain_update(generation.to_be_bytes())
            .chain_update(source.as_bytes())
            .chain_update(domain.as_bytes())
            .finalize()
            .into(),
    )
}

/// Retains the complete current protected transfer set, including empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAuthenticatedTransferInventoryV1 {
    generation: u64,
    source: ObjectDigest,
    entries: Vec<LifecycleBootDomainEntryV1>,
    commitment: ObjectDigest,
}

impl LifecycleAuthenticatedTransferInventoryV1 {
    pub(crate) fn from_protected_records(
        generation: u64,
        source: ObjectDigest,
        records: &[crate::multi_node::ProtectedMultiNodeCurrentRecordV1],
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if generation == 0
            || source.as_bytes() == &[0; 32]
            || records.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(records.len())
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        for protected in records {
            let record = protected.record().record();
            if record.domain() != crate::multi_node::MultiNodeJournalDomainV1::SnapshotTransfer {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
            entries.push(LifecycleBootDomainEntryV1 {
                resource: LifecycleResourceV1::Other(ResourceId::from_bytes(
                    *record.operation().as_bytes(),
                )),
                identity: record.digest(),
            });
        }
        entries.sort_unstable_by_key(|entry| entry.identity);
        if !entries
            .windows(2)
            .all(|pair| pair[0].identity < pair[1].identity)
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let commitment = complete_domain_inventory_digest(
            LifecycleBootDomainV1::Transfer,
            generation,
            source,
            &entries,
        );
        Ok(Self {
            generation,
            source,
            entries,
            commitment,
        })
    }

    /// Returns the protected-source generation owning this complete set.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrows all retained transfers in strict record-identity order.
    #[must_use]
    pub fn entries(&self) -> &[LifecycleBootDomainEntryV1] {
        &self.entries
    }

    /// Returns the exact whole-inventory commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }

    pub(crate) const fn source(&self) -> ObjectDigest {
        self.source
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn fresh_physical_inventory(
    runtime: &LifecycleAuthenticatedRuntimeInventoryV1,
    mounts: &LifecycleAuthenticatedBrokerDomainInventoryV1,
    storage: &LifecycleAuthenticatedStorageInventoryV1,
    network: &LifecycleAuthenticatedBrokerDomainInventoryV1,
    cache: &crate::cache_residency::CacheLifecycleBootInventoryV1,
    transfer: &LifecycleAuthenticatedTransferInventoryV1,
) -> Result<LifecycleFreshPhysicalInventoryV1, LifecyclePhase6ErrorV1> {
    let domains = [
        runtime.commitment(),
        mounts.commitment(),
        storage.commitment(),
        network.commitment(),
        cache.root(),
        transfer.commitment(),
    ];
    let mut rows = Vec::new();
    rows.try_reserve_exact(
        runtime
            .entries()
            .len()
            .saturating_add(mounts.entries().len())
            .saturating_add(storage.entries().len())
            .saturating_add(network.entries().len())
            .saturating_add(cache.entries().len())
            .saturating_add(transfer.entries().len()),
    )
    .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
    rows.extend(
        runtime
            .entries()
            .iter()
            .copied()
            .map(|entry| LifecyclePhysicalBootRowV1 {
                domain: LifecycleBootDomainV1::Runtime,
                entry,
                authority: None,
                quarantined: false,
            }),
    );
    if mounts.endpoint() != LifecycleBootBootstrapEndpointV1::Mount
        || network.endpoint() != LifecycleBootBootstrapEndpointV1::Network
    {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    rows.extend(
        mounts
            .entries()
            .iter()
            .copied()
            .map(|entry| LifecyclePhysicalBootRowV1 {
                domain: LifecycleBootDomainV1::Mount,
                entry,
                authority: None,
                quarantined: false,
            }),
    );
    for storage in storage.entries() {
        let identity = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.storage-physical-row.v1\0")
                .chain_update([storage.kind as u8])
                .chain_update(storage.identity.as_bytes())
                .finalize()
                .into(),
        );
        rows.push(LifecyclePhysicalBootRowV1 {
            domain: LifecycleBootDomainV1::Storage,
            entry: LifecycleBootDomainEntryV1 {
                resource: storage.resource,
                identity,
            },
            authority: storage.lifecycle_operation,
            quarantined: matches!(storage.resource, LifecycleResourceV1::Other(_)),
        });
    }
    rows.extend(
        network
            .entries()
            .iter()
            .copied()
            .map(|entry| LifecyclePhysicalBootRowV1 {
                domain: LifecycleBootDomainV1::Network,
                entry,
                authority: None,
                quarantined: false,
            }),
    );
    rows.extend(
        cache
            .entries()
            .iter()
            .copied()
            .map(|entry| LifecyclePhysicalBootRowV1 {
                domain: LifecycleBootDomainV1::Cache,
                entry,
                authority: None,
                quarantined: false,
            }),
    );
    rows.extend(
        transfer
            .entries()
            .iter()
            .copied()
            .map(|entry| LifecyclePhysicalBootRowV1 {
                domain: LifecycleBootDomainV1::Transfer,
                entry,
                authority: None,
                quarantined: false,
            }),
    );
    LifecycleFreshPhysicalInventoryV1::new(
        domains,
        runtime.generation,
        runtime.source,
        runtime.session_binding,
        rows,
    )
}

/// Binds one complete protected domain inventory to the aggregate record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleBootDomainInventoryV1 {
    domain: LifecycleBootDomainV1,
    commitment: ObjectDigest,
}

impl LifecycleBootDomainInventoryV1 {
    pub(crate) fn from_protected_current(
        domain: LifecycleBootDomainV1,
        commitment: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if commitment.as_bytes() == &[0; 32] {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self { domain, commitment })
    }

    /// Returns the protected inventory domain.
    #[must_use]
    pub const fn domain(self) -> LifecycleBootDomainV1 {
        self.domain
    }

    /// Returns the exact protected domain-inventory commitment.
    #[must_use]
    pub const fn commitment(self) -> ObjectDigest {
        self.commitment
    }
}

/// Borrows the closed six-domain inventory set from a fixed protected owner.
#[must_use = "boot-domain inventory authority must remain bound to its fixed owner"]
pub struct CurrentLifecycleBootDomainInventoriesV1<'current> {
    domains: [LifecycleBootDomainInventoryV1; 6],
    physical: LifecycleFreshPhysicalInventoryV1,
    desired: LifecycleAuthenticatedBootDesiredV1,
    operation: OperationId,
    operation_record: super::LifecycleRecordDigestV1,
    aggregate: ObjectDigest,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

/// Carries a consumed protected all-domain join into boot-root publication.
pub(crate) struct LifecycleBootInventoryRefreshSourceV1 {
    operation: OperationId,
    projection_root: ObjectDigest,
    physical: LifecycleFreshPhysicalInventoryV1,
}

/// Carries the first complete protected six-owner join into one-shot publication.
pub(crate) struct LifecycleBootInventoryBootstrapSourceV1 {
    challenge: LifecycleBootInventoryBootstrapChallengeV1,
    physical: LifecycleFreshPhysicalInventoryV1,
}

impl LifecycleBootInventoryBootstrapSourceV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_protected_join(
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        runtime: &LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
        mounts: &LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        storage: &LifecycleAuthenticatedStorageInventoryBootstrapV1,
        storage_launch: &crate::DurableStorageResourceInventorySnapshotV1,
        network: &LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        cache: &crate::cache_residency::CacheLifecycleBootInventoryV1,
        transfer: &LifecycleAuthenticatedTransferInventoryV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let challenge_binding = (
            challenge.operation(),
            challenge.operation_record(),
            challenge.projection_root(),
            challenge.host_boot(),
        );
        if runtime.binding() != challenge_binding
            || storage.binding() != challenge_binding
            || mounts.binding() != challenge_binding
            || network.binding() != challenge_binding
            || mounts.current().endpoint() != LifecycleBootBootstrapEndpointV1::Mount
            || network.current().endpoint() != LifecycleBootBootstrapEndpointV1::Network
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        runtime.current().recheck_boot(challenge.host_boot())?;
        storage.current().recheck_launch_snapshot(storage_launch)?;
        let physical = fresh_physical_inventory(
            runtime.current(),
            mounts.current(),
            storage.current(),
            network.current(),
            cache,
            transfer,
        )?;
        Ok(Self {
            challenge,
            physical,
        })
    }

    pub(crate) const fn challenge(&self) -> LifecycleBootInventoryBootstrapChallengeV1 {
        self.challenge
    }

    pub(super) fn into_physical(self) -> LifecycleFreshPhysicalInventoryV1 {
        self.physical
    }

    pub(crate) fn into_refresh_source(self) -> LifecycleBootInventoryRefreshSourceV1 {
        LifecycleBootInventoryRefreshSourceV1 {
            operation: self.challenge.operation(),
            projection_root: self.challenge.projection_root(),
            physical: self.physical,
        }
    }
}

impl LifecycleBootInventoryRefreshSourceV1 {
    pub(super) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }

    pub(super) fn into_physical(self) -> LifecycleFreshPhysicalInventoryV1 {
        self.physical
    }
}

impl<'current> CurrentLifecycleBootDomainInventoriesV1<'current> {
    pub(crate) const fn from_protected_current(
        domains: [LifecycleBootDomainInventoryV1; 6],
        physical: LifecycleFreshPhysicalInventoryV1,
        desired: LifecycleAuthenticatedBootDesiredV1,
        operation: OperationId,
        operation_record: super::LifecycleRecordDigestV1,
        aggregate: ObjectDigest,
        projection_root: ObjectDigest,
    ) -> Self {
        Self {
            domains,
            physical,
            desired,
            operation,
            operation_record,
            aggregate,
            projection_root,
            current: PhantomData,
        }
    }

    /// Borrows one fixed domain inventory by its closed discriminator.
    #[must_use]
    pub fn domain(&self, domain: LifecycleBootDomainV1) -> &LifecycleBootDomainInventoryV1 {
        &self.domains[usize::from(domain as u8 - 1)]
    }

    pub(crate) fn into_refresh_source(self) -> LifecycleBootInventoryRefreshSourceV1 {
        LifecycleBootInventoryRefreshSourceV1 {
            operation: self.operation,
            projection_root: self.projection_root,
            physical: self.physical,
        }
    }

    fn observe_from_protected_domain(
        &self,
        key: LifecycleBootResourceKeyV1,
        state: LifecycleBootResourceStateV1,
        observation: ObjectDigest,
    ) -> Result<LifecycleBootResourceObservationV1, LifecyclePhase6ErrorV1> {
        LifecycleBootResourceObservationV1::from_protected_inventory(
            key.resource,
            self.domain(key.domain),
            self.operation,
            self.operation_record,
            self.physical.commitment,
            self.desired.commitment,
            state,
            observation,
        )
    }

    /// Derives fail-closed observations for resources without a typed matcher.
    ///
    /// Every result is bound to this exact six-owner snapshot and selects
    /// `Quarantine`. No caller supplies a state or observation digest. Typed
    /// domain matchers may later replace individual quarantine rows, but an
    /// incomplete matcher can never silently select adoption or deletion.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless `inventory` is the exact
    /// operation-bound aggregate from which this six-owner set was issued.
    pub fn quarantine_unmatched(
        &self,
        inventory: &CurrentLifecycleBootInventoryV1<'_>,
    ) -> Result<Vec<LifecycleBootResourceObservationV1>, LifecyclePhase6ErrorV1> {
        self.require_inventory(inventory)?;
        let actual = physical_resources(&self.physical);
        let desired = &self.desired.resources;
        let missing_desired = desired
            .iter()
            .filter(|resource| !actual.contains_key(resource))
            .count();
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(actual.len().saturating_add(missing_desired))
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        let mut resources = Vec::new();
        resources
            .try_reserve_exact(actual.len().saturating_add(missing_desired))
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        resources.extend(actual.keys().copied());
        resources.extend(desired.iter().copied());
        resources.sort_unstable();
        resources.dedup();
        for resource in resources {
            let commitment = ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(b"aos.sandbox.lifecycle.unmatched-boot-resource.v1\0")
                    .chain_update(self.physical.commitment.as_bytes())
                    .chain_update(self.desired.commitment.as_bytes())
                    .chain_update([resource.domain as u8, resource.resource.code()])
                    .chain_update(resource.resource.as_bytes())
                    .finalize()
                    .into(),
            );
            observations.push(self.observe_from_protected_domain(
                resource,
                LifecycleBootResourceStateV1::UnknownOwnership,
                commitment,
            )?);
        }
        Ok(observations)
    }

    /// Classifies the complete observed set against protected desired state.
    ///
    /// The caller supplies neither classification nor evidence digest. The
    /// protected boot record supplies only semantic desired state. The actual
    /// set comes exclusively from the fresh six-domain physical join. Matching
    /// presence is adopted, desired absence is repaired, and every newly
    /// discovered physical resource is classified under its owning domain.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless `inventory` is the exact
    /// protected aggregate from which this six-owner set was issued.
    pub fn classify(
        &self,
        inventory: &CurrentLifecycleBootInventoryV1<'_>,
    ) -> Result<Vec<LifecycleBootResourceObservationV1>, LifecyclePhase6ErrorV1> {
        self.require_inventory(inventory)?;

        let actual = physical_resources(&self.physical);
        let desired = &self.desired.resources;
        let mut resources = Vec::new();
        resources
            .try_reserve_exact(actual.len().saturating_add(desired.len()))
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        resources.extend(actual.keys().copied());
        resources.extend(desired.iter().copied());
        resources.sort_unstable();
        resources.dedup();

        resources
            .into_iter()
            .map(|resource| {
                let observed = actual.get(&resource);
                let quarantined =
                    observed.is_some_and(|rows| rows.iter().any(|row| row.quarantined));
                let state = if quarantined {
                    LifecycleBootResourceStateV1::UnknownOwnership
                } else if desired.binary_search(&resource).is_ok() {
                    if observed.is_some() {
                        LifecycleBootResourceStateV1::DesiredPresent
                    } else {
                        LifecycleBootResourceStateV1::DesiredMissing
                    }
                } else if observed.is_some() {
                    LifecycleBootResourceStateV1::UndesiredPresent
                } else {
                    LifecycleBootResourceStateV1::UnknownOwnership
                };
                let observation = classified_observation_digest(
                    self.domain(resource.domain),
                    self.physical.commitment,
                    self.desired.commitment,
                    resource.resource,
                    state,
                    observed.map_or(&[], Vec::as_slice),
                );
                self.observe_from_protected_domain(resource, state, observation)
            })
            .collect()
    }

    /// Converts an authenticated post-effect domain readback into deletion evidence.
    ///
    /// Drain evidence additionally requires a fresh complete physical snapshot
    /// in which the target is absent; no caller-provided counters are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for a foreign operation, substituted
    /// domain/action/target, or a Drain target still present in any domain.
    pub fn observe_deletion_readback(
        &self,
        observation: LifecycleEffectObservationV1,
        action: LifecycleDeletionActionV1,
        resource: LifecycleResourceV1,
    ) -> Result<LifecycleDeletionObservationV1, LifecyclePhase6ErrorV1> {
        let request = observation.request();
        if request.operation() != self.operation
            || request.target() != *resource.as_bytes()
            || observation.inventory().as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        match action {
            LifecycleDeletionActionV1::Detach => {
                LifecycleDeletionObservationV1::from_mount_detach(observation, resource)
            }
            LifecycleDeletionActionV1::Drain => {
                if observation.inventory_generation() != self.physical.runtime_generation
                    || observation.inventory_source() != self.physical.runtime_source
                    || observation.inventory_session() != self.physical.runtime_session
                    || self.physical.rows.iter().any(|row| {
                        row.domain == LifecycleBootDomainV1::Runtime
                            && row.entry.resource == resource
                    })
                {
                    return Err(LifecyclePhase6ErrorV1::InvalidTransition);
                }
                let drain = ObjectDigest::from_bytes(
                    Sha256::new()
                        .chain_update(b"aos.sandbox.lifecycle.deletion-drain-readback.v1\0")
                        .chain_update(self.physical.commitment.as_bytes())
                        .chain_update(observation.inventory().as_bytes())
                        .chain_update(observation.result().as_bytes())
                        .chain_update([resource.code()])
                        .chain_update(resource.as_bytes())
                        .finalize()
                        .into(),
                );
                LifecycleDeletionObservationV1::from_runtime_drain(observation, resource, drain)
            }
            LifecycleDeletionActionV1::ReleasePins => {
                LifecycleDeletionObservationV1::from_cache_release(observation, resource)
            }
            LifecycleDeletionActionV1::DestroyStorage => {
                LifecycleDeletionObservationV1::from_storage_destroy(observation, resource)
            }
            LifecycleDeletionActionV1::RevokeAdmission
            | LifecycleDeletionActionV1::Reap
            | LifecycleDeletionActionV1::Deferred
            | LifecycleDeletionActionV1::Complete => Err(LifecyclePhase6ErrorV1::InvalidTransition),
        }
    }

    fn require_inventory(
        &self,
        inventory: &CurrentLifecycleBootInventoryV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        if inventory.inventory().operation() != self.operation
            || inventory.inventory().operation_record() != self.operation_record
            || inventory.inventory().inventory().digest() != self.aggregate
            || inventory.projection_root() != self.projection_root
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(())
    }

    pub(super) const fn domains(&self) -> &[LifecycleBootDomainInventoryV1; 6] {
        &self.domains
    }

    pub(super) const fn aggregate(&self) -> ObjectDigest {
        self.aggregate
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }

    pub(crate) const fn boot_binding(&self) -> (OperationId, ObjectDigest) {
        (self.operation, self.projection_root)
    }
}

/// Classifies observed state relative to protected desired state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleBootResourceStateV1 {
    /// Desired and observed state agree exactly.
    DesiredPresent = 1,
    /// Desired state exists but the resource is missing or stale.
    DesiredMissing = 2,
    /// No desired owner remains for an observed resource.
    UndesiredPresent = 3,
    /// Ownership or observation is ambiguous and must fail closed.
    UnknownOwnership = 4,
}

/// Retains one resource observation authenticated by a domain inventory.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleBootResourceObservationV1 {
    resource: LifecycleResourceV1,
    domain: LifecycleBootDomainV1,
    state: LifecycleBootResourceStateV1,
    operation: OperationId,
    operation_record: super::LifecycleRecordDigestV1,
    domain_inventory: ObjectDigest,
    aggregate_inventory: ObjectDigest,
    desired_inventory: ObjectDigest,
    observation: ObjectDigest,
}

impl LifecycleBootResourceObservationV1 {
    fn from_protected_inventory(
        resource: LifecycleResourceV1,
        domain: &LifecycleBootDomainInventoryV1,
        operation: OperationId,
        operation_record: super::LifecycleRecordDigestV1,
        aggregate_inventory: ObjectDigest,
        desired_inventory: ObjectDigest,
        state: LifecycleBootResourceStateV1,
        observation: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.as_bytes() == &[0; 32]
            || aggregate_inventory.as_bytes() == &[0; 32]
            || desired_inventory.as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            resource,
            domain: domain.domain,
            state,
            operation,
            operation_record,
            domain_inventory: domain.commitment,
            aggregate_inventory,
            desired_inventory,
            observation,
        })
    }

    /// Returns the authenticated observed resource.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the protected inventory domain that supplied the observation.
    #[must_use]
    pub const fn domain(self) -> LifecycleBootDomainV1 {
        self.domain
    }

    /// Returns the derived desired/observed-state classification.
    #[must_use]
    pub const fn state(self) -> LifecycleBootResourceStateV1 {
        self.state
    }
}

/// Selects the exact recovery action derived from desired and observed state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleBootRecoveryActionV1 {
    /// Adopts exact matching state without a lower-domain mutation.
    Adopt = 1,
    /// Recreates a missing or stale runtime.
    RepairRuntime = 2,
    /// Reconstructs a missing mount or attachment.
    RepairMount = 3,
    /// Repairs missing storage custody.
    RepairStorage = 4,
    /// Repairs missing network state.
    RepairNetwork = 5,
    /// Reconciles cache publication and pin state.
    ReconcileCache = 6,
    /// Resumes a durable incomplete snapshot transfer.
    ResumeTransfer = 7,
    /// Stops an undesired runtime.
    StopRuntime = 8,
    /// Detaches an undesired mount.
    DetachMount = 9,
    /// Reaps undesired storage only through lifecycle deletion.
    ReapStorage = 10,
    /// Releases an undesired network allocation.
    ReleaseNetwork = 11,
    /// Releases an undesired cache publication or pin.
    ReleaseCache = 12,
    /// Cancels or reaps an undesired transfer.
    CancelTransfer = 13,
    /// Quarantines ambiguous state without adopting or deleting it.
    Quarantine = 14,
}

/// Binds one recovery action to the exact protected observation that selected it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBootRecoveryStepV1 {
    resource: LifecycleResourceV1,
    domain: LifecycleBootDomainV1,
    action: LifecycleBootRecoveryActionV1,
    observation: ObjectDigest,
}

impl LifecycleBootRecoveryStepV1 {
    /// Returns the exact derived recovery action.
    #[must_use]
    pub const fn action(self) -> LifecycleBootRecoveryActionV1 {
        self.action
    }

    /// Returns the typed resource affected by the recovery action.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }
}

/// Retains a bounded aggregate boot reconciliation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleBootReconcilerV1 {
    inventory: LifecycleBootInventoryV1,
    operation: OperationId,
    method_plan: super::LifecycleMethodPlanV1,
    steps: Vec<LifecycleBootRecoveryStepV1>,
    cursor: usize,
}

impl LifecycleBootReconcilerV1 {
    /// Joins all six complete inventories and derives exact recovery actions.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the inventory is bound to the
    /// current protected operation and every resource has exactly one trusted
    /// observation under all six exact domain commitments.
    pub fn plan(
        current: &CurrentLifecycleOperationV1<'_>,
        protected_inventory: &CurrentLifecycleBootInventoryV1<'_>,
        domains: &CurrentLifecycleBootDomainInventoriesV1<'_>,
        observations: Vec<LifecycleBootResourceObservationV1>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let inventory = protected_inventory.inventory();
        let physical = physical_resources(&domains.physical);
        let expected_resources = physical
            .keys()
            .copied()
            .chain(domains.desired.resources.iter().copied())
            .collect::<BTreeSet<_>>();
        if protected_inventory.projection_root() != current.projection_root()
            || inventory.operation() != current.operation().operation_id()
            || domains.projection_root() != current.projection_root()
            || domains.aggregate() != inventory.inventory().digest()
            || !domains_match(inventory, domains.domains())
            || observations.len() != expected_resources.len()
            || observations.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !observations
                .windows(2)
                .all(|pair| observation_key(&pair[0]) < observation_key(&pair[1]))
            || observations.iter().any(|observation| {
                !observation_is_classified_from_inventory(observation, inventory, domains)
                    || observation.operation != current.operation().operation_id()
                    || observation.operation_record != current.record()
                    || observation.aggregate_inventory != domains.physical.commitment
                    || observation.desired_inventory != domains.desired.commitment
                    || domains.domains().iter().all(|domain| {
                        domain.domain != observation.domain
                            || domain.commitment != observation.domain_inventory
                    })
            })
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let mut steps = Vec::new();
        steps
            .try_reserve_exact(observations.len())
            .map_err(|_| LifecyclePhase6ErrorV1::Capacity)?;
        steps.extend(
            observations
                .into_iter()
                .map(|observation| LifecycleBootRecoveryStepV1 {
                    resource: observation.resource,
                    domain: observation.domain,
                    action: recovery_action(observation.domain, observation.state),
                    observation: observation.observation,
                }),
        );
        let method_plan = super::LifecycleMethodPlanV1::from_current(current, steps.len())?;
        let mut reconciler = Self {
            inventory: inventory.clone(),
            operation: current.operation().operation_id(),
            method_plan,
            steps,
            cursor: 0,
        };
        reconciler.validate_method_plan(current)?;
        reconciler.restore_persisted_cursor(current)?;
        Ok(reconciler)
    }

    /// Returns the exact next recovery step.
    #[must_use]
    pub fn next(&self) -> Option<LifecycleBootRecoveryStepV1> {
        self.steps.get(self.cursor).copied()
    }

    /// Advances after exact protected readback of the selected action.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for a substituted step or receipt.
    pub fn observe(
        mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        observation: LifecycleEffectObservationV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request() != self.next_effect(current)?.request() {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.cursor += 1;
        Ok(self)
    }

    /// Produces the controller-owned disposition for one exact-match adoption.
    ///
    /// Adoption performs no lower-domain mutation, but its exact protected
    /// inventory disposition is still recorded through the same lifecycle
    /// attempt transaction as every repair action.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the next derived step is an
    /// exact protected-inventory adoption.
    pub fn adopt(
        &self,
        current: &CurrentLifecycleOperationV1<'_>,
        protected_inventory: &CurrentLifecycleBootInventoryV1<'_>,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        if current.operation().operation_id() != self.operation
            || protected_inventory.inventory().operation() != self.operation
            || protected_inventory.inventory() != &self.inventory
            || self.next().map(LifecycleBootRecoveryStepV1::action)
                != Some(LifecycleBootRecoveryActionV1::Adopt)
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let step = self
            .next()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        self.next_effect(current)?.observe_controller_readback(
            recovery_step_digest(&self.inventory, step),
            self.inventory.inventory().digest(),
        )
    }

    /// Derives an inert protected-domain handoff for the next disposition.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for stale current state or completion.
    pub fn next_effect<'current>(
        &self,
        current: &CurrentLifecycleOperationV1<'current>,
    ) -> Result<CurrentLifecycleEffectV1<'current>, LifecyclePhase6ErrorV1> {
        if current.operation().operation_id() != self.operation {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let step = self
            .next()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        let domain = if step.action == LifecycleBootRecoveryActionV1::Adopt {
            LifecycleEffectDomainV1::Controller
        } else {
            effect_domain(step.domain)
        };
        current.recover_reserved_effect(
            domain,
            u32::try_from(self.cursor).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?,
            *step.resource.as_bytes(),
            step.observation,
            recovery_step_digest(&self.inventory, step),
        )
    }

    /// Reports whether every inventory member has an exact disposition.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.cursor == self.steps.len()
    }

    fn restore_persisted_cursor(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        match self.method_plan.cursor_index(current)? {
            Some(index) => {
                self.cursor = index;
                let _current_effect = self.next_effect(current)?;
                Ok(())
            }
            None if current
                .require_persisted_completion(&[current.operation().intent().method()])
                .is_ok_and(|completion| completion.plan() == self.method_plan.commitment()) =>
            {
                self.cursor = self.steps.len();
                Ok(())
            }
            None => Err(LifecyclePhase6ErrorV1::InvalidTransition),
        }
    }

    fn validate_method_plan(
        &self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        for (index, step) in self.steps.iter().copied().enumerate() {
            let expected = super::LifecycleStepPlanDigestV1::commit(
                recovery_step_digest(&self.inventory, step).as_bytes(),
            );
            if current.operation().steps()[index].plan() != expected {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        }
        Ok(())
    }
}

fn observation_is_classified_from_inventory(
    observation: &LifecycleBootResourceObservationV1,
    _inventory: &LifecycleBootInventoryV1,
    domains: &CurrentLifecycleBootDomainInventoriesV1<'_>,
) -> bool {
    let desired = &domains.desired.resources;
    let physical = physical_resources(&domains.physical);
    let key = observation_key(observation);
    let observed = physical.get(&key);
    if observation.state == LifecycleBootResourceStateV1::UnknownOwnership {
        if observed.is_none() && desired.binary_search(&key).is_err() {
            return false;
        }
        let expected = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.unmatched-boot-resource.v1\0")
                .chain_update(domains.physical.commitment.as_bytes())
                .chain_update(domains.desired.commitment.as_bytes())
                .chain_update([observation.domain as u8, observation.resource.code()])
                .chain_update(observation.resource.as_bytes())
                .finalize()
                .into(),
        );
        let classified = classified_observation_digest(
            domains.domain(observation.domain),
            domains.physical.commitment,
            domains.desired.commitment,
            observation.resource,
            LifecycleBootResourceStateV1::UnknownOwnership,
            observed.map_or(&[], Vec::as_slice),
        );
        return observation.observation == expected || observation.observation == classified;
    }
    let expected_state = if desired.binary_search(&key).is_ok() {
        if observed.is_some() {
            LifecycleBootResourceStateV1::DesiredPresent
        } else {
            LifecycleBootResourceStateV1::DesiredMissing
        }
    } else if observed.is_some() {
        LifecycleBootResourceStateV1::UndesiredPresent
    } else {
        return false;
    };
    observation.state == expected_state
        && observation.observation
            == classified_observation_digest(
                domains.domain(observation.domain),
                domains.physical.commitment,
                domains.desired.commitment,
                observation.resource,
                expected_state,
                observed.map_or(&[], Vec::as_slice),
            )
}

fn classified_observation_digest(
    domain: &LifecycleBootDomainInventoryV1,
    aggregate: ObjectDigest,
    desired: ObjectDigest,
    resource: LifecycleResourceV1,
    state: LifecycleBootResourceStateV1,
    rows: &[LifecyclePhysicalBootRowV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.classified-boot-resource.v1\0")
        .chain_update(aggregate.as_bytes())
        .chain_update(desired.as_bytes())
        .chain_update(domain.commitment().as_bytes())
        .chain_update([resource.code(), domain.domain() as u8, state as u8])
        .chain_update(resource.as_bytes())
        .chain_update((rows.len() as u64).to_be_bytes());
    for row in rows {
        hasher = hasher
            .chain_update([row.domain as u8])
            .chain_update(row.entry.identity.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn physical_resources(
    physical: &LifecycleFreshPhysicalInventoryV1,
) -> BTreeMap<LifecycleBootResourceKeyV1, Vec<LifecyclePhysicalBootRowV1>> {
    let mut resources = BTreeMap::new();
    for row in &physical.rows {
        resources
            .entry(LifecycleBootResourceKeyV1 {
                domain: row.domain,
                resource: row.entry.resource,
            })
            .or_insert_with(Vec::new)
            .push(*row);
    }
    resources
}

fn domains_match(
    inventory: &LifecycleBootInventoryV1,
    actual: &[LifecycleBootDomainInventoryV1; 6],
) -> bool {
    let expected = inventory.domains();
    actual
        == &[
            LifecycleBootDomainInventoryV1 {
                domain: LifecycleBootDomainV1::Runtime,
                commitment: expected.runtime(),
            },
            LifecycleBootDomainInventoryV1 {
                domain: LifecycleBootDomainV1::Mount,
                commitment: expected.mounts(),
            },
            LifecycleBootDomainInventoryV1 {
                domain: LifecycleBootDomainV1::Storage,
                commitment: expected.storage(),
            },
            LifecycleBootDomainInventoryV1 {
                domain: LifecycleBootDomainV1::Network,
                commitment: expected.network(),
            },
            LifecycleBootDomainInventoryV1 {
                domain: LifecycleBootDomainV1::Cache,
                commitment: expected.cache(),
            },
            LifecycleBootDomainInventoryV1 {
                domain: LifecycleBootDomainV1::Transfer,
                commitment: expected.transfers(),
            },
        ]
}

const fn recovery_action(
    domain: LifecycleBootDomainV1,
    state: LifecycleBootResourceStateV1,
) -> LifecycleBootRecoveryActionV1 {
    match state {
        LifecycleBootResourceStateV1::DesiredPresent => LifecycleBootRecoveryActionV1::Adopt,
        LifecycleBootResourceStateV1::UnknownOwnership => LifecycleBootRecoveryActionV1::Quarantine,
        LifecycleBootResourceStateV1::DesiredMissing => match domain {
            LifecycleBootDomainV1::Runtime => LifecycleBootRecoveryActionV1::RepairRuntime,
            LifecycleBootDomainV1::Mount => LifecycleBootRecoveryActionV1::RepairMount,
            LifecycleBootDomainV1::Storage => LifecycleBootRecoveryActionV1::RepairStorage,
            LifecycleBootDomainV1::Network => LifecycleBootRecoveryActionV1::RepairNetwork,
            LifecycleBootDomainV1::Cache => LifecycleBootRecoveryActionV1::ReconcileCache,
            LifecycleBootDomainV1::Transfer => LifecycleBootRecoveryActionV1::ResumeTransfer,
        },
        LifecycleBootResourceStateV1::UndesiredPresent => match domain {
            LifecycleBootDomainV1::Runtime => LifecycleBootRecoveryActionV1::StopRuntime,
            LifecycleBootDomainV1::Mount => LifecycleBootRecoveryActionV1::DetachMount,
            LifecycleBootDomainV1::Storage => LifecycleBootRecoveryActionV1::ReapStorage,
            LifecycleBootDomainV1::Network => LifecycleBootRecoveryActionV1::ReleaseNetwork,
            LifecycleBootDomainV1::Cache => LifecycleBootRecoveryActionV1::ReleaseCache,
            LifecycleBootDomainV1::Transfer => LifecycleBootRecoveryActionV1::CancelTransfer,
        },
    }
}

const fn effect_domain(domain: LifecycleBootDomainV1) -> LifecycleEffectDomainV1 {
    match domain {
        LifecycleBootDomainV1::Runtime => LifecycleEffectDomainV1::Runtime,
        LifecycleBootDomainV1::Mount => LifecycleEffectDomainV1::Mount,
        LifecycleBootDomainV1::Storage => LifecycleEffectDomainV1::Storage,
        LifecycleBootDomainV1::Network => LifecycleEffectDomainV1::Network,
        LifecycleBootDomainV1::Cache => LifecycleEffectDomainV1::Cache,
        LifecycleBootDomainV1::Transfer => LifecycleEffectDomainV1::Transfer,
    }
}

fn desired_domains(resource: LifecycleResourceV1) -> impl Iterator<Item = LifecycleBootDomainV1> {
    let domains = match resource {
        LifecycleResourceV1::Sandbox(_) => [
            Some(LifecycleBootDomainV1::Runtime),
            Some(LifecycleBootDomainV1::Storage),
            Some(LifecycleBootDomainV1::Network),
        ],
        LifecycleResourceV1::Execution(_) => [Some(LifecycleBootDomainV1::Runtime), None, None],
        LifecycleResourceV1::View(_) | LifecycleResourceV1::Attachment(_) => [
            Some(LifecycleBootDomainV1::Mount),
            Some(LifecycleBootDomainV1::Cache),
            None,
        ],
        LifecycleResourceV1::Snapshot(_) => [Some(LifecycleBootDomainV1::Storage), None, None],
        LifecycleResourceV1::Capability(_) | LifecycleResourceV1::Environment(_) => {
            [Some(LifecycleBootDomainV1::Cache), None, None]
        }
        LifecycleResourceV1::Project(_) => [Some(LifecycleBootDomainV1::Network), None, None],
        LifecycleResourceV1::Other(_) => [Some(LifecycleBootDomainV1::Transfer), None, None],
    };
    domains.into_iter().flatten()
}

const fn observation_key(
    observation: &LifecycleBootResourceObservationV1,
) -> LifecycleBootResourceKeyV1 {
    LifecycleBootResourceKeyV1 {
        domain: observation.domain,
        resource: observation.resource,
    }
}

fn recovery_step_digest(
    inventory: &LifecycleBootInventoryV1,
    step: LifecycleBootRecoveryStepV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.boot-recovery-step.v1\0")
            .chain_update(inventory.inventory().digest().as_bytes())
            .chain_update([step.resource.code(), step.domain as u8, step.action as u8])
            .chain_update(step.resource.as_bytes())
            .chain_update(step.observation.as_bytes())
            .finalize()
            .into(),
    )
}

fn complete_domain_inventory_digest(
    domain: LifecycleBootDomainV1,
    generation: u64,
    source: ObjectDigest,
    entries: &[LifecycleBootDomainEntryV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.complete-domain-inventory.v1\0")
        .chain_update([domain as u8])
        .chain_update(generation.to_be_bytes())
        .chain_update(source.as_bytes())
        .chain_update((entries.len() as u32).to_be_bytes());
    for entry in entries {
        hasher = hasher
            .chain_update([entry.resource.code()])
            .chain_update(entry.resource.as_bytes())
            .chain_update(entry.identity.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
