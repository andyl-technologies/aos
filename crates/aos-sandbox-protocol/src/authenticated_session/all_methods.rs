//! Method-complete authenticated broker semantic admission.
//!
//! The established authenticated bootstrap owns a specialized Network
//! inventory path. This module supplies the dormant uniform path for every
//! method in the same closed authenticated profile. It composes canonical signed
//! packet verification with the existing method decoders and retains exact
//! body bytes plus a method-separated semantic commitment. It does not itself
//! invoke a service, consume descriptors, authorize an effect, or write durable
//! state.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, InventoryNetworksRequest,
};
use aos_sandbox_broker_session_protocol::{
    BrokerOutcomeAdmissionV1, BrokerRequestAdmissionV1, BrokerSessionMethodProfileV1,
    BrokerSessionReplayEvidenceV1, BrokerSessionSequenceError, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionVerificationContextV1, authenticated_broker_method_profile_v1,
    decode_canonical_request_v1, decode_canonical_response_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::host_catalog::{
    decode_host_catalog_publication_request, decode_host_catalog_publication_response,
};
use crate::mount_catalog::{
    decode_mount_catalog_preparation, decode_mount_catalog_preparation_response,
};
use crate::mount_scope::{decode_mount_scope_request, decode_mount_scope_response};
use crate::mount_scope_identity::decode_mount_scope_identity_response_v1;
use crate::mount_source_acquisition::decode_mount_source_acquisition_inventory_response_with_maximum;
use crate::payload_scope::{decode_payload_scope_request, decode_payload_scope_response};
use crate::semantics::mount_scope::{
    canonical_mount_scope_identity_semantics_v1, canonical_mount_scope_semantics_v1,
};
use crate::semantics::payload_scope::canonical_payload_scope_semantics_v1;
use crate::semantics::{
    CanonicalNetworkSemanticsV1, CanonicalStorageGuestRootSemanticsV1,
    CanonicalStoragePreparationSemanticsV1, CanonicalStorageRepairSemanticsV1,
    CanonicalStorageSemanticsV1, CatalogBindingV1, MountCatalogBindingV1,
    canonical_acquire_mount_source_semantics_v1, canonical_destination_slot_semantics_v1,
    canonical_host_semantics_v1, canonical_mount_semantics_v1,
    canonical_release_mount_source_acquisition_semantics_v1, decode_storage_guest_root_response_v1,
};
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedBrokerError,
    ValidatedBrokerRequestEnvelope, ValidatedHeader, decode_acquire_mount_source_request,
    decode_acquire_mount_source_response, decode_atomic_storage_snapshot_request,
    decode_atomic_storage_snapshot_response, decode_destination_slot_inventory_request,
    decode_destination_slot_inventory_response, decode_destination_slot_request,
    decode_inventory_runtime_request_v1, decode_mount_inventory_request,
    decode_mount_inventory_response, decode_mount_request, decode_mount_result_for_apply,
    decode_mount_source_acquisition_inventory_request, decode_network_resource_inventory_request,
    decode_network_resource_inventory_response, decode_observe_runtime_request_v1,
    decode_query_runtime_effect_request_v1, decode_query_runtime_effect_response,
    decode_release_mount_source_acquisition_request,
    decode_release_mount_source_acquisition_response, decode_storage_inventory_recovery_request_v1,
    decode_storage_inventory_recovery_response_v1, decode_storage_resource_inventory_request,
    decode_storage_resource_inventory_response, validate_runtime_effect_receipt_for_apply,
};

use super::{
    protocol_id_for_profile, validate_decoded_request_envelope, validate_decoded_response_envelope,
    validate_outcome_against_profile, validate_request_against_profile,
};

/// Bridges live semantic evidence into journal-neutral durable records.
pub mod checkpoint;
mod host;
mod mount;
mod network;
#[cfg(test)]
mod no_apply_tests;
mod storage;

use host::{validate_runtime_inventory, validate_runtime_observation};
use mount::validate_destination_slot_apply_response;
use network::{validate_network_apply_response, validate_network_inventory};
use storage::{
    validate_storage_apply_response, validate_storage_preparation_response,
    validate_storage_repair_response,
};

const REQUEST_SEMANTIC_DOMAIN: &[u8] = b"aos-sandbox-authenticated-method-request-v1\0";
const OUTCOME_SEMANTIC_DOMAIN: &[u8] = b"aos-sandbox-authenticated-method-outcome-v1\0";
const CATALOG_GENERATION_BINDING_DOMAIN: &[u8] =
    b"aos-sandbox-authenticated-catalog-generation-binding-v1\0";

/// Reports a failed method-complete authenticated admission.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthenticatedBrokerMethodErrorV1 {
    /// The method is absent from the closed authenticated profile.
    #[error("unsupported authenticated broker method")]
    UnsupportedMethod,
    /// Canonical cryptographic traffic admission failed.
    #[error("authenticated broker traffic failed: {0}")]
    Traffic(#[from] BrokerSessionSequenceError),
    /// The outer or nested established protocol contract failed.
    #[error("authenticated broker method protocol failed: {0}")]
    Protocol(#[from] ProtocolValidationError),
    /// Portable effect semantics could not be constructed.
    #[error("authenticated broker method has invalid portable semantics")]
    PortableSemantics,
    /// A method requiring protected catalog input did not receive it.
    #[error("authenticated broker method is missing its verified catalog binding")]
    MissingCatalogBinding,
    /// A replay differs from the exact semantic evidence retained by its owner.
    #[error("authenticated broker method replay equivocated")]
    ReplayEquivocation,
    /// Signed, envelope, header, session, request, or method fields disagree.
    #[error("authenticated broker method cross-link is inconsistent")]
    InconsistentCrossLink,
}

/// Supplies separately verified catalog inputs needed by portable compilers.
///
/// These values remain nonauthorizing. The caller must obtain them from the
/// protected owner and recheck currentness before admission and before use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthenticatedBrokerSemanticBindingsV1 {
    storage_catalog: Option<CatalogBindingV1>,
    mount_catalog: Option<MountCatalogBindingV1>,
}

impl AuthenticatedBrokerSemanticBindingsV1 {
    /// Constructs exact optional Storage and Mount catalog bindings.
    #[must_use]
    pub const fn new(
        storage_catalog: Option<CatalogBindingV1>,
        mount_catalog: Option<MountCatalogBindingV1>,
    ) -> Self {
        Self {
            storage_catalog,
            mount_catalog,
        }
    }
}

/// Derives the sole method-specific semantic bindings from a signed envelope.
///
/// The returned values remain nonauthorizing compiler inputs. Their authority
/// comes only from subsequent fixed broker-domain verification. This parser
/// rejects aliases: Storage Apply requires exactly its generation/digest pair,
/// Mount Apply permits only its digest, and all other methods forbid bindings.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1`] for missing, extra, zero,
/// malformed, or unknown binding fields.
pub fn authenticated_semantic_bindings_from_envelope_v1(
    envelope: &BrokerRequestEnvelope,
    method: BrokerMethod,
) -> Result<AuthenticatedBrokerSemanticBindingsV1, AuthenticatedBrokerMethodErrorV1> {
    let binding = envelope.semantic_bindings.as_option();
    if binding.is_some_and(|binding| !binding.__buffa_unknown_fields.is_empty()) {
        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
    }
    match method {
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
            let binding = binding.ok_or(AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding)?;
            let digest: [u8; 32] = binding
                .storage_catalog_digest
                .as_slice()
                .try_into()
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding)?;
            if binding.storage_catalog_generation == 0
                || digest == [0; 32]
                || !binding.mount_catalog_digest.is_empty()
            {
                return Err(AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding);
            }
            let storage = CatalogBindingV1::from_publisher(
                binding.storage_catalog_generation,
                aos_sandbox_core::ObjectDigest::from_bytes(digest),
            )
            .map_err(|_| AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding)?;
            Ok(AuthenticatedBrokerSemanticBindingsV1::new(
                Some(storage),
                None,
            ))
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => {
            let mount = match binding {
                None => None,
                Some(binding) => {
                    if binding.storage_catalog_generation != 0
                        || !binding.storage_catalog_digest.is_empty()
                    {
                        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
                    }
                    if binding.mount_catalog_digest.is_empty() {
                        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
                    }
                    let digest: [u8; 32] = binding
                        .mount_catalog_digest
                        .as_slice()
                        .try_into()
                        .map_err(|_| AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding)?;
                    Some(
                        MountCatalogBindingV1::from_verified_digest(
                            aos_sandbox_core::ObjectDigest::from_bytes(digest),
                        )
                        .map_err(|_| AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding)?,
                    )
                }
            };
            Ok(AuthenticatedBrokerSemanticBindingsV1::new(None, mount))
        }
        BrokerMethod::BROKER_METHOD_UNSPECIFIED => {
            Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod)
        }
        _ if binding.is_none() => Ok(AuthenticatedBrokerSemanticBindingsV1::default()),
        _ => Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink),
    }
}

/// Names the semantic decoder path used for one admitted body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedBrokerMethodSemanticsV1 {
    /// Host ApplyRuntime.
    HostApplyRuntime,
    /// Host ObserveRuntime.
    HostObserveRuntime,
    /// Host InventoryRuntime.
    HostInventoryRuntime,
    /// Mount Apply.
    MountApply,
    /// Mount resource inventory.
    MountInventoryResources,
    /// Storage Apply.
    StorageApply,
    /// Network Apply.
    NetworkApply,
    /// Legacy Network inventory.
    NetworkInventory,
    /// Host durable-effect query.
    HostQueryRuntimeEffect,
    /// Host payload-scope acquisition.
    HostObservePayloadScope,
    /// Host mount-scope acquisition.
    HostObserveMountScope,
    /// Host namespace-identity readback with its own signed purpose.
    HostObserveMountScopeIdentity,
    /// Storage-only Host physical consumer-cgroup readback.
    HostObserveConsumerCgroup,
    /// Mount catalog preparation.
    MountPrepareCatalog,
    /// Mount destination-slot effect.
    MountApplyDestinationSlot,
    /// Mount destination-slot inventory.
    MountInventoryDestinationSlots,
    /// Host catalog publication.
    HostPublishCatalog,
    /// Host execution intent handoff.
    HostApplyExecution,
    /// Host protected execution outcome readback.
    HostQueryExecution,
    /// Sealed Controller argument-source transport; no successful outcome exists yet.
    HostObserveRuntimeArgument,
    /// Controller-signed provisional Host output reservation.
    HostReserveExecutionOutput,
    /// Read-only exact original Host output reservation query.
    HostQueryExecutionOutput,
    /// Signed, one-shot Controller attempt for a fresh Host-owned Guest readback.
    HostObserveExecutionArgument,
    /// Read-only historical query of the original Host argument attempt.
    HostQueryExecutionArgument,
    /// Mutating Host terminal settlement before execution Apply.
    HostTerminalNoApply,
    /// Read-only historical Host no-Apply marker query.
    HostQueryNoApply,
    /// Signed preliminary Host settlement coordinate; no Controller CAS authority.
    HostSettleNoApplyPreliminary,
    /// Read-only signed Host settlement history query.
    HostQueryNoApplySettlement,
    /// Read-only Storage capture candidate; issuer and signed outcome are closed.
    StorageCaptureCandidateReadback,
    /// Host OpenSSH forced-command installation and signed readback.
    HostInstallAttachGate,
    /// Advisory current Host OpenSSH gate readiness.
    HostQueryAttachGateReadiness,
    /// Fresh physical readback of an accepted OpenSSH route.
    HostQueryAttachGateRoute,
    /// Storage resource inventory.
    StorageInventoryResources,
    /// Recovery-only signed control for an original Storage inventory.
    StorageRecoverInventory,
    /// Network resource inventory.
    NetworkInventoryResources,
    /// Storage catalog preparation.
    StoragePrepareCatalog,
    /// Storage workspace-pin repair.
    StorageRepairWorkspacePin,
    /// One complete grouped Storage dataset snapshot.
    StorageAtomicSnapshot,
    /// One separately admitted physical guest-root publication.
    StoragePopulateGuestRoot,
    /// Mount source acquisition.
    MountAcquireSource,
    /// Mount source-acquisition release.
    MountReleaseSourceAcquisition,
    /// Mount source-acquisition inventory.
    MountInventorySourceAcquisitions,
}

/// Identifies which endpoint advanced client-to-broker request state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedBrokerRequestDirectionV1 {
    /// The protected client verified its locally signed packet before sending.
    ClientSend,
    /// The protected broker verified the packet received from its client.
    ServerReceive,
}

/// Identifies which endpoint advanced broker-to-client outcome state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedBrokerOutcomeDirectionV1 {
    /// The protected broker verified its locally signed outcome before sending.
    ServerSend,
    /// The protected client verified the outcome received from its broker.
    ClientReceive,
}

/// Identifies the dormant pure adapter for one existing request/reply pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedBrokerMethodAdapterV1 {
    profile: BrokerSessionMethodProfileV1,
    semantics: AuthenticatedBrokerMethodSemanticsV1,
}

impl AuthenticatedBrokerMethodAdapterV1 {
    /// Returns the exact authenticated method profile.
    #[must_use]
    pub const fn profile(self) -> BrokerSessionMethodProfileV1 {
        self.profile
    }

    /// Returns the existing method semantic decoder selected by the adapter.
    #[must_use]
    pub const fn semantics(self) -> AuthenticatedBrokerMethodSemanticsV1 {
        self.semantics
    }
}

/// Resolves a closed method to its existing protocol request/reply adapter.
#[must_use]
pub const fn authenticated_broker_method_adapter_v1(
    method: BrokerMethod,
) -> Option<AuthenticatedBrokerMethodAdapterV1> {
    let profile = match authenticated_broker_method_profile_v1(method) {
        Some(profile) => profile,
        None => return None,
    };
    let semantics = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
            AuthenticatedBrokerMethodSemanticsV1::HostApplyRuntime
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME => {
            AuthenticatedBrokerMethodSemanticsV1::HostObserveRuntime
        }
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME => {
            AuthenticatedBrokerMethodSemanticsV1::HostInventoryRuntime
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => AuthenticatedBrokerMethodSemanticsV1::MountApply,
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES => {
            AuthenticatedBrokerMethodSemanticsV1::MountInventoryResources
        }
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
            AuthenticatedBrokerMethodSemanticsV1::StorageApply
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => {
            AuthenticatedBrokerMethodSemanticsV1::NetworkApply
        }
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY => {
            AuthenticatedBrokerMethodSemanticsV1::NetworkInventory
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryRuntimeEffect
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
            AuthenticatedBrokerMethodSemanticsV1::HostObservePayloadScope
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
            AuthenticatedBrokerMethodSemanticsV1::HostObserveMountScope
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
            AuthenticatedBrokerMethodSemanticsV1::HostObserveMountScopeIdentity
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP => {
            AuthenticatedBrokerMethodSemanticsV1::HostObserveConsumerCgroup
        }
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG => {
            AuthenticatedBrokerMethodSemanticsV1::MountPrepareCatalog
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT => {
            AuthenticatedBrokerMethodSemanticsV1::MountApplyDestinationSlot
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS => {
            AuthenticatedBrokerMethodSemanticsV1::MountInventoryDestinationSlots
        }
        BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => {
            AuthenticatedBrokerMethodSemanticsV1::HostPublishCatalog
        }
        BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION => {
            AuthenticatedBrokerMethodSemanticsV1::HostApplyExecution
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryExecution
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT => {
            AuthenticatedBrokerMethodSemanticsV1::HostObserveRuntimeArgument
        }
        BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => {
            AuthenticatedBrokerMethodSemanticsV1::HostReserveExecutionOutput
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryExecutionOutput
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT => {
            AuthenticatedBrokerMethodSemanticsV1::HostObserveExecutionArgument
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryExecutionArgument
        }
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY => {
            AuthenticatedBrokerMethodSemanticsV1::HostTerminalNoApply
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApply
        }
        BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => {
            AuthenticatedBrokerMethodSemanticsV1::StorageCaptureCandidateReadback
        }
        BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE => {
            AuthenticatedBrokerMethodSemanticsV1::HostInstallAttachGate
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryAttachGateReadiness
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryAttachGateRoute
        }
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => {
            AuthenticatedBrokerMethodSemanticsV1::StorageInventoryResources
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY => {
            AuthenticatedBrokerMethodSemanticsV1::StorageRecoverInventory
        }
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => {
            AuthenticatedBrokerMethodSemanticsV1::NetworkInventoryResources
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => {
            AuthenticatedBrokerMethodSemanticsV1::StoragePrepareCatalog
        }
        BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
            AuthenticatedBrokerMethodSemanticsV1::StorageRepairWorkspacePin
        }
        BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => {
            AuthenticatedBrokerMethodSemanticsV1::MountAcquireSource
        }
        BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
            AuthenticatedBrokerMethodSemanticsV1::MountReleaseSourceAcquisition
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => {
            AuthenticatedBrokerMethodSemanticsV1::MountInventorySourceAcquisitions
        }
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
            AuthenticatedBrokerMethodSemanticsV1::StorageAtomicSnapshot
        }
        BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => {
            AuthenticatedBrokerMethodSemanticsV1::StoragePopulateGuestRoot
        }
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::HostSettleNoApplyPreliminary
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApplySettlement
        }
        // These provisional carriers remain closed until their independent
        // issuers and cross-owner currentness joins exist.
        BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT => return None,
        BrokerMethod::BROKER_METHOD_UNSPECIFIED => return None,
    };
    Some(AuthenticatedBrokerMethodAdapterV1 { profile, semantics })
}

/// Retains one fully validated signed request without execution authority.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedBrokerMethodRequestV1 {
    direction: AuthenticatedBrokerRequestDirectionV1,
    method: BrokerMethod,
    semantics: AuthenticatedBrokerMethodSemanticsV1,
    canonical_packet: Vec<u8>,
    exact_body: Vec<u8>,
    semantic_commitment: [u8; 32],
    catalog_binding: Option<[u8; 32]>,
    published_catalog_binding: Option<[u8; 32]>,
    peer: PeerCredentials,
    peer_policy: PeerPolicy,
    session_binding: [u8; 32],
    request_id: [u8; 16],
    client_sequence: u64,
    maximum_response_bytes: u32,
    deadline_boottime_nanoseconds: u64,
    signed_request_digest: [u8; 32],
    envelope: ValidatedBrokerRequestEnvelope,
    outcome_context: RequestOutcomeContextV1,
}

impl AuthenticatedBrokerMethodRequestV1 {
    /// Returns the endpoint-local direction of this admission.
    #[must_use]
    pub const fn direction(&self) -> AuthenticatedBrokerRequestDirectionV1 {
        self.direction
    }

    /// Returns the exact closed method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the method-specific semantic decoder path.
    #[must_use]
    pub const fn semantics(&self) -> AuthenticatedBrokerMethodSemanticsV1 {
        self.semantics
    }

    /// Returns the canonical complete signed request packet.
    #[must_use]
    pub fn canonical_packet(&self) -> &[u8] {
        &self.canonical_packet
    }

    /// Returns the exact semantically validated nested request body.
    #[must_use]
    pub fn exact_body(&self) -> &[u8] {
        &self.exact_body
    }

    /// Returns the method-separated semantic commitment.
    #[must_use]
    pub const fn semantic_commitment(&self) -> [u8; 32] {
        self.semantic_commitment
    }

    /// Returns the protected catalog digest used by semantic compilation.
    #[must_use]
    pub const fn catalog_binding(&self) -> Option<[u8; 32]> {
        self.catalog_binding
    }

    /// Returns the catalog generation/digest expected after a publication.
    #[must_use]
    pub const fn published_catalog_binding(&self) -> Option<[u8; 32]> {
        self.published_catalog_binding
    }

    /// Returns the exact kernel credentials admitted with the signed packet.
    #[must_use]
    pub const fn peer(&self) -> PeerCredentials {
        self.peer
    }

    /// Returns the exact local peer policy used for semantic admission.
    #[must_use]
    pub const fn peer_policy(&self) -> PeerPolicy {
        self.peer_policy
    }

    /// Returns the exact authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the exact request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the client-to-broker sequence.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the authenticated request's response ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the originally admitted absolute boot-time deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the semantically validated authorization quartet, when required.
    #[must_use]
    pub const fn authorization(
        &self,
    ) -> Option<&crate::session::ValidatedUntrustedAuthorizationArtifacts> {
        self.envelope.authorization()
    }

    /// Returns the digest of the complete signed ClientRecord artifact.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }
}

/// Retains a completely validated terminal result without installing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatedBrokerMethodResultV1 {
    /// A method-specific success body passed its closed decoder.
    Success {
        /// Exact canonical successful body bytes.
        exact_body: Vec<u8>,
        /// Method-separated commitment to the validated result.
        semantic_commitment: [u8; 32],
        /// Optional dormant FUSE-worker qualification record commitment.
        filesystem_worker_qualification_commitment: Option<[u8; 32]>,
    },
    /// A signed terminal error passed the closed broker error contract.
    Error(ValidatedBrokerError),
}

/// Retains one completely validated signed terminal outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedBrokerMethodOutcomeV1 {
    direction: AuthenticatedBrokerOutcomeDirectionV1,
    method: BrokerMethod,
    canonical_packet: Vec<u8>,
    request: AuthenticatedBrokerMethodRequestV1,
    broker_sequence: u64,
    result: AuthenticatedBrokerMethodResultV1,
}

/// Borrows one signed client-received Host no-Apply outcome with its checked marker.
///
/// This observation is not a Controller settlement capability. The original
/// method-37 archive and the Host marker's protected currentness still require
/// separate owner readback before a failed Create may be committed.
pub struct AuthenticatedHostNoApplyReadbackV1<'outcome> {
    outcome: &'outcome AuthenticatedBrokerMethodOutcomeV1,
    record: crate::host_execution_no_apply::HostExecutionNoApplyRecordV1,
}

impl AuthenticatedHostNoApplyReadbackV1<'_> {
    /// Returns the exact checked Host no-Apply marker.
    #[must_use]
    pub const fn record(&self) -> &crate::host_execution_no_apply::HostExecutionNoApplyRecordV1 {
        &self.record
    }

    /// Returns the complete signed outcome and its authenticated request.
    #[must_use]
    pub const fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        self.outcome
    }
}

impl AuthenticatedBrokerMethodOutcomeV1 {
    /// Returns the endpoint-local direction of this admission.
    #[must_use]
    pub const fn direction(&self) -> AuthenticatedBrokerOutcomeDirectionV1 {
        self.direction
    }

    /// Returns the exact closed method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the request cross-linked by this outcome.
    #[must_use]
    pub const fn request(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        &self.request
    }

    /// Returns the canonical complete signed outcome packet.
    #[must_use]
    pub fn canonical_packet(&self) -> &[u8] {
        &self.canonical_packet
    }

    /// Returns the broker-to-client sequence.
    #[must_use]
    pub const fn broker_sequence(&self) -> u64 {
        self.broker_sequence
    }

    /// Returns the closed terminal result.
    #[must_use]
    pub const fn result(&self) -> &AuthenticatedBrokerMethodResultV1 {
        &self.result
    }

    /// Returns the signed dormant FUSE-worker qualification commitment.
    #[must_use]
    pub const fn filesystem_worker_qualification_commitment(&self) -> Option<[u8; 32]> {
        match &self.result {
            AuthenticatedBrokerMethodResultV1::Success {
                filesystem_worker_qualification_commitment,
                ..
            } => *filesystem_worker_qualification_commitment,
            AuthenticatedBrokerMethodResultV1::Error(_) => None,
        }
    }

    /// Returns the method-separated commitment to the closed terminal semantics.
    #[must_use]
    pub fn semantic_commitment(&self) -> [u8; 32] {
        match &self.result {
            AuthenticatedBrokerMethodResultV1::Success {
                semantic_commitment,
                ..
            } => *semantic_commitment,
            AuthenticatedBrokerMethodResultV1::Error(_) => {
                method_digest(OUTCOME_SEMANTIC_DOMAIN, self.method, &self.canonical_packet)
            }
        }
    }

    /// Borrows a recorded Host no-Apply marker only from a signed client outcome.
    ///
    /// A method-40 ABSENT response, a signed terminal error, or another method
    /// returns `None`. Even a recorded marker remains nonauthorizing until the
    /// original method-37 archive and current Host custody are joined.
    ///
    /// # Errors
    ///
    /// Rejects a changed method, direction, semantic commitment, or marker
    /// cross-link in the retained authenticated outcome.
    pub fn recorded_host_no_apply(
        &self,
    ) -> Result<Option<AuthenticatedHostNoApplyReadbackV1<'_>>, AuthenticatedBrokerMethodErrorV1>
    {
        if !matches!(
            self.method,
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY
        ) {
            return Ok(None);
        }
        if self.direction != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || self.request.direction != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || self.method != self.request.method
        {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        let AuthenticatedBrokerMethodResultV1::Success {
            exact_body,
            semantic_commitment,
            ..
        } = &self.result
        else {
            return Ok(None);
        };
        if *semantic_commitment != method_digest(OUTCOME_SEMANTIC_DOMAIN, self.method, exact_body) {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        let record = decode_recorded_host_no_apply(
            self.method,
            &self.request.outcome_context,
            exact_body,
            self.request.session_binding,
            self.request.signed_request_digest,
        )?;
        Ok(record.map(|record| AuthenticatedHostNoApplyReadbackV1 {
            outcome: self,
            record,
        }))
    }

    /// Reads exact Host settlement history from a signed method-43 outcome.
    ///
    /// A matching history is protected Host custody, not a live lease or
    /// Controller settlement authority. An error outcome returns `None`.
    ///
    /// # Errors
    ///
    /// Rejects changed signed direction, method, semantic commitment, source,
    /// status, or any stage in the protected predecessor chain.
    pub fn recorded_host_no_apply_settlement_history(
        &self,
    ) -> Result<
        Option<crate::host_execution_no_apply::HostNoApplySettlementHistoryV2>,
        AuthenticatedBrokerMethodErrorV1,
    > {
        if self.method != BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 {
            return Ok(None);
        }
        if self.direction != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || self.request.direction != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || self.method != self.request.method
        {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        let AuthenticatedBrokerMethodResultV1::Success {
            exact_body,
            semantic_commitment,
            ..
        } = &self.result
        else {
            return Ok(None);
        };
        if *semantic_commitment != method_digest(OUTCOME_SEMANTIC_DOMAIN, self.method, exact_body) {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        let RequestOutcomeContextV1::HostNoApplySettlementQuery(original) =
            &self.request.outcome_context
        else {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        };
        crate::host_execution_no_apply::decode_host_no_apply_settlement_query_response_v2(
            exact_body, original,
        )
        .map(Some)
        .map_err(Into::into)
    }
}

/// Classifies a new request versus an exact cryptographic replay.
pub enum AuthenticatedBrokerMethodRequestAdmissionV1 {
    /// A new semantic request and its uncommitted next traffic state.
    New {
        /// Fully authenticated, semantically closed request evidence.
        request: AuthenticatedBrokerMethodRequestV1,
        /// Pure next traffic state; the owner must durably commit before use.
        next_traffic: Box<BrokerSessionTrafficStateV1>,
    },
    /// An exact replay that requires no new state write.
    ExactReplay(BrokerSessionReplayEvidenceV1),
}

/// Classifies a new terminal outcome versus an exact cryptographic replay.
pub enum AuthenticatedBrokerMethodOutcomeAdmissionV1 {
    /// A new semantic outcome and its uncommitted next traffic state.
    New {
        /// Fully authenticated, semantically closed outcome evidence.
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        /// Pure next traffic state; the owner must durably commit before use.
        next_traffic: Box<BrokerSessionTrafficStateV1>,
    },
    /// An exact replay that requires no new state write.
    ExactReplay(BrokerSessionReplayEvidenceV1),
}

/// Verifies that a cryptographic request replay is byte-identical to retained semantics.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1::ReplayEquivocation`] unless the
/// replay tuple and packet exactly identify the retained semantic request.
pub fn validate_exact_authenticated_request_replay_v1(
    replay: &BrokerSessionReplayEvidenceV1,
    retained: &AuthenticatedBrokerMethodRequestV1,
    candidate_packet: &[u8],
) -> Result<(), AuthenticatedBrokerMethodErrorV1> {
    if replay.request_id() != retained.request_id()
        || replay.sequence() != retained.client_sequence()
        || replay.signed_artifact_digest() != retained.signed_request_digest()
        || candidate_packet != retained.canonical_packet()
    {
        return Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation);
    }
    Ok(())
}

/// Verifies that a cryptographic outcome replay is byte-identical to retained semantics.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1::ReplayEquivocation`] unless the
/// replay tuple and packet exactly identify the retained terminal outcome.
pub fn validate_exact_authenticated_outcome_replay_v1(
    replay: &BrokerSessionReplayEvidenceV1,
    retained: &AuthenticatedBrokerMethodOutcomeV1,
    candidate_packet: &[u8],
) -> Result<(), AuthenticatedBrokerMethodErrorV1> {
    if replay.request_id() != retained.request().request_id()
        || replay.sequence() != retained.broker_sequence()
        || candidate_packet != retained.canonical_packet()
    {
        return Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation);
    }
    Ok(())
}

/// Authenticates and semantically admits any method in the closed profile.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1`] for packet, profile, peer,
/// header, descriptor, portable-semantic, context, or sequence failure.
#[allow(clippy::too_many_arguments)]
fn admit_authenticated_broker_method_request_v1(
    direction: AuthenticatedBrokerRequestDirectionV1,
    traffic: &BrokerSessionTrafficStateV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodRequestV1>,
    actual_descriptor_count: usize,
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
    bindings: AuthenticatedBrokerSemanticBindingsV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
    let canonical = decode_canonical_request_v1(bytes).map_err(BrokerSessionSequenceError::from)?;
    let method = canonical.signed_artifact().method();
    let adapter = authenticated_broker_method_adapter_v1(method)
        .ok_or(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod)?;
    let profile = adapter.profile();
    if actual_descriptor_count != profile.request_descriptor_roles().len() {
        return Err(ProtocolValidationError::DescriptorTableMismatch.into());
    }
    let envelope = validate_decoded_request_envelope(
        canonical.message().clone(),
        protocol_id_for_profile(profile.protocol()),
        actual_descriptor_count,
    )?;
    validate_request_against_profile(&envelope, &profile)?;

    // A byte-exact request retained by the protected owner is classified by
    // the authenticated traffic state before any live deadline check. The
    // retained semantic object was admitted when it was fresh; replay may be
    // needed after that deadline solely to recover its exact terminal result.
    if let Some(retained) = retained_replay.filter(|retained| {
        retained.canonical_packet() == bytes
            && retained.direction() == direction
            && retained.method() == method
            && retained.semantics() == adapter.semantics()
            && retained.exact_body() == envelope.body()
            && retained.peer() == peer
            && retained.peer_policy() == policy
            && retained.session_binding() == traffic.transcript().session_binding()
    }) {
        let admission = traffic.admit_request(
            &canonical,
            retained.request_id(),
            retained.maximum_response_bytes(),
            context,
        )?;
        return match admission {
            BrokerRequestAdmissionV1::ExactReplay(replay) => {
                validate_exact_authenticated_request_replay_v1(&replay, retained, bytes)?;
                Ok(AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(
                    replay,
                ))
            }
            BrokerRequestAdmissionV1::New { .. } => {
                Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation)
            }
        };
    }

    let semantic = validate_request_semantics(
        method,
        envelope.body(),
        envelope
            .descriptors()
            .iter()
            .map(|entry| entry.role())
            .collect::<Vec<_>>()
            .as_slice(),
        peer,
        policy,
        now_boottime_nanoseconds,
        bindings,
    )?;
    if semantic.kind != adapter.semantics() {
        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
    }
    validate_header_profile(&semantic.header, &profile, traffic)?;

    let admission = traffic.admit_request(
        &canonical,
        *semantic.header.request_id(),
        semantic.header.maximum_response_bytes(),
        context,
    )?;
    match admission {
        BrokerRequestAdmissionV1::New {
            request,
            next_state,
        } => Ok(AuthenticatedBrokerMethodRequestAdmissionV1::New {
            request: AuthenticatedBrokerMethodRequestV1 {
                direction,
                method,
                semantics: semantic.kind,
                canonical_packet: bytes.to_vec(),
                exact_body: envelope.body().to_vec(),
                semantic_commitment: semantic.commitment,
                catalog_binding: semantic.catalog_binding,
                published_catalog_binding: semantic.published_catalog_binding,
                peer,
                peer_policy: policy,
                session_binding: traffic.transcript().session_binding(),
                request_id: request.request_id(),
                client_sequence: request.sequence(),
                maximum_response_bytes: semantic.header.maximum_response_bytes(),
                deadline_boottime_nanoseconds: semantic.header.deadline_boottime_nanoseconds(),
                signed_request_digest: request.signed_request_digest(),
                envelope,
                outcome_context: semantic.outcome_context,
            },
            next_traffic: next_state,
        }),
        BrokerRequestAdmissionV1::ExactReplay(replay) => {
            let retained =
                retained_replay.ok_or(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation)?;
            if retained.direction() != direction {
                return Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation);
            }
            validate_exact_authenticated_request_replay_v1(&replay, retained, bytes)?;
            Ok(AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(
                replay,
            ))
        }
    }
}

/// Verifies a client-authored packet before the protected client sends it.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1`] for packet, profile, peer,
/// header, descriptor, portable-semantic, context, or sequence failure.
#[allow(clippy::too_many_arguments)]
pub fn prepare_client_sent_authenticated_broker_method_request_v1(
    traffic: &BrokerSessionTrafficStateV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodRequestV1>,
    actual_descriptor_count: usize,
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
    bindings: AuthenticatedBrokerSemanticBindingsV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
    admit_authenticated_broker_method_request_v1(
        AuthenticatedBrokerRequestDirectionV1::ClientSend,
        traffic,
        bytes,
        retained_replay,
        actual_descriptor_count,
        peer,
        policy,
        now_boottime_nanoseconds,
        bindings,
        context,
    )
}

/// Verifies a client-authored packet received by the protected broker.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1`] for packet, profile, peer,
/// header, descriptor, portable-semantic, context, or sequence failure.
#[allow(clippy::too_many_arguments)]
pub fn admit_server_received_authenticated_broker_method_request_v1(
    traffic: &BrokerSessionTrafficStateV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodRequestV1>,
    actual_descriptor_count: usize,
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
    bindings: AuthenticatedBrokerSemanticBindingsV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
    admit_authenticated_broker_method_request_v1(
        AuthenticatedBrokerRequestDirectionV1::ServerReceive,
        traffic,
        bytes,
        retained_replay,
        actual_descriptor_count,
        peer,
        policy,
        now_boottime_nanoseconds,
        bindings,
        context,
    )
}

/// Authenticates and semantically admits a terminal outcome for any method.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1`] for changed context, absent or
/// mismatched request state, sequence failure, profile or descriptor mismatch,
/// malformed error, or invalid method-specific success semantics.
fn admit_authenticated_broker_method_outcome_v1(
    direction: AuthenticatedBrokerOutcomeDirectionV1,
    traffic: &BrokerSessionTrafficStateV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodOutcomeV1>,
    actual_descriptor_count: usize,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
    let matching_request_direction = match direction {
        AuthenticatedBrokerOutcomeDirectionV1::ServerSend => {
            AuthenticatedBrokerRequestDirectionV1::ServerReceive
        }
        AuthenticatedBrokerOutcomeDirectionV1::ClientReceive => {
            AuthenticatedBrokerRequestDirectionV1::ClientSend
        }
    };
    if request.session_binding() != traffic.transcript().session_binding() {
        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
    } else if request.direction() != matching_request_direction {
        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
    }
    let profile = authenticated_broker_method_profile_v1(request.method())
        .ok_or(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod)?;
    let admission = traffic.decode_and_admit_outcome(bytes, context)?;
    let canonical =
        decode_canonical_response_v1(bytes).map_err(BrokerSessionSequenceError::from)?;

    match admission {
        BrokerOutcomeAdmissionV1::New {
            outcome,
            next_state,
        } => {
            let envelope = validate_decoded_response_envelope(
                canonical.message().clone(),
                &request.request_id(),
                request.method(),
                request.envelope.descriptors(),
                actual_descriptor_count,
            )?;
            validate_outcome_against_profile(&envelope, &profile)?;
            let result = if let Some(error) = envelope.error() {
                AuthenticatedBrokerMethodResultV1::Error(error.clone())
            } else {
                let filesystem_worker_qualification_commitment =
                    validate_success_semantics(request, envelope.body())?;
                AuthenticatedBrokerMethodResultV1::Success {
                    exact_body: envelope.body().to_vec(),
                    semantic_commitment: method_digest(
                        OUTCOME_SEMANTIC_DOMAIN,
                        request.method(),
                        envelope.body(),
                    ),
                    filesystem_worker_qualification_commitment,
                }
            };
            Ok(AuthenticatedBrokerMethodOutcomeAdmissionV1::New {
                outcome: AuthenticatedBrokerMethodOutcomeV1 {
                    direction,
                    method: request.method(),
                    canonical_packet: bytes.to_vec(),
                    request: request.clone(),
                    broker_sequence: outcome.sequence(),
                    result,
                },
                next_traffic: next_state,
            })
        }
        BrokerOutcomeAdmissionV1::ExactReplay(replay) => {
            let retained =
                retained_replay.ok_or(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation)?;
            if retained.direction() != direction {
                return Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation);
            }
            validate_exact_authenticated_outcome_replay_v1(&replay, retained, bytes)?;
            Ok(AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(
                replay,
            ))
        }
    }
}

/// Verifies a broker-authored outcome before the protected broker sends it.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1`] for changed context, absent or
/// mismatched request state, or invalid signed outcome semantics.
pub fn prepare_server_sent_authenticated_broker_method_outcome_v1(
    traffic: &BrokerSessionTrafficStateV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodOutcomeV1>,
    actual_descriptor_count: usize,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
    admit_authenticated_broker_method_outcome_v1(
        AuthenticatedBrokerOutcomeDirectionV1::ServerSend,
        traffic,
        request,
        bytes,
        retained_replay,
        actual_descriptor_count,
        context,
    )
}

/// Verifies a broker-authored outcome received by the protected client.
///
/// # Errors
///
/// Returns [`AuthenticatedBrokerMethodErrorV1`] for changed context, absent or
/// mismatched request state, or invalid signed outcome semantics.
pub fn admit_client_received_authenticated_broker_method_outcome_v1(
    traffic: &BrokerSessionTrafficStateV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodOutcomeV1>,
    actual_descriptor_count: usize,
    context: &ProtectedBrokerSessionVerificationContextV1,
) -> Result<AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
    admit_authenticated_broker_method_outcome_v1(
        AuthenticatedBrokerOutcomeDirectionV1::ClientReceive,
        traffic,
        request,
        bytes,
        retained_replay,
        actual_descriptor_count,
        context,
    )
}

struct ValidatedRequestSemanticV1 {
    kind: AuthenticatedBrokerMethodSemanticsV1,
    header: ValidatedHeader,
    commitment: [u8; 32],
    catalog_binding: Option<[u8; 32]>,
    published_catalog_binding: Option<[u8; 32]>,
    outcome_context: RequestOutcomeContextV1,
}

#[derive(Clone, Debug, PartialEq)]
enum RequestOutcomeContextV1 {
    None,
    HostObserve(crate::ValidatedObserveRuntimeRequestV1),
    MountApply(crate::ValidatedMountRequest),
    NetworkApply(CanonicalNetworkSemanticsV1),
    StorageApply(CanonicalStorageSemanticsV1),
    HostQuery(crate::ValidatedQueryRuntimeEffectRequestV1),
    PayloadScope(crate::payload_scope::ValidatedPayloadScopeRequest),
    MountScope(crate::mount_scope::ValidatedMountScopeRequest),
    MountScopeIdentity(crate::mount_scope::ValidatedMountScopeRequest),
    HostConsumerCgroup(crate::host_consumer_cgroup::ValidatedConsumerCgroupRequestV1),
    MountAcquireSource(crate::ValidatedAcquireMountSourceRequest),
    MountReleaseSource(crate::ValidatedReleaseMountSourceAcquisitionRequest),
    StoragePrepare(CanonicalStoragePreparationSemanticsV1),
    StorageRepair(CanonicalStorageRepairSemanticsV1),
    StorageGuestRoot(CanonicalStorageGuestRootSemanticsV1),
    MountPrepareCatalog(crate::mount_catalog::ValidatedMountCatalogPreparation),
    MountDestinationSlot(crate::ValidatedDestinationSlotRequest),
    HostPublishCatalog(crate::host_catalog::ValidatedHostCatalogPublication),
    HostExecutionApply(crate::ValidatedHostExecutionApplyV1),
    HostExecutionQuery(crate::ValidatedHostExecutionQueryV1),
    HostOutputReserve(crate::host_output::ValidatedHostOutputReserveRequestV1),
    HostOutputQuery(crate::host_output::ValidatedHostOutputQueryRequestV1),
    HostArgumentObserve(crate::host_execution_argument::ValidatedHostExecutionArgumentRequestV1),
    HostArgumentQuery(crate::host_execution_argument::ValidatedHostExecutionArgumentRequestV1),
    HostNoApply(crate::host_execution_no_apply::ValidatedHostExecutionNoApplyRequestV1),
    HostNoApplyQuery(crate::host_execution_no_apply::ValidatedHostExecutionNoApplyRequestV1),
    HostNoApplySettlement(crate::host_execution_no_apply::ValidatedHostNoApplySettlementRequestV2),
    HostNoApplySettlementQuery(
        crate::host_execution_no_apply::ValidatedHostNoApplySettlementQueryV2,
    ),
    HostAttachGate(crate::ValidatedHostAttachGateRequestV1),
    HostAttachReadiness,
    HostAttachRoute(crate::ValidatedHostAttachRouteQueryV1),
}

#[allow(clippy::too_many_arguments)]
fn validate_request_semantics(
    method: BrokerMethod,
    body: &[u8],
    descriptor_roles: &[aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
    bindings: AuthenticatedBrokerSemanticBindingsV1,
) -> Result<ValidatedRequestSemanticV1, AuthenticatedBrokerMethodErrorV1> {
    let (kind, header, portable_commitment) = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
            let request = crate::decode_runtime_request(body, peer, policy, now)?;
            let semantics = canonical_host_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostApplyRuntime,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME => {
            let request = decode_observe_runtime_request_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostObserveRuntime,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME => (
            AuthenticatedBrokerMethodSemanticsV1::HostInventoryRuntime,
            decode_inventory_runtime_request_v1(body, peer, policy, now)?,
            None,
        ),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => {
            let request = decode_mount_request(body, peer, policy, now)?;
            let semantics =
                canonical_mount_semantics_v1(&request, bindings.mount_catalog, descriptor_roles)
                    .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::MountApply,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES => (
            AuthenticatedBrokerMethodSemanticsV1::MountInventoryResources,
            decode_mount_inventory_request(body, peer, policy, now)?,
            None,
        ),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
            let catalog = bindings
                .storage_catalog
                .ok_or(AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding)?;
            let semantics = CanonicalStorageSemanticsV1::decode(body, catalog, peer, policy, now)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StorageApply,
                *semantics.header(),
                Some(*semantics.argument_commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => {
            let semantics = CanonicalNetworkSemanticsV1::decode(body, peer, policy, now)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::NetworkApply,
                *semantics.header(),
                Some(*semantics.argument_commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY => (
            AuthenticatedBrokerMethodSemanticsV1::NetworkInventory,
            validate_simple_inventory_request(body, peer, policy, now, profile_protocol(method)?)?,
            None,
        ),
        BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT => {
            let request = decode_query_runtime_effect_request_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryRuntimeEffect,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
            let request = decode_payload_scope_request(body, peer, policy, now)?;
            let semantics = canonical_payload_scope_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostObservePayloadScope,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
            let request = decode_mount_scope_request(body, peer, policy, now)?;
            let semantics = canonical_mount_scope_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostObserveMountScope,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
            let request = decode_mount_scope_request(body, peer, policy, now)?;
            let semantics = canonical_mount_scope_identity_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostObserveMountScopeIdentity,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP => {
            let request = crate::host_consumer_cgroup::decode_consumer_cgroup_request_v1(
                body, peer, policy, now,
            )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostObserveConsumerCgroup,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG => {
            let request = decode_mount_catalog_preparation(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::MountPrepareCatalog,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT => {
            let request = decode_destination_slot_request(body, peer, policy, now)?;
            let semantics = canonical_destination_slot_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::MountApplyDestinationSlot,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS => (
            AuthenticatedBrokerMethodSemanticsV1::MountInventoryDestinationSlots,
            decode_destination_slot_inventory_request(body, peer, policy, now)?,
            None,
        ),
        BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => {
            let request = decode_host_catalog_publication_request(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostPublishCatalog,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION => {
            let request = crate::decode_host_execution_apply_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostApplyExecution,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION => {
            let request = crate::decode_host_execution_query_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryExecution,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT => {
            let request = crate::host_argument_source::decode_host_runtime_argument_request_v1(
                body, peer, policy, now,
            )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostObserveRuntimeArgument,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => {
            let request =
                crate::host_output::decode_host_output_reserve_request_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostReserveExecutionOutput,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT => {
            let request =
                crate::host_output::decode_host_output_query_request_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryExecutionOutput,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT => {
            let request =
                crate::host_execution_argument::decode_host_execution_argument_observe_request_v1(
                    body, peer, policy, now,
                )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostObserveExecutionArgument,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT => {
            let request =
                crate::host_execution_argument::decode_host_execution_argument_query_request_v1(
                    body, peer, policy, now,
                )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryExecutionArgument,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY => {
            let request =
                crate::host_execution_no_apply::decode_host_execution_argument_no_apply_request_v1(
                    body, peer, policy, now,
                )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostTerminalNoApply,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY => {
            let request = crate::host_execution_no_apply::
                decode_host_execution_argument_query_no_apply_request_v1(
                    body, peer, policy, now,
                )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApply,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
            let request =
                crate::host_execution_no_apply::decode_host_no_apply_settlement_request_v2(
                    body, peer, policy, now,
                )?;
            if request.phase()
                != crate::host_execution_no_apply::HostNoApplySettlementPhaseV2::Preliminary
            {
                return Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod);
            }
            (
                AuthenticatedBrokerMethodSemanticsV1::HostSettleNoApplyPreliminary,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            let request =
                crate::host_execution_no_apply::decode_host_no_apply_settlement_query_request_v2(
                    body, peer, policy, now,
                )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApplySettlement,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => {
            let request =
                crate::storage_capture_candidate::decode_storage_capture_candidate_request_v1(
                    body, peer, policy, now,
                )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StorageCaptureCandidateReadback,
                *request.header(),
                Some(
                    *request
                        .query()
                        .argument_commitment(*request.header().request_id())?
                        .digest()
                        .as_bytes(),
                ),
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE => {
            let request = crate::decode_host_attach_gate_request_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostInstallAttachGate,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS => {
            let request = crate::decode_host_attach_readiness_request_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryAttachGateReadiness,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE => {
            let request = crate::decode_host_attach_route_query_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryAttachGateRoute,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => (
            AuthenticatedBrokerMethodSemanticsV1::StorageInventoryResources,
            decode_storage_resource_inventory_request(body, peer, policy, now)?,
            None,
        ),
        BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY => {
            let request = decode_storage_inventory_recovery_request_v1(body, peer, policy, now)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StorageRecoverInventory,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => (
            AuthenticatedBrokerMethodSemanticsV1::NetworkInventoryResources,
            decode_network_resource_inventory_request(body, peer, policy, now)?,
            None,
        ),
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => {
            let semantics = CanonicalStoragePreparationSemanticsV1::decode(body, peer, policy, now)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StoragePrepareCatalog,
                *semantics.header(),
                Some(method_digest(
                    REQUEST_SEMANTIC_DOMAIN,
                    method,
                    semantics.canonical_bytes(),
                )),
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
            let semantics = CanonicalStorageRepairSemanticsV1::decode(body, peer, policy, now)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StorageRepairWorkspacePin,
                *semantics.header(),
                Some(method_digest(
                    REQUEST_SEMANTIC_DOMAIN,
                    method,
                    semantics.canonical_bytes(),
                )),
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => {
            let request = decode_acquire_mount_source_request(body, peer, policy, now)?;
            let semantics = canonical_acquire_mount_source_semantics_v1(request.request())
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::MountAcquireSource,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
            let request = decode_release_mount_source_acquisition_request(body, peer, policy, now)?;
            let semantics =
                canonical_release_mount_source_acquisition_semantics_v1(request.request())
                    .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::MountReleaseSourceAcquisition,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => (
            AuthenticatedBrokerMethodSemanticsV1::MountInventorySourceAcquisitions,
            decode_mount_source_acquisition_inventory_request(body, peer, policy, now)?,
            None,
        ),
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
            let request = decode_atomic_storage_snapshot_request(body, peer, policy, now)?;
            let commitment = request.argument_commitment();
            (
                AuthenticatedBrokerMethodSemanticsV1::StorageAtomicSnapshot,
                *request.header(),
                Some(*commitment.digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => {
            let request = CanonicalStorageGuestRootSemanticsV1::decode(body, peer, policy, now)?;
            let commitment = request.argument_commitment();
            (
                AuthenticatedBrokerMethodSemanticsV1::StoragePopulateGuestRoot,
                *request.header(),
                Some(*commitment.digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_UNSPECIFIED => {
            return Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod);
        }
    };
    let outcome_context = match method {
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME => RequestOutcomeContextV1::HostObserve(
            decode_observe_runtime_request_v1(body, peer, policy, now)?,
        ),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => {
            RequestOutcomeContextV1::MountApply(decode_mount_request(body, peer, policy, now)?)
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => RequestOutcomeContextV1::NetworkApply(
            CanonicalNetworkSemanticsV1::decode(body, peer, policy, now)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?,
        ),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
            let catalog = bindings
                .storage_catalog
                .ok_or(AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding)?;
            RequestOutcomeContextV1::StorageApply(
                CanonicalStorageSemanticsV1::decode(body, catalog, peer, policy, now)
                    .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT => {
            RequestOutcomeContextV1::HostQuery(decode_query_runtime_effect_request_v1(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
            RequestOutcomeContextV1::PayloadScope(decode_payload_scope_request(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
            RequestOutcomeContextV1::MountScope(decode_mount_scope_request(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
            RequestOutcomeContextV1::MountScopeIdentity(decode_mount_scope_request(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP => {
            RequestOutcomeContextV1::HostConsumerCgroup(
                crate::host_consumer_cgroup::decode_consumer_cgroup_request_v1(
                    body, peer, policy, now,
                )?,
            )
        }
        BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => {
            let request = decode_acquire_mount_source_request(body, peer, policy, now)?;
            RequestOutcomeContextV1::MountAcquireSource(request.request().clone())
        }
        BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
            let request = decode_release_mount_source_acquisition_request(body, peer, policy, now)?;
            RequestOutcomeContextV1::MountReleaseSource(request.request().clone())
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => {
            RequestOutcomeContextV1::StoragePrepare(
                CanonicalStoragePreparationSemanticsV1::decode(body, peer, policy, now)
                    .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?,
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
            RequestOutcomeContextV1::StorageRepair(
                CanonicalStorageRepairSemanticsV1::decode(body, peer, policy, now)
                    .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?,
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => {
            RequestOutcomeContextV1::StorageGuestRoot(CanonicalStorageGuestRootSemanticsV1::decode(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG => {
            RequestOutcomeContextV1::MountPrepareCatalog(decode_mount_catalog_preparation(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT => {
            RequestOutcomeContextV1::MountDestinationSlot(decode_destination_slot_request(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => {
            RequestOutcomeContextV1::HostPublishCatalog(decode_host_catalog_publication_request(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION => {
            RequestOutcomeContextV1::HostExecutionApply(crate::decode_host_execution_apply_v1(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION => {
            RequestOutcomeContextV1::HostExecutionQuery(crate::decode_host_execution_query_v1(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT => {
            crate::host_argument_source::decode_host_runtime_argument_request_v1(
                body, peer, policy, now,
            )?;
            RequestOutcomeContextV1::None
        }
        BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => {
            RequestOutcomeContextV1::HostOutputReserve(
                crate::host_output::decode_host_output_reserve_request_v1(body, peer, policy, now)?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT => {
            RequestOutcomeContextV1::HostOutputQuery(
                crate::host_output::decode_host_output_query_request_v1(body, peer, policy, now)?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT => {
            RequestOutcomeContextV1::HostArgumentObserve(
                crate::host_execution_argument::decode_host_execution_argument_observe_request_v1(
                    body, peer, policy, now,
                )?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT => {
            RequestOutcomeContextV1::HostArgumentQuery(
                crate::host_execution_argument::decode_host_execution_argument_query_request_v1(
                    body, peer, policy, now,
                )?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY => {
            RequestOutcomeContextV1::HostNoApply(
                crate::host_execution_no_apply::decode_host_execution_argument_no_apply_request_v1(
                    body, peer, policy, now,
                )?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY => {
            RequestOutcomeContextV1::HostNoApplyQuery(
                crate::host_execution_no_apply::
                    decode_host_execution_argument_query_no_apply_request_v1(
                        body, peer, policy, now,
                    )?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
            RequestOutcomeContextV1::HostNoApplySettlement(
                crate::host_execution_no_apply::decode_host_no_apply_settlement_request_v2(
                    body, peer, policy, now,
                )?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            RequestOutcomeContextV1::HostNoApplySettlementQuery(
                crate::host_execution_no_apply::decode_host_no_apply_settlement_query_request_v2(
                    body, peer, policy, now,
                )?,
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => {
            crate::storage_capture_candidate::decode_storage_capture_candidate_request_v1(
                body, peer, policy, now,
            )?;
            RequestOutcomeContextV1::None
        }
        BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE => {
            RequestOutcomeContextV1::HostAttachGate(crate::decode_host_attach_gate_request_v1(
                body, peer, policy, now,
            )?)
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS => {
            crate::decode_host_attach_readiness_request_v1(body, peer, policy, now)?;
            RequestOutcomeContextV1::HostAttachReadiness
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE => {
            RequestOutcomeContextV1::HostAttachRoute(crate::decode_host_attach_route_query_v1(
                body, peer, policy, now,
            )?)
        }
        _ => RequestOutcomeContextV1::None,
    };
    Ok(ValidatedRequestSemanticV1 {
        kind,
        header,
        commitment: portable_commitment
            .unwrap_or_else(|| method_digest(REQUEST_SEMANTIC_DOMAIN, method, body)),
        catalog_binding: match method {
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY => bindings.storage_catalog.map(|catalog| {
                authenticated_catalog_generation_binding_v1(
                    catalog.generation(),
                    *catalog.digest().as_bytes(),
                )
            }),
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY => bindings
                .mount_catalog
                .map(|catalog| *catalog.digest().as_bytes()),
            _ => None,
        },
        published_catalog_binding: match &outcome_context {
            RequestOutcomeContextV1::HostPublishCatalog(publication) => {
                Some(authenticated_catalog_generation_binding_v1(
                    publication.catalog_generation(),
                    *publication.catalog_digest().as_bytes(),
                ))
            }
            _ => None,
        },
        outcome_context,
    })
}

fn decode_recorded_host_no_apply(
    method: BrokerMethod,
    context: &RequestOutcomeContextV1,
    body: &[u8],
    session_binding: [u8; 32],
    signed_request_digest: [u8; 32],
) -> Result<
    Option<crate::host_execution_no_apply::HostExecutionNoApplyRecordV1>,
    AuthenticatedBrokerMethodErrorV1,
> {
    use crate::host_execution_no_apply::{
        HostExecutionNoApplyReadbackV1, decode_host_execution_argument_no_apply_response_v1,
        decode_host_execution_argument_query_no_apply_response_v1,
    };

    match (method, context) {
        (
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
            RequestOutcomeContextV1::HostNoApply(original),
        ) => Ok(Some(decode_host_execution_argument_no_apply_response_v1(
            body,
            original,
            session_binding,
            signed_request_digest,
        )?)),
        (
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY,
            RequestOutcomeContextV1::HostNoApplyQuery(original),
        ) => Ok(
            match decode_host_execution_argument_query_no_apply_response_v1(body, original)? {
                HostExecutionNoApplyReadbackV1::Absent => None,
                HostExecutionNoApplyReadbackV1::Recorded(record) => Some(record),
            },
        ),
        _ => Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink),
    }
}

fn validate_success_semantics(
    request: &AuthenticatedBrokerMethodRequestV1,
    body: &[u8],
) -> Result<Option<[u8; 32]>, AuthenticatedBrokerMethodErrorV1> {
    let maximum = request.maximum_response_bytes();
    match request.method() {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
            validate_runtime_effect_receipt_for_apply(body, request.exact_body())?;
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME => {
            let RequestOutcomeContextV1::HostObserve(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            validate_runtime_observation(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME => {
            validate_runtime_inventory(body)?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => {
            let RequestOutcomeContextV1::MountApply(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            return Ok(
                decode_mount_result_for_apply(body, original, request.exact_body())?
                    .filesystem_worker_qualification_commitment(),
            );
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES => {
            decode_mount_inventory_response(body, maximum)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
            let RequestOutcomeContextV1::StorageApply(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            validate_storage_apply_response(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => {
            let RequestOutcomeContextV1::NetworkApply(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            validate_network_apply_response(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY => {
            validate_network_inventory(body)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT => {
            let RequestOutcomeContextV1::HostQuery(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            let original_apply = original
                .original_apply_candidate()
                .canonical_request()
                .ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
            decode_query_runtime_effect_response(body, original_apply)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE => {
            let RequestOutcomeContextV1::PayloadScope(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            decode_payload_scope_response(body, original.fence(), original.runtime_handle())?;
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE => {
            let RequestOutcomeContextV1::MountScope(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            decode_mount_scope_response(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1 => {
            let RequestOutcomeContextV1::MountScopeIdentity(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            decode_mount_scope_identity_response_v1(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG => {
            let RequestOutcomeContextV1::MountPrepareCatalog(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            decode_mount_catalog_preparation_response(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT => {
            let RequestOutcomeContextV1::MountDestinationSlot(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            validate_destination_slot_apply_response(
                body,
                maximum,
                original,
                request.exact_body(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS => {
            decode_destination_slot_inventory_response(body, maximum)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => {
            let RequestOutcomeContextV1::HostPublishCatalog(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            let response = decode_host_catalog_publication_response(body)?;
            if response.generation() != original.catalog_generation()
                || response.catalog_digest() != original.catalog_digest()
            {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION => {
            let RequestOutcomeContextV1::HostExecutionApply(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::decode_host_execution_outcome_v1(
                body,
                original.operation_id(),
                original.execution_id(),
                original.source_commitment(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION => {
            let RequestOutcomeContextV1::HostExecutionQuery(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::decode_host_execution_outcome_v1(
                body,
                original.operation_id(),
                original.execution_id(),
                original.source_commitment(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME_ARGUMENT => {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => {
            let RequestOutcomeContextV1::HostOutputReserve(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_output::decode_host_output_reservation_response_v1(
                body,
                original.locator(),
                false,
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT => {
            let RequestOutcomeContextV1::HostOutputQuery(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_output::decode_host_output_reservation_response_v1(
                body,
                original.locator(),
                true,
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP => {
            let RequestOutcomeContextV1::HostConsumerCgroup(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_consumer_cgroup::decode_consumer_cgroup_response_v1(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE => {
            let RequestOutcomeContextV1::HostAttachGate(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::decode_host_attach_gate_evidence_v1(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS => {
            if !matches!(
                &request.outcome_context,
                RequestOutcomeContextV1::HostAttachReadiness
            ) {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            }
            crate::decode_host_attach_readiness_v1(body)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE => {
            let RequestOutcomeContextV1::HostAttachRoute(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::decode_host_attach_route_evidence_v1(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => {
            decode_storage_resource_inventory_response(body, maximum)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY => {
            decode_storage_inventory_recovery_response_v1(body, maximum)?;
        }
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => {
            decode_network_resource_inventory_response(body, maximum)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => {
            let RequestOutcomeContextV1::StoragePrepare(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            validate_storage_preparation_response(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
            let RequestOutcomeContextV1::StorageRepair(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            validate_storage_repair_response(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => {
            let RequestOutcomeContextV1::MountAcquireSource(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            decode_acquire_mount_source_response(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
            let RequestOutcomeContextV1::MountReleaseSource(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            decode_release_mount_source_acquisition_response(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => {
            decode_mount_source_acquisition_inventory_response_with_maximum(body, maximum)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
            decode_atomic_storage_snapshot_response(body)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => {
            let RequestOutcomeContextV1::StorageGuestRoot(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            let proof = decode_storage_guest_root_response_v1(body, maximum)?;
            if proof.sandbox != *original.fence().sandbox_id()
                || proof.incarnation != *original.fence().incarnation_id()
                || proof.assignment_epoch != original.fence().assignment_epoch()
                || proof.assignment_digest != *original.fence().assignment_digest()
                || proof.workspace_handle != original.workspace_handle()
                || proof.creation_operation != original.creation_operation_id()
            {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT => {
            let RequestOutcomeContextV1::HostArgumentObserve(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_execution_argument::decode_host_execution_argument_observe_response_v1(
                body,
                original.canonical_attempt(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT => {
            let RequestOutcomeContextV1::HostArgumentQuery(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_execution_argument::decode_host_execution_argument_query_response_v1(
                body,
                original.canonical_attempt(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY => {
            decode_recorded_host_no_apply(
                request.method(),
                &request.outcome_context,
                body,
                request.session_binding(),
                request.signed_request_digest(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
            let RequestOutcomeContextV1::HostNoApplySettlement(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_execution_no_apply::decode_host_no_apply_settlement_response_v2(
                body,
                original,
                request.session_binding(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            let RequestOutcomeContextV1::HostNoApplySettlementQuery(original) =
                &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_execution_no_apply::decode_host_no_apply_settlement_query_response_v2(
                body, original,
            )?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => {
            return Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod);
        }
        BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
        | BrokerMethod::BROKER_METHOD_UNSPECIFIED => {
            return Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod);
        }
    }
    Ok(None)
}

fn validate_header_profile(
    header: &ValidatedHeader,
    profile: &BrokerSessionMethodProfileV1,
    traffic: &BrokerSessionTrafficStateV1,
) -> Result<(), AuthenticatedBrokerMethodErrorV1> {
    if (
        header.protocol_version().major(),
        header.protocol_version().minor(),
    ) != profile.version()
        || header.audience() != profile.audience()
        || header.audience() != traffic.transcript().audience()
    {
        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
    }
    Ok(())
}

fn validate_simple_inventory_request(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
    protocol: aos_sandbox_core::ProtocolId,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    let request = InventoryNetworksRequest::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    crate::validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        protocol,
        now,
    )
}

fn profile_protocol(
    method: BrokerMethod,
) -> Result<aos_sandbox_core::ProtocolId, AuthenticatedBrokerMethodErrorV1> {
    authenticated_broker_method_profile_v1(method)
        .map(|profile| protocol_id_for_profile(profile.protocol()))
        .ok_or(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod)
}

fn method_digest(domain: &[u8], method: BrokerMethod, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((method as i32).to_be_bytes());
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

/// Commits one exact catalog generation and digest for protected-state comparison.
#[must_use]
pub fn authenticated_catalog_generation_binding_v1(generation: u64, digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CATALOG_GENERATION_BINDING_DOMAIN);
    hasher.update(generation.to_be_bytes());
    hasher.update(digest);
    hasher.finalize().into()
}
