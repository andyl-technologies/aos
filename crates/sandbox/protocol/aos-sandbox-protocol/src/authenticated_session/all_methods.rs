//! Method-complete authenticated broker semantic admission.
//!
//! The established authenticated bootstrap owns a specialized Network
//! inventory path. This module supplies the dormant uniform path for every
//! method in the same closed authenticated profile. It composes canonical signed
//! packet verification with the existing method decoders and retains exact
//! body bytes plus a method-separated semantic commitment. It does not itself
//! invoke a service, consume descriptors, authorize an effect, or write durable
//! state.

use aos_sandbox_api::aos::sandbox::local::v1::{
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
    canonical_release_mount_source_acquisition_semantics_v1, decode_storage_guest_root_response_v2,
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
/// Retains the reached closed Storage terminal comparison without authority.
pub mod outcome_capture;
pub mod request_capture;
use outcome_capture::{AuthenticatedBrokerMethodOutcomeCaptureV1, StorageBodyCaptureV1};
use aos_sandbox_model::retained::CaptureValueV1;
mod host;
mod mount;
mod network;
#[cfg(test)]
mod no_apply_tests;
mod storage;
#[cfg(test)]
mod storage_capture_tests;
#[cfg(test)]
mod delete_inventory_cut_tests;

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
                aos_sandbox_model::ObjectDigest::from_bytes(digest),
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
                            aos_sandbox_model::ObjectDigest::from_bytes(digest),
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
    /// Mount's exact no-slot namespace-anchor effect.
    MountApplyAttachmentAnchorV1,
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
    /// Storage-audience Host output readback of one protected Controller attempt.
    HostObserveStorageOutput,
    /// Signed, one-shot Controller attempt for a fresh Host-owned Guest readback.
    HostObserveExecutionArgument,
    /// Non-consuming preparation bound to the actual retained Agent and Session.
    HostPrepareExecutionArgumentV2,
    /// Predurable availability and accepted binding on the same paid Host owner.
    HostPrepareExecutionAvailabilityV2,
    /// Predurable availability and accepted binding on the same paid Storage owner.
    StoragePrepareExecutionAvailabilityV2,
    /// Exact native acceptance before the one-shot Guest observation.
    HostAcceptExecutionArgumentV2,
    /// Read-only historical query of the original Host argument attempt.
    HostQueryExecutionArgument,
    /// Mutating Host terminal settlement before execution Apply.
    HostTerminalNoApply,
    /// Read-only historical Host no-Apply marker query.
    HostQueryNoApply,
    /// Signed finite Host settlement command; no detached Controller CAS authority.
    HostSettleNoApplyV2,
    /// Read-only signed Host settlement history query.
    HostQueryNoApplySettlement,
    /// Read-only Storage capture candidate; issuer and signed outcome are closed.
    StorageCaptureCandidateReadback,
    /// Controller-signed original logical output registration.
    StorageReserveExecutionOutput,
    /// Historical original logical output registration query.
    StorageQueryExecutionOutput,
    /// Separately signed physical capture; no logical-output grant substitutes it.
    StorageReserveExecutionCapture,
    /// Fresh read-only query of the original physical capture attempt.
    StorageQueryExecutionCapture,
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
    /// Original pending Nix Start's independently authorized Storage preparation.
    StoragePrepareNixGeneration,
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
    /// Exact purpose-57 FUSE intent; successful worker/read outcomes remain closed.
    MountFuseReserveIntent,
    /// Exact four-role purpose-56 preparation; terminal/read outcomes stay closed.
    HostPrepareFuseWorkerSession,
    /// Original-disclosure resolution of one independently preadmitted recipe.
    NixResolveProtectedRecipe,
    /// Exact leased realization of an admitted derivation in the fixed domain.
    NixRealizeAuthorizedDerivation,
    /// Fresh readback of one exact original realization and retained root set.
    NixQueryAuthorizedPathInfo,
    /// Opt-in denial-only preparation/readback through the existing owner.
    GitProjectCoverage,
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
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1 => {
            AuthenticatedBrokerMethodSemanticsV1::GitProjectCoverage
        }
        BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::NixResolveProtectedRecipe
        }
        BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::NixRealizeAuthorizedDerivation
        }
        BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::NixQueryAuthorizedPathInfo
        }
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
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 => {
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
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1 => {
            AuthenticatedBrokerMethodSemanticsV1::MountApplyAttachmentAnchorV1
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
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => {
            AuthenticatedBrokerMethodSemanticsV1::HostObserveStorageOutput
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT => {
            AuthenticatedBrokerMethodSemanticsV1::HostObserveExecutionArgument
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::HostPrepareExecutionArgumentV2
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::HostPrepareExecutionAvailabilityV2
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::StoragePrepareExecutionAvailabilityV2
        }
        BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::HostAcceptExecutionArgumentV2
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
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1 => {
            AuthenticatedBrokerMethodSemanticsV1::StoragePrepareNixGeneration
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
        BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1 => {
            AuthenticatedBrokerMethodSemanticsV1::MountFuseReserveIntent
        }
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
            AuthenticatedBrokerMethodSemanticsV1::StorageAtomicSnapshot
        }
        BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => {
            AuthenticatedBrokerMethodSemanticsV1::StoragePopulateGuestRoot
        }
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::HostSettleNoApplyV2
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApplySettlement
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1 => {
            AuthenticatedBrokerMethodSemanticsV1::HostPrepareFuseWorkerSession
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT => {
            AuthenticatedBrokerMethodSemanticsV1::StorageReserveExecutionOutput
        }
        BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT => {
            AuthenticatedBrokerMethodSemanticsV1::StorageQueryExecutionOutput
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1 => {
            AuthenticatedBrokerMethodSemanticsV1::StorageReserveExecutionCapture
        }
        BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1 => {
            AuthenticatedBrokerMethodSemanticsV1::StorageQueryExecutionCapture
        }
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

    /// Borrows the sole canonical availability context from this signed request.
    ///
    /// This avoids decoding or copying its proposal during native completion.
    /// The context is DATA and supplies no paid receiver or current lease.
    #[must_use]
    pub fn execution_availability_data_v2(&self)
        -> Option<&crate::execution_availability::ValidatedExecutionAvailabilityRequestV2>
    {
        if !matches!(self.method,
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2)
        { return None; }
        match &self.outcome_context {
            RequestOutcomeContextV1::ExecutionAvailabilityV2(original) => Some(original),
            _ => None,
        }
    }

    /// Borrows the canonical held42 command without reconstructing its owner.
    #[must_use]
    pub fn host_held_no_apply_settlement_data_v2(&self)
        -> Option<&crate::host_execution_no_apply::held_settlement_transport::ValidatedHostHeldNoApplySettlementRequestV2>
    {
        if self.method != BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 {
            return None;
        }
        match &self.outcome_context {
            RequestOutcomeContextV1::HostHeldNoApplySettlementV2(original) => Some(original),
            _ => None,
        }
    }

    /// Borrows the exact closed43 current-lease query from this signed request.
    ///
    /// Its comparison and Root nonce are DATA, never a retained native owner.
    #[must_use]
    pub fn host_no_apply_current_lease_query_data_v2(&self)
        -> Option<&crate::host_execution_no_apply::current_lease_transport::ValidatedHostNoApplyCurrentLeaseQueryV2>
    {
        if self.method != BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 {
            return None;
        }
        match &self.outcome_context {
            RequestOutcomeContextV1::HostNoApplyCurrentLeaseQueryV2(query) => Some(query),
            _ => None,
        }
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

    /// Borrows the canonical Host Query selector already retained by this request.
    ///
    /// This is parsed authenticated Session DATA; actual Host native admission,
    /// currentness and fresh read-clock checks remain independently required.
    #[must_use]
    pub fn host_execution_query_data_v3(&self) -> Option<&crate::host_execution::ValidatedHostExecutionQueryV1> {
        match &self.outcome_context {
            RequestOutcomeContextV1::HostExecutionQuery(query) => Some(query),
            _ => None,
        }
    }

    /// Borrows the exact parsed early no-Apply branch from this signed request.
    ///
    /// This is Session DATA. The actual HostState grant admission, paid native
    /// owner and same protected runtime lock remain separately required.
    pub fn host_before_argument_no_apply_data_v2(&self)
        -> Option<&crate::host_execution_no_apply::ValidatedHostBeforeArgumentNoApplyRequestV2> {
        match &self.outcome_context {
            RequestOutcomeContextV1::HostBeforeArgumentNoApply(request)
                | RequestOutcomeContextV1::HostBeforeArgumentNoApplyQuery(request) => Some(request),
            _ => None,
        }
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

    /// Borrows the original strictly decoded Create Prepare meaning as DATA.
    ///
    /// This shares the retained request context without decoding a second
    /// body or constructing a peer. The later Apply issuer must independently
    /// join the actual completed C9, original intake, currentness and new grant;
    /// neither this observation nor the old Prepare plan authorizes Apply.
    #[must_use]
    pub fn storage_create_preparation_data_v1(
        &self,
    ) -> Option<&CanonicalStoragePreparationSemanticsV1> {
        match &self.outcome_context {
            RequestOutcomeContextV1::StoragePrepare(original)
                if self.method == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                    && matches!(original.operation(),
                        crate::semantics::StoragePreparationOperationV1::CreateWorkspace { .. }) =>
                Some(original),
            _ => None,
        }
    }

    /// Borrows the same admitted Apply request's canonical semantics as DATA.
    ///
    /// This has no Session, native workspace, publication or Root authority.
    #[must_use]
    pub fn storage_apply_data_v1(&self) -> Option<&CanonicalStorageSemanticsV1> {
        match &self.outcome_context {
            RequestOutcomeContextV1::StorageApply(value) if self.method == BrokerMethod::BROKER_METHOD_STORAGE_APPLY => Some(value),
            _ => None,
        }
    }

    /// Borrows the same admitted method31 canonical semantics as DATA.
    ///
    /// The original peer/header decoder owns this model. Native workspace,
    /// current-publication, lease and Root authority remain separate lenders.
    #[must_use]
    pub fn storage_guest_root_data_v2(&self) -> Option<&CanonicalStorageGuestRootSemanticsV1> {
        match &self.outcome_context {
            RequestOutcomeContextV1::StorageGuestRoot(value)
                if self.method == BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT => Some(value),
            _ => None,
        }
    }

    /// Borrows the sole admitted Host catalog request context as comparison DATA.
    ///
    /// The protected request decoder already validated its Header, peer,
    /// descriptor roles and exact body. This view supplies no publication,
    /// currentness, native receipt or activation authority.
    #[must_use]
    pub fn host_catalog_publication_data_v2(&self)
        -> Option<&crate::host_catalog::ValidatedHostCatalogPublication> {
        match &self.outcome_context {
            RequestOutcomeContextV1::HostPublishCatalog(original)
                if self.method == BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => Some(original),
            _ => None,
        }
    }

    /// Borrows the actual admitted version-two preparation semantics as DATA.
    ///
    /// The retained descriptor, native receiving loan, signed domain admission
    /// and protected reservation remain independent requirements. Lifecycle
    /// method nine cannot lend a preparation context through this selector.
    #[must_use]
    pub fn network_preparation_data_v2(&self) -> Option<&CanonicalNetworkSemanticsV1> {
        match &self.outcome_context {
            RequestOutcomeContextV1::NetworkApply(original)
                if self.method == BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
                    && original.preparation_content_reference_v2().is_some() => Some(original),
            _ => None,
        }
    }

    /// Borrows only authenticated lifecycle Destroy9 semantics as DATA.
    ///
    /// Signed domain admission, the actual enrolled Source/F loan, native
    /// worker custody and every physical frontier remain independent gates.
    /// Prepare63 and other lifecycle actions cannot use this selector.
    #[must_use]
    pub fn network_destroy_data_v4(&self) -> Option<&CanonicalNetworkSemanticsV1> {
        match &self.outcome_context {
            RequestOutcomeContextV1::NetworkApply(original)
                if self.method == BrokerMethod::BROKER_METHOD_NETWORK_APPLY
                    && matches!(original.operation(),
                        crate::semantics::network::NetworkOperation::Destroy { .. }) => Some(original),
            _ => None,
        }
    }

    /// Borrows the sole admitted Mount62 request context as comparison DATA.
    ///
    /// This lends no namespace, native receipt, currentness or execution grant.
    #[must_use]
    pub fn mount_attachment_anchor_data_v2(&self)
        -> Option<&crate::mount_attachment_anchor::ValidatedAttachmentAnchorRequestV1> {
        match &self.outcome_context {
            RequestOutcomeContextV1::MountAttachmentAnchorV1(original)
                if self.method == BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1 => Some(original),
            _ => None,
        }
    }

    /// Borrows the whole explicitly versioned ongoing Capture source DATA.
    ///
    /// Actual native admission
    /// must verify the same signed request and keep its original lifetime owner.
    #[must_use]
    pub fn storage_execution_capture_source_ongoing_v2(&self)
        -> Option<&crate::storage_capture_grant::StorageCaptureGrantSourceV2>
    {
        match &self.outcome_context {
            RequestOutcomeContextV1::StorageCaptureReserve(request) => request.ongoing_source_v2(),
            RequestOutcomeContextV1::StorageCaptureQuery(request) => request.ongoing_source_v2(),
            _ => None,
        }
    }


    /// Borrows the crosslinked original registration body on physical Reserve only.
    /// Historical bytes are comparison DATA; signatures and physical custody
    /// remain obligations of the actual Storage receiver.
    #[must_use]
    pub fn storage_execution_capture_original_output_request_v2(&self) -> Option<&[u8]> {
        match &self.outcome_context {
            RequestOutcomeContextV1::StorageCaptureReserve(request) =>
                Some(request.canonical_original_storage_output_request_v2()),
            _ => None,
        }
    }

    /// Borrows the same already-decoded historical registration records.
    #[must_use]
    pub fn storage_execution_capture_output_records_v2(&self)
        -> Option<&crate::storage_output_reserve::StorageOutputReserveRecordsV1>
    {
        match &self.outcome_context {
            RequestOutcomeContextV1::StorageCaptureReserve(request) =>
                Some(request.original_output_records_v2()),
            _ => None,
        }
    }

    /// Returns the digest of the complete signed ClientRecord artifact.
    #[must_use]
    pub const fn signed_request_digest(&self) -> [u8; 32] {
        self.signed_request_digest
    }

    /// Borrows the already admitted closed coverage request as DATA.
    ///
    /// This avoids decoding its wire/header again during an independent
    /// original-pair comparison. The borrow conveys no live peer, journal,
    /// floor, allocation or coverage authority.
    #[doc(hidden)]
    #[must_use]
    pub fn git_coverage_request_v1(
        &self,
    ) -> Option<&crate::git_project_coverage::ValidatedGitProjectCoverageRequestV1> {
        match &self.outcome_context {
            RequestOutcomeContextV1::GitCoverage(request) => Some(request),
            _ => None,
        }
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

/// Borrows the exact signed Host outcome with its explicit no-Apply variant.
///
/// Neither variant supplies a live settlement lease, Root floor or Controller
/// terminal permission. Original authenticated archives remain separately held.
pub struct AuthenticatedHostNoApplyReadbackV2<'outcome> {
    outcome: &'outcome AuthenticatedBrokerMethodOutcomeV1,
    record: crate::host_execution_no_apply::HostExecutionNoApplyRecordV2,
}

impl AuthenticatedHostNoApplyReadbackV2<'_> {
    /// Borrows the exact structurally and cryptographically matched variant.
    pub const fn record(&self) -> &crate::host_execution_no_apply::HostExecutionNoApplyRecordV2 {
        &self.record
    }

    /// Borrows the complete authenticated signed request and outcome archive.
    pub const fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 { self.outcome }
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

    /// Reads either exact no-Apply branch from its signed client outcome.
    ///
    /// An error outcome or explicit historical absence returns None. A closed
    /// before-argument record preserves its distinct source and terminal archive;
    /// no absent original argument fields are synthesized for the V1 API.
    ///
    /// # Errors
    /// Rejects changed signed direction, method, semantic commitment, source,
    /// terminal Session identity or canonical variant.
    pub fn recorded_host_no_apply_v2(&self)
        -> Result<Option<AuthenticatedHostNoApplyReadbackV2<'_>>, AuthenticatedBrokerMethodErrorV1> {
        if !matches!(self.method, BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY) { return Ok(None); }
        if self.direction != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || self.request.direction != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || self.method != self.request.method
        { return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink); }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, semantic_commitment, .. } = &self.result
        else { return Ok(None); };
        if *semantic_commitment != method_digest(OUTCOME_SEMANTIC_DOMAIN, self.method, exact_body) {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        let record = decode_recorded_host_no_apply_v2(self.method, &self.request.outcome_context,
            exact_body, self.request.session_binding, self.request.signed_request_digest)?;
        Ok(record.map(|record| AuthenticatedHostNoApplyReadbackV2 { outcome: self, record }))
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
        if matches!(self.request.outcome_context, RequestOutcomeContextV1::HostNoApplyCurrentLeaseQueryV2(_)) {
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

    /// Reads lease DATA from the exact authenticated held42 response.
    ///
    /// This validates comparison DATA only; it cannot reconstruct the native
    /// Host owner or authorize a Controller append or positive disposal.
    ///
    /// # Errors
    /// Rejects changed direction, canonical context, semantic commitment,
    /// terminal, current request or immutable native lease coordinates.
    pub fn recorded_host_held_no_apply_lease_v2(&self)
        -> Result<Option<crate::host_execution_no_apply::current_lease::CurrentHostNoApplyLeaseDataV2>, AuthenticatedBrokerMethodErrorV1>
    {
        let Some(original) = self.request.host_held_no_apply_settlement_data_v2() else {
            return Ok(None);
        };
        if self.direction != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || self.request.direction != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || self.method != self.request.method
        { return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink); }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, semantic_commitment, .. } = &self.result
        else { return Ok(None); };
        if *semantic_commitment != method_digest(OUTCOME_SEMANTIC_DOMAIN, self.method, exact_body) {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        crate::host_execution_no_apply::held_settlement_transport::decode_host_held_no_apply_settlement_response_v2(
            exact_body, original, self.request.session_binding, self.request.signed_request_digest,
        ).map(Some).map_err(Into::into)
    }

    /// Reads current lease DATA from an actual authenticated closed43 outcome.
    ///
    /// This joins the fresh Root read nonce through the exact signed request.
    /// Native retained custody and Root's own paid nonce remain separate checks.
    ///
    /// # Errors
    /// Rejects changed direction, semantic commitment, Session/request identity,
    /// native interval, original terminal, cuts/head/epoch or observed deadline.
    pub fn recorded_host_no_apply_current_lease_v2(&self)
        -> Result<Option<crate::host_execution_no_apply::current_lease::CurrentHostNoApplyLeaseDataV2>, AuthenticatedBrokerMethodErrorV1>
    {
        if self.method != BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 {
            return Ok(None);
        }
        let Some(original) = self.request.host_no_apply_current_lease_query_data_v2() else {
            return Ok(None);
        };
        if self.direction != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || self.request.direction != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || self.method != self.request.method
        { return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink); }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, semantic_commitment, .. } = &self.result else {
            return Ok(None);
        };
        if *semantic_commitment != method_digest(OUTCOME_SEMANTIC_DOMAIN, self.method, exact_body) {
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        crate::host_execution_no_apply::current_lease_transport::decode_host_no_apply_current_lease_response_v2(
            exact_body, original, self.request.session_binding(), self.request.signed_request_digest(),
        ).map(Some).map_err(Into::into)
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
    admit_authenticated_broker_method_request_engine(direction, traffic, bytes, retained_replay,
        actual_descriptor_count, peer, policy, now_boottime_nanoseconds, bindings, context, None)
}

fn admit_authenticated_broker_method_request_engine(
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
    capture: Option<&mut request_capture::AuthenticatedBrokerMethodRequestCaptureV1>,
) -> Result<AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
    let selected = capture.is_some();
    let (canonical_decode, canonical_slot, raw_slot, envelope_slot, body_slot, admission_capture, admission_slot, replay_slot, authorization_slot, semantic_slot) =
        match capture {
            Some(capture) => (Some(&mut capture.canonical_decode), Some(&mut capture.canonical),
                Some(&mut capture.raw_envelope), Some(&mut capture.envelope), Some(&mut capture.body),
                Some(&mut capture.traffic), Some(&mut capture.admission), Some(&mut capture.replay),
                Some(&mut capture.authorization), Some(&mut capture.semantic)),
            None => (None, None, None, None, None, None, None, None, None, None),
        };
    let canonical = match canonical_decode {
        Some(capture) => {
            aos_sandbox_broker_session_protocol::projection::decode_canonical_request_retaining_v1(bytes, capture)
                .map_err(BrokerSessionSequenceError::from)?;
            capture.take_model_once().map_err(BrokerSessionSequenceError::from)?
        }
        None => decode_canonical_request_v1(bytes).map_err(BrokerSessionSequenceError::from)?,
    };
    let canonical = CaptureValueV1::new(Some(canonical), canonical_slot);
    let canonical = canonical.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
    let method = canonical.signed_artifact().method();
    let adapter = authenticated_broker_method_adapter_v1(method)
        .ok_or(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod)?;
    let profile = adapter.profile();
    if canonical.message().method.as_known() != Some(method) || profile.method() != method {
        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
    }
    if actual_descriptor_count != profile.request_descriptor_roles().len() {
        return Err(ProtocolValidationError::DescriptorTableMismatch.into());
    }
    // Both selected request profiles have no descriptors. Inventory forbids
    // authorization; Prepare keeps the ordinary required-artifact checks and
    // runs the same four Core validators into actual retained destinations.
    if selected && (!matches!(method,
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            | BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
            | BrokerMethod::BROKER_METHOD_NETWORK_APPLY)
        || (method == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            && canonical.message().authorization.as_option().is_some())) {
        return Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod);
    }
    if selected && !canonical.message().descriptors.is_empty() {
        return Err(ProtocolValidationError::DescriptorTableMismatch.into());
    }
    let envelope = crate::session::validate_authenticated_request_envelope_retaining_authorization_engine(
        canonical.message().clone(),
        protocol_id_for_profile(profile.protocol()),
        actual_descriptor_count, raw_slot, authorization_slot,
    )?;
    let envelope = CaptureValueV1::new(Some(envelope), envelope_slot);
    let envelope_ref = envelope.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
    validate_request_against_profile(envelope_ref, &profile)?;

    // A byte-exact request retained by the protected owner is classified by
    // the authenticated traffic state before any live deadline check. The
    // retained semantic object was admitted when it was fresh; replay may be
    // needed after that deadline solely to recover its exact terminal result.
    if let Some(retained) = retained_replay.filter(|retained| {
        retained.canonical_packet() == bytes
            && retained.direction() == direction
            && retained.method() == method
            && retained.semantics() == adapter.semantics()
            && retained.exact_body() == envelope_ref.body()
            && retained.peer() == peer
            && retained.peer_policy() == policy
            && retained.session_binding() == traffic.transcript().session_binding()
    }) {
        let admission = request_capture::traffic_admission_value(traffic, canonical,
            retained.request_id(), retained.maximum_response_bytes(), context, admission_capture)?;
        let admission = CaptureValueV1::new(Some(admission), admission_slot);
        return match admission.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)? {
            BrokerRequestAdmissionV1::ExactReplay(replay) => {
                validate_exact_authenticated_request_replay_v1(replay, retained, bytes)?;
                match admission.take().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)? {
                    BrokerRequestAdmissionV1::ExactReplay(replay) =>
                        Ok(AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(replay)),
                    BrokerRequestAdmissionV1::New { .. } => Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation),
                }
            }
            BrokerRequestAdmissionV1::New { .. } => {
                Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation)
            }
        };
    }

    let semantic = validate_request_semantics_engine(
        method,
        envelope_ref.body(),
        envelope_ref
            .descriptors()
            .iter()
            .map(|entry| entry.role())
            .collect::<Vec<_>>()
            .as_slice(),
        peer,
        policy,
        now_boottime_nanoseconds,
        bindings, body_slot,
    )?;
    let semantic = CaptureValueV1::new(Some(semantic), semantic_slot);
    let semantic_ref = semantic.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
    if semantic_ref.kind != adapter.semantics() {
        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
    }
    validate_header_profile(&semantic_ref.header, &profile, traffic)?;

    let admission = request_capture::traffic_admission_value(traffic, canonical,
        *semantic_ref.header.request_id(), semantic_ref.header.maximum_response_bytes(), context, admission_capture)?;
    let admission = CaptureValueV1::new(Some(admission), admission_slot);
    match admission.take().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)? {
        BrokerRequestAdmissionV1::New {
            request,
            next_state,
        } => {
            let semantic = semantic.take().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
            Ok(AuthenticatedBrokerMethodRequestAdmissionV1::New {
                request: AuthenticatedBrokerMethodRequestV1 {
                    direction,
                    method,
                    semantics: semantic.kind,
                    canonical_packet: bytes.to_vec(),
                    exact_body: envelope_ref.body().to_vec(),
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
                    envelope: envelope.take().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?,
                    outcome_context: semantic.outcome_context,
                },
                next_traffic: next_state,
            })
        },
        BrokerRequestAdmissionV1::ExactReplay(replay) => {
            let replay = CaptureValueV1::new(Some(replay), replay_slot);
            let retained =
                retained_replay.ok_or(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation)?;
            if retained.direction() != direction {
                return Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation);
            }
            validate_exact_authenticated_request_replay_v1(replay.as_ref()
                .ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?, retained, bytes)?;
            Ok(AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(replay.take()
                .ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?))
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
    admit_authenticated_broker_method_outcome_engine(
        direction, traffic, request, bytes, retained_replay, actual_descriptor_count, context, None,
    )
}

fn admit_authenticated_broker_method_outcome_engine(
    direction: AuthenticatedBrokerOutcomeDirectionV1,
    traffic: &BrokerSessionTrafficStateV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodOutcomeV1>,
    actual_descriptor_count: usize,
    context: &ProtectedBrokerSessionVerificationContextV1,
    capture: Option<&mut AuthenticatedBrokerMethodOutcomeCaptureV1>,
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
    let (packet, admission_slot, canonical_decode, canonical_slot, envelope_capture, envelope_slot, bodies, verified_slot, next_slot, replay_slot) = match capture {
        Some(capture) => (
            Some(&mut capture.packet), Some(&mut capture.traffic_admission),
            Some(&mut capture.canonical_decode), Some(&mut capture.canonical),
            Some(&mut capture.envelope_partial), Some(&mut capture.envelope), Some(&mut capture.bodies),
            Some(&mut capture.verified_outcome), Some(&mut capture.next_traffic), Some(&mut capture.replay),
        ),
        None => (None, None, None, None, None, None, None, None, None, None),
    };
    let admission = match packet {
        Some(packet) => {
            traffic.decode_and_admit_outcome_retaining_v1(bytes, context, packet)?;
            packet.take_admission_once()?
        }
        None => traffic.decode_and_admit_outcome(bytes, context)?,
    };
    let admission = CaptureValueV1::new(Some(admission), admission_slot);
    let canonical = match canonical_decode {
        Some(capture) => {
            aos_sandbox_broker_session_protocol::projection::decode_canonical_response_retaining_v1(bytes, capture)
                .map_err(BrokerSessionSequenceError::from)?;
            capture.take_model_once().map_err(BrokerSessionSequenceError::from)?
        }
        None => decode_canonical_response_v1(bytes).map_err(BrokerSessionSequenceError::from)?,
    };
    let canonical = CaptureValueV1::new(Some(canonical), canonical_slot);
    let canonical = canonical.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;

    match admission.take().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)? {
        BrokerOutcomeAdmissionV1::New { outcome, next_state } => {
            // Ordinary locals retain their original arm-local drop interval.
            // Selected values park both actual admission pieces before the
            // first envelope/profile/body fallible operation.
            let outcome = CaptureValueV1::new(Some(outcome), verified_slot);
            let next_state = CaptureValueV1::new(Some(next_state), next_slot);
            let envelope = crate::session::validate_decoded_response_envelope_engine(
                canonical.message().clone(),
                &request.request_id(),
                request.method(),
                request.envelope.descriptors(),
                actual_descriptor_count,
                envelope_capture,
            )?;
            let envelope = CaptureValueV1::new(Some(envelope), envelope_slot);
            let envelope = envelope.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
            validate_outcome_against_profile(envelope, &profile)?;
            let result = if let Some(error) = envelope.error() {
                AuthenticatedBrokerMethodResultV1::Error(error.clone())
            } else {
                let filesystem_worker_qualification_commitment = match bodies {
                    Some(bodies) => bodies.validate_once(request, envelope.body())?,
                    None => validate_success_semantics(request, envelope.body())?,
                };
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
            let broker_sequence = outcome.as_ref()
                .ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?.sequence();
            let next_state = next_state.take()
                .ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
            Ok(AuthenticatedBrokerMethodOutcomeAdmissionV1::New {
                outcome: AuthenticatedBrokerMethodOutcomeV1 {
                    direction,
                    method: request.method(),
                    canonical_packet: bytes.to_vec(),
                    request: request.clone(),
                    broker_sequence,
                    result,
                },
                next_traffic: next_state,
            })
        }
        BrokerOutcomeAdmissionV1::ExactReplay(replay) => {
            let replay = CaptureValueV1::new(Some(replay), replay_slot);
            let observed = replay.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
            let retained =
                retained_replay.ok_or(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation)?;
            if retained.direction() != direction {
                return Err(AuthenticatedBrokerMethodErrorV1::ReplayEquivocation);
            }
            validate_exact_authenticated_outcome_replay_v1(observed, retained, bytes)?;
            Ok(AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(
                replay.take().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?,
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
    GitCoverage(crate::git_project_coverage::ValidatedGitProjectCoverageRequestV1),
    Nix(crate::nix_build::ValidatedNixBuildRequestV2),
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
    StoragePrepareNixGeneration(crate::nix_generation::CanonicalNixGenerationPreparationV1),
    StorageRepair(CanonicalStorageRepairSemanticsV1),
    StorageGuestRoot(CanonicalStorageGuestRootSemanticsV1),
    StorageOutputReserve(crate::storage_output_reserve::ValidatedStorageOutputReserveRequestV1),
    StorageOutputQuery(crate::storage_output_reserve::ValidatedStorageOutputQueryRequestV1),
    StorageCaptureReserve(crate::storage_capture_grant::ValidatedStorageCaptureReserveRequestV1),
    StorageCaptureQuery(crate::storage_capture_grant::ValidatedStorageCaptureQueryRequestV1),
    MountPrepareCatalog(crate::mount_catalog::ValidatedMountCatalogPreparation),
    MountDestinationSlot(crate::ValidatedDestinationSlotRequest),
    MountAttachmentAnchorV1(crate::mount_attachment_anchor::ValidatedAttachmentAnchorRequestV1),
    HostPublishCatalog(crate::host_catalog::ValidatedHostCatalogPublication),
    HostExecutionApply(crate::ValidatedHostExecutionApplyV1),
    HostExecutionQuery(crate::ValidatedHostExecutionQueryV1),
    HostOutputReserve(crate::host_output::ValidatedHostOutputReserveRequestV1),
    HostOutputQuery(crate::host_output::ValidatedHostOutputQueryRequestV1),
    HostStorageOutput(
        crate::host_storage_output_readback::ValidatedHostStorageOutputReadbackRequestV1,
    ),
    HostArgumentObserve(crate::host_execution_argument::ValidatedHostExecutionArgumentRequestV1),
    HostArgumentPrepareV2(crate::host_execution_argument::ValidatedHostExecutionArgumentRequestV1),
    ExecutionAvailabilityV2(crate::execution_availability::ValidatedExecutionAvailabilityRequestV2),
    HostArgumentAcceptV2(crate::host_execution_argument::ValidatedHostExecutionArgumentAcceptV2),
    HostArgumentQuery(crate::host_execution_argument::ValidatedHostExecutionArgumentRequestV1),
    HostNoApply(crate::host_execution_no_apply::ValidatedHostExecutionNoApplyRequestV1),
    HostNoApplyQuery(crate::host_execution_no_apply::ValidatedHostExecutionNoApplyRequestV1),
    HostBeforeArgumentNoApply(crate::host_execution_no_apply::ValidatedHostBeforeArgumentNoApplyRequestV2),
    HostBeforeArgumentNoApplyQuery(crate::host_execution_no_apply::ValidatedHostBeforeArgumentNoApplyRequestV2),
    HostNoApplySettlement(crate::host_execution_no_apply::ValidatedHostNoApplySettlementRequestV2),
    HostHeldNoApplySettlementV2(crate::host_execution_no_apply::held_settlement_transport::ValidatedHostHeldNoApplySettlementRequestV2),
    HostNoApplySettlementQuery(
        crate::host_execution_no_apply::ValidatedHostNoApplySettlementQueryV2,
    ),
    HostNoApplyCurrentLeaseQueryV2(
        crate::host_execution_no_apply::current_lease_transport::ValidatedHostNoApplyCurrentLeaseQueryV2,
    ),
    HostAttachGate(crate::ValidatedHostAttachGateRequestV1),
    HostAttachReadiness,
    HostAttachRoute(crate::ValidatedHostAttachRouteQueryV1),
}

#[allow(clippy::too_many_arguments)]
fn validate_request_semantics(
    method: BrokerMethod,
    body: &[u8],
    descriptor_roles: &[aos_sandbox_api::aos::sandbox::local::v1::BrokerDescriptorRole],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
    bindings: AuthenticatedBrokerSemanticBindingsV1,
) -> Result<ValidatedRequestSemanticV1, AuthenticatedBrokerMethodErrorV1> {
    validate_request_semantics_engine(method, body, descriptor_roles, peer, policy, now, bindings, None)
}

fn validate_request_semantics_engine(
    method: BrokerMethod,
    body: &[u8],
    descriptor_roles: &[aos_sandbox_api::aos::sandbox::local::v1::BrokerDescriptorRole],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
    bindings: AuthenticatedBrokerSemanticBindingsV1,
    mut capture: Option<&mut request_capture::RequestBodyCaptureV1>,
) -> Result<ValidatedRequestSemanticV1, AuthenticatedBrokerMethodErrorV1> {
    let mut nix_outcome_context = RequestOutcomeContextV1::None;
    let mut git_coverage_outcome_context = RequestOutcomeContextV1::None;
    let mut storage_capture_outcome_context = RequestOutcomeContextV1::None;
    let (kind, header, portable_commitment) = match method {
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1 => {
            let request = crate::git_project_coverage::decode_git_project_coverage_request_v1(
                body, method, peer, policy, now,
            )?;
            let header = *request.header();
            git_coverage_outcome_context = RequestOutcomeContextV1::GitCoverage(request);
            (AuthenticatedBrokerMethodSemanticsV1::GitProjectCoverage, header, None)
        }
        BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2
        | BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2
        | BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 => {
            let request = crate::nix_build::decode_nix_build_request_v2(
                body, method, peer, policy, now,
            )?;
            let kind = authenticated_broker_method_adapter_v1(method)
                .ok_or(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod)?
                .semantics();
            let header = *request.header();
            let commitment = request.commitment();

            nix_outcome_context = RequestOutcomeContextV1::Nix(request);
            (kind, header, Some(commitment))
        }
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
            let request = crate::decode_runtime_request(body, peer, policy, now)?;
            let semantics = canonical_host_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            let header = *request.header();
            let commitment = *semantics.commitment().digest().as_bytes();
            if let Some(capture) = capture.as_deref_mut() {
                capture.host_runtime = Some(request);
            }
            (
                AuthenticatedBrokerMethodSemanticsV1::HostApplyRuntime,
                header,
                Some(commitment),
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
            let semantics = match capture.as_deref_mut() {
                Some(capture) => capture.apply_header.decode_once(body, catalog, peer, policy, now),
                None => CanonicalStorageSemanticsV1::decode(body, catalog, peer, policy, now),
            }.map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StorageApply,
                *semantics.header(),
                Some(*semantics.argument_commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 => {
            let semantics = decode_network_method_body_engine_v4(method, body, peer, policy, now,
                capture.as_deref_mut().map(|capture| &mut capture.network_header))?;
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
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1 => {
            let request = crate::mount_attachment_anchor::decode_attachment_anchor_request_v1(body, peer, policy, now)?;
            let semantics = crate::mount_attachment_anchor::canonical_attachment_anchor_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (AuthenticatedBrokerMethodSemanticsV1::MountApplyAttachmentAnchorV1,
                *request.header(), Some(*semantics.commitment().digest().as_bytes()))
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
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => {
            let request = crate::host_storage_output_readback::decode_captured_host_storage_output_readback_request_v1(body, peer, policy, now)?;
            let grant = crate::host_storage_output_readback::captured_host_storage_output_readback_grant_v1(
                request.records().assignment(),
                *request.header().request_id(),
                body,
            )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostObserveStorageOutput,
                *request.header(),
                Some(*grant.argument_commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => {
            let request = crate::host_execution_argument::decode_host_execution_argument_prepare_request_v2(
                body, peer, policy, now,
            )?;
            (AuthenticatedBrokerMethodSemanticsV1::HostPrepareExecutionArgumentV2, *request.header(), None)
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => {
            let request = crate::host_execution_availability::decode_host_execution_availability_request_v2(body, peer, policy, now)?;
            (AuthenticatedBrokerMethodSemanticsV1::HostPrepareExecutionAvailabilityV2, *request.header(), None)
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 => {
            let request = crate::storage_execution_availability::decode_storage_execution_availability_request_v2(body, peer, policy, now)?;
            (AuthenticatedBrokerMethodSemanticsV1::StoragePrepareExecutionAvailabilityV2, *request.header(), None)
        }
        BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => {
            let request = crate::host_execution_argument::decode_host_execution_argument_accept_request_v2(
                body, peer, policy, now,
            )?;
            (AuthenticatedBrokerMethodSemanticsV1::HostAcceptExecutionArgumentV2, *request.source().header(), None)
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
                crate::host_execution_no_apply::decode_host_execution_no_apply_request_v2(
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
                decode_host_execution_no_apply_query_request_v2(
                    body, peer, policy, now,
                )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApply,
                *request.header(),
                None,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
            if crate::host_execution_no_apply::held_settlement_transport::is_held_settlement_request_v2(body) {
                let request = crate::host_execution_no_apply::held_settlement_transport::decode_host_held_no_apply_settlement_request_v2(
                    body, peer, policy, now,
                )?;
                (AuthenticatedBrokerMethodSemanticsV1::HostSettleNoApplyV2, *request.header(), None)
            } else {
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
                AuthenticatedBrokerMethodSemanticsV1::HostSettleNoApplyV2,
                *request.header(),
                None,
            )
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            if crate::host_execution_no_apply::current_lease_transport::is_current_lease_query_v2(body) {
                let request = crate::host_execution_no_apply::current_lease_transport::decode_host_no_apply_current_lease_query_v2(
                    body, peer, policy, now,
                )?;
                (AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApplySettlement, *request.header(), None)
            } else {
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
            match capture.as_deref_mut() {
                Some(capture) => capture.inventory.decode_once(body, peer, policy, now)?,
                None => decode_storage_resource_inventory_request(body, peer, policy, now)?,
            },
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
            let semantics = match capture.as_deref_mut() {
                Some(capture) => capture.preparation_header.decode_once(body, peer, policy, now),
                None => CanonicalStoragePreparationSemanticsV1::decode(body, peer, policy, now),
            }
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
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1 => {
            let semantics = crate::nix_generation::CanonicalNixGenerationPreparationV1::decode(
                body, peer, policy, now,
            )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StoragePrepareNixGeneration,
                *semantics.prepare().header(),
                Some(method_digest(REQUEST_SEMANTIC_DOMAIN, method, body)),
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
        BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1 => {
            let request = crate::mount_fuse_reserve_intent::decode_fuse_reserve_intent_request_v1(
                body, peer, policy, now,
            )?;
            let semantics = crate::semantics::mount_fuse_reserve_intent::canonical_mount_fuse_reserve_intent_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::MountFuseReserveIntent,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1 => {
            let request =
                crate::host_fuse_worker_session::decode_host_fuse_worker_session_request_v1(
                    body, peer, policy, now,
                )?;
            let semantics = crate::semantics::host_fuse_worker_session::canonical_host_fuse_worker_session_semantics_v1(&request)
                .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
            (
                AuthenticatedBrokerMethodSemanticsV1::HostPrepareFuseWorkerSession,
                *request.header(),
                Some(*semantics.commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT => {
            let request = crate::storage_output_reserve::decode_captured_storage_output_reserve_request_v1(body, peer, policy, now)?;
            let grant = crate::storage_output_reserve::captured_storage_output_reserve_grant_v1(
                request.records().assignment(),
                *request.header().request_id(),
                body,
            )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StorageReserveExecutionOutput,
                *request.header(),
                Some(*grant.argument_commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT => {
            let request = crate::storage_output_reserve::decode_captured_storage_output_query_request_v1(body, peer, policy, now)?;
            let grant = crate::storage_output_reserve::captured_storage_output_query_grant_v1(
                request.records().assignment(),
                *request.header().request_id(),
                body,
            )?;
            (
                AuthenticatedBrokerMethodSemanticsV1::StorageQueryExecutionOutput,
                *request.header(),
                Some(*grant.argument_commitment().digest().as_bytes()),
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1 => {
            let request = crate::storage_capture_grant::decode_storage_capture_reserve_request_v1(
                body, peer, policy, now,
            )?;
            let commitment = request.argument_commitment_data_v2()?;
            let header = *request.header();
            storage_capture_outcome_context = RequestOutcomeContextV1::StorageCaptureReserve(request);
            (AuthenticatedBrokerMethodSemanticsV1::StorageReserveExecutionCapture,
                header, Some(*commitment.digest().as_bytes()))
        }
        BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1 => {
            let request = crate::storage_capture_grant::decode_storage_capture_query_request_v1(
                body, peer, policy, now,
            )?;
            let commitment = request.argument_commitment_data_v2()?;
            storage_capture_outcome_context = RequestOutcomeContextV1::StorageCaptureQuery(request);
            (AuthenticatedBrokerMethodSemanticsV1::StorageQueryExecutionCapture,
                *request.header(), Some(*commitment.digest().as_bytes()))
        }
        BrokerMethod::BROKER_METHOD_UNSPECIFIED => {
            return Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod);
        }
    };
    let outcome_context = match method {
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1 => storage_capture_outcome_context,
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1 => git_coverage_outcome_context,
        BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2
        | BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2
        | BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 => nix_outcome_context,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME => RequestOutcomeContextV1::HostObserve(
            decode_observe_runtime_request_v1(body, peer, policy, now)?,
        ),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => {
            RequestOutcomeContextV1::MountApply(decode_mount_request(body, peer, policy, now)?)
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 => RequestOutcomeContextV1::NetworkApply(
            decode_network_method_body_engine_v4(method, body, peer, policy, now,
                capture.as_deref_mut().map(|capture| &mut capture.network_context))?,
        ),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
            let catalog = bindings
                .storage_catalog
                .ok_or(AuthenticatedBrokerMethodErrorV1::MissingCatalogBinding)?;
            RequestOutcomeContextV1::StorageApply(
                match capture.as_deref_mut() {
                    Some(capture) => capture.apply_context.decode_once(body, catalog, peer, policy, now),
                    None => CanonicalStorageSemanticsV1::decode(body, catalog, peer, policy, now),
                }.map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?,
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
                match capture.as_deref_mut() {
                Some(capture) => capture.preparation_context.decode_once(body, peer, policy, now),
                None => CanonicalStoragePreparationSemanticsV1::decode(body, peer, policy, now),
            }
                    .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?,
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1 => {
            RequestOutcomeContextV1::StoragePrepareNixGeneration(
                crate::nix_generation::CanonicalNixGenerationPreparationV1::decode(
                    body, peer, policy, now,
                )?,
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
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT => {
            RequestOutcomeContextV1::StorageOutputReserve(
                crate::storage_output_reserve::decode_captured_storage_output_reserve_request_v1(body, peer, policy, now)?,
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT => {
            RequestOutcomeContextV1::StorageOutputQuery(
                crate::storage_output_reserve::decode_captured_storage_output_query_request_v1(body, peer, policy, now)?,
            )
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
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1 => {
            RequestOutcomeContextV1::MountAttachmentAnchorV1(
                crate::mount_attachment_anchor::decode_attachment_anchor_request_v1(body, peer, policy, now)?)
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
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => {
            RequestOutcomeContextV1::HostStorageOutput(
                crate::host_storage_output_readback::decode_captured_host_storage_output_readback_request_v1(body, peer, policy, now)?,
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => {
            RequestOutcomeContextV1::HostArgumentPrepareV2(
                crate::host_execution_argument::decode_host_execution_argument_prepare_request_v2(body, peer, policy, now)?
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 => {
            RequestOutcomeContextV1::ExecutionAvailabilityV2(
                crate::host_execution_availability::decode_host_execution_availability_request_v2(body, peer, policy, now)?
            )
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 => {
            RequestOutcomeContextV1::ExecutionAvailabilityV2(
                crate::storage_execution_availability::decode_storage_execution_availability_request_v2(body, peer, policy, now)?
            )
        }
        BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => {
            RequestOutcomeContextV1::HostArgumentAcceptV2(
                crate::host_execution_argument::decode_host_execution_argument_accept_request_v2(body, peer, policy, now)?
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
            match crate::host_execution_no_apply::decode_host_execution_no_apply_request_v2(body, peer, policy, now)? {
                crate::host_execution_no_apply::HostExecutionNoApplyRequestV2::AfterArgument(request) =>
                    RequestOutcomeContextV1::HostNoApply(request),
                crate::host_execution_no_apply::HostExecutionNoApplyRequestV2::BeforeArgument(request) =>
                    RequestOutcomeContextV1::HostBeforeArgumentNoApply(request),
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY => {
            match crate::host_execution_no_apply::decode_host_execution_no_apply_query_request_v2(body, peer, policy, now)? {
                crate::host_execution_no_apply::HostExecutionNoApplyRequestV2::AfterArgument(request) =>
                    RequestOutcomeContextV1::HostNoApplyQuery(request),
                crate::host_execution_no_apply::HostExecutionNoApplyRequestV2::BeforeArgument(request) =>
                    RequestOutcomeContextV1::HostBeforeArgumentNoApplyQuery(request),
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
            if crate::host_execution_no_apply::held_settlement_transport::is_held_settlement_request_v2(body) {
                RequestOutcomeContextV1::HostHeldNoApplySettlementV2(
                    crate::host_execution_no_apply::held_settlement_transport::decode_host_held_no_apply_settlement_request_v2(
                        body, peer, policy, now,
                    )?,
                )
            } else {
            RequestOutcomeContextV1::HostNoApplySettlement(
                crate::host_execution_no_apply::decode_host_no_apply_settlement_request_v2(
                    body, peer, policy, now,
                )?,
            )
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            if crate::host_execution_no_apply::current_lease_transport::is_current_lease_query_v2(body) {
                RequestOutcomeContextV1::HostNoApplyCurrentLeaseQueryV2(
                    crate::host_execution_no_apply::current_lease_transport::decode_host_no_apply_current_lease_query_v2(
                        body, peer, policy, now,
                    )?,
                )
            } else {
                RequestOutcomeContextV1::HostNoApplySettlementQuery(
                    crate::host_execution_no_apply::decode_host_no_apply_settlement_query_request_v2(
                        body, peer, policy, now,
                    )?,
                )
            }
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

fn decode_recorded_host_no_apply_v2(
    method: BrokerMethod,
    context: &RequestOutcomeContextV1,
    body: &[u8],
    session_binding: [u8; 32],
    signed_request_digest: [u8; 32],
) -> Result<Option<crate::host_execution_no_apply::HostExecutionNoApplyRecordV2>, AuthenticatedBrokerMethodErrorV1> {
    use crate::host_execution_no_apply::{HostExecutionNoApplyRecordV2,
        decode_host_before_argument_no_apply_response_v2,
        decode_host_before_argument_no_apply_query_response_v2};

    match (method, context) {
        (BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
            RequestOutcomeContextV1::HostBeforeArgumentNoApply(original)) => {
            decode_host_before_argument_no_apply_response_v2(body, original, session_binding, signed_request_digest)
                .map(|record| Some(HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(record)))
                .map_err(Into::into)
        }
        (BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY,
            RequestOutcomeContextV1::HostBeforeArgumentNoApplyQuery(original)) => {
            decode_host_before_argument_no_apply_query_response_v2(body, original)
                .map(|record| record.map(HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument))
                .map_err(Into::into)
        }
        _ => decode_recorded_host_no_apply(method, context, body, session_binding, signed_request_digest)
            .map(|record| record.map(HostExecutionNoApplyRecordV2::AfterArgument)),
    }
}

fn validate_success_semantics(
    request: &AuthenticatedBrokerMethodRequestV1,
    body: &[u8],
) -> Result<Option<[u8; 32]>, AuthenticatedBrokerMethodErrorV1> {
    validate_success_semantics_engine(request, body, None)
}

fn validate_success_semantics_engine(
    request: &AuthenticatedBrokerMethodRequestV1,
    body: &[u8],
    capture: Option<&mut StorageBodyCaptureV1>,
) -> Result<Option<[u8; 32]>, AuthenticatedBrokerMethodErrorV1> {
    let maximum = request.maximum_response_bytes();
    match request.method() {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
            if let Some(capture) = capture {
                capture.host_apply = Some(crate::session::runtime_effect_observation_for_apply_v2(
                    body, request.exact_body(),
                ));
                capture.host_apply.as_ref()
                    .ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
                    .as_ref().map_err(Clone::clone)?;
            } else {
                validate_runtime_effect_receipt_for_apply(body, request.exact_body())?;
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME => {
            let RequestOutcomeContextV1::HostObserve(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            validate_runtime_observation(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME => {
            if let Some(capture) = capture {
                capture.host_inventory = Some(host::decode_runtime_inventory_data_v2(body, request.request_id()));
                capture.host_inventory.as_ref()
                    .ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
                    .as_ref().map_err(Clone::clone)?;
            } else {
                validate_runtime_inventory(body, request.request_id())?;
            }
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
            match capture {
                Some(capture) => capture.apply.validate_once(body, original)?,
                None => validate_storage_apply_response(body, original)?,
            }
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 => {
            let RequestOutcomeContextV1::NetworkApply(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            match capture {
                Some(capture) if request.method() == BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2 => {
                    capture.network_prepare = Some(network::decode_network_apply_response_data_v4(body, original));
                    capture.network_prepare.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
                        .as_ref().map_err(Clone::clone)?;
                }
                Some(capture) if request.method() == BrokerMethod::BROKER_METHOD_NETWORK_APPLY => {
                    capture.network_apply.validate_once(body, original)?;
                }
                _ => validate_network_apply_response(body, original)?,
            }
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
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1 => {
            let RequestOutcomeContextV1::MountAttachmentAnchorV1(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            let result = crate::mount_attachment_anchor::validate_attachment_anchor_apply_response_v1(
                body, maximum, original, request.exact_body());
            match capture {
                Some(capture) => {
                    capture.mount_namespace = Some(result);
                    capture.mount_namespace.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
                        .as_ref().map_err(Clone::clone)?;
                }
                None => { result?; },
            }
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS => {
            let result = decode_destination_slot_inventory_response(body, maximum).and_then(|model| {
                if model.native_absence_v2().is_some_and(|absence|
                    absence.request_id_v2() != &request.request_id()) {
                    return Err(ProtocolValidationError::InvalidField("Mount native absence request"));
                }
                Ok(model)
            });
            match capture {
                Some(capture) => {
                    capture.mount_inventory = Some(result);
                    capture.mount_inventory.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
                        .as_ref().map_err(Clone::clone)?;
                }
                None => { result?; }
            }
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
            if original.monitor_v3().is_some() {
                crate::host_execution::decode_host_execution_monitor_outcome_v3(body, original)?;
            } else {
                crate::decode_host_execution_outcome_v1(body, original.operation_id(),
                    original.execution_id(), original.source_commitment())?;
            }
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
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT => {
            let RequestOutcomeContextV1::HostStorageOutput(original) = &request.outcome_context
            else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_storage_output_readback::decode_host_storage_output_readback_response_v1(
                body, original,
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
            match capture {
                Some(capture) => capture.inventory.decode_once(body, maximum)?,
                None => { decode_storage_resource_inventory_response(body, maximum)?; }
            }
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RECOVER_INVENTORY => {
            decode_storage_inventory_recovery_response_v1(body, maximum)?;
        }
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => {
            let result = decode_network_resource_inventory_response(body, maximum).and_then(|model| {
                if model.native_absence_v2().is_some_and(|absence|
                    absence.request_id_v2() != &request.request_id()) {
                    return Err(ProtocolValidationError::InvalidField("Network native absence request"));
                }
                Ok(model)
            });
            match capture {
                Some(capture) => {
                    capture.network_inventory = Some(result);
                    capture.network_inventory.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
                        .as_ref().map_err(Clone::clone)?;
                }
                None => { result?; }
            }
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => {
            let RequestOutcomeContextV1::StoragePrepare(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            match capture {
                Some(capture) => capture.preparation.decode_once(body, original)?,
                None => validate_storage_preparation_response(body, original)?,
            }
        }
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_NIX_GENERATION_V1 => {
            let RequestOutcomeContextV1::StoragePrepareNixGeneration(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            validate_storage_preparation_response(body, original.prepare())?;
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
            let validate = |response: &crate::semantics::storage_guest_root::StorageGuestRootResponseDataV2| {
                let arguments = crate::semantics::CanonicalStorageGuestRootArgumentsV1::decode_data_v1(
                    original.canonical_bytes(),
                )?;
                response.current_publication_v2().require_request_data_v2(
                    response.proof_v1(), &arguments, original.header().request_id(),
                )
            };
            match capture {
                Some(capture) => {
                    capture.guest_root_publication = Some(
                        decode_storage_guest_root_response_v2(body, maximum).and_then(|response| {
                            validate(&response)?;
                            Ok(response)
                        }),
                    );
                    capture.guest_root_publication.as_ref()
                        .ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
                        .as_ref().map_err(Clone::clone)?;
                }
                None => validate(&decode_storage_guest_root_response_v2(body, maximum)?)?,
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 => {
            let RequestOutcomeContextV1::HostArgumentPrepareV2(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            let preparation = crate::host_execution_argument::preparation::HostArgumentPreparationV2::decode(body)?;
            if preparation.proposed_source() != original.canonical_attempt()
                || preparation.controller_session() != request.session_binding()
                || preparation.signed_prepare_request() != request.signed_request_digest()
            {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 => {
            let RequestOutcomeContextV1::ExecutionAvailabilityV2(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            if request.method() == BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 {
                crate::host_execution_availability::validate_host_execution_availability_response_v2(
                    body, original, request.session_binding(), request.signed_request_digest(),
                )?;
            } else {
                crate::storage_execution_availability::validate_storage_execution_availability_response_v2(
                    body, original, request.session_binding(), request.signed_request_digest(),
                )?;
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 => {
            let RequestOutcomeContextV1::HostArgumentAcceptV2(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::host_execution_argument::decode_host_execution_argument_observe_response_v1(
                body, original.source().canonical_attempt(),
            )?;
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
            decode_recorded_host_no_apply_v2(
                request.method(),
                &request.outcome_context,
                body,
                request.session_binding(),
                request.signed_request_digest(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => {
            match &request.outcome_context {
                RequestOutcomeContextV1::HostHeldNoApplySettlementV2(original) => {
                    crate::host_execution_no_apply::held_settlement_transport::decode_host_held_no_apply_settlement_response_v2(
                        body, original, request.session_binding(), request.signed_request_digest(),
                    )?;
                }
                RequestOutcomeContextV1::HostNoApplySettlement(original) => {
                    crate::host_execution_no_apply::decode_host_no_apply_settlement_response_v2(
                        body, original, request.session_binding(),
                    )?;
                }
                _ => return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink),
            }
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
            match &request.outcome_context {
                RequestOutcomeContextV1::HostNoApplyCurrentLeaseQueryV2(original) => {
                    crate::host_execution_no_apply::current_lease_transport::decode_host_no_apply_current_lease_response_v2(
                        body, original, request.session_binding(), request.signed_request_digest(),
                    )?;
                }
                RequestOutcomeContextV1::HostNoApplySettlementQuery(original) => {
                    crate::host_execution_no_apply::decode_host_no_apply_settlement_query_response_v2(
                        body, original,
                    )?;
                }
                _ => return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink),
            }
        }
        BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2
        | BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2
        | BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 => {
            let RequestOutcomeContextV1::Nix(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::nix_build::decode_nix_build_response_v2(body, original, request.method())?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1 => {
            let RequestOutcomeContextV1::GitCoverage(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::git_project_coverage::compare_git_project_coverage_response_v1(body, original)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
        | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1 => {
            validate_storage_capture_response(request.method(), &request.outcome_context, body)?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE => {
            return Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod);
        }
        BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT => {
            let RequestOutcomeContextV1::StorageOutputReserve(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            let plan_digest = crate::storage_output_reserve::continuation::original_plan_digest_v1(request)?;
            crate::storage_output_reserve::continuation::decode_registration_response_v1(
                body, original.records(), request.request_id(), plan_digest,
            )?;
        }
        BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT => {
            let RequestOutcomeContextV1::StorageOutputQuery(original) = &request.outcome_context else {
                return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            };
            crate::storage_output_reserve::continuation::decode_registration_response_v1(
                body, original.records(), original.original_request_id(), original.original_plan_digest(),
            )?;
        }
        BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1
        | BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1
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

// Both routes use the same locator/status codec. Reserve cannot acknowledge
// absence; a fresh Query may observe it without authorizing another reserve.
fn validate_storage_capture_response(
    method: BrokerMethod,
    context: &RequestOutcomeContextV1,
    body: &[u8],
) -> Result<(), AuthenticatedBrokerMethodErrorV1> {
    match (method, context) {
        (BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1,
            RequestOutcomeContextV1::StorageCaptureReserve(request)) => {
            let source = request.ongoing_source_v2().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
            crate::storage_capture_grant::decode_storage_capture_attempt_response_ongoing_v2(body, source, false)?;
        }
        (BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1,
            RequestOutcomeContextV1::StorageCaptureQuery(request)) => {
            let source = request.ongoing_source_v2().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?;
            crate::storage_capture_grant::decode_storage_capture_query_response_ongoing_v2(body, source)?;
        }
        _ => return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink),
    }
    Ok(())
}

fn validate_simple_inventory_request(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
    protocol: aos_sandbox_model::ProtocolId,
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
) -> Result<aos_sandbox_model::ProtocolId, AuthenticatedBrokerMethodErrorV1> {
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

#[cfg(test)]
mod nix_request_context_tests {
    use aos_sandbox_api::aos::sandbox::local::v1::{
        AssignmentFence, Audience, NixBuildRequestV2, RequestHeader,
    };
    use buffa::Message as _;

    use super::*;

    const METHODS: [BrokerMethod; 3] = [
        BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2,
        BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2,
        BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2,
    ];

    fn peer_policy() -> (PeerCredentials, PeerPolicy) {
        (
            PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(42),
            },
            PeerPolicy {
                uid: 1000,
                gid: Some(1000),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
        )
    }

    fn header() -> RequestHeader {
        RequestHeader {
            protocol_major: 1,
            protocol_minor: 0,
            request_id: vec![1; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 100,
            maximum_response_bytes: 4096,
            ..Default::default()
        }
    }

    fn request(method: BrokerMethod) -> NixBuildRequestV2 {
        // Comparison DATA only: this fixture supplies no signed traffic or
        // protected recipe, parent admission, roots, lease or floor authority.
        NixBuildRequestV2 {
            header: Some(header()).into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: 1,
                desired_generation: 1,
                assignment_digest: vec![4; 32],
                ..Default::default()
            })
            .into(),
            operation_id: vec![5; 16],
            recipe_digest: vec![6; 32],
            domain_digest: vec![7; 32],
            disclosure_digest: vec![8; 32],
            environment_digest: vec![9; 32],
            parent_admission_digest: vec![10; 32],
            input_presentation_digest: vec![11; 32],
            expected_output_map_digest: vec![12; 32],
            build_transaction_digest: if method
                == BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2
            {
                Vec::new()
            } else {
                vec![13; 32]
            },
            original_realization_digest: if method
                == BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2
            {
                vec![14; 32]
            } else {
                Vec::new()
            },
            ..Default::default()
        }
    }

    #[test]
    fn all_three_methods_retain_the_exact_validated_request_context() {
        let (peer, policy) = peer_policy();

        for method in METHODS {
            let body = request(method).encode_to_vec();
            let expected =
                crate::nix_build::decode_nix_build_request_v2(&body, method, peer, policy, 1)
                    .unwrap();

            let semantic = validate_request_semantics(
                method,
                &body,
                &[],
                peer,
                policy,
                1,
                AuthenticatedBrokerSemanticBindingsV1::default(),
            )
            .unwrap();

            assert_eq!(semantic.header, *expected.header());
            assert_eq!(semantic.commitment, expected.commitment());
            assert_eq!(
                semantic.kind,
                authenticated_broker_method_adapter_v1(method)
                    .unwrap()
                    .semantics()
            );
            let RequestOutcomeContextV1::Nix(retained) = semantic.outcome_context else {
                panic!("Nix method must retain its original request DATA");
            };
            assert_eq!(retained, expected);
            assert_eq!(retained.wire().encode_to_vec(), body);
            assert_eq!(retained.method(), method);
        }
    }

    #[test]
    fn method_specific_effect_coordinates_reject_cross_method_substitution() {
        let (peer, policy) = peer_policy();
        let resolve = BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2;
        let realize = BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2;
        let query = BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2;
        let cases = [
            (
                request(resolve),
                realize,
                ProtocolValidationError::InvalidFixedBytes {
                    field: "build_transaction_digest",
                    bytes: 32,
                },
            ),
            (
                request(realize),
                resolve,
                ProtocolValidationError::InvalidField("resolve effect coordinates"),
            ),
            (
                request(query),
                realize,
                ProtocolValidationError::InvalidField("realize original coordinate"),
            ),
            (
                request(realize),
                query,
                ProtocolValidationError::InvalidFixedBytes {
                    field: "original_realization_digest",
                    bytes: 32,
                },
            ),
        ];

        for (wire, method, expected) in cases {
            let error = validate_request_semantics(
                method,
                &wire.encode_to_vec(),
                &[],
                peer,
                policy,
                1,
                AuthenticatedBrokerSemanticBindingsV1::default(),
            )
            .err()
            .unwrap();

            assert_eq!(error, AuthenticatedBrokerMethodErrorV1::Protocol(expected));
        }
    }

    #[test]
    fn all_three_methods_preserve_header_fence_coordinate_and_deadline_errors() {
        let (peer, policy) = peer_policy();

        for method in METHODS {
            let original = request(method);
            let mut missing_header = original.clone();
            missing_header.header = None.into();
            let mut missing_fence = original.clone();
            missing_fence.fence = None.into();
            let mut zero_request_id = original.clone();
            zero_request_id.header = Some(RequestHeader {
                request_id: vec![0; 16],
                ..header()
            })
            .into();
            let mut zero_operation = original.clone();
            zero_operation.operation_id = vec![0; 16];
            let cases = [
                (
                    missing_header,
                    1,
                    ProtocolValidationError::MissingField("header"),
                ),
                (
                    missing_fence,
                    1,
                    ProtocolValidationError::MissingField("fence"),
                ),
                (
                    zero_request_id,
                    1,
                    ProtocolValidationError::InvalidFixedBytes {
                        field: "header.request_id",
                        bytes: 16,
                    },
                ),
                (
                    zero_operation,
                    1,
                    ProtocolValidationError::InvalidFixedBytes {
                        field: "operation_id",
                        bytes: 16,
                    },
                ),
                (original, 100, ProtocolValidationError::DeadlineExpired),
            ];

            for (wire, now, expected) in cases {
                let body = wire.encode_to_vec();
                let error = validate_request_semantics(
                    method,
                    &body,
                    &[],
                    peer,
                    policy,
                    now,
                    AuthenticatedBrokerSemanticBindingsV1::default(),
                )
                .err()
                .unwrap();

                assert_eq!(error, AuthenticatedBrokerMethodErrorV1::Protocol(expected));
            }

            assert!(matches!(
                validate_request_semantics(
                    method,
                    &[0xff],
                    &[],
                    peer,
                    policy,
                    1,
                    AuthenticatedBrokerSemanticBindingsV1::default(),
                ),
                Err(AuthenticatedBrokerMethodErrorV1::Protocol(
                    ProtocolValidationError::MalformedWire(_)
                ))
            ));
        }
    }
}

// Both closed methods use the one existing Network decoder. Method selection
// is checked before admission: old method nine cannot reinterpret Prepare,
// and the sole descriptor-bearing method cannot issue a lifecycle action.
fn decode_network_method_body_v2(
    method: BrokerMethod, body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
) -> Result<CanonicalNetworkSemanticsV1, AuthenticatedBrokerMethodErrorV1> {
    decode_network_method_body_engine_v4(method, body, peer, policy, now, None)
}

fn decode_network_method_body_engine_v4(
    method: BrokerMethod, body: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
    capture: Option<&mut request_capture::NetworkBodyCaptureV4>,
) -> Result<CanonicalNetworkSemanticsV1, AuthenticatedBrokerMethodErrorV1> {
    let semantics = match capture {
        Some(capture) => capture.decode_once(body, peer, policy, now),
        None => CanonicalNetworkSemanticsV1::decode(body, peer, policy, now),
    }
        .map_err(|_| AuthenticatedBrokerMethodErrorV1::PortableSemantics)?;
    if semantics.broker_method_v2() != method {
        return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
    }
    Ok(semantics)
}

#[cfg(test)]
mod network_method_separation_tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::{ApplyNetworkRequest, AssignmentFence, Audience, NetworkAction, RequestHeader};
    use buffa::Message as _;

    #[test]
    fn retained_destroy_response_rejects_substitution_and_preserves_decode_failure() {
        let peer = PeerCredentials { uid: 1000, gid: 1000, pid: Some(42) };
        let policy = PeerPolicy { uid: 1000, gid: Some(1000), audience: Audience::AUDIENCE_NODE_CONTROLLER };
        let mut destroy = request(NetworkAction::NETWORK_ACTION_DESTROY);
        destroy.network_handle = vec![5; 32];
        let bytes = destroy.encode_to_vec();
        let semantic = decode_network_method_body_v2(BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            &bytes, peer, policy, 10).unwrap();
        let mut result = aos_sandbox_api::aos::sandbox::local::v1::NetworkResult {
            network_handle: destroy.network_handle,
            state: aos_sandbox_api::aos::sandbox::local::v1::NetworkState::NETWORK_STATE_ABSENT.into(),
            ..Default::default()
        };
        let mut original = network::NetworkApplyResponseCaptureV4::default();
        original.validate_once(&result.encode_to_vec(), &semantic).unwrap();
        assert_eq!(original.destroy_data_v4(), Some(&result));

        result.network_handle[0] ^= 1;
        let mut substituted = network::NetworkApplyResponseCaptureV4::default();
        assert!(substituted.validate_once(&result.encode_to_vec(), &semantic).is_err());
        assert!(substituted.destroy_data_v4().is_none());
        assert!(substituted.cause().is_some());

        let mut truncated = network::NetworkApplyResponseCaptureV4::default();
        assert!(truncated.validate_once(&[0x0a, 0x20, 1], &semantic).is_err());
        assert!(truncated.cause().is_some());
        assert!(truncated.validate_once(&result.encode_to_vec(), &semantic).is_err());
        assert!(truncated.destroy_data_v4().is_none());
    }

    fn request(action: NetworkAction) -> ApplyNetworkRequest {
        ApplyNetworkRequest {
            header: Some(RequestHeader {
                protocol_major: 1, protocol_minor: 0, request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100, maximum_response_bytes: 4096,
                ..Default::default()
            }).into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16], incarnation_id: vec![3; 16], assignment_epoch: 1,
                desired_generation: 1, assignment_digest: vec![4; 32], ..Default::default()
            }).into(),
            action: action.into(), ..Default::default()
        }
    }

    #[test]
    fn sole_prepare_method_rejects_old_method_and_lifecycle_body() {
        use crate::semantics::network::preparation_content::{NetworkPreparationContentV2, NetworkPreparationContentReferenceV2};
        let peer = PeerCredentials { uid: 1000, gid: 1000, pid: Some(42) };
        let policy = PeerPolicy { uid: 1000, gid: Some(1000), audience: Audience::AUDIENCE_NODE_CONTROLLER };
        let mut prepare = request(NetworkAction::NETWORK_ACTION_PREPARE);
        // Framing/dispatch comparison DATA only: this fixture does not enter
        // a sealed reader, decode these model operands or create a reservation.
        let content = NetworkPreparationContentV2::new(b"manifest", b"specification").unwrap().encode().unwrap();
        NetworkPreparationContentReferenceV2::for_content(&content).unwrap().bind_request(&mut prepare);
        let bytes = prepare.encode_to_vec();
        assert!(decode_network_method_body_v2(BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2, &bytes, peer, policy, 10).is_ok());
        assert!(decode_network_method_body_v2(BrokerMethod::BROKER_METHOD_NETWORK_APPLY, &bytes, peer, policy, 10).is_err());

        let mut destroy = request(NetworkAction::NETWORK_ACTION_DESTROY);
        destroy.network_handle = vec![5; 32];
        let bytes = destroy.encode_to_vec();
        assert!(decode_network_method_body_v2(BrokerMethod::BROKER_METHOD_NETWORK_APPLY, &bytes, peer, policy, 10).is_ok());
        assert!(decode_network_method_body_v2(BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2, &bytes, peer, policy, 10).is_err());
    }
}

/// Decodes the complete canonical Host runtime inventory as comparison DATA.
///
/// This is the same validator used by authenticated Host3 outcomes. It does not
/// authenticate a packet or supply a native runtime, Session or currentness.
///
/// # Errors
/// Refuses malformed or noncanonical bytes, unknown fields, invalid runtime
/// observations, duplicate/out-of-order handles, conflicting stopped scopes or
/// an absence record bound to another request identifier.
pub fn decode_host_runtime_inventory_data_v2(
    body: &[u8],
    request_id: [u8; 16],
) -> Result<aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse, ProtocolValidationError> {
    host::decode_runtime_inventory_data_v2(body, request_id)
}
