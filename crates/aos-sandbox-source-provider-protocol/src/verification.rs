//! Composite SourceProvider request and response verification.
//!
//! These entry points cryptographically authenticate signed protocol records,
//! validate their complete graph, and return opaque results. Process and
//! descriptor observations remain supplied model inputs until a future branded
//! kernel adapter establishes their provenance.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::codec::{
    SourceProviderFrameError, SourceProviderMessageV1, decode_acquire_request,
    decode_inventory_request, decode_release_request, validate_message_descriptor_contract,
};
use crate::crypto::{
    SignedSourceExportLeaseV1, SignedSourceProviderHelloV1, SignedSourceProviderInventoryV1,
    SignedSourceProviderReceiptV1, SignedSourceProviderRequestV1, SignedSourceProviderStatusV1,
    SignedSourceReleaseReceiptV1, SourceProviderSignatureError, SourceProviderSigningKeyV1,
    digest_acquire_request, digest_inventory_request, digest_provider_proof,
    digest_release_request, digest_signed_export_lease, digest_signed_hello, digest_signed_request,
    empty_descriptor_set_commitment_v1, encode_signer, provider_resource_commitment_v1,
    response_result_digest_v1, verify_export_lease, verify_hello, verify_inventory,
    verify_provider_receipt, verify_release_receipt, verify_request, verify_response_status,
};
use crate::model::{
    AcquireSourceRequestV1, AcquireSourceResponseV1, InventorySourceRequestV1,
    InventorySourceResponseV1, ReleaseSourceRequestV1, ReleaseSourceResponseV1,
    SourceProviderAuthorityV1, SourceProviderDescriptorRole, SourceProviderMethod,
    SourceProviderStatus, SourceProviderValidationError, require_digest, require_generation,
    require_nonzero,
};
use crate::proof::SourceProviderProofV1;
use crate::trust::{
    ProtectedSourceProviderRouteV1, ProviderCatalogFloorV1, SourceProviderCurrentAuthorityV1,
    SourceProviderIngressSessionV1, SourceProviderProcessIdentityV1, SourceProviderSessionV1,
    SourceProviderTrustError, SourceProviderTrustSetV1, SourceSelectionFloorV1,
};

const REQUEST_ATTEMPT_DOMAIN: &[u8] = b"aos-source-provider-request-attempt-v1\0";
const ACQUIRE_INTENT_DOMAIN: &[u8] = b"aos-source-provider-acquire-intent-v1\0";
const RELEASE_INTENT_DOMAIN: &[u8] = b"aos-source-provider-release-intent-v1\0";
const INVENTORY_INTENT_DOMAIN: &[u8] = b"aos-source-provider-inventory-intent-v1\0";

/// Reports a failed complete SourceProvider verification graph.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderVerificationError {
    /// A typed protocol body is malformed or noncanonical.
    #[error("SourceProvider typed message verification failed: {0}")]
    Codec(#[from] SourceProviderFrameError),
    /// Canonical signature or signed-envelope verification failed.
    #[error("SourceProvider signature verification failed: {0}")]
    Signature(#[from] SourceProviderSignatureError),
    /// Trust, route, or supplied session verification failed.
    #[error("SourceProvider trust, route, or session verification failed: {0}")]
    Trust(#[from] SourceProviderTrustError),
    /// A semantic value or descriptor table was invalid.
    #[error("SourceProvider semantic verification failed: {0}")]
    InvalidValue(#[from] SourceProviderValidationError),
    /// A request, response, lease, receipt, route, or observation cross-link differs.
    #[error("SourceProvider verified inputs do not describe one operation")]
    CrossLink,
    /// A request or returned lease lies outside supplied current bounds.
    #[error("SourceProvider operation is outside current time or ownership bounds")]
    Bounds,
    /// Provider state is below or equivocates with a supplied rollback floor.
    #[error("SourceProvider authority, catalog, resource, or selection violated its floor")]
    Rollback,
}

/// Models current controller and ownership bounds supplied to verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderVerificationContextV1 {
    now_seconds: i64,
    maximum_lease_expiry_seconds: i64,
    node_id: [u8; 16],
    boot_id: [u8; 16],
    holder_authority_id: [u8; 16],
    holder_generation: u64,
    holder_authority_digest: ObjectDigest,
    revocation_digest: ObjectDigest,
    expected_request_sequence: u64,
    expected_response_sequence: u64,
}

impl SourceProviderVerificationContextV1 {
    /// Constructs shaped current bounds for one Root Mount holder.
    ///
    /// Production callers must obtain these values from protected controller and
    /// ownership state; construction alone establishes no such provenance.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderVerificationError`] for sentinel identities or
    /// digests, zero generation, negative time, or an exhausted expiry bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        now_seconds: i64,
        maximum_lease_expiry_seconds: i64,
        node_id: [u8; 16],
        boot_id: [u8; 16],
        holder_authority_id: [u8; 16],
        holder_generation: u64,
        holder_authority_digest: ObjectDigest,
        revocation_digest: ObjectDigest,
        expected_request_sequence: u64,
        expected_response_sequence: u64,
    ) -> Result<Self, SourceProviderVerificationError> {
        if now_seconds < 0 || maximum_lease_expiry_seconds <= now_seconds {
            return Err(SourceProviderVerificationError::Bounds);
        }
        require_nonzero("verification node ID", &node_id)?;
        require_nonzero("verification boot ID", &boot_id)?;
        require_nonzero("verification holder authority ID", &holder_authority_id)?;
        require_generation("verification holder", holder_generation)?;
        require_digest(
            "verification holder authority digest",
            holder_authority_digest,
        )?;
        require_digest("verification revocation digest", revocation_digest)?;
        require_generation("expected request sequence", expected_request_sequence)?;
        require_generation("expected response sequence", expected_response_sequence)?;
        Ok(Self {
            now_seconds,
            maximum_lease_expiry_seconds,
            node_id,
            boot_id,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            revocation_digest,
            expected_request_sequence,
            expected_response_sequence,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProviderRequestSequenceExpectationKindV1 {
    Fresh {
        expected_sequence: u64,
    },
    ExactReplay {
        session_binding: ObjectDigest,
        admitted_sequence: u64,
        request_id: [u8; 16],
        signed_request_digest: ObjectDigest,
        current_next_sequence: u64,
    },
}

/// Supplies a fresh or byte-exact replay sequence expectation to provider ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRequestSequenceExpectationV1(ProviderRequestSequenceExpectationKindV1);

impl ProviderRequestSequenceExpectationV1 {
    /// Constructs a fresh request sequence expectation.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderVerificationError::Bounds`] for zero or a value
    /// that cannot advance without reaching the reserved maximum sequence.
    pub fn fresh(expected_sequence: u64) -> Result<Self, SourceProviderVerificationError> {
        if expected_sequence == 0 || expected_sequence >= u64::MAX - 1 {
            return Err(SourceProviderVerificationError::Bounds);
        }
        Ok(Self(ProviderRequestSequenceExpectationKindV1::Fresh {
            expected_sequence,
        }))
    }

    /// Constructs an exact retained replay expectation.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderVerificationError`] unless every retained field
    /// is non-sentinel and `0 < admitted < current_next < u64::MAX`.
    pub fn exact_replay(
        session_binding: ObjectDigest,
        admitted_sequence: u64,
        request_id: [u8; 16],
        signed_request_digest: ObjectDigest,
        current_next_sequence: u64,
    ) -> Result<Self, SourceProviderVerificationError> {
        require_digest("provider replay session binding", session_binding)?;
        require_traffic_sequence(admitted_sequence)?;
        require_nonzero("provider replay request ID", &request_id)?;
        require_digest("provider replay request digest", signed_request_digest)?;
        require_traffic_sequence(current_next_sequence)?;
        if admitted_sequence >= current_next_sequence || current_next_sequence >= u64::MAX {
            return Err(SourceProviderVerificationError::Bounds);
        }
        Ok(Self(
            ProviderRequestSequenceExpectationKindV1::ExactReplay {
                session_binding,
                admitted_sequence,
                request_id,
                signed_request_digest,
                current_next_sequence,
            },
        ))
    }
}

/// Supplies protected current bounds for provider-side request admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRequestVerificationContextV1 {
    now_seconds: i64,
    maximum_request_deadline_seconds: i64,
    expected_node_id: [u8; 16],
    expected_boot_id: [u8; 16],
    expected_holder_revocation_digest: ObjectDigest,
    current_root_mount_identity: SourceProviderProcessIdentityV1,
    sequence_expectation: ProviderRequestSequenceExpectationV1,
}

impl ProviderRequestVerificationContextV1 {
    /// Constructs shaped provider-ingress verification bounds.
    ///
    /// Construction does not establish protected or kernel provenance.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderVerificationError`] for invalid time bounds or
    /// sentinel node, boot, or revocation values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        now_seconds: i64,
        maximum_request_deadline_seconds: i64,
        expected_node_id: [u8; 16],
        expected_boot_id: [u8; 16],
        expected_holder_revocation_digest: ObjectDigest,
        current_root_mount_identity: SourceProviderProcessIdentityV1,
        sequence_expectation: ProviderRequestSequenceExpectationV1,
    ) -> Result<Self, SourceProviderVerificationError> {
        if now_seconds < 0 || maximum_request_deadline_seconds <= 0 {
            return Err(SourceProviderVerificationError::Bounds);
        }
        require_nonzero("provider-ingress node ID", &expected_node_id)?;
        require_nonzero("provider-ingress boot ID", &expected_boot_id)?;
        require_digest(
            "provider-ingress holder revocation digest",
            expected_holder_revocation_digest,
        )?;
        Ok(Self {
            now_seconds,
            maximum_request_deadline_seconds,
            expected_node_id,
            expected_boot_id,
            expected_holder_revocation_digest,
            current_root_mount_identity,
            sequence_expectation,
        })
    }
}

/// Identifies one stable authenticated request attempt without granting execution authority.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProviderRequestAttemptV1 {
    method: SourceProviderMethod,
    request_id: [u8; 16],
    signed_request_digest: ObjectDigest,
    attempt_digest: ObjectDigest,
    canonical_signed_request: Vec<u8>,
}

impl VerifiedProviderRequestAttemptV1 {
    /// Returns the exact request method.
    #[must_use]
    pub const fn method(&self) -> SourceProviderMethod {
        self.method
    }

    /// Returns the idempotency request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the digest of the complete signed request envelope.
    #[must_use]
    pub const fn signed_request_digest(&self) -> ObjectDigest {
        self.signed_request_digest
    }

    /// Returns the stable signer/method/request-ID attempt digest.
    #[must_use]
    pub const fn attempt_digest(&self) -> ObjectDigest {
        self.attempt_digest
    }

    /// Returns the exact canonical signed request envelope.
    #[must_use]
    pub fn canonical_signed_request(&self) -> &[u8] {
        &self.canonical_signed_request
    }
}

/// Proves a fresh provider request sequence can advance only in caller-owned durable state.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProviderRequestSequenceAdvanceV1 {
    session_binding: ObjectDigest,
    accepted_sequence: u64,
    next_sequence: u64,
    attempt_digest: ObjectDigest,
}

impl VerifiedProviderRequestSequenceAdvanceV1 {
    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the accepted request sequence.
    #[must_use]
    pub const fn accepted_sequence(&self) -> u64 {
        self.accepted_sequence
    }

    /// Returns the exact next sequence for the durable compare-and-swap.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the stable authenticated attempt digest.
    #[must_use]
    pub const fn attempt_digest(&self) -> ObjectDigest {
        self.attempt_digest
    }
}

/// Identifies an exact authenticated replay that performs no sequence write.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProviderRequestReplayV1 {
    session_binding: ObjectDigest,
    admitted_sequence: u64,
    current_next_sequence: u64,
    request_id: [u8; 16],
    request_digest: ObjectDigest,
    attempt_digest: ObjectDigest,
}

impl VerifiedProviderRequestReplayV1 {
    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the previously admitted request sequence.
    #[must_use]
    pub const fn admitted_sequence(&self) -> u64 {
        self.admitted_sequence
    }

    /// Returns the unchanged durable next sequence.
    #[must_use]
    pub const fn current_next_sequence(&self) -> u64 {
        self.current_next_sequence
    }

    /// Returns the exact retained request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the byte-exact signed request digest.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the stable authenticated attempt digest.
    #[must_use]
    pub const fn attempt_digest(&self) -> ObjectDigest {
        self.attempt_digest
    }
}

/// Distinguishes fresh sequence advancement from exact no-write replay.
#[derive(Debug, Eq, PartialEq)]
pub enum VerifiedProviderRequestSequenceV1 {
    /// Carries a token that must accompany the durable request reservation.
    Fresh(VerifiedProviderRequestSequenceAdvanceV1),
    /// Carries byte-exact retained replay evidence.
    ExactReplay(VerifiedProviderRequestReplayV1),
}

/// Retains the exact Root Mount process projection accepted as the writer.
///
/// The projection is constructed only as part of complete ingress
/// verification. Its scalar fields remain observations supplied by the future
/// branded kernel adapter; this protocol crate does not establish their
/// provenance on its own.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedRootMountProcessProjectionV1 {
    uid: u32,
    gid: u32,
    tgid: u32,
    start_time_ticks: u64,
    cgroup_digest: ObjectDigest,
    pidfd_live: bool,
}

impl VerifiedRootMountProcessProjectionV1 {
    /// Returns the accepted effective user ID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the accepted effective group ID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the accepted thread-group ID.
    #[must_use]
    pub const fn tgid(&self) -> u32 {
        self.tgid
    }

    /// Returns the accepted process start-time ticks.
    #[must_use]
    pub const fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }

    /// Returns the accepted cgroup-v2 projection digest.
    #[must_use]
    pub const fn cgroup_digest(&self) -> ObjectDigest {
        self.cgroup_digest
    }

    /// Reports the retained pidfd-liveness observation.
    #[must_use]
    pub const fn pidfd_live(&self) -> bool {
        self.pidfd_live
    }
}

/// Retains the complete nonforgeable ingress projection used for one request.
///
/// This object packages the exact authenticated hello, trust, route, key-role,
/// and process evidence so a durable consumer never reconstructs the ingress
/// decision from separately supplied shape-only scalars. It grants no signing,
/// sequence-advancement, backend, descriptor, or journal authority.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProviderIngressProjectionV1 {
    signed_root_mount_hello: SignedSourceProviderHelloV1,
    signed_provider_hello: SignedSourceProviderHelloV1,
    root_mount_hello_digest: ObjectDigest,
    provider_hello_digest: ObjectDigest,
    session_binding: ObjectDigest,
    signer_set_commitment: ObjectDigest,
    root_mount_authority: SourceProviderAuthorityV1,
    provider_authority: SourceProviderAuthorityV1,
    ordered_signers: [SourceProviderSigningKeyV1; 4],
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    resource_namespace_digest: ObjectDigest,
    proof_class_capabilities: u8,
    supports_recursive: bool,
    supports_kernel_coupled: bool,
    actual_writer_root_mount_process: VerifiedRootMountProcessProjectionV1,
    root_mount_process_instance: [u8; 16],
    provider_process_instance: [u8; 16],
    verified_at_seconds: i64,
    current_valid_until_seconds: i64,
}

impl VerifiedProviderIngressProjectionV1 {
    /// Returns the exact signed Root Mount hello.
    #[must_use]
    pub const fn signed_root_mount_hello(&self) -> &SignedSourceProviderHelloV1 {
        &self.signed_root_mount_hello
    }

    /// Returns the exact signed provider hello.
    #[must_use]
    pub const fn signed_provider_hello(&self) -> &SignedSourceProviderHelloV1 {
        &self.signed_provider_hello
    }

    /// Returns the digest of the exact signed Root Mount hello.
    #[must_use]
    pub const fn root_mount_hello_digest(&self) -> ObjectDigest {
        self.root_mount_hello_digest
    }

    /// Returns the digest of the exact signed provider hello.
    #[must_use]
    pub const fn provider_hello_digest(&self) -> ObjectDigest {
        self.provider_hello_digest
    }

    /// Returns the authenticated hello-transcript binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the commitment to the four ordered signing roles.
    #[must_use]
    pub const fn signer_set_commitment(&self) -> ObjectDigest {
        self.signer_set_commitment
    }

    /// Returns the exact current Root Mount authority generation.
    #[must_use]
    pub const fn root_mount_authority(&self) -> &SourceProviderAuthorityV1 {
        &self.root_mount_authority
    }

    /// Returns the exact current provider authority generation.
    #[must_use]
    pub const fn provider_authority(&self) -> &SourceProviderAuthorityV1 {
        &self.provider_authority
    }

    /// Returns signer references in RootMountHello, RootMountRecord,
    /// ProviderHello, ProviderOutcome order.
    #[must_use]
    pub const fn ordered_signers(&self) -> &[SourceProviderSigningKeyV1; 4] {
        &self.ordered_signers
    }

    /// Returns the protected trust generation used for verification.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// Returns the protected trust digest used for verification.
    #[must_use]
    pub const fn trust_digest(&self) -> ObjectDigest {
        self.trust_digest
    }

    /// Returns the protected revocation generation used for verification.
    #[must_use]
    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Returns the protected revocation digest used for verification.
    #[must_use]
    pub const fn revocation_digest(&self) -> ObjectDigest {
        self.revocation_digest
    }

    /// Returns the exact protected route ID.
    #[must_use]
    pub const fn route_id(&self) -> [u8; 16] {
        self.route_id
    }

    /// Returns the exact protected route generation.
    #[must_use]
    pub const fn route_generation(&self) -> u64 {
        self.route_generation
    }

    /// Returns the exact protected route digest.
    #[must_use]
    pub const fn route_digest(&self) -> ObjectDigest {
        self.route_digest
    }

    /// Returns the protected resource-namespace digest.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }

    /// Returns the negotiated provider proof-class capabilities.
    #[must_use]
    pub const fn proof_class_capabilities(&self) -> u8 {
        self.proof_class_capabilities
    }

    /// Reports whether the authenticated provider supports recursive proofs.
    #[must_use]
    pub const fn supports_recursive(&self) -> bool {
        self.supports_recursive
    }

    /// Reports whether the authenticated provider supports kernel-coupled proofs.
    #[must_use]
    pub const fn supports_kernel_coupled(&self) -> bool {
        self.supports_kernel_coupled
    }

    /// Returns the exact retained actual-writer Root Mount process projection.
    #[must_use]
    pub const fn actual_writer_root_mount_process(&self) -> &VerifiedRootMountProcessProjectionV1 {
        &self.actual_writer_root_mount_process
    }

    /// Returns the Root Mount process instance signed into the transcript.
    #[must_use]
    pub const fn root_mount_process_instance(&self) -> [u8; 16] {
        self.root_mount_process_instance
    }

    /// Returns the provider process instance signed into the transcript.
    #[must_use]
    pub const fn provider_process_instance(&self) -> [u8; 16] {
        self.provider_process_instance
    }

    /// Returns the exact Unix time at which currentness was verified.
    #[must_use]
    pub const fn verified_at_seconds(&self) -> i64 {
        self.verified_at_seconds
    }

    /// Returns the exclusive end of the intersected current validity window.
    #[must_use]
    pub const fn current_valid_until_seconds(&self) -> i64 {
        self.current_valid_until_seconds
    }
}

/// Carries a verified provider-side Acquire request.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProviderAcquireRequestV1 {
    request: AcquireSourceRequestV1,
    attempt: VerifiedProviderRequestAttemptV1,
    sequence: VerifiedProviderRequestSequenceV1,
    acquire_intent_digest: ObjectDigest,
    provider_process_instance: [u8; 16],
    ingress_projection: VerifiedProviderIngressProjectionV1,
}

/// Carries a verified provider-side Release request.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProviderReleaseRequestV1 {
    request: ReleaseSourceRequestV1,
    attempt: VerifiedProviderRequestAttemptV1,
    sequence: VerifiedProviderRequestSequenceV1,
    release_intent_digest: ObjectDigest,
    provider_process_instance: [u8; 16],
    ingress_projection: VerifiedProviderIngressProjectionV1,
}

/// Carries a verified provider-side Inventory request.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedProviderInventoryRequestV1 {
    request: InventorySourceRequestV1,
    attempt: VerifiedProviderRequestAttemptV1,
    sequence: VerifiedProviderRequestSequenceV1,
    inventory_intent_digest: ObjectDigest,
    provider_process_instance: [u8; 16],
    ingress_projection: VerifiedProviderIngressProjectionV1,
}

macro_rules! provider_request_accessors {
    ($type:ty, $request:ty, $intent:ident) => {
        impl $type {
            /// Returns the complete validated typed request.
            #[must_use]
            pub const fn request(&self) -> &$request {
                &self.request
            }

            /// Returns the exact signed request-attempt evidence.
            #[must_use]
            pub const fn attempt(&self) -> &VerifiedProviderRequestAttemptV1 {
                &self.attempt
            }

            /// Returns the fresh or exact-replay sequence classification.
            #[must_use]
            pub const fn sequence(&self) -> &VerifiedProviderRequestSequenceV1 {
                &self.sequence
            }

            /// Returns the authenticated session binding.
            #[must_use]
            pub const fn session_binding(&self) -> ObjectDigest {
                self.request.session_binding()
            }

            /// Returns the authenticated provider process instance.
            #[must_use]
            pub const fn provider_process_instance(&self) -> [u8; 16] {
                self.provider_process_instance
            }

            /// Returns the complete retained ingress verification projection.
            #[must_use]
            pub const fn ingress_projection(&self) -> &VerifiedProviderIngressProjectionV1 {
                &self.ingress_projection
            }

            /// Returns the method-specific deadline-free intent digest.
            #[must_use]
            pub const fn $intent(&self) -> ObjectDigest {
                self.$intent
            }
        }
    };
}

provider_request_accessors!(
    VerifiedProviderAcquireRequestV1,
    AcquireSourceRequestV1,
    acquire_intent_digest
);
provider_request_accessors!(
    VerifiedProviderReleaseRequestV1,
    ReleaseSourceRequestV1,
    release_intent_digest
);
provider_request_accessors!(
    VerifiedProviderInventoryRequestV1,
    InventorySourceRequestV1,
    inventory_intent_digest
);

/// Carries one method-typed provider-ingress request verification result.
#[derive(Debug, Eq, PartialEq)]
pub enum VerifiedProviderRequestV1 {
    /// Contains a verified Acquire request.
    Acquire(VerifiedProviderAcquireRequestV1),
    /// Contains a verified Release request.
    Release(VerifiedProviderReleaseRequestV1),
    /// Contains a verified Inventory request.
    Inventory(VerifiedProviderInventoryRequestV1),
}

/// Models exact source-root fields supplied by a future kernel adapter.
///
/// Construction validates field shape only. A production adapter must issue
/// non-forgeable evidence after inspecting the received descriptor; public
/// scalar construction does not prove kernel provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRootObservationV1 {
    kernel_boot_id: [u8; 16],
    device: u64,
    inode: u64,
    unique_mount_id: u64,
    o_path: bool,
    directory: bool,
    read_only: bool,
}

impl SourceRootObservationV1 {
    /// Returns the observed kernel boot identity.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the observed device identity.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the observed inode identity.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the observed kernel-lifetime unique mount identity.
    #[must_use]
    pub const fn unique_mount_id(&self) -> u64 {
        self.unique_mount_id
    }

    /// Reports whether the observed descriptor has `O_PATH` semantics.
    #[must_use]
    pub const fn is_o_path(&self) -> bool {
        self.o_path
    }

    /// Reports whether the observed descriptor names a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.directory
    }

    /// Reports whether the observed mount is read-only.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Constructs one shaped `O_PATH` directory descriptor observation.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderVerificationError`] for sentinel observation fields or
    /// a value that does not describe a read-only `O_PATH` directory.
    pub fn new(
        kernel_boot_id: [u8; 16],
        device: u64,
        inode: u64,
        unique_mount_id: u64,
        o_path: bool,
        directory: bool,
        read_only: bool,
    ) -> Result<Self, SourceProviderVerificationError> {
        require_nonzero("source-root boot ID", &kernel_boot_id)?;
        require_generation("source-root device", device)?;
        require_generation("source-root inode", inode)?;
        require_generation("source-root mount ID", unique_mount_id)?;
        if !o_path || !directory || !read_only {
            return Err(SourceProviderVerificationError::CrossLink);
        }
        Ok(Self {
            kernel_boot_id,
            device,
            inode,
            unique_mount_id,
            o_path,
            directory,
            read_only,
        })
    }
}

/// Commits the exact supplied completed-Acquire descriptor observation.
#[must_use]
pub fn source_root_descriptor_commitment_v1(observation: &SourceRootObservationV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-source-provider-descriptor-set-v1\0");
    hasher.update(1u32.to_be_bytes());
    hasher.update([SourceProviderDescriptorRole::SourceRoot as u8]);
    hasher.update([0; 7]);
    hasher.update(observation.kernel_boot_id);
    hasher.update(observation.device.to_be_bytes());
    hasher.update(observation.inode.to_be_bytes());
    hasher.update(observation.unique_mount_id.to_be_bytes());
    hasher.update([u8::from(observation.o_path)
        | (u8::from(observation.directory) << 1)
        | (u8::from(observation.read_only) << 2)]);
    hasher.update([0; 7]);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Proves both direction-local sequence numbers were verified exactly.
///
/// This evidence does not advance or persist either sequence. The caller must
/// perform the required atomic durable compare-and-swap before descriptor use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceProviderSequenceV1 {
    session_binding: ObjectDigest,
    request_sequence: u64,
    response_sequence: u64,
}

impl VerifiedSourceProviderSequenceV1 {
    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }
    /// Returns the verified client request sequence without advancing state.
    #[must_use]
    pub const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }
    /// Returns the verified provider response sequence without advancing state.
    #[must_use]
    pub const fn response_sequence(&self) -> u64 {
        self.response_sequence
    }
}

/// Carries a nonconstructible cryptographically verified provider disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceProviderDispositionV1<T> {
    status: SourceProviderStatus,
    result: Option<T>,
    sequence: VerifiedSourceProviderSequenceV1,
}

impl<T> VerifiedSourceProviderDispositionV1<T> {
    /// Returns the authenticated provider status.
    #[must_use]
    pub const fn status(&self) -> SourceProviderStatus {
        self.status
    }

    /// Returns the opaque completed result, if the authenticated status is Complete.
    #[must_use]
    pub const fn result(&self) -> Option<&T> {
        self.result.as_ref()
    }

    /// Returns the opaque sequencing evidence for caller-owned advancement.
    #[must_use]
    pub const fn sequence(&self) -> &VerifiedSourceProviderSequenceV1 {
        &self.sequence
    }
}

/// Carries one verified Acquire graph over a supplied descriptor observation.
///
/// A future branded kernel adapter must establish the observation's provenance
/// before this result is sufficient for production Mount admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceAcquisitionV1 {
    signed_lease: SignedSourceExportLeaseV1,
    lease_digest: ObjectDigest,
    provider_resource_commitment: ObjectDigest,
    observation: SourceRootObservationV1,
    selection_floor: SourceSelectionFloorV1,
}

impl VerifiedSourceAcquisitionV1 {
    /// Returns the exact signed provider export lease.
    #[must_use]
    pub const fn signed_lease(&self) -> &SignedSourceExportLeaseV1 {
        &self.signed_lease
    }

    /// Returns the digest of the exact signed lease envelope.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the Stage-1-compatible provider resource/proof commitment.
    #[must_use]
    pub const fn provider_resource_commitment(&self) -> ObjectDigest {
        self.provider_resource_commitment
    }

    /// Returns the exact supplied source-root observation fields.
    #[must_use]
    pub const fn observation(&self) -> &SourceRootObservationV1 {
        &self.observation
    }

    /// Returns the exact acquisition-scoped floor derived from this result.
    #[must_use]
    pub const fn selection_floor(&self) -> &SourceSelectionFloorV1 {
        &self.selection_floor
    }
}

/// Carries one fully verified terminal provider release result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceReleaseV1 {
    lease_digest: ObjectDigest,
    release_generation: u64,
}

impl VerifiedSourceReleaseV1 {
    /// Returns the released exact signed-lease digest.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the provider's monotonic release generation.
    #[must_use]
    pub const fn release_generation(&self) -> u64 {
        self.release_generation
    }
}

/// Carries one fully verified provider inventory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSourceInventoryV1 {
    signed_inventory: SignedSourceProviderInventoryV1,
    matched_entry_indices: Vec<u16>,
    authenticated_residual_entry_indices: Vec<u16>,
}

impl VerifiedSourceInventoryV1 {
    /// Returns the exact verified signed inventory.
    #[must_use]
    pub const fn signed_inventory(&self) -> &SignedSourceProviderInventoryV1 {
        &self.signed_inventory
    }

    /// Iterates entries matching caller-supplied acquisition floors.
    pub fn matched_entries(
        &self,
    ) -> impl ExactSizeIterator<Item = &crate::model::SourceProviderInventoryEntryV1> {
        self.matched_entry_indices
            .iter()
            .map(|index| &self.signed_inventory.subject().entries()[usize::from(*index)])
    }

    /// Iterates valid signed entries unknown to the supplied floor set.
    pub fn authenticated_residual_entries(
        &self,
    ) -> impl ExactSizeIterator<Item = &crate::model::SourceProviderInventoryEntryV1> {
        self.authenticated_residual_entry_indices
            .iter()
            .map(|index| &self.signed_inventory.subject().entries()[usize::from(*index)])
    }
}

/// Verifies one RootMountRecord request for provider-side durable admission.
///
/// Verification authenticates and classifies bytes but does not advance a
/// sequence, reserve backend work, or authorize an effect. A caller must
/// atomically consume [`VerifiedProviderRequestSequenceV1::Fresh`] with its
/// own durable request reservation. Exact replay is strictly no-write.
///
/// # Errors
///
/// Returns [`SourceProviderVerificationError`] for a noncanonical or malformed
/// method body, descriptors, inactive trust, invalid signature, stale session
/// or process evidence, holder/node/boot/revocation mismatch, invalid sequence,
/// or a fresh request outside its deadline bounds.
#[allow(clippy::too_many_arguments)]
pub fn verify_provider_request(
    signed_request: &SignedSourceProviderRequestV1,
    session: &SourceProviderIngressSessionV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
    context: &ProviderRequestVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
) -> Result<VerifiedProviderRequestV1, SourceProviderVerificationError> {
    if !descriptor_roles.is_empty() {
        return Err(SourceProviderValidationError::DescriptorContract.into());
    }

    let decoded = match signed_request.method() {
        SourceProviderMethod::Acquire => {
            ProviderRequestBody::Acquire(decode_acquire_request(signed_request.subject())?)
        }
        SourceProviderMethod::Release => {
            ProviderRequestBody::Release(decode_release_request(signed_request.subject())?)
        }
        SourceProviderMethod::Inventory => {
            ProviderRequestBody::Inventory(decode_inventory_request(signed_request.subject())?)
        }
        SourceProviderMethod::Hello => return Err(SourceProviderVerificationError::CrossLink),
    };

    verify_current_request(signed_request, trust_set, root_current, context.now_seconds)?;
    verify_ingress_session_current(
        session,
        signed_request,
        trust_set,
        root_current,
        provider_current,
        route,
        context,
    )?;

    let common = decoded.common();
    if common.session_binding != session.binding()
        || common.holder_authority_id != root_current.authority().authority_id()
        || common.holder_generation != root_current.authority().authority_generation()
        || common.holder_authority_digest != root_current.authority().authority_digest()
        || common.holder_authority_id != signed_request.signer().authority_id()
        || common.holder_generation != signed_request.signer().authority_generation()
        || common.holder_authority_digest != signed_request.signer().authority_digest()
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    if let ProviderRequestBody::Acquire(request) = &decoded
        && (request.node_id() != context.expected_node_id
            || request.boot_id() != context.expected_boot_id
            || request.revocation_digest() != context.expected_holder_revocation_digest)
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }

    let signed_request_digest = digest_signed_request(signed_request);
    let attempt_digest = source_provider_request_attempt_digest_v1(
        signed_request.signer(),
        signed_request.method(),
        common.request_id,
    );
    let sequence = classify_provider_request_sequence(
        &context.sequence_expectation,
        common.session_binding,
        common.sequence,
        common.request_id,
        signed_request_digest,
        attempt_digest,
    )?;
    if matches!(&sequence, VerifiedProviderRequestSequenceV1::Fresh(_))
        && (common.deadline_seconds <= context.now_seconds
            || common.deadline_seconds > context.maximum_request_deadline_seconds)
    {
        return Err(SourceProviderVerificationError::Bounds);
    }
    let attempt = VerifiedProviderRequestAttemptV1 {
        method: signed_request.method(),
        request_id: common.request_id,
        signed_request_digest,
        attempt_digest,
        canonical_signed_request: signed_request.to_canonical_bytes(),
    };
    let provider_process_instance = session.provider_process_instance();
    let ingress_projection = verified_ingress_projection(
        session,
        trust_set,
        root_current,
        provider_current,
        route,
        context.now_seconds,
    );

    Ok(match decoded {
        ProviderRequestBody::Acquire(request) => {
            let acquire_intent_digest = source_provider_acquire_intent_digest_v1(&request);
            VerifiedProviderRequestV1::Acquire(VerifiedProviderAcquireRequestV1 {
                request,
                attempt,
                sequence,
                acquire_intent_digest,
                provider_process_instance,
                ingress_projection,
            })
        }
        ProviderRequestBody::Release(request) => {
            let release_intent_digest = source_provider_release_intent_digest_v1(&request);
            VerifiedProviderRequestV1::Release(VerifiedProviderReleaseRequestV1 {
                request,
                attempt,
                sequence,
                release_intent_digest,
                provider_process_instance,
                ingress_projection,
            })
        }
        ProviderRequestBody::Inventory(request) => {
            let inventory_intent_digest = source_provider_inventory_intent_digest_v1(&request);
            VerifiedProviderRequestV1::Inventory(VerifiedProviderInventoryRequestV1 {
                request,
                attempt,
                sequence,
                inventory_intent_digest,
                provider_process_instance,
                ingress_projection,
            })
        }
    })
}

enum ProviderRequestBody {
    Acquire(AcquireSourceRequestV1),
    Release(ReleaseSourceRequestV1),
    Inventory(InventorySourceRequestV1),
}

struct ProviderRequestCommon {
    session_binding: ObjectDigest,
    sequence: u64,
    request_id: [u8; 16],
    holder_authority_id: [u8; 16],
    holder_generation: u64,
    holder_authority_digest: ObjectDigest,
    deadline_seconds: i64,
}

impl ProviderRequestBody {
    fn common(&self) -> ProviderRequestCommon {
        match self {
            Self::Acquire(request) => ProviderRequestCommon {
                session_binding: request.session_binding(),
                sequence: request.sequence(),
                request_id: request.request_id(),
                holder_authority_id: request.holder_authority_id(),
                holder_generation: request.holder_generation(),
                holder_authority_digest: request.holder_authority_digest(),
                deadline_seconds: request.deadline_seconds(),
            },
            Self::Release(request) => ProviderRequestCommon {
                session_binding: request.session_binding(),
                sequence: request.sequence(),
                request_id: request.request_id(),
                holder_authority_id: request.holder_authority_id(),
                holder_generation: request.holder_generation(),
                holder_authority_digest: request.holder_authority_digest(),
                deadline_seconds: request.deadline_seconds(),
            },
            Self::Inventory(request) => ProviderRequestCommon {
                session_binding: request.session_binding(),
                sequence: request.sequence(),
                request_id: request.request_id(),
                holder_authority_id: request.holder_authority_id(),
                holder_generation: request.holder_generation(),
                holder_authority_digest: request.holder_authority_digest(),
                deadline_seconds: request.deadline_seconds(),
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_ingress_session_current(
    session: &SourceProviderIngressSessionV1,
    signed_request: &SignedSourceProviderRequestV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
    context: &ProviderRequestVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    let root_hello_key = trust_set.resolve_current(
        root_current,
        session.root_mount_hello().signer(),
        context.now_seconds,
    )?;
    let provider_hello_key = trust_set.resolve_current(
        provider_current,
        session.provider_hello().signer(),
        context.now_seconds,
    )?;
    verify_hello(session.root_mount_hello(), root_hello_key)?;
    verify_hello(session.provider_hello(), provider_hello_key)?;
    trust_set.resolve_current(
        root_current,
        session.root_mount_hello().subject().traffic_signer(),
        context.now_seconds,
    )?;
    trust_set.resolve_current(
        provider_current,
        session.provider_hello().subject().traffic_signer(),
        context.now_seconds,
    )?;
    route.verify_current_authority(root_current)?;
    route.verify_current_authority(provider_current)?;
    if session.route() != route
        || session.root_mount_hello().signer() != root_current.hello_signer()
        || session.provider_hello().signer() != provider_current.hello_signer()
        || signed_request.signer() != root_current.traffic_signer()
        || session.root_mount_hello().subject().traffic_signer() != signed_request.signer()
        || session.provider_hello().subject().traffic_signer() != provider_current.traffic_signer()
        || session
            .root_mount_hello()
            .subject()
            .expected_peer_traffic_signer()
            != provider_current.traffic_signer()
        || session
            .provider_hello()
            .subject()
            .expected_peer_traffic_signer()
            != signed_request.signer()
        || session.root_mount_identity() != &context.current_root_mount_identity
        || session.root_mount_hello().subject().kernel_boot_id() != context.expected_boot_id
        || session.provider_hello().subject().kernel_boot_id() != context.expected_boot_id
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(())
}

fn verified_ingress_projection(
    session: &SourceProviderIngressSessionV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
    verified_at_seconds: i64,
) -> VerifiedProviderIngressProjectionV1 {
    let signed_root_mount_hello = session.root_mount_hello();
    let signed_provider_hello = session.provider_hello();
    let root_mount_hello = signed_root_mount_hello.subject();
    let provider_hello = signed_provider_hello.subject();

    VerifiedProviderIngressProjectionV1 {
        signed_root_mount_hello: signed_root_mount_hello.clone(),
        signed_provider_hello: signed_provider_hello.clone(),
        root_mount_hello_digest: digest_signed_hello(signed_root_mount_hello),
        provider_hello_digest: digest_signed_hello(signed_provider_hello),
        session_binding: session.binding(),
        signer_set_commitment: session.signer_set_commitment(),
        root_mount_authority: root_current.authority().clone(),
        provider_authority: provider_current.authority().clone(),
        ordered_signers: [
            signed_root_mount_hello.signer().clone(),
            root_mount_hello.traffic_signer().clone(),
            signed_provider_hello.signer().clone(),
            provider_hello.traffic_signer().clone(),
        ],
        trust_generation: trust_set.trust_generation(),
        trust_digest: trust_set.trust_digest(),
        revocation_generation: trust_set.revocation_generation(),
        revocation_digest: trust_set.revocation_digest(),
        route_id: route.route_id(),
        route_generation: route.route_generation(),
        route_digest: route.route_digest(),
        resource_namespace_digest: route.resource_namespace_digest(),
        proof_class_capabilities: provider_hello.proof_class_capabilities(),
        supports_recursive: provider_hello.supports_recursive(),
        supports_kernel_coupled: provider_hello.supports_kernel_coupled(),
        actual_writer_root_mount_process: VerifiedRootMountProcessProjectionV1 {
            uid: session.root_mount_identity().uid(),
            gid: session.root_mount_identity().gid(),
            tgid: session.root_mount_identity().tgid(),
            start_time_ticks: session.root_mount_identity().start_time_ticks(),
            cgroup_digest: session.root_mount_identity().cgroup_digest(),
            pidfd_live: session.root_mount_identity().pidfd_live(),
        },
        root_mount_process_instance: root_mount_hello.process_instance(),
        provider_process_instance: provider_hello.process_instance(),
        verified_at_seconds,
        current_valid_until_seconds: root_current
            .valid_until_seconds()
            .min(provider_current.valid_until_seconds()),
    }
}

fn classify_provider_request_sequence(
    expectation: &ProviderRequestSequenceExpectationV1,
    session_binding: ObjectDigest,
    sequence: u64,
    request_id: [u8; 16],
    signed_request_digest: ObjectDigest,
    attempt_digest: ObjectDigest,
) -> Result<VerifiedProviderRequestSequenceV1, SourceProviderVerificationError> {
    require_traffic_sequence(sequence)?;
    match &expectation.0 {
        ProviderRequestSequenceExpectationKindV1::Fresh { expected_sequence }
            if sequence == *expected_sequence =>
        {
            let next_sequence = sequence
                .checked_add(1)
                .filter(|next| *next != u64::MAX)
                .ok_or(SourceProviderVerificationError::Bounds)?;
            Ok(VerifiedProviderRequestSequenceV1::Fresh(
                VerifiedProviderRequestSequenceAdvanceV1 {
                    session_binding,
                    accepted_sequence: sequence,
                    next_sequence,
                    attempt_digest,
                },
            ))
        }
        ProviderRequestSequenceExpectationKindV1::ExactReplay {
            session_binding: expected_binding,
            admitted_sequence,
            request_id: expected_request_id,
            signed_request_digest: expected_digest,
            current_next_sequence,
        } if session_binding == *expected_binding
            && sequence == *admitted_sequence
            && request_id == *expected_request_id
            && signed_request_digest == *expected_digest =>
        {
            Ok(VerifiedProviderRequestSequenceV1::ExactReplay(
                VerifiedProviderRequestReplayV1 {
                    session_binding,
                    admitted_sequence: sequence,
                    current_next_sequence: *current_next_sequence,
                    request_id,
                    request_digest: signed_request_digest,
                    attempt_digest,
                },
            ))
        }
        _ => Err(SourceProviderVerificationError::CrossLink),
    }
}

fn require_traffic_sequence(sequence: u64) -> Result<(), SourceProviderVerificationError> {
    if sequence == 0 || sequence == u64::MAX {
        Err(SourceProviderVerificationError::Bounds)
    } else {
        Ok(())
    }
}

/// Computes the stable signer/method/request-ID attempt identity.
///
/// This helper is pure and nonauthorizing. Durable owners use it to recompute
/// retained identities during hostile recovery; protected currentness and
/// signature verification remain separate requirements.
#[must_use]
pub fn source_provider_request_attempt_digest_v1(
    signer: &crate::crypto::SourceProviderSigningKeyV1,
    method: SourceProviderMethod,
    request_id: [u8; 16],
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_ATTEMPT_DOMAIN);
    let mut signer_bytes = Vec::with_capacity(120);
    encode_signer(&mut signer_bytes, signer);
    hasher.update(&signer_bytes);
    hasher.update([method as u8]);
    hasher.update([0; 7]);
    hasher.update(request_id);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn append_holder_authority(
    hasher: &mut Sha256,
    authority_id: [u8; 16],
    generation: u64,
    digest: ObjectDigest,
) {
    hasher.update(authority_id);
    hasher.update(generation.to_be_bytes());
    hasher.update(digest.as_bytes());
}

/// Computes the canonical deadline-free semantic intent digest for Acquire.
///
/// This pure projection omits session binding, sequence, request ID,
/// acquisition ID, and deadline. It authenticates nothing and grants no
/// reservation, replay, descriptor, or backend authority.
#[must_use]
pub fn source_provider_acquire_intent_digest_v1(request: &AcquireSourceRequestV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(ACQUIRE_INTENT_DOMAIN);
    hasher.update((request.prospective_apply_template().len() as u32).to_be_bytes());
    hasher.update(request.prospective_apply_template());
    hasher.update(request.prospective_apply_template_digest().as_bytes());
    hasher.update([request.source_use() as u8]);
    hasher.update([0; 7]);
    hasher.update(request.node_id());
    hasher.update(request.boot_id());
    append_holder_authority(
        &mut hasher,
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
    );
    hasher.update((request.binding().len() as u32).to_be_bytes());
    hasher.update(request.binding());
    hasher.update(request.binding_digest().as_bytes());
    hasher.update(request.requested_lease_seconds().to_be_bytes());
    hasher.update(request.revocation_digest().as_bytes());
    hasher.update([u8::from(request.recursive()) | (u8::from(request.kernel_coupled()) << 1)]);
    hasher.update([0; 3]);
    hasher.update(request.requested_maximum_submounts().to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Computes the canonical semantic intent digest for Release.
///
/// This pure projection commits the acquisition, holder, and exact lease. It
/// authenticates nothing and grants no reservation, replay, or release
/// authority.
#[must_use]
pub fn source_provider_release_intent_digest_v1(request: &ReleaseSourceRequestV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(RELEASE_INTENT_DOMAIN);
    hasher.update(request.acquisition_id().as_bytes());
    append_holder_authority(
        &mut hasher,
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
    );
    hasher.update(request.lease_id());
    hasher.update(request.lease_digest().as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Computes the canonical semantic intent digest for Inventory.
///
/// This pure projection commits the holder and optional known inventory
/// digest. It authenticates nothing and grants no reservation, replay, or
/// inventory authority.
#[must_use]
pub fn source_provider_inventory_intent_digest_v1(
    request: &InventorySourceRequestV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_INTENT_DOMAIN);
    append_holder_authority(
        &mut hasher,
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
    );
    match request.known_inventory_digest() {
        Some(digest) => {
            hasher.update([1]);
            hasher.update([0; 7]);
            hasher.update(digest.as_bytes());
        }
        None => {
            hasher.update([0; 8]);
            hasher.update([0; 32]);
        }
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Verifies one complete Acquire query/session/response graph.
///
/// # Errors
///
/// Returns [`SourceProviderVerificationError`] for any signature, trust,
/// route, session, deadline, lease, capability, receipt, descriptor, or
/// cross-object mismatch.
#[allow(clippy::too_many_arguments)]
pub fn verify_acquire(
    signed_request: &SignedSourceProviderRequestV1,
    response: &AcquireSourceResponseV1,
    session: &SourceProviderSessionV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
    catalog_floor: &ProviderCatalogFloorV1,
    selection_floor: Option<&SourceSelectionFloorV1>,
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
    observation: Option<SourceRootObservationV1>,
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceAcquisitionV1>,
    SourceProviderVerificationError,
> {
    require_method(signed_request, SourceProviderMethod::Acquire)?;
    let request = decode_acquire_request(signed_request.subject())?;
    validate_message_descriptor_contract(
        &SourceProviderMessageV1::AcquireResponse(response.clone()),
        descriptor_roles,
    )?;
    verify_current_session(
        session,
        signed_request,
        trust_set,
        root_current,
        provider_current,
        route,
        context,
    )?;
    verify_current_request(signed_request, trust_set, root_current, context.now_seconds)?;
    verify_current_status_signature(
        response.signed_status(),
        trust_set,
        provider_current,
        context.now_seconds,
    )?;
    verify_request_session(
        request.session_binding(),
        request.sequence(),
        session,
        context,
    )?;
    verify_acquire_bounds(&request, context)?;
    let descriptor_commitment = match (response.status(), observation.as_ref()) {
        (SourceProviderStatus::Complete, Some(observation)) => {
            source_root_descriptor_commitment_v1(observation)
        }
        (SourceProviderStatus::Complete, None) => {
            return Err(SourceProviderVerificationError::CrossLink);
        }
        (_, None) => empty_descriptor_set_commitment_v1(),
        (_, Some(_)) => return Err(SourceProviderVerificationError::CrossLink),
    };
    let sequence = verify_outer_status(
        signed_request,
        response.signed_status(),
        response.signed_receipt(),
        request.request_id(),
        session,
        context,
        descriptor_commitment,
    )?;
    if response.status() != SourceProviderStatus::Complete {
        if observation.is_some() {
            return Err(SourceProviderVerificationError::CrossLink);
        }
        return disposition(response.status(), None, sequence);
    }

    let observation = observation.ok_or(SourceProviderVerificationError::CrossLink)?;
    let signed_receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(
        response
            .signed_receipt()
            .ok_or(SourceProviderVerificationError::CrossLink)?,
    )?;
    let receipt_key = trust_set.resolve_current(
        provider_current,
        signed_receipt.signer(),
        context.now_seconds,
    )?;
    verify_provider_receipt(&signed_receipt, receipt_key)?;
    let receipt = signed_receipt.subject();
    let signed_lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())?;
    let lease = signed_lease.subject();
    let lease_key = match selection_floor {
        Some(floor) => trust_set.resolve_historical_outcome(
            signed_lease.signer(),
            lease.issued_seconds(),
            floor,
        )?,
        None => trust_set.resolve_current(
            provider_current,
            signed_lease.signer(),
            context.now_seconds,
        )?,
    };
    verify_export_lease(&signed_lease, lease_key)?;

    if receipt.request_id() != request.request_id()
        || receipt.request_digest() != digest_acquire_request(&request)
        || receipt.acquisition_id() != request.acquisition_id()
        || receipt.provider_process_instance() != session.provider_hello().process_instance()
        || receipt.kernel_boot_id() != observation.kernel_boot_id
        || observation.kernel_boot_id != request.boot_id()
        || receipt.device() != observation.device
        || receipt.inode() != observation.inode
        || receipt.unique_mount_id() != observation.unique_mount_id
        || !observation.directory
        || !observation.o_path
        || !observation.read_only
        || lease.request_id() != request.request_id()
        || lease.request_digest() != digest_acquire_request(&request)
        || lease.holder_authority_id() != request.holder_authority_id()
        || lease.holder_generation() != request.holder_generation()
        || lease.holder_authority_digest() != request.holder_authority_digest()
        || lease.binding_digest() != request.binding_digest()
        || lease.revocation_digest() != request.revocation_digest()
        || matches!(
            lease.proof(),
            SourceProviderProofV1::LocalLiveExport { proof, .. }
                if proof.consumer_authority_id() != request.holder_authority_id()
                    || proof.consumer_generation() != request.holder_generation()
        )
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    verify_provider_selection(
        lease,
        &request,
        session,
        provider_current,
        route,
        catalog_floor,
        selection_floor,
        context,
    )?;
    let lease_digest = digest_signed_export_lease(&signed_lease);
    if receipt.lease_digest() != lease_digest {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    let proof_digest = digest_provider_proof(lease.proof());
    if receipt.observed_proof_digest() != proof_digest {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    let provider_resource_commitment =
        provider_resource_commitment_v1(lease.resource(), proof_digest);
    if let Some(floor) = selection_floor {
        require_exact_selection_floor(
            floor,
            request.acquisition_id(),
            route,
            &signed_lease,
            proof_digest,
            provider_resource_commitment,
        )?;
    }
    let selection_floor = match selection_floor {
        Some(floor) => floor.clone(),
        None => SourceSelectionFloorV1::new(
            request.acquisition_id(),
            lease.provider().authority_id(),
            route.route_id(),
            lease.resource().clone(),
            signed_lease.signer().clone(),
            lease.lease_id(),
            lease_digest,
            lease.proof().class_code(),
            proof_digest,
            provider_resource_commitment,
            trust_set.trust_generation(),
            trust_set.trust_digest(),
            trust_set.revocation_generation(),
            trust_set.revocation_digest(),
        )?,
    };
    Ok(VerifiedSourceProviderDispositionV1 {
        status: SourceProviderStatus::Complete,
        result: Some(VerifiedSourceAcquisitionV1 {
            signed_lease,
            lease_digest,
            provider_resource_commitment,
            observation,
            selection_floor,
        }),
        sequence,
    })
}

/// Verifies one complete Release query/session/response graph.
///
/// # Errors
///
/// Returns [`SourceProviderVerificationError`] for any signature, trust,
/// route, session, deadline, receipt, descriptor, or cross-object mismatch.
#[allow(clippy::too_many_arguments)]
pub fn verify_release(
    signed_request: &SignedSourceProviderRequestV1,
    response: &ReleaseSourceResponseV1,
    session: &SourceProviderSessionV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
    selection_floor: &SourceSelectionFloorV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceReleaseV1>,
    SourceProviderVerificationError,
> {
    require_method(signed_request, SourceProviderMethod::Release)?;
    let request = decode_release_request(signed_request.subject())?;
    validate_message_descriptor_contract(
        &SourceProviderMessageV1::ReleaseResponse(response.clone()),
        descriptor_roles,
    )?;
    verify_current_session(
        session,
        signed_request,
        trust_set,
        root_current,
        provider_current,
        route,
        context,
    )?;
    verify_current_request(signed_request, trust_set, root_current, context.now_seconds)?;
    verify_current_status_signature(
        response.signed_status(),
        trust_set,
        provider_current,
        context.now_seconds,
    )?;
    verify_request_session(
        request.session_binding(),
        request.sequence(),
        session,
        context,
    )?;
    verify_request_bounds(
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        request.deadline_seconds(),
        context,
    )?;
    let sequence = verify_outer_status(
        signed_request,
        response.signed_status(),
        response.signed_receipt(),
        request.request_id(),
        session,
        context,
        empty_descriptor_set_commitment_v1(),
    )?;
    trust_set.validate_selection_floor(selection_floor)?;
    if request.acquisition_id() != selection_floor.acquisition_id()
        || request.lease_id() != selection_floor.lease_id()
        || request.lease_digest() != selection_floor.signed_lease_digest()
        || selection_floor.provider_authority_id() != provider_current.authority().authority_id()
        || selection_floor.route_id() != route.route_id()
        || selection_floor.resource().resource_namespace_digest()
            != route.resource_namespace_digest()
    {
        return Err(SourceProviderVerificationError::Rollback);
    }
    if response.status() != SourceProviderStatus::Complete {
        return disposition(response.status(), None, sequence);
    }
    let signed_receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(
        response
            .signed_receipt()
            .ok_or(SourceProviderVerificationError::CrossLink)?,
    )?;
    let receipt_key = trust_set.resolve_current(
        provider_current,
        signed_receipt.signer(),
        context.now_seconds,
    )?;
    verify_release_receipt(&signed_receipt, receipt_key)?;
    let receipt = signed_receipt.subject();
    if receipt.request_id() != request.request_id()
        || receipt.request_digest() != digest_release_request(&request)
        || receipt.lease_id() != request.lease_id()
        || receipt.lease_digest() != request.lease_digest()
        || receipt.provider_process_instance() != session.provider_hello().process_instance()
        || receipt.released_seconds() > context.now_seconds
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(VerifiedSourceProviderDispositionV1 {
        status: SourceProviderStatus::Complete,
        result: Some(VerifiedSourceReleaseV1 {
            lease_digest: receipt.lease_digest(),
            release_generation: receipt.release_generation(),
        }),
        sequence,
    })
}

/// Verifies one complete Inventory query/session/response graph.
///
/// # Errors
///
/// Returns [`SourceProviderVerificationError`] for any signature, trust,
/// route, session, deadline, snapshot, descriptor, rollback, or cross-object
/// mismatch.
#[allow(clippy::too_many_arguments)]
pub fn verify_source_inventory(
    signed_request: &SignedSourceProviderRequestV1,
    response: &InventorySourceResponseV1,
    session: &SourceProviderSessionV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
    catalog_floor: &ProviderCatalogFloorV1,
    selection_floors: &[SourceSelectionFloorV1],
    context: &SourceProviderVerificationContextV1,
    descriptor_roles: &[SourceProviderDescriptorRole],
) -> Result<
    VerifiedSourceProviderDispositionV1<VerifiedSourceInventoryV1>,
    SourceProviderVerificationError,
> {
    require_method(signed_request, SourceProviderMethod::Inventory)?;
    let request = decode_inventory_request(signed_request.subject())?;
    validate_message_descriptor_contract(
        &SourceProviderMessageV1::InventoryResponse(response.clone()),
        descriptor_roles,
    )?;
    verify_current_session(
        session,
        signed_request,
        trust_set,
        root_current,
        provider_current,
        route,
        context,
    )?;
    verify_current_request(signed_request, trust_set, root_current, context.now_seconds)?;
    verify_current_status_signature(
        response.signed_status(),
        trust_set,
        provider_current,
        context.now_seconds,
    )?;
    verify_request_session(
        request.session_binding(),
        request.sequence(),
        session,
        context,
    )?;
    verify_request_bounds(
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        request.deadline_seconds(),
        context,
    )?;
    let sequence = verify_outer_status(
        signed_request,
        response.signed_status(),
        response.signed_inventory(),
        request.request_id(),
        session,
        context,
        empty_descriptor_set_commitment_v1(),
    )?;
    if response.status() != SourceProviderStatus::Complete {
        return disposition(response.status(), None, sequence);
    }
    let signed_inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(
        response
            .signed_inventory()
            .ok_or(SourceProviderVerificationError::CrossLink)?,
    )?;
    let inventory_key = trust_set.resolve_current(
        provider_current,
        signed_inventory.signer(),
        context.now_seconds,
    )?;
    verify_inventory(&signed_inventory, inventory_key)?;
    let inventory = signed_inventory.subject();
    if inventory.request_id() != request.request_id()
        || inventory.request_digest() != digest_inventory_request(&request)
        || inventory.holder_authority_id() != request.holder_authority_id()
        || inventory.holder_generation() != request.holder_generation()
        || inventory.holder_authority_digest() != request.holder_authority_digest()
        || inventory.provider_process_instance() != session.provider_hello().process_instance()
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    if inventory.provider() != provider_current.authority()
        || catalog_floor.provider_authority_id() != provider_current.authority().authority_id()
        || catalog_floor.resource_namespace_digest() != route.resource_namespace_digest()
        || below_floor_or_equivocates(
            inventory.catalog_generation(),
            inventory.catalog_digest(),
            catalog_floor.minimum_catalog_generation(),
            catalog_floor.minimum_catalog_digest(),
        )
    {
        return Err(SourceProviderVerificationError::Rollback);
    }
    if selection_floors.len() > crate::trust::MAXIMUM_SOURCE_SELECTION_FLOORS
        || !selection_floors
            .windows(2)
            .all(|pair| pair[0].acquisition_id() < pair[1].acquisition_id())
    {
        return Err(SourceProviderVerificationError::Rollback);
    }
    for floor in selection_floors {
        trust_set.validate_selection_floor(floor)?;
        if floor.provider_authority_id() != provider_current.authority().authority_id()
            || floor.route_id() != route.route_id()
            || floor.resource().resource_namespace_digest() != route.resource_namespace_digest()
        {
            return Err(SourceProviderVerificationError::Rollback);
        }
    }
    let mut matched_entry_indices = Vec::new();
    let mut authenticated_residual_entry_indices = Vec::new();
    for (index, entry) in inventory.entries().iter().enumerate() {
        let resource = entry.resource();
        if resource.resource_namespace_digest() != route.resource_namespace_digest()
            || resource.catalog_generation() > inventory.catalog_generation()
            || (resource.catalog_generation() == inventory.catalog_generation()
                && resource.catalog_digest() != inventory.catalog_digest())
            || entry.proof_class() == 0
            || entry.proof_class() > 4
            || (1 << (entry.proof_class() - 1)) & route.proof_capabilities() == 0
            || (1 << (entry.proof_class() - 1)) & provider_current.proof_capabilities() == 0
            || (1 << (entry.proof_class() - 1))
                & session.provider_hello().proof_class_capabilities()
                == 0
            || entry.resource_commitment()
                != provider_resource_commitment_v1(resource, entry.proof_digest())
        {
            return Err(SourceProviderVerificationError::Rollback);
        }
        if let Some(floor) = selection_floors
            .iter()
            .find(|floor| floor.acquisition_id() == entry.acquisition_id())
        {
            if !inventory_entry_matches_floor(entry, floor, route, provider_current) {
                return Err(SourceProviderVerificationError::Rollback);
            }
            matched_entry_indices
                .push(u16::try_from(index).map_err(|_| SourceProviderVerificationError::Rollback)?);
        } else {
            authenticated_residual_entry_indices
                .push(u16::try_from(index).map_err(|_| SourceProviderVerificationError::Rollback)?);
        }
    }
    Ok(VerifiedSourceProviderDispositionV1 {
        status: SourceProviderStatus::Complete,
        result: Some(VerifiedSourceInventoryV1 {
            signed_inventory,
            matched_entry_indices,
            authenticated_residual_entry_indices,
        }),
        sequence,
    })
}

fn verify_current_session(
    session: &SourceProviderSessionV1,
    signed_request: &SignedSourceProviderRequestV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    let root_hello_key = trust_set.resolve_current(
        root_current,
        session.signed_root_mount_hello().signer(),
        context.now_seconds,
    )?;
    let provider_hello_key = trust_set.resolve_current(
        provider_current,
        session.signed_provider_hello().signer(),
        context.now_seconds,
    )?;
    verify_hello(session.signed_root_mount_hello(), root_hello_key)?;
    verify_hello(session.signed_provider_hello(), provider_hello_key)?;
    route.verify_current_authority(root_current)?;
    route.verify_current_authority(provider_current)?;
    let root_hello = session.root_mount_hello();
    let provider_hello = session.provider_hello();
    if session.route() != route
        || signed_request.signer() != root_current.traffic_signer()
        || root_hello.traffic_signer() != signed_request.signer()
        || root_hello.expected_peer_traffic_signer() != provider_current.traffic_signer()
        || provider_hello.traffic_signer() != provider_current.traffic_signer()
        || provider_hello.expected_peer_traffic_signer() != signed_request.signer()
        || root_hello.kernel_boot_id() != context.boot_id
        || provider_hello.kernel_boot_id() != context.boot_id
        || provider_hello.proof_class_capabilities() & route.proof_capabilities() == 0
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(())
}

fn verify_current_request(
    signed_request: &SignedSourceProviderRequestV1,
    trust_set: &SourceProviderTrustSetV1,
    root_current: &SourceProviderCurrentAuthorityV1,
    now_seconds: i64,
) -> Result<(), SourceProviderVerificationError> {
    let public_key =
        trust_set.resolve_current(root_current, signed_request.signer(), now_seconds)?;
    verify_request(signed_request, public_key)?;
    Ok(())
}

fn verify_current_status_signature(
    signed_status: &SignedSourceProviderStatusV1,
    trust_set: &SourceProviderTrustSetV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    now_seconds: i64,
) -> Result<(), SourceProviderVerificationError> {
    let public_key =
        trust_set.resolve_current(provider_current, signed_status.signer(), now_seconds)?;
    verify_response_status(signed_status, public_key)?;
    Ok(())
}

fn verify_request_session(
    binding: ObjectDigest,
    sequence: u64,
    session: &SourceProviderSessionV1,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    if binding != session.binding() || sequence != context.expected_request_sequence {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_outer_status(
    signed_request: &SignedSourceProviderRequestV1,
    signed_status: &SignedSourceProviderStatusV1,
    result: Option<&[u8]>,
    request_id: [u8; 16],
    session: &SourceProviderSessionV1,
    context: &SourceProviderVerificationContextV1,
    descriptor_commitment: ObjectDigest,
) -> Result<VerifiedSourceProviderSequenceV1, SourceProviderVerificationError> {
    let status = signed_status.subject();
    if status.method() != signed_request.method()
        || status.request_id() != request_id
        || status.signed_request_digest() != digest_signed_request(signed_request)
        || status.provider_process_instance() != session.provider_hello().process_instance()
        || status.session_binding() != session.binding()
        || status.response_sequence() != context.expected_response_sequence
        || status.result_digest()
            != response_result_digest_v1(status.method(), status.status(), result)
        || status.descriptor_commitment() != descriptor_commitment
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(VerifiedSourceProviderSequenceV1 {
        session_binding: session.binding(),
        request_sequence: context.expected_request_sequence,
        response_sequence: context.expected_response_sequence,
    })
}

fn verify_acquire_bounds(
    request: &AcquireSourceRequestV1,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    verify_request_bounds(
        request.holder_authority_id(),
        request.holder_generation(),
        request.holder_authority_digest(),
        request.deadline_seconds(),
        context,
    )?;
    if request.node_id() != context.node_id
        || request.boot_id() != context.boot_id
        || request.revocation_digest() != context.revocation_digest
    {
        return Err(SourceProviderVerificationError::Bounds);
    }
    Ok(())
}

fn verify_request_bounds(
    holder_authority_id: [u8; 16],
    holder_generation: u64,
    holder_authority_digest: ObjectDigest,
    deadline_seconds: i64,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    if holder_authority_id != context.holder_authority_id
        || holder_generation != context.holder_generation
        || holder_authority_digest != context.holder_authority_digest
        || context.now_seconds >= deadline_seconds
    {
        return Err(SourceProviderVerificationError::Bounds);
    }
    Ok(())
}

fn verify_provider_selection(
    lease: &crate::model::SourceExportLeaseV1,
    request: &AcquireSourceRequestV1,
    session: &SourceProviderSessionV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
    route: &ProtectedSourceProviderRouteV1,
    catalog_floor: &ProviderCatalogFloorV1,
    selection_floor: Option<&SourceSelectionFloorV1>,
    context: &SourceProviderVerificationContextV1,
) -> Result<(), SourceProviderVerificationError> {
    let provider_hello = session.provider_hello();
    let resource = lease.resource();
    let proof = lease.proof();
    let duration = lease
        .expires_seconds()
        .checked_sub(lease.issued_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or(SourceProviderVerificationError::Bounds)?;
    if lease.issued_seconds() > context.now_seconds
        || context.now_seconds >= lease.expires_seconds()
        || lease.expires_seconds() > context.maximum_lease_expiry_seconds
        || duration == 0
        || duration > request.requested_lease_seconds()
    {
        return Err(SourceProviderVerificationError::Bounds);
    }
    let expected_provider_authority = selection_floor
        .map(SourceSelectionFloorV1::outcome_signer)
        .map(|signer| {
            (
                signer.authority_id(),
                signer.authority_generation(),
                signer.authority_digest(),
            )
        })
        .unwrap_or((
            provider_current.authority().authority_id(),
            provider_current.authority().authority_generation(),
            provider_current.authority().authority_digest(),
        ));
    let new_selection_violates_catalog_floor = selection_floor.is_none()
        && below_floor_or_equivocates(
            resource.catalog_generation(),
            resource.catalog_digest(),
            catalog_floor.minimum_catalog_generation(),
            catalog_floor.minimum_catalog_digest(),
        );
    if (
        lease.provider().authority_id(),
        lease.provider().authority_generation(),
        lease.provider().authority_digest(),
    ) != expected_provider_authority
        || catalog_floor.provider_authority_id() != provider_current.authority().authority_id()
        || catalog_floor.resource_namespace_digest() != route.resource_namespace_digest()
        || resource.resource_namespace_digest() != route.resource_namespace_digest()
        || new_selection_violates_catalog_floor
    {
        return Err(SourceProviderVerificationError::Rollback);
    }
    let proof_bit = proof.capability_bit();
    if proof_bit & provider_current.proof_capabilities() == 0
        || proof_bit & route.proof_capabilities() == 0
        || proof_bit & provider_hello.proof_class_capabilities() == 0
        || proof.requires_kernel_coupled() != request.kernel_coupled()
        || (request.kernel_coupled()
            && (!provider_hello.supports_kernel_coupled() || !route.allows_kernel_coupled()))
        || (request.recursive()
            && (!provider_hello.supports_recursive() || !route.allows_recursive()))
        || proof.topology().observed_submounts() > request.requested_maximum_submounts()
        || (!request.recursive() && proof.topology().observed_submounts() != 0)
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    if selection_floor.is_some_and(|floor| {
        floor.acquisition_id() != request.acquisition_id()
            || floor.provider_authority_id() != provider_current.authority().authority_id()
            || floor.route_id() != route.route_id()
    }) {
        return Err(SourceProviderVerificationError::Rollback);
    }
    Ok(())
}

fn below_floor_or_equivocates(
    generation: u64,
    digest: ObjectDigest,
    floor_generation: u64,
    floor_digest: ObjectDigest,
) -> bool {
    generation < floor_generation || (generation == floor_generation && digest != floor_digest)
}

fn require_exact_selection_floor(
    floor: &SourceSelectionFloorV1,
    acquisition_id: ObjectDigest,
    route: &ProtectedSourceProviderRouteV1,
    signed_lease: &SignedSourceExportLeaseV1,
    proof_digest: ObjectDigest,
    resource_commitment: ObjectDigest,
) -> Result<(), SourceProviderVerificationError> {
    let lease = signed_lease.subject();
    if floor.acquisition_id() != acquisition_id
        || floor.provider_authority_id() != lease.provider().authority_id()
        || floor.route_id() != route.route_id()
        || floor.resource() != lease.resource()
        || floor.outcome_signer() != signed_lease.signer()
        || floor.lease_id() != lease.lease_id()
        || floor.signed_lease_digest() != digest_signed_export_lease(signed_lease)
        || floor.proof_class() != lease.proof().class_code()
        || floor.proof_digest() != proof_digest
        || floor.resource_commitment() != resource_commitment
    {
        return Err(SourceProviderVerificationError::Rollback);
    }
    Ok(())
}

fn inventory_entry_matches_floor(
    entry: &crate::model::SourceProviderInventoryEntryV1,
    floor: &SourceSelectionFloorV1,
    route: &ProtectedSourceProviderRouteV1,
    provider_current: &SourceProviderCurrentAuthorityV1,
) -> bool {
    floor.provider_authority_id() == provider_current.authority().authority_id()
        && floor.route_id() == route.route_id()
        && entry.lease_id() == floor.lease_id()
        && entry.lease_digest() == floor.signed_lease_digest()
        && entry.resource() == floor.resource()
        && entry.proof_class() == floor.proof_class()
        && entry.proof_digest() == floor.proof_digest()
        && entry.resource_commitment() == floor.resource_commitment()
}

fn require_method(
    request: &SignedSourceProviderRequestV1,
    expected: SourceProviderMethod,
) -> Result<(), SourceProviderVerificationError> {
    if request.method() != expected {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    Ok(())
}

fn disposition<T>(
    status: SourceProviderStatus,
    complete: Option<T>,
    sequence: VerifiedSourceProviderSequenceV1,
) -> Result<VerifiedSourceProviderDispositionV1<T>, SourceProviderVerificationError> {
    match (status, complete) {
        (SourceProviderStatus::Complete, Some(value)) => Ok(VerifiedSourceProviderDispositionV1 {
            status,
            result: Some(value),
            sequence,
        }),
        (
            SourceProviderStatus::Pending
            | SourceProviderStatus::Rejected
            | SourceProviderStatus::Unavailable,
            None,
        ) => Ok(VerifiedSourceProviderDispositionV1 {
            status,
            result: None,
            sequence,
        }),
        _ => Err(SourceProviderVerificationError::CrossLink),
    }
}
