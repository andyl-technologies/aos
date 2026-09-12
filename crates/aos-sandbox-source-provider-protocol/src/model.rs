//! Validated SourceProvider 1.0 semantic values.
//!
//! The model separates stable provider authority and resource generations from
//! the process instance claimed as a receipt issuer. Backend-specific
//! proof bytes are structured and bounded, while their truth remains the
//! responsibility of the provider implementation and its configured verifier.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::crypto::{
    SignedSourceProviderInventoryV1, SignedSourceProviderReceiptV1, SignedSourceProviderStatusV1,
    SignedSourceReleaseReceiptV1, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
    empty_descriptor_set_commitment_v1, response_result_digest_v1,
};
use crate::proof::SourceProviderProofV1;

const LOGICAL_BINDING_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.mount.source-realization-binding.v1\0";
const PROSPECTIVE_MOUNT_TEMPLATE_DIGEST_DOMAIN: &[u8] =
    b"aos-source-provider-prospective-mount-template-v1\0";
const MOUNT_SEMANTICS_MAGIC: &[u8; 8] = b"AOSMSEM1";
const MAXIMUM_MOUNT_TEMPLATE_BYTES: usize = 2 * 1024;
const MAXIMUM_SIGNED_INVENTORY_BYTES: usize = 768 * 1024;

/// Largest canonical logical source binding accepted by protocol 1.0.
pub const MAXIMUM_BINDING_BYTES: usize = 64 * 1024;
/// Longest holder lease permitted by protocol 1.0.
pub const MAXIMUM_SOURCE_LEASE_SECONDS: u64 = 86_400;
/// Largest recursive source tree admitted by a protocol 1.0 proof.
pub const MAXIMUM_RECURSIVE_ENTRY_COUNT: u64 = 1 << 48;
/// Largest represented recursive source size admitted by protocol 1.0.
pub const MAXIMUM_RECURSIVE_BYTE_COUNT: u64 = 1 << 60;
/// Largest represented directory depth admitted by protocol 1.0.
pub const MAXIMUM_RECURSIVE_DEPTH: u32 = 1 << 20;
/// Largest lease inventory returned in one protocol 1.0 response.
pub const MAXIMUM_INVENTORY_ENTRIES: usize = 2_048;
/// Largest requested or observed source submount count.
pub const MAXIMUM_SOURCE_SUBMOUNTS: u32 = 65_536;
/// Bitmask containing every SourceProvider 1.0 proof class.
pub const ALL_PROOF_CLASS_CAPABILITIES: u8 = 0b1111;

/// Reports a noncanonical or semantically invalid SourceProvider value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderValidationError {
    /// A required fixed identifier or digest uses its reserved all-zero value.
    #[error("{0} must not use the all-zero sentinel")]
    Zero(&'static str),
    /// A generation or revision uses its reserved zero value.
    #[error("{0} generation must be nonzero")]
    ZeroGeneration(&'static str),
    /// A bounded byte string is empty or exceeds its protocol limit.
    #[error("{field} length {actual} is outside 1..={maximum}")]
    InvalidLength {
        /// Field whose byte length is invalid.
        field: &'static str,
        /// Observed byte length.
        actual: usize,
        /// Inclusive protocol ceiling.
        maximum: usize,
    },
    /// A validity interval is empty, reversed, or already outside its parent interval.
    #[error("invalid {0} time interval")]
    InvalidInterval(&'static str),
    /// Recursive topology counters exceed protocol ceilings or contradict one another.
    #[error("invalid recursive topology counters")]
    InvalidTopology,
    /// Inventory entries are unordered, duplicated, or too numerous.
    #[error("provider inventory entries are not canonical")]
    InventoryNotCanonical,
    /// Response status and receipt presence disagree.
    #[error("source-provider response status and receipt presence disagree")]
    ResponseShape,
    /// Exact logical binding bytes do not match their committed digest.
    #[error("logical binding bytes do not match their digest")]
    BindingDigestMismatch,
    /// A method/status/descriptor table violates the closed transfer contract.
    #[error("source-provider descriptor contract does not match the method and status")]
    DescriptorContract,
    /// A capability mask contains an unknown bit or excludes every proof class.
    #[error("invalid SourceProvider capability set")]
    InvalidCapabilities,
    /// Recursive or kernel-coupled proof facts exceed the exact request.
    #[error("source proof exceeds requested topology capabilities")]
    ProofCapabilityMismatch,
    /// Canonical Mount semantics bytes are malformed or use another format.
    #[error("invalid prospective Mount Apply template")]
    InvalidMountTemplate,
}

/// Identifies the endpoint role claimed by a SourceProvider hello subject.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderPeerRole {
    /// Root Mount broker issuing holder-scoped queries.
    RootMount = 1,
    /// Source provider answering for one configured route.
    Provider = 2,
}

/// Identifies an exact SourceProvider 1.0 operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderMethod {
    /// Introduces one protocol endpoint and its claimed execution instance.
    Hello = 1,
    /// Acquires or exactly replays one source-root lease and descriptor.
    Acquire = 2,
    /// Releases one exact provider lease.
    Release = 3,
    /// Inventories leases held for one exact Mount holder.
    Inventory = 4,
}

/// Identifies a required SourceProvider 1.0 semantic feature.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderFeature {
    /// Requires signed receipts, holder leases, and exact replay.
    SignedLeaseReceipts = 1,
}

/// Identifies the sole descriptor role in SourceProvider 1.0.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderDescriptorRole {
    /// One provider-opened `O_PATH` source-root directory.
    SourceRoot = 1,
}

/// Reports the closed result class for a SourceProvider operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderStatus {
    /// The operation completed and its receipt is present.
    Complete = 1,
    /// The exact request is still durably pending.
    Pending = 2,
    /// The exact request was durably rejected without an effect.
    Rejected = 3,
    /// The provider cannot currently answer without weakening authority.
    Unavailable = 4,
}

/// Describes why Mount will use an acquired source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceUseV1 {
    /// Supplies the source of one prospective Mount Create operation.
    MountCreate = 1,
}

/// Carries one exact protocol endpoint introduction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderHelloV1 {
    pub(crate) role: SourceProviderPeerRole,
    pub(crate) nonce: [u8; 32],
    pub(crate) process_instance: [u8; 16],
    pub(crate) kernel_boot_id: [u8; 16],
    pub(crate) expected_peer_signer: SourceProviderSigningKeyV1,
    pub(crate) route_id: [u8; 16],
    pub(crate) route_generation: u64,
    pub(crate) route_digest: ObjectDigest,
    pub(crate) client_hello_digest: Option<ObjectDigest>,
    pub(crate) proof_class_capabilities: u8,
    pub(crate) supports_recursive: bool,
    pub(crate) supports_kernel_coupled: bool,
}

impl SourceProviderHelloV1 {
    /// Constructs a SourceProvider endpoint introduction subject.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for a zero nonce, instance,
    /// boot, route field, invalid peer-key use, capabilities, or client-digest
    /// shape.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: SourceProviderPeerRole,
        nonce: [u8; 32],
        process_instance: [u8; 16],
        kernel_boot_id: [u8; 16],
        expected_peer_signer: SourceProviderSigningKeyV1,
        route_id: [u8; 16],
        route_generation: u64,
        route_digest: ObjectDigest,
        client_hello_digest: Option<ObjectDigest>,
        proof_class_capabilities: u8,
        supports_recursive: bool,
        supports_kernel_coupled: bool,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("hello nonce", &nonce)?;
        require_nonzero("process instance", &process_instance)?;
        require_nonzero("hello boot ID", &kernel_boot_id)?;
        require_nonzero("hello route ID", &route_id)?;
        require_generation("hello route", route_generation)?;
        require_digest("hello route digest", route_digest)?;
        require_proof_capabilities(proof_class_capabilities)?;
        let expected_usage = match role {
            SourceProviderPeerRole::RootMount => SourceProviderKeyUsageV1::ProviderReceipt,
            SourceProviderPeerRole::Provider => SourceProviderKeyUsageV1::RootMountQuery,
        };
        if expected_peer_signer.usage() != expected_usage
            || (role == SourceProviderPeerRole::RootMount && client_hello_digest.is_some())
            || (role == SourceProviderPeerRole::Provider && client_hello_digest.is_none())
        {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        if let Some(digest) = client_hello_digest {
            require_digest("signed client hello digest", digest)?;
        }
        Ok(Self {
            role,
            nonce,
            process_instance,
            kernel_boot_id,
            expected_peer_signer,
            route_id,
            route_generation,
            route_digest,
            client_hello_digest,
            proof_class_capabilities,
            supports_recursive,
            supports_kernel_coupled,
        })
    }

    /// Returns the claimed endpoint role.
    #[must_use]
    pub const fn role(&self) -> SourceProviderPeerRole {
        self.role
    }

    /// Returns the claimed ephemeral process-execution instance.
    #[must_use]
    pub const fn process_instance(&self) -> [u8; 16] {
        self.process_instance
    }

    /// Returns the transcript nonce claim.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    /// Returns the claimed kernel boot for this process instance.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Returns the exact peer-key reference claimed for this transcript.
    #[must_use]
    pub const fn expected_peer_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.expected_peer_signer
    }

    /// Returns the claimed route identity.
    #[must_use]
    pub const fn route_id(&self) -> [u8; 16] {
        self.route_id
    }

    /// Returns the claimed route generation.
    #[must_use]
    pub const fn route_generation(&self) -> u64 {
        self.route_generation
    }

    /// Returns the claimed route digest.
    #[must_use]
    pub const fn route_digest(&self) -> ObjectDigest {
        self.route_digest
    }

    /// Returns the claimed digest of the exact signed client hello.
    #[must_use]
    pub const fn client_hello_digest(&self) -> Option<ObjectDigest> {
        self.client_hello_digest
    }

    /// Returns the claimed supported proof-class bitset.
    #[must_use]
    pub const fn proof_class_capabilities(&self) -> u8 {
        self.proof_class_capabilities
    }

    /// Reports whether recursive source traversal is claimed as supported.
    #[must_use]
    pub const fn supports_recursive(&self) -> bool {
        self.supports_recursive
    }

    /// Reports whether kernel-coupled live exports are claimed as supported.
    #[must_use]
    pub const fn supports_kernel_coupled(&self) -> bool {
        self.supports_kernel_coupled
    }
}

/// Identifies one stable provider authority and signing-key generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAuthorityV1 {
    pub(crate) authority_id: [u8; 16],
    pub(crate) authority_generation: u64,
    pub(crate) authority_digest: ObjectDigest,
    pub(crate) key_id: [u8; 16],
    pub(crate) key_generation: u64,
    pub(crate) public_key_digest: ObjectDigest,
}

impl ProviderAuthorityV1 {
    /// Constructs a stable provider authority and exact signing-key reference.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel identities,
    /// generations, or digests.
    pub fn new(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: ObjectDigest,
        key_id: [u8; 16],
        key_generation: u64,
        public_key_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("provider authority ID", &authority_id)?;
        require_generation("provider authority", authority_generation)?;
        require_digest("provider authority digest", authority_digest)?;
        require_nonzero("provider key ID", &key_id)?;
        require_generation("provider key", key_generation)?;
        require_digest("provider public-key digest", public_key_digest)?;
        Ok(Self {
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            public_key_digest,
        })
    }

    /// Returns the stable authority ID.
    #[must_use]
    pub const fn authority_id(&self) -> [u8; 16] {
        self.authority_id
    }

    /// Returns the authority generation.
    #[must_use]
    pub const fn authority_generation(&self) -> u64 {
        self.authority_generation
    }

    /// Returns the authority-state digest.
    #[must_use]
    pub const fn authority_digest(&self) -> ObjectDigest {
        self.authority_digest
    }

    /// Returns the stable key ID.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 16] {
        self.key_id
    }

    /// Returns the signing-key generation.
    #[must_use]
    pub const fn key_generation(&self) -> u64 {
        self.key_generation
    }

    /// Returns SHA-256 over the exact Ed25519 public key.
    #[must_use]
    pub const fn public_key_digest(&self) -> ObjectDigest {
        self.public_key_digest
    }
}

/// Identifies one stable provider resource and selected catalog generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceResourceV1 {
    pub(crate) resource_namespace_digest: ObjectDigest,
    pub(crate) resource_id: [u8; 32],
    pub(crate) resource_generation: u64,
    pub(crate) resource_digest: ObjectDigest,
    pub(crate) catalog_generation: u64,
    pub(crate) catalog_digest: ObjectDigest,
    pub(crate) selection_generation: u64,
    pub(crate) selection_digest: ObjectDigest,
}

impl SourceResourceV1 {
    /// Constructs one exact provider resource and selection.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource_namespace_digest: ObjectDigest,
        resource_id: [u8; 32],
        resource_generation: u64,
        resource_digest: ObjectDigest,
        catalog_generation: u64,
        catalog_digest: ObjectDigest,
        selection_generation: u64,
        selection_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_digest(
            "provider resource namespace digest",
            resource_namespace_digest,
        )?;
        require_nonzero("provider resource ID", &resource_id)?;
        require_generation("provider resource", resource_generation)?;
        require_digest("provider resource digest", resource_digest)?;
        require_generation("provider catalog", catalog_generation)?;
        require_digest("provider catalog digest", catalog_digest)?;
        require_generation("provider selection", selection_generation)?;
        require_digest("provider selection digest", selection_digest)?;
        Ok(Self {
            resource_namespace_digest,
            resource_id,
            resource_generation,
            resource_digest,
            catalog_generation,
            catalog_digest,
            selection_generation,
            selection_digest,
        })
    }

    /// Returns the claimed resource-namespace commitment.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }

    /// Returns the stable provider resource ID.
    #[must_use]
    pub const fn resource_id(&self) -> [u8; 32] {
        self.resource_id
    }

    /// Returns the resource generation.
    #[must_use]
    pub const fn resource_generation(&self) -> u64 {
        self.resource_generation
    }

    /// Returns the resource-state digest.
    #[must_use]
    pub const fn resource_digest(&self) -> ObjectDigest {
        self.resource_digest
    }

    /// Returns the provider catalog generation.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    /// Returns the provider catalog digest.
    #[must_use]
    pub const fn catalog_digest(&self) -> ObjectDigest {
        self.catalog_digest
    }

    /// Returns the exact selection generation within the provider catalog.
    #[must_use]
    pub const fn selection_generation(&self) -> u64 {
        self.selection_generation
    }

    /// Returns the exact selection digest within the provider catalog.
    #[must_use]
    pub const fn selection_digest(&self) -> ObjectDigest {
        self.selection_digest
    }
}

/// Requests one exact source lease and root descriptor from a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireSourceRequestV1 {
    pub(crate) session_binding: ObjectDigest,
    pub(crate) sequence: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) prospective_apply_template: Vec<u8>,
    pub(crate) prospective_apply_template_digest: ObjectDigest,
    pub(crate) source_use: SourceUseV1,
    pub(crate) node_id: [u8; 16],
    pub(crate) boot_id: [u8; 16],
    pub(crate) holder_authority_id: [u8; 16],
    pub(crate) holder_generation: u64,
    pub(crate) holder_authority_digest: ObjectDigest,
    pub(crate) binding: Vec<u8>,
    pub(crate) binding_digest: ObjectDigest,
    pub(crate) deadline_seconds: i64,
    pub(crate) requested_lease_seconds: u64,
    pub(crate) revocation_digest: ObjectDigest,
    pub(crate) recursive: bool,
    pub(crate) requested_maximum_submounts: u32,
    pub(crate) kernel_coupled: bool,
}

impl AcquireSourceRequestV1 {
    /// Constructs one bounded provider acquisition query.
    ///
    /// `binding` is the exact canonical Mount logical-binding encoding. This
    /// crate commits it byte-for-byte without interpreting Mount semantics.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel identities,
    /// digests, generations, deadline/lease bounds, or invalid binding bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_binding: ObjectDigest,
        sequence: u64,
        request_id: [u8; 16],
        acquisition_id: ObjectDigest,
        prospective_apply_template: Vec<u8>,
        prospective_apply_template_digest: ObjectDigest,
        source_use: SourceUseV1,
        node_id: [u8; 16],
        boot_id: [u8; 16],
        holder_authority_id: [u8; 16],
        holder_generation: u64,
        holder_authority_digest: ObjectDigest,
        binding: Vec<u8>,
        binding_digest: ObjectDigest,
        deadline_seconds: i64,
        requested_lease_seconds: u64,
        revocation_digest: ObjectDigest,
        recursive: bool,
        requested_maximum_submounts: u32,
        kernel_coupled: bool,
    ) -> Result<Self, SourceProviderValidationError> {
        require_digest("Acquire session binding", session_binding)?;
        require_generation("Acquire sequence", sequence)?;
        require_nonzero("acquire request ID", &request_id)?;
        require_digest("acquisition ID", acquisition_id)?;
        validate_prospective_mount_template(
            &prospective_apply_template,
            prospective_apply_template_digest,
        )?;
        require_nonzero("node ID", &node_id)?;
        require_nonzero("boot ID", &boot_id)?;
        require_nonzero("holder authority ID", &holder_authority_id)?;
        require_generation("holder", holder_generation)?;
        require_digest("holder authority digest", holder_authority_digest)?;
        require_bytes("logical binding", &binding, MAXIMUM_BINDING_BYTES)?;
        require_digest("logical binding digest", binding_digest)?;
        if digest_logical_binding_bytes(&binding) != binding_digest {
            return Err(SourceProviderValidationError::BindingDigestMismatch);
        }
        require_digest("revocation digest", revocation_digest)?;
        if deadline_seconds <= 0
            || requested_lease_seconds == 0
            || requested_lease_seconds > MAXIMUM_SOURCE_LEASE_SECONDS
        {
            return Err(SourceProviderValidationError::InvalidInterval(
                "acquisition",
            ));
        }
        if requested_maximum_submounts > MAXIMUM_SOURCE_SUBMOUNTS
            || (!recursive && requested_maximum_submounts != 0)
        {
            return Err(SourceProviderValidationError::ProofCapabilityMismatch);
        }
        Ok(Self {
            session_binding,
            sequence,
            request_id,
            acquisition_id,
            prospective_apply_template,
            prospective_apply_template_digest,
            source_use,
            node_id,
            boot_id,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            binding,
            binding_digest,
            deadline_seconds,
            requested_lease_seconds,
            revocation_digest,
            recursive,
            requested_maximum_submounts,
            kernel_coupled,
        })
    }

    /// Returns the provider-idempotency request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the claimed hello-transcript binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the client-to-provider session sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the Mount-minted acquisition ID.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the prospective Mount Apply/template commitment.
    #[must_use]
    pub const fn prospective_apply_template_digest(&self) -> ObjectDigest {
        self.prospective_apply_template_digest
    }

    /// Returns the intended use of the source.
    #[must_use]
    pub const fn source_use(&self) -> SourceUseV1 {
        self.source_use
    }

    /// Returns the exact canonical logical binding bytes.
    #[must_use]
    pub fn binding(&self) -> &[u8] {
        &self.binding
    }

    /// Returns the separately committed logical binding digest.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }
}

/// Claims a bounded holder lease over an exact selected source resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceExportLeaseV1 {
    pub(crate) lease_id: [u8; 16],
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: ObjectDigest,
    pub(crate) holder_authority_id: [u8; 16],
    pub(crate) holder_generation: u64,
    pub(crate) holder_authority_digest: ObjectDigest,
    pub(crate) provider: ProviderAuthorityV1,
    pub(crate) resource: SourceResourceV1,
    pub(crate) proof: SourceProviderProofV1,
    pub(crate) binding_digest: ObjectDigest,
    pub(crate) issued_seconds: i64,
    pub(crate) expires_seconds: i64,
    pub(crate) revocation_digest: ObjectDigest,
}

impl SourceExportLeaseV1 {
    /// Constructs one exact provider export lease.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields or an
    /// empty/reversed validity interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_id: [u8; 16],
        request_id: [u8; 16],
        request_digest: ObjectDigest,
        holder_authority_id: [u8; 16],
        holder_generation: u64,
        holder_authority_digest: ObjectDigest,
        provider: ProviderAuthorityV1,
        resource: SourceResourceV1,
        proof: SourceProviderProofV1,
        binding_digest: ObjectDigest,
        issued_seconds: i64,
        expires_seconds: i64,
        revocation_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("source export lease ID", &lease_id)?;
        require_nonzero("source export request ID", &request_id)?;
        require_digest("source export request digest", request_digest)?;
        require_nonzero("lease holder authority ID", &holder_authority_id)?;
        require_generation("lease holder", holder_generation)?;
        require_digest("lease holder authority digest", holder_authority_digest)?;
        require_digest("lease binding digest", binding_digest)?;
        require_digest("lease revocation digest", revocation_digest)?;
        let lease_seconds = expires_seconds
            .checked_sub(issued_seconds)
            .and_then(|seconds| u64::try_from(seconds).ok());
        if issued_seconds < 0
            || lease_seconds
                .is_none_or(|seconds| seconds == 0 || seconds > MAXIMUM_SOURCE_LEASE_SECONDS)
        {
            return Err(SourceProviderValidationError::InvalidInterval(
                "source export lease",
            ));
        }
        Ok(Self {
            lease_id,
            request_id,
            request_digest,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            provider,
            resource,
            proof,
            binding_digest,
            issued_seconds,
            expires_seconds,
            revocation_digest,
        })
    }

    /// Returns the stable provider lease ID.
    #[must_use]
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }

    /// Returns the acquisition request digest.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the stable provider authority and receipt-key reference.
    #[must_use]
    pub const fn provider(&self) -> &ProviderAuthorityV1 {
        &self.provider
    }

    /// Returns the exact provider resource selection.
    #[must_use]
    pub const fn resource(&self) -> &SourceResourceV1 {
        &self.resource
    }

    /// Returns the provider proof claim.
    #[must_use]
    pub const fn proof(&self) -> &SourceProviderProofV1 {
        &self.proof
    }
}

/// Carries one successful descriptor-bearing provider receipt subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderReceiptV1 {
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: ObjectDigest,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) provider_process_instance: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) signed_export_lease: Vec<u8>,
    pub(crate) descriptor_role: SourceProviderDescriptorRole,
    pub(crate) kernel_boot_id: [u8; 16],
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) unique_mount_id: u64,
    pub(crate) observed_proof_digest: ObjectDigest,
}

impl SourceProviderReceiptV1 {
    /// Constructs one successful provider receipt claim.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for any sentinel field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: [u8; 16],
        request_digest: ObjectDigest,
        acquisition_id: ObjectDigest,
        provider_process_instance: [u8; 16],
        lease_digest: ObjectDigest,
        signed_export_lease: Vec<u8>,
        descriptor_role: SourceProviderDescriptorRole,
        kernel_boot_id: [u8; 16],
        device: u64,
        inode: u64,
        unique_mount_id: u64,
        observed_proof_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("receipt request ID", &request_id)?;
        require_digest("receipt request digest", request_digest)?;
        require_digest("receipt acquisition ID", acquisition_id)?;
        require_nonzero("provider process instance", &provider_process_instance)?;
        require_digest("receipt lease digest", lease_digest)?;
        require_bytes("signed export lease", &signed_export_lease, 256 * 1024)?;
        require_nonzero("receipt boot ID", &kernel_boot_id)?;
        require_generation("source device", device)?;
        require_generation("source inode", inode)?;
        require_generation("source mount ID", unique_mount_id)?;
        require_digest("observed proof digest", observed_proof_digest)?;
        Ok(Self {
            request_id,
            request_digest,
            acquisition_id,
            provider_process_instance,
            lease_digest,
            signed_export_lease,
            descriptor_role,
            kernel_boot_id,
            device,
            inode,
            unique_mount_id,
            observed_proof_digest,
        })
    }

    /// Returns the provider process instance named as this receipt's issuer.
    #[must_use]
    pub const fn provider_process_instance(&self) -> [u8; 16] {
        self.provider_process_instance
    }

    /// Returns the claimed digest of the exact signed export lease.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the exact canonical signed export lease carried by this receipt.
    #[must_use]
    pub fn signed_export_lease(&self) -> &[u8] {
        &self.signed_export_lease
    }

    /// Returns the claimed descriptor role.
    #[must_use]
    pub const fn descriptor_role(&self) -> SourceProviderDescriptorRole {
        self.descriptor_role
    }
}

/// Commits the claimed disposition of one request in one session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderResponseStatusV1 {
    pub(crate) method: SourceProviderMethod,
    pub(crate) request_id: [u8; 16],
    pub(crate) signed_request_digest: ObjectDigest,
    pub(crate) status: SourceProviderStatus,
    pub(crate) provider_process_instance: [u8; 16],
    pub(crate) session_binding: ObjectDigest,
    pub(crate) response_sequence: u64,
    pub(crate) result_digest: ObjectDigest,
    pub(crate) descriptor_commitment: ObjectDigest,
}

impl SourceProviderResponseStatusV1 {
    /// Constructs one provider response signing subject.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for Hello, a sentinel identity,
    /// digest, process instance, session binding, or response sequence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        method: SourceProviderMethod,
        request_id: [u8; 16],
        signed_request_digest: ObjectDigest,
        status: SourceProviderStatus,
        provider_process_instance: [u8; 16],
        session_binding: ObjectDigest,
        response_sequence: u64,
        result_digest: ObjectDigest,
        descriptor_commitment: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        if method == SourceProviderMethod::Hello {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        require_nonzero("response request ID", &request_id)?;
        require_digest("signed request digest", signed_request_digest)?;
        require_nonzero(
            "response provider process instance",
            &provider_process_instance,
        )?;
        require_digest("response session binding", session_binding)?;
        require_generation("response sequence", response_sequence)?;
        require_digest("response result digest", result_digest)?;
        require_digest("response descriptor commitment", descriptor_commitment)?;
        Ok(Self {
            method,
            request_id,
            signed_request_digest,
            status,
            provider_process_instance,
            session_binding,
            response_sequence,
            result_digest,
            descriptor_commitment,
        })
    }

    /// Returns the claimed method.
    #[must_use]
    pub const fn method(&self) -> SourceProviderMethod {
        self.method
    }
    /// Returns the claimed request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    /// Returns the claimed digest of the full signed request envelope.
    #[must_use]
    pub const fn signed_request_digest(&self) -> ObjectDigest {
        self.signed_request_digest
    }
    /// Returns the claimed disposition.
    #[must_use]
    pub const fn status(&self) -> SourceProviderStatus {
        self.status
    }
    /// Returns the provider process instance named as this status's issuer.
    #[must_use]
    pub const fn provider_process_instance(&self) -> [u8; 16] {
        self.provider_process_instance
    }
    /// Returns the claimed signed hello-transcript binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }
    /// Returns the provider-to-client sequence.
    #[must_use]
    pub const fn response_sequence(&self) -> u64 {
        self.response_sequence
    }
    /// Returns the commitment to the exact nested result bytes.
    #[must_use]
    pub const fn result_digest(&self) -> ObjectDigest {
        self.result_digest
    }
    /// Returns the claimed descriptor-set commitment.
    #[must_use]
    pub const fn descriptor_commitment(&self) -> ObjectDigest {
        self.descriptor_commitment
    }
}

/// Carries one Acquire response without embedding native descriptor state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireSourceResponseV1 {
    pub(crate) signed_status: SignedSourceProviderStatusV1,
    pub(crate) signed_receipt: Option<Vec<u8>>,
}

impl AcquireSourceResponseV1 {
    /// Constructs one status/receipt pair with exact descriptor semantics.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] unless only a Complete response
    /// carries one nonempty bounded signed receipt.
    pub fn new(
        signed_status: SignedSourceProviderStatusV1,
        signed_receipt: Option<Vec<u8>>,
    ) -> Result<Self, SourceProviderValidationError> {
        if signed_status.subject().method() != SourceProviderMethod::Acquire {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        let correct_shape = match (signed_status.subject().status(), &signed_receipt) {
            (SourceProviderStatus::Complete, Some(bytes)) => {
                !bytes.is_empty() && bytes.len() <= 64 * 1024
            }
            (SourceProviderStatus::Pending, None)
            | (SourceProviderStatus::Rejected, None)
            | (SourceProviderStatus::Unavailable, None) => true,
            _ => false,
        };
        if !correct_shape {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        validate_response_commitments(&signed_status, signed_receipt.as_deref(), true)?;
        if let Some(bytes) = signed_receipt.as_deref()
            && SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).is_err()
        {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        Ok(Self {
            signed_status,
            signed_receipt,
        })
    }

    /// Returns the closed response status.
    #[must_use]
    pub const fn status(&self) -> SourceProviderStatus {
        self.signed_status.subject().status()
    }

    /// Returns the echoed provider request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.signed_status.subject().request_id()
    }

    /// Returns the provider-signed status envelope.
    #[must_use]
    pub const fn signed_status(&self) -> &SignedSourceProviderStatusV1 {
        &self.signed_status
    }

    /// Returns the exact signed completed receipt, when present.
    #[must_use]
    pub fn signed_receipt(&self) -> Option<&[u8]> {
        self.signed_receipt.as_deref()
    }
}

/// Carries one Release response and optional exact signed release receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSourceResponseV1 {
    pub(crate) signed_status: SignedSourceProviderStatusV1,
    pub(crate) signed_receipt: Option<Vec<u8>>,
}

impl ReleaseSourceResponseV1 {
    /// Constructs one exact Release status envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] unless only a Complete
    /// response carries one nonempty bounded signed release receipt.
    pub fn new(
        signed_status: SignedSourceProviderStatusV1,
        signed_receipt: Option<Vec<u8>>,
    ) -> Result<Self, SourceProviderValidationError> {
        if signed_status.subject().method() != SourceProviderMethod::Release {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        validate_response_shape(signed_status.subject().status(), &signed_receipt, 64 * 1024)?;
        validate_response_commitments(&signed_status, signed_receipt.as_deref(), false)?;
        if let Some(bytes) = signed_receipt.as_deref()
            && SignedSourceReleaseReceiptV1::from_canonical_bytes(bytes).is_err()
        {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        Ok(Self {
            signed_status,
            signed_receipt,
        })
    }

    /// Returns the echoed provider request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.signed_status.subject().request_id()
    }

    /// Returns the closed response status.
    #[must_use]
    pub const fn status(&self) -> SourceProviderStatus {
        self.signed_status.subject().status()
    }

    /// Returns the provider-signed status envelope.
    #[must_use]
    pub const fn signed_status(&self) -> &SignedSourceProviderStatusV1 {
        &self.signed_status
    }

    /// Returns the exact signed completed release receipt, when present.
    #[must_use]
    pub fn signed_receipt(&self) -> Option<&[u8]> {
        self.signed_receipt.as_deref()
    }
}

/// Carries one Inventory response and optional exact signed inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventorySourceResponseV1 {
    pub(crate) signed_status: SignedSourceProviderStatusV1,
    pub(crate) signed_inventory: Option<Vec<u8>>,
}

impl InventorySourceResponseV1 {
    /// Constructs one exact Inventory status envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] unless only a Complete
    /// response carries one nonempty bounded signed inventory.
    pub fn new(
        signed_status: SignedSourceProviderStatusV1,
        signed_inventory: Option<Vec<u8>>,
    ) -> Result<Self, SourceProviderValidationError> {
        if signed_status.subject().method() != SourceProviderMethod::Inventory {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        validate_response_shape(
            signed_status.subject().status(),
            &signed_inventory,
            MAXIMUM_SIGNED_INVENTORY_BYTES,
        )?;
        validate_response_commitments(&signed_status, signed_inventory.as_deref(), false)?;
        if let Some(bytes) = signed_inventory.as_deref()
            && SignedSourceProviderInventoryV1::from_canonical_bytes(bytes).is_err()
        {
            return Err(SourceProviderValidationError::ResponseShape);
        }
        Ok(Self {
            signed_status,
            signed_inventory,
        })
    }

    /// Returns the echoed provider request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.signed_status.subject().request_id()
    }

    /// Returns the closed response status.
    #[must_use]
    pub const fn status(&self) -> SourceProviderStatus {
        self.signed_status.subject().status()
    }

    /// Returns the provider-signed status envelope.
    #[must_use]
    pub const fn signed_status(&self) -> &SignedSourceProviderStatusV1 {
        &self.signed_status
    }

    /// Returns the exact signed completed inventory, when present.
    #[must_use]
    pub fn signed_inventory(&self) -> Option<&[u8]> {
        self.signed_inventory.as_deref()
    }
}

fn validate_response_shape(
    status: SourceProviderStatus,
    signed_result: &Option<Vec<u8>>,
    maximum_signed_result_bytes: usize,
) -> Result<(), SourceProviderValidationError> {
    let correct_shape = match (status, signed_result) {
        (SourceProviderStatus::Complete, Some(bytes)) => {
            !bytes.is_empty() && bytes.len() <= maximum_signed_result_bytes
        }
        (
            SourceProviderStatus::Pending
            | SourceProviderStatus::Rejected
            | SourceProviderStatus::Unavailable,
            None,
        ) => true,
        _ => false,
    };
    if !correct_shape {
        return Err(SourceProviderValidationError::ResponseShape);
    }
    Ok(())
}

fn validate_response_commitments(
    signed_status: &SignedSourceProviderStatusV1,
    signed_result: Option<&[u8]>,
    acquire: bool,
) -> Result<(), SourceProviderValidationError> {
    let status = signed_status.subject();
    let empty_descriptors = empty_descriptor_set_commitment_v1();
    let descriptor_shape = if acquire && status.status() == SourceProviderStatus::Complete {
        status.descriptor_commitment() != empty_descriptors
    } else {
        status.descriptor_commitment() == empty_descriptors
    };
    if !descriptor_shape
        || status.result_digest()
            != response_result_digest_v1(status.method(), status.status(), signed_result)
    {
        return Err(SourceProviderValidationError::ResponseShape);
    }
    Ok(())
}

/// Requests release of one exact provider lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSourceRequestV1 {
    pub(crate) session_binding: ObjectDigest,
    pub(crate) sequence: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) holder_authority_id: [u8; 16],
    pub(crate) holder_generation: u64,
    pub(crate) holder_authority_digest: ObjectDigest,
    pub(crate) lease_id: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) deadline_seconds: i64,
}

impl ReleaseSourceRequestV1 {
    /// Constructs an exact idempotent source-lease release request.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields or a
    /// nonpositive deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_binding: ObjectDigest,
        sequence: u64,
        request_id: [u8; 16],
        acquisition_id: ObjectDigest,
        holder_authority_id: [u8; 16],
        holder_generation: u64,
        holder_authority_digest: ObjectDigest,
        lease_id: [u8; 16],
        lease_digest: ObjectDigest,
        deadline_seconds: i64,
    ) -> Result<Self, SourceProviderValidationError> {
        require_digest("Release session binding", session_binding)?;
        require_generation("Release sequence", sequence)?;
        require_nonzero("release request ID", &request_id)?;
        require_digest("release acquisition ID", acquisition_id)?;
        require_nonzero("release holder authority ID", &holder_authority_id)?;
        require_generation("release holder", holder_generation)?;
        require_digest("release holder authority digest", holder_authority_digest)?;
        require_nonzero("release lease ID", &lease_id)?;
        require_digest("release lease digest", lease_digest)?;
        if deadline_seconds <= 0 {
            return Err(SourceProviderValidationError::InvalidInterval("release"));
        }
        Ok(Self {
            session_binding,
            sequence,
            request_id,
            acquisition_id,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            lease_id,
            lease_digest,
            deadline_seconds,
        })
    }
}

/// Claims the terminal state of one exact provider lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReleaseReceiptV1 {
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: ObjectDigest,
    pub(crate) lease_id: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) provider: ProviderAuthorityV1,
    pub(crate) provider_process_instance: [u8; 16],
    pub(crate) release_generation: u64,
    pub(crate) released_seconds: i64,
}

impl SourceReleaseReceiptV1 {
    /// Constructs one exact terminal provider release receipt.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields or an
    /// invalid release time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: [u8; 16],
        request_digest: ObjectDigest,
        lease_id: [u8; 16],
        lease_digest: ObjectDigest,
        provider: ProviderAuthorityV1,
        provider_process_instance: [u8; 16],
        release_generation: u64,
        released_seconds: i64,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("release receipt request ID", &request_id)?;
        require_digest("release receipt request digest", request_digest)?;
        require_nonzero("release receipt lease ID", &lease_id)?;
        require_digest("release receipt lease digest", lease_digest)?;
        require_nonzero(
            "release provider process instance",
            &provider_process_instance,
        )?;
        require_generation("release", release_generation)?;
        if released_seconds < 0 {
            return Err(SourceProviderValidationError::InvalidInterval(
                "release receipt",
            ));
        }
        Ok(Self {
            request_id,
            request_digest,
            lease_id,
            lease_digest,
            provider,
            provider_process_instance,
            release_generation,
            released_seconds,
        })
    }
}

/// Requests a signed bounded inventory for one exact Mount holder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventorySourceRequestV1 {
    pub(crate) session_binding: ObjectDigest,
    pub(crate) sequence: u64,
    pub(crate) request_id: [u8; 16],
    pub(crate) holder_authority_id: [u8; 16],
    pub(crate) holder_generation: u64,
    pub(crate) holder_authority_digest: ObjectDigest,
    pub(crate) known_inventory_digest: Option<ObjectDigest>,
    pub(crate) deadline_seconds: i64,
}

impl InventorySourceRequestV1 {
    /// Constructs one holder-scoped inventory request.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields or a
    /// nonpositive deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_binding: ObjectDigest,
        sequence: u64,
        request_id: [u8; 16],
        holder_authority_id: [u8; 16],
        holder_generation: u64,
        holder_authority_digest: ObjectDigest,
        known_inventory_digest: Option<ObjectDigest>,
        deadline_seconds: i64,
    ) -> Result<Self, SourceProviderValidationError> {
        require_digest("Inventory session binding", session_binding)?;
        require_generation("Inventory sequence", sequence)?;
        require_nonzero("inventory request ID", &request_id)?;
        require_nonzero("inventory holder authority ID", &holder_authority_id)?;
        require_generation("inventory holder", holder_generation)?;
        require_digest("inventory holder authority digest", holder_authority_digest)?;
        if let Some(digest) = known_inventory_digest {
            require_digest("known inventory digest", digest)?;
        }
        if deadline_seconds <= 0 {
            return Err(SourceProviderValidationError::InvalidInterval("inventory"));
        }
        Ok(Self {
            session_binding,
            sequence,
            request_id,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            known_inventory_digest,
            deadline_seconds,
        })
    }
}

/// Identifies the durable provider-side state of an inventoried lease.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InventoryLeaseStateV1 {
    /// The provider still retains the exact selected source for Mount.
    Active = 1,
    /// The provider is durably releasing the exact lease.
    Reaping = 2,
    /// The provider records a terminal released tombstone.
    Released = 3,
}

/// Carries one canonical provider inventory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderInventoryEntryV1 {
    pub(crate) lease_id: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) state: InventoryLeaseStateV1,
    pub(crate) resource: SourceResourceV1,
    pub(crate) proof_class: u8,
    pub(crate) proof_digest: ObjectDigest,
    pub(crate) resource_commitment: ObjectDigest,
}

impl SourceProviderInventoryEntryV1 {
    /// Constructs one exact provider inventory entry.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_id: [u8; 16],
        lease_digest: ObjectDigest,
        acquisition_id: ObjectDigest,
        state: InventoryLeaseStateV1,
        resource: SourceResourceV1,
        proof_class: u8,
        proof_digest: ObjectDigest,
        resource_commitment: ObjectDigest,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("inventory lease ID", &lease_id)?;
        require_digest("inventory lease digest", lease_digest)?;
        require_digest("inventory acquisition ID", acquisition_id)?;
        if !(1..=4).contains(&proof_class) {
            return Err(SourceProviderValidationError::InvalidCapabilities);
        }
        require_digest("inventory proof digest", proof_digest)?;
        require_digest("inventory resource commitment", resource_commitment)?;
        Ok(Self {
            lease_id,
            lease_digest,
            acquisition_id,
            state,
            resource,
            proof_class,
            proof_digest,
            resource_commitment,
        })
    }
}

/// Carries one holder-scoped provider inventory signing subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderInventoryV1 {
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: ObjectDigest,
    pub(crate) holder_authority_id: [u8; 16],
    pub(crate) holder_generation: u64,
    pub(crate) holder_authority_digest: ObjectDigest,
    pub(crate) provider: ProviderAuthorityV1,
    pub(crate) provider_process_instance: [u8; 16],
    pub(crate) catalog_generation: u64,
    pub(crate) catalog_digest: ObjectDigest,
    pub(crate) inventory_generation: u64,
    pub(crate) entries: Vec<SourceProviderInventoryEntryV1>,
}

impl SourceProviderInventoryV1 {
    /// Constructs a sorted, duplicate-free provider inventory snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel fields, too many
    /// entries, or entries not strictly ordered by lease ID.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: [u8; 16],
        request_digest: ObjectDigest,
        holder_authority_id: [u8; 16],
        holder_generation: u64,
        holder_authority_digest: ObjectDigest,
        provider: ProviderAuthorityV1,
        provider_process_instance: [u8; 16],
        catalog_generation: u64,
        catalog_digest: ObjectDigest,
        inventory_generation: u64,
        entries: Vec<SourceProviderInventoryEntryV1>,
    ) -> Result<Self, SourceProviderValidationError> {
        require_nonzero("inventory response request ID", &request_id)?;
        require_digest("inventory request digest", request_digest)?;
        require_nonzero("inventory holder authority ID", &holder_authority_id)?;
        require_generation("inventory holder", holder_generation)?;
        require_digest("inventory holder authority digest", holder_authority_digest)?;
        require_nonzero(
            "inventory provider process instance",
            &provider_process_instance,
        )?;
        require_generation("inventory catalog", catalog_generation)?;
        require_digest("inventory catalog digest", catalog_digest)?;
        require_generation("inventory", inventory_generation)?;
        if entries.len() > MAXIMUM_INVENTORY_ENTRIES
            || !entries
                .windows(2)
                .all(|pair| pair[0].lease_id < pair[1].lease_id)
        {
            return Err(SourceProviderValidationError::InventoryNotCanonical);
        }
        Ok(Self {
            request_id,
            request_digest,
            holder_authority_id,
            holder_generation,
            holder_authority_digest,
            provider,
            provider_process_instance,
            catalog_generation,
            catalog_digest,
            inventory_generation,
            entries,
        })
    }

    /// Returns the canonical lease entries.
    #[must_use]
    pub fn entries(&self) -> &[SourceProviderInventoryEntryV1] {
        &self.entries
    }
}

/// Computes the Mount-defined digest of exact canonical logical-binding bytes.
///
/// This function does not claim the bytes decode as a Mount binding. Root Mount
/// must supply its canonical encoding; SourceProvider uses this shared domain
/// only to reject byte/digest substitution.
#[must_use]
pub fn digest_logical_binding_bytes(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(LOGICAL_BINDING_DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Commits exact deadline-free canonical `AOSMSEM1` Mount semantics bytes.
///
/// The preimage is the domain string
/// `aos-source-provider-prospective-mount-template-v1\0`, followed directly by
/// the complete `AOSMSEM1` field encoding. The helper validates its ordered
/// field envelope and exact format/version fields, but does not interpret
/// Mount-specific field meanings.
///
/// # Errors
///
/// Returns [`SourceProviderValidationError::InvalidMountTemplate`] unless the
/// bytes are a bounded, complete sequence of fields 1 through 27 beginning
/// with exact `AOSMSEM1` format version 1.
pub fn prospective_mount_apply_template_digest_v1(
    bytes: &[u8],
) -> Result<ObjectDigest, SourceProviderValidationError> {
    validate_mount_template_envelope(bytes)?;

    let mut digest = Sha256::new();
    digest.update(PROSPECTIVE_MOUNT_TEMPLATE_DIGEST_DOMAIN);
    digest.update(bytes);
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

fn validate_prospective_mount_template(
    bytes: &[u8],
    expected_digest: ObjectDigest,
) -> Result<(), SourceProviderValidationError> {
    require_digest("prospective Mount Apply template digest", expected_digest)?;
    if prospective_mount_apply_template_digest_v1(bytes)? != expected_digest {
        return Err(SourceProviderValidationError::InvalidMountTemplate);
    }
    Ok(())
}

fn validate_mount_template_envelope(bytes: &[u8]) -> Result<(), SourceProviderValidationError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_MOUNT_TEMPLATE_BYTES {
        return Err(SourceProviderValidationError::InvalidMountTemplate);
    }

    let mut cursor = 0usize;
    for expected_tag in 1u8..=27 {
        let tag = *bytes
            .get(cursor)
            .ok_or(SourceProviderValidationError::InvalidMountTemplate)?;
        cursor = cursor
            .checked_add(1)
            .ok_or(SourceProviderValidationError::InvalidMountTemplate)?;
        if tag != expected_tag {
            return Err(SourceProviderValidationError::InvalidMountTemplate);
        }
        let length_bytes: [u8; 4] = bytes
            .get(cursor..cursor + 4)
            .and_then(|value| value.try_into().ok())
            .ok_or(SourceProviderValidationError::InvalidMountTemplate)?;
        cursor += 4;
        let length = u32::from_be_bytes(length_bytes) as usize;
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(SourceProviderValidationError::InvalidMountTemplate)?;
        let value = &bytes[cursor..end];
        if (tag == 1 && value != MOUNT_SEMANTICS_MAGIC) || (tag == 2 && value != 1u16.to_be_bytes())
        {
            return Err(SourceProviderValidationError::InvalidMountTemplate);
        }
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(SourceProviderValidationError::InvalidMountTemplate);
    }
    Ok(())
}

pub(crate) fn require_proof_capabilities(
    capabilities: u8,
) -> Result<(), SourceProviderValidationError> {
    if capabilities == 0 || capabilities & !ALL_PROOF_CLASS_CAPABILITIES != 0 {
        Err(SourceProviderValidationError::InvalidCapabilities)
    } else {
        Ok(())
    }
}

pub(crate) fn require_nonzero(
    field: &'static str,
    bytes: &[u8],
) -> Result<(), SourceProviderValidationError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(SourceProviderValidationError::Zero(field))
    } else {
        Ok(())
    }
}

pub(crate) fn require_digest(
    field: &'static str,
    digest: ObjectDigest,
) -> Result<(), SourceProviderValidationError> {
    require_nonzero(field, digest.as_bytes())
}

pub(crate) fn require_generation(
    field: &'static str,
    generation: u64,
) -> Result<(), SourceProviderValidationError> {
    if generation == 0 {
        Err(SourceProviderValidationError::ZeroGeneration(field))
    } else {
        Ok(())
    }
}

pub(crate) fn require_bytes(
    field: &'static str,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), SourceProviderValidationError> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(SourceProviderValidationError::InvalidLength {
            field,
            actual: bytes.len(),
            maximum,
        })
    } else {
        Ok(())
    }
}
