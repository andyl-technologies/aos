//! Domain-separated SourceProvider 1.0 digests and Ed25519 signatures.
//!
//! Signing-key references bind a stable authority generation separately from
//! the process instance carried by provider receipts. Successful verification
//! authenticates canonical bytes and the configured key reference; it does not
//! verify backend claims such as ZFS holds or immutable publication state.
//!
//! ```text
//! AOSSPX01 || version:u16be || purpose:u8 || method:u8 || reserved[4]=0 ||
//! signer-authority-id[16] || signer-authority-generation:u64be ||
//! signer-authority-digest[32] || signer-key-id[16] ||
//! signer-key-generation:u64be || signer-public-key-digest[32] ||
//! signer-key-usage:u8 || signer-reserved[7]=0 || subject-length:u32be ||
//! canonical-subject[subject-length] || ed25519-signature[64]
//! ```
//!
//! Purposes 1 through 7 are respectively export lease, Acquire receipt,
//! Release receipt, Inventory snapshot, Root Mount operation request, endpoint
//! hello, and provider response status. The method byte is zero for purposes
//! 1 through 4, `Hello` for purpose 6, and the exact operation otherwise.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::codec::{
    MAXIMUM_FRAME_BYTES, SourceProviderFrameError, decode_acquire_request, decode_export_lease,
    decode_hello, decode_inventory, decode_inventory_request, decode_provider_receipt,
    decode_release_receipt, decode_release_request, decode_response_status, encode_acquire_request,
    encode_export_lease, encode_hello, encode_inventory, encode_inventory_request,
    encode_provider_proof, encode_provider_receipt, encode_release_receipt, encode_release_request,
    encode_response_status,
};
use crate::model::{
    AcquireSourceRequestV1, InventorySourceRequestV1, ReleaseSourceRequestV1, SourceExportLeaseV1,
    SourceProviderAuthorityV1, SourceProviderHelloV1, SourceProviderInventoryV1,
    SourceProviderMethod, SourceProviderPeerRole, SourceProviderReceiptV1,
    SourceProviderResponseStatusV1, SourceProviderValidationError, SourceReleaseReceiptV1,
};
use crate::proof::SourceProviderProofV1;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-request-digest-v1\0";
const PROOF_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-proof-digest-v1\0";
const RESOURCE_COMMITMENT_DOMAIN: &[u8] = b"aos-source-provider-resource-commitment-v1\0";
const LEASE_DIGEST_DOMAIN: &[u8] = b"aos-source-export-lease-digest-v1\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-receipt-digest-v1\0";
const RELEASE_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-release-digest-v1\0";
const INVENTORY_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-inventory-digest-v1\0";
const REQUEST_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-mount-query-signature-v1\0";
const LEASE_SIGNATURE_DOMAIN: &[u8] = b"aos-source-export-lease-signature-v1\0";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-receipt-signature-v1\0";
const RELEASE_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-release-signature-v1\0";
const INVENTORY_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-inventory-signature-v1\0";
const HELLO_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-hello-signature-v1\0";
const STATUS_SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-status-signature-v1\0";
const SIGNED_REQUEST_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-signed-request-v1\0";
const SIGNED_HELLO_DIGEST_DOMAIN: &[u8] = b"aos-source-provider-signed-hello-v1\0";
const SESSION_BINDING_DOMAIN: &[u8] = b"aos-source-provider-session-binding-v1\0";
const RESPONSE_RESULT_DOMAIN: &[u8] = b"aos-source-provider-response-result-v1\0";
const EMPTY_DESCRIPTOR_SET_DOMAIN: &[u8] = b"aos-source-provider-descriptor-set-v1\0";
const SIGNED_MAGIC: &[u8; 8] = b"AOSSPX01";
const SIGNED_VERSION: u16 = 1;
const SIGNATURE_BYTES: usize = 64;

/// Identifies the four physically separated SourceProvider signing roles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceProviderKeyUsageV1 {
    /// Authenticates only the Root Mount endpoint hello.
    RootMountHello = 1,
    /// Authenticates only the provider endpoint hello.
    ProviderHello = 2,
    /// Authenticates Root Mount Acquire, Release, and Inventory requests.
    RootMountRecord = 3,
    /// Authenticates provider statuses, leases, receipts, and inventories.
    ProviderOutcome = 4,
}

/// Binds a stable authority and key generation to one SourceProvider use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderSigningKeyV1 {
    pub(crate) authority_id: [u8; 16],
    pub(crate) authority_generation: u64,
    pub(crate) authority_digest: ObjectDigest,
    pub(crate) key_id: [u8; 16],
    pub(crate) key_generation: u64,
    pub(crate) public_key_digest: ObjectDigest,
    pub(crate) usage: SourceProviderKeyUsageV1,
}

impl SourceProviderSigningKeyV1 {
    /// Constructs one exact SourceProvider signing-key reference.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel identities,
    /// generations, or digests.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: ObjectDigest,
        key_id: [u8; 16],
        key_generation: u64,
        public_key_digest: ObjectDigest,
        usage: SourceProviderKeyUsageV1,
    ) -> Result<Self, SourceProviderValidationError> {
        crate::model::require_nonzero("signing authority ID", &authority_id)?;
        crate::model::require_generation("signing authority", authority_generation)?;
        crate::model::require_digest("signing authority digest", authority_digest)?;
        crate::model::require_nonzero("signing key ID", &key_id)?;
        crate::model::require_generation("signing key", key_generation)?;
        crate::model::require_digest("signing public-key digest", public_key_digest)?;
        Ok(Self {
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            public_key_digest,
            usage,
        })
    }

    /// Constructs a reference whose fingerprint matches `signing_key`.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderValidationError`] for sentinel authority or key metadata.
    pub fn for_signing_key(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: ObjectDigest,
        key_id: [u8; 16],
        key_generation: u64,
        usage: SourceProviderKeyUsageV1,
        signing_key: &SigningKey,
    ) -> Result<Self, SourceProviderValidationError> {
        let digest =
            ObjectDigest::from_bytes(Sha256::digest(signing_key.verifying_key().as_bytes()).into());
        Self::new(
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            digest,
            usage,
        )
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

    /// Returns the key usage.
    #[must_use]
    pub const fn usage(&self) -> SourceProviderKeyUsageV1 {
        self.usage
    }
}

/// Stores one fixed Ed25519 signature without native library representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProviderSignature([u8; SIGNATURE_BYTES]);

impl SourceProviderSignature {
    /// Constructs a signature from its exact 64 wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }
}

/// Reports an invalid SourceProvider signature or signed envelope.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceProviderSignatureError {
    /// Canonical subject or envelope decoding failed.
    #[error("invalid signed SourceProvider encoding: {0}")]
    Codec(#[from] SourceProviderFrameError),
    /// Key metadata does not match the required signing use or subject authority.
    #[error("SourceProvider signing-key reference does not match the subject")]
    SignerMismatch,
    /// The supplied public key does not match the committed fingerprint.
    #[error("SourceProvider public-key fingerprint mismatch")]
    PublicKeyMismatch,
    /// The supplied raw Ed25519 public key is invalid.
    #[error("invalid SourceProvider Ed25519 public key")]
    InvalidPublicKey,
    /// Ed25519 verification failed.
    #[error("invalid SourceProvider Ed25519 signature")]
    InvalidSignature,
    /// A signed envelope is malformed, oversized, unknown, or noncanonical.
    #[error("invalid SourceProvider signed envelope")]
    InvalidEnvelope,
}

/// Carries one signed Root Mount provider request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceProviderRequestV1 {
    method: SourceProviderMethod,
    subject: Vec<u8>,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

/// Carries one provider-signed export lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceExportLeaseV1 {
    lease: SourceExportLeaseV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

/// Carries one provider-signed successful Acquire receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceProviderReceiptV1 {
    receipt: SourceProviderReceiptV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

/// Carries one provider-signed terminal Release receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceReleaseReceiptV1 {
    receipt: SourceReleaseReceiptV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

/// Carries one provider-signed holder inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceProviderInventoryV1 {
    inventory: SourceProviderInventoryV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

/// Carries one signed endpoint hello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceProviderHelloV1 {
    hello: SourceProviderHelloV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

/// Carries one provider-signed response status for every disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceProviderStatusV1 {
    status: SourceProviderResponseStatusV1,
    signer: SourceProviderSigningKeyV1,
    signature: SourceProviderSignature,
}

macro_rules! signed_accessors {
    ($type:ty, $field:ident, $subject:ty) => {
        impl $type {
            /// Returns the typed canonical signed subject.
            #[must_use]
            pub const fn subject(&self) -> &$subject {
                &self.$field
            }

            /// Returns the exact stable signer reference.
            #[must_use]
            pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
                &self.signer
            }

            /// Returns the detached Ed25519 signature.
            #[must_use]
            pub const fn signature(&self) -> &SourceProviderSignature {
                &self.signature
            }
        }
    };
}

signed_accessors!(SignedSourceExportLeaseV1, lease, SourceExportLeaseV1);
signed_accessors!(
    SignedSourceProviderReceiptV1,
    receipt,
    SourceProviderReceiptV1
);
signed_accessors!(SignedSourceProviderHelloV1, hello, SourceProviderHelloV1);
signed_accessors!(
    SignedSourceProviderStatusV1,
    status,
    SourceProviderResponseStatusV1
);
signed_accessors!(
    SignedSourceReleaseReceiptV1,
    receipt,
    SourceReleaseReceiptV1
);
signed_accessors!(
    SignedSourceProviderInventoryV1,
    inventory,
    SourceProviderInventoryV1
);

impl SignedSourceProviderRequestV1 {
    /// Returns the exact signed request method.
    #[must_use]
    pub const fn method(&self) -> SourceProviderMethod {
        self.method
    }

    /// Returns the canonical typed-method request bytes.
    #[must_use]
    pub fn subject(&self) -> &[u8] {
        &self.subject
    }

    /// Returns the exact stable Root Mount signer reference.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }

    /// Returns the detached signature.
    #[must_use]
    pub const fn signature(&self) -> &SourceProviderSignature {
        &self.signature
    }
}

/// Computes the domain-separated digest of one Acquire query.
#[must_use]
pub fn digest_acquire_request(value: &AcquireSourceRequestV1) -> ObjectDigest {
    request_digest(
        SourceProviderMethod::Acquire,
        &encode_acquire_request(value),
    )
}

/// Computes the domain-separated digest of one Release query.
#[must_use]
pub fn digest_release_request(value: &ReleaseSourceRequestV1) -> ObjectDigest {
    request_digest(
        SourceProviderMethod::Release,
        &encode_release_request(value),
    )
}

/// Computes the domain-separated digest of one Inventory query.
#[must_use]
pub fn digest_inventory_request(value: &InventorySourceRequestV1) -> ObjectDigest {
    request_digest(
        SourceProviderMethod::Inventory,
        &encode_inventory_request(value),
    )
}

/// Computes the domain-separated digest of one backend proof claim.
#[must_use]
pub fn digest_provider_proof(value: &SourceProviderProofV1) -> ObjectDigest {
    domain_digest(PROOF_DIGEST_DOMAIN, &encode_provider_proof(value))
}

/// Commits the exact selected resource and complete backend proof.
///
/// The preimage is the domain string
/// `aos-source-provider-resource-commitment-v1\0`, followed by the 32-byte
/// resource-namespace digest, 32-byte resource ID, resource generation,
/// resource-state digest, selection generation, selection digest, and
/// [`digest_provider_proof`] result in that order. A later Mount acquisition
/// ledger maps this value directly into the
/// existing Stage-1 `provider_resource_digest` field before deriving a
/// realization handle.
#[must_use]
pub fn provider_resource_commitment_v1(
    resource: &crate::model::SourceResourceV1,
    proof_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(RESOURCE_COMMITMENT_DOMAIN);
    hasher.update(resource.resource_namespace_digest().as_bytes());
    hasher.update(resource.resource_id());
    hasher.update(resource.resource_generation().to_be_bytes());
    hasher.update(resource.resource_digest().as_bytes());
    hasher.update(resource.selection_generation().to_be_bytes());
    hasher.update(resource.selection_digest().as_bytes());
    hasher.update(proof_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Computes the domain-separated digest of an exact signed export-lease envelope.
#[must_use]
pub fn digest_signed_export_lease(value: &SignedSourceExportLeaseV1) -> ObjectDigest {
    domain_digest(LEASE_DIGEST_DOMAIN, &value.to_canonical_bytes())
}

/// Computes the domain-separated digest of one successful provider receipt.
#[must_use]
pub fn digest_provider_receipt(value: &SourceProviderReceiptV1) -> ObjectDigest {
    domain_digest(RECEIPT_DIGEST_DOMAIN, &encode_provider_receipt(value))
}

/// Computes the domain-separated digest of one release receipt.
#[must_use]
pub fn digest_release_receipt(value: &SourceReleaseReceiptV1) -> ObjectDigest {
    domain_digest(RELEASE_DIGEST_DOMAIN, &encode_release_receipt(value))
}

/// Computes the domain-separated digest of one provider inventory.
#[must_use]
pub fn digest_inventory(value: &SourceProviderInventoryV1) -> ObjectDigest {
    domain_digest(INVENTORY_DIGEST_DOMAIN, &encode_inventory(value))
}

/// Computes the digest of the complete signed request envelope.
#[must_use]
pub fn digest_signed_request(value: &SignedSourceProviderRequestV1) -> ObjectDigest {
    domain_digest(SIGNED_REQUEST_DIGEST_DOMAIN, &value.to_canonical_bytes())
}

/// Computes the digest of the complete signed hello envelope.
#[must_use]
pub fn digest_signed_hello(value: &SignedSourceProviderHelloV1) -> ObjectDigest {
    domain_digest(SIGNED_HELLO_DIGEST_DOMAIN, &value.to_canonical_bytes())
}

/// Derives a session binding from both complete signed hello envelopes.
#[must_use]
pub fn source_provider_session_binding_v1(
    client: &SignedSourceProviderHelloV1,
    server: &SignedSourceProviderHelloV1,
) -> ObjectDigest {
    let mut preimage = Vec::new();
    let client = client.to_canonical_bytes();
    let server = server.to_canonical_bytes();
    preimage.extend_from_slice(&(client.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&client);
    preimage.extend_from_slice(&(server.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&server);
    domain_digest(SESSION_BINDING_DOMAIN, &preimage)
}

/// Commits exact optional nested-result bytes for one status and method.
#[must_use]
pub fn response_result_digest_v1(
    method: SourceProviderMethod,
    status: crate::model::SourceProviderStatus,
    result: Option<&[u8]>,
) -> ObjectDigest {
    let result = result.unwrap_or_default();
    let mut preimage = Vec::with_capacity(6 + result.len());
    preimage.push(method as u8);
    preimage.push(status as u8);
    preimage.extend_from_slice(&(result.len() as u32).to_be_bytes());
    preimage.extend_from_slice(result);
    domain_digest(RESPONSE_RESULT_DOMAIN, &preimage)
}

/// Commits the canonical empty response descriptor set.
#[must_use]
pub fn empty_descriptor_set_commitment_v1() -> ObjectDigest {
    domain_digest(EMPTY_DESCRIPTOR_SET_DOMAIN, &[0, 0, 0, 0])
}

/// Signs one endpoint hello under its endpoint authority.
///
/// # Errors
///
/// Returns [`SourceProviderSignatureError`] for wrong role/key use or a
/// key-fingerprint mismatch. Session authentication checks the expected peer.
pub fn sign_hello(
    hello: SourceProviderHelloV1,
    signer: SourceProviderSigningKeyV1,
    signing_key: &SigningKey,
) -> Result<SignedSourceProviderHelloV1, SourceProviderSignatureError> {
    let expected_usage = match hello.role() {
        SourceProviderPeerRole::RootMount => SourceProviderKeyUsageV1::RootMountHello,
        SourceProviderPeerRole::Provider => SourceProviderKeyUsageV1::ProviderHello,
    };
    require_usage(&signer, expected_usage)?;
    let signature = sign_bytes(
        HELLO_SIGNATURE_DOMAIN,
        hello.role() as u8,
        &encode_hello(&hello),
        &signer,
        signing_key,
    )?;
    Ok(SignedSourceProviderHelloV1 {
        hello,
        signer,
        signature,
    })
}

/// Verifies one signed endpoint hello against an already resolved public key.
///
/// # Errors
///
/// Returns [`SourceProviderSignatureError`] for a role/use mismatch, weak key
/// material, fingerprint mismatch, or an invalid signature.
pub(crate) fn verify_hello(
    value: &SignedSourceProviderHelloV1,
    public_key: &[u8; 32],
) -> Result<(), SourceProviderSignatureError> {
    let expected_usage = match value.hello.role() {
        SourceProviderPeerRole::RootMount => SourceProviderKeyUsageV1::RootMountHello,
        SourceProviderPeerRole::Provider => SourceProviderKeyUsageV1::ProviderHello,
    };
    require_usage(&value.signer, expected_usage)?;
    verify_bytes(
        HELLO_SIGNATURE_DOMAIN,
        value.hello.role() as u8,
        &encode_hello(&value.hello),
        &value.signer,
        &value.signature,
        public_key,
    )
}

/// Signs one provider disposition subject, including non-success.
///
/// # Errors
///
/// Returns [`SourceProviderSignatureError`] for wrong key use or fingerprint.
pub fn sign_response_status(
    status: SourceProviderResponseStatusV1,
    signer: SourceProviderSigningKeyV1,
    signing_key: &SigningKey,
) -> Result<SignedSourceProviderStatusV1, SourceProviderSignatureError> {
    require_usage(&signer, SourceProviderKeyUsageV1::ProviderOutcome)?;
    let signature = sign_bytes(
        STATUS_SIGNATURE_DOMAIN,
        status.method() as u8,
        &encode_response_status(&status),
        &signer,
        signing_key,
    )?;
    Ok(SignedSourceProviderStatusV1 {
        status,
        signer,
        signature,
    })
}

/// Verifies one provider disposition against an already resolved public key.
///
/// # Errors
///
/// Returns [`SourceProviderSignatureError`] for wrong key use, weak key
/// material, fingerprint mismatch, or an invalid signature.
pub(crate) fn verify_response_status(
    value: &SignedSourceProviderStatusV1,
    public_key: &[u8; 32],
) -> Result<(), SourceProviderSignatureError> {
    require_usage(&value.signer, SourceProviderKeyUsageV1::ProviderOutcome)?;
    verify_bytes(
        STATUS_SIGNATURE_DOMAIN,
        value.status.method() as u8,
        &encode_response_status(&value.status),
        &value.signer,
        &value.signature,
        public_key,
    )
}

/// Signs one canonical Root Mount Acquire, Release, or Inventory query.
///
/// # Errors
///
/// Returns [`SourceProviderSignatureError`] for a non-query method, malformed
/// subject, wrong key use, or key-fingerprint mismatch.
pub fn sign_request(
    method: SourceProviderMethod,
    subject: Vec<u8>,
    signer: SourceProviderSigningKeyV1,
    signing_key: &SigningKey,
) -> Result<SignedSourceProviderRequestV1, SourceProviderSignatureError> {
    validate_request_subject(method, &subject)?;
    require_usage(&signer, SourceProviderKeyUsageV1::RootMountRecord)?;
    let signature = sign_bytes(
        REQUEST_SIGNATURE_DOMAIN,
        method as u8,
        &subject,
        &signer,
        signing_key,
    )?;
    Ok(SignedSourceProviderRequestV1 {
        method,
        subject,
        signer,
        signature,
    })
}

/// Verifies one canonical Root Mount provider query.
///
/// # Errors
///
/// Returns [`SourceProviderSignatureError`] for malformed subject, a holder
/// authority that differs from the signer, a weak or mismatched key, or an
/// invalid strict Ed25519 signature.
pub(crate) fn verify_request(
    value: &SignedSourceProviderRequestV1,
    public_key: &[u8; 32],
) -> Result<(), SourceProviderSignatureError> {
    validate_request_subject(value.method, &value.subject)?;
    require_usage(&value.signer, SourceProviderKeyUsageV1::RootMountRecord)?;
    let (holder_id, holder_generation, holder_digest) = request_holder(value)?;
    if holder_id != value.signer.authority_id
        || holder_generation != value.signer.authority_generation
        || holder_digest != value.signer.authority_digest
    {
        return Err(SourceProviderSignatureError::SignerMismatch);
    }
    verify_bytes(
        REQUEST_SIGNATURE_DOMAIN,
        value.method as u8,
        &value.subject,
        &value.signer,
        &value.signature,
        public_key,
    )
}

fn request_holder(
    value: &SignedSourceProviderRequestV1,
) -> Result<([u8; 16], u64, ObjectDigest), SourceProviderSignatureError> {
    match value.method {
        SourceProviderMethod::Acquire => {
            let request = decode_acquire_request(&value.subject)?;
            Ok((
                request.holder_authority_id(),
                request.holder_generation(),
                request.holder_authority_digest(),
            ))
        }
        SourceProviderMethod::Release => {
            let request = decode_release_request(&value.subject)?;
            Ok((
                request.holder_authority_id(),
                request.holder_generation(),
                request.holder_authority_digest(),
            ))
        }
        SourceProviderMethod::Inventory => {
            let request = decode_inventory_request(&value.subject)?;
            Ok((
                request.holder_authority_id(),
                request.holder_generation(),
                request.holder_authority_digest(),
            ))
        }
        SourceProviderMethod::Hello => Err(SourceProviderSignatureError::SignerMismatch),
    }
}

macro_rules! typed_sign_verify {
    ($sign:ident, $verify:ident, $signed:ident, $subject:ty, $field:ident, $encode:ident, $domain:ident, $code:expr, $authority:expr) => {
        #[doc = concat!("Signs one canonical `", stringify!($subject), "`.")]
        ///
        /// # Errors
        ///
        /// Returns [`SourceProviderSignatureError`] for wrong key use,
        /// authority mismatch, or key-fingerprint mismatch.
        pub fn $sign(
            subject: $subject,
            signer: SourceProviderSigningKeyV1,
            signing_key: &SigningKey,
        ) -> Result<$signed, SourceProviderSignatureError> {
            require_usage(&signer, SourceProviderKeyUsageV1::ProviderOutcome)?;
            if !($authority)(&subject, &signer) {
                return Err(SourceProviderSignatureError::SignerMismatch);
            }
            let signature = sign_bytes($domain, $code, &$encode(&subject), &signer, signing_key)?;
            Ok($signed {
                $field: subject,
                signer,
                signature,
            })
        }

        #[doc = concat!("Verifies one canonical `", stringify!($subject), "` signature.")]
        ///
        /// # Errors
        ///
        /// Returns [`SourceProviderSignatureError`] for wrong key use,
        /// authority/fingerprint mismatch, invalid key, or invalid signature.
        pub(crate) fn $verify(
            value: &$signed,
            public_key: &[u8; 32],
        ) -> Result<(), SourceProviderSignatureError> {
            require_usage(&value.signer, SourceProviderKeyUsageV1::ProviderOutcome)?;
            if !($authority)(&value.$field, &value.signer) {
                return Err(SourceProviderSignatureError::SignerMismatch);
            }
            verify_bytes(
                $domain,
                $code,
                &$encode(&value.$field),
                &value.signer,
                &value.signature,
                public_key,
            )
        }
    };
}

typed_sign_verify!(
    sign_export_lease,
    verify_export_lease,
    SignedSourceExportLeaseV1,
    SourceExportLeaseV1,
    lease,
    encode_export_lease,
    LEASE_SIGNATURE_DOMAIN,
    1,
    lease_authority_matches
);
typed_sign_verify!(
    sign_release_receipt,
    verify_release_receipt,
    SignedSourceReleaseReceiptV1,
    SourceReleaseReceiptV1,
    receipt,
    encode_release_receipt,
    RELEASE_SIGNATURE_DOMAIN,
    3,
    release_authority_matches
);
typed_sign_verify!(
    sign_inventory,
    verify_inventory,
    SignedSourceProviderInventoryV1,
    SourceProviderInventoryV1,
    inventory,
    encode_inventory,
    INVENTORY_SIGNATURE_DOMAIN,
    4,
    inventory_authority_matches
);

/// Signs one successful receipt whose embedded export lease is already valid.
///
/// # Errors
///
/// Returns [`SourceProviderSignatureError`] for an invalid embedded lease,
/// signer/authority mismatch, wrong key use, or key-fingerprint mismatch.
pub fn sign_provider_receipt(
    receipt: SourceProviderReceiptV1,
    signer: SourceProviderSigningKeyV1,
    signing_key: &SigningKey,
) -> Result<SignedSourceProviderReceiptV1, SourceProviderSignatureError> {
    require_usage(&signer, SourceProviderKeyUsageV1::ProviderOutcome)?;
    receipt_lease(&receipt)?;
    let signature = sign_bytes(
        RECEIPT_SIGNATURE_DOMAIN,
        2,
        &encode_provider_receipt(&receipt),
        &signer,
        signing_key,
    )?;
    Ok(SignedSourceProviderReceiptV1 {
        receipt,
        signer,
        signature,
    })
}

/// Verifies one successful receipt and its embedded provider export lease.
///
/// # Errors
///
/// Returns [`SourceProviderSignatureError`] for an invalid nested lease,
/// signer/authority mismatch, wrong key/fingerprint, or invalid signature.
pub(crate) fn verify_provider_receipt(
    value: &SignedSourceProviderReceiptV1,
    public_key: &[u8; 32],
) -> Result<(), SourceProviderSignatureError> {
    require_usage(&value.signer, SourceProviderKeyUsageV1::ProviderOutcome)?;
    verify_bytes(
        RECEIPT_SIGNATURE_DOMAIN,
        2,
        &encode_provider_receipt(&value.receipt),
        &value.signer,
        &value.signature,
        public_key,
    )
}

fn validate_request_subject(
    method: SourceProviderMethod,
    bytes: &[u8],
) -> Result<(), SourceProviderSignatureError> {
    match method {
        SourceProviderMethod::Acquire => {
            decode_acquire_request(bytes)?;
        }
        SourceProviderMethod::Release => {
            decode_release_request(bytes)?;
        }
        SourceProviderMethod::Inventory => {
            decode_inventory_request(bytes)?;
        }
        SourceProviderMethod::Hello => return Err(SourceProviderSignatureError::SignerMismatch),
    }
    Ok(())
}

fn lease_authority_matches(
    value: &SourceExportLeaseV1,
    signer: &SourceProviderSigningKeyV1,
) -> bool {
    provider_matches(value.provider(), signer)
}

fn release_authority_matches(
    value: &SourceReleaseReceiptV1,
    signer: &SourceProviderSigningKeyV1,
) -> bool {
    provider_matches(&value.provider, signer)
}

fn inventory_authority_matches(
    value: &SourceProviderInventoryV1,
    signer: &SourceProviderSigningKeyV1,
) -> bool {
    provider_matches(&value.provider, signer)
}

fn receipt_lease(
    receipt: &SourceProviderReceiptV1,
) -> Result<SignedSourceExportLeaseV1, SourceProviderSignatureError> {
    let signed_lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())?;
    if digest_signed_export_lease(&signed_lease) != receipt.lease_digest()
        || signed_lease.subject().request_id() != receipt.request_id()
        || signed_lease.subject().request_digest() != receipt.request_digest()
        || digest_provider_proof(signed_lease.subject().proof()) != receipt.observed_proof_digest()
    {
        return Err(SourceProviderSignatureError::SignerMismatch);
    }
    Ok(signed_lease)
}

fn provider_matches(
    value: &SourceProviderAuthorityV1,
    signer: &SourceProviderSigningKeyV1,
) -> bool {
    value.authority_id() == signer.authority_id
        && value.authority_generation() == signer.authority_generation
        && value.authority_digest() == signer.authority_digest
}

fn sign_bytes(
    domain: &[u8],
    code: u8,
    subject: &[u8],
    signer: &SourceProviderSigningKeyV1,
    signing_key: &SigningKey,
) -> Result<SourceProviderSignature, SourceProviderSignatureError> {
    require_key_fingerprint(signer, signing_key.verifying_key().as_bytes())?;
    let message = signing_message(domain, code, subject, signer);
    Ok(SourceProviderSignature::from_bytes(
        signing_key.sign(&message).to_bytes(),
    ))
}

fn verify_bytes(
    domain: &[u8],
    code: u8,
    subject: &[u8],
    signer: &SourceProviderSigningKeyV1,
    signature: &SourceProviderSignature,
    public_key: &[u8; 32],
) -> Result<(), SourceProviderSignatureError> {
    require_key_fingerprint(signer, public_key)?;
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| SourceProviderSignatureError::InvalidPublicKey)?;
    if verifying_key.is_weak() {
        return Err(SourceProviderSignatureError::InvalidPublicKey);
    }
    let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify_strict(&signing_message(domain, code, subject, signer), &signature)
        .map_err(|_| SourceProviderSignatureError::InvalidSignature)
}

fn require_usage(
    signer: &SourceProviderSigningKeyV1,
    expected: SourceProviderKeyUsageV1,
) -> Result<(), SourceProviderSignatureError> {
    if signer.usage == expected {
        Ok(())
    } else {
        Err(SourceProviderSignatureError::SignerMismatch)
    }
}

fn require_key_fingerprint(
    signer: &SourceProviderSigningKeyV1,
    public_key: &[u8; 32],
) -> Result<(), SourceProviderSignatureError> {
    let digest = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
    if digest == signer.public_key_digest {
        Ok(())
    } else {
        Err(SourceProviderSignatureError::PublicKeyMismatch)
    }
}

fn signing_message(
    domain: &[u8],
    code: u8,
    subject: &[u8],
    signer: &SourceProviderSigningKeyV1,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + 1 + 120 + subject.len());
    message.extend_from_slice(domain);
    message.push(code);
    encode_signer(&mut message, signer);
    message.extend_from_slice(&(subject.len() as u32).to_be_bytes());
    message.extend_from_slice(subject);
    message
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn request_digest(method: SourceProviderMethod, bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update([method as u8]);
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(crate) fn encode_signer(bytes: &mut Vec<u8>, signer: &SourceProviderSigningKeyV1) {
    bytes.extend_from_slice(&signer.authority_id);
    bytes.extend_from_slice(&signer.authority_generation.to_be_bytes());
    bytes.extend_from_slice(signer.authority_digest.as_bytes());
    bytes.extend_from_slice(&signer.key_id);
    bytes.extend_from_slice(&signer.key_generation.to_be_bytes());
    bytes.extend_from_slice(signer.public_key_digest.as_bytes());
    bytes.push(signer.usage as u8);
    bytes.extend_from_slice(&[0; 7]);
}

pub(crate) fn decode_signer(
    bytes: &[u8],
) -> Result<SourceProviderSigningKeyV1, SourceProviderSignatureError> {
    if bytes.len() != 120 {
        return Err(SourceProviderSignatureError::InvalidEnvelope);
    }
    let array = |start: usize, end: usize| {
        bytes
            .get(start..end)
            .ok_or(SourceProviderSignatureError::InvalidEnvelope)
    };
    let authority_id: [u8; 16] = array(0, 16)?
        .try_into()
        .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?;
    let authority_generation = u64::from_be_bytes(
        array(16, 24)?
            .try_into()
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?,
    );
    let authority_digest = ObjectDigest::from_bytes(
        array(24, 56)?
            .try_into()
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?,
    );
    let key_id = array(56, 72)?
        .try_into()
        .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?;
    let key_generation = u64::from_be_bytes(
        array(72, 80)?
            .try_into()
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?,
    );
    let public_key_digest = ObjectDigest::from_bytes(
        array(80, 112)?
            .try_into()
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?,
    );
    let usage = match bytes[112] {
        1 => SourceProviderKeyUsageV1::RootMountHello,
        2 => SourceProviderKeyUsageV1::ProviderHello,
        3 => SourceProviderKeyUsageV1::RootMountRecord,
        4 => SourceProviderKeyUsageV1::ProviderOutcome,
        _ => return Err(SourceProviderSignatureError::InvalidEnvelope),
    };
    if bytes[113..120].iter().any(|byte| *byte != 0) {
        return Err(SourceProviderSignatureError::InvalidEnvelope);
    }
    SourceProviderSigningKeyV1::new(
        authority_id,
        authority_generation,
        authority_digest,
        key_id,
        key_generation,
        public_key_digest,
        usage,
    )
    .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)
}

fn encode_signed(
    purpose: u8,
    method: u8,
    signer: &SourceProviderSigningKeyV1,
    subject: &[u8],
    signature: &SourceProviderSignature,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(144 + subject.len() + SIGNATURE_BYTES);
    bytes.extend_from_slice(SIGNED_MAGIC);
    bytes.extend_from_slice(&SIGNED_VERSION.to_be_bytes());
    bytes.push(purpose);
    bytes.push(method);
    bytes.extend_from_slice(&[0; 4]);
    encode_signer(&mut bytes, signer);
    bytes.extend_from_slice(&(subject.len() as u32).to_be_bytes());
    bytes.extend_from_slice(subject);
    bytes.extend_from_slice(signature.as_bytes());
    bytes
}

fn decode_signed(
    bytes: &[u8],
) -> Result<
    (
        u8,
        u8,
        SourceProviderSigningKeyV1,
        &[u8],
        SourceProviderSignature,
    ),
    SourceProviderSignatureError,
> {
    const HEADER: usize = 8 + 2 + 1 + 1 + 4 + 120 + 4;
    if bytes.len() < HEADER + SIGNATURE_BYTES || bytes.len() > MAXIMUM_FRAME_BYTES {
        return Err(SourceProviderSignatureError::InvalidEnvelope);
    }
    if &bytes[..8] != SIGNED_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != SIGNED_VERSION
        || bytes[12..16].iter().any(|byte| *byte != 0)
    {
        return Err(SourceProviderSignatureError::InvalidEnvelope);
    }
    let signer = decode_signer(&bytes[16..136])?;
    let length = u32::from_be_bytes(
        bytes[136..140]
            .try_into()
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?,
    ) as usize;
    let subject_end = HEADER
        .checked_add(length)
        .ok_or(SourceProviderSignatureError::InvalidEnvelope)?;
    if length == 0 || subject_end.checked_add(SIGNATURE_BYTES) != Some(bytes.len()) {
        return Err(SourceProviderSignatureError::InvalidEnvelope);
    }
    let signature = SourceProviderSignature::from_bytes(
        bytes[subject_end..]
            .try_into()
            .map_err(|_| SourceProviderSignatureError::InvalidEnvelope)?,
    );
    Ok((
        bytes[10],
        bytes[11],
        signer,
        &bytes[HEADER..subject_end],
        signature,
    ))
}

macro_rules! signed_wire {
    ($type:ty, $purpose:expr, $method:expr, $field:ident, $encode:ident, $decode:ident, $usage:expr) => {
        impl $type {
            /// Encodes the exact canonical signed envelope.
            #[must_use]
            pub fn to_canonical_bytes(&self) -> Vec<u8> {
                encode_signed(
                    $purpose,
                    $method,
                    &self.signer,
                    &$encode(&self.$field),
                    &self.signature,
                )
            }

            /// Decodes the exact canonical signed envelope and typed subject.
            ///
            /// This verifies framing and semantic canonicality, not the Ed25519
            /// signature. Call the corresponding `verify_*` function afterward.
            ///
            /// # Errors
            ///
            /// Returns [`SourceProviderSignatureError`] for malformed,
            /// oversized, unknown, reserved, noncanonical, or trailing bytes.
            pub fn from_canonical_bytes(
                bytes: &[u8],
            ) -> Result<Self, SourceProviderSignatureError> {
                let (purpose, method, signer, subject, signature) = decode_signed(bytes)?;
                if purpose != $purpose || method != $method {
                    return Err(SourceProviderSignatureError::InvalidEnvelope);
                }
                let decoded = $decode(subject)?;
                if signer.usage() != $usage(&decoded) {
                    return Err(SourceProviderSignatureError::InvalidEnvelope);
                }
                Ok(Self {
                    $field: decoded,
                    signer,
                    signature,
                })
            }
        }
    };
}

fn provider_outcome_usage<T>(_: &T) -> SourceProviderKeyUsageV1 {
    SourceProviderKeyUsageV1::ProviderOutcome
}

fn hello_usage(hello: &SourceProviderHelloV1) -> SourceProviderKeyUsageV1 {
    match hello.role() {
        SourceProviderPeerRole::RootMount => SourceProviderKeyUsageV1::RootMountHello,
        SourceProviderPeerRole::Provider => SourceProviderKeyUsageV1::ProviderHello,
    }
}

signed_wire!(
    SignedSourceExportLeaseV1,
    1,
    0,
    lease,
    encode_export_lease,
    decode_export_lease,
    provider_outcome_usage
);
signed_wire!(
    SignedSourceProviderReceiptV1,
    2,
    0,
    receipt,
    encode_provider_receipt,
    decode_provider_receipt,
    provider_outcome_usage
);
signed_wire!(
    SignedSourceReleaseReceiptV1,
    3,
    0,
    receipt,
    encode_release_receipt,
    decode_release_receipt,
    provider_outcome_usage
);
signed_wire!(
    SignedSourceProviderInventoryV1,
    4,
    0,
    inventory,
    encode_inventory,
    decode_inventory,
    provider_outcome_usage
);
signed_wire!(
    SignedSourceProviderHelloV1,
    6,
    1,
    hello,
    encode_hello,
    decode_hello,
    hello_usage
);

impl SignedSourceProviderStatusV1 {
    /// Encodes the exact canonical signed status envelope.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_signed(
            7,
            self.status.method() as u8,
            &self.signer,
            &encode_response_status(&self.status),
            &self.signature,
        )
    }

    /// Decodes an exact signed response status without verifying its signature.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSignatureError`] for malformed, unknown,
    /// reserved, oversized, noncanonical, or trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceProviderSignatureError> {
        let (purpose, method, signer, subject, signature) = decode_signed(bytes)?;
        if purpose != 7 {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        let status = decode_response_status(subject)?;
        if method != status.method() as u8
            || signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
        {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        Ok(Self {
            status,
            signer,
            signature,
        })
    }
}

impl SignedSourceProviderRequestV1 {
    /// Encodes the exact canonical signed query envelope.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_signed(
            5,
            self.method as u8,
            &self.signer,
            &self.subject,
            &self.signature,
        )
    }

    /// Decodes an exact signed Acquire, Release, or Inventory query envelope.
    ///
    /// This validates framing and typed subject canonicality but not the Ed25519
    /// signature. Use a composite verifier in [`crate::verification`] before
    /// treating the result as authenticated.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSignatureError`] for malformed, unknown,
    /// reserved, oversized, noncanonical, or trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceProviderSignatureError> {
        let (purpose, method, signer, subject, signature) = decode_signed(bytes)?;
        if purpose != 5 || signer.usage() != SourceProviderKeyUsageV1::RootMountRecord {
            return Err(SourceProviderSignatureError::InvalidEnvelope);
        }
        let method = match method {
            2 => SourceProviderMethod::Acquire,
            3 => SourceProviderMethod::Release,
            4 => SourceProviderMethod::Inventory,
            _ => return Err(SourceProviderSignatureError::InvalidEnvelope),
        };
        validate_request_subject(method, subject)?;
        Ok(Self {
            method,
            subject: subject.to_vec(),
            signer,
            signature,
        })
    }
}
