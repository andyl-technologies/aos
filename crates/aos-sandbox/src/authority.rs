//! Prepares immutable controller authority artifacts for protected signing.
//!
//! The unprivileged controller canonicalizes a broker authorization plan and
//! ownership lease, binds each resulting digest to a purpose-specific
//! [`SignatureStatement`], and exports the exact domain-separated bytes that a
//! protected Ed25519 signer must sign. Private keys and signer implementations
//! never enter this crate.
//!
//! Returned raw signatures or canonical detached envelopes are accepted only
//! when their statements exactly equal the prepared statements and their
//! signatures verify against the pinned public policy material. Successful
//! completion yields an owned quartet whose borrowed view can be passed to a
//! transport adapter without re-encoding any artifact.

use aos_sandbox_core::format::{
    decode_signature, decode_trust_policy, encode_broker_authorization_plan,
    encode_ownership_lease, encode_signature, encode_signature_statement,
};
use aos_sandbox_core::model::{
    InvalidTrustModel, KeyReference, Signature, SignatureBytes, SignaturePurpose,
    SignatureStatement,
};
use aos_sandbox_core::{
    BrokerAuthorizationPlan, CanonicalCborError, DecodeLimits, DescriptorRole, MediaType,
    ObjectDescriptor, ObjectDigest, OwnershipLease, PortableMediaType, RegistryError, TrustScopeId,
    descriptor_for_bytes, signature_signing_message, validate_descriptor_role, verify_signature,
};
use sha2::{Digest as _, Sha256};

const MAXIMUM_TRUST_POLICY_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_ENVELOPE_BYTES: usize = 64 * 1024;

/// Pins public verification material for one protected signing authority.
///
/// This value contains only a public key and public policy object. It cannot
/// sign anything and deliberately has no private-key or signer callback field.
#[derive(Clone, Debug)]
pub struct SigningAuthority {
    canonical_policy: Vec<u8>,
    policy_descriptor: ObjectDescriptor,
    trust_scope: TrustScopeId,
    signer: KeyReference,
    public_key: [u8; 32],
    purpose: SignaturePurpose,
}

impl SigningAuthority {
    /// Constructs a validated, public-only authority generation.
    ///
    /// The canonical policy bytes are copied and pinned by their descriptor.
    /// The policy must authorize the exact scope, purpose, signer generation,
    /// and SHA-256 fingerprint of `public_key`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationPreparationError`] if the policy is malformed,
    /// its descriptor is not exact, or any scope, purpose, signer, or public-key
    /// binding differs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        canonical_policy: Vec<u8>,
        policy_descriptor: ObjectDescriptor,
        trust_scope: TrustScopeId,
        signer: KeyReference,
        public_key: [u8; 32],
        purpose: SignaturePurpose,
        limits: DecodeLimits,
    ) -> Result<Self, AuthorizationPreparationError> {
        if canonical_policy.len() > MAXIMUM_TRUST_POLICY_BYTES {
            return Err(AuthorizationPreparationError::PolicyTooLarge);
        }
        validate_descriptor_role(
            DescriptorRole::SignatureVerificationPolicy,
            &policy_descriptor,
        )?;
        let policy = decode_trust_policy(&canonical_policy, bounded_policy_limits(limits))?;
        let computed =
            descriptor_for_bytes(policy_descriptor.media_type().clone(), &canonical_policy);
        if computed != policy_descriptor {
            return Err(AuthorizationPreparationError::PolicyDescriptorMismatch);
        }
        if policy.trust_scope() != trust_scope {
            return Err(AuthorizationPreparationError::TrustScopeMismatch);
        }
        if policy.purpose() != purpose {
            return Err(AuthorizationPreparationError::PurposeMismatch);
        }
        if !policy.allowed_keys().contains(&signer) {
            return Err(AuthorizationPreparationError::SignerMismatch);
        }
        let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
        if signer.public_key_sha256() != fingerprint {
            return Err(AuthorizationPreparationError::PublicKeyFingerprintMismatch);
        }

        Ok(Self {
            canonical_policy,
            policy_descriptor,
            trust_scope,
            signer,
            public_key,
            purpose,
        })
    }

    /// Returns the exact immutable signer generation.
    #[must_use]
    pub const fn signer(&self) -> &KeyReference {
        &self.signer
    }

    /// Returns the exact verification-policy descriptor.
    #[must_use]
    pub const fn policy_descriptor(&self) -> &ObjectDescriptor {
        &self.policy_descriptor
    }
}

/// Describes one exact statement submitted to a protected signer.
///
/// Both byte slices are owned by the enclosing [`AuthorizationPreparation`].
/// `signing_message` is the precise Ed25519 input, including the RFC-0019
/// domain separator. Signing only `canonical_statement` is invalid.
#[derive(Clone, Copy, Debug)]
pub struct PreparedSigningRequest<'a> {
    statement: &'a SignatureStatement,
    canonical_statement: &'a [u8],
    signing_message: &'a [u8],
}

impl<'a> PreparedSigningRequest<'a> {
    /// Returns the purpose-, policy-, validity-, and signer-bound statement.
    #[must_use]
    pub const fn statement(self) -> &'a SignatureStatement {
        self.statement
    }

    /// Returns the exact canonical CBOR statement embedded in the envelope.
    #[must_use]
    pub const fn canonical_statement(self) -> &'a [u8] {
        self.canonical_statement
    }

    /// Returns the exact domain-separated bytes the external signer must sign.
    #[must_use]
    pub const fn signing_message(self) -> &'a [u8] {
        self.signing_message
    }

    /// Returns the immutable descriptor of the artifact being signed.
    #[must_use]
    pub const fn subject_descriptor(self) -> &'a ObjectDescriptor {
        self.statement.subject()
    }
}

#[derive(Clone, Debug)]
struct PreparedArtifact {
    canonical_object: Vec<u8>,
    statement: SignatureStatement,
    canonical_statement: Vec<u8>,
    signing_message: Vec<u8>,
    authority: SigningAuthority,
}

impl PreparedArtifact {
    fn signing_request(&self) -> PreparedSigningRequest<'_> {
        PreparedSigningRequest {
            statement: &self.statement,
            canonical_statement: &self.canonical_statement,
            signing_message: &self.signing_message,
        }
    }
}

/// Holds byte-exact plan and lease objects while protected signatures are pending.
///
/// All fields are private and the type exposes no mutable byte access. The
/// prepared statements therefore remain immutable-by-digest from preparation
/// through completion.
#[derive(Clone, Debug)]
pub struct AuthorizationPreparation {
    broker_plan: PreparedArtifact,
    ownership_lease: PreparedArtifact,
}

impl AuthorizationPreparation {
    /// Canonicalizes and freezes one coherent broker-plan/ownership-lease pair.
    ///
    /// Artifact validity is copied exactly into its signature statement. The
    /// lease assignment, node, and signing authority must match the plan's
    /// corresponding commitments.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationPreparationError`] if an authority has the wrong
    /// purpose, the plan and lease do not describe the same assignment and
    /// node, the plan names another ownership authority, or statement
    /// construction fails.
    pub fn new(
        broker_plan: BrokerAuthorizationPlan,
        broker_authority: SigningAuthority,
        ownership_lease: OwnershipLease,
        ownership_authority: SigningAuthority,
    ) -> Result<Self, AuthorizationPreparationError> {
        if broker_authority.purpose != SignaturePurpose::BrokerAuthorization
            || ownership_authority.purpose != SignaturePurpose::OwnershipLease
        {
            return Err(AuthorizationPreparationError::PurposeMismatch);
        }
        let plan_assignment = broker_plan.assignment();
        let lease_assignment = ownership_lease.assignment();
        if plan_assignment.sandbox() != lease_assignment.sandbox()
            || plan_assignment.incarnation() != lease_assignment.incarnation()
            || plan_assignment.epoch() != lease_assignment.epoch()
            || plan_assignment.digest() != lease_assignment.digest()
            || broker_plan.node() != ownership_lease.node()
        {
            return Err(AuthorizationPreparationError::ArtifactContextMismatch);
        }
        if broker_plan.ownership_authority() != ownership_authority.signer() {
            return Err(AuthorizationPreparationError::SignerMismatch);
        }

        let plan_bytes = encode_broker_authorization_plan(&broker_plan);
        let plan = prepare_artifact(
            plan_bytes,
            PortableMediaType::BrokerAuthorizationPlan,
            broker_authority,
            broker_plan.issued_seconds(),
            broker_plan.expires_seconds(),
        )?;
        let lease_bytes = encode_ownership_lease(&ownership_lease);
        let lease = prepare_artifact(
            lease_bytes,
            PortableMediaType::OwnershipLease,
            ownership_authority,
            ownership_lease.authority_issued_seconds(),
            ownership_lease.authority_expires_seconds(),
        )?;

        Ok(Self {
            broker_plan: plan,
            ownership_lease: lease,
        })
    }

    /// Returns the exact broker-plan signing request.
    #[must_use]
    pub fn broker_plan_signing_request(&self) -> PreparedSigningRequest<'_> {
        self.broker_plan.signing_request()
    }

    /// Returns the exact ownership-lease signing request.
    #[must_use]
    pub fn ownership_lease_signing_request(&self) -> PreparedSigningRequest<'_> {
        self.ownership_lease.signing_request()
    }

    /// Returns the frozen canonical broker-plan bytes committed by its statement.
    #[must_use]
    pub fn broker_plan_bytes(&self) -> &[u8] {
        &self.broker_plan.canonical_object
    }

    /// Returns the frozen canonical ownership-lease bytes committed by its statement.
    #[must_use]
    pub fn ownership_lease_bytes(&self) -> &[u8] {
        &self.ownership_lease.canonical_object
    }

    /// Verifies both returned signatures and emits an owned artifact quartet.
    ///
    /// `now_seconds` applies inclusive issue and exclusive expiry semantics to
    /// both statements. Envelope inputs are retained byte-for-byte after the
    /// canonical decoder proves that re-encoding is identical.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationPreparationError`] for malformed or noncanonical
    /// envelopes, a statement that differs in subject, purpose, validity,
    /// policy, scope, or signer, an invalid signature, or stale authority.
    pub fn complete(
        self,
        broker_plan_signature: ReturnedSignature<'_>,
        ownership_lease_signature: ReturnedSignature<'_>,
        now_seconds: i64,
    ) -> Result<AuthorizationArtifacts, AuthorizationPreparationError> {
        let plan_signature =
            accept_signature(&self.broker_plan, broker_plan_signature, now_seconds)?;
        let lease_signature = accept_signature(
            &self.ownership_lease,
            ownership_lease_signature,
            now_seconds,
        )?;

        Ok(AuthorizationArtifacts {
            broker_plan: self.broker_plan.canonical_object,
            broker_plan_signature: plan_signature,
            ownership_lease: self.ownership_lease.canonical_object,
            ownership_lease_signature: lease_signature,
        })
    }
}

/// Supplies either raw signature bytes or a complete canonical envelope.
#[derive(Clone, Copy, Debug)]
pub enum ReturnedSignature<'a> {
    /// Exact 64-byte Ed25519 signature over the prepared signing message.
    Bytes(SignatureBytes),
    /// Canonical detached `Signature` CBOR bytes returned by the signer.
    Envelope(&'a [u8]),
}

/// Owns the exact four authorization byte strings required by an effect request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationArtifacts {
    broker_plan: Vec<u8>,
    broker_plan_signature: Vec<u8>,
    ownership_lease: Vec<u8>,
    ownership_lease_signature: Vec<u8>,
}

impl AuthorizationArtifacts {
    /// Borrows all four byte strings without transformation or re-encoding.
    #[must_use]
    pub fn as_quartet(&self) -> AuthorizationArtifactQuartet<'_> {
        AuthorizationArtifactQuartet {
            broker_plan: &self.broker_plan,
            broker_plan_signature: &self.broker_plan_signature,
            ownership_lease: &self.ownership_lease,
            ownership_lease_signature: &self.ownership_lease_signature,
        }
    }
}

/// Borrows the core-level authorization quartet for a transport adapter.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationArtifactQuartet<'a> {
    /// Canonical `BrokerAuthorizationPlan` CBOR bytes.
    pub broker_plan: &'a [u8],
    /// Canonical detached broker-plan `Signature` CBOR bytes.
    pub broker_plan_signature: &'a [u8],
    /// Canonical `OwnershipLease` CBOR bytes.
    pub ownership_lease: &'a [u8],
    /// Canonical detached ownership-lease `Signature` CBOR bytes.
    pub ownership_lease_signature: &'a [u8],
}

/// Reports invalid preparation input or an unacceptable signer response.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorizationPreparationError {
    /// A canonical policy or returned signature envelope failed decoding.
    #[error("invalid canonical authority object: {0}")]
    CanonicalObject(#[from] CanonicalCborError),
    /// Canonical policy bytes exceed the controller's fixed allocation bound.
    #[error("canonical trust policy exceeds 64 KiB")]
    PolicyTooLarge,
    /// A descriptor uses an invalid registry role.
    #[error("invalid authority descriptor: {0}")]
    Registry(#[from] RegistryError),
    /// Signature-statement construction rejected its semantic fields.
    #[error("invalid signature statement: {0}")]
    Statement(#[from] InvalidTrustModel),
    /// Canonical policy bytes differ from their immutable descriptor.
    #[error("canonical trust policy bytes do not match their descriptor")]
    PolicyDescriptorMismatch,
    /// Policy and requested statement use different trust scopes.
    #[error("trust policy and requested signature use different scopes")]
    TrustScopeMismatch,
    /// Authority or returned statement has another signature purpose.
    #[error("signature purpose mismatch")]
    PurposeMismatch,
    /// Policy, plan, or returned statement names another signer generation.
    #[error("signer generation mismatch")]
    SignerMismatch,
    /// The public key does not match the immutable signer fingerprint.
    #[error("public key fingerprint mismatch")]
    PublicKeyFingerprintMismatch,
    /// Plan and lease assignment or node bindings differ.
    #[error("broker plan and ownership lease context mismatch")]
    ArtifactContextMismatch,
    /// The returned envelope statement is not byte-semantically identical.
    #[error("returned signature statement differs from the prepared statement")]
    ReturnedStatementMismatch,
    /// Canonical decoding and re-encoding did not preserve the envelope bytes.
    #[error("returned signature envelope is not byte-exact canonical CBOR")]
    NonCanonicalEnvelope,
    /// Cryptographic verification or current policy validation failed.
    #[error("returned signature verification failed: {0}")]
    Signature(#[from] aos_sandbox_core::SignatureVerificationError),
    /// A fixed registered media type unexpectedly failed syntax validation.
    #[error("registered authority media type is invalid")]
    InvalidRegisteredMediaType,
}

fn prepare_artifact(
    canonical_object: Vec<u8>,
    media_type: PortableMediaType,
    authority: SigningAuthority,
    issued_seconds: i64,
    expires_seconds: i64,
) -> Result<PreparedArtifact, AuthorizationPreparationError> {
    let media_type = MediaType::new(media_type.as_str().to_owned())
        .map_err(|_| AuthorizationPreparationError::InvalidRegisteredMediaType)?;
    let subject = descriptor_for_bytes(media_type, &canonical_object);
    let statement = SignatureStatement::new(
        subject,
        authority.trust_scope,
        authority.signer.clone(),
        authority.purpose,
        issued_seconds,
        Some(expires_seconds),
        authority.policy_descriptor.clone(),
    )?;
    let canonical_statement = encode_signature_statement(&statement);
    let signing_message = signature_signing_message(&statement);

    Ok(PreparedArtifact {
        canonical_object,
        statement,
        canonical_statement,
        signing_message,
        authority,
    })
}

fn accept_signature(
    prepared: &PreparedArtifact,
    returned: ReturnedSignature<'_>,
    now_seconds: i64,
) -> Result<Vec<u8>, AuthorizationPreparationError> {
    let (signature, envelope_bytes) = match returned {
        ReturnedSignature::Bytes(bytes) => {
            let signature = Signature::new(prepared.statement.clone(), bytes);
            let envelope = encode_signature(&signature);
            (signature, envelope)
        }
        ReturnedSignature::Envelope(bytes) => {
            let limits = signature_decode_limits();
            let signature = decode_signature(bytes, limits)?;
            if encode_signature(&signature) != bytes {
                return Err(AuthorizationPreparationError::NonCanonicalEnvelope);
            }
            (signature, bytes.to_vec())
        }
    };
    if signature.statement() != &prepared.statement {
        return Err(AuthorizationPreparationError::ReturnedStatementMismatch);
    }
    verify_signature(
        &signature,
        &prepared.authority.canonical_policy,
        &prepared.authority.public_key,
        now_seconds,
        bounded_policy_limits(DecodeLimits::default()),
    )?;
    Ok(envelope_bytes)
}

const fn signature_decode_limits() -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: MAXIMUM_SIGNATURE_ENVELOPE_BYTES,
        maximum_collection_items: 64,
        maximum_total_items: 512,
        maximum_byte_string_bytes: 1024,
        maximum_text_bytes: 255,
        maximum_depth: 16,
    }
}

const fn bounded_policy_limits(requested: DecodeLimits) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: min_usize(requested.maximum_bytes, MAXIMUM_TRUST_POLICY_BYTES),
        maximum_collection_items: min_usize(requested.maximum_collection_items, 1024),
        maximum_total_items: min_usize(requested.maximum_total_items, 4096),
        maximum_byte_string_bytes: min_usize(requested.maximum_byte_string_bytes, 1024),
        maximum_text_bytes: min_usize(requested.maximum_text_bytes, 255),
        maximum_depth: min_usize(requested.maximum_depth, 16),
    }
}

const fn min_usize(left: usize, right: usize) -> usize {
    if left < right { left } else { right }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::format::{
        decode_broker_authorization_plan, decode_ownership_lease, encode_trust_policy,
    };
    use aos_sandbox_core::model::{KeyUsage, StableKeyId, TrustPolicy};
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment, BrokerAudience, BrokerGrant,
        BrokerGrantTarget, BrokerVerb, DesiredGeneration, IncarnationId, LeaseAssignment, NodeId,
        ProtocolId, ProtocolVersion, RevocationScopeId, SandboxId, sign_statement,
    };
    use ed25519_dalek::SigningKey;

    use super::*;

    struct Fixture {
        preparation: AuthorizationPreparation,
        broker_key: SigningKey,
        lease_key: SigningKey,
    }

    fn key_reference(name: &str, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            1,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn authority(
        name: &str,
        purpose: SignaturePurpose,
        key: &SigningKey,
        scope_byte: u8,
    ) -> SigningAuthority {
        let usage = match purpose {
            SignaturePurpose::BrokerAuthorization => KeyUsage::BrokerAuthorization,
            SignaturePurpose::OwnershipLease => KeyUsage::OwnershipLease,
            _ => panic!("test only constructs authorization authorities"),
        };
        let signer = key_reference(name, usage, key);
        let scope = TrustScopeId::from_bytes([scope_byte; 16]);
        let policy = TrustPolicy::new(scope, purpose, vec![signer.clone()], Vec::new())
            .unwrap_or_else(|error| panic!("test policy failed: {error}"));
        let policy_bytes = encode_trust_policy(&policy);
        let media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test media type failed: {error}"));
        let descriptor = descriptor_for_bytes(media_type, &policy_bytes);
        SigningAuthority::new(
            policy_bytes,
            descriptor,
            scope,
            signer,
            key.verifying_key().to_bytes(),
            purpose,
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test authority failed: {error}"))
    }

    fn fixture() -> Fixture {
        let broker_key = SigningKey::from_bytes(&[9; 32]);
        let lease_key = SigningKey::from_bytes(&[31; 32]);
        let broker_authority = authority(
            "broker-controller",
            SignaturePurpose::BrokerAuthorization,
            &broker_key,
            10,
        );
        let lease_authority = authority(
            "ownership-authority",
            SignaturePurpose::OwnershipLease,
            &lease_key,
            11,
        );
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        let node = NodeId::from_bytes([6; 16]);
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(1, 0),
            assignment,
            node,
            lease_authority.signer().clone(),
            vec![
                BrokerGrant::new(
                    BrokerVerb::MountCreate,
                    BrokerGrantTarget::Assignment,
                    BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes([7; 32]))
                        .unwrap_or_else(|error| panic!("test argument commitment failed: {error}")),
                    4096,
                    0,
                )
                .unwrap_or_else(|error| panic!("test grant failed: {error}")),
            ],
            ObjectDigest::from_bytes([8; 32]),
            RevocationScopeId::from_bytes([9; 16]),
            100,
            200,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test plan failed: {error}"));
        let lease_assignment = LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test lease assignment failed: {error}"));
        let lease = OwnershipLease::new(lease_assignment, node, 1, 110, 190, 5, [12; 16])
            .unwrap_or_else(|error| panic!("test lease failed: {error}"));
        let preparation =
            AuthorizationPreparation::new(plan, broker_authority, lease, lease_authority)
                .unwrap_or_else(|error| panic!("test preparation failed: {error}"));

        Fixture {
            preparation,
            broker_key,
            lease_key,
        }
    }

    fn signatures(fixture: &Fixture) -> (Signature, Signature) {
        let plan = sign_statement(
            fixture
                .preparation
                .broker_plan_signing_request()
                .statement()
                .clone(),
            &fixture.broker_key,
        )
        .unwrap_or_else(|error| panic!("test plan signing failed: {error}"));
        let lease = sign_statement(
            fixture
                .preparation
                .ownership_lease_signing_request()
                .statement()
                .clone(),
            &fixture.lease_key,
        )
        .unwrap_or_else(|error| panic!("test lease signing failed: {error}"));
        (plan, lease)
    }

    #[test]
    fn preparation_is_byte_exact_and_completes_from_mixed_responses() {
        let fixture = fixture();
        let plan_request = fixture.preparation.broker_plan_signing_request();
        assert_eq!(
            plan_request.signing_message(),
            signature_signing_message(plan_request.statement())
        );
        let prepared_plan_descriptor = plan_request.subject_descriptor().clone();
        let prepared_lease_descriptor = fixture
            .preparation
            .ownership_lease_signing_request()
            .subject_descriptor()
            .clone();
        let (plan_signature, lease_signature) = signatures(&fixture);
        let exact_lease_envelope = encode_signature(&lease_signature);

        let artifacts = fixture
            .preparation
            .complete(
                ReturnedSignature::Bytes(plan_signature.signature()),
                ReturnedSignature::Envelope(&exact_lease_envelope),
                150,
            )
            .unwrap_or_else(|error| panic!("test completion failed: {error}"));
        let quartet = artifacts.as_quartet();
        assert_eq!(quartet.ownership_lease_signature, exact_lease_envelope);
        assert_eq!(
            descriptor_for_bytes(
                MediaType::new(
                    PortableMediaType::BrokerAuthorizationPlan
                        .as_str()
                        .to_owned(),
                )
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
                quartet.broker_plan,
            ),
            prepared_plan_descriptor
        );
        assert_eq!(
            descriptor_for_bytes(
                MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
                    .unwrap_or_else(|error| panic!("test media type failed: {error}")),
                quartet.ownership_lease,
            ),
            prepared_lease_descriptor
        );
        assert!(
            decode_broker_authorization_plan(quartet.broker_plan, DecodeLimits::default()).is_ok()
        );
        assert!(decode_ownership_lease(quartet.ownership_lease, DecodeLimits::default()).is_ok());
    }

    #[test]
    fn swapped_signatures_are_rejected_by_statement_binding() {
        let fixture = fixture();
        let (plan, lease) = signatures(&fixture);
        let plan_envelope = encode_signature(&plan);
        let lease_envelope = encode_signature(&lease);

        assert_eq!(
            fixture.preparation.complete(
                ReturnedSignature::Envelope(&lease_envelope),
                ReturnedSignature::Envelope(&plan_envelope),
                150,
            ),
            Err(AuthorizationPreparationError::ReturnedStatementMismatch)
        );
    }

    #[test]
    fn stale_and_forged_signatures_are_rejected() {
        let stale = fixture();
        let (plan, lease) = signatures(&stale);
        assert!(matches!(
            stale.preparation.complete(
                ReturnedSignature::Bytes(plan.signature()),
                ReturnedSignature::Bytes(lease.signature()),
                200,
            ),
            Err(AuthorizationPreparationError::Signature(
                aos_sandbox_core::SignatureVerificationError::Expired
            ))
        ));

        let forged = fixture();
        let (_, lease) = signatures(&forged);
        assert!(matches!(
            forged.preparation.complete(
                ReturnedSignature::Bytes(SignatureBytes::new([0; 64])),
                ReturnedSignature::Bytes(lease.signature()),
                150,
            ),
            Err(AuthorizationPreparationError::Signature(
                aos_sandbox_core::SignatureVerificationError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn wrong_policy_signer_and_validity_envelopes_are_rejected() {
        for mutation in 0..3 {
            let fixture = fixture();
            let request = fixture.preparation.broker_plan_signing_request();
            let original = request.statement();
            let (signer, issued, policy) = match mutation {
                0 => (
                    original.signer().clone(),
                    original.issued_seconds(),
                    fixture
                        .preparation
                        .ownership_lease_signing_request()
                        .statement()
                        .verification_policy()
                        .clone(),
                ),
                1 => (
                    key_reference(
                        "other-controller",
                        KeyUsage::BrokerAuthorization,
                        &fixture.broker_key,
                    ),
                    original.issued_seconds(),
                    original.verification_policy().clone(),
                ),
                _ => (
                    original.signer().clone(),
                    original.issued_seconds() + 1,
                    original.verification_policy().clone(),
                ),
            };
            let changed = SignatureStatement::new(
                original.subject().clone(),
                original.trust_scope(),
                signer,
                SignaturePurpose::BrokerAuthorization,
                issued,
                original.expires_seconds(),
                policy,
            )
            .unwrap_or_else(|error| panic!("test changed statement failed: {error}"));
            let envelope = encode_signature(&Signature::new(changed, SignatureBytes::new([0; 64])));
            let (_, lease) = signatures(&fixture);

            assert_eq!(
                fixture.preparation.complete(
                    ReturnedSignature::Envelope(&envelope),
                    ReturnedSignature::Bytes(lease.signature()),
                    150,
                ),
                Err(AuthorizationPreparationError::ReturnedStatementMismatch)
            );
        }
    }

    #[test]
    fn wrong_purpose_envelope_is_rejected() {
        let fixture = fixture();
        let wrong = fixture
            .preparation
            .ownership_lease_signing_request()
            .statement()
            .clone();
        let envelope = encode_signature(&Signature::new(wrong, SignatureBytes::new([0; 64])));
        let (_, lease) = signatures(&fixture);

        assert_eq!(
            fixture.preparation.complete(
                ReturnedSignature::Envelope(&envelope),
                ReturnedSignature::Bytes(lease.signature()),
                150,
            ),
            Err(AuthorizationPreparationError::ReturnedStatementMismatch)
        );
    }

    #[test]
    fn public_policy_input_has_an_unexpandable_size_bound() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let signer = key_reference("broker-controller", KeyUsage::BrokerAuthorization, &key);
        let descriptor = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([1; 32]),
            (MAXIMUM_TRUST_POLICY_BYTES + 1) as u64,
        );

        assert!(matches!(
            SigningAuthority::new(
                vec![0; MAXIMUM_TRUST_POLICY_BYTES + 1],
                descriptor,
                TrustScopeId::from_bytes([1; 16]),
                signer,
                key.verifying_key().to_bytes(),
                SignaturePurpose::BrokerAuthorization,
                DecodeLimits::default(),
            ),
            Err(AuthorizationPreparationError::PolicyTooLarge)
        ));
    }
}
