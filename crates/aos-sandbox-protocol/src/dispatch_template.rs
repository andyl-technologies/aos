//! Owns complete non-authorizing immutable dispatch template DATA.

use aos_proto::aos::sandbox::local::v1::{BrokerDescriptorRole, BrokerMethod, RuntimeAction};
use aos_sandbox_core::format::decode_broker_authorization_plan;
use aos_sandbox_core::model::KeyReference;
use aos_sandbox_core::{BrokerArgumentCommitment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrantTarget, BrokerVerb, ObjectDigest, ProtocolId};
use crate::{MAXIMUM_PACKET_DESCRIPTORS, MAXIMUM_REQUEST_BYTES};
use crate::authorization_artifact::SignedBrokerPlan;
use sha2::{Digest as _, Sha256};

const TEMPLATE_DOMAIN: &[u8] = b"aos.sandbox.broker-dispatch-template.v1\0";
const SEMANTIC_IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.broker-semantic-identity.v1\0";
const MAXIMUM_DEADLINE_FIELD_BYTES: usize = 11;

/// Names the controller-asserted portable grant for one immutable request.
///
/// This value carries no proof that a protobuf body has these semantics. It is
/// an immutable dispatch correlation value; the privileged broker independently
/// derives and compares the authoritative semantic identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerDispatchSemanticIdentityV1 {
    verb: BrokerVerb,
    target: BrokerGrantTarget,
    argument_commitment: BrokerArgumentCommitment,
}


impl BrokerDispatchSemanticIdentityV1 {
    /// Constructs an identity returned by a protocol semantic compiler.
    ///
    /// Construction is non-authorizing because this type cannot prove the
    /// provenance of its three values.
    #[must_use]
    pub const fn new(
        verb: BrokerVerb,
        target: BrokerGrantTarget,
        argument_commitment: BrokerArgumentCommitment,
    ) -> Self {
        Self {
            verb,
            target,
            argument_commitment,
        }
    }

    /// Returns the exact semantic verb.
    #[must_use]
    pub const fn verb(self) -> BrokerVerb {
        self.verb
    }

    /// Returns the assignment or resource target.
    #[must_use]
    pub const fn target(self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the canonical typed argument commitment.
    #[must_use]
    pub const fn argument_commitment(self) -> BrokerArgumentCommitment {
        self.argument_commitment
    }
}

/// Freezes one reusable, non-authorizing operation without lease or clock facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerDispatchTemplateV1 {
    signed_plan: SignedBrokerPlan,
    method: BrokerMethod,
    body_without_deadline: Vec<u8>,
    descriptor_roles: Vec<BrokerDescriptorRole>,
    semantics: BrokerDispatchSemanticIdentityV1,
    digest: ObjectDigest,
}

impl BrokerDispatchTemplateV1 {
    /// Constructs a byte-exact immutable dispatch template.
    ///
    /// `body_without_deadline` must be a protobuf request whose field 1 is its
    /// common header and whose header omits field 5. An attempt injects that
    /// deadline field without decoding or rewriting any other body bytes.
    /// `semantics` should come from the corresponding portable protocol
    /// compiler. This constructor only proves that the asserted identity occurs
    /// in the signed plan; it deliberately cannot prove the body has that
    /// meaning because catalog-resolved semantics remain broker-owned. The
    /// receiving broker must decode and independently recompute it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerDispatchTemplateError`] when method, protocol,
    /// semantics, body framing, descriptors, or signed grant bounds differ.
    pub fn new(
        signed_plan: SignedBrokerPlan,
        method: BrokerMethod,
        body_without_deadline: Vec<u8>,
        descriptor_roles: Vec<BrokerDescriptorRole>,
        semantics: BrokerDispatchSemanticIdentityV1,
    ) -> Result<Self, BrokerDispatchTemplateError> {
        validate_method(&signed_plan, method)?;
        validate_method_semantics(method, semantics.verb())?;
        validate_descriptor_roles(&descriptor_roles)?;

        let maximum_body = body_without_deadline
            .len()
            .checked_add(MAXIMUM_DEADLINE_FIELD_BYTES)
            .ok_or(BrokerDispatchTemplateError::BodyTooLarge)?;
        if maximum_body > MAXIMUM_REQUEST_BYTES {
            return Err(BrokerDispatchTemplateError::BodyTooLarge);
        }
        locate_deadline_free_header(&body_without_deadline)?;
        let request_bytes =
            u32::try_from(maximum_body).map_err(|_| BrokerDispatchTemplateError::BodyTooLarge)?;
        let descriptor_count = u16::try_from(descriptor_roles.len())
            .map_err(|_| BrokerDispatchTemplateError::DescriptorTable)?;
        match_plan_grant(
            signed_plan.plan(),
            semantics,
            request_bytes,
            descriptor_count,
        )?;

        let digest = template_digest(
            &signed_plan,
            method,
            &body_without_deadline,
            &descriptor_roles,
            semantics,
        );
        Ok(Self {
            signed_plan,
            method,
            body_without_deadline,
            descriptor_roles,
            semantics,
            digest,
        })
    }

    /// Returns the stable digest of every immutable template component.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the exact signed broker plan.
    #[must_use]
    pub const fn signed_plan(&self) -> &SignedBrokerPlan {
        &self.signed_plan
    }

    /// Returns the exact closed broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the deadline-free request body bytes.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.body_without_deadline
    }

    /// Returns ancillary descriptor roles in exact descriptor order.
    #[must_use]
    pub fn descriptor_roles(&self) -> &[BrokerDescriptorRole] {
        &self.descriptor_roles
    }

    /// Returns the portable operation semantics matched by the plan.
    #[must_use]
    pub const fn semantics(&self) -> BrokerDispatchSemanticIdentityV1 {
        self.semantics
    }
}

/// Reports invalid immutable template input.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerDispatchTemplateError {
    /// Method is not an effect method for the signed audience and protocol.
    #[error("broker method does not match the signed audience and protocol")]
    MethodMismatch,
    /// Protobuf body has no unique deadline-free common header.
    #[error("broker request body is not a deadline-free V1 body")]
    InvalidBody,
    /// Body cannot remain within the fixed packet allocation ceiling.
    #[error("broker request body exceeds the fixed V1 bound")]
    BodyTooLarge,
    /// Descriptor roles are oversized, unspecified, or repeated.
    #[error("broker descriptor role table is invalid")]
    DescriptorTable,
    /// Portable request semantics or bounds are not present in the plan.
    #[error("broker request is not committed by the signed plan")]
    PlanGrantMismatch,
}


fn validate_method(
    signed_plan: &SignedBrokerPlan,
    method: BrokerMethod,
) -> Result<(), BrokerDispatchTemplateError> {
    let method_matches_protocol = match signed_plan.plan().protocol() {
        ProtocolId::HostBroker => method == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
        ProtocolId::MountBroker => matches!(
            method,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY
                | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
                | BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
                | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
        ),
        ProtocolId::StorageBroker => matches!(
            method,
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                | BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
        ),
        ProtocolId::NetworkBroker => method == BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
        _ => return Err(BrokerDispatchTemplateError::MethodMismatch),
    };
    if !method_matches_protocol
        || signed_plan.plan().audience().protocol() != signed_plan.plan().protocol()
    {
        return Err(BrokerDispatchTemplateError::MethodMismatch);
    }
    Ok(())
}

fn validate_method_semantics(
    method: BrokerMethod,
    verb: BrokerVerb,
) -> Result<(), BrokerDispatchTemplateError> {
    let semantics_match = match method {
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
            verb == BrokerVerb::StorageAtomicSnapshot
        }
        BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE => verb == BrokerVerb::MountAcquireSource,
        BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION => {
            verb == BrokerVerb::MountReleaseSourceAcquisition
        }
        _ => true,
    };
    if semantics_match {
        Ok(())
    } else {
        Err(BrokerDispatchTemplateError::PlanGrantMismatch)
    }
}

fn validate_descriptor_roles(
    roles: &[BrokerDescriptorRole],
) -> Result<(), BrokerDispatchTemplateError> {
    if roles.len() > MAXIMUM_PACKET_DESCRIPTORS {
        return Err(BrokerDispatchTemplateError::DescriptorTable);
    }
    for (index, role) in roles.iter().copied().enumerate() {
        if role == BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED
            || roles[..index].contains(&role)
        {
            return Err(BrokerDispatchTemplateError::DescriptorTable);
        }
    }
    Ok(())
}

pub fn match_plan_grant(
    plan: &BrokerAuthorizationPlan,
    semantics: BrokerDispatchSemanticIdentityV1,
    request_bytes: u32,
    descriptor_count: u16,
) -> Result<(), BrokerDispatchTemplateError> {
    let matched = plan.grants().iter().any(|grant| {
        grant.verb() == semantics.verb
            && grant.target() == semantics.target
            && grant.argument_commitment() == semantics.argument_commitment
            && request_bytes <= grant.maximum_request_bytes()
            && descriptor_count <= grant.maximum_descriptors()
    });
    if matched {
        Ok(())
    } else {
        Err(BrokerDispatchTemplateError::PlanGrantMismatch)
    }
}

fn template_digest(
    signed_plan: &SignedBrokerPlan,
    method: BrokerMethod,
    body: &[u8],
    roles: &[BrokerDescriptorRole],
    semantics: BrokerDispatchSemanticIdentityV1,
) -> ObjectDigest {
    template_digest_from_parts(
        signed_plan.digest(),
        signed_plan.canonical_signature(),
        method,
        body,
        roles,
        semantics,
    )
}

pub fn template_digest_from_parts(
    plan_digest: ObjectDigest,
    plan_signature: &[u8],
    method: BrokerMethod,
    body: &[u8],
    roles: &[BrokerDescriptorRole],
    semantics: BrokerDispatchSemanticIdentityV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(TEMPLATE_DOMAIN);
    digest.update(plan_digest.as_bytes());
    digest.update(
        u64::try_from(plan_signature.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(plan_signature);
    digest.update((method as i32).to_be_bytes());
    digest.update(semantics.verb.get().to_be_bytes());
    encode_target(&mut digest, semantics.target);
    digest.update(semantics.argument_commitment.digest().as_bytes());
    digest.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(body);
    digest.update(u16::try_from(roles.len()).unwrap_or(u16::MAX).to_be_bytes());
    for role in roles {
        digest.update((*role as i32).to_be_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub fn semantic_identity_digest(
    semantics: BrokerDispatchSemanticIdentityV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(SEMANTIC_IDENTITY_DOMAIN);
    digest.update(semantics.verb.get().to_be_bytes());
    encode_target(&mut digest, semantics.target);
    digest.update(semantics.argument_commitment.digest().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_target(digest: &mut Sha256, target: BrokerGrantTarget) {
    match target {
        BrokerGrantTarget::Assignment => digest.update([1]),
        BrokerGrantTarget::Resource(handle) => {
            digest.update([2]);
            digest.update(handle.as_bytes());
        }
        BrokerGrantTarget::ResourcePair {
            previous,
            successor,
        } => {
            digest.update([3]);
            digest.update(previous.as_bytes());
            digest.update(successor.as_bytes());
        }
    }
}

fn locate_deadline_free_header(body: &[u8]) -> Result<(usize, usize), BrokerDispatchTemplateError> {
    if body.first() != Some(&0x0a) {
        return Err(BrokerDispatchTemplateError::InvalidBody);
    }
    let (length, length_bytes) = decode_varint(&body[1..])?;
    let start = 1_usize
        .checked_add(length_bytes)
        .ok_or(BrokerDispatchTemplateError::InvalidBody)?;
    let length = usize::try_from(length).map_err(|_| BrokerDispatchTemplateError::InvalidBody)?;
    let end = start
        .checked_add(length)
        .filter(|end| *end <= body.len())
        .ok_or(BrokerDispatchTemplateError::InvalidBody)?;
    validate_header_fields(&body[start..end])?;
    validate_remaining_body_fields(&body[end..])?;
    Ok((start, end))
}

pub fn validate_durable_deadline_free_body(body: &[u8]) -> bool {
    body.len()
        .checked_add(MAXIMUM_DEADLINE_FIELD_BYTES)
        .is_some_and(|size| size <= MAXIMUM_REQUEST_BYTES)
        && locate_deadline_free_header(body).is_ok()
}

pub fn validate_durable_attempt_body(
    deadline_free_body: &[u8],
    deadline_boottime_nanoseconds: u64,
    attempt_body: &[u8],
) -> bool {
    inject_deadline(deadline_free_body, deadline_boottime_nanoseconds)
        .is_ok_and(|body| body == attempt_body)
}


fn validate_remaining_body_fields(bytes: &[u8]) -> Result<(), BrokerDispatchTemplateError> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let (key, key_bytes) = decode_varint(&bytes[cursor..])?;
        if key >> 3 == 0 || key >> 3 == 1 {
            return Err(BrokerDispatchTemplateError::InvalidBody);
        }
        cursor = cursor
            .checked_add(key_bytes)
            .ok_or(BrokerDispatchTemplateError::InvalidBody)?;
        cursor = skip_wire_value(bytes, cursor, key & 7)?;
    }
    Ok(())
}

fn validate_header_fields(header: &[u8]) -> Result<(), BrokerDispatchTemplateError> {
    let mut cursor = 0;
    while cursor < header.len() {
        let (key, key_bytes) = decode_varint(&header[cursor..])?;
        cursor = cursor
            .checked_add(key_bytes)
            .ok_or(BrokerDispatchTemplateError::InvalidBody)?;
        if key >> 3 == 0 || key >> 3 == 5 {
            return Err(BrokerDispatchTemplateError::InvalidBody);
        }
        cursor = skip_wire_value(header, cursor, key & 7)?;
    }
    Ok(())
}

fn skip_wire_value(
    bytes: &[u8],
    cursor: usize,
    wire: u64,
) -> Result<usize, BrokerDispatchTemplateError> {
    match wire {
        0 => decode_varint(&bytes[cursor..])?
            .1
            .checked_add(cursor)
            .ok_or(BrokerDispatchTemplateError::InvalidBody),
        1 => cursor
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or(BrokerDispatchTemplateError::InvalidBody),
        2 => {
            let (length, length_bytes) = decode_varint(&bytes[cursor..])?;
            cursor
                .checked_add(length_bytes)
                .and_then(|start| start.checked_add(usize::try_from(length).ok()?))
                .filter(|end| *end <= bytes.len())
                .ok_or(BrokerDispatchTemplateError::InvalidBody)
        }
        5 => cursor
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or(BrokerDispatchTemplateError::InvalidBody),
        _ => Err(BrokerDispatchTemplateError::InvalidBody),
    }
}

pub fn inject_deadline(body: &[u8], deadline: u64) -> Result<Vec<u8>, DeadlineInjectionError> {
    let (header_start, header_end) =
        locate_deadline_free_header(body).map_err(|_| DeadlineInjectionError)?;
    let mut deadline_bytes = [0_u8; 10];
    let deadline_length = encode_varint(deadline, &mut deadline_bytes);
    let header_length = header_end - header_start;
    let new_header_length = header_length
        .checked_add(1 + deadline_length)
        .ok_or(DeadlineInjectionError)?;
    let mut header_length_bytes = [0_u8; 10];
    let header_length_count = encode_varint(
        u64::try_from(new_header_length).map_err(|_| DeadlineInjectionError)?,
        &mut header_length_bytes,
    );
    let capacity = body
        .len()
        .checked_add(MAXIMUM_DEADLINE_FIELD_BYTES)
        .ok_or(DeadlineInjectionError)?;
    let mut result = Vec::with_capacity(capacity);
    result.push(0x0a);
    result.extend_from_slice(&header_length_bytes[..header_length_count]);
    result.extend_from_slice(&body[header_start..header_end]);
    result.push(0x28);
    result.extend_from_slice(&deadline_bytes[..deadline_length]);
    result.extend_from_slice(&body[header_end..]);
    Ok(result)
}

fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), BrokerDispatchTemplateError> {
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().copied().take(10).enumerate() {
        let shift =
            u32::try_from(index * 7).map_err(|_| BrokerDispatchTemplateError::InvalidBody)?;
        if index == 9 && byte > 1 {
            return Err(BrokerDispatchTemplateError::InvalidBody);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(BrokerDispatchTemplateError::InvalidBody);
            }
            return Ok((value, index + 1));
        }
    }
    Err(BrokerDispatchTemplateError::InvalidBody)
}

fn encode_varint(mut value: u64, output: &mut [u8; 10]) -> usize {
    let mut index = 0;
    loop {
        output[index] = (value as u8) & 0x7f;
        value >>= 7;
        if value == 0 {
            return index + 1;
        }
        output[index] |= 0x80;
        index += 1;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("attempt body exceeds the fixed V1 bound")]
pub struct DeadlineInjectionError;

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, Audience, Feature, ResourceLimit, RuntimeAction,
    };
    use aos_sandbox_core::format::{
        decode_ownership_lease, encode_ownership_lease, encode_signature, encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerGrant, DecodeLimits,
        DesiredGeneration, IncarnationId, LeaseAssignment, MediaType, NodeId, OwnershipLease,
        OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolVersion, RevocationScopeId,
        SandboxId, TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use crate::{
        decode_host_guardian_companion_v1, decode_request_envelope, decode_runtime_template_v1,
        semantics::host::canonical_host_template_semantics_v1,
    };
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;

    use aos_sandbox_ownership_protocol::{OwnershipAuthorityVerifier, OwnershipClaimV1, OwnershipTransactionReceiptV1, UnverifiedOwnershipLeaseResponse};
    use crate::authorization_artifact::{
        BrokerPlanPreparation, ReturnedSignature, SigningAuthority,
    };

    use crate::authorization_artifact::tests::{authority, key_reference};
    use super::*;

    struct Fixture {
        template: BrokerDispatchTemplateV1,
        assignment: BrokerAssignment,
        node: NodeId,
        lease_key: SigningKey,
        lease_authority: KeyReference,
        lease_scope: TrustScopeId,
        lease_policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        lease_verifier: OwnershipAuthorityVerifier,
    }

    fn fixture() -> Fixture {
        let key = SigningKey::from_bytes(&[42; 32]);
        let lease_key = SigningKey::from_bytes(&[43; 32]);
        let lease_authority =
            key_reference("ownership-authority", KeyUsage::OwnershipLease, &lease_key);
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            DesiredGeneration::new(4),
            ObjectDigest::from_bytes([5; 32]),
        )
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
        let node = NodeId::from_bytes([6; 16]);
        let commitment = BrokerArgumentCommitment::for_canonical_bytes(b"mount-create");
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::MountCreate,
            BrokerGrantTarget::Assignment,
            commitment,
        );
        let plan = aos_sandbox_core::BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(2, 0),
            assignment,
            node,
            lease_authority.clone(),
            vec![
                BrokerGrant::new(
                    semantics.verb(),
                    semantics.target(),
                    semantics.argument_commitment(),
                    4096,
                    2,
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
        let preparation = BrokerPlanPreparation::new(plan, authority("controller", SignaturePurpose::BrokerAuthorization, &key, 21))
            .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let signature = sign_statement(preparation.signing_request().statement().clone(), &key)
            .unwrap_or_else(|error| panic!("test signing failed: {error}"));
        let lease_scope = TrustScopeId::from_bytes([31; 16]);
        let lease_policy = TrustPolicy::new(
            lease_scope,
            SignaturePurpose::OwnershipLease,
            vec![lease_authority.clone()],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test lease policy failed: {error}"));
        let lease_policy_bytes = encode_trust_policy(&lease_policy);
        let lease_policy_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test policy media type failed: {error}")),
            &lease_policy_bytes,
        );
        let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            lease_policy_bytes,
            lease_policy_descriptor.clone(),
            lease_scope,
            lease_authority.clone(),
            lease_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test lease anchor failed: {error}"));
        let lease_verifier = OwnershipAuthorityVerifier::new(lease_anchor, lease_authority.clone());
        let signed_plan = preparation
            .complete(ReturnedSignature::Bytes(signature.signature()), 150)
            .unwrap_or_else(|error| panic!("test completion failed: {error}"));

        // Field 1 is a deadline-free common header; field 2 stands for the
        // remainder of the method body and must survive injection byte-exactly.
        let body = vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x02, 0xaa, 0xbb];
        let template = BrokerDispatchTemplateV1::new(
            signed_plan,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            body,
            vec![BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT],
            semantics,
        )
        .unwrap_or_else(|error| panic!("test template failed: {error}"));
        Fixture {
            template,
            assignment,
            node,
            lease_key,
            lease_authority,
            lease_scope,
            lease_policy_descriptor,
            lease_verifier,
        }
    }
    fn signed_plan(plan: BrokerAuthorizationPlan, key: &SigningKey) -> SignedBrokerPlan {
        let preparation = BrokerPlanPreparation::new(plan, authority("controller", SignaturePurpose::BrokerAuthorization, key, 21))
            .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let signature = sign_statement(preparation.signing_request().statement().clone(), key)
            .unwrap_or_else(|error| panic!("test plan signature failed: {error}"));
        preparation
            .complete(ReturnedSignature::Bytes(signature.signature()), 150)
            .unwrap_or_else(|error| panic!("test plan completion failed: {error}"))
    }
    #[test]
    fn substitutions_change_identity_or_fail_closed() {
        let fixture = fixture();
        let body_changed = BrokerDispatchTemplateV1::new(
            fixture.template.signed_plan().clone(),
            fixture.template.method(),
            vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x01, 0xcc],
            fixture.template.descriptor_roles().to_vec(),
            fixture.template.semantics(),
        )
        .unwrap_or_else(|error| panic!("changed-body template failed: {error}"));
        let roles_changed = BrokerDispatchTemplateV1::new(
            fixture.template.signed_plan().clone(),
            fixture.template.method(),
            fixture.template.body_without_deadline().to_vec(),
            Vec::new(),
            fixture.template.semantics(),
        )
        .unwrap_or_else(|error| panic!("changed-roles template failed: {error}"));
        assert_ne!(body_changed.digest(), fixture.template.digest());
        assert_ne!(roles_changed.digest(), fixture.template.digest());

        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                fixture.template.body_without_deadline().to_vec(),
                fixture.template.descriptor_roles().to_vec(),
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::MethodMismatch)
        );
        let wrong_semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::MountInstall,
            BrokerGrantTarget::Resource(
                aos_sandbox_core::BrokerResourceHandle::from_bytes([44; 32])
                    .unwrap_or_else(|error| panic!("test handle failed: {error}")),
            ),
            fixture.template.semantics().argument_commitment(),
        );
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                fixture.template.body_without_deadline().to_vec(),
                fixture.template.descriptor_roles().to_vec(),
                wrong_semantics,
            ),
            Err(BrokerDispatchTemplateError::PlanGrantMismatch)
        );
    }
    #[test]
    fn source_acquisition_methods_require_their_exact_plan_verbs() {
        let fixture = fixture();
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let acquire_semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::MountAcquireSource,
            BrokerGrantTarget::Assignment,
            BrokerArgumentCommitment::for_canonical_bytes(b"acquire-source"),
        );
        let release_semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::MountReleaseSourceAcquisition,
            BrokerGrantTarget::Resource(
                aos_sandbox_core::BrokerResourceHandle::from_bytes([47; 32])
                    .unwrap_or_else(|error| panic!("test handle failed: {error}")),
            ),
            BrokerArgumentCommitment::for_canonical_bytes(b"release-source"),
        );
        let plan = aos_sandbox_core::BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(2, 0),
            fixture.assignment,
            fixture.node,
            fixture.lease_authority.clone(),
            vec![
                BrokerGrant::new(
                    acquire_semantics.verb(),
                    acquire_semantics.target(),
                    acquire_semantics.argument_commitment(),
                    4096,
                    0,
                )
                .unwrap_or_else(|error| panic!("test Acquire grant failed: {error}")),
                BrokerGrant::new(
                    release_semantics.verb(),
                    release_semantics.target(),
                    release_semantics.argument_commitment(),
                    4096,
                    0,
                )
                .unwrap_or_else(|error| panic!("test Release grant failed: {error}")),
            ],
            ObjectDigest::from_bytes([48; 32]),
            RevocationScopeId::from_bytes([49; 16]),
            100,
            200,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test source-acquisition plan failed: {error}"));
        let plan = signed_plan(plan, &signing_key);
        let body = vec![0x0a, 0x02, 0x08, 0x01];

        assert_eq!(
            validate_method_semantics(
                BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
                BrokerVerb::MountAcquireSource,
            ),
            Ok(())
        );
        assert_eq!(
            validate_method_semantics(
                BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
                BrokerVerb::MountReleaseSourceAcquisition,
            ),
            Ok(())
        );
        assert_eq!(
            validate_method_semantics(
                BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
                BrokerVerb::MountReleaseSourceAcquisition,
            ),
            Err(BrokerDispatchTemplateError::PlanGrantMismatch)
        );
        assert_eq!(
            validate_method_semantics(
                BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
                BrokerVerb::MountAcquireSource,
            ),
            Err(BrokerDispatchTemplateError::PlanGrantMismatch)
        );
        assert!(
            BrokerDispatchTemplateV1::new(
                plan.clone(),
                BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
                body.clone(),
                Vec::new(),
                acquire_semantics,
            )
            .is_ok()
        );
        assert!(
            BrokerDispatchTemplateV1::new(
                plan.clone(),
                BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
                body.clone(),
                Vec::new(),
                release_semantics,
            )
            .is_ok()
        );
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                plan.clone(),
                BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
                body.clone(),
                Vec::new(),
                release_semantics,
            ),
            Err(BrokerDispatchTemplateError::PlanGrantMismatch)
        );
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                plan,
                BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
                body,
                Vec::new(),
                acquire_semantics,
            ),
            Err(BrokerDispatchTemplateError::PlanGrantMismatch)
        );

        for method in [
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT,
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
        ] {
            assert_eq!(
                validate_method_semantics(method, BrokerVerb::MountCreate),
                Ok(())
            );
        }
    }
    #[test]
    fn template_does_not_misrepresent_controller_semantics_as_body_proof() {
        let fixture = fixture();
        // This is valid generic protobuf framing but not a valid ApplyMount
        // request. Construction may freeze it and correlate the controller's
        // asserted grant, but only broker-side typed decoding can reject it.
        let hostile_body = vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x01, 0xff];
        let template = BrokerDispatchTemplateV1::new(
            fixture.template.signed_plan().clone(),
            fixture.template.method(),
            hostile_body.clone(),
            fixture.template.descriptor_roles().to_vec(),
            fixture.template.semantics(),
        )
        .unwrap_or_else(|error| panic!("non-authorizing template failed: {error}"));

        assert_eq!(template.body_without_deadline(), hostile_body);
        assert_ne!(template.digest(), fixture.template.digest());
    }
    #[test]
    fn template_enforces_deadline_absence_and_fixed_bounds() {
        let fixture = fixture();
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                vec![0x0a, 0x02, 0x28, 0x01],
                Vec::new(),
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::InvalidBody)
        );
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                vec![0x0a, 0x02, 0x08, 0x01, 0x0a, 0x02, 0x28, 0x01],
                Vec::new(),
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::InvalidBody)
        );
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                fixture.template.body_without_deadline().to_vec(),
                vec![BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT; 2],
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::DescriptorTable)
        );
        let mut oversized = vec![0x0a, 0x02, 0x08, 0x01];
        oversized.resize(MAXIMUM_REQUEST_BYTES, 0);
        assert_eq!(
            BrokerDispatchTemplateV1::new(
                fixture.template.signed_plan().clone(),
                fixture.template.method(),
                oversized,
                Vec::new(),
                fixture.template.semantics(),
            ),
            Err(BrokerDispatchTemplateError::BodyTooLarge)
        );
    }
}
