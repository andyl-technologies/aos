//! Durable V3 prepared/current codecs and structural recovery validation.
//!
//! The isolated journal namespace contains two bounded record shapes:
//!
//! ```text
//! prepared/<digest> = complete publication bytes
//! current/<sandbox> = metadata header | complete publication bytes
//! ```

use super::*;

pub(super) fn encode_current(prepared: &PreparedAuthorityPublicationV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(176 + prepared.bytes.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(prepared.sandbox.as_bytes());
    bytes.extend_from_slice(&prepared.incarnation);
    bytes.extend_from_slice(&prepared.epoch.to_be_bytes());
    bytes.extend_from_slice(&prepared.desired_generation.to_be_bytes());
    bytes.extend_from_slice(prepared.assignment_digest.as_bytes());
    bytes.extend_from_slice(&prepared.node);
    bytes.extend_from_slice(&prepared.lease_generation.to_be_bytes());
    bytes.extend_from_slice(prepared.lease_digest.as_bytes());
    bytes.extend_from_slice(prepared.digest.as_bytes());
    bytes.extend_from_slice(
        &u64::try_from(prepared.bytes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&prepared.bytes);
    bytes
}

pub(super) fn decode_current(
    bytes: &[u8],
) -> Result<CurrentAuthorityPublicationV1, AuthorityPublicationError> {
    if bytes.starts_with(LEGACY_V1_MAGIC) || bytes.starts_with(LEGACY_V2_MAGIC) {
        return Err(AuthorityPublicationError::MigrationRequired);
    }
    if bytes.len() < CURRENT_HEADER_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let mut cursor = 10;
    let sandbox = SandboxId::from_bytes(take_array(bytes, &mut cursor)?);
    let incarnation = take_array(bytes, &mut cursor)?;
    let epoch = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
    let desired_generation = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
    let assignment_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let node = take_array(bytes, &mut cursor)?;
    let lease_generation = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
    let lease_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let length = usize::try_from(u64::from_be_bytes(take_array(bytes, &mut cursor)?))
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    if length > MAXIMUM_PUBLICATION_BYTES || cursor.checked_add(length) != Some(bytes.len()) {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let publication = bytes[cursor..].to_vec();
    if publication_digest(&publication) != digest {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let recovered = validate_encoded_publication(
        &publication,
        sandbox,
        incarnation,
        epoch,
        desired_generation,
        assignment_digest,
        node,
        lease_generation,
        lease_digest,
    )?;
    let source_draft_digest = derive_source_draft_digest(&publication, &recovered.templates)?;
    let receipt =
        OwnershipTransactionReceiptV1::from_canonical_bytes(recovered.lease.canonical_receipt())
            .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    Ok(CurrentAuthorityPublicationV1 {
        prepared: PreparedAuthorityPublicationV1 {
            sandbox,
            incarnation,
            epoch,
            desired_generation,
            assignment_digest,
            node,
            lease_generation,
            lease_digest,
            receipt_authority: receipt.authority().clone(),
            receipt_action: receipt.action(),
            receipt_request_id: *receipt.request_id(),
            receipt_claim_digest: receipt.claim_digest(),
            source_draft_digest,
            digest,
            bytes: publication,
        },
        lease: recovered.lease,
        templates: recovered.templates,
    })
}

pub(super) fn decode_prepared(
    bytes: &[u8],
    expected_digest: ObjectDigest,
) -> Result<PreparedAuthorityPublicationV1, AuthorityPublicationError> {
    if bytes.starts_with(LEGACY_V1_MAGIC) || bytes.starts_with(LEGACY_V2_MAGIC) {
        return Err(AuthorityPublicationError::MigrationRequired);
    }
    if bytes.len() > MAXIMUM_PUBLICATION_BYTES
        || bytes.len() < 10
        || &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || publication_digest(bytes) != expected_digest
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let mut cursor = 10;
    let manifest_bytes = take_bytes(bytes, &mut cursor)?;
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        DecodeLimits::default(),
    )
    .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let lease_bytes = take_bytes(bytes, &mut cursor)?;
    let lease = decode_ownership_lease(lease_bytes, DecodeLimits::default())
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let lease_media = aos_sandbox_core::MediaType::new(
        aos_sandbox_core::PortableMediaType::OwnershipLease
            .as_str()
            .to_owned(),
    )
    .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let lease_digest = descriptor_for_bytes(lease_media, lease_bytes).digest();
    let sandbox = manifest.manifest().sandbox();
    let incarnation = *manifest.manifest().incarnation().as_bytes();
    let epoch = manifest.manifest().epoch().get();
    let desired_generation = manifest.manifest().desired_generation().get();
    let assignment_digest = manifest.digest();
    let node = *manifest.manifest().node().as_bytes();
    let lease_generation = lease.lease_generation();
    let recovered = validate_encoded_publication(
        bytes,
        sandbox,
        incarnation,
        epoch,
        desired_generation,
        assignment_digest,
        node,
        lease_generation,
        lease_digest,
    )?;
    let source_draft_digest = derive_source_draft_digest(bytes, &recovered.templates)?;
    let receipt =
        OwnershipTransactionReceiptV1::from_canonical_bytes(recovered.lease.canonical_receipt())
            .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    Ok(PreparedAuthorityPublicationV1 {
        sandbox,
        incarnation,
        epoch,
        desired_generation,
        assignment_digest,
        node,
        lease_generation,
        lease_digest,
        receipt_authority: receipt.authority().clone(),
        receipt_action: receipt.action(),
        receipt_request_id: *receipt.request_id(),
        receipt_claim_digest: receipt.claim_digest(),
        source_draft_digest,
        digest: expected_digest,
        bytes: bytes.to_vec(),
    })
}

fn derive_source_draft_digest(
    publication: &[u8],
    templates: &[RecoveredBrokerDispatchTemplateV1],
) -> Result<ObjectDigest, AuthorityPublicationError> {
    let mut cursor = 10;
    let manifest_bytes = take_bytes(publication, &mut cursor)?;
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        DecodeLimits::default(),
    )
    .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    for _ in 0..4 {
        take_bytes(publication, &mut cursor)?;
    }
    let audience_count = take_u32(publication, &mut cursor)?;
    let audience_bytes = take(publication, &mut cursor, audience_count)?;
    let audiences = audience_bytes
        .iter()
        .copied()
        .map(audience_from_code)
        .collect::<Result<Vec<_>, _>>()?;
    let draft = encode_recovered_draft(&manifest, &audiences, templates)?;
    Ok(draft_digest(&draft))
}

// Keeping every independently persisted summary field visible here makes the
// replay cross-link audit harder to accidentally weaken when the format grows.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_encoded_publication(
    bytes: &[u8],
    sandbox: SandboxId,
    incarnation: [u8; 16],
    epoch: u64,
    desired_generation: u64,
    assignment_digest: ObjectDigest,
    node: [u8; 16],
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<RecoveredPublicationArtifactsV1, AuthorityPublicationError> {
    if bytes.len() < 10 || &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_be_bytes() {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let mut cursor = 10;
    let manifest_bytes = take_bytes(bytes, &mut cursor)?;
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        DecodeLimits::default(),
    )
    .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    if manifest.manifest().sandbox() != sandbox
        || manifest.manifest().incarnation().as_bytes() != &incarnation
        || manifest.manifest().epoch().get() != epoch
        || manifest.manifest().desired_generation().get() != desired_generation
        || manifest.manifest().node().as_bytes() != &node
        || manifest.digest() != assignment_digest
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let lease_bytes = take_bytes(bytes, &mut cursor)?;
    let lease = decode_ownership_lease(lease_bytes, DecodeLimits::default())
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let media = aos_sandbox_core::MediaType::new(
        aos_sandbox_core::PortableMediaType::OwnershipLease
            .as_str()
            .to_owned(),
    )
    .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let lease_descriptor = descriptor_for_bytes(media, lease_bytes);
    if lease_descriptor.digest() != lease_digest
        || lease.assignment().digest() != assignment_digest
        || lease.assignment().sandbox() != sandbox
        || lease.assignment().incarnation().as_bytes() != &incarnation
        || lease.assignment().epoch().get() != epoch
        || lease.node().as_bytes() != &node
        || lease.lease_generation() != lease_generation
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let signature_bytes = take_bytes(bytes, &mut cursor)?;
    let signature = decode_signature(signature_bytes, DecodeLimits::default())
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    if encode_signature(&signature) != signature_bytes
        || signature.statement().subject() != &lease_descriptor
        || signature.statement().purpose() != SignaturePurpose::OwnershipLease
        || signature.statement().issued_seconds() != lease.authority_issued_seconds()
        || signature.statement().expires_seconds() != Some(lease.authority_expires_seconds())
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let receipt_bytes = take_bytes(bytes, &mut cursor)?;
    let receipt = OwnershipTransactionReceiptV1::from_canonical_bytes(receipt_bytes)
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    if receipt.authority() != signature.statement().signer()
        || receipt.lease_descriptor() != &lease_descriptor
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let receipt_signature_bytes = take_bytes(bytes, &mut cursor)?;
    let receipt_signature = decode_signature(receipt_signature_bytes, DecodeLimits::default())
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let receipt_media = aos_sandbox_core::MediaType::new(
        aos_sandbox_core::PortableMediaType::OwnershipTransactionReceipt
            .as_str()
            .to_owned(),
    )
    .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let receipt_descriptor = descriptor_for_bytes(receipt_media, receipt_bytes);
    if encode_signature(&receipt_signature) != receipt_signature_bytes
        || receipt_signature.statement().subject() != &receipt_descriptor
        || receipt_signature.statement().purpose() != SignaturePurpose::OwnershipLease
        || receipt_signature.statement().signer() != receipt.authority()
        || receipt_signature.statement().trust_scope() != signature.statement().trust_scope()
        || receipt_signature.statement().verification_policy()
            != signature.statement().verification_policy()
        || receipt_signature.statement().issued_seconds() != lease.authority_issued_seconds()
        || receipt_signature.statement().expires_seconds()
            != Some(lease.authority_expires_seconds())
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let recovered_lease = RecoveredOwnershipLeaseV1 {
        lease,
        canonical_lease: lease_bytes.to_vec(),
        canonical_signature: signature_bytes.to_vec(),
        canonical_receipt: receipt_bytes.to_vec(),
        canonical_receipt_signature: receipt_signature_bytes.to_vec(),
        digest: lease_digest,
    };
    let required = take_u32(bytes, &mut cursor)?;
    if required == 0 || required > 4 {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let audiences = take(bytes, &mut cursor, required)?;
    if audiences.iter().any(|code| !(1..=4).contains(code))
        || audiences.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let templates = take_u32(bytes, &mut cursor)?;
    if templates == 0 || templates > MAXIMUM_TEMPLATES {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    let assignment = manifest
        .broker_assignment()
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
    let mut plans: BTreeMap<u8, (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    let mut recovered_templates = Vec::with_capacity(templates);
    for _ in 0..templates {
        let stored_template_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let audience = *take(bytes, &mut cursor, 1)?
            .first()
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        if !audiences.contains(&audience) {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let plan_bytes = take_bytes(bytes, &mut cursor)?;
        let plan = decode_broker_authorization_plan(plan_bytes, DecodeLimits::default())
            .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
        let plan_signature = take_bytes(bytes, &mut cursor)?;
        let decoded = decode_signature(plan_signature, DecodeLimits::default())
            .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
        let plan_media = aos_sandbox_core::MediaType::new(
            aos_sandbox_core::PortableMediaType::BrokerAuthorizationPlan
                .as_str()
                .to_owned(),
        )
        .map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
        let plan_descriptor = descriptor_for_bytes(plan_media, plan_bytes);
        if encode_signature(&decoded) != plan_signature
            || decoded.statement().subject() != &plan_descriptor
            || decoded.statement().purpose() != SignaturePurpose::BrokerAuthorization
            || decoded.statement().issued_seconds() != plan.issued_seconds()
            || decoded.statement().expires_seconds() != Some(plan.expires_seconds())
            || audience_code(plan.audience()) != audience
            || plan.assignment() != assignment
            || plan.node().as_bytes() != &node
            || plan.ownership_authority() != signature.statement().signer()
        {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        match plans.get(&audience) {
            Some((prior_plan, prior_signature))
                if prior_plan != plan_bytes || prior_signature != plan_signature =>
            {
                return Err(AuthorityPublicationError::CorruptCurrent);
            }
            None => {
                plans.insert(audience, (plan_bytes.to_vec(), plan_signature.to_vec()));
            }
            _ => {}
        }
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        if !matches!((audience, method_code), (1, 1) | (2, 4) | (3, 7) | (4, 9)) {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let method = broker_method_from_code(method_code)?;
        let body = take_bytes(bytes, &mut cursor)?;
        if !crate::dispatch::validate_durable_deadline_free_body(body) {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let roles = take_u32(bytes, &mut cursor)?;
        if roles > 16 {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let mut role_codes = Vec::with_capacity(roles);
        let mut descriptor_roles = Vec::with_capacity(roles);
        for _ in 0..roles {
            let role = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
            if !(1..=7).contains(&role) || role_codes.contains(&role) {
                return Err(AuthorityPublicationError::CorruptCurrent);
            }
            role_codes.push(role);
            descriptor_roles.push(broker_descriptor_role_from_code(role)?);
        }
        let verb = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let target_start = cursor;
        let target = *take(bytes, &mut cursor, 1)?
            .first()
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        take(
            bytes,
            &mut cursor,
            match target {
                1 => 0,
                2 => 32,
                3 => 64,
                _ => return Err(AuthorityPublicationError::CorruptCurrent),
            },
        )?;
        let target_bytes = &bytes[target_start..cursor];
        let commitment = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let maximum_body = body
            .len()
            .checked_add(11)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(AuthorityPublicationError::CorruptCurrent)?;
        let descriptor_count =
            u16::try_from(roles).map_err(|_| AuthorityPublicationError::CorruptCurrent)?;
        let matching_grant = plan.grants().iter().find(|grant| {
            let mut encoded_target = Vec::new();
            encode_target(&mut encoded_target, grant.target());
            grant.verb().get() == verb
                && encoded_target == target_bytes
                && grant.argument_commitment().digest() == commitment
                && maximum_body <= grant.maximum_request_bytes()
                && descriptor_count <= grant.maximum_descriptors()
        });
        if matching_grant.is_none()
            || durable_template_digest(
                plan_descriptor.digest(),
                plan_signature,
                method_code,
                body,
                &role_codes,
                verb,
                target_bytes,
                commitment,
            ) != stored_template_digest
        {
            return Err(AuthorityPublicationError::CorruptCurrent);
        }
        let grant = matching_grant.ok_or(AuthorityPublicationError::CorruptCurrent)?;
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            grant.verb(),
            grant.target(),
            grant.argument_commitment(),
        );
        recovered_templates.push(RecoveredBrokerDispatchTemplateV1 {
            digest: stored_template_digest,
            audience: audience_from_code(audience)?,
            plan,
            canonical_plan: plan_bytes.to_vec(),
            canonical_plan_signature: plan_signature.to_vec(),
            method,
            body_without_deadline: body.to_vec(),
            descriptor_roles,
            semantics,
        });
    }
    if cursor != bytes.len() || plans.len() != audiences.len() {
        return Err(AuthorityPublicationError::CorruptCurrent);
    }
    Ok(RecoveredPublicationArtifactsV1 {
        lease: recovered_lease,
        templates: recovered_templates,
    })
}
