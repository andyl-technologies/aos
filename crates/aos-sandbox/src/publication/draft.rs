//! Canonical lease-independent authority draft validation and encoding.
//!
//! The bounded controller-local format is:
//!
//! ```text
//! magic | version | manifest | audiences | canonical template sequence
//! ```

use super::*;

pub(super) fn validate_draft(
    manifest: &CanonicalAssignmentManifestV1,
    required_audiences: &[BrokerAudience],
    templates: &[BrokerDispatchTemplateV1],
) -> Result<aos_sandbox_core::model::KeyReference, AuthorityPublicationError> {
    if required_audiences.is_empty()
        || required_audiences.len() > 4
        || templates.is_empty()
        || templates.len() > MAXIMUM_TEMPLATES
        || !strictly_increasing(required_audiences)
    {
        return Err(AuthorityPublicationError::IncompleteAudienceSet);
    }
    let assignment = manifest
        .broker_assignment()
        .map_err(|_| AuthorityPublicationError::ContextMismatch)?;
    let first = templates
        .first()
        .ok_or(AuthorityPublicationError::IncompleteAudienceSet)?;
    let ownership_authority = first.signed_plan().plan().ownership_authority().clone();
    let mut plans: BTreeMap<BrokerAudience, (ObjectDigest, &[u8])> = BTreeMap::new();
    let mut prior_order = None;
    for template in templates {
        let plan = template.signed_plan().plan();
        let order = (audience_code(plan.audience()), template.digest());
        if plan.assignment() != assignment
            || plan.node() != manifest.manifest().node()
            || plan.ownership_authority() != &ownership_authority
            || !required_audiences.contains(&plan.audience())
            || prior_order.is_some_and(|prior| prior >= order)
        {
            return Err(AuthorityPublicationError::ContextMismatch);
        }
        prior_order = Some(order);
        match plans.get(&plan.audience()) {
            Some((digest, signature))
                if *digest != template.signed_plan().digest()
                    || *signature != template.signed_plan().canonical_signature() =>
            {
                return Err(AuthorityPublicationError::ContextMismatch);
            }
            None => {
                plans.insert(
                    plan.audience(),
                    (
                        template.signed_plan().digest(),
                        template.signed_plan().canonical_signature(),
                    ),
                );
            }
            _ => {}
        }
    }
    if plans.len() != required_audiences.len()
        || required_audiences
            .iter()
            .any(|audience| !plans.contains_key(audience))
    {
        return Err(AuthorityPublicationError::IncompleteAudienceSet);
    }
    Ok(ownership_authority)
}

pub(super) fn encode_draft(
    manifest: &CanonicalAssignmentManifestV1,
    required_audiences: &[BrokerAudience],
    templates: &[BrokerDispatchTemplateV1],
) -> Result<Vec<u8>, AuthorityPublicationError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DRAFT_MAGIC);
    bytes.extend_from_slice(&DRAFT_VERSION.to_be_bytes());
    put_bytes(&mut bytes, manifest.canonical_bytes())?;
    put_u32(&mut bytes, required_audiences.len())?;
    for audience in required_audiences {
        bytes.push(audience_code(*audience));
    }
    put_u32(&mut bytes, templates.len())?;
    for template in templates {
        bytes.extend_from_slice(template.digest().as_bytes());
        bytes.push(audience_code(template.signed_plan().plan().audience()));
        put_bytes(&mut bytes, template.signed_plan().canonical_plan())?;
        put_bytes(&mut bytes, template.signed_plan().canonical_signature())?;
        bytes.extend_from_slice(&(template.method() as i32).to_be_bytes());
        put_bytes(&mut bytes, template.body_without_deadline())?;
        put_u32(&mut bytes, template.descriptor_roles().len())?;
        for role in template.descriptor_roles() {
            bytes.extend_from_slice(&(*role as i32).to_be_bytes());
        }
        bytes.extend_from_slice(&template.semantics().verb().get().to_be_bytes());
        encode_target(&mut bytes, template.semantics().target());
        bytes.extend_from_slice(
            template
                .semantics()
                .argument_commitment()
                .digest()
                .as_bytes(),
        );
        if bytes.len() > MAXIMUM_PUBLICATION_DRAFT_BYTES {
            return Err(AuthorityPublicationError::PublicationTooLarge);
        }
    }
    Ok(bytes)
}

pub(super) fn encode_recovered_draft(
    manifest: &CanonicalAssignmentManifestV1,
    required_audiences: &[BrokerAudience],
    templates: &[RecoveredBrokerDispatchTemplateV1],
) -> Result<Vec<u8>, AuthorityPublicationError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DRAFT_MAGIC);
    bytes.extend_from_slice(&DRAFT_VERSION.to_be_bytes());
    put_bytes(&mut bytes, manifest.canonical_bytes())?;
    put_u32(&mut bytes, required_audiences.len())?;
    for audience in required_audiences {
        bytes.push(audience_code(*audience));
    }
    encode_recovered_templates(&mut bytes, templates)?;
    Ok(bytes)
}

fn encode_recovered_templates(
    bytes: &mut Vec<u8>,
    templates: &[RecoveredBrokerDispatchTemplateV1],
) -> Result<(), AuthorityPublicationError> {
    put_u32(bytes, templates.len())?;
    for template in templates {
        bytes.extend_from_slice(template.digest.as_bytes());
        bytes.push(audience_code(template.audience));
        put_bytes(bytes, &template.canonical_plan)?;
        put_bytes(bytes, &template.canonical_plan_signature)?;
        bytes.extend_from_slice(&(template.method as i32).to_be_bytes());
        put_bytes(bytes, &template.body_without_deadline)?;
        put_u32(bytes, template.descriptor_roles.len())?;
        for role in &template.descriptor_roles {
            bytes.extend_from_slice(&(*role as i32).to_be_bytes());
        }
        bytes.extend_from_slice(&template.semantics.verb().get().to_be_bytes());
        encode_target(bytes, template.semantics.target());
        bytes.extend_from_slice(template.semantics.argument_commitment().digest().as_bytes());
        if bytes.len() > MAXIMUM_PUBLICATION_DRAFT_BYTES {
            return Err(AuthorityPublicationError::PublicationTooLarge);
        }
    }
    Ok(())
}

pub(super) fn encode_bound_draft(
    draft: &AuthorityPublicationDraftV1,
    lease: &SignedOwnershipLease,
) -> Result<Vec<u8>, AuthorityPublicationError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    put_bytes(&mut bytes, draft.manifest.canonical_bytes())?;
    put_bytes(&mut bytes, lease.canonical_lease())?;
    put_bytes(&mut bytes, lease.canonical_signature())?;
    put_bytes(&mut bytes, lease.canonical_receipt())?;
    put_bytes(&mut bytes, lease.canonical_receipt_signature())?;
    put_u32(&mut bytes, draft.required_audiences.len())?;
    for audience in &draft.required_audiences {
        bytes.push(audience_code(*audience));
    }
    encode_recovered_templates(&mut bytes, &draft.templates)?;
    Ok(bytes)
}

pub(super) fn decode_draft(
    bytes: &[u8],
) -> Result<AuthorityPublicationDraftV1, AuthorityPublicationError> {
    if bytes.len() < 18
        || bytes.len() > MAXIMUM_PUBLICATION_DRAFT_BYTES
        || &bytes[..8] != DRAFT_MAGIC
        || bytes[8..10] != DRAFT_VERSION.to_be_bytes()
    {
        return Err(AuthorityPublicationError::InvalidDraft);
    }
    let mut cursor = 10;
    let manifest_bytes = take_bytes(bytes, &mut cursor)?;
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        DecodeLimits::default(),
    )
    .map_err(|_| AuthorityPublicationError::InvalidDraft)?;
    let assignment = manifest
        .broker_assignment()
        .map_err(|_| AuthorityPublicationError::InvalidDraft)?;

    let audience_count = take_u32(bytes, &mut cursor)?;
    if audience_count == 0 || audience_count > 4 {
        return Err(AuthorityPublicationError::InvalidDraft);
    }
    let audience_codes = take(bytes, &mut cursor, audience_count)?;
    if audience_codes.iter().any(|code| !(1..=4).contains(code))
        || audience_codes.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(AuthorityPublicationError::InvalidDraft);
    }
    let required_audiences = audience_codes
        .iter()
        .copied()
        .map(audience_from_code)
        .collect::<Result<Vec<_>, _>>()?;
    let template_count = take_u32(bytes, &mut cursor)?;
    if template_count == 0 || template_count > MAXIMUM_TEMPLATES {
        return Err(AuthorityPublicationError::InvalidDraft);
    }

    let mut ownership_authority = None;
    let mut plans: BTreeMap<BrokerAudience, (ObjectDigest, Vec<u8>)> = BTreeMap::new();
    let mut prior_order = None;
    let mut recovered_templates = Vec::with_capacity(template_count);
    for _ in 0..template_count {
        let stored_template_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let audience_code_value = *take(bytes, &mut cursor, 1)?
            .first()
            .ok_or(AuthorityPublicationError::InvalidDraft)?;
        let audience = audience_from_code(audience_code_value)?;
        if !required_audiences.contains(&audience) {
            return Err(AuthorityPublicationError::InvalidDraft);
        }

        let plan_bytes = take_bytes(bytes, &mut cursor)?;
        let plan = decode_broker_authorization_plan(plan_bytes, DecodeLimits::default())
            .map_err(|_| AuthorityPublicationError::InvalidDraft)?;
        let plan_signature = take_bytes(bytes, &mut cursor)?;
        let decoded = decode_signature(plan_signature, DecodeLimits::default())
            .map_err(|_| AuthorityPublicationError::InvalidDraft)?;
        let plan_media = aos_sandbox_core::MediaType::new(
            aos_sandbox_core::PortableMediaType::BrokerAuthorizationPlan
                .as_str()
                .to_owned(),
        )
        .map_err(|_| AuthorityPublicationError::InvalidDraft)?;
        let plan_descriptor = descriptor_for_bytes(plan_media, plan_bytes);
        if encode_signature(&decoded) != plan_signature
            || decoded.statement().subject() != &plan_descriptor
            || decoded.statement().purpose() != SignaturePurpose::BrokerAuthorization
            || decoded.statement().issued_seconds() != plan.issued_seconds()
            || decoded.statement().expires_seconds() != Some(plan.expires_seconds())
            || plan.audience() != audience
            || plan.assignment() != assignment
            || plan.node() != manifest.manifest().node()
        {
            return Err(AuthorityPublicationError::InvalidDraft);
        }
        let order = (audience_code_value, stored_template_digest);
        if prior_order.is_some_and(|prior| prior >= order) {
            return Err(AuthorityPublicationError::InvalidDraft);
        }
        prior_order = Some(order);
        match plans.get(&audience) {
            Some((digest, signature))
                if *digest != plan_descriptor.digest()
                    || signature.as_slice() != plan_signature =>
            {
                return Err(AuthorityPublicationError::InvalidDraft);
            }
            None => {
                plans.insert(
                    audience,
                    (plan_descriptor.digest(), plan_signature.to_vec()),
                );
            }
            _ => {}
        }
        match &ownership_authority {
            Some(authority) if authority != plan.ownership_authority() => {
                return Err(AuthorityPublicationError::InvalidDraft);
            }
            None => ownership_authority = Some(plan.ownership_authority().clone()),
            _ => {}
        }

        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        if !matches!(
            (audience_code_value, method_code),
            (1, 1) | (2, 4) | (3, 7) | (4, 9)
        ) {
            return Err(AuthorityPublicationError::InvalidDraft);
        }
        let method = broker_method_from_code(method_code)?;
        let body = take_bytes(bytes, &mut cursor)?;
        if !crate::dispatch::validate_durable_deadline_free_body(body) {
            return Err(AuthorityPublicationError::InvalidDraft);
        }
        let role_count = take_u32(bytes, &mut cursor)?;
        if role_count > 16 {
            return Err(AuthorityPublicationError::InvalidDraft);
        }
        let mut role_codes = Vec::with_capacity(role_count);
        let mut descriptor_roles = Vec::with_capacity(role_count);
        for _ in 0..role_count {
            let role = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
            if !(1..=7).contains(&role) || role_codes.contains(&role) {
                return Err(AuthorityPublicationError::InvalidDraft);
            }
            role_codes.push(role);
            descriptor_roles.push(broker_descriptor_role_from_code(role)?);
        }
        let verb = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let target_start = cursor;
        let target = *take(bytes, &mut cursor, 1)?
            .first()
            .ok_or(AuthorityPublicationError::InvalidDraft)?;
        take(
            bytes,
            &mut cursor,
            match target {
                1 => 0,
                2 => 32,
                3 => 64,
                _ => return Err(AuthorityPublicationError::InvalidDraft),
            },
        )?;
        let target_bytes = &bytes[target_start..cursor];
        let commitment = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let maximum_body = body
            .len()
            .checked_add(11)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(AuthorityPublicationError::InvalidDraft)?;
        let descriptor_count =
            u16::try_from(role_count).map_err(|_| AuthorityPublicationError::InvalidDraft)?;
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
            return Err(AuthorityPublicationError::InvalidDraft);
        }
        let grant = matching_grant.ok_or(AuthorityPublicationError::InvalidDraft)?;
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            grant.verb(),
            grant.target(),
            grant.argument_commitment(),
        );
        recovered_templates.push(RecoveredBrokerDispatchTemplateV1 {
            digest: stored_template_digest,
            audience,
            plan,
            canonical_plan: plan_bytes.to_vec(),
            canonical_plan_signature: plan_signature.to_vec(),
            method,
            body_without_deadline: body.to_vec(),
            descriptor_roles,
            semantics,
        });
    }
    if cursor != bytes.len()
        || plans.len() != required_audiences.len()
        || required_audiences
            .iter()
            .any(|audience| !plans.contains_key(audience))
    {
        return Err(AuthorityPublicationError::InvalidDraft);
    }
    let ownership_authority = ownership_authority.ok_or(AuthorityPublicationError::InvalidDraft)?;
    let canonical = encode_recovered_draft(&manifest, &required_audiences, &recovered_templates)?;
    if canonical != bytes {
        return Err(AuthorityPublicationError::InvalidDraft);
    }
    Ok(AuthorityPublicationDraftV1 {
        manifest,
        required_audiences,
        templates: recovered_templates,
        ownership_authority,
        digest: draft_digest(bytes),
        bytes: bytes.to_vec(),
    })
}

pub(super) fn draft_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(DRAFT_DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn validate_proposal(
    proposal: &AuthorityPublicationProposalV1,
) -> Result<(), AuthorityPublicationError> {
    if proposal.required_audiences.is_empty()
        || proposal.required_audiences.len() > 4
        || proposal.templates.is_empty()
        || proposal.templates.len() > MAXIMUM_TEMPLATES
        || !strictly_increasing(&proposal.required_audiences)
    {
        return Err(AuthorityPublicationError::IncompleteAudienceSet);
    }
    let assignment = proposal
        .manifest
        .broker_assignment()
        .map_err(|_| AuthorityPublicationError::ContextMismatch)?;
    let lease_assignment = proposal.lease.assignment();
    if assignment.sandbox() != lease_assignment.sandbox()
        || assignment.incarnation() != lease_assignment.incarnation()
        || assignment.epoch() != lease_assignment.epoch()
        || assignment.digest() != lease_assignment.digest()
        || proposal.manifest.manifest().node() != proposal.lease.node()
    {
        return Err(AuthorityPublicationError::ContextMismatch);
    }

    let mut plans: BTreeMap<BrokerAudience, (ObjectDigest, &[u8])> = BTreeMap::new();
    let mut prior_order = None;
    for template in &proposal.templates {
        let plan = template.signed_plan().plan();
        let order = (audience_code(plan.audience()), template.digest());
        if !proposal.required_audiences.contains(&plan.audience())
            || plan.assignment() != assignment
            || plan.node() != proposal.manifest.manifest().node()
            || plan.ownership_authority() != proposal.lease.signer()
            || prior_order.is_some_and(|prior| prior >= order)
        {
            return Err(AuthorityPublicationError::ContextMismatch);
        }
        prior_order = Some(order);
        match plans.get(&plan.audience()) {
            Some((digest, signature))
                if *digest != template.signed_plan().digest()
                    || *signature != template.signed_plan().canonical_signature() =>
            {
                return Err(AuthorityPublicationError::ContextMismatch);
            }
            None => {
                plans.insert(
                    plan.audience(),
                    (
                        template.signed_plan().digest(),
                        template.signed_plan().canonical_signature(),
                    ),
                );
            }
            _ => {}
        }
    }
    if plans.len() != proposal.required_audiences.len()
        || proposal
            .required_audiences
            .iter()
            .any(|audience| !plans.contains_key(audience))
    {
        return Err(AuthorityPublicationError::IncompleteAudienceSet);
    }
    Ok(())
}

pub(super) fn encode_proposal(
    proposal: &AuthorityPublicationProposalV1,
) -> Result<Vec<u8>, AuthorityPublicationError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    put_bytes(&mut bytes, proposal.manifest.canonical_bytes())?;
    put_bytes(&mut bytes, proposal.lease.canonical_lease())?;
    put_bytes(&mut bytes, proposal.lease.canonical_signature())?;
    put_bytes(&mut bytes, proposal.lease.canonical_receipt())?;
    put_bytes(&mut bytes, proposal.lease.canonical_receipt_signature())?;
    put_u32(&mut bytes, proposal.required_audiences.len())?;
    for audience in &proposal.required_audiences {
        bytes.push(audience_code(*audience));
    }
    put_u32(&mut bytes, proposal.templates.len())?;
    for template in &proposal.templates {
        bytes.extend_from_slice(template.digest().as_bytes());
        bytes.push(audience_code(template.signed_plan().plan().audience()));
        put_bytes(&mut bytes, template.signed_plan().canonical_plan())?;
        put_bytes(&mut bytes, template.signed_plan().canonical_signature())?;
        bytes.extend_from_slice(&(template.method() as i32).to_be_bytes());
        put_bytes(&mut bytes, template.body_without_deadline())?;
        put_u32(&mut bytes, template.descriptor_roles().len())?;
        for role in template.descriptor_roles() {
            bytes.extend_from_slice(&(*role as i32).to_be_bytes());
        }
        bytes.extend_from_slice(&template.semantics().verb().get().to_be_bytes());
        encode_target(&mut bytes, template.semantics().target());
        bytes.extend_from_slice(
            template
                .semantics()
                .argument_commitment()
                .digest()
                .as_bytes(),
        );
    }
    Ok(bytes)
}

pub(super) fn validate_encoded_size(
    proposal: &AuthorityPublicationProposalV1,
) -> Result<(), AuthorityPublicationError> {
    let mut size = 64_usize
        .checked_add(proposal.manifest.canonical_bytes().len())
        .and_then(|value| value.checked_add(proposal.lease.canonical_lease().len()))
        .and_then(|value| value.checked_add(proposal.lease.canonical_signature().len()))
        .and_then(|value| value.checked_add(proposal.lease.canonical_receipt().len()))
        .and_then(|value| value.checked_add(proposal.lease.canonical_receipt_signature().len()))
        .ok_or(AuthorityPublicationError::PublicationTooLarge)?;
    for template in &proposal.templates {
        size = size
            .checked_add(128)
            .and_then(|value| value.checked_add(template.signed_plan().canonical_plan().len()))
            .and_then(|value| value.checked_add(template.signed_plan().canonical_signature().len()))
            .and_then(|value| value.checked_add(template.body_without_deadline().len()))
            .and_then(|value| value.checked_add(template.descriptor_roles().len() * 4))
            .ok_or(AuthorityPublicationError::PublicationTooLarge)?;
        if size > MAXIMUM_PUBLICATION_BYTES {
            return Err(AuthorityPublicationError::PublicationTooLarge);
        }
    }
    Ok(())
}

pub(super) fn encode_target(bytes: &mut Vec<u8>, target: aos_sandbox_core::BrokerGrantTarget) {
    match target {
        aos_sandbox_core::BrokerGrantTarget::Assignment => bytes.push(1),
        aos_sandbox_core::BrokerGrantTarget::Resource(handle) => {
            bytes.push(2);
            bytes.extend_from_slice(handle.as_bytes());
        }
        aos_sandbox_core::BrokerGrantTarget::ResourcePair {
            previous,
            successor,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(previous.as_bytes());
            bytes.extend_from_slice(successor.as_bytes());
        }
    }
}
