//! Owns the sole bounded V1 prepared/current codec and structural recovery engine.
//!
//! The Native Journal owner uses these DATA encodings in its isolated namespace:
//!
//! ```text
//! prepared/<digest> = complete AOSCPUB1 publication bytes
//! current/<sandbox> = AOSCPUB1 | version:u16 | sandbox:16 | incarnation:16
//!                    | epoch:u64 | desired-generation:u64 | assignment-digest:32
//!                    | node:16 | lease-generation:u64 | lease-digest:32
//!                    | publication-digest:32 | publication-length:u64 | publication
//! ```
//!
//! Fixed integers are big-endian; the current envelope header occupies 186 bytes.
//! Recovery retains the complete canonical bytes and decoded artifacts, checking
//! their digests and cross-links without signature verification, Journal selection
//! or construction of an accepted Native publication identity.

use super::*;

/// Returns the exact current-envelope width around a prepared publication.
///
/// This is format DATA only; it neither decodes nor selects a publication.
/// `None` reports checked length overflow.
#[must_use]
pub fn current_publication_encoded_bytes_v1(publication_bytes: usize) -> Option<usize> {
    CURRENT_HEADER_BYTES.checked_add(publication_bytes)
}

/// Encodes a history as a current-record envelope with its fixed metadata header.
///
/// The encoded name does not establish currentness; the Native Journal owner
/// controls whether this record becomes selected.
pub fn encode_current(prepared: &PublicationHistoryV1) -> Vec<u8> {
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

/// Decodes a bounded current envelope and its complete structural publication.
///
/// The result retains the history, recovered lease and templates from this decode.
/// No signature or present Journal selection is authenticated.
///
/// # Errors
///
/// Returns [`PublicationHistoryError`] for invalid framing, length or version,
/// digest mismatches, unsupported encoded values or inconsistent canonical
/// publication cross-links.
pub fn decode_current(
    bytes: &[u8],
) -> Result<DecodedPublicationCurrentV1, PublicationHistoryError> {
    if bytes.len() < CURRENT_HEADER_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
    {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let mut reader = publication_reader(bytes)?;
    let sandbox = SandboxId::from_bytes(reader.array()?);
    let incarnation = reader.array()?;
    let epoch = reader.u64()?;
    let desired_generation = reader.u64()?;
    let assignment_digest = ObjectDigest::from_bytes(reader.array()?);
    let node = reader.array()?;
    let lease_generation = reader.u64()?;
    let lease_digest = ObjectDigest::from_bytes(reader.array()?);
    let digest = ObjectDigest::from_bytes(reader.array()?);
    let length =
        usize::try_from(reader.u64()?).map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    if length > MAXIMUM_PUBLICATION_BYTES || length != reader.remaining() {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let publication = reader.remaining_bytes().to_vec();
    if publication_digest(&publication) != digest {
        return Err(PublicationHistoryError::CorruptCurrent);
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
            .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    Ok(DecodedPublicationCurrentV1 {
        history: PublicationHistoryV1 {
            manifest: recovered.manifest,
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

/// Decodes complete prepared bytes with an expected publication digest.
///
/// The returned history is structural DATA, without currentness or Native acceptance.
///
/// # Errors
///
/// Returns [`PublicationHistoryError`] for malformed or oversized encodings,
/// digest mismatches or inconsistent canonical publication cross-links.
pub fn decode_prepared(
    bytes: &[u8],
    expected_digest: ObjectDigest,
) -> Result<PublicationHistoryV1, PublicationHistoryError> {
    decode_prepared_with_artifacts(bytes, expected_digest).map(|(prepared, _)| prepared)
}

/// Decodes a prepared history and retains the artifacts from that same complete pass.
///
/// The returned artifacts own the decoded manifest, lease and templates. Their
/// borrowed accessors neither clone nor reparse them. Structural validation does
/// not verify signatures or construct an accepted Native publication identity.
///
/// # Errors
///
/// Returns [`PublicationHistoryError`] for malformed or oversized encodings,
/// digest mismatches or inconsistent canonical publication cross-links.
pub fn decode_prepared_with_artifacts(
    bytes: &[u8],
    expected_digest: ObjectDigest,
) -> Result<(PublicationHistoryV1, RecoveredPublicationArtifactsV1), PublicationHistoryError> {
    if bytes.len() > MAXIMUM_PUBLICATION_BYTES
        || bytes.len() < 10
        || &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || publication_digest(bytes) != expected_digest
    {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let mut reader = publication_reader(bytes)?;
    let manifest_bytes = read_bytes(&mut reader)?;
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        DecodeLimits::default(),
    )
    .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    let lease_bytes = read_bytes(&mut reader)?;
    let lease = decode_ownership_lease(lease_bytes, DecodeLimits::default())
        .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    let lease_media = aos_sandbox_model::MediaType::new(
        aos_sandbox_model::PortableMediaType::OwnershipLease
            .as_str()
            .to_owned(),
    )
    .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
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
            .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    let prepared = PublicationHistoryV1 {
        manifest,
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
    };
    Ok((prepared, recovered))
}

fn derive_source_draft_digest(
    publication: &[u8],
    templates: &[RecoveredBrokerDispatchTemplateV1],
) -> Result<ObjectDigest, PublicationHistoryError> {
    let mut reader = publication_reader(publication)?;
    let manifest_bytes = read_bytes(&mut reader)?;
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        DecodeLimits::default(),
    )
    .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    for _ in 0..4 {
        read_bytes(&mut reader)?;
    }
    let audience_count = read_count(&mut reader)?;
    let audience_bytes = reader.bytes(audience_count)?;
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
) -> Result<RecoveredPublicationArtifactsV1, PublicationHistoryError> {
    if bytes.len() < 10 || &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_be_bytes() {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let mut reader = publication_reader(bytes)?;
    let manifest_bytes = read_bytes(&mut reader)?;
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        DecodeLimits::default(),
    )
    .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    if manifest.manifest().sandbox() != sandbox
        || manifest.manifest().incarnation().as_bytes() != &incarnation
        || manifest.manifest().epoch().get() != epoch
        || manifest.manifest().desired_generation().get() != desired_generation
        || manifest.manifest().node().as_bytes() != &node
        || manifest.digest() != assignment_digest
    {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let lease_bytes = read_bytes(&mut reader)?;
    let lease = decode_ownership_lease(lease_bytes, DecodeLimits::default())
        .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    let media = aos_sandbox_model::MediaType::new(
        aos_sandbox_model::PortableMediaType::OwnershipLease
            .as_str()
            .to_owned(),
    )
    .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    let lease_descriptor = descriptor_for_bytes(media, lease_bytes);
    if lease_descriptor.digest() != lease_digest
        || lease.assignment().digest() != assignment_digest
        || lease.assignment().sandbox() != sandbox
        || lease.assignment().incarnation().as_bytes() != &incarnation
        || lease.assignment().epoch().get() != epoch
        || lease.node().as_bytes() != &node
        || lease.lease_generation() != lease_generation
    {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let signature_bytes = read_bytes(&mut reader)?;
    let signature = decode_signature(signature_bytes, DecodeLimits::default())
        .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    if encode_signature(&signature) != signature_bytes
        || signature.statement().subject() != &lease_descriptor
        || signature.statement().purpose() != SignaturePurpose::OwnershipLease
        || signature.statement().issued_seconds() != lease.authority_issued_seconds()
        || signature.statement().expires_seconds() != Some(lease.authority_expires_seconds())
    {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let receipt_bytes = read_bytes(&mut reader)?;
    let receipt = OwnershipTransactionReceiptV1::from_canonical_bytes(receipt_bytes)
        .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    if receipt.authority() != signature.statement().signer()
        || receipt.lease_descriptor() != &lease_descriptor
    {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let receipt_signature_bytes = read_bytes(&mut reader)?;
    let receipt_signature = decode_signature(receipt_signature_bytes, DecodeLimits::default())
        .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    let receipt_media = aos_sandbox_model::MediaType::new(
        aos_sandbox_model::PortableMediaType::OwnershipTransactionReceipt
            .as_str()
            .to_owned(),
    )
    .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
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
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let recovered_lease = RecoveredOwnershipLeaseV1 {
        lease,
        canonical_lease: lease_bytes.to_vec(),
        canonical_signature: signature_bytes.to_vec(),
        canonical_receipt: receipt_bytes.to_vec(),
        canonical_receipt_signature: receipt_signature_bytes.to_vec(),
        digest: lease_digest,
    };
    let required = read_count(&mut reader)?;
    if required == 0 || required > 4 {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let audiences = reader.bytes(required)?;
    if audiences.iter().any(|code| !(1..=4).contains(code))
        || audiences.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let templates = read_count(&mut reader)?;
    if templates == 0 || templates > MAXIMUM_TEMPLATES {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    let assignment = manifest
        .broker_assignment()
        .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    let mut plans: BTreeMap<u8, (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    let mut recovered_templates = Vec::with_capacity(templates);
    for _ in 0..templates {
        let stored_template_digest = ObjectDigest::from_bytes(reader.array()?);
        let audience = reader.u8()?;
        if !audiences.contains(&audience) {
            return Err(PublicationHistoryError::CorruptCurrent);
        }
        let plan_bytes = read_bytes(&mut reader)?;
        let plan = decode_broker_authorization_plan(plan_bytes, DecodeLimits::default())
            .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
        let plan_signature = read_bytes(&mut reader)?;
        let decoded = decode_signature(plan_signature, DecodeLimits::default())
            .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
        let plan_media = aos_sandbox_model::MediaType::new(
            aos_sandbox_model::PortableMediaType::BrokerAuthorizationPlan
                .as_str()
                .to_owned(),
        )
        .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
        let plan_descriptor = descriptor_for_bytes(plan_media, plan_bytes);
        if encode_signature(&decoded) != plan_signature
            || decoded.statement().subject() != &plan_descriptor
            || decoded.statement().purpose() != SignaturePurpose::BrokerAuthorization
            || decoded.statement().issued_seconds() != plan.issued_seconds()
            || decoded.statement().expires_seconds() != Some(plan.expires_seconds())
            || audience_code(plan.audience())? != audience
            || plan.assignment() != assignment
            || plan.node().as_bytes() != &node
            || plan.ownership_authority() != signature.statement().signer()
        {
            return Err(PublicationHistoryError::CorruptCurrent);
        }
        match plans.get(&audience) {
            Some((prior_plan, prior_signature))
                if prior_plan != plan_bytes || prior_signature != plan_signature =>
            {
                return Err(PublicationHistoryError::CorruptCurrent);
            }
            None => {
                plans.insert(audience, (plan_bytes.to_vec(), plan_signature.to_vec()));
            }
            _ => {}
        }
        let method_code = i32::from_be_bytes(reader.array()?);
        if !matches!((audience, method_code), (1, 1) | (2, 4) | (3, 7) | (4, 9)) {
            return Err(PublicationHistoryError::CorruptCurrent);
        }
        let method = broker_method_from_code(method_code)?;
        let body = read_bytes(&mut reader)?;
        if !crate::dispatch_template::validate_durable_deadline_free_body(body) {
            return Err(PublicationHistoryError::CorruptCurrent);
        }
        let roles = read_count(&mut reader)?;
        if roles > 16 {
            return Err(PublicationHistoryError::CorruptCurrent);
        }
        let mut role_codes = Vec::with_capacity(roles);
        let mut descriptor_roles = Vec::with_capacity(roles);
        for _ in 0..roles {
            let role = i32::from_be_bytes(reader.array()?);
            if !(1..=7).contains(&role) || role_codes.contains(&role) {
                return Err(PublicationHistoryError::CorruptCurrent);
            }
            role_codes.push(role);
            descriptor_roles.push(broker_descriptor_role_from_code(role)?);
        }
        let verb = reader.u32()?;
        let target_start = bytes.len() - reader.remaining();
        let target = reader.u8()?;
        reader.bytes(match target {
            1 => 0,
            2 => 32,
            3 => 64,
            _ => return Err(PublicationHistoryError::CorruptCurrent),
        })?;
        let target_bytes = &bytes[target_start..bytes.len() - reader.remaining()];
        let commitment = ObjectDigest::from_bytes(reader.array()?);
        let maximum_body = body
            .len()
            .checked_add(11)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(PublicationHistoryError::CorruptCurrent)?;
        let descriptor_count =
            u16::try_from(roles).map_err(|_| PublicationHistoryError::CorruptCurrent)?;
        let matching_grant = plan.grants().iter().find(|grant| {
            let mut encoded_target = Vec::new();
            encode_target(&mut encoded_target, grant.target());
            grant.verb().get() == verb
                && encoded_target == target_bytes
                && grant.argument_commitment().digest() == commitment
                && maximum_body <= grant.maximum_request_bytes()
                && descriptor_count <= grant.maximum_descriptors()
        });
        let grant = matching_grant.ok_or(PublicationHistoryError::CorruptCurrent)?;
        // The matched grant preserves the stored hash inputs. Copying its semantic
        // identity adds no admission or allocation before the digest check.
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            grant.verb(),
            grant.target(),
            grant.argument_commitment(),
        );
        if crate::dispatch_template::template_digest_from_parts(
            plan_descriptor.digest(),
            plan_signature,
            method,
            body,
            &descriptor_roles,
            semantics,
        ) != stored_template_digest
        {
            return Err(PublicationHistoryError::CorruptCurrent);
        }
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
    if !reader.is_empty() || plans.len() != audiences.len() {
        return Err(PublicationHistoryError::CorruptCurrent);
    }
    Ok(RecoveredPublicationArtifactsV1 {
        manifest,
        lease: recovered_lease,
        templates: recovered_templates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_artifact_decode_preserves_the_old_result_and_exact_lease_preimages() {
        let (_, original) = crate::publication::tests::activation_fixture(1);
        let bytes = original.canonical_bytes();

        let old = decode_prepared(bytes, original.digest()).unwrap();
        let (prepared, artifacts) =
            decode_prepared_with_artifacts(bytes, original.digest()).unwrap();

        assert_eq!(old, original);
        assert_eq!(prepared, old);
        assert_eq!(prepared.canonical_bytes(), bytes);
        let expected = (
            artifacts.lease.canonical_lease(),
            artifacts.lease.canonical_signature(),
        );
        assert!(
            crate::publication::validate_historical_output_publication_v1(
                bytes,
                original.digest(),
                Some(expected),
            )
            .is_ok()
        );
    }

    #[test]
    fn historical_comparison_rejects_each_changed_expected_lease_preimage() {
        let (_, original) = crate::publication::tests::activation_fixture(1);
        let bytes = original.canonical_bytes();
        let (_, artifacts) = decode_prepared_with_artifacts(bytes, original.digest()).unwrap();
        let lease = artifacts.lease.canonical_lease();
        let signature = artifacts.lease.canonical_signature();
        let mut changed_lease = lease.to_vec();
        changed_lease[0] ^= 1;
        let mut changed_signature = signature.to_vec();
        changed_signature[0] ^= 1;

        let changed_preimages = [
            (changed_lease.as_slice(), signature),
            (lease, changed_signature.as_slice()),
        ];
        for expected in changed_preimages {
            assert!(matches!(
                crate::publication::validate_historical_output_publication_v1(
                    bytes,
                    original.digest(),
                    Some(expected),
                ),
                Err(PublicationHistoryError::CorruptCurrent),
            ));
        }
    }

    #[test]
    fn old_and_artifact_decoders_keep_malformed_publication_errors_even_without_a_carrier() {
        let (_, original) = crate::publication::tests::activation_fixture(1);
        let bytes = original.canonical_bytes();
        let mut reader = publication_reader(bytes).unwrap();
        let mut payload_offsets = Vec::new();
        for _ in 0..5 {
            let field = read_bytes(&mut reader).unwrap();
            payload_offsets.push(bytes.len() - reader.remaining() - field.len());
        }
        let audiences = read_count(&mut reader).unwrap();
        reader.bytes(audiences).unwrap();
        assert!(read_count(&mut reader).unwrap() > 0);
        reader.bytes(33).unwrap();
        let first_plan = read_bytes(&mut reader).unwrap();
        payload_offsets.push(bytes.len() - reader.remaining() - first_plan.len());

        for offset in [0, 8].into_iter().chain(payload_offsets) {
            let mut changed = bytes.to_vec();
            changed[offset] ^= 0xff;
            let digest = publication_digest(&changed);

            assert!(
                matches!(
                    decode_prepared(&changed, digest),
                    Err(PublicationHistoryError::CorruptCurrent)
                ),
                "old decoder accepted {offset}",
            );
            assert!(
                matches!(
                    decode_prepared_with_artifacts(&changed, digest),
                    Err(PublicationHistoryError::CorruptCurrent)
                ),
                "artifact decoder accepted {offset}",
            );
            assert!(
                matches!(
                    crate::publication::validate_historical_output_publication_v1(
                        &changed, digest, None,
                    ),
                    Err(PublicationHistoryError::CorruptCurrent)
                ),
                "carrier-free validation accepted {offset}",
            );
        }

        assert!(matches!(
            decode_prepared(bytes, ObjectDigest::from_bytes([0; 32])),
            Err(PublicationHistoryError::CorruptCurrent)
        ));
        assert!(matches!(
            decode_prepared_with_artifacts(bytes, ObjectDigest::from_bytes([0; 32])),
            Err(PublicationHistoryError::CorruptCurrent)
        ));
    }
}
