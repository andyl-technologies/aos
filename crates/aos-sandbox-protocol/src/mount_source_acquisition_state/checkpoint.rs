//! Canonical SourceProvider signed-session and attempt checkpoint validation.
//!
//! Recovery authenticates historical hello signatures against the exact raw
//! keys retained at session admission. It does not restore current authority;
//! future live transitions must present fresh protected trust again.

use aos_sandbox_source_provider_protocol::{
    AcquireSourceResponseV1, InventorySourceResponseV1, ReleaseSourceResponseV1,
    SignedSourceProviderHelloV1, SignedSourceProviderRequestV1, SignedSourceProviderStatusV1,
    SourceProviderKeyUsageV1, SourceProviderMethod, SourceProviderPeerRole,
    SourceProviderSigningKeyV1, SourceProviderStatus, decode_acquire_request,
    decode_inventory_request, decode_release_request, digest_signed_hello, digest_signed_request,
    empty_descriptor_set_commitment_v1, encode_acquire_response, encode_inventory_response,
    encode_release_response, response_result_digest_v1, source_provider_session_binding_v1,
    source_provider_signer_set_commitment_v1, verify_hello, verify_request, verify_response_status,
};
use sha2::{Digest as _, Sha256};

use super::Result;
use super::format::{
    MAXIMUM_OWNER_PREDECESSOR_WITNESS_BYTES, MAXIMUM_PROVIDER_ATTEMPT_SIGNED_BYTES,
    MAXIMUM_RESERVED_PROVIDER_ATTEMPT_BYTES, MAXIMUM_SIGNED_PROVIDER_BYTES, state_error,
};
use super::model::{
    OutcomeVerificationAnchorV2, ProviderAttemptStateV2, ProviderMethodV2, ProviderStatusV2,
    SignerRoleV2, SignerSnapshotV2, SourceProviderQueryAttemptV2, SourceProviderSessionV2,
};

const OUTCOME_VERIFICATION_ANCHOR_DOMAIN: &[u8] =
    b"aos.sandbox.source-provider.mount-outcome-verification-anchor.v2\0";

/// Computes the exact trusted verification-time commitment for one outcome.
#[must_use]
pub fn outcome_verification_anchor_digest_v2(
    anchor: &OutcomeVerificationAnchorV2,
    session_id: [u8; 32],
    attempt_id: [u8; 32],
    request_sequence: u64,
    response_sequence: u64,
    canonical_response_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OUTCOME_VERIFICATION_ANCHOR_DOMAIN);
    hasher.update(anchor.verification_started_seconds.to_be_bytes());
    hasher.update(anchor.verification_completed_seconds.to_be_bytes());
    hasher.update(anchor.kernel_boot_id);
    hasher.update(anchor.trusted_clock_evidence_digest);
    hasher.update(session_id);
    hasher.update(attempt_id);
    hasher.update(request_sequence.to_be_bytes());
    hasher.update(response_sequence.to_be_bytes());
    hasher.update(canonical_response_digest);
    hasher.finalize().into()
}

pub fn validate_session_checkpoint(session: &SourceProviderSessionV2) -> Result<()> {
    if session.signed_root_mount_hello.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
        || session.signed_provider_hello.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
    {
        return Err(state_error(
            "retained SourceProvider hello exceeds its bound",
        ));
    }
    let root = SignedSourceProviderHelloV1::from_canonical_bytes(&session.signed_root_mount_hello)
        .map_err(|_| state_error("retained Root Mount hello is invalid"))?;
    let provider =
        SignedSourceProviderHelloV1::from_canonical_bytes(&session.signed_provider_hello)
            .map_err(|_| state_error("retained provider hello is invalid"))?;

    if root.subject().role() != SourceProviderPeerRole::RootMount
        || provider.subject().role() != SourceProviderPeerRole::Provider
        || digest_signed_hello(&root).as_bytes() != &session.signed_root_mount_hello_digest
        || digest_signed_hello(&provider).as_bytes() != &session.signed_provider_hello_digest
        || source_provider_session_binding_v1(&root, &provider).as_bytes()
            != &session.session_binding
        || provider.subject().client_hello_digest() != Some(digest_signed_hello(&root))
        || root.subject().route_id() != session.scope.route_id
        || provider.subject().route_id() != session.scope.route_id
        || root.subject().route_generation() != session.route_generation
        || provider.subject().route_generation() != session.route_generation
        || root.subject().route_digest().as_bytes() != &session.route_digest
        || provider.subject().route_digest().as_bytes() != &session.route_digest
        || root.subject().process_instance() != session.root_mount_process_instance
        || provider.subject().process_instance() != session.provider_process_instance
        || root.subject().kernel_boot_id() != session.kernel_boot_id
        || provider.subject().kernel_boot_id() != session.kernel_boot_id
        || session.negotiated_capabilities.proof_class_capabilities
            != provider.subject().proof_class_capabilities()
        || provider.subject().proof_class_capabilities()
            & !root.subject().proof_class_capabilities()
            != 0
        || session.negotiated_capabilities.supports_recursive
            != provider.subject().supports_recursive()
        || session.negotiated_capabilities.supports_kernel_coupled
            != provider.subject().supports_kernel_coupled()
        || (provider.subject().supports_recursive() && !root.subject().supports_recursive())
        || (provider.subject().supports_kernel_coupled()
            && !root.subject().supports_kernel_coupled())
    {
        return Err(state_error(
            "retained SourceProvider hello graph is inconsistent",
        ));
    }

    let roles = [
        SignerRoleV2::RootMountHello,
        SignerRoleV2::RootMountRecord,
        SignerRoleV2::ProviderHello,
        SignerRoleV2::ProviderOutcome,
    ];
    if session
        .signers
        .iter()
        .zip(roles)
        .any(|(signer, role)| signer.role != role)
    {
        return Err(state_error(
            "SourceProvider signer snapshots are out of order",
        ));
    }
    validate_signer(
        &session.signers[0],
        root.signer(),
        SourceProviderKeyUsageV1::RootMountHello,
    )?;
    validate_signer(
        &session.signers[1],
        root.subject().traffic_signer(),
        SourceProviderKeyUsageV1::RootMountRecord,
    )?;
    validate_signer(
        &session.signers[2],
        provider.signer(),
        SourceProviderKeyUsageV1::ProviderHello,
    )?;
    validate_signer(
        &session.signers[3],
        provider.subject().traffic_signer(),
        SourceProviderKeyUsageV1::ProviderOutcome,
    )?;
    if root.subject().expected_peer_traffic_signer() != provider.subject().traffic_signer()
        || provider.subject().expected_peer_traffic_signer() != root.subject().traffic_signer()
        || source_provider_signer_set_commitment_v1(
            root.signer(),
            root.subject().traffic_signer(),
            provider.signer(),
            provider.subject().traffic_signer(),
        )
        .as_bytes()
            != &session.signer_set_commitment
    {
        return Err(state_error(
            "SourceProvider four-signer reciprocity is invalid",
        ));
    }
    verify_hello(&root, &session.signers[0].public_key)
        .map_err(|_| state_error("retained Root Mount hello signature is invalid"))?;
    verify_hello(&provider, &session.signers[2].public_key)
        .map_err(|_| state_error("retained provider hello signature is invalid"))?;
    Ok(())
}

pub fn validate_attempt_checkpoint(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
) -> Result<()> {
    let materialized_attempt_bytes = serde_json::to_vec(attempt)
        .map_err(|_| state_error("cannot materialize SourceProvider attempt"))?;
    let materialized_predecessor_bytes = attempt
        .owner_predecessor
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| state_error("cannot materialize provider owner predecessor"))?;
    let retained_signed_bytes = match &attempt.state {
        ProviderAttemptStateV2::DispositionConsumed {
            signed_status,
            signed_result,
            ..
        } => attempt
            .signed_request
            .len()
            .checked_add(signed_status.len())
            .and_then(|value| value.checked_add(signed_result.len())),
        ProviderAttemptStateV2::Reserved
        | ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        | ProviderAttemptStateV2::SupersededIndeterminate { .. } => {
            Some(attempt.signed_request.len())
        }
    };
    if attempt.signed_request.is_empty()
        || attempt.signed_request.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
        || retained_signed_bytes.is_none_or(|value| value > MAXIMUM_PROVIDER_ATTEMPT_SIGNED_BYTES)
        || materialized_predecessor_bytes
            .as_ref()
            .is_some_and(|value| value.len() > MAXIMUM_OWNER_PREDECESSOR_WITNESS_BYTES)
        || (matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
            && materialized_attempt_bytes.len() > MAXIMUM_RESERVED_PROVIDER_ATTEMPT_BYTES)
    {
        return Err(state_error(
            "retained SourceProvider attempt exceeds a materialization bound",
        ));
    }
    let request = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| state_error("retained SourceProvider request is invalid"))?;
    let method = protocol_method(attempt.method);
    let request_deadline_seconds = request_deadline_seconds(attempt.method, request.subject())?;
    if request.method() != method
        || digest_signed_request(&request).as_bytes() != &attempt.signed_request_digest
        || !signer_matches(&session.signers[1], request.signer())
    {
        return Err(state_error(
            "retained SourceProvider request graph is inconsistent",
        ));
    }
    verify_request(&request, &session.signers[1].public_key)
        .map_err(|_| state_error("retained SourceProvider request signature is invalid"))?;

    match &attempt.state {
        ProviderAttemptStateV2::Reserved => Ok(()),
        ProviderAttemptStateV2::DispositionConsumed {
            response_sequence,
            verification_anchor,
            status,
            signed_status,
            signed_status_digest,
            signed_result,
            signed_result_digest,
        } => {
            if signed_status.is_empty()
                || signed_status.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
                || signed_result.len() > MAXIMUM_SIGNED_PROVIDER_BYTES
            {
                return Err(state_error(
                    "retained SourceProvider disposition exceeds its bound",
                ));
            }
            let envelope = SignedSourceProviderStatusV1::from_canonical_bytes(signed_status)
                .map_err(|_| state_error("retained SourceProvider status is invalid"))?;
            let subject = envelope.subject();
            let protocol_status = protocol_status(*status);
            let canonical_response_digest =
                canonical_response_digest(attempt.method, envelope.clone(), signed_result)?;
            if subject.method() != method
                || subject.status() != protocol_status
                || subject.request_id() != attempt.request_id
                || subject.signed_request_digest().as_bytes() != &attempt.signed_request_digest
                || subject.provider_process_instance() != session.provider_process_instance
                || subject.session_binding().as_bytes() != &session.session_binding
                || subject.response_sequence() != *response_sequence
                || *response_sequence != attempt.request_sequence
                || !signer_matches(&session.signers[3], envelope.signer())
                || hash_exact(signed_status) != *signed_status_digest
                || response_result_digest_v1(
                    method,
                    protocol_status,
                    (!signed_result.is_empty()).then_some(signed_result.as_slice()),
                )
                .as_bytes()
                    != signed_result_digest
                || subject.result_digest().as_bytes() != signed_result_digest
                || verification_anchor.verification_started_seconds
                    < session.authenticated_at_seconds
                || verification_anchor.verification_completed_seconds
                    < verification_anchor.verification_started_seconds
                || verification_anchor.verification_completed_seconds >= request_deadline_seconds
                || verification_anchor.kernel_boot_id != session.kernel_boot_id
                || verification_anchor.trusted_clock_evidence_digest
                    != session.trusted_clock_evidence_digest
                || verification_anchor.anchor_digest
                    != outcome_verification_anchor_digest_v2(
                        verification_anchor,
                        session.session_id,
                        attempt.attempt_id,
                        attempt.request_sequence,
                        *response_sequence,
                        canonical_response_digest,
                    )
            {
                return Err(state_error(
                    "retained SourceProvider disposition graph is inconsistent",
                ));
            }
            verify_response_status(&envelope, &session.signers[3].public_key)
                .map_err(|_| state_error("retained SourceProvider status signature is invalid"))?;
            let complete = *status == ProviderStatusV2::Complete;
            if complete != !signed_result.is_empty() {
                return Err(state_error(
                    "SourceProvider result presence contradicts status",
                ));
            }
            if (attempt.method != ProviderMethodV2::Acquire || !complete)
                && subject.descriptor_commitment() != empty_descriptor_set_commitment_v1()
            {
                return Err(state_error(
                    "SourceProvider descriptor commitment has invalid shape",
                ));
            }
            Ok(())
        }
        ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        | ProviderAttemptStateV2::SupersededIndeterminate { .. } => Ok(()),
    }
}

fn request_deadline_seconds(method: ProviderMethodV2, subject: &[u8]) -> Result<i64> {
    match method {
        ProviderMethodV2::Acquire => decode_acquire_request(subject)
            .map(|request| request.deadline_seconds())
            .map_err(|_| state_error("retained Acquire request body is invalid")),
        ProviderMethodV2::Release => decode_release_request(subject)
            .map(|request| request.deadline_seconds())
            .map_err(|_| state_error("retained Release request body is invalid")),
        ProviderMethodV2::Inventory => decode_inventory_request(subject)
            .map(|request| request.deadline_seconds())
            .map_err(|_| state_error("retained Inventory request body is invalid")),
    }
}

fn canonical_response_digest(
    method: ProviderMethodV2,
    signed_status: SignedSourceProviderStatusV1,
    signed_result: &[u8],
) -> Result<[u8; 32]> {
    let result = (!signed_result.is_empty()).then(|| signed_result.to_vec());
    let canonical = match method {
        ProviderMethodV2::Acquire => encode_acquire_response(
            &AcquireSourceResponseV1::new(signed_status, result)
                .map_err(|_| state_error("retained Acquire response shape is invalid"))?,
        ),
        ProviderMethodV2::Release => encode_release_response(
            &ReleaseSourceResponseV1::new(signed_status, result)
                .map_err(|_| state_error("retained Release response shape is invalid"))?,
        ),
        ProviderMethodV2::Inventory => encode_inventory_response(
            &InventorySourceResponseV1::new(signed_status, result)
                .map_err(|_| state_error("retained Inventory response shape is invalid"))?,
        ),
    };
    Ok(Sha256::digest(canonical).into())
}

fn validate_signer(
    snapshot: &SignerSnapshotV2,
    signer: &SourceProviderSigningKeyV1,
    usage: SourceProviderKeyUsageV1,
) -> Result<()> {
    let fingerprint: [u8; 32] = Sha256::digest(snapshot.public_key).into();
    if snapshot.authority_id != signer.authority_id()
        || snapshot.authority_generation != signer.authority_generation()
        || snapshot.authority_digest != *signer.authority_digest().as_bytes()
        || snapshot.key_id != signer.key_id()
        || snapshot.key_generation != signer.key_generation()
        || snapshot.public_key_fingerprint != *signer.public_key_digest().as_bytes()
        || fingerprint != snapshot.public_key_fingerprint
        || signer.usage() != usage
    {
        return Err(state_error(
            "retained SourceProvider signer snapshot is inconsistent",
        ));
    }
    Ok(())
}

pub fn signer_matches(snapshot: &SignerSnapshotV2, signer: &SourceProviderSigningKeyV1) -> bool {
    snapshot.authority_id == signer.authority_id()
        && snapshot.authority_generation == signer.authority_generation()
        && snapshot.authority_digest == *signer.authority_digest().as_bytes()
        && snapshot.key_id == signer.key_id()
        && snapshot.key_generation == signer.key_generation()
        && snapshot.public_key_fingerprint == *signer.public_key_digest().as_bytes()
}

pub fn hash_exact(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub const fn protocol_method(method: ProviderMethodV2) -> SourceProviderMethod {
    match method {
        ProviderMethodV2::Acquire => SourceProviderMethod::Acquire,
        ProviderMethodV2::Release => SourceProviderMethod::Release,
        ProviderMethodV2::Inventory => SourceProviderMethod::Inventory,
    }
}

const fn protocol_status(status: ProviderStatusV2) -> SourceProviderStatus {
    match status {
        ProviderStatusV2::Complete => SourceProviderStatus::Complete,
        ProviderStatusV2::Pending => SourceProviderStatus::Pending,
        ProviderStatusV2::Rejected => SourceProviderStatus::Rejected,
        ProviderStatusV2::Unavailable => SourceProviderStatus::Unavailable,
    }
}
