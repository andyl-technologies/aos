//! Signed disposition checkpoint identity and signer validation.
//!
//! These helpers reproduce Root Mount query authority and provider receipt
//! authority from exact canonical envelopes retained by AOSMSA01.

use super::*;

pub(super) fn validate_checkpoint_provider_signer(
    checkpoint: &ProviderDispositionCheckpointV1,
    provider: SourceProviderContextSnapshotV1,
    require_current_generation: bool,
) -> Result<()> {
    let signed_status =
        SignedSourceProviderStatusV1::from_canonical_bytes(&checkpoint.signed_status)
            .map_err(|error| state_error(error.to_string()))?;
    let signer = signed_status.signer();
    if signer.authority_id() != provider.provider_authority_id
        || signer.usage() != SourceProviderKeyUsageV1::ProviderReceipt
        || require_current_generation
            && (signer.authority_generation() != provider.provider_authority_generation
                || signer.authority_digest().as_bytes() != &provider.provider_authority_digest
                || signer.key_id() != provider.provider_key_id
                || signer.key_generation() != provider.provider_key_generation
                || signer.public_key_digest().as_bytes() != &provider.provider_public_key_digest)
    {
        return Err(state_error(
            "provider disposition signer differs from its protected context",
        ));
    }
    Ok(())
}

pub(super) fn validate_checkpoint_provider_signer_against_head(
    checkpoint: &ProviderDispositionCheckpointV1,
    head: &SourceProviderHeadV1,
) -> Result<()> {
    let signed_status =
        SignedSourceProviderStatusV1::from_canonical_bytes(&checkpoint.signed_status)
            .map_err(|error| state_error(error.to_string()))?;
    let signer = signed_status.signer();
    if signer.authority_id() != head.provider_authority_id
        || signer.authority_generation() != head.provider_authority_generation
        || signer.authority_digest().as_bytes() != &head.provider_authority_digest
        || signer.key_id() != head.provider_key_id
        || signer.key_generation() != head.provider_key_generation
        || signer.public_key_digest().as_bytes() != &head.provider_public_key_digest
        || signer.usage() != SourceProviderKeyUsageV1::ProviderReceipt
    {
        return Err(state_error(
            "provider Inventory signer differs from its protected head",
        ));
    }
    Ok(())
}

pub(super) const fn checkpoint_sequences_are_paired(request: u64, response: u64) -> bool {
    request == response
}

pub(super) fn checkpoint_request_identity(
    signed: &SignedSourceProviderRequestV1,
    method: ProviderMethodV1,
) -> Result<([u8; 16], [u8; 32], u64)> {
    match method {
        ProviderMethodV1::Acquire => {
            let request = decode_acquire_request(signed.subject())
                .map_err(|error| state_error(error.to_string()))?;
            validate_root_query_signer(
                signed.signer(),
                request.holder_authority_id(),
                request.holder_generation(),
                *request.holder_authority_digest().as_bytes(),
            )?;
            Ok((
                request.request_id(),
                *request.session_binding().as_bytes(),
                request.sequence(),
            ))
        }
        ProviderMethodV1::Release => {
            let request = decode_release_request(signed.subject())
                .map_err(|error| state_error(error.to_string()))?;
            validate_root_query_signer(
                signed.signer(),
                request.holder_authority_id(),
                request.holder_generation(),
                *request.holder_authority_digest().as_bytes(),
            )?;
            Ok((
                request.request_id(),
                *request.session_binding().as_bytes(),
                request.sequence(),
            ))
        }
        ProviderMethodV1::Inventory => {
            let request = decode_inventory_request(signed.subject())
                .map_err(|error| state_error(error.to_string()))?;
            validate_root_query_signer(
                signed.signer(),
                request.holder_authority_id(),
                request.holder_generation(),
                *request.holder_authority_digest().as_bytes(),
            )?;
            Ok((
                request.request_id(),
                *request.session_binding().as_bytes(),
                request.sequence(),
            ))
        }
    }
}

pub(super) fn validate_root_query_signer(
    signer: &aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: [u8; 32],
) -> Result<()> {
    if signer.authority_id() != authority_id
        || signer.authority_generation() != authority_generation
        || signer.authority_digest().as_bytes() != &authority_digest
        || signer.usage() != SourceProviderKeyUsageV1::RootMountQuery
    {
        return Err(state_error(
            "provider query signer differs from its holder authority",
        ));
    }
    Ok(())
}
