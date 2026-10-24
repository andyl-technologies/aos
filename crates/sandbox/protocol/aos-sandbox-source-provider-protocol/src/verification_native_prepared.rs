//! Current Root-role comparison for one original native preparation carrier.
//!
//! Protected custody supplies the current Session, selector and trust snapshot.
//! This verifier authenticates a claim, not Root journal funding or an effect.

use crate::native_held_completion::{
    NativeHeldControlKindV1,
    frame::{NativeHeldSignerV1, SignedNativeHeldControlV1},
};
use crate::{
    SourceProviderCurrentAuthorityV1, SourceProviderIngressSessionV1, SourceProviderPeerRole,
    SourceProviderTrustSetV1, SourceProviderVerificationError,
};

/// Verifies RootPrepared against the supplied current RootMountRecord pin.
///
/// Inputs remain comparison data until a real owner supplies their provenance.
/// Success grants no append, signing, dispatch, nonce or native bridge authority.
///
/// # Errors
///
/// Rejects another kind, Session, role or traffic pin, inactive or mismatched
/// trust, or a signature differing from the independently resolved current key.
pub fn verify_current_root_prepared_v1(
    control: &SignedNativeHeldControlV1,
    session: &SourceProviderIngressSessionV1,
    trust: &SourceProviderTrustSetV1,
    root: &SourceProviderCurrentAuthorityV1,
    now_seconds: i64,
) -> Result<(), SourceProviderVerificationError> {
    if control.kind() != NativeHeldControlKindV1::RootPrepared
        || root.role() != SourceProviderPeerRole::RootMount
        || root.traffic_signer() != session.root_mount_hello().subject().traffic_signer()
        || control.scope().original_source_session != session.binding()
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }

    control
        .scope()
        .validate_root_only()
        .map_err(|_| SourceProviderVerificationError::CrossLink)?;
    let key = trust.resolve_current(root, root.traffic_signer(), now_seconds)?;
    control
        .verify_signature_claim(
            &NativeHeldSignerV1::SourceProvider(root.traffic_signer().clone()),
            key,
        )
        .map_err(|_| SourceProviderVerificationError::CrossLink)
}

/// Verifies RootAccepted against the same original Root1 and current traffic key.
///
/// These borrowed inputs remain comparison DATA. The retaining transport owner
/// independently establishes task, endpoint, clock and protected-cut provenance.
/// Success grants no append, relay signing, acknowledgement or release authority.
///
/// # Errors
///
/// Rejects an invalid Root1, another control kind, changed original scope or
/// signer, inactive current trust, or a mismatched canonical signature.
pub fn verify_current_root_accepted_v5(
    root1: &SignedNativeHeldControlV1,
    accepted: &SignedNativeHeldControlV1,
    session: &SourceProviderIngressSessionV1,
    trust: &SourceProviderTrustSetV1,
    root: &SourceProviderCurrentAuthorityV1,
    now_seconds: i64,
) -> Result<(), SourceProviderVerificationError> {
    verify_current_root_prepared_v1(root1, session, trust, root, now_seconds)?;
    if accepted.kind() != NativeHeldControlKindV1::RootAccepted
        || accepted.prepared().signer() != root1.prepared().signer()
    {
        return Err(SourceProviderVerificationError::CrossLink);
    }
    accepted.scope().require_root_prefix(root1.scope())
        .map_err(|_| SourceProviderVerificationError::CrossLink)?;
    let key = trust.resolve_current(root, root.traffic_signer(), now_seconds)?;
    accepted.verify_signature_claim(
        &NativeHeldSignerV1::SourceProvider(root.traffic_signer().clone()), key,
    ).map_err(|_| SourceProviderVerificationError::CrossLink)
}
