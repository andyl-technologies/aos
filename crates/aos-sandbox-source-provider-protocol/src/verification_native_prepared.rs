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
