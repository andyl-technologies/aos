//! Signed deployment input declarations for the explicit V2 compiler profile.
//!
//! The existing `AOSPDH01` head and deployment signing role remain unchanged.
//! Each of its four inputs uses the existing canonical model serializer:
//!
//! ```text
//! u64be(domain-length) || domain || u64be(payload-length) ||
//! canonical-json([[2, head-generation, deployment-signer-generation], typed-data])
//! ```
//!
//! Exact typed reserialization is mandatory; this module never deserializes
//! owner-proof-shaped models from untrusted JSON. Signed Node/Site ceilings are
//! provenance. Backend and catalog declarations do not prove installed
//! enforcement or live catalog currentness. No publication or read is enabled.

use aos_sandbox_policy::signed_inputs::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputProfileV2, PolicyDeploymentInputsV1,
};

use aos_sandbox_policy::journal_keys::{HEAD_KEY, SIGNER_PINS_KEY};

use super::*;
use aos_sandbox_policy::signed_inputs::verify_policy_deployment_profile_data_v2;
use aos_sandbox_policy::{
    BackendCapabilitiesV1, EndpointCatalogEntryV1, NamespaceDestinationV1, NodePolicyInputV1,
    SitePolicyInputV1,
};
use aos_sandbox_policy::canonical_endpoint_catalog_v1;
use aos_sandbox_policy::canonical_namespace_catalog_v1;
use aos_sandbox_model::ObjectDescriptor;

/// Admits a V2-profile head under the existing fixed Root deployment role.
///
/// The key parameter supports verification before opening the journal; it is
/// not a trust nomination. Root independently reads its protected deployment
/// pin and rejects any different key or generation before the shared head CAS.
/// The V1 installer and all public policy gates remain unchanged.
///
/// # Errors
///
/// Rejects malformed or substituted typed bytes, invalid signature/validity,
/// changed role pins, unsafe Root names, held publication, generation conflict,
/// ambiguous append, or failed readback.
pub fn admit_fixed_policy_deployment_profile_v2(
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    profile: &PolicyDeploymentInputProfileV2,
    verifying_key: &VerifyingKey,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    let verified = verify_policy_deployment_profile_data_v2(
        packet,
        inputs,
        profile,
        verifying_key,
        now_unix_seconds,
    )
    .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    let (key, generation) = read_deployment_role(&mut journal)?;
    if key != *verifying_key || generation != profile.signer_generation() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let admitted = admit_deployment_head_in_journal(&mut journal, packet, verified, &key)?;
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    Ok(admitted)
}

/// Verifies exact declarations against a retained fixed Root writer and head.
///
/// This read-only check uses the independently stored deployment pin, not a
/// request-supplied key. The returned existing head is signed provenance only;
/// it cannot replace Root history/floor, live backend/catalog proofs, or the
/// cross-owner compiler/publication barrier.
///
/// # Errors
///
/// Rejects unsafe fixed names, missing/changed pins or head, expiry, invalid
/// signature, legacy profile bytes, or any typed declaration substitution.
pub fn verify_current_policy_deployment_profile_v2(
    journal: &mut Journal,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    profile: &PolicyDeploymentInputProfileV2,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    let verified = verify_current_profile(journal, packet, inputs, profile, now_unix_seconds)?;
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    Ok(verified)
}

pub(super) fn verify_current_profile(
    journal: &mut Journal,
    packet: &[u8],
    inputs: &PolicyDeploymentInputsV1<'_>,
    profile: &PolicyDeploymentInputProfileV2,
    now_unix_seconds: i64,
) -> Result<PolicyDeploymentHeadV1, PolicyDeploymentHeadErrorV1> {
    let (key, generation) = read_deployment_role(journal)?;
    if generation != profile.signer_generation() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(HEAD_KEY)? != Some(packet) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    verify_policy_deployment_profile_data_v2(packet, inputs, profile, &key, now_unix_seconds)
        .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)
}

fn read_deployment_role(
    journal: &mut Journal,
) -> Result<(VerifyingKey, u64), PolicyDeploymentHeadErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let pins = authority
        .get(SIGNER_PINS_KEY)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let (deployment_generation, deployment, _, _) = decode_policy_signer_pins_v1(pins)?;
    Ok((deployment, deployment_generation))
}

#[cfg(test)]
mod tests;
