//! Owns canonical signed deployment/project DATA without native admission.
//!
//! Verification preserves the original role domains, byte bounds and typed
//! policy derivation. These models do not retain protected pins, writer locks,
//! current Source/Controller/Root owners, a Q04 loan or publication permission.
//! Actual native owners must reverify original packets against their genuine
//! protected credentials and independently join every current prerequisite.

mod deployment;
mod held_root;
mod profile;
mod project;
mod startup_deployment;

/// Owns the existing twelve-member fixed startup credential DATA recipe.
pub mod startup_credentials;
pub use startup_credentials::{RootStartupCredentialGeometryErrorV1, RootStartupCredentialMemberV1};

pub use startup_deployment::RootPolicyStartupDeploymentV1;

#[doc(hidden)]
pub use aos_sandbox_model::RecordNamespace as HeldRootRecordNamespaceV1;

pub use deployment::{
    DeploymentLayerV1 as DeploymentLayerDataV1, INPUT_MAGICS as DEPLOYMENT_INPUT_MAGICS,
    MAGIC as DEPLOYMENT_MAGIC, PACKET_BYTES as DEPLOYMENT_PACKET_BYTES,
    PAYLOAD_BYTES as DEPLOYMENT_PAYLOAD_BYTES, SIGNING_DOMAIN as DEPLOYMENT_SIGNING_DOMAIN,
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    SignedProjectPolicyHeadV1, decode_layer as decode_deployment_layer_data_v1,
    decode_policy_deployment_sources_v1, fixed_root_startup_decoding_bytes_v1,
    verify_policy_deployment_head_v1,
    verify_historical_packet as verify_historical_policy_deployment_packet_v1,
};
pub use profile::{
    INPUT_DOMAINS as DEPLOYMENT_PROFILE_INPUT_DOMAINS,
    PolicyDeploymentCatalogDeclarationsV2, PolicyDeploymentInputProfileV2,
    verify_policy_deployment_profile_data_v2,
};
pub use project::{
    INPUT_MAGIC as PROJECT_INPUT_MAGIC, MAGIC as PROJECT_MAGIC,
    PACKET_BYTES as PROJECT_PACKET_BYTES, PAYLOAD_BYTES as PROJECT_PAYLOAD_BYTES,
    SIGNING_DOMAIN as PROJECT_SIGNING_DOMAIN, SignedProjectPolicyHeadV2,
    VerifiedSignedProjectPolicySourceV2,
    explicit_layer_with_authenticated_binding as materialize_signed_project_layer_data_v1,
    verify_signed_project_policy_source_v2,
};
#[cfg(target_os = "linux")]
pub use project::Q04SignedProjectLayerRecipeV1;

/// Preserves signed-input framing, signature and stale DATA classifications.
#[derive(Debug, thiserror::Error)]
pub enum SignedPolicyInputDataErrorV1 {
    /// The signed packet, canonical input or validity interval is malformed.
    #[error("invalid deployment policy head")]
    InvalidHead,
    /// The dedicated deployment/project key did not sign this exact packet.
    #[error("deployment policy head signature is invalid")]
    InvalidSignature,
    /// A supplied signer-pin DATA generation does not match.
    #[error("deployment policy head generation is not current")]
    StaleHead,
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SignedPolicyInputDataErrorV1> {
    Ok(u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .and_then(|part| part.try_into().ok())
            .ok_or(SignedPolicyInputDataErrorV1::InvalidHead)?,
    ))
}

pub(super) fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, SignedPolicyInputDataErrorV1> {
    Ok(i64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .and_then(|part| part.try_into().ok())
            .ok_or(SignedPolicyInputDataErrorV1::InvalidHead)?,
    ))
}

pub(super) fn read_digest(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; 32], SignedPolicyInputDataErrorV1> {
    bytes
        .get(offset..offset + 32)
        .and_then(|part| part.try_into().ok())
        .ok_or(SignedPolicyInputDataErrorV1::InvalidHead)
}

#[cfg(feature = "native-journal")]
pub(crate) use project::project_source_verification_receiving_bytes_v2;

#[cfg(feature = "native-journal")]
pub(crate) use deployment::deployment_sources_decoding_bytes_v1;
