//! Shares independent Root signed-policy verification over its held journal.
//!
//! This pure helper neither opens a policy owner nor grants currentness. Each
//! caller retains and posts its own actual owner before and after verification.

use aos_sandbox_policy::signed_inputs::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    VerifiedSignedProjectPolicySourceV2,
};

use aos_sandbox_policy::journal_keys::{HEAD_KEY, SIGNER_PINS_KEY};

use crate::journal::{Journal, RecordNamespace};

use super::deployment_head::decode_policy_signer_pins_v1;
use super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};
use super::PolicyDeploymentHeadErrorV1;

pub(crate) type RootSignedProjectSourcesV1 = (
    VerifiedSignedProjectPolicySourceV2,
    PolicyDeploymentHeadV1,
    PolicyDeploymentSourcesV1,
);

#[derive(Debug, thiserror::Error)]
pub(crate) enum RootSignedSourcesErrorV1 {
    #[error("actual Root signed policy input cut changed")]
    ChangedCut,
    #[error(transparent)]
    Deployment(#[from] PolicyDeploymentHeadErrorV1),
}

// Packet and verifying-key selection always comes from the actual held Root
// records. Raw supplied input bytes authenticate only by exact existing heads.
pub(super) fn verify_root_signed_project_sources_v1(
    journal: &Journal,
    project_input: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    now_unix_seconds: i64,
) -> Result<RootSignedProjectSourcesV1, RootSignedSourcesErrorV1> {
    let namespace = RecordNamespace::DesiredState;
    let pins = journal.get(namespace, SIGNER_PINS_KEY)
        .ok_or(RootSignedSourcesErrorV1::ChangedCut)?;
    let (deployment_generation, deployment_key, project_generation, project_key) =
        decode_policy_signer_pins_v1(pins)?;
    let deployment_packet = journal.get(namespace, HEAD_KEY)
        .ok_or(RootSignedSourcesErrorV1::ChangedCut)?;
    let deployment = aos_sandbox_policy::signed_inputs::verify_policy_deployment_head_v1(
        deployment_packet,
        deployment_inputs,
        &deployment_key,
        now_unix_seconds,
    )
    .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    let decoded = aos_sandbox_policy::signed_inputs::decode_policy_deployment_sources_v1(
        deployment_inputs,
        deployment,
    )
    .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    let project_packet = journal
        .get(namespace, HEAD_KEY_V2)
        .ok_or(RootSignedSourcesErrorV1::ChangedCut)?;
    if journal.get(namespace, INPUT_KEY_V2) != Some(project_input) {
        return Err(RootSignedSourcesErrorV1::ChangedCut);
    }
    let project = aos_sandbox_policy::signed_inputs::verify_signed_project_policy_source_v2(
        project_packet,
        project_input,
        &project_key,
        now_unix_seconds,
    )
    .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    if project.head().deployment_signer_generation() != deployment_generation
        || project.head().project_signer_generation() != project_generation
        || project.head().prerequisite_claims()[1] != deployment.packet_digest()
    {
        return Err(RootSignedSourcesErrorV1::ChangedCut);
    }
    Ok((project, deployment, decoded))
}

// Shared verification of the actual retained signed input bytes. The caller
// independently establishes which public pins and current C/Source heads apply;
// successful signature/expiry checks do not supply a Root currentness grant.
pub(crate) fn verify_signed_project_input_data_v2(
    deployment_packet: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    project_packet: &[u8],
    project_input: &[u8],
    deployment_key: &ed25519_dalek::VerifyingKey,
    project_key: &ed25519_dalek::VerifyingKey,
    now_unix_seconds: i64,
) -> Result<RootSignedProjectSourcesV1, super::PolicyDeploymentHeadErrorV1> {
    let deployment = aos_sandbox_policy::signed_inputs::verify_policy_deployment_head_v1(
        deployment_packet,
        deployment_inputs,
        deployment_key,
        now_unix_seconds,
    )
    .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    let sources = aos_sandbox_policy::signed_inputs::decode_policy_deployment_sources_v1(
        deployment_inputs,
        deployment,
    )
    .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    let project = aos_sandbox_policy::signed_inputs::verify_signed_project_policy_source_v2(
        project_packet,
        project_input,
        project_key,
        now_unix_seconds,
    )
    .map_err(crate::policy_compiler::PolicyDeploymentHeadErrorV1::from)?;
    Ok((project, deployment, sources))
}
