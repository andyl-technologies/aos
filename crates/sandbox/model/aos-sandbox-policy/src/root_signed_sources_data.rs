//! Verifies saved Root signed-input DATA against complete historical rows.
//!
//! This module owns no journal, native role, protected interval or receiving
//! authority. It checks the caller's borrowed rows with the same canonical
//! signed-input recipe; callers retain their own provenance and owed posts.

use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use crate::signed_inputs::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyDeploymentSourcesV1,
    SignedPolicyInputDataErrorV1, VerifiedSignedProjectPolicySourceV2,
};

/// Carries verified signature/model DATA without proving native currentness.
pub type RootSignedProjectSourcesDataV1 = (
    VerifiedSignedProjectPolicySourceV2,
    PolicyDeploymentHeadV1,
    PolicyDeploymentSourcesV1,
);

/// Preserves the held-row comparison and signed-input DATA failure categories.
#[derive(Debug, thiserror::Error)]
pub enum RootSignedSourcesDataErrorV1 {
    /// Supplied packets, rows, generations, or prerequisite commitments differ.
    #[error("actual Root signed policy input cut changed")]
    ChangedCut,
    /// Canonical signature or signer-pin DATA is invalid or stale.
    #[error(transparent)]
    Deployment(#[from] SignedPolicyInputDataErrorV1),
}

/// Verifies complete held signed-source rows with the sole canonical recipe.
///
/// # Errors
/// Refuses missing/substituted rows, invalid packets or pin DATA, stale signer
/// generations, expired signatures, or a mismatched deployment prerequisite.
/// The caller separately proves actual native provenance/currentness.
pub fn verify_root_signed_project_sources_data_v1(
    journal: HistoricalLedgerReadViewV1<'_>,
    project_input: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    now_unix_seconds: i64,
) -> Result<RootSignedProjectSourcesDataV1, RootSignedSourcesDataErrorV1> {
    crate::verify_held_root_signed_sources_data_v1! {
        journal: journal,
        project_input: project_input,
        deployment_inputs: deployment_inputs,
        now: now_unix_seconds,
        outputs: (project, deployment, decoded),
        changed_cut: RootSignedSourcesDataErrorV1::ChangedCut,
        changed_projection: [],
        decode_pins: pins => {
            aos_sandbox_protocol::policy_data::signer_pins::decode_policy_signer_pins_v1(pins)
                .map_err(|error| match error {
                    aos_sandbox_protocol::policy_data::signer_pins::PolicySignerPinsDataErrorV1::InvalidHead => SignedPolicyInputDataErrorV1::InvalidHead,
                    aos_sandbox_protocol::policy_data::signer_pins::PolicySignerPinsDataErrorV1::StaleHead => SignedPolicyInputDataErrorV1::StaleHead,
                })?
        },
        signed_projection: [],
        before_deployment: {},
        before_project: project_packet => {},
    }
    Ok((project, deployment, decoded))
}

