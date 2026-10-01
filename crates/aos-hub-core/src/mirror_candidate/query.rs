//! Distinct controlled purpose for metadata-only mirror query experiments.
//!
//! The signature addresses only the reserved candidate placement and closed
//! membership operation. It supplies no production acceptance or mutation.

use anyhow::{ensure, Result};

use crate::storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan};

/// Controlled query entrypoint absent from ordinary Worker builds.
pub const MIRROR_CANDIDATE_QUERY_PATH: &str = "/__hub/mirror-candidate-query";
const DOMAIN: &[u8] = b"aos.hub.mirror-controlled-query.v1\0";

/// Signs an exact bounded candidate query, with no producer permission.
///
/// # Errors
/// Returns an error for a public destination, unsupported operation or plan.
pub fn sign(key: &StorageWorkKey, plan: &StorageWorkPlan) -> Result<String> {
    validate(plan)?;
    key.sign_body(&purpose_body(&serde_json::to_vec(plan)?))
        .map_err(Into::into)
}

/// Authenticates the separate query purpose and its original freshness.
///
/// # Errors
/// Returns an error for a foreign purpose, changed body, namespace or deadline.
pub fn verify(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    now: i64,
) -> Result<StorageWorkPlan> {
    ensure!(
        body.len() <= 256 * 1024,
        "candidate query exceeds control bound"
    );
    key.verify_body(signature, &purpose_body(body))?;
    let plan: StorageWorkPlan = serde_json::from_slice(body)?;
    plan.validate(deployment, now)?;
    validate(&plan)?;
    Ok(plan)
}

fn validate(plan: &StorageWorkPlan) -> Result<()> {
    plan.validate(&plan.deployment_id, plan.issued_at)?;
    ensure!(
        matches!(
            &plan.operation,
            StorageWorkOperation::InspectMirrorMembership { .. }
        ),
        "candidate query cannot grant other reads or effects"
    );
    let pieces: Vec<_> = plan.placement_prefix.split('/').collect();
    ensure!(
        pieces.len() == 3
            && pieces[0] == ".aos-mirror-qualification"
            && pieces[1].len() == 32
            && pieces[1]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && pieces[2] == "final"
            && plan.binding_kind == "deployment_r2",
        "candidate query cannot address public or external placement"
    );
    Ok(())
}

fn purpose_body(body: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(DOMAIN.len() + body.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(body);
    signed
}
