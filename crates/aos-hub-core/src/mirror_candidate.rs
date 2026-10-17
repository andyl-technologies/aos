//! Purpose-separated controls for storage-local mirror runtime experiments.
//!
//! These plans may address only a reserved controlled destination. Their
//! signature grants no production mirror capability or hosted acceptance.

use anyhow::{ensure, Result};

use crate::storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan};

pub mod query;

/// Identifies the emulator-only controlled mirror endpoint.
pub const MIRROR_CANDIDATE_PATH: &str = "/__hub/mirror-candidate";

const DOMAIN: &[u8] = b"aos.hub.mirror-controlled-candidate.v1\0";

/// Signs one exact mirror-only controlled plan under its separate purpose.
///
/// # Errors
/// Returns an error for a noncandidate destination, malformed plan or encoding.
pub fn sign_mirror_candidate_plan(key: &StorageWorkKey, plan: &StorageWorkPlan) -> Result<String> {
    plan.validate(&plan.deployment_id, plan.issued_at)?;
    validate_candidate_plan(plan)?;
    Ok(key.sign_body(&signed_body(&serde_json::to_vec(plan)?))?)
}

/// Authenticates the exact bounded control and its current execution deadline.
///
/// # Errors
/// Returns an error for an invalid signature, stale plan or foreign destination.
pub fn verify_mirror_candidate_plan(
    key: &StorageWorkKey,
    signature: &str,
    body: &[u8],
    deployment: &str,
    now: i64,
) -> Result<StorageWorkPlan> {
    ensure!(
        body.len() <= 256 * 1024,
        "mirror candidate control exceeds its bound"
    );
    key.verify_body(signature, &signed_body(body))?;
    let plan: StorageWorkPlan = serde_json::from_slice(body)?;
    plan.validate(deployment, now)?;
    validate_candidate_plan(&plan)?;
    Ok(plan)
}

fn signed_body(body: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(DOMAIN.len() + body.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(body);
    signed
}

fn validate_candidate_plan(plan: &StorageWorkPlan) -> Result<()> {
    let originals = match &plan.operation {
        StorageWorkOperation::MirrorTransfer { original, .. } => vec![original],
        StorageWorkOperation::MirrorTransferBatch { items } => {
            items.iter().map(|item| &item.original).collect()
        }
        _ => anyhow::bail!("candidate controls require a typed mirror operation"),
    };
    for original in originals {
        original.validate()?;
        let pieces: Vec<_> = original.placement_prefix.split('/').collect();
        ensure!(
            pieces.len() == 3
                && pieces[0] == ".aos-mirror-qualification"
                && pieces[1].len() == 32
                && pieces[1]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && pieces[2] == "final"
                && plan.binding_kind == "deployment_r2"
                && original.placement_prefix == plan.placement_prefix,
            "mirror candidate cannot address a public or external destination"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
