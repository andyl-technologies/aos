//! Shares the original cut encoding in each concrete comparison owner.
//!
//! The recipe contains borrowed DATA only. Currentness, native history,
//! original clock and role admission remain at the actual writer and flight.

use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, SandboxId};

/// Borrows the existing original cut fields without granting continuation authority.
pub struct Q04CutRecipeV1<'recipe> {
    /// Copies the actual flight nonce as comparison DATA.
    pub nonce: [u8; 16],
    /// Names the original project.
    pub project: ProjectId,
    /// Names the original operation.
    pub operation: OperationId,
    /// Names the original sandbox.
    pub sandbox: SandboxId,
    /// Copies the independently qualified Controller UID.
    pub controller_uid: u32,
    /// Copies the independently qualified Source UID.
    pub source_uid: u32,
    /// Borrows the exact original prehold metadata.
    pub controller_metadata: &'recipe [u8],
    /// Copies the original Root boot identifier.
    pub root_boot: [u8; 16],
    /// Copies the original Root start clock without refreshing it.
    pub root_started: u64,
    /// Copies the staged binding generation.
    pub handoff_epoch: u64,
    /// Copies the original Stage transaction identity.
    pub stage: [u8; 16],
    /// Copies the compared publication transaction identity.
    pub publication: [u8; 16],
    /// Keeps the fourteen existing ordered cut commitments.
    pub digests: [ObjectDigest; 14],
}


/// Encodes the existing original cut at the caller's actual typed error boundary.
///
/// The lexical expansion preserves Bounds, Expired and the original fixed
/// history codec error without a new owning Result forwarding interface.
/// This byte recipe performs no IO, allocation, clock sampling or admission.
#[macro_export]
macro_rules! encode_original_q04_cut_recipe_v1 {
    ($recipe:ident, $error:ty) => {{
    if $recipe.controller_metadata.len() != $crate::domain_ledger::create_q04_history::transfer::PREHOLD_METADATA_BYTES {
        return Err(<$error>::Bounds);
    }
    let mut body = [0; $crate::domain_ledger::create_q04_history::IDENTITY_BYTES];
    body[16..32].copy_from_slice(&$recipe.nonce);
    body[32..48].copy_from_slice($recipe.project.as_bytes());
    body[48..64].copy_from_slice($recipe.operation.as_bytes());
    body[64..80].copy_from_slice($recipe.sandbox.as_bytes());
    body[80..84].copy_from_slice(&$recipe.controller_uid.to_be_bytes());
    body[84..88].copy_from_slice(&$recipe.source_uid.to_be_bytes());
    body[88..96].copy_from_slice(&$recipe.controller_metadata[32..40]);
    body[96..104].copy_from_slice(&1_u64.to_be_bytes());
    body[112..128].copy_from_slice(&$recipe.root_boot);
    body[128..144].copy_from_slice(&$recipe.controller_metadata[16..32]);
    body[144..152].copy_from_slice(&$recipe.root_started.to_be_bytes());
    body[152..160].copy_from_slice(&$recipe.root_started
        .checked_add(65_000_000_000).ok_or(<$error>::Expired)?.to_be_bytes());
    body[160..168].copy_from_slice(&$recipe.handoff_epoch.to_be_bytes());
    body[168..184].copy_from_slice(&$recipe.stage);
    body[184..200].copy_from_slice(&$recipe.publication);
    for (index, digest) in $recipe.digests.into_iter().enumerate() {
        let start = 200 + index * 32;
        body[start..start + 32].copy_from_slice(digest.as_bytes());
    }
    $crate::domain_ledger::create_q04_history::Q04CutIdentityV1::from_body(body).map_err(<$error>::from)
    }};
}
