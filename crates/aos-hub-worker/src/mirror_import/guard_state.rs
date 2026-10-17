//! Read-only validation of a held final mirror original and provider receipt.
//!
//! Unknown effects and released owners cannot prove a new publication. A
//! positive exact completion receipt may be read after a crash before its
//! matching pending marker was cleared; this module never clears that marker.
//!
//! ```text
//! mirror-owner + mirror-progress + mutation-receipt:<job>:destination-complete
//! ```

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::mirror_work::{MirrorOriginal, MirrorProgress};

use crate::hybrid_object_state::{
    DeleteClaim, Mutation, MutationKind, MutationOutcome, MutationReceipt,
};

/// Derives the exact retained provider attempt that may prove publication.
pub(crate) fn expected_final_mutation(
    key: &str,
    original: &MirrorOriginal,
    progress: &MirrorProgress,
) -> Result<Mutation> {
    original.validate()?;
    progress.commit_digest(original)?;
    ensure!(
        key == aos_hub_core::keymap::r2_key(&original.placement_prefix, &original.path),
        "mirror guard selected another physical key"
    );
    if original.verification.size() == 0 {
        Mutation::new(
            key,
            &format!("{}:destination-create", original.job_id),
            MutationKind::Mirror,
            &(original, &progress.verified),
        )
    } else {
        let upload = progress
            .destination_upload_id
            .as_deref()
            .context("mirror final lacks its original multipart identity")?;
        Mutation::new(
            key,
            &format!("{}:destination-complete", original.job_id),
            MutationKind::Mirror,
            &(
                original,
                (upload, &progress.destination_parts, &progress.verified),
            ),
        )
    }
}

/// Proves only a currently held final owner with an exact positive receipt.
pub(crate) fn validate_retained_final(
    key: &str,
    owner: Option<&MirrorOriginal>,
    progress: Option<&MirrorProgress>,
    receipt: Option<&MutationReceipt>,
    pending: Option<&Mutation>,
    legacy_delete: Option<&DeleteClaim>,
) -> Result<(MirrorOriginal, MirrorProgress)> {
    let owner = owner.context("mirror final key has no held original")?;
    let progress = progress.context("mirror final owner has no positive progress")?;
    let completed = expected_final_mutation(key, owner, progress)?;
    let receipt = receipt.context("mirror final completion has no retained provider receipt")?;
    ensure!(
        receipt.mutation == completed
            && matches!(&receipt.outcome, MutationOutcome::Mirror { progress: observed } if observed == progress),
        "mirror final receipt changed its original or completion"
    );
    ensure!(
        pending.is_none() || pending == Some(&completed),
        "mirror final key retains a different unknown mutation"
    );
    ensure!(
        legacy_delete.is_none(),
        "mirror final key retains an unknown delete"
    );
    Ok((owner.clone(), progress.clone()))
}

#[cfg(test)]
mod tests;
