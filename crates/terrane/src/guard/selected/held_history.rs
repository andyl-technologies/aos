//! Completes one candidate only after a combined physical input closing check.
//!
//! The same held producer first obtains pending semantic history, then extends
//! its genuine Original exclusion with every late consumed pin. A final native
//! read closes all original controls, selection and payload recipes together;
//! synchronous Guard promotion follows without another awaited validation.

use super::meta_batch::{EarlyControlInputs, ImmutableEffectContext};
use super::*;
use crate::bucket::publication::receipts::RecordRead;
use crate::guard::{CompletedCandidateHistory, HistoryObservation};
use terrane_core::identity::Digest;

/// Borrows the actual candidate and selected inputs of this held operation.
pub(super) struct HistoryScope<'scope, 'history, 'held, F: LocalFs, B, V, C, R> {
    /// The actual coordinator using the acquired destination holder.
    pub(super) coordinator:
        &'scope crate::ref_advance::Coordinator<HeldBucket<'held, F, B, V, true>, C, R>,
    /// The actual retained selection refreshed after durable staging.
    pub(super) observed: &'scope SelectedObservation<'held>,
    /// The same tracked candidate and consumed-input observation.
    pub(super) history: HistoryObservation<'history>,
    /// The actual admitted candidate's immutable identity.
    pub(super) view: Digest,
}

/// Promotes pending history after every original physical input closes together.
///
/// # Errors
/// Preserves semantic history, Original, current request and deadline failures;
/// rejects late foreign controls, changed original physical recipes, unsupported
/// native reads or a substituted candidate, holder or consumed operation.
pub(super) async fn complete<F, B, V, C, R>(
    inputs: HistoryScope<'_, '_, '_, F, B, V, C, R>,
    authority: &OriginalAuthority,
    context: &mut ImmutableEffectContext<'_, '_>,
    early: &mut EarlyControlInputs<'_, F>,
) -> Result<(CompletedCandidateHistory, Vec<RecordRead>), crate::ref_advance::AdvanceError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + BucketBinding,
    R: LocalFs + BucketBinding,
{
    let HistoryScope {
        coordinator,
        observed,
        history,
        view,
    } = inputs;
    let held = coordinator.store();
    let reads = held
        .held_node_reads(observed, context.effect_context().final_check())
        .await?;
    let pending = coordinator
        .guard()
        .prepare_candidate_history_with_node_reads(view, history, &reads)
        .await?;

    let consumed = history.resolver().ok_or_else(invalid)?;
    let controls = context
        .extend_history_controls(early, authority, consumed)
        .await?;
    coordinator.guard().retain_original_controls(&controls)?;
    let checked = crate::store::native_publication_effects::close_history_inputs(
        held.fs(),
        observed,
        context.effect_context(),
        history,
        &reads,
    )
    .await?;

    // Only data copies and the owning synchronous promotion follow the complete
    // closing observation. Later native effects still repeat original recipes.
    let artifacts = checked.artifacts().to_vec();
    coordinator
        .guard()
        .retain_original_controls(checked.controls().first().ok_or_else(invalid)?)?;
    let completed = coordinator
        .guard()
        .promote_candidate_history(pending, checked)?;
    Ok((completed, artifacts))
}
