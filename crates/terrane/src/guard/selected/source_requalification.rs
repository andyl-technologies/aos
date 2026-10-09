//! Publishes fresh complete lineage for one genuinely selected unchanged source.
//!
//! This producer walks the actual source through ordinary owning verification.
//! It changes only the protected lineage selector and publication revision; the
//! signed Commit, whole head/log, Guard and loss generation remain unchanged.
//! Missing context is repaired only by full completion, never decoded claims.

use std::time::Duration;

use terrane_core::gc::publication::SourceLineage;
use terrane_core::gc::publication::evidence::CheckedLineage;
use terrane_core::refs::RefRecord;

use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, OriginalAuthority};
use crate::ref_advance::{AdvanceError, CommitTiming};
use crate::selected_bridge::{CheckedEvidence, CheckedMutation, OwnedFinalCheck};
use crate::store::{Clock, ContentValidator, LocalFs, RefStore, StoreErrorKind, StoreFailure};

use super::{
    GuardEffectContext, LocalControlInputs, SharedCheck, capture_selected_reads,
    hold_consumed_controls, invalid, retain_final_check,
};

/// Borrows ordinary public request data without granting checked authority.
pub(crate) struct RequalificationRequest<'a> {
    /// Names the actual selected source whose whole record remains unchanged.
    pub(crate) source: &'a str,
    /// Borrows the caller token for genuine current Fork authorization.
    pub(crate) token: &'a [u8],
    /// Names the actual authorization surface.
    pub(crate) surface: &'a str,
    /// Retains the original monotonic request start for final duration checks.
    pub(crate) started: Duration,
    /// Retains the configured operation timing bounds.
    pub(crate) timing: CommitTiming,
}

/// Completes ordinary admission and acknowledges one same-head source transition.
///
/// The public request supplies no evidence constructor or semantic profile.
/// Byte-identical already-selected lineage is Unsupported in this bounded lane;
/// it cannot claim a fresh proof-case-1 transition or durability acknowledgment.
///
/// # Errors
/// Preserves current Fork/path/domain, signed history/profile/index and Original
/// failures, unsupported or unknown retained history, changed controls and time,
/// storage failures and uncertain native publication without claiming success.
pub(crate) async fn publish<'held, F, B, V, C, D>(
    concrete: &Guard<FileBucket<F, B, V>, D>,
    current: &Guard<HeldBucket<'held, F, B, V, true>, C>,
    authority: &OriginalAuthority,
    observed: &SelectedObservation<'held>,
    request: RequalificationRequest<'_>,
) -> Result<RefRecord, AdvanceError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + BucketBinding,
{
    let RequalificationRequest {
        source,
        token,
        surface,
        started,
        timing,
    } = request;

    observed.revalidate().await?;
    current.check_source_requalification_authority(authority)?;
    if observed.identity().root() != authority.root()
        || observed.identity().physical_identity() != authority.physical_identity()
    {
        return Err(invalid().into());
    }
    let selected_reads = capture_selected_reads(current.store(), observed, &[source]).await?;
    let consumed = ConsumedResolver::new(current, authority)?;
    consumed.registration(authority)?;
    let completed = current
        .complete_fork_source_requalification(
            source,
            token,
            surface,
            observed.identity(),
            &consumed,
        )
        .await?;
    let history = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let history_reads = current
        .store()
        .selected_source_history_records(observed, source, completed.record())
        .await?;

    let LocalControlInputs {
        exclusion: mut controls,
        snapshot,
        used,
    } = hold_consumed_controls(concrete, authority, current.store(), observed, &consumed).await?;
    if !used
        .check_supported_view_contexts()
        .map_err(|_| invalid())?
    {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
    }
    let retained = controls.retain_used(&used.controls).await?;
    let configured = current.source_requalification_configuration_adapter()?;
    current.retain_original_controls(&retained)?;
    current
        .revalidate_original_context(completed.original(), history)
        .await?;
    current.check_requalification_source_profile(completed.commit())?;

    let lineage = CheckedLineage {
        source_name: source.to_owned(),
        source: completed.record().clone(),
        commit_id: completed.commit().identity(),
        commit_bytes: completed
            .commit()
            .commit()
            .encode()
            .map_err(|_| invalid())?,
        guard_digest: *blake3::hash(&snapshot).as_bytes(),
        loss_generation: observed.state().loss_generation,
        controls: used.controls.clone(),
        original: crate::guard::consumed_registration(completed.original().baseline().authority()),
        used,
    };
    if consumed.finish()? != lineage.used {
        return Err(invalid().into());
    }
    lineage
        .check_guard_snapshot(&snapshot)
        .map_err(|_| invalid())?;
    current.check_requalification_views(&lineage, completed.commit().commit())?;
    for view in &lineage.used.views {
        current.compare_requalification_view_inputs(&lineage, view)?;
        configured.compare_requalification_view_inputs(&lineage, view)?;
    }
    let bytes = lineage.encode().map_err(|_| invalid())?;
    let digest = *blake3::hash(&bytes).as_bytes();
    if observed
        .state()
        .sources
        .iter()
        .any(|row| row.name == source && row.digest == digest)
    {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
    }

    let requests = retain_final_check(current, completed.requests(), started, timing)?;
    let final_snapshot = snapshot.clone();
    let final_authority = authority.clone();
    let comparisons = OwnedFinalCheck {
        check: SharedCheck::new(move || {
            if ConsumedResolver::new(&configured, &final_authority)?.snapshot_bytes()?
                != final_snapshot
            {
                return Err(invalid());
            }
            for view in &lineage.used.views {
                configured.compare_requalification_view_inputs(&lineage, view)?;
            }
            Ok(())
        }),
    };
    let final_check = OwnedFinalCheck {
        check: SharedCheck::new(move || {
            requests.recheck()?;
            comparisons.recheck()
        }),
    };
    final_check.recheck()?;
    controls.revalidate().await?;
    observed.revalidate().await?;
    if current.store().ref_get(source).await?.as_ref() != Some(completed.record()) {
        return Err(invalid().into());
    }

    let mut next = observed.state().clone();
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(AdvanceError::Exhausted)?;
    next.sources.retain(|row| row.name != source);
    next.sources.push(SourceLineage {
        name: source.to_owned(),
        digest,
    });
    next.sources
        .sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let permit = CheckedMutation {
        observed,
        sources: Vec::new(),
        next,
        changes: Vec::new(),
        evidence: CheckedEvidence::SourceRequalification {
            snapshot,
            lineage: bytes,
            history_reads,
        },
        final_check: Box::new(|| final_check.recheck()),
        effect_context: Some(GuardEffectContext {
            existing_reads: Vec::new(),
            final_check: final_check.clone(),
            controls: vec![retained],
            selected_reads,
            publication_original: None,
        }),
    };
    match current.store().publish_checked(permit).await {
        Ok(_) => Ok(completed.record().clone()),
        Err(error) if matches!(error.kind(), StoreErrorKind::Unavailable { .. }) => {
            // The source head is intentionally unchanged. This reread is only
            // diagnostic data and cannot establish selected lineage or ACK.
            Err(AdvanceError::Indeterminate {
                observed: current
                    .store()
                    .ref_get(source)
                    .await
                    .map(|record| record.map(Box::new)),
                source: Box::new(error),
            })
        }
        Err(error) => Err(error.into()),
    }
}
