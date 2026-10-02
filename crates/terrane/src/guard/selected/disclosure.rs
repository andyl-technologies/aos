//! Captures genuine source authority for paired native disclosure publication.
//!
//! Source Read authorization, original authoring context and dedicated disclosure
//! signing authority remain separate. Only actual held native factories populate
//! these private inputs; copied records and caller coordinates confer no rights.

#[path = "disclosure/projection.rs"]
mod projection;

use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{
    AuthorizedRef, AuthorizedSnapshot, ConsumedResolver, DisclosureSourceSelection, Guard,
    HistoryObservation, OriginalCommitContext, RetainedControls,
};
use crate::repository::local_authority::disclosure::DisclosureSigner;
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};

use super::{LocalControlInputs, SharedCheck, invalid};

/// Keeps independently checked source rights and exact physical controls private.
struct DisclosureSource<'guard, F: LocalFs> {
    snapshots: Vec<AuthorizedSnapshot>,
    requests: Vec<AuthorizedRef>,
    originals: Vec<OriginalCommitContext>,
    signer: DisclosureSigner,
    controls: LocalControlInputs<'guard, F>,
    retained: RetainedControls,
    final_check: crate::selected_bridge::OwnedFinalCheck,
}

/// Captures source rights before any imported control or destination upload.
///
/// Every original dependency is checked before taking configuration exclusion,
/// then its exact consumed bytes are checked again under that exclusion. This
/// avoids reacquiring the source lock while retaining complete original evidence.
async fn capture_source<'guard, F, B, V, C, D>(
    concrete: &'guard Guard<FileBucket<F, B, V>, C>,
    source: &Guard<HeldBucket<'_, F, B, V, false>, D>,
    observed: &SelectedObservation<'_>,
    selections: &[DisclosureSourceSelection<'_>],
    timing: crate::ref_advance::CommitTiming,
) -> Result<DisclosureSource<'guard, F>, StoreFailure>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    let started = source.clock().monotonic();
    let authority = concrete.configured_original_authority()?;
    let consumed = ConsumedResolver::new(source, &authority)?;
    consumed.registration(&authority)?;
    let history = HistoryObservation::held(observed.identity()).tracked(&consumed);
    if selections.is_empty() {
        return Err(invalid());
    }
    let mut snapshots = Vec::new();
    let mut originals = Vec::new();
    let mut requests = Vec::new();
    for selection in selections {
        let selection = DisclosureSourceSelection {
            reference: selection.reference,
            commit: selection.commit,
            token: selection.token,
            path: selection.path,
            surface: selection.surface,
        };
        let (snapshot, selected_requests) = source
            .capture_disclosure_source_observed(selection, history)
            .await?;
        for request in &selected_requests {
            if requests
                .first()
                .is_some_and(|first: &AuthorizedRef| first.subject() != request.subject())
            {
                return Err(invalid());
            }
            consumed.operation(request)?;
        }
        let original = source.original_commit(&snapshot.commit.identity())?;
        source
            .revalidate_original_context(&original, history)
            .await?;
        requests.extend(selected_requests);
        originals.push(original);
        snapshots.push(snapshot);
    }

    let mut controls =
        super::hold_consumed_controls(concrete, &authority, source.store(), observed, &consumed)
            .await?;
    let now = source.now(
        requests.first().ok_or_else(invalid)?.reference(),
        terrane_core::auth::Verb::Read,
    )?;
    let signer = crate::repository::local_authority::disclosure::load(
        concrete,
        &authority,
        &mut controls.exclusion,
        now,
    )
    .await
    .map_err(crate::guard::retention_failure)?;

    let mut records = Vec::new();
    for pin in &controls.used.controls {
        let bytes = controls.exclusion.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
        records.push((pin.key.clone(), bytes));
    }
    records.extend(
        signer
            .retained_records()
            .map_err(crate::guard::retention_failure)?,
    );
    let retained = controls.exclusion.retain_named(&records).await?;

    let requests_check = super::retain_final_check(source, &requests, started, timing)?;
    let role = signer.role().clone();
    let clock = source.clock().retain_native_clock().map_err(|failure| {
        StoreFailure::with_source(crate::store::StoreErrorKind::Unsupported, failure)
    })?;
    let final_check = crate::selected_bridge::OwnedFinalCheck {
        check: SharedCheck::new(move || {
            requests_check.recheck()?;
            let now = clock
                .now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| invalid())?
                .as_secs();
            if now < role.not_before || role.not_after.is_some_and(|end| now >= end) {
                return Err(invalid());
            }
            Ok(())
        }),
    };
    final_check.recheck()?;
    observed.revalidate().await?;

    Ok(DisclosureSource {
        snapshots,
        requests,
        originals,
        signer,
        controls,
        retained,
        final_check,
    })
}
