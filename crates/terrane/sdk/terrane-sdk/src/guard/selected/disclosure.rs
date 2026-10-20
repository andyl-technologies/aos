//! Captures genuine source authority for paired native disclosure publication.
//!
//! Source Read authorization, original authoring context and dedicated disclosure
//! signing authority remain separate. Only actual held native factories populate
//! these private inputs; copied records and caller coordinates confer no rights.

#[path = "disclosure/projection.rs"]
mod projection;

#[path = "disclosure/destination.rs"]
mod destination;

#[path = "disclosure/publication.rs"]
mod publication;
pub(crate) use publication::publish;

#[cfg(all(test, feature = "tokio"))]
pub(crate) use publication::test_pause::pause_next_after_baseline;

#[cfg(all(test, feature = "tokio"))]
#[path = "disclosure/mutations.rs"]
mod mutations;
#[cfg(all(test, feature = "tokio"))]
pub(crate) use mutations::{CertificateMutation, corrupt_next_certificate};

/// Arms one test interruption after actual import installation and before selection.
///
/// # Errors
/// Rejects unavailable synchronization or an already armed interruption.
#[cfg(all(test, feature = "tokio"))]
pub(crate) fn interrupt_next_import_selection(
    root: &std::path::Path,
) -> Result<(), crate::store::StoreFailure> {
    destination::interrupt_next_selection(root)
}

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

#[cfg(all(feature = "tokio", unix))]
pub(crate) use destination::GuardTransition;

/// Keeps independently checked source rights and exact physical controls private.
struct DisclosureSource<'guard, F: LocalFs> {
    authority: crate::guard::OriginalAuthority,
    snapshots: Vec<AuthorizedSnapshot>,
    issuer_keys: Vec<terrane_format::auth::IssuerKey>,
    requests: Vec<AuthorizedRef>,
    originals: Vec<OriginalCommitContext>,
    signer: DisclosureSigner,
    controls: LocalControlInputs<'guard, F>,
    retained: RetainedControls,
    final_check: crate::selected_bridge::OwnedFinalCheck,
    selected_reads: Vec<crate::bucket::publication::receipts::RecordRead>,
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
    let mut selected_reads = Vec::new();
    #[cfg(all(feature = "tokio", unix))]
    let guard_record = source
        .store()
        .selected_guard_snapshot_record_retained(observed)
        .await?;
    #[cfg(not(all(feature = "tokio", unix)))]
    let guard_record = source
        .store()
        .selected_guard_snapshot_record(observed)
        .await?;
    if let Some(record) = guard_record {
        selected_reads.push(record);
    }
    let mut names = std::collections::BTreeSet::new();
    for selection in selections {
        if names.insert(selection.reference) {
            #[cfg(all(feature = "tokio", unix))]
            let record = source
                .store()
                .selected_lineage_record_retained(observed, selection.reference)
                .await?;
            #[cfg(not(all(feature = "tokio", unix)))]
            let record = source
                .store()
                .selected_lineage_record(observed, selection.reference)
                .await?;
            if let Some(record) = record {
                selected_reads.push(record);
            }
        }
    }
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
                .is_some_and(|first: &AuthorizedRef| !first.same_principal(request))
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
        terrane_format::auth::Verb::Read,
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

        // Complete source history consumed these exact original records before
        // configuration exclusion. Retain every public producer's checked
        // context, not merely the top-level selected commit's association.
        if let Some(commit) = original_control_commit(pin.kind, &bytes)? {
            let context = source.original_commit(&commit)?;
            if let Some(existing) = originals.iter().find(|value| value.commit() == &commit) {
                if existing != &context {
                    return Err(invalid());
                }
            } else {
                originals.push(context);
            }
        }
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
        selected_reads,
        authority,
        issuer_keys: concrete.keys().to_vec(),
        snapshots,
        requests,
        originals,
        signer,
        controls,
        retained,
        final_check,
    })
}

/// Reads a consumed original selector from its already checked canonical bytes.
///
/// Decoding identifies a context to retain; it cannot create original authority.
/// The context must already exist in the genuinely verified source guard map.
fn original_control_commit(
    kind: terrane_format::gc::publication::evidence::ControlKind,
    bytes: &[u8],
) -> Result<Option<terrane_format::identity::Digest>, StoreFailure> {
    use crate::repository::local_authority::retention::{CommitAssociation, ImportRecord, Record};
    use terrane_format::gc::publication::evidence::ControlKind;

    match kind {
        ControlKind::Association => Ok(Some(
            CommitAssociation::decode(bytes)
                .map_err(crate::guard::retention_failure)?
                .commit,
        )),
        ControlKind::Import => Ok(Some(
            ImportRecord::decode(bytes)
                .map_err(crate::guard::retention_failure)?
                .association
                .commit,
        )),
        _ => Ok(None),
    }
}
