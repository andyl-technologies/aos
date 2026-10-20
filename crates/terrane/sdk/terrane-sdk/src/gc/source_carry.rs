//! Completes independent ordinary source visits before a destructive loss transition.
//!
//! Each selected source gets a separate metadata adapter and resolver. Its full,
//! retention-bounded walk supplies eligibility marks and fresh per-view completion;
//! prior lineage is compared data, never permission or a substitute for a visit.

use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::publication::receipts::RecordRead;
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::runner::{CollectionError, denied, roots, session::Session, walk};
use crate::guard::{
    ConsumedResolver, Guard, HistoryObservation, OriginalAuthority, RetainedControls,
};
use crate::store::{Clock, ContentValidator, LocalFs, RefStore};
use std::collections::{BTreeMap, BTreeSet};
use terrane_format::gc::publication::SourceLineage;
use terrane_format::gc::publication::evidence::{
    CheckedLineage, LineageUsedInputs, RequiredControlPin,
};
use terrane_format::identity::Digest;

/// Keeps source preservation evidence produced by complete independent visits.
///
/// Only this module constructs the result. Its bodies are fresh successor data;
/// the current collector, candidate index and native atomic acknowledgment remain
/// separately required before any retirement may consume it.
pub(crate) struct CompletedSources {
    lineages: Vec<(SourceLineage, Vec<u8>)>,
    prior: Vec<SourceLineage>,
    marks: BTreeSet<Digest>,
    inputs: Vec<RecordRead>,
    protected: Vec<RecordRead>,
    controls: Vec<RequiredControlPin>,
}

impl CompletedSources {
    /// Borrows canonical fresh source bodies and their successor selection rows.
    pub(crate) fn lineages(&self) -> &[(SourceLineage, Vec<u8>)] {
        &self.lineages
    }

    /// Borrows the exact prior selected rows paired with each fresh lineage.
    pub(crate) fn prior(&self) -> &[SourceLineage] {
        &self.prior
    }

    /// Borrows independently completed source marks before candidate selection.
    pub(crate) fn marks(&self) -> &BTreeSet<Digest> {
        &self.marks
    }

    /// Borrows exact ordinary metadata and inventory inputs consumed by each walk.
    pub(crate) fn inputs(&self) -> &[RecordRead] {
        &self.inputs
    }

    /// Borrows prior selected lineage preimages with their protected read receipts.
    pub(crate) fn protected(&self) -> &[RecordRead] {
        &self.protected
    }

    /// Unions actual factory-consumed control pins without splitting another trace.
    ///
    /// # Errors
    /// Rejects conflicting whole pins at one independently configured owner/key
    /// and invalid canonical owner encodings.
    pub(crate) fn merge_controls(
        &self,
        pins: &[RequiredControlPin],
    ) -> Result<Vec<RequiredControlPin>, CollectionError> {
        let mut rows = BTreeMap::new();
        for pin in pins.iter().chain(&self.controls) {
            let owner = pin.owner.encode().map_err(|_| denied())?;
            let selector = (pin.kind, owner, pin.key.clone());
            if rows
                .insert(selector, pin.clone())
                .is_some_and(|old| old != *pin)
            {
                return Err(denied().into());
            }
        }
        Ok(rows.into_values().collect())
    }
}

fn compare_completed(
    old: &LineageUsedInputs,
    fresh: &LineageUsedInputs,
) -> Result<(), CollectionError> {
    let old_contexts = old.view_interpretations.as_ref().ok_or_else(denied)?;
    let fresh_contexts = fresh.view_interpretations.as_ref().ok_or_else(denied)?;
    if old.configuration != fresh.configuration
        || old.registries != fresh.registries
        || old.issuers.iter().any(|row| !fresh.issuers.contains(row))
        || old
            .disclosures
            .iter()
            .any(|row| !fresh.disclosures.contains(row))
        || old.controls.iter().any(|row| !fresh.controls.contains(row))
        || old.views.iter().any(|row| !fresh.views.contains(row))
        || old_contexts.iter().any(|row| !fresh_contexts.contains(row))
    {
        return Err(denied().into());
    }
    Ok(())
}

/// Independently completes every eligible selected source under the actual holder.
///
/// Missing per-view context only drops unsupported eligibility. Present evidence
/// must match fresh full visitation, current whole refs, actual Guard/backend and
/// genuine Original associations. No witness-only or aggregate trace is reused.
///
/// # Errors
/// Preserves complete history, index, metadata and Original failures. Refuses
/// changed selected evidence, stale loss/Guard/whole ref, mismatched completed
/// interpretation/dependencies, conflicting controls or lost Session authority.
pub(crate) async fn qualify<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &Session,
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &SelectedObservation<'_>,
    settings: (
        &super::native_collection_roots::QualifiedCollectionRoots<'_>,
        Option<&RetainedControls>,
    ),
) -> Result<CompletedSources, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let (current, retained) = settings;
    let mut completed = CompletedSources {
        lineages: Vec::new(),
        prior: Vec::new(),
        marks: BTreeSet::new(),
        inputs: Vec::new(),
        protected: Vec::new(),
        controls: Vec::new(),
    };
    for selected in &observed.state().sources {
        session.recheck()?;
        let read = held
            .selected_lineage_record(observed, &selected.name)
            .await?
            .ok_or_else(denied)?;
        let old = CheckedLineage::decode(read.bytes().ok_or_else(denied)?).map_err(|_| denied())?;
        completed.protected.push(read);
        if old.used.view_interpretations.is_none()
            || !old
                .used
                .check_supported_view_contexts()
                .map_err(|_| denied())?
        {
            continue;
        }
        let reference = held.ref_get(&selected.name).await?.ok_or_else(denied)?;
        let consumed = ConsumedResolver::new(guard, authority)?;
        consumed.registration(authority)?;
        let snapshot = consumed.snapshot_bytes()?;
        let registration = crate::guard::consumed_registration(authority);
        if old.source_name != selected.name
            || old.source != reference
            || old.commit_id != reference.commit
            || old.loss_generation != observed.state().loss_generation
            || old.guard_digest != *blake3::hash(&snapshot).as_bytes()
            || observed.state().guard != Some(old.guard_digest)
            || old.original != registration
            || old.controls.iter().any(|pin| pin.owner != registration)
        {
            return Err(denied().into());
        }
        let history = crate::guard::collection_authority::historical_guard(
            guard,
            held,
            observed,
            session,
            session.clock()?,
        )?;
        if let Some(retained) = retained {
            history.retain_original_controls(retained)?;
        }
        let qualified = super::native_collection_roots::source(
            &history,
            &consumed,
            held,
            observed,
            session,
            (&selected.name, current),
        )
        .await?;
        let Some(qualified) = qualified else {
            // An expired lease head remains an ordinary metadata witness;
            // it cannot manufacture a live tree or source carry eligibility.
            continue;
        };
        let mut state = roots::initial(qualified.snapshot());
        let mut marks = BTreeSet::new();
        let observation = HistoryObservation::held(observed.identity()).tracked(&consumed);
        while !state.pending.is_empty() {
            session.recheck()?;
            walk::expand(
                &history,
                &consumed,
                observation,
                &qualified,
                &mut state,
                &mut marks,
            )
            .await?;
        }
        let verified = qualified
            .history(&reference.commit)?
            .ok_or_else(denied)?
            .tree();
        let commit_bytes = verified.commit.commit().encode().map_err(|_| denied())?;
        if verified.commit.identity() != old.commit_id || commit_bytes != old.commit_bytes {
            return Err(denied().into());
        }
        let used = consumed.finish()?;
        compare_completed(&old.used, &used)?;
        if used.controls.iter().any(|pin| pin.owner != registration) {
            return Err(denied().into());
        }
        for identity in history.store().identities()? {
            marks.insert(identity.terrane_v1_digest().map_err(|_| denied())?);
        }
        completed
            .inputs
            .extend(qualified.current_inputs()?.iter().cloned());
        completed.inputs.extend(history.store().reads()?);
        completed.marks.extend(marks);
        completed.controls.extend(used.controls.iter().cloned());
        let lineage = CheckedLineage {
            source_name: selected.name.clone(),
            source: reference,
            commit_id: verified.commit.identity(),
            commit_bytes,
            guard_digest: old.guard_digest,
            loss_generation: observed
                .state()
                .loss_generation
                .checked_add(1)
                .ok_or_else(denied)?,
            controls: used.controls.clone(),
            original: registration,
            used,
        };
        let bytes = lineage.encode().map_err(|_| denied())?;
        completed.prior.push(selected.clone());
        completed.lineages.push((
            SourceLineage {
                name: selected.name.clone(),
                digest: *blake3::hash(&bytes).as_bytes(),
            },
            bytes,
        ));
        observed.revalidate().await?;
        session.recheck()?;
    }
    completed.controls = completed.merge_controls(&[])?;
    Ok(completed)
}
