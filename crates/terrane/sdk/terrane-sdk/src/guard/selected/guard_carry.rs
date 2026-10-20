//! Preserves genuinely selected completed sources through an explicit Guard update.
//!
//! Only the paired disclosure publisher calls this factory while its actual
//! destination namespace and Original controls remain excluded. Old lineage
//! supplies prior completion, never current interpretation, Original or actor
//! authority. Fresh carried bytes change only their selected Guard digest.

use std::collections::BTreeMap;

use terrane_format::gc::publication::evidence::{
    CheckedLineage, GuardSnapshot, RequiredControlPin,
};

use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{
    ConsumedResolver, ControlExclusion, Guard, OriginalAuthority, RetainedControls,
    consumed_registration, invalid,
};
use crate::selected_bridge::{GuardCarriedLineage, OwnedFinalCheck};
use crate::store::{Clock, ContentValidator, LocalFs, RefStore, StoreFailure};

use super::{SelectedControlRead, SharedCheck, selected_control_read};

#[path = "guard_carry/source.rs"]
mod source;

#[cfg(all(test, feature = "tokio"))]
#[path = "guard_carry/observations.rs"]
pub(super) mod observations;

/// Owns the genuinely checked carry result and actual post-update snapshot.
pub(super) struct PreparedGuardCarry {
    snapshot: Vec<u8>,
    parts: GuardCarryParts,
}

impl PreparedGuardCarry {
    /// Borrows the snapshot independently derived from the held current Guard.
    pub(super) fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }

    /// Transfers checked carry data and actual retained receipts to the publisher.
    pub(super) fn into_parts(self) -> GuardCarryParts {
        self.parts
    }
}

/// Retains exact checked dependencies through native durable acknowledgment.
pub(super) struct GuardCarryParts {
    /// Fresh immutable bodies paired with their actual prior selected selectors.
    pub(super) lineages: Vec<GuardCarriedLineage>,
    /// Actual Original controls held during qualification and final native checks.
    pub(super) controls: RetainedControls,
    /// Actual previous Guard and every retained prior lineage physical preimage.
    pub(super) selected_reads: Vec<SelectedControlRead>,
    /// Current configuration and independently selected per-view final comparison.
    pub(super) final_check: OwnedFinalCheck,
}

/// Checks selected completed sources against the genuinely installed new Guard.
///
/// Missing optional per-view context explicitly drops that source's eligibility.
/// It never initializes a Legacy selection or repairs prior completion. Present
/// unsupported data and all qualification failures retain their typed refusal.
/// The enclosing publisher independently retains its actual current requests.
///
/// # Errors
/// Rejects stale selected heads or loss generation, malformed or unsupported
/// evidence, changed used trust or profiles, unavailable or changed Original
/// contexts, unsafe protected controls and originating storage failures.
pub(super) async fn prepare<'guard, 'held, F, B, V, C, D>(
    concrete: &'guard Guard<FileBucket<F, B, V>, C>,
    current: &Guard<HeldBucket<'held, F, B, V, true>, D>,
    authority: &OriginalAuthority,
    observed: &SelectedObservation<'held>,
    controls: &mut ControlExclusion<'guard, F>,
) -> Result<PreparedGuardCarry, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    #[cfg(all(test, feature = "tokio"))]
    let before = concrete.store().observe_content_for_tests().snapshot();

    let result = prepare_held(concrete, current, authority, observed, controls).await;

    #[cfg(all(test, feature = "tokio"))]
    observations::record(
        authority.root(),
        [before.node_gets, before.node_puts, before.node_decodes],
        {
            let after = concrete.store().observe_content_for_tests().snapshot();
            [after.node_gets, after.node_puts, after.node_decodes]
        },
        result.is_ok(),
        result
            .as_ref()
            .map(|prepared| {
                prepared
                    .parts
                    .lineages
                    .iter()
                    .map(|lineage| lineage.previous().name.clone())
                    .collect()
            })
            .unwrap_or_default(),
    );

    result
}

/// Closes test observation only after the caller's actual durable Guard ACK.
///
/// # Panics
/// Panics on missing/duplicate phase observation or poisoned test synchronization.
#[cfg(all(test, feature = "tokio"))]
pub(super) fn observe_install<F, B, V, C>(concrete: &Guard<FileBucket<F, B, V>, C>)
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let after = concrete.store().observe_content_for_tests().snapshot();
    observations::acknowledge(
        concrete.store().root(),
        [after.node_gets, after.node_puts, after.node_decodes],
    );
}

async fn prepare_held<'guard, 'held, F, B, V, C, D>(
    concrete: &'guard Guard<FileBucket<F, B, V>, C>,
    current: &Guard<HeldBucket<'held, F, B, V, true>, D>,
    authority: &OriginalAuthority,
    observed: &SelectedObservation<'held>,
    controls: &mut ControlExclusion<'guard, F>,
) -> Result<PreparedGuardCarry, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    observed.revalidate().await?;
    controls.revalidate().await?;
    if current.configured_original_authority()? != *authority
        || concrete.configured_original_authority()? != *authority
        || observed.identity().root() != authority.root()
        || observed.identity().physical_identity() != authority.physical_identity()
    {
        return Err(invalid());
    }

    let consumed = ConsumedResolver::new(current, authority)?;
    let snapshot = consumed.snapshot_bytes()?;
    if ConsumedResolver::new(concrete, authority)?.snapshot_bytes()? != snapshot {
        return Err(invalid());
    }
    let next_guard = GuardSnapshot::decode(&snapshot).map_err(|_| invalid())?;
    let prior_guard = current
        .store()
        .selected_guard_snapshot_record(observed)
        .await?
        .ok_or_else(invalid)?;
    let previous_bytes = prior_guard.bytes().ok_or_else(invalid)?;
    if observed.state().guard != Some(*blake3::hash(previous_bytes).as_bytes()) {
        return Err(invalid());
    }
    GuardSnapshot::decode(previous_bytes).map_err(|_| invalid())?;

    let mut selected_reads = vec![selected_control_read(observed, prior_guard.clone())];
    let mut candidates = Vec::new();
    let mut required = BTreeMap::<String, RequiredControlPin>::new();
    let retention_owner = consumed_registration(authority);
    for previous in &observed.state().sources {
        let record = current
            .store()
            .selected_lineage_record(observed, &previous.name)
            .await?
            .ok_or_else(invalid)?;
        let bytes = record.bytes().ok_or_else(invalid)?;
        let lineage = CheckedLineage::decode(bytes).map_err(|_| invalid())?;
        if *blake3::hash(bytes).as_bytes() != previous.digest
            || lineage.source_name != previous.name
            || current.store().ref_get(&previous.name).await?.as_ref() != Some(&lineage.source)
            || lineage.guard_digest != observed.state().guard.ok_or_else(invalid)?
            || lineage.loss_generation != observed.state().loss_generation
        {
            return Err(invalid());
        }
        lineage
            .check_guard_snapshot(previous_bytes)
            .map_err(|_| invalid())?;

        // This is the sole eligibility omission, determined before qualification.
        // A malformed or present unsupported context cannot take this branch.
        if !lineage
            .used
            .check_supported_view_contexts()
            .map_err(|_| invalid())?
        {
            continue;
        }
        source::check_used_guard(&lineage, &next_guard)?;
        for pin in &lineage.controls {
            // Foreign source Originals use independently checked imports whose
            // physical retention owner is this actual destination registration.
            if pin.owner != retention_owner {
                return Err(invalid());
            }
            if required.get(&pin.key).is_some_and(|old| old != pin) {
                return Err(invalid());
            }
            required.insert(pin.key.clone(), pin.clone());
        }
        selected_reads.push(selected_control_read(observed, record));
        candidates.push((previous.clone(), lineage));
    }

    let pins = required.into_values().collect::<Vec<_>>();
    let retained = controls.retain_used(&pins).await?;
    let configured = current.guard_carry_configuration_adapter()?;
    configured.retain_original_controls(&retained)?;
    let mut checked_sources = Vec::with_capacity(candidates.len());
    for (previous, lineage) in candidates {
        source::qualify(
            current,
            &configured,
            authority,
            observed,
            &retained,
            &lineage,
        )
        .await?;
        checked_sources.push((previous, lineage));
    }

    // Retain the original physical preimages, rather than refreshing away a
    // replacement with equal canonical bytes. Native publication refreshes these
    // receipts and all selected-read incarnations before its durable slot/ACK.
    source::check_controls(&retained, &controls.retain_used(&pins).await?)?;
    observed.revalidate().await?;
    controls.revalidate().await?;
    if ConsumedResolver::new(current, authority)?.snapshot_bytes()? != snapshot {
        return Err(invalid());
    }

    let next_digest = *blake3::hash(&snapshot).as_bytes();
    let mut lineages = Vec::with_capacity(checked_sources.len());
    let mut preserved = Vec::with_capacity(checked_sources.len());
    for (previous, mut lineage) in checked_sources {
        lineage.guard_digest = next_digest;
        lineage
            .check_guard_snapshot(&snapshot)
            .map_err(|_| invalid())?;
        lineages.push(GuardCarriedLineage {
            previous,
            encoded: lineage.encode().map_err(|_| invalid())?,
        });
        preserved.push(lineage);
    }
    let snapshot_disclosures = ConsumedResolver::snapshot_disclosure_inputs(current)?;
    let expected_snapshot = snapshot.clone();
    let final_authority = authority.clone();
    let final_check = OwnedFinalCheck {
        check: SharedCheck::new(move || {
            if ConsumedResolver::new_with_snapshot_disclosures(
                &configured,
                &final_authority,
                &snapshot_disclosures,
            )?
            .snapshot_bytes()?
                != expected_snapshot
            {
                return Err(invalid());
            }
            for lineage in &preserved {
                source::check_selected_inputs(&configured, lineage)?;
            }
            Ok(())
        }),
    };
    final_check.recheck()?;

    Ok(PreparedGuardCarry {
        snapshot,
        parts: GuardCarryParts {
            lineages,
            controls: retained,
            selected_reads,
            final_check,
        },
    })
}
