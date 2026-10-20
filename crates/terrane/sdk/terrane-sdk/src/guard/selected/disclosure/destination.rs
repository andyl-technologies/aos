//! Installs source-derived public trust under independently checked destination authority.
//!
//! Only the paired producer calls this transition. Ordinary native reopening
//! still requires complete equality with the selected configuration snapshot.

use super::{DisclosureSource, invalid};
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, OriginalAuthority};
use crate::repository::local_authority::{
    import_binding::ImportBindingRecord,
    public_trust::PublicTrustRecord,
    retention::{self, ImportRecord, Record},
};
use crate::selected_bridge::{CheckedEvidence, CheckedMutation, OwnedFinalCheck};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use terrane_format::gc::publication::evidence::{DisclosureRow, GuardSnapshot};

#[cfg(all(feature = "tokio", unix))]
#[path = "destination/transition.rs"]
mod transition;
#[cfg(all(feature = "tokio", unix))]
pub(crate) use transition::GuardTransition;

/// Contains only records derived from freshly checked original and signer contexts.
#[derive(Clone)]
struct ImportPlan {
    import: ImportRecord,
    binding: ImportBindingRecord,
    trust: PublicTrustRecord,
}

/// Borrows request data and preserves the original destination operation timing.
pub(super) struct DestinationRequest<'request> {
    /// Actual destination writer-session reference, independently of source references.
    pub(super) reference: &'request str,
    /// Capability chain requiring fresh destination Commit authorization.
    pub(super) token: &'request [u8],
    /// Actual destination paths whose root ACLs authorize the complete candidate.
    pub(super) paths: &'request [Vec<u8>],
    /// Destination consumer surface checked against capability caveats.
    pub(super) surface: &'request str,
    /// Exact whole destination head observed for the paired selected transition.
    pub(super) expected: Option<&'request terrane_format::refs::RefRecord>,
    /// Monotonic start of the original publication attempt, including preloading.
    pub(super) started: std::time::Duration,
    /// Original publication deadlines retained through both final authority checks.
    pub(super) timing: crate::ref_advance::CommitTiming,
}

/// Selects the exact added public mappings while retaining both actual owners.
///
/// # Errors
/// Rejects different principals, stale selected configuration, altered original
/// controls, conflicting imports, changed physical bindings or expired requests.
pub(super) async fn install<'held, F, B, V, C, D>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    destination: &Guard<HeldBucket<'held, F, B, V, true>, D>,
    observed: &SelectedObservation<'held>,
    source_observed: &SelectedObservation<'held>,
    source: &mut DisclosureSource<'_, F>,
    request: DestinationRequest<'_>,
) -> Result<(), StoreFailure>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    let mut selected_reads =
        super::super::capture_selected_reads(destination.store(), observed, &[]).await?;
    selected_reads.extend(
        source
            .selected_reads
            .iter()
            .map(|read| super::super::selected_control_read(source_observed, read.clone())),
    );
    let principal = source.requests.first().ok_or_else(invalid)?;
    let authority = concrete.configured_original_authority()?;
    let plans = import_plans(source, &authority)?;
    let before = ConsumedResolver::new(destination, &authority)?;
    before.registration(&authority)?;
    #[cfg(all(feature = "tokio", unix))]
    let transition = GuardTransition::capture(
        concrete,
        destination,
        &authority,
        transition::CaptureScope {
            destination: observed,
            source: source_observed,
            resolver: &before,
        },
        source,
        &plans,
        &request,
    )
    .await?;
    let before_observation = HistoryObservation::held(observed.identity()).tracked(&before);
    #[cfg(all(feature = "tokio", unix))]
    let before_observation = before_observation.paired_transition(&transition);
    let current = destination
        .authorize_observed(
            request.reference,
            request.token,
            terrane_format::auth::Verb::Commit,
            request.paths,
            request.surface,
            before_observation,
        )
        .await?;
    if !current.same_principal(principal) || current.record() != request.expected {
        return Err(invalid());
    }
    before.operation(&current)?;
    let requests = [current];
    #[cfg(all(feature = "tokio", unix))]
    drop(transition);
    let mut controls =
        hold_paired_controls(concrete, &authority, destination, observed, &before, &plans).await?;
    let previous_snapshot = controls.snapshot.clone();
    let destination_check =
        super::super::retain_final_check(destination, &requests, request.started, request.timing)?;
    let source_check = source.final_check.clone();
    let final_check = OwnedFinalCheck {
        check: super::super::SharedCheck::new(move || {
            destination_check.recheck()?;
            source_check.recheck()
        }),
    };
    let owner = destination.store().operator_uid(observed).await?;
    if concrete.store().publication_operator_uid() != Some(owner) {
        return Err(invalid());
    }

    let mut imports = Vec::new();
    for plan in &plans {
        final_check.recheck()?;
        source.controls.exclusion.revalidate().await?;
        source_observed.revalidate().await?;
        controls.exclusion.revalidate().await?;
        observed.revalidate().await?;

        retain(
            destination.store().fs(),
            authority.control(),
            owner,
            &plan.import,
        )
        .await?;
        retain(
            destination.store().fs(),
            authority.control(),
            owner,
            &plan.binding,
        )
        .await?;
        retain(
            destination.store().fs(),
            authority.control(),
            owner,
            &plan.trust,
        )
        .await?;
        imports.push(plan.import.clone());
    }

    // Native verification acquires protected configuration exclusion itself.
    // The two actual namespace exclusions and source controls remain held.
    drop(controls);
    for import in &imports {
        let identity = observed.identity();
        let checked = concrete
            .load_original_import_held(&authority, import, identity)
            .await?;
        let borrowed = destination
            .load_original_import_held(&authority, import, identity)
            .await?;
        if checked != borrowed {
            return Err(invalid());
        }
    }
    let after = ConsumedResolver::new(destination, &authority)?;
    after.registration(&authority)?;
    #[cfg(all(feature = "tokio", unix))]
    let transition = GuardTransition::capture(
        concrete,
        destination,
        &authority,
        transition::CaptureScope {
            destination: observed,
            source: source_observed,
            resolver: &after,
        },
        source,
        &plans,
        &request,
    )
    .await?;
    let after_observation = HistoryObservation::held(observed.identity()).tracked(&after);
    #[cfg(all(feature = "tokio", unix))]
    let after_observation = after_observation.paired_transition(&transition);
    let refreshed = destination
        .authorize_observed(
            request.reference,
            request.token,
            terrane_format::auth::Verb::Commit,
            request.paths,
            request.surface,
            after_observation,
        )
        .await?;
    if !refreshed.same_principal(principal) || refreshed.record() != request.expected {
        return Err(invalid());
    }
    after.operation(&refreshed)?;
    let refreshed_check = super::super::retain_final_check(
        destination,
        &[refreshed],
        request.started,
        request.timing,
    )?;
    let preceding_check = final_check;
    let final_check = OwnedFinalCheck {
        check: super::super::SharedCheck::new(move || {
            preceding_check.recheck()?;
            refreshed_check.recheck()
        }),
    };
    for import in &imports {
        after.original(&destination.original_commit(&import.association.commit)?)?;
    }
    let snapshot = after.snapshot_bytes()?;
    check_transition(&previous_snapshot, &snapshot, &plans)?;
    #[cfg(all(feature = "tokio", unix))]
    drop(transition);
    let inputs = after.finish()?;
    let mut controls = concrete
        .hold_original_registration(&authority, observed.identity())
        .await?;
    concrete
        .check_retained_trust_controls(
            &authority,
            &mut controls,
            &terrane_format::gc::publication::evidence::GuardSnapshot::decode(&snapshot)
                .map_err(|_| invalid())?,
        )
        .await?;
    let mut records = Vec::new();
    for pin in &inputs.controls {
        if pin.owner != crate::guard::consumed_registration(&authority) {
            return Err(invalid());
        }
        let bytes = controls.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
        records.push((pin.key.clone(), bytes));
    }
    for role in concrete.configured_disclosure_roles()? {
        records.push((
            role.selector().map_err(crate::guard::retention_failure)?,
            role.encode().map_err(crate::guard::retention_failure)?,
        ));
    }
    let retained = controls.retain_named(&records).await?;
    let carry = super::super::guard_carry::prepare(
        concrete,
        destination,
        &authority,
        observed,
        &mut controls,
    )
    .await?;
    if carry.snapshot() != snapshot.as_slice() {
        return Err(invalid());
    }
    let super::super::guard_carry::GuardCarryParts {
        lineages: carried,
        controls: carry_controls,
        selected_reads: carry_reads,
        final_check: carry_check,
    } = carry.into_parts();
    selected_reads.extend(carry_reads);
    let preceding_check = final_check;
    let final_check = OwnedFinalCheck {
        check: super::super::SharedCheck::new(move || {
            preceding_check.recheck()?;
            carry_check.recheck()
        }),
    };
    let mut source_records = Vec::new();
    for pin in &source.controls.used.controls {
        let bytes = source.controls.exclusion.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
        source_records.push((pin.key.clone(), bytes));
    }
    source_records.extend(
        source
            .signer
            .retained_records()
            .map_err(crate::guard::retention_failure)?,
    );
    let source_retained = source
        .controls
        .exclusion
        .retain_named(&source_records)
        .await?;
    let mut next = observed.state().clone();
    next.revision = next.revision.checked_add(1).ok_or_else(invalid)?;
    next.guard = Some(*blake3::hash(&snapshot).as_bytes());
    next.sources = carried
        .iter()
        .map(|carried| terrane_format::gc::publication::SourceLineage {
            name: carried.previous().name.clone(),
            digest: *blake3::hash(carried.lineage()).as_bytes(),
        })
        .collect();
    final_check.recheck()?;
    source.controls.exclusion.revalidate().await?;
    #[cfg(all(test, feature = "tokio"))]
    if selection_faults()
        .lock()
        .map_err(|_| invalid())?
        .remove(authority.root())
    {
        return Err(invalid());
    }
    destination
        .store()
        .publish_checked(CheckedMutation {
            observed,
            sources: vec![source_observed],
            next,
            changes: Vec::new(),
            evidence: CheckedEvidence::Guard { snapshot, carried },
            final_check: Box::new(|| final_check.recheck()),
            effect_context: Some(super::super::GuardEffectContext {
                existing_reads: Vec::new(),
                final_check: final_check.clone(),
                controls: vec![retained, source_retained, carry_controls],
                selected_reads,
                publication_original: None,
            }),
        })
        .await?;
    #[cfg(all(test, feature = "tokio"))]
    super::super::guard_carry::observe_install(concrete);
    controls.revalidate().await?;
    source.controls.exclusion.revalidate().await?;
    Ok(())
}

#[cfg(all(test, feature = "tokio"))]
fn selection_faults() -> &'static std::sync::Mutex<std::collections::BTreeSet<std::path::PathBuf>> {
    static FAULTS: std::sync::Mutex<std::collections::BTreeSet<std::path::PathBuf>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    &FAULTS
}

/// Interrupts one genuine import transition immediately before Guard selection.
///
/// # Errors
/// Rejects unavailable test synchronization or a duplicate armed interruption.
#[cfg(all(test, feature = "tokio"))]
pub(super) fn interrupt_next_selection(root: &std::path::Path) -> Result<(), StoreFailure> {
    if !selection_faults()
        .lock()
        .map_err(|_| invalid())?
        .insert(root.to_owned())
    {
        return Err(invalid());
    }
    Ok(())
}

async fn retain<F: LocalFs + Sync, R: Record>(
    fs: &F,
    directory: &std::path::Path,
    owner: u32,
    record: &R,
) -> Result<(), StoreFailure> {
    retention::retain(
        fs,
        directory,
        owner,
        &record.selector().map_err(crate::guard::retention_failure)?,
        record,
        false,
    )
    .await
    .map_err(crate::guard::retention_failure)
}

/// Derives complete expected imports without consulting destination presence.
fn import_plans<F: LocalFs>(
    source: &DisclosureSource<'_, F>,
    destination: &OriginalAuthority,
) -> Result<Vec<ImportPlan>, StoreFailure> {
    let mut plans = Vec::new();
    for original in &source.originals {
        let import = original.retained_import_record()?;
        let import_digest =
            *blake3::hash(&import.encode().map_err(crate::guard::retention_failure)?).as_bytes();
        let binding = ImportBindingRecord {
            commit: *original.commit(),
            source_authority: *original.baseline().authority().id(),
            destination_authority: *destination.id(),
            import_digest,
        };
        let mut issuer_keys = match original.historical_keys()? {
            Some(keys) => keys,
            None if original.baseline().authority() == &source.authority => {
                source.issuer_keys.clone()
            }
            None => return Err(invalid()),
        };
        issuer_keys.sort_by(|left, right| {
            (&left.issuer, &left.key_id).cmp(&(&right.issuer, &right.key_id))
        });
        let mut roles = original.historical_disclosure_roles()?.unwrap_or_default();
        roles.push(source.signer.role().clone());
        roles.sort_by(|left, right| {
            (
                &left.repository,
                &left.domain,
                left.public_key,
                left.not_before,
            )
                .cmp(&(
                    &right.repository,
                    &right.domain,
                    right.public_key,
                    right.not_before,
                ))
        });
        roles.dedup();
        let trust = PublicTrustRecord {
            import_digest,
            source_authority: binding.source_authority,
            destination_authority: binding.destination_authority,
            issuer_keys,
            disclosure_roles: roles,
        };
        binding
            .validate_pair(&import, destination.id())
            .map_err(crate::guard::retention_failure)?;
        trust.validate().map_err(crate::guard::retention_failure)?;
        plans.push(ImportPlan {
            import,
            binding,
            trust,
        });
    }
    Ok(plans)
}

/// Recovers only a cached transition independently authorized by this held pair.
///
/// DOM-24 requires freshly captured source Read and destination Commit before
/// this call. PROV-26/27 require the exact source signer and independently checked
/// originals in `plans`; their physical controls stay retained by the caller.
/// PROV-28/29/31 and AUTH-26/28/29/30 remain ordinary candidate checks. No
/// selection occurs here, and ordinary startup and control capture remain strict.
async fn hold_paired_controls<'guard, F, B, V, C, D>(
    concrete: &'guard Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    destination: &Guard<HeldBucket<'_, F, B, V, true>, D>,
    observed: &SelectedObservation<'_>,
    consumed: &ConsumedResolver,
    plans: &[ImportPlan],
) -> Result<super::super::LocalControlInputs<'guard, F>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    observed.revalidate().await?;
    let snapshot = consumed.snapshot_bytes()?;
    let selected = destination
        .store()
        .selected_guard_snapshot(observed)
        .await?
        .ok_or_else(invalid)?;
    if selected == snapshot {
        // Installation mutates protected import records even when the current
        // Guard snapshot already matches. Retained readers can outlive their
        // backend holder, so namespace exclusion cannot replace a writer lock.
        let controls = concrete
            .hold_original_registration_write(authority, observed.identity())
            .await?;
        return super::super::refresh_consumed_controls(
            concrete,
            authority,
            destination.store(),
            observed,
            consumed,
            controls,
        )
        .await;
    }
    check_transition(&selected, &snapshot, plans)?;
    let selected = GuardSnapshot::decode(&selected).map_err(|_| invalid())?;

    // Every installed carrier of an added role must be this pair's exact
    // expected import. Re-read its physical records before taking exclusion;
    // consumed pins then bind those same bytes throughout the transition.
    for trust in destination.retained_public_trust()? {
        if !trust
            .disclosure_roles
            .iter()
            .any(|role| !selected.disclosures.contains(&role_row(role)))
        {
            continue;
        }
        let trust_bytes = trust.encode().map_err(crate::guard::retention_failure)?;
        let mut matching = None;
        for plan in plans {
            if plan
                .trust
                .encode()
                .map_err(crate::guard::retention_failure)?
                == trust_bytes
            {
                matching = Some(plan);
                break;
            }
        }
        let plan = matching.ok_or_else(invalid)?;
        let checked = concrete
            .load_original_import_held(authority, &plan.import, observed.identity())
            .await?;
        let borrowed = destination
            .load_original_import_held(authority, &plan.import, observed.identity())
            .await?;
        let checked_trust = PublicTrustRecord {
            import_digest: plan.trust.import_digest,
            source_authority: plan.trust.source_authority,
            destination_authority: plan.trust.destination_authority,
            issuer_keys: borrowed.historical_keys()?.ok_or_else(invalid)?,
            disclosure_roles: borrowed
                .historical_disclosure_roles()?
                .ok_or_else(invalid)?,
        };
        if checked != borrowed
            || borrowed.retained_import_record()? != plan.import
            || checked_trust
                .encode()
                .map_err(crate::guard::retention_failure)?
                != trust_bytes
        {
            return Err(invalid());
        }
        consumed.original(&borrowed)?;
    }

    let mut controls = concrete
        .hold_original_registration_write(authority, observed.identity())
        .await?;
    if ConsumedResolver::new(destination, authority)?.snapshot_bytes()? != snapshot {
        return Err(invalid());
    }
    concrete
        .check_retained_trust_controls(
            authority,
            &mut controls,
            &GuardSnapshot::decode(&snapshot).map_err(|_| invalid())?,
        )
        .await?;
    let used = consumed.finish()?;
    for pin in &used.controls {
        if pin.owner != crate::guard::consumed_registration(authority) {
            return Err(invalid());
        }
        pin.check_record(&controls.read_record(&pin.key).await?)
            .map_err(|_| invalid())?;
    }
    controls.revalidate().await?;
    observed.revalidate().await?;
    Ok(super::super::LocalControlInputs {
        exclusion: controls,
        snapshot,
        used,
    })
}

fn role_row(
    role: &crate::repository::local_authority::public_trust::DisclosureRoleRecord,
) -> DisclosureRow {
    DisclosureRow {
        repository: role.repository.clone(),
        domain: role.domain.clone(),
        public_key: role.public_key,
        not_before: role.not_before,
        not_after: role.not_after,
    }
}

/// Allows only exact freshly source-derived additions to the dedicated role set.
fn check_transition(before: &[u8], after: &[u8], plans: &[ImportPlan]) -> Result<(), StoreFailure> {
    let before = GuardSnapshot::decode(before).map_err(|_| invalid())?;
    let after = GuardSnapshot::decode(after).map_err(|_| invalid())?;
    if before.registration != after.registration
        || before.issuers != after.issuers
        || before.configuration != after.configuration
        || before.registries != after.registries
        || before
            .disclosures
            .iter()
            .any(|role| !after.disclosures.contains(role))
        || after.disclosures.iter().any(|role| {
            !before.disclosures.contains(role)
                && !plans.iter().any(|plan| {
                    plan.trust
                        .disclosure_roles
                        .iter()
                        .any(|expected| role_row(expected) == *role)
                })
        })
    {
        return Err(invalid());
    }
    Ok(())
}
