//! Installs source-derived public trust under independently checked destination authority.
//!
//! Only the paired producer calls this transition. Ordinary native reopening
//! still requires complete equality with the selected configuration snapshot.

use super::{DisclosureSource, invalid};
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::repository::local_authority::{
    import_binding::ImportBindingRecord,
    public_trust::PublicTrustRecord,
    retention::{self, Record},
};
use crate::selected_bridge::{CheckedEvidence, CheckedMutation, OwnedFinalCheck};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};

/// Borrows request data that still requires actual destination authorization.
pub(super) struct DestinationRequest<'request> {
    pub(super) reference: &'request str,
    pub(super) token: &'request [u8],
    pub(super) paths: &'request [Vec<u8>],
    pub(super) surface: &'request str,
    pub(super) expected: Option<&'request terrane_core::refs::RefRecord>,
}

/// Selects the exact added public mappings while retaining both actual owners.
///
/// # Errors
/// Rejects different principals, stale selected configuration, altered original
/// controls, conflicting imports, changed physical bindings or expired requests.
pub(super) async fn install<'held, F, B, V, C, D>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    destination: &Guard<HeldBucket<'_, F, B, V, true>, D>,
    observed: &SelectedObservation<'held>,
    source_observed: &SelectedObservation<'held>,
    source: &mut DisclosureSource<'_, F>,
    request: DestinationRequest<'_>,
    started: std::time::Duration,
    timing: crate::ref_advance::CommitTiming,
) -> Result<(), StoreFailure>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    let principal = source.requests.first().ok_or_else(invalid)?.subject();
    let authority = concrete.configured_original_authority()?;
    let before = ConsumedResolver::new(destination, &authority)?;
    before.registration(&authority)?;
    let current = destination
        .authorize_observed(
            request.reference,
            request.token,
            terrane_core::auth::Verb::Commit,
            request.paths,
            request.surface,
            HistoryObservation::held(observed.identity()).tracked(&before),
        )
        .await?;
    if current.subject() != principal || current.record() != request.expected {
        return Err(invalid());
    }
    before.operation(&current)?;
    let requests = [current];
    let mut controls = super::super::hold_consumed_controls(
        concrete,
        &authority,
        destination.store(),
        observed,
        &before,
    )
    .await?;
    let previous_snapshot = controls.snapshot.clone();
    let destination_check =
        super::super::retain_final_check(destination, &requests, started, timing)?;
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
    for original in &source.originals {
        final_check.recheck()?;
        source.controls.exclusion.revalidate().await?;
        source_observed.revalidate().await?;
        controls.exclusion.revalidate().await?;
        observed.revalidate().await?;

        let import = original.retained_import_record()?;
        let import_digest =
            *blake3::hash(&import.encode().map_err(crate::guard::retention_failure)?).as_bytes();
        let binding = ImportBindingRecord {
            commit: *original.commit(),
            source_authority: *original.baseline().authority().id(),
            destination_authority: *authority.id(),
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
            .validate_pair(&import, authority.id())
            .map_err(crate::guard::retention_failure)?;
        trust.validate().map_err(crate::guard::retention_failure)?;
        retain(
            destination.store().fs(),
            authority.control(),
            owner,
            &import,
        )
        .await?;
        retain(
            destination.store().fs(),
            authority.control(),
            owner,
            &binding,
        )
        .await?;
        retain(destination.store().fs(), authority.control(), owner, &trust).await?;
        imports.push(import);
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
    let refreshed = destination
        .authorize_observed(
            request.reference,
            request.token,
            terrane_core::auth::Verb::Commit,
            request.paths,
            request.surface,
            HistoryObservation::held(observed.identity()).tracked(&after),
        )
        .await?;
    if refreshed.subject() != principal || refreshed.record() != request.expected {
        return Err(invalid());
    }
    after.operation(&refreshed)?;
    let refreshed_check =
        super::super::retain_final_check(destination, &[refreshed], started, timing)?;
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
    check_transition(&previous_snapshot, &snapshot)?;
    let inputs = after.finish()?;
    let mut controls = concrete
        .hold_original_registration(&authority, observed.identity())
        .await?;
    concrete
        .check_retained_trust_controls(
            &authority,
            &mut controls,
            &terrane_core::gc::publication::evidence::GuardSnapshot::decode(&snapshot)
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
    next.sources.clear();
    final_check.recheck()?;
    source.controls.exclusion.revalidate().await?;
    destination
        .store()
        .publish_checked(CheckedMutation {
            observed,
            sources: vec![source_observed],
            next,
            changes: Vec::new(),
            evidence: CheckedEvidence::Guard { snapshot },
            final_check: Box::new(|| final_check.recheck()),
            effect_context: Some(super::super::GuardEffectContext {
                final_check: final_check.clone(),
                controls: vec![retained, source_retained],
            }),
        })
        .await?;
    controls.revalidate().await?;
    source.controls.exclusion.revalidate().await?;
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

/// Allows only source-derived additions to the dedicated disclosure role set.
fn check_transition(before: &[u8], after: &[u8]) -> Result<(), StoreFailure> {
    use terrane_core::gc::publication::evidence::GuardSnapshot;
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
    {
        return Err(invalid());
    }
    Ok(())
}
