//! Selects fresh dedicated source keys while preserving completed native dependencies.
//!
//! The actual held source and current Admin decision own this transition.
//! Historical public role bytes remain immutable. A separately checked pending
//! Guard becomes the serving configuration only after the native durable ACK.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::bucket::held::SingleHeld;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, invalid};
use crate::repository::local_authority::{disclosure, retention::Record};
use crate::selected_bridge::{CheckedEvidence, CheckedMutation, OwnedFinalCheck};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::auth::Verb;
use terrane_format::gc::publication::evidence::{DisclosureRow, GuardSnapshot};

use super::{GuardEffectContext, SharedCheck, capture_selected_reads, guard_carry};

/// Publishes one exactly additive dedicated-key configuration under live Admin authority.
///
/// # Errors
/// Preserves current scope, token, whole-head, protected configuration, retained
/// dependency, issue-time and native durability failures without repairing state.
pub(crate) async fn rotate<F, B, V, C>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    reference: &str,
    token: &[u8],
    surface: &str,
    started: Duration,
    maximum: Duration,
) -> Result<[u8; 32], StoreFailure>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    if concrete
        .config()
        .policy_authority
        .as_deref()
        .is_some_and(|authority| authority != reference)
    {
        return Err(crate::guard::denied(reference, Verb::Admin));
    }
    let authority = concrete.configured_original_authority()?;
    let previous_roles = concrete.configured_disclosure_roles()?;
    let holder = SingleHeld::acquire(concrete.store()).await?;
    let held = holder.destination();
    let observed = held.observe_publication().await?;
    let old = concrete.held_guard(holder.destination(), retained_clock(concrete.clock())?)?;
    let before = ConsumedResolver::new(&old, &authority)?;
    before.registration(&authority)?;
    let paths = [b"/".to_vec()];
    let current = old
        .authorize_observed(
            reference,
            token,
            Verb::Admin,
            &paths,
            surface,
            HistoryObservation::held(observed.identity()).tracked(&before),
        )
        .await?;
    before.operation(&current)?;
    let previous_snapshot = before.snapshot_bytes()?;
    if held.selected_guard_snapshot(&observed).await?.as_deref()
        != Some(previous_snapshot.as_slice())
    {
        return Err(invalid());
    }
    let expected_head = current.record().cloned();
    let checks = old.retain_request_checks(std::slice::from_ref(&current), started, maximum)?;
    let before_check = OwnedFinalCheck {
        check: SharedCheck::new(move || checks.recheck()),
    };
    let before_inputs = before.finish()?;

    // Both full Admin/history authorizations use the genuinely selected old
    // Guard before any role effect. Installing the new protected role makes
    // the old inventory incomplete and does not yet select the candidate Guard.
    let refresh = ConsumedResolver::new(&old, &authority)?;
    refresh.registration(&authority)?;
    let refreshed = old
        .authorize_observed(
            reference,
            token,
            Verb::Admin,
            &paths,
            surface,
            HistoryObservation::held(observed.identity()).tracked(&refresh),
        )
        .await?;
    if refreshed.record() != expected_head.as_ref() || !refreshed.same_principal(&current) {
        return Err(invalid());
    }
    refresh.operation(&refreshed)?;
    if refresh.snapshot_bytes()? != previous_snapshot {
        return Err(invalid());
    }
    let refreshed_inputs = refresh.finish()?;
    let refresh_checks =
        old.retain_request_checks(std::slice::from_ref(&refreshed), started, maximum)?;
    let preceding = before_check;
    let before_check = OwnedFinalCheck {
        check: SharedCheck::new(move || {
            preceding.recheck()?;
            refresh_checks.recheck()
        }),
    };

    let mut selected_reads = capture_selected_reads(&held, &observed, &[]).await?;
    let mut controls = concrete
        .hold_original_registration_write(&authority, observed.identity())
        .await?;
    concrete
        .check_retained_trust_controls(
            &authority,
            &mut controls,
            &GuardSnapshot::decode(&previous_snapshot).map_err(|_| invalid())?,
        )
        .await?;
    for pin in before_inputs
        .controls
        .iter()
        .chain(&refreshed_inputs.controls)
    {
        if pin.owner != crate::guard::consumed_registration(&authority) {
            return Err(invalid());
        }
        pin.check_record(&controls.read_record(&pin.key).await?)
            .map_err(|_| invalid())?;
    }
    before_check.recheck()?;
    observed.revalidate().await?;

    let signer = disclosure::prepare_rotation(concrete, &authority, &mut controls, &before_check)
        .await
        .map_err(crate::guard::retention_failure)?;
    let candidate = concrete.disclosure_rotation_adapter(retained_clock(concrete.clock())?)?;
    let records = signer
        .retained_records()
        .map_err(crate::guard::retention_failure)?;
    let seed_name = records
        .iter()
        .find(|(name, _)| name.ends_with(".seed"))
        .map(|(name, _)| name.as_str())
        .ok_or_else(invalid)?;
    candidate
        .install_checked_disclosure_rotation(&authority, signer.role(), seed_name, &mut controls)
        .await?;
    before_check.recheck()?;
    controls.revalidate().await?;
    drop(controls);

    // The candidate is proposed configuration, never a selected authorization
    // scope. Its only permitted change is the checked additive role below; the
    // namespace exclusion preserves the old head, ACL and immutable history.
    let pending = candidate.held_guard(holder.destination(), retained_clock(candidate.clock())?)?;
    let after = ConsumedResolver::new(&pending, &authority)?;
    after.registration(&authority)?;
    after.operation(&refreshed)?;
    let checks = pending.retain_request_checks(&[refreshed], started, maximum)?;
    let issue_clock = retained_clock(pending.clock())?;
    let not_before = signer.role().not_before;
    let final_check = OwnedFinalCheck {
        check: SharedCheck::new(move || {
            before_check.recheck()?;
            checks.recheck()?;
            if issue_clock
                .now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| invalid())?
                .as_secs()
                < not_before
            {
                return Err(invalid());
            }
            Ok(())
        }),
    };
    let snapshot = after.snapshot_bytes()?;
    check_transition(&previous_snapshot, &snapshot, signer.role())?;
    let candidate_inputs = after.finish()?;
    let mut controls = candidate
        .hold_original_registration_write(&authority, observed.identity())
        .await?;
    candidate
        .check_retained_trust_controls(
            &authority,
            &mut controls,
            &GuardSnapshot::decode(&snapshot).map_err(|_| invalid())?,
        )
        .await?;
    let mut retained_records = BTreeMap::new();
    // Keep both genuine completed-history input sets independent, including
    // their Recorded view interpretations; union only their physical pin needs.
    for pin in before_inputs
        .controls
        .iter()
        .chain(&refreshed_inputs.controls)
        .chain(&candidate_inputs.controls)
    {
        if pin.owner != crate::guard::consumed_registration(&authority) {
            return Err(invalid());
        }
        let bytes = controls.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
        if retained_records
            .insert(pin.key.clone(), bytes.clone())
            .is_some_and(|previous| previous != bytes)
        {
            return Err(invalid());
        }
    }
    for role in candidate.configured_disclosure_roles()? {
        retained_records.insert(
            role.selector().map_err(crate::guard::retention_failure)?,
            role.encode().map_err(crate::guard::retention_failure)?,
        );
    }
    for (name, bytes) in records {
        if retained_records
            .insert(name, bytes.clone())
            .is_some_and(|previous| previous != bytes)
        {
            return Err(invalid());
        }
    }
    let retained = controls
        .retain_named(&retained_records.into_iter().collect::<Vec<_>>())
        .await?;
    let carry =
        guard_carry::prepare(&candidate, &pending, &authority, &observed, &mut controls).await?;
    if carry.snapshot() != snapshot.as_slice() {
        return Err(invalid());
    }
    let guard_carry::GuardCarryParts {
        lineages: carried,
        controls: carry_controls,
        selected_reads: carry_reads,
        final_check: carry_check,
    } = carry.into_parts();
    // Rotation cannot silently drop an existing completed source whose context
    // is too old for carry. Such a source needs explicit requalification first.
    if carried.len() != observed.state().sources.len()
        || carried
            .iter()
            .zip(&observed.state().sources)
            .any(|(carried, source)| carried.previous() != source)
    {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported));
    }
    selected_reads.extend(carry_reads);
    let preceding = final_check;
    let final_check = OwnedFinalCheck {
        check: SharedCheck::new(move || {
            preceding.recheck()?;
            carry_check.recheck()
        }),
    };
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
    controls.revalidate().await?;
    observed.revalidate().await?;
    held.publish_checked(CheckedMutation {
        observed: &observed,
        sources: Vec::new(),
        next,
        changes: Vec::new(),
        evidence: CheckedEvidence::Guard { snapshot, carried },
        final_check: Box::new(|| final_check.recheck()),
        effect_context: Some(GuardEffectContext {
            existing_reads: Vec::new(),
            final_check: final_check.clone(),
            controls: vec![retained, carry_controls],
            selected_reads,
            publication_original: None,
        }),
    })
    .await?;
    #[cfg(all(test, feature = "tokio"))]
    guard_carry::observe_install(&candidate);
    controls.revalidate().await?;
    concrete.adopt_disclosure_rotation(&candidate, &previous_roles)?;
    Ok(signer.role().public_key)
}

fn retained_clock<C: Clock>(clock: &C) -> Result<crate::store::NativeEffectClock, StoreFailure> {
    clock.retain_native_clock().map_err(|error| {
        let kind = if error.kind() == std::io::ErrorKind::Unsupported {
            StoreErrorKind::Unsupported
        } else {
            StoreErrorKind::Unavailable { retry_after: None }
        };
        StoreFailure::with_source(kind, error)
    })
}

/// Limits the complete snapshot delta to the exact freshly checked public role.
fn check_transition(
    previous: &[u8],
    next: &[u8],
    role: &crate::repository::local_authority::public_trust::DisclosureRoleRecord,
) -> Result<(), StoreFailure> {
    let mut expected = GuardSnapshot::decode(previous).map_err(|_| invalid())?;
    let row = DisclosureRow {
        repository: role.repository.clone(),
        domain: role.domain.clone(),
        public_key: role.public_key,
        not_before: role.not_before,
        not_after: role.not_after,
    };
    if expected.disclosures.contains(&row) {
        return Err(invalid());
    }
    expected.disclosures.push(row);
    expected.disclosures.sort_by(|left, right| {
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
    if expected.encode().map_err(|_| invalid())? != next {
        return Err(invalid());
    }
    Ok(())
}
