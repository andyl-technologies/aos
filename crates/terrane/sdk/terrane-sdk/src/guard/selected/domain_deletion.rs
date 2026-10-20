//! Qualifies complete native domain roots under one actual namespace exclusion.
//!
//! CAPABILITIES key 10 supplies the complete name inventory. Every inventoried
//! whole ref is retained, including absent names and advisory records; only
//! authoritative classes contribute canonical roots and current Admin checks.

use std::collections::BTreeMap;

use crate::bucket::{
    BucketBinding, FileBucket, held::HeldBucket, publication::SelectedObservation,
};
use crate::domain::{DomainAccess, DomainBinding};
use crate::guard::{AuthorizedRef, ConsumedResolver, Guard, HistoryObservation};
use crate::ref_advance::CommitTiming;
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::auth::Verb;
use terrane_format::bucket::{BucketCapabilities, BucketKey};
use terrane_format::refs::{RefClass, RefName, RefRecord};

use super::{
    GuardEffectContext, capture_selected_reads, hold_consumed_controls, invalid, retain_final_check,
};

/// Retains independently checked roots, whole heads and genuine native checks.
///
/// Only this factory constructs the context after verified historical policy,
/// current administration, complete inventory and actual protected controls.
pub(crate) struct QualifiedDomain {
    /// Complete canonical authoritative root occurrences for this held namespace.
    pub(crate) roots: Vec<DomainBinding>,
    /// Actual current Admin decisions matching each canonical root occurrence.
    pub(crate) permissions: Vec<DomainAccess>,
    /// Every complete inventoried ref value or absence, including advisory names.
    pub(crate) records: BTreeMap<String, Option<Vec<u8>>>,
    /// Exact selected CAPABILITIES bytes carrying complete key-10 inventory.
    pub(crate) capabilities: Vec<u8>,
    /// Actual protected controls, selected preimages and independent request checks.
    pub(crate) context: GuardEffectContext,
}

/// Checks every actual authoritative root rather than a caller-selected subset.
///
/// # Errors
/// Returns Unsupported without complete CAPABILITIES key 10. Rejects absent
/// canonical history, changed whole records, domain mismatches, incomplete
/// current administration, changed protected controls and expired requests.
pub(crate) async fn qualify<F, B, V, C, D, const WRITABLE: bool>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    held: &Guard<HeldBucket<'_, F, B, V, WRITABLE>, D>,
    observed: &SelectedObservation<'_>,
    token: &[u8],
    surface: &str,
    timing: CommitTiming,
) -> Result<QualifiedDomain, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    qualify_selected(concrete, held, observed, token, surface, timing, None).await
}

/// Qualifies only the configured audit route while retaining its complete inventory.
///
/// # Errors
/// Preserves complete inventory and genuine current route Admin failures.
pub(crate) async fn qualify_audit<F, B, V, C, D, const WRITABLE: bool>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    held: &Guard<HeldBucket<'_, F, B, V, WRITABLE>, D>,
    observed: &SelectedObservation<'_>,
    token: &[u8],
    configured: &crate::domain::ConfiguredDomainRoute,
    timing: CommitTiming,
) -> Result<QualifiedDomain, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    if observed.identity().root() != configured.audit().root
        || held.config().storage_domain != configured.audit().domain
    {
        return Err(invalid());
    }
    qualify_selected(
        concrete,
        held,
        observed,
        token,
        "sdk",
        timing,
        Some(configured.control_ref()),
    )
    .await
}

async fn qualify_selected<F, B, V, C, D, const WRITABLE: bool>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    held: &Guard<HeldBucket<'_, F, B, V, WRITABLE>, D>,
    observed: &SelectedObservation<'_>,
    token: &[u8],
    surface: &str,
    timing: CommitTiming,
    audit_reference: Option<&str>,
) -> Result<QualifiedDomain, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    let started = held.clock().monotonic();
    let capabilities = observed
        .logical()
        .get("CAPABILITIES")
        .and_then(Option::as_ref)
        .ok_or_else(invalid)?
        .clone();
    let names = BucketCapabilities::decode(&capabilities)
        .map_err(|_| invalid())?
        .ref_names
        .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
    let authority = concrete.configured_original_authority()?;
    let consumed = ConsumedResolver::new(held, &authority)?;
    consumed.registration(&authority)?;
    let history = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let mut records = BTreeMap::new();
    let mut roots = Vec::new();
    let mut permissions = Vec::new();
    let mut requests = Vec::new();

    for name in &names {
        let class = RefName::parse(name).map_err(|_| invalid())?.class();
        let key = BucketKey::ref_record(name).map_err(|_| invalid())?;
        let bytes = observed.logical().get(key.as_str()).ok_or_else(invalid)?;
        records.insert(name.clone(), bytes.clone());
        let Some(bytes) = bytes else { continue };

        // Notes are opaque selected inventory fences, never content roots or
        // authority edges. Their bytes need not encode an authoritative ref.
        if class == RefClass::Notes {
            continue;
        }
        let record = RefRecord::decode(bytes).map_err(|_| {
            StoreFailure::new(StoreErrorKind::Corrupt(
                crate::store::CorruptSubject::RefName(key.as_str().into()),
            ))
        })?;
        if audit_reference.is_some_and(|reference| reference != name) {
            continue;
        }
        let verified = held.verified_tree_observed(record.commit, history).await?;
        for occurrence in verified
            .evidence
            .occurrences(held.config().min_chunk_size)?
        {
            let access = held
                .domain_access_observed(
                    name,
                    token,
                    Verb::Admin,
                    &occurrence.path,
                    surface,
                    history,
                )
                .await?;
            if access.reference_record() != Some(&record)
                || access.binding().path != occurrence.path
            {
                return Err(invalid());
            }
            let request = held
                .authorize_observed(
                    name,
                    token,
                    Verb::Admin,
                    &[occurrence.path],
                    surface,
                    history,
                )
                .await?;
            if request.record() != Some(&record)
                || requests
                    .first()
                    .is_some_and(|first: &AuthorizedRef| !first.same_principal(&request))
            {
                return Err(invalid());
            }
            consumed.operation(&request)?;
            roots.push(access.binding().clone());
            permissions.push(access);
            requests.push(request);
            if audit_reference.is_some() {
                let read = held
                    .authorize_observed(
                        name,
                        token,
                        Verb::Read,
                        &[permissions
                            .last()
                            .ok_or_else(invalid)?
                            .binding()
                            .path
                            .clone()],
                        surface,
                        history,
                    )
                    .await?;
                if read.record() != Some(&record) {
                    return Err(invalid());
                }
                consumed.operation(&read)?;
                requests.push(read);
            }
        }
    }

    // The complete inventory and every whole value are compared while the
    // original namespace exclusion remains held, before retaining effect inputs.
    let current = held.store().observe_publication_retained().await?;
    if current
        .logical()
        .get("CAPABILITIES")
        .and_then(Option::as_ref)
        != Some(&capabilities)
    {
        return Err(invalid());
    }
    for (name, expected) in &records {
        let key = BucketKey::ref_record(name).map_err(|_| invalid())?;
        if current.logical().get(key.as_str()) != Some(expected) {
            return Err(invalid());
        }
    }
    let mut controls =
        hold_consumed_controls(concrete, &authority, held.store(), observed, &consumed).await?;
    let retained = controls
        .exclusion
        .retain_used(&controls.used.controls)
        .await?;
    held.retain_original_controls(&retained)?;
    let names = names.iter().map(String::as_str).collect::<Vec<_>>();
    let selected_reads = capture_selected_reads(held.store(), observed, &names).await?;
    let final_check = if requests.is_empty() && audit_reference.is_none() {
        // Complete absence of authoritative roots creates no caller request.
        // This check supplies only the independent source deadline; deletion
        // additionally requires the separately qualified registered route Admin.
        let clock = held
            .clock()
            .retain_native_clock()
            .map_err(|error| StoreFailure::with_source(StoreErrorKind::Unsupported, error))?;
        crate::selected_bridge::OwnedFinalCheck {
            check: super::SharedCheck::new(move || {
                if clock
                    .monotonic()
                    .checked_sub(started)
                    .is_none_or(|elapsed| elapsed > timing.maximum())
                {
                    return Err(invalid());
                }
                Ok(())
            }),
        }
    } else {
        retain_final_check(held, &requests, started, timing)?
    };
    final_check.recheck()?;
    observed.revalidate().await?;

    Ok(QualifiedDomain {
        roots,
        permissions,
        records,
        capabilities,
        context: GuardEffectContext {
            final_check,
            controls: vec![retained],
            selected_reads,
            publication_original: None,
            existing_reads: Vec::new(),
        },
    })
}

/// Combines only two contexts produced by current genuine native qualification.
pub(crate) fn paired_context(
    mut source: GuardEffectContext,
    mut audit: GuardEffectContext,
) -> GuardEffectContext {
    let source_check = source.final_check;
    let audit_check = audit.final_check;
    let final_check = crate::selected_bridge::OwnedFinalCheck {
        check: super::SharedCheck::new(move || {
            source_check.recheck()?;
            audit_check.recheck()
        }),
    };
    audit.controls.append(&mut source.controls);
    source.selected_reads.append(&mut audit.selected_reads);
    source.existing_reads.append(&mut audit.existing_reads);
    GuardEffectContext {
        final_check,
        controls: audit.controls,
        selected_reads: source.selected_reads,
        existing_reads: source.existing_reads,
        publication_original: None,
    }
}

/// Qualifies one caller's selected file and its independent current Read request.
///
/// # Errors
/// Rejects unauthorized current callers, untrusted fixed views, wrong file
/// selectors, malformed content, changed protected controls and expired checks.
pub(crate) async fn qualify_read<F, B, V, C, D, const WRITABLE: bool>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    held: &Guard<HeldBucket<'_, F, B, V, WRITABLE>, D>,
    observed: &SelectedObservation<'_>,
    selection: crate::guard::DisclosureSourceSelection<'_>,
    content: terrane_format::tree_format::ContentRef,
    size: u64,
    timing: CommitTiming,
) -> Result<
    (
        crate::guard::AuthorizedSnapshot,
        DomainAccess,
        GuardEffectContext,
    ),
    StoreFailure,
>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    let started = held.clock().monotonic();
    let authority = concrete.configured_original_authority()?;
    let consumed = ConsumedResolver::new(held, &authority)?;
    consumed.registration(&authority)?;
    let history = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let reference = selection.reference;
    let path = selection.path;
    let (snapshot, requests) = held
        .capture_disclosure_source_observed(selection, history)
        .await?;
    let access = held
        .domain_content_access_observed(&snapshot, path, content, size, history)
        .await?;
    for request in &requests {
        consumed.operation(request)?;
    }
    let context = operation_context(
        concrete,
        held,
        observed,
        OperationInputs {
            authority: &authority,
            consumed: &consumed,
            requests: &requests,
            reference,
            started,
            timing,
        },
    )
    .await?;
    Ok((snapshot, access, context))
}

/// Qualifies one actual current caller Commit request for routed content staging.
///
/// # Errors
/// Rejects missing or changed current heads, denied Commit, a wrong canonical
/// root/domain, untrusted history, changed protected controls and expired checks.
pub(crate) async fn qualify_write<F, B, V, C, D, const WRITABLE: bool>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    held: &Guard<HeldBucket<'_, F, B, V, WRITABLE>, D>,
    observed: &SelectedObservation<'_>,
    request: &crate::domain::DomainWriteRequest<'_>,
    timing: CommitTiming,
) -> Result<(DomainAccess, GuardEffectContext), StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    let reference = request.reference;
    let token = request.token;
    let path = request.path;
    let surface = request.surface;
    let started = held.clock().monotonic();
    let authority = concrete.configured_original_authority()?;
    let consumed = ConsumedResolver::new(held, &authority)?;
    consumed.registration(&authority)?;
    let history = HistoryObservation::held(observed.identity()).tracked(&consumed);
    let access = held
        .domain_access_observed(reference, token, Verb::Commit, path, surface, history)
        .await?;
    let request = held
        .authorize_observed(
            reference,
            token,
            Verb::Commit,
            &[path.to_vec()],
            surface,
            history,
        )
        .await?;
    if request.record() != access.reference_record() {
        return Err(invalid());
    }
    consumed.operation(&request)?;
    let context = operation_context(
        concrete,
        held,
        observed,
        OperationInputs {
            authority: &authority,
            consumed: &consumed,
            requests: &[request],
            reference,
            started,
            timing,
        },
    )
    .await?;
    Ok((access, context))
}

/// Groups genuine consumed evidence with its original operation deadline.
struct OperationInputs<'a> {
    authority: &'a crate::guard::OriginalAuthority,
    consumed: &'a ConsumedResolver,
    requests: &'a [AuthorizedRef],
    reference: &'a str,
    started: std::time::Duration,
    timing: CommitTiming,
}

async fn operation_context<F, B, V, C, D, const WRITABLE: bool>(
    concrete: &Guard<FileBucket<F, B, V>, C>,
    held: &Guard<HeldBucket<'_, F, B, V, WRITABLE>, D>,
    observed: &SelectedObservation<'_>,
    inputs: OperationInputs<'_>,
) -> Result<GuardEffectContext, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
    D: Clock,
{
    let OperationInputs {
        authority,
        consumed,
        requests,
        reference,
        started,
        timing,
    } = inputs;
    let mut controls =
        hold_consumed_controls(concrete, authority, held.store(), observed, consumed).await?;
    let retained = controls
        .exclusion
        .retain_used(&controls.used.controls)
        .await?;
    held.retain_original_controls(&retained)?;
    let selected_reads = capture_selected_reads(held.store(), observed, &[reference]).await?;
    let final_check = retain_final_check(held, requests, started, timing)?;
    final_check.recheck()?;
    observed.revalidate().await?;
    Ok(GuardEffectContext {
        final_check,
        controls: vec![retained],
        selected_reads,
        publication_original: None,
        existing_reads: Vec::new(),
    })
}

/// Binds current caller and operator route checks to actual contextual staging.
///
/// The caller context supplies the target's rights. The audit context supplies
/// only active-route control and cannot confer caller rights on the target.
pub(crate) fn staging_context<'operation, 'held>(
    caller: GuardEffectContext,
    audit: GuardEffectContext,
    target: &SelectedObservation<'_>,
    audit_observed: &'operation SelectedObservation<'held>,
) -> super::meta_batch::ImmutableEffectContext<'operation, 'held> {
    // The contextual destination is the target; its genuine controls must lead.
    let effect = paired_context(audit, caller);
    super::meta_batch::ImmutableEffectContext::current_operation(
        effect,
        target,
        vec![audit_observed],
    )
}
