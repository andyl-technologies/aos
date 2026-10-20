//! Reuses genuine signed history, current Read and trust for actual occurrences.

use super::loading::{Row, append};
use super::{IndexLookupCurrentWork, IndexLookupError, count};
use crate::guard::{AuthorizedRef, AuthorizedSnapshot, Guard, HistoryObservation};
use crate::store::{Clock, Store, StoreErrorKind};
use terrane_format::derived::{AttrRecord, AttributeName, AttributeValue, verify_record_producer};
use terrane_format::identity::Digest;
use terrane_format::properties::{Domain, RootLayer};
use terrane_format::provenance::{Preset, Selector};
use terrane_format::tree_format::EntryKind;

/// Checks only the actual requested scope, without treating absence as Legacy.
pub(super) fn within_scope(snapshot: &AuthorizedSnapshot, path: &[u8]) -> bool {
    snapshot.scope == b"/"
        || path == snapshot.scope
        || path
            .strip_prefix(snapshot.scope.as_slice())
            .is_some_and(|tail| tail.starts_with(b"/"))
}

/// Rechecks an actual indexed file against signed evidence and current authority.
///
/// # Errors
/// Preserves invalid content/value binding, unsupported interpretation and store failures.
/// Genuine current Denied decisions filter occurrences; metadata Absence is not swallowed.
pub(super) async fn check_occurrence<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    snapshot: &AuthorizedSnapshot,
    row: &Row,
    attribute: &str,
    observation: HistoryObservation<'_>,
    requests: &mut Vec<AuthorizedRef>,
    work: &mut IndexLookupCurrentWork,
) -> Result<bool, IndexLookupError> {
    count(&mut work.occurrence_checks, 1)?;
    let relative = row.path.strip_prefix(b"/").ok_or(crate::guard::invalid())?;
    let (location, _) = snapshot
        .history
        .locate(snapshot.commit.identity(), relative)
        .map_err(|error| {
            crate::store::StoreFailure::with_source(crate::guard::invalid().kind().clone(), error)
        })?;
    if location.root != row.source_root {
        return Err(crate::guard::invalid().into());
    }
    let entry = snapshot
        .history
        .entry(&location)
        .map_err(|_| crate::guard::invalid())?;
    let EntryKind::File { content, size, .. } = &entry.kind else {
        return Err(crate::guard::invalid().into());
    };
    if *content != row.content || *size != row.size {
        return Err(crate::guard::invalid().into());
    }
    if entry
        .attrs
        .iter()
        .find(|value| value.name == attribute)
        .map(|value| value.value)
        != row.value.as_deref()
    {
        return Err(crate::guard::invalid().into());
    }
    // The ordinary evaluator checks all graft policies and actual immutable provenance.
    let trust = snapshot.interpretation.evaluator(
        &snapshot.history,
        (snapshot.commit.identity(), snapshot.evidence.root),
        Selector::preset(Preset::Any),
        &snapshot.storage_domain,
        None,
    )?;
    if !trust.accepts_path(relative) {
        return Ok(false);
    }
    match guard
        .snapshot_authorizations_observed(snapshot, &row.path, observation)
        .await
    {
        Ok(authorized) => {
            requests.extend(authorized);
            Ok(true)
        }
        Err(error) if matches!(error.kind(), StoreErrorKind::Denied { .. }) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Qualifies the inline value's actual producer through independently readable signed history.
///
/// # Errors
/// Preserves incomplete producer history, invalid inline attribution, unsupported
/// profiles and unavailable store/control reads. A current producer denial filters
/// the candidate, while storage absence remains an error instead of an empty result.
pub(super) async fn check_producer<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    snapshot: &AuthorizedSnapshot,
    row: &Row,
    attribute: &str,
    observation: HistoryObservation<'_>,
    requests: &mut Vec<AuthorizedRef>,
    work: &mut IndexLookupCurrentWork,
) -> Result<Option<ProducerCheck>, IndexLookupError> {
    count(&mut work.attribute_origin_checks, 1)?;
    let relative = row.path.strip_prefix(b"/").ok_or(crate::guard::invalid())?;
    let (location, _) = snapshot
        .history
        .locate(snapshot.commit.identity(), relative)
        .map_err(|_| crate::guard::invalid())?;
    let entry = snapshot
        .history
        .entry(&location)
        .map_err(|_| crate::guard::invalid())?;
    let inline = entry
        .attrs
        .iter()
        .find(|value| value.name == attribute)
        .ok_or(crate::guard::invalid())?;
    if Some(inline.value) != row.value.as_deref() {
        return Err(crate::guard::invalid().into());
    }
    let producer = snapshot
        .history
        .attribute_producer(&location, attribute)
        .map_err(|error| {
            crate::store::StoreFailure::with_source(crate::guard::invalid().kind().clone(), error)
        })?;
    // This authenticates the producer in its own independently selected context.
    let (verified, history) = guard
        .verified_tree_history_observed(producer, observation)
        .await?;
    count(&mut work.history_boundary_calls, 1)?;
    if history.commit(&producer).is_none() {
        return Err(crate::guard::invalid().into());
    }
    let paths = {
        let mut paths = Vec::new();
        for occurrence in verified
            .evidence
            .occurrences(guard.config().min_chunk_size)?
        {
            let tree = verified
                .evidence
                .tree(occurrence.root, guard.config().min_chunk_size)?;
            for item in tree.iter() {
                count(&mut work.producer_entries, 1)?;
                let EntryKind::File { content, size, .. } = &item.entry.kind else {
                    continue;
                };
                if *content != row.content || *size != row.size {
                    continue;
                }
                if !item.entry.attrs.iter().any(|value| {
                    value.name == attribute && Some(value.value) == row.value.as_deref()
                }) {
                    continue;
                }
                let mut path = occurrence.path.clone();
                append(&mut path, &item.key)?;
                let relative = path.strip_prefix(b"/").ok_or(crate::guard::invalid())?;
                let (source_location, _) = history
                    .locate(producer, relative)
                    .map_err(|_| crate::guard::invalid())?;
                if history
                    .attribute_producer(&source_location, attribute)
                    .map_err(|_| crate::guard::invalid())?
                    != producer
                {
                    continue;
                }
                if let Ok(name) = AttributeName::parse(attribute) {
                    let value = AttributeValue::decode(
                        name,
                        row.value.as_deref().ok_or(crate::guard::invalid())?,
                    )
                    .map_err(|error| {
                        crate::store::StoreFailure::with_source(
                            crate::guard::invalid().kind().clone(),
                            error,
                        )
                    })?;
                    // This ordinary unsigned claim is derived only from the
                    // signed inline value. The existing verifier independently
                    // checks its object, origin and completed original scopes.
                    let record = AttrRecord::new(row.object(), value, producer);
                    verify_record_producer(&record, &history, &source_location).map_err(
                        |error| {
                            crate::store::StoreFailure::with_source(
                                crate::guard::invalid().kind().clone(),
                                error,
                            )
                        },
                    )?;
                }
                paths.push(path);
            }
        }
        paths
    };
    if paths.is_empty() {
        return Err(crate::guard::invalid().into());
    }
    for path in paths {
        let check = ProducerCheck {
            view: producer,
            path,
            target_path: row.path.clone(),
        };
        if let Some(successful) =
            authorize_producer(guard, snapshot, &check, observation, work).await?
        {
            requests.extend(successful);
            return Ok(Some(check));
        }
    }
    Ok(None)
}

/// Retains selectors for repeating an actual successful producer Read.
///
/// These fields describe ordinary paths, never producer evidence or authority.
pub(super) struct ProducerCheck {
    /// Signed producer view independently resolved through completed history.
    pub(super) view: Digest,
    /// Actual signed producer occurrence that passed current Read and trust.
    pub(super) path: Vec<u8>,
    /// Actual consuming occurrence whose resolved domain permits the reference.
    pub(super) target_path: Vec<u8>,
}

/// Repeats producer history, exact interpretation/domain and current Read before return.
///
/// # Errors
/// Preserves actual unavailable storage, Original or metadata errors. Refuses a
/// previously successful path that no longer satisfies domain, trust or current Read.
pub(super) async fn recheck_producer<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    snapshot: &AuthorizedSnapshot,
    check: &ProducerCheck,
    observation: HistoryObservation<'_>,
    work: &mut IndexLookupCurrentWork,
) -> Result<Vec<AuthorizedRef>, IndexLookupError> {
    authorize_producer(guard, snapshot, check, observation, work)
        .await?
        .ok_or_else(|| {
            crate::guard::denied(
                &snapshot.authority_reference,
                terrane_format::auth::Verb::Read,
            )
            .into()
        })
}

async fn authorize_producer<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    target: &AuthorizedSnapshot,
    check: &ProducerCheck,
    observation: HistoryObservation<'_>,
    work: &mut IndexLookupCurrentWork,
) -> Result<Option<Vec<AuthorizedRef>>, IndexLookupError> {
    count(&mut work.producer_checks, 1)?;
    // The target is the actual consuming occurrence, not the containing view's
    // root domain. Independently selected graft layers can choose another domain.
    if guard.select_view(target.commit.identity(), target.evidence.root, observation)?
        != target.interpretation
    {
        return Err(crate::guard::invalid().into());
    }
    let target_layers = target
        .evidence
        .policy_path(&check.target_path, guard.config().min_chunk_size)?;
    let target_layers = target_layers
        .iter()
        .map(|(properties, overrides)| RootLayer {
            properties,
            overrides,
        })
        .collect::<Vec<_>>();
    let target_policy = target
        .interpretation
        .resolve(&target_layers, guard.defaults_for(&target.evidence))?;
    let target_domain =
        crate::guard::domain_label(&target_policy).map_err(|_| crate::guard::invalid())?;
    let target_domain = Domain::parse(target_domain).map_err(|_| crate::guard::invalid())?;

    count(&mut work.history_boundary_calls, 1)?;
    let (verified, history) = guard
        .verified_tree_history_observed(check.view, observation)
        .await?;
    let (interpretation, _) = guard.selected_view_profile(&verified.commit, observation)?;
    let producer_layers = verified
        .evidence
        .policy_path(&check.path, guard.config().min_chunk_size)?;
    let producer_layers = producer_layers
        .iter()
        .map(|(properties, overrides)| RootLayer {
            properties,
            overrides,
        })
        .collect::<Vec<_>>();
    let producer_policy =
        interpretation.resolve(&producer_layers, guard.defaults_for(&verified.evidence))?;
    let domain = crate::guard::domain_label(&producer_policy)
        .map_err(|_| crate::guard::invalid())?
        .to_owned();
    if !target_domain
        .permits_reference(Domain::parse(&domain).map_err(|_| crate::guard::invalid())?)
    {
        return Ok(None);
    }
    // Trust is a proved exclusion before the ordinary Read helper can return
    // Absent; a stored missing Commit/Node/control never becomes this branch.
    let trust = interpretation.evaluator(
        &history,
        (check.view, verified.evidence.root),
        Selector::preset(Preset::Any),
        &domain,
        None,
    )?;
    if !trust.accepts_path(
        check
            .path
            .strip_prefix(b"/")
            .ok_or(crate::guard::invalid())?,
    ) {
        return Ok(None);
    }
    let original = verified
        .commit
        .commit()
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or(crate::guard::invalid())?
        .reference();
    let authority_reference = guard
        .config()
        .policy_authority
        .as_deref()
        .unwrap_or(original)
        .to_owned();
    // This child owns no public constructor. Every field is derived above from
    // actual completed signed history, its original reference and exact caller
    // selection. The existing helper independently checks all current obligations.
    let producer = AuthorizedSnapshot {
        history,
        commit: verified.commit,
        evidence: verified.evidence,
        scope: check.path.clone(),
        storage_domain: domain,
        interpretation,
        authority_reference,
        token: target.token.clone(),
        surface: target.surface.clone(),
    };
    match guard
        .snapshot_authorizations_observed(&producer, &check.path, observation)
        .await
    {
        Ok(requests) => Ok(Some(requests)),
        Err(error) if matches!(error.kind(), StoreErrorKind::Denied { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}
