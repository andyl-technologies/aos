//! Owns private native cold-fork lineage and source-policy qualification.
//!
//! A complete held factory must independently verify every retained dependency.

#[path = "cold_fork/derivation.rs"]
mod derivation;
#[path = "cold_fork/publication.rs"]
mod publication;
pub(crate) use publication::publish;

use std::{collections::BTreeMap, os::unix::fs::MetadataExt, time::Duration};

use terrane_core::auth::RequestRoot;
use terrane_core::gc::publication::evidence::{
    CheckedLineage, ConsumedViewPolicy, ControlKind, GuardSnapshot, OriginalAssociation,
    OriginalBootstrap, TrustedGuardConfig,
};
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::provenance::{self, VerifiedCommit};
use terrane_core::refs::{Commit, RefRecord};

use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::publication::receipts::RecordRead;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::cold_fork::occurrence_domain;
use crate::guard::{
    AuthorizedRef, ConsumedResolver, ControlExclusion, Guard, OriginalAuthority, RetainedControls,
    consumed_registration, invalid,
};
use crate::ref_advance::{AdvanceError, CommitTiming};
use crate::store::{
    Clock, ContentValidator, LocalFs, RefStore, Store, StoreErrorKind, StoreFailure,
};

/// Supplies untrusted operation input, never lineage or publication authority.
pub(crate) struct ColdForkRequest<'a> {
    /// Names the exact live source ref to qualify.
    pub(crate) source: &'a str,
    /// Supplies the current operation's capability chain.
    pub(crate) token: &'a [u8],
    /// Names the current producing surface for token caveats.
    pub(crate) surface: &'a str,
    /// Retains the original operation's monotonic start.
    pub(crate) started: Duration,
    /// Retains its existing publication deadline without extending it.
    pub(crate) timing: CommitTiming,
}

/// Borrows policy evidence qualified under a fresh actual backend and control holder.
///
/// Only this factory constructs the fields. Access remains borrowed from the
/// enclosing qualification, so retaining public lineage bytes cannot prolong it.
pub(crate) struct QualifiedPolicies {
    lineage: CheckedLineage,
    snapshot: Vec<u8>,
    authority: OriginalAuthority,
    source_view_index: usize,
}

impl QualifiedPolicies {
    /// Returns the exact selected source name checked by this held factory.
    pub(crate) fn source_name(&self) -> &str {
        &self.lineage.source_name
    }

    /// Borrows the complete selected source head, including its candidate selector.
    pub(crate) fn source_record(&self) -> &RefRecord {
        &self.lineage.source
    }

    /// Borrows the canonical root occurrences for the exact signed source Commit.
    ///
    /// The private factory checks this index before construction and neither the
    /// index nor the immutable lineage can subsequently be changed by a caller.
    pub(crate) fn source_view(&self) -> &ConsumedViewPolicy {
        &self.lineage.used.views[self.source_view_index]
    }

    /// Preserves every source policy occurrence row, including repeated view rows.
    pub(crate) fn source_views(&self) -> impl Iterator<Item = &ConsumedViewPolicy> {
        self.lineage
            .used
            .views
            .iter()
            .filter(|view| view.view == self.source_view().view)
    }

    /// Borrows the independently reselected full source profile.
    ///
    /// # Errors
    /// Rejects absent or inconsistent context in this qualified source.
    pub(crate) fn source_profile(
        &self,
    ) -> Result<&terrane_core::gc::publication::evidence::ConfiguredRegistryInputs, StoreFailure>
    {
        self.lineage
            .used
            .view_interpretations
            .as_ref()
            .and_then(|contexts| {
                contexts
                    .iter()
                    .find(|context| context.view == self.lineage.commit_id)
            })
            .map(|context| &context.registries)
            .ok_or_else(invalid)
    }

    /// Borrows the exact interpretation inputs compared with the selected Guard.
    pub(crate) fn configuration(&self) -> &TrustedGuardConfig {
        &self.lineage.used.configuration
    }

    /// Refuses another concrete interpretation of the checked selected policies.
    ///
    /// # Errors
    /// Rejects changed issuer rows, registries, profile, policy or physical setup.
    pub(crate) fn check_guard<S: Store, C: Clock>(
        &self,
        guard: &Guard<S, C>,
    ) -> Result<(), StoreFailure> {
        if ConsumedResolver::new(guard, &self.authority)?.snapshot_bytes()? != self.snapshot {
            return Err(invalid());
        }
        for view in &self.lineage.used.views {
            compare_view_inputs(guard, &self.lineage, view)?;
        }
        Ok(())
    }

    /// Binds a policy use to the same actual held namespace registration.
    ///
    /// # Errors
    /// Rejects another root or coordination incarnation despite equal ref bytes.
    pub(crate) fn check_backend(
        &self,
        held: &crate::bucket::held::HeldIdentity<'_>,
    ) -> Result<(), StoreFailure> {
        if held.root() != self.authority.root()
            || held.physical_identity() != self.authority.physical_identity()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Retains qualified source evidence and actual exclusion for this held operation.
///
/// This is not a ref-publication permit. Fresh candidate signing, destination
/// original retention and final selected publication remain separate obligations.
pub(crate) struct QualifiedSource<'operation, 'held, F: LocalFs> {
    policies: QualifiedPolicies,
    commit: VerifiedCommit,
    authorization: AuthorizedRef,
    controls: ControlExclusion<'operation, F>,
    retained_controls: RetainedControls,
    guard_read: RecordRead,
    lineage_read: RecordRead,
    observed: &'operation SelectedObservation<'held>,
    started: Duration,
    timing: CommitTiming,
}

impl<F: LocalFs> QualifiedSource<'_, '_, F> {
    /// Borrows operation-local policy evidence while actual controls remain held.
    pub(crate) fn policies(&self) -> &QualifiedPolicies {
        &self.policies
    }

    /// Borrows the source signature checked in its independent original context.
    pub(crate) fn commit(&self) -> &VerifiedCommit {
        &self.commit
    }

    /// Borrows the separately checked live source Fork request.
    pub(crate) fn authorization(&self) -> &AuthorizedRef {
        &self.authorization
    }
}

impl<F: LocalFs + BucketBinding> QualifiedSource<'_, '_, F> {
    /// Rechecks held selection, exact source head, controls and current credentials.
    ///
    /// # Errors
    /// Rejects expired operations, changed controls or selected evidence, current
    /// token denial and any source whole-record mismatch.
    pub(crate) async fn revalidate<B, V, C>(
        &mut self,
        guard: &Guard<HeldBucket<'_, F, B, V, true>, C>,
    ) -> Result<(), AdvanceError>
    where
        B: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
        C: Clock,
    {
        check_time(guard.clock(), self.started, self.timing)?;
        self.policies.check_guard(guard)?;
        let guard_read = guard
            .store()
            .selected_guard_snapshot_record(self.observed)
            .await?
            .ok_or_else(invalid)?;
        check_read(&self.guard_read, &guard_read)?;
        let lineage_read = guard
            .store()
            .selected_lineage_record(self.observed, self.policies.source_name())
            .await?
            .ok_or_else(invalid)?;
        check_read(&self.lineage_read, &lineage_read)?;
        self.observed.revalidate().await?;
        if guard
            .store()
            .ref_get(self.policies.source_name())
            .await?
            .as_ref()
            != Some(self.policies.source_record())
        {
            return Err(invalid().into());
        }
        let current_controls = self
            .controls
            .retain_used(&self.policies.lineage.controls)
            .await?;
        check_controls(&self.retained_controls, &current_controls)?;
        self.controls.revalidate().await?;
        guard.refresh_authorized_time(&self.authorization)?;
        self.observed.revalidate().await?;
        check_time(guard.clock(), self.started, self.timing)
    }
}

// Equal canonical bytes do not preserve a protected leaf's incarnation. These
// comparisons retain the original qualification rather than refreshing it.
fn check_read(previous: &RecordRead, current: &RecordRead) -> Result<(), StoreFailure> {
    let previous_metadata = previous.metadata().ok_or_else(invalid)?;
    let current_metadata = current.metadata().ok_or_else(invalid)?;
    let signature = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if previous.path() != current.path()
        || previous.bytes() != current.bytes()
        || signature(previous_metadata) != signature(current_metadata)
    {
        return Err(invalid());
    }
    Ok(())
}

fn check_controls(
    previous: &RetainedControls,
    current: &RetainedControls,
) -> Result<(), StoreFailure> {
    if previous.directory() != current.directory()
        || previous.owner() != current.owner()
        || previous.identities() != current.identities()
        || previous.ancestors() != current.ancestors()
        || previous.records().len() != current.records().len()
        || previous
            .records()
            .iter()
            .zip(current.records())
            .any(|(previous, current)| {
                previous.path() != current.path()
                    || previous.identity() != current.identity()
                    || previous.bytes() != current.bytes()
            })
    {
        return Err(invalid());
    }
    Ok(())
}

fn check_time(
    clock: &impl Clock,
    started: Duration,
    timing: CommitTiming,
) -> Result<(), AdvanceError> {
    if clock
        .monotonic()
        .checked_sub(started)
        .is_none_or(|elapsed| elapsed > timing.maximum())
    {
        return Err(AdvanceError::Expired);
    }
    Ok(())
}

/// Qualifies current selected source lineage under actual fresh exclusions.
///
/// # Errors
/// Preserves missing/malformed context, changed selection, profiles, Original,
/// current Fork/path/domain, control, timing and originating I/O failures.
pub(crate) async fn qualify_source<'operation, 'held, F, B, V, C, D>(
    concrete: &'operation Guard<FileBucket<F, B, V>, D>,
    authority: &OriginalAuthority,
    guard: &Guard<HeldBucket<'held, F, B, V, true>, C>,
    observed: &'operation SelectedObservation<'held>,
    request: ColdForkRequest<'_>,
) -> Result<QualifiedSource<'operation, 'held, F>, AdvanceError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    qualify_source_with_controls(concrete, authority, guard, observed, request, None).await
}

/// Carries only the real early immutable effect frame produced by this factory.
///
/// Private fields are initialized after actual cold qualification/current/Original
/// checks. No consumer can create this from decoded lineage or callback inputs.
pub(super) struct ColdImmutableInputs {
    effect: super::GuardEffectContext,
    selected: terrane_core::gc::publication::PublicationState,
}

impl ColdImmutableInputs {
    /// Moves the actual retained frame without exposing a constructor.
    pub(super) fn into_parts(
        self,
    ) -> (
        super::GuardEffectContext,
        terrane_core::gc::publication::PublicationState,
    ) {
        (self.effect, self.selected)
    }
}

/// Qualifies selected local lineage without fetching any ordinary content object.
///
/// The actual backend selection establishes which protected evidence is eligible;
/// exact current Guard inputs and protected original records are independently
/// checked before its policy occurrences can authorize the live Fork request.
/// Foreign control owners require the paired-control factory and fail closed here.
///
/// # Errors
/// Rejects absent/raw lineage, stale whole heads or loss generation, mismatched
/// trusted configuration, unavailable originals, malformed or unauthenticated
/// signed commits, current Fork denial and elapsed publication deadlines.
async fn qualify_source_with_controls<'operation, 'held, F, B, V, C, D>(
    concrete: &'operation Guard<FileBucket<F, B, V>, D>,
    authority: &OriginalAuthority,
    guard: &Guard<HeldBucket<'held, F, B, V, true>, C>,
    observed: &'operation SelectedObservation<'held>,
    request: ColdForkRequest<'_>,
    existing_controls: Option<ControlExclusion<'operation, F>>,
) -> Result<QualifiedSource<'operation, 'held, F>, AdvanceError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    check_time(guard.clock(), request.started, request.timing)?;
    observed.revalidate().await?;
    guard.check_source_requalification_authority(authority)?;
    let held = guard.store();
    let lineage_read = held
        .selected_lineage_record(observed, request.source)
        .await?
        .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
    let lineage =
        CheckedLineage::decode(lineage_read.bytes().ok_or_else(invalid)?).map_err(|_| invalid())?;
    // The held Guard restores actual checked local Original state. The acyclic
    // capture retains filesystem/configuration but deliberately has no verifier.
    let snapshot = ConsumedResolver::new(guard, authority)?.snapshot_bytes()?;
    let guard_read = held
        .selected_guard_snapshot_record(observed)
        .await?
        .ok_or_else(invalid)?;
    if guard_read.bytes() != Some(snapshot.as_slice())
        || lineage.source_name != request.source
        || held.ref_get(request.source).await?.as_ref() != Some(&lineage.source)
        || lineage.loss_generation != observed.state().loss_generation
        || observed.state().guard != Some(lineage.guard_digest)
    {
        return Err(invalid().into());
    }
    if lineage.original != consumed_registration(authority) {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
    }
    lineage
        .check_guard_snapshot(&snapshot)
        .map_err(|_| invalid())?;
    let current = GuardSnapshot::decode(&snapshot).map_err(|_| invalid())?;
    if lineage
        .used
        .issuers
        .iter()
        .any(|row| !current.issuers.contains(row))
        || lineage
            .used
            .disclosures
            .iter()
            .any(|row| !current.disclosures.contains(row))
    {
        return Err(invalid().into());
    }
    let registration = consumed_registration(authority);
    if lineage.controls.iter().any(|pin| pin.owner != registration) {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
    }
    let mut controls = match existing_controls {
        Some(controls) => controls,
        None => {
            concrete
                .hold_original_registration(authority, observed.identity())
                .await?
        }
    };
    controls.revalidate().await?;
    let mut records = Vec::with_capacity(lineage.controls.len());
    for pin in &lineage.controls {
        let bytes = controls.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
        records.push(bytes);
    }
    // Exact selected lineage qualifies the prior completed graph traversal.
    // Missing original records still invalidate it, including after a successful
    // earlier qualification; an in-memory snapshot never repairs protected loss.
    let commit = Commit::decode(&lineage.commit_bytes).map_err(|_| invalid())?;
    if !lineage
        .used
        .check_supported_view_contexts()
        .map_err(|_| invalid())?
    {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
    }
    let source_view_index = check_views(&lineage, &commit)?;
    for view in &lineage.used.views {
        compare_view_inputs(concrete, &lineage, view)?;
        compare_view_inputs(guard, &lineage, view)?;
    }
    // U3's actual owning completion currently supports only typed empty Index.
    // This refuses required indexes; it never turns loader data into completion.
    for view in &lineage.used.views {
        for root in &view.roots {
            crate::guard::cold_fork::with_occurrence_policy(
                guard,
                root,
                view,
                &lineage.used.configuration,
                |policy| match policy.get(terrane_core::properties::PropertyName::Index) {
                    Some(terrane_core::properties::Value::Names(names)) if names.is_empty() => {
                        Ok(())
                    }
                    Some(terrane_core::properties::Value::Names(_)) => {
                        Err(StoreFailure::new(StoreErrorKind::Unsupported))
                    }
                    _ => Err(invalid()),
                },
            )?;
        }
    }
    let retained_controls = controls.retain_used(&lineage.controls).await?;
    let originals = concrete
        .bind_cold_originals(
            authority,
            observed.identity(),
            &retained_controls,
            &lineage,
            &records,
        )
        .await?;
    let original = originals
        .iter()
        .find(|context| context.commit() == &lineage.commit_id)
        .ok_or_else(invalid)?;
    let association = check_originals(&lineage, &records, &registration)?;
    if original.baseline().reference() != association.ref_name
        || original.baseline().epoch() != association.epoch
        || original.baseline().authority() != authority
    {
        return Err(invalid().into());
    }
    let context = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or_else(invalid)?;
    if association.ref_name != context.reference()
        || association.epoch != commit.provenance.writer_epoch
        || commit.profile_pair.chunk_profile != guard.config().chunk_profile_name
    {
        return Err(invalid().into());
    }
    for claim in context.roots() {
        let candidate = &lineage.used.views[source_view_index];
        let previous = commit
            .parents
            .first()
            .and_then(|parent| lineage.used.views.iter().find(|view| &view.view == parent));
        let mut witnessed = false;
        for view in std::iter::once(candidate).chain(previous) {
            for root in &view.roots {
                if root.path == claim.path()
                    && occurrence_domain(guard, root, view, &lineage.used.configuration)?
                        == claim.domain()
                {
                    witnessed = true;
                }
            }
        }
        if !witnessed {
            return Err(invalid().into());
        }
    }
    let roots = context
        .roots()
        .iter()
        .map(|claim| RequestRoot {
            path: claim.path(),
            domain: claim.domain(),
        })
        .collect::<Vec<_>>();
    let verified = provenance::verify_history(
        &commit,
        guard.keys(),
        &roots,
        &[(association.ref_name.as_str(), association.epoch)],
    )
    .map_err(|_| invalid())?;
    guard.check_requalification_source_profile(&verified)?;
    if verified.identity() != lineage.commit_id {
        return Err(invalid().into());
    }
    let policies = QualifiedPolicies {
        lineage,
        snapshot,
        authority: authority.clone(),
        source_view_index,
    };
    let authorization = guard
        .authorize_cold_fork_source(&policies, request.token, request.surface)
        .await?;
    let retained_controls = controls.retain_used(&policies.lineage.controls).await?;
    let mut qualified = QualifiedSource {
        policies,
        commit: verified,
        authorization,
        controls,
        retained_controls,
        guard_read,
        lineage_read,
        observed,
        started: request.started,
        timing: request.timing,
    };
    qualified.revalidate(guard).await?;
    Ok(qualified)
}

// The retained context is data; both property and attribute selections come
// independently from Guard's actual Legacy constructor and registered inputs.
// ROOT has no Recorded/foreign view selector in this bounded producer. Source
// signature and physical-profile checks follow actual Original validation.
/// Compares one retained view's ordinary inputs with actual installed meanings.
///
/// # Errors
/// Rejects absent context, mismatched full profile or unavailable actual selection.
fn compare_view_inputs<S, C>(
    guard: &Guard<S, C>,
    lineage: &CheckedLineage,
    view: &ConsumedViewPolicy,
) -> Result<(), StoreFailure> {
    guard.compare_requalification_view_inputs(lineage, view)
}

/// Checks occurrence structure and the signed source's exact retained root.
///
/// This comparison grants no signature, Original or completed-history authority.
///
/// # Errors
/// Rejects contradictory paths/layers, invalid defaults or a source-root mismatch.
fn check_views(lineage: &CheckedLineage, commit: &Commit) -> Result<usize, StoreFailure> {
    let views = &lineage.used.views;
    let mut occurrences = BTreeMap::new();
    for view in views {
        for root in &view.roots {
            if occurrences
                .insert((view.view, root.path.as_slice()), root)
                .is_some_and(|prior| prior != root)
            {
                return Err(invalid());
            }
        }
        if view
            .roots
            .first()
            .is_none_or(|root| root.path != b"/" || root.layers.len() != 1)
        {
            return Err(invalid());
        }
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Node, &view.roots[0].root)
            .map_err(|_| invalid())?;
        if view.default_domain != crate::domain::private_default(&identity) {
            return Err(invalid());
        }
        let mut paths = std::collections::BTreeSet::new();
        if view
            .roots
            .iter()
            .any(|root| !paths.insert(root.path.as_slice()))
        {
            return Err(invalid());
        }
        for root in view.roots.iter().skip(1) {
            let parent = view
                .roots
                .iter()
                .filter(|parent| {
                    parent.path == b"/"
                        || root.path.starts_with(&parent.path)
                            && root.path.get(parent.path.len()) == Some(&b'/')
                })
                .max_by_key(|parent| parent.path.len())
                .ok_or_else(invalid)?;
            if root.layers.len() != parent.layers.len() + 1
                || !root.layers.starts_with(&parent.layers)
            {
                return Err(invalid());
            }
        }
    }
    let index = views
        .iter()
        .position(|view| view.view == lineage.commit_id)
        .ok_or_else(invalid)?;
    if views[index].roots[0].root != commit.tree {
        return Err(invalid());
    }
    Ok(index)
}

fn check_originals(
    lineage: &CheckedLineage,
    records: &[Vec<u8>],
    registration: &terrane_core::gc::publication::evidence::PhysicalRegistration,
) -> Result<OriginalAssociation, StoreFailure> {
    let mut associations = Vec::new();
    let mut bootstraps = Vec::new();
    let mut registered = false;
    for (pin, bytes) in lineage.controls.iter().zip(records) {
        match pin.kind {
            ControlKind::Registration => registered = &pin.owner == registration,
            ControlKind::Association => {
                associations.push(OriginalAssociation::decode(bytes).map_err(|_| invalid())?)
            }
            ControlKind::Bootstrap => {
                bootstraps.push(OriginalBootstrap::decode(bytes).map_err(|_| invalid())?)
            }
            // Imported contexts must use actual paired original/import/trust
            // retention. The ordinary local owner cannot certify that authority.
            ControlKind::Import | ControlKind::ImportBinding | ControlKind::ImportTrust => {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
        }
    }
    if !registered {
        return Err(invalid());
    }
    for view in &lineage.used.views {
        let association = associations
            .iter()
            .find(|row| row.commit == view.view)
            .ok_or_else(invalid)?;
        if !bootstraps.iter().any(|bootstrap| {
            bootstrap.original_id == association.original_id
                && bootstrap.ref_name == association.ref_name
                && bootstrap.epoch == association.epoch
        }) {
            return Err(invalid());
        }
    }
    associations
        .into_iter()
        .find(|row| row.commit == lineage.commit_id)
        .ok_or_else(invalid)
}
