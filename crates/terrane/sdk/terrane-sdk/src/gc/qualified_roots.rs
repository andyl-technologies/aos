//! Completes independently selected root histories under their own signed scope.
//!
//! The closed factories derive roots from actual selection. Cycle roots
//! come from authoritative logical checkpoint bytes; physical caches are kept
//! separately. Current roots come from complete inventory and actual Session
//! time; source roots preserve those actual retention cutoffs under an independent trace.
//! The resulting history reuse grants no retirement or deletion authority.

use crate::bucket::BucketBinding;
use crate::bucket::held::{HeldBucket, HeldIdentity};
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::bucket::publication::receipts::RecordRead;
use crate::bucket::publication::{SelectedObservation, collection_observation};
use crate::gc::runner::{CollectionError, denied, roots, session::Session};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation, VerifiedCollectionTree};
use crate::store::{Clock, ContentValidator, LocalFs};
use std::collections::BTreeMap;
use terrane_format::gc::{GcLease, GcRoots, GcState, Phase, RootReason, Windows};
use terrane_format::identity::Digest;

/// Keeps selected cycle data and its distinct physical cache preimages together.
struct CycleSnapshot {
    state: GcState,
    roots_read: RecordRead,
    state_read: RecordRead,
    selected_roots: Vec<u8>,
    selected_state: Vec<u8>,
}

enum Basis {
    Cycle(Box<CycleSnapshot>),
    Current { inputs: Vec<RecordRead> },
    Source { inputs: Vec<RecordRead> },
}

/// Retains complete own-context history of every genuinely selected snapshot root.
///
/// Its fields and basis constructors are private to this producer module. The
/// exact observation identity and resolver references prevent cross-invocation
/// reuse; the Session borrow keeps current clock and poison checks live. No
/// caller root set, expanded-state membership or decoder constructs this type.
pub(crate) struct QualifiedCollectionRoots<'operation> {
    identity: &'operation HeldIdentity<'operation>,
    consumed: &'operation ConsumedResolver,
    session: &'operation Session,
    lease: GcLease,
    snapshot: GcRoots,
    histories: BTreeMap<Digest, VerifiedCollectionTree>,
    guard_read: RecordRead,
    basis: Basis,
}

impl QualifiedCollectionRoots<'_> {
    fn recheck(&self) -> Result<(), CollectionError> {
        let now = self.session.recheck()?;
        self.session.lease().check(Some(&self.lease), now)?;
        Ok(())
    }

    /// Checks exact held-observation and trace identity before scoped history reuse.
    ///
    /// # Errors
    /// Refuses another holder/observation/resolver, lost native retention,
    /// Session poison, actual clock rollback or live whole lease expiry.
    /// It does not replace the producer's async selected-state revalidation or
    /// the worker's retained complete preimage and control checks.
    pub(crate) fn check_binding(
        &self,
        observation: HistoryObservation<'_>,
        consumed: &ConsumedResolver,
    ) -> Result<(), CollectionError> {
        self.recheck()?;
        if !observation
            .identity()
            .is_some_and(|identity| std::ptr::eq(identity, self.identity))
            || !observation.tracks(consumed)
            || !std::ptr::eq(consumed, self.consumed)
        {
            return Err(denied().into());
        }
        self.identity.retained_namespace()?;
        Ok(())
    }

    /// Borrows an independently completed producer in that producer's own signed scope.
    ///
    /// # Errors
    /// Refuses Session poison, rollback, lost whole ownership or expiry. None
    /// means the producer is not independently qualified by this actual snapshot;
    /// catalog claims and old expanded contexts cannot add an entry.
    pub(crate) fn history(
        &self,
        commit: &Digest,
    ) -> Result<Option<&VerifiedCollectionTree>, CollectionError> {
        self.recheck()?;
        Ok(self.histories.get(commit))
    }

    /// Finds an exact dependency layer context established by completed root histories.
    ///
    /// # Errors
    /// Refuses changed Session ownership or conflicting signed root expectations.
    pub(crate) fn contextual_layer(
        &self,
        commit: &Digest,
    ) -> Result<Option<Digest>, CollectionError> {
        self.recheck()?;
        let mut selected = None;
        for root in self.histories.values() {
            if let Some(layer) = root.completed().contextual_layer(commit) {
                if selected.is_some_and(|previous| previous != layer) {
                    return Err(denied().into());
                }
                selected = Some(layer);
            }
        }
        Ok(selected)
    }

    /// Borrows the actual authenticated snapshot without providing a constructor.
    pub(crate) fn snapshot(&self) -> &GcRoots {
        &self.snapshot
    }

    /// Borrows the exact authoritative selected cycle state.
    ///
    /// # Errors
    /// Refuses use of a freshly recomputed CurrentSnapshot as cycle checkpoint
    /// evidence and preserves current Session refusal.
    pub(in crate::selected_bridge) fn cycle_state(&self) -> Result<&GcState, CollectionError> {
        self.recheck()?;
        match &self.basis {
            Basis::Cycle(cycle) => Ok(&cycle.state),
            Basis::Current { .. } | Basis::Source { .. } => Err(denied().into()),
        }
    }

    /// Borrows physical root/state cache preimages separately from selection.
    ///
    /// # Errors
    /// Refuses a current-snapshot basis and preserves Session refusal. Physical
    /// bytes may validly differ from the authoritative logical checkpoint.
    pub(in crate::selected_bridge) fn cycle_reads(
        &self,
    ) -> Result<(&RecordRead, &RecordRead), CollectionError> {
        self.recheck()?;
        match &self.basis {
            Basis::Cycle(cycle) => Ok((&cycle.roots_read, &cycle.state_read)),
            Basis::Current { .. } | Basis::Source { .. } => Err(denied().into()),
        }
    }

    /// Borrows the exact authoritative logical root/state bytes for pointer digests.
    ///
    /// # Errors
    /// Refuses a current-snapshot basis and preserves Session refusal. These
    /// values are selected data, never reconstructed from physical caches.
    pub(in crate::selected_bridge) fn cycle_bytes(
        &self,
    ) -> Result<(&[u8], &[u8]), CollectionError> {
        self.recheck()?;
        match &self.basis {
            Basis::Cycle(cycle) => Ok((&cycle.selected_roots, &cycle.selected_state)),
            Basis::Current { .. } | Basis::Source { .. } => Err(denied().into()),
        }
    }

    /// Borrows every exact selected ref/log input consumed by current or source selection.
    ///
    /// # Errors
    /// Refuses substituting cycle data for fresh current-root inputs and
    /// preserves current Session refusal.
    pub(in crate::selected_bridge) fn current_inputs(
        &self,
    ) -> Result<&[RecordRead], CollectionError> {
        self.recheck()?;
        match &self.basis {
            Basis::Current { inputs } | Basis::Source { inputs } => Ok(inputs),
            Basis::Cycle(_) => Err(denied().into()),
        }
    }

    /// Borrows the exact protected selected Guard read for native preimage retention.
    pub(in crate::selected_bridge) fn guard_read(&self) -> &RecordRead {
        &self.guard_read
    }
}

async fn validate<F, B, V, C>(
    history: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    consumed: &ConsumedResolver,
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &SelectedObservation<'_>,
    session: &Session,
) -> Result<(GcLease, RecordRead), CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    history.store().check_binding(held, observed, session)?;
    consumed.check_guard(history)?;
    let selected = observed
        .logical()
        .get("gc/lease")
        .and_then(Option::as_deref)
        .map(GcLease::decode)
        .transpose()?;
    session
        .lease()
        .check(selected.as_ref(), session.recheck()?)?;
    let guard_read = held
        .selected_guard_snapshot_record(observed)
        .await?
        .ok_or_else(denied)?;
    let configured = consumed.snapshot_bytes()?;
    if observed.state().guard != Some(*blake3::hash(&configured).as_bytes())
        || guard_read.bytes() != Some(configured.as_slice())
        || observed.identity().root() != held.root()
        || observed.identity().physical_identity() != held.physical_identity()
        || !observed.identity().writable()
    {
        return Err(denied().into());
    }
    held.retained_namespace()?;
    observed.revalidate().await?;
    Ok((selected.ok_or_else(denied)?, guard_read))
}

async fn complete<F, B, V, C>(
    history: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    consumed: &ConsumedResolver,
    observed: &SelectedObservation<'_>,
    session: &Session,
    snapshot: &GcRoots,
) -> Result<BTreeMap<Digest, VerifiedCollectionTree>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let observation = HistoryObservation::held(observed.identity()).tracked(consumed);
    let mut histories = BTreeMap::new();
    for root in &snapshot.roots {
        session.recheck()?;
        if histories.contains_key(&root.commit) {
            continue;
        }
        // This is the root's own independent signed scope. No consuming A
        // EntryLocation or certified audit edge is passed to this verifier.
        let verified = history
            .verified_collection_tree_observed(root.commit, observation)
            .await?;
        histories.insert(root.commit, verified);
    }
    observation.finish()?;
    observed.revalidate().await?;
    session.recheck()?;
    Ok(histories)
}

/// Derives complete independent root histories from actual selected cycle bytes.
///
/// # Errors
/// Refuses absent or malformed authoritative logical roots/state, mismatched
/// cycle/epoch/snapshot, unfinished physical sweep progress, incomplete signed
/// history, different metadata binding/Guard configuration or lost Session.
/// Valid stale physical cache bytes remain retained preimages, not corruption.
pub(crate) async fn cycle<'operation, F, B, V, C>(
    history: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    consumed: &'operation ConsumedResolver,
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &'operation SelectedObservation<'_>,
    session: &'operation Session,
    cycle: u64,
) -> Result<QualifiedCollectionRoots<'operation>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let (lease, guard_read) = validate(history, consumed, held, observed, session).await?;
    let root_key = format!("gc/{cycle}/roots");
    let state_key = format!("gc/{cycle}/state");
    let selected_roots = observed
        .logical()
        .get(&root_key)
        .and_then(Option::as_ref)
        .ok_or_else(denied)?
        .clone();
    let selected_state = observed
        .logical()
        .get(&state_key)
        .and_then(Option::as_ref)
        .ok_or_else(denied)?
        .clone();
    let snapshot = GcRoots::decode(&selected_roots)?;
    let state = GcState::decode(&selected_state)?;
    if snapshot.cycle != cycle
        || state.cycle != cycle
        || snapshot.timestamp != state.snapshot_at
        || snapshot.epoch != state.epoch
        || state.epoch != lease.epoch
        || !matches!(state.phase, Phase::Mark | Phase::Sweep)
        || !state.progress.is_empty()
    {
        return Err(denied().into());
    }
    let roots_read = collection_observation::record(held, &root_key).await?;
    let state_read = collection_observation::record(held, &state_key).await?;
    let histories = complete(history, consumed, observed, session, &snapshot).await?;
    Ok(QualifiedCollectionRoots {
        identity: observed.identity(),
        consumed,
        session,
        lease,
        snapshot,
        histories,
        guard_read,
        basis: Basis::Cycle(Box::new(CycleSnapshot {
            state,
            roots_read,
            state_read,
            selected_roots,
            selected_state,
        })),
    })
}

/// Derives fresh independent root histories from complete authoritative current inventory.
///
/// # Errors
/// Preserves actual inventory/log/retention and signed-history failures. Refuses
/// unknown completeness, another held adapter/Session/Guard configuration,
/// stale selection, cancellation, clock rollback or whole live lease expiry.
/// Epoch/time come from the actual Session; caller snapshot bytes are never used.
pub(crate) async fn current<'operation, F, B, V, C>(
    history: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    consumed: &'operation ConsumedResolver,
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &'operation SelectedObservation<'_>,
    session: &'operation Session,
    settings: (u64, Windows),
) -> Result<QualifiedCollectionRoots<'operation>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let (cycle, windows) = settings;
    let (lease, guard_read) = validate(history, consumed, held, observed, session).await?;
    // Even an empty root set requires genuinely complete current catalog data;
    // legacy Unknown inventory/exclusions/burns cannot stand for known empty.
    history.store().collection_catalog().await?;
    let mut inputs = Vec::new();
    let refs = collection_observation::inventory(held, observed, &mut inputs).await?;
    let snapshot = roots::snapshot(
        history,
        consumed,
        HistoryObservation::held(observed.identity()).tracked(consumed),
        refs,
        roots::SnapshotSettings {
            cycle,
            epoch: lease.epoch,
            timestamp: session.recheck()?,
            windows,
        },
    )
    .await?;
    let histories = complete(history, consumed, observed, session, &snapshot).await?;
    Ok(QualifiedCollectionRoots {
        identity: observed.identity(),
        consumed,
        session,
        lease,
        snapshot,
        histories,
        guard_read,
        basis: Basis::Current { inputs },
    })
}

/// Derives one full retained source root from the closed current snapshot.
///
/// The source name is only a selector. The whole ref, history, clock, lease and
/// completed signed scope are independently derived under this exact holder.
/// The actual current reason and cutoff remain unchanged. A witness-only head
/// returns no eligible source, while its ordinary witness metadata stays retained.
/// This factory does not accept lineage bytes, raw roots or caller cutoffs.
///
/// # Errors
/// Refuses absent selected source/ref, incomplete inventory, different actual
/// Guard/Session binding, failed own-context history or lost current authority.
pub(crate) async fn source<'operation, F, B, V, C>(
    history: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    consumed: &'operation ConsumedResolver,
    held: &HeldBucket<'_, F, B, V, true>,
    observed: &'operation SelectedObservation<'_>,
    session: &'operation Session,
    settings: (&str, &QualifiedCollectionRoots<'_>),
) -> Result<Option<QualifiedCollectionRoots<'operation>>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let (name, current) = settings;
    let (lease, guard_read) = validate(history, consumed, held, observed, session).await?;
    current.recheck()?;
    if !matches!(current.basis, Basis::Current { .. })
        || !std::ptr::eq(current.identity, observed.identity())
        || !std::ptr::eq(current.session, session)
        || current.lease != lease
        || current.snapshot.epoch != lease.epoch
    {
        return Err(denied().into());
    }
    if !observed
        .state()
        .sources
        .iter()
        .any(|source| source.name == name)
    {
        return Err(denied().into());
    }
    history.store().collection_catalog().await?;
    let mut inputs = Vec::new();
    let inventory = collection_observation::inventory(held, observed, &mut inputs).await?;
    let selected = inventory
        .iter()
        .find(|row| row.name.as_str() == name)
        .ok_or_else(denied)?;
    let reference = selected.current.as_ref().ok_or_else(denied)?;
    // The current factory emits each actual head before that name's reflog
    // rows. Its closed basis and exact identity bind this first row to the
    // independently selected whole current Ref, including expired lease policy.
    let root = current
        .snapshot
        .roots
        .iter()
        .find(|root| root.reference == selected.name)
        .ok_or_else(denied)?;
    if root.commit != reference.commit {
        return Err(denied().into());
    }
    match root.reason {
        RootReason::RetentionWitness => return Ok(None),
        RootReason::Current | RootReason::Tag | RootReason::Lease | RootReason::Job => {}
        _ => return Err(denied().into()),
    }
    let snapshot = GcRoots {
        cycle: current.snapshot.cycle,
        epoch: current.snapshot.epoch,
        timestamp: current.snapshot.timestamp,
        roots: vec![root.clone()],
    };
    let histories = complete(history, consumed, observed, session, &snapshot).await?;
    Ok(Some(QualifiedCollectionRoots {
        identity: observed.identity(),
        consumed,
        session,
        lease,
        snapshot,
        histories,
        guard_read,
        basis: Basis::Source { inputs },
    }))
}
