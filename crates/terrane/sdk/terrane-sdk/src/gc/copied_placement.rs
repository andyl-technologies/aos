//! Qualifies current copied DATA under genuine destination maintenance authority.
//!
//! Fresh destination registration, the actual selected Guard, whole live lease,
//! complete refs/history and current eligible containers are independently read.
//! Foreign Original permission is not inferred or required for this physical
//! placement check. The result carries no lineage, barrier age or delete right.

#[path = "copied_placement/artifacts.rs"]
mod artifacts;
#[path = "copied_placement/data.rs"]
mod data;
#[path = "copied_placement/ordinary.rs"]
mod ordinary;

pub(crate) use artifacts::PlacementArtifacts;

use super::{GcCheckpointEffectContext, GcControlOwner, OwnedFinalCheck};
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::publication::collection_observation::{self, MetadataStore};
use crate::bucket::publication::receipts::{GcPackRead, RecordRead};
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::runner::{CollectionError, session::Session};
use crate::guard::{ConsumedResolver, Guard, OriginalAuthority, RetainedControls};
use crate::pack::{PackClass, PackId, RecordState};
use crate::selected_bridge::native_permanent_local::CheckedPermanentLocalOwner;
use crate::store::{Clock, ContentStore, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use std::collections::BTreeSet;
use terrane_format::bucket::{BucketCapabilities, BucketKey, GenerationManifest};
use terrane_format::gc::publication::{
    Activation, BackendRegistration, CommittedSelection, PermanentOwnerSelection,
    PublicationCommit, PublicationTransaction,
};
use terrane_format::gc::retirement::{FenceRef, OwnershipSlot};
use terrane_format::gc::{GcLease, GcRoot, ParentCutoff, RootReason};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::refs::RefClass;

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;

/// Retains independently checked current DATA and destination native controls.
///
/// Private fields prevent decoded copied records from constructing this result.
/// It borrows the actual selected holder and Session through every subsequent
/// effect. No foreign historical permission or carried lineage is represented.
pub(crate) struct CheckedDataPlacement<'operation, 'held> {
    observed: &'operation SelectedObservation<'held>,
    session: &'operation Session,
    pack: [u8; 16],
    genesis: OwnershipSlot,
    refs: Vec<FenceRef>,
    roots: Vec<GcRoot>,
    snapshot_at: u64,
    checkpoint_cycle: Option<u64>,
    packs: Vec<GcPackRead>,
    traversal: data::Traversal,
    capabilities: Vec<u8>,
    manifest: Vec<u8>,
    guard: RecordRead,
    reads: Vec<RecordRead>,
    effects: GcCheckpointEffectContext,
}

impl<'operation, 'held> CheckedDataPlacement<'operation, 'held> {
    /// Borrows the actual current destination selection.
    pub(crate) fn observed(&self) -> &'operation SelectedObservation<'held> {
        self.observed
    }

    /// Borrows the actual live destination Session used for this DATA check.
    pub(crate) fn session(&self) -> &'operation Session {
        self.session
    }

    /// Returns the copied visibility-only family qualified by this invocation.
    pub(crate) fn pack(&self) -> [u8; 16] {
        self.pack
    }

    /// Borrows the genuine earlier destination fresh-copy genesis association.
    pub(crate) fn genesis(&self) -> &OwnershipSlot {
        &self.genesis
    }

    /// Borrows every exact current ref and retained selected absence/history.
    pub(crate) fn refs(&self) -> &[FenceRef] {
        &self.refs
    }

    /// Borrows the complete conservative physical root set, without pruning.
    pub(crate) fn roots(&self) -> &[GcRoot] {
        &self.roots
    }

    /// Returns the actual qualified snapshot time without relabeling it.
    pub(super) fn snapshot_at(&self) -> u64 {
        self.snapshot_at
    }

    /// Returns the authenticated fresh cycle, if an ordinary walk fixed one.
    pub(super) fn checkpoint_cycle(&self) -> Option<u64> {
        self.checkpoint_cycle
    }

    /// Borrows actual metadata-only eligible container/index observations.
    pub(crate) fn packs(&self) -> &[GcPackRead] {
        &self.packs
    }

    /// Borrows actual completed unbounded commit expansions without proof authority.
    pub(crate) fn expanded(&self) -> &[terrane_format::gc::ExpandedContext] {
        &self.traversal.commits
    }

    /// Borrows exact sorted current eligible identities held without pruning.
    pub(crate) fn hashes(&self) -> &[Digest] {
        &self.traversal.hashes
    }

    /// Borrows actual typed structural expansions without proof pruning.
    pub(crate) fn objects(&self) -> &[terrane_format::gc::ExpandedObject] {
        &self.traversal.objects
    }

    /// Borrows whole actual selected CAPABILITIES bytes.
    pub(crate) fn capabilities(&self) -> &[u8] {
        &self.capabilities
    }

    /// Borrows whole actual selected MANIFEST bytes.
    pub(crate) fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// Borrows the physically observed actual selected destination Guard.
    pub(crate) fn guard(&self) -> &RecordRead {
        &self.guard
    }

    /// Borrows every physical DATA and history preimage retained by qualification.
    pub(crate) fn reads(&self) -> &[RecordRead] {
        &self.reads
    }

    /// Borrows genuine complete retained destination control and clock predicates.
    pub(crate) fn effects(&self) -> &GcCheckpointEffectContext {
        &self.effects
    }

    /// Rechecks the whole selected state and actual Session before publication.
    ///
    /// # Errors
    /// Refuses changed selection, expired ownership or interrupted clock continuity.
    pub(crate) async fn revalidate(&self) -> Result<(), StoreFailure> {
        self.session.recheck()?;
        self.observed.revalidate().await?;
        self.session.recheck()?;
        Ok(())
    }
}

/// Qualifies DATA specifically for the still-unowned copied visibility selector.
///
/// The private wrapper distinguishes first ownership from recurring checks of
/// an already permanent owner. DATA observations alone are not first-owner
/// authorization, lineage certification or elapsed barrier permission.
pub(crate) struct CheckedCopiedPlacement<'operation, 'held> {
    data: CheckedDataPlacement<'operation, 'held>,
}

impl<'operation, 'held> CheckedCopiedPlacement<'operation, 'held> {
    /// Borrows independently checked current physical DATA observations.
    pub(crate) fn data(&self) -> &CheckedDataPlacement<'operation, 'held> {
        &self.data
    }

    /// Proposes fresh physical checkpoints without granting first ownership.
    ///
    /// # Errors
    /// Refuses mismatched holders, occupied names, changed current DATA and
    /// expired leases. Actual installation still requires a closed native ACK.
    pub(crate) async fn artifacts<F, B, V>(
        &self,
        held: &HeldBucket<'_, F, B, V, true>,
    ) -> Result<PlacementArtifacts, StoreFailure>
    where
        F: LocalFs + BucketBinding,
        B: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    {
        PlacementArtifacts::fresh(&self.data, held).await
    }
}

/// Retains current DATA with its independently checked existing permanent owner.
///
/// This distinct result grants no first-ownership or lineage permission. The
/// owner remains borrowed from the sibling's actual selected-authority check.
pub(crate) struct CheckedOwnedPlacement<'operation, 'held> {
    data: CheckedDataPlacement<'operation, 'held>,
    owner: &'operation CheckedPermanentLocalOwner<'operation, 'held>,
}

impl<'operation, 'held> CheckedOwnedPlacement<'operation, 'held> {
    /// Borrows independently checked current physical DATA observations.
    pub(crate) fn data(&self) -> &CheckedDataPlacement<'operation, 'held> {
        &self.data
    }

    /// Borrows the genuine already-selected owner without copying permission.
    pub(crate) fn owner(&self) -> &'operation CheckedPermanentLocalOwner<'operation, 'held> {
        self.owner
    }

    /// Rechecks both the actual owner and current DATA selection and Session.
    ///
    /// # Errors
    /// Refuses changed owner/control/selection or expired whole lease/clock.
    pub(crate) async fn revalidate(&self) -> Result<(), StoreFailure> {
        self.owner.revalidate().await?;
        self.data.revalidate().await
    }

    /// Proposes fresh physical checkpoints for this actual current-owned DATA.
    ///
    /// The encoder chooses its own destination cycle and retains real absence
    /// observations. A consuming closed native producer must install and select
    /// these exact bytes before treating their fence as a current checkpoint.
    ///
    /// # Errors
    /// Refuses changed owner/selection, mismatched holders, occupied checkpoint
    /// names, failed entropy and expired whole leases.
    pub(crate) async fn artifacts<F, B, V>(
        &self,
        held: &HeldBucket<'_, F, B, V, true>,
    ) -> Result<PlacementArtifacts, StoreFailure>
    where
        F: LocalFs + BucketBinding,
        B: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    {
        self.revalidate().await?;
        let artifacts = PlacementArtifacts::fresh(&self.data, held).await?;
        self.revalidate().await?;
        Ok(artifacts)
    }
}

enum PlacementOwner<'operation, 'held> {
    Copied,
    Permanent(&'operation CheckedPermanentLocalOwner<'operation, 'held>),
}

fn denied() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "gc-copied-placement",
        pattern: "current destination copied DATA".into(),
    })
}

fn digest(bytes: &[u8]) -> Digest {
    *blake3::hash(bytes).as_bytes()
}

fn genesis(
    observed: &SelectedObservation<'_>,
    copied_pack: Option<&[u8; 16]>,
) -> Result<OwnershipSlot, StoreFailure> {
    let registration = observed.physical_reads().first().ok_or_else(denied)?;
    let control = registration.path().parent().ok_or_else(denied)?;
    if registration.path() != control.join("backend-registration.cbor") {
        return Err(denied());
    }
    let registration = BackendRegistration::decode(registration.bytes().ok_or_else(denied)?)
        .map_err(|_| denied())?;
    if registration.activation != Activation::Active
        || registration.binding != observed.state().binding
    {
        return Err(denied());
    }
    let expected = registration.genesis.ok_or_else(denied)?;
    let slot = observed
        .physical_reads()
        .iter()
        .find(|read| read.path() == control.join("publication/commits/0"))
        .and_then(RecordRead::bytes)
        .ok_or_else(denied)?;
    let commit = PublicationCommit::decode(slot).map_err(|_| denied())?;
    if commit.revision != 0 || commit.predecessor.is_some() || digest(slot) != expected {
        return Err(denied());
    }
    let transaction = observed
        .physical_reads()
        .iter()
        .find(|read| read.path() == control.join(&commit.transaction_key))
        .and_then(RecordRead::bytes)
        .ok_or_else(denied)?;
    commit
        .check_transaction("publication/commits/0", transaction)
        .map_err(|_| denied())?;
    let transaction = PublicationTransaction::decode(transaction).map_err(|_| denied())?;
    if transaction.old.is_some()
        || transaction.new.revision != 0
        || transaction.new.binding != registration.binding
        || !transaction.new.sources.is_empty()
        || copied_pack.is_some_and(|pack| {
            transaction.new.burn_owners.as_ref().is_none_or(|owners| {
                !owners.iter().any(|owner| {
                    owner.pack == *pack
                        && owner.selection == PermanentOwnerSelection::CopiedVisibility
                })
            })
        })
    {
        return Err(denied());
    }
    Ok(OwnershipSlot {
        revision: 0,
        digest: expected,
    })
}

/// Qualifies complete current copied placement under an actual retained holder.
///
/// Existing controls reuse their genuine exclusion during same-holder renewal;
/// otherwise the destination's configured registration factory acquires it.
/// Complete eligible Live DATA is retained conservatively. No foreign authority
/// is guessed and no root, historical ref or metadata edge is pruned.
///
/// # Errors
/// Refuses incomplete inventory/history, unresolved Live DATA, burned or
/// excluded fallback, stale destination Guard/lease/registration, unsafe native
/// controls and any canonical identity or dependency disagreement.
pub(crate) async fn qualify<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    pack: [u8; 16],
    retained: Option<&RetainedControls>,
) -> Result<CheckedCopiedPlacement<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let data = qualify_data(
        guard,
        authority,
        session,
        held,
        observed,
        (pack, PlacementOwner::Copied),
        (retained, None),
    )
    .await?;
    Ok(CheckedCopiedPlacement { data })
}

/// Qualifies current DATA for one genuinely checked existing permanent owner.
///
/// This entry cannot qualify first ownership. It compares the exact same held
/// selection and Session against the independently constructed opaque owner.
///
/// # Errors
/// Refuses another holder/Session/genesis/selected owner, expired authority or
/// any incomplete current DATA/control check shared with physical qualification.
pub(crate) async fn qualify_current_owned<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    owner: &'operation CheckedPermanentLocalOwner<'operation, 'held>,
    settings: (Option<&RetainedControls>, &terrane_format::gc::Windows),
) -> Result<CheckedOwnedPlacement<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let (retained, windows) = settings;
    if !std::ptr::eq(owner.observed(), observed) || !std::ptr::eq(owner.session(), session) {
        return Err(denied().into());
    }
    owner.revalidate().await?;
    let data = qualify_data(
        guard,
        authority,
        session,
        held,
        observed,
        (owner.pack(), PlacementOwner::Permanent(owner)),
        (retained, Some(windows)),
    )
    .await?;
    owner.revalidate().await?;
    Ok(CheckedOwnedPlacement { data, owner })
}

async fn qualify_data<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    placement: ([u8; 16], PlacementOwner<'operation, 'held>),
    settings: (
        Option<&RetainedControls>,
        Option<&terrane_format::gc::Windows>,
    ),
) -> Result<CheckedDataPlacement<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let (pack, owner) = placement;
    let (retained, windows) = settings;
    let now = session.recheck()?;
    let lease = observed
        .logical()
        .get("gc/lease")
        .and_then(Option::as_deref)
        .map(GcLease::decode)
        .transpose()?;
    session.lease().check(lease.as_ref(), now)?;
    observed.revalidate().await?;
    if held.root() != observed.identity().root()
        || held.physical_identity() != observed.identity().physical_identity()
        || guard.store().root() != held.root()
        || authority.root() != held.root()
        || authority.physical_identity().0 != held.physical_identity().0
        || guard.store().publication_operator_uid() != Some(observed.configured_operator_uid())
        || !observed.identity().writable()
    {
        return Err(denied().into());
    }
    held.retained_namespace()?;
    // First copied ownership requires the actual copied-visibility genesis.
    // A separately checked permanent Sweep owner instead binds the registered
    // ordinary destination genesis; its pack need not have existed at creation.
    let copied_pack = match &owner {
        PlacementOwner::Copied => Some(&pack),
        PlacementOwner::Permanent(owner) => match owner.authorization() {
            terrane_format::gc::retirement::PermanentDeleteAuthorization::Copied(_) => Some(&pack),
            terrane_format::gc::retirement::PermanentDeleteAuthorization::Sweep(_) => None,
        },
    };
    let genesis = genesis(observed, copied_pack)?;
    let ordinary_sweep = matches!(&owner, PlacementOwner::Permanent(owner)
        if matches!(owner.authorization(), terrane_format::gc::retirement::PermanentDeleteAuthorization::Sweep(_)));
    let selection = match owner {
        PlacementOwner::Copied => PermanentOwnerSelection::CopiedVisibility,
        PlacementOwner::Permanent(owner) => {
            if owner.genesis() != &genesis {
                return Err(denied().into());
            }
            PermanentOwnerSelection::Permanent(owner.selected_owner().clone())
        }
    };
    if observed.state().burn_owners.as_ref().is_none_or(|owners| {
        !owners
            .iter()
            .any(|owner| owner.pack == pack && owner.selection == selection)
    }) {
        return Err(denied().into());
    }

    let consumed = ConsumedResolver::new(guard, authority)?;
    consumed.registration(authority)?;
    let snapshot = consumed.snapshot_bytes()?;
    let guard_read = held
        .selected_guard_snapshot_record(observed)
        .await?
        .ok_or_else(denied)?;
    if guard_read.bytes() != Some(snapshot.as_slice())
        || observed.state().guard != Some(digest(&snapshot))
    {
        return Err(denied().into());
    }
    let metadata = MetadataStore::new(held, observed, session);
    let catalog = metadata.collection_catalog().await?;
    let inventory = catalog.inventory()?;
    let exclusions = catalog.exclusions()?;
    let burns = catalog.burns()?;
    if burns.binary_search(&pack).is_err() {
        return Err(denied().into());
    }
    let mut reads = Vec::new();
    let references = collection_observation::inventory(held, observed, &mut reads).await?;
    let mut roots = Vec::new();
    for reference in &references {
        if let Some(current) = &reference.current {
            roots.push(GcRoot {
                reference: reference.name.clone(),
                commit: current.commit,
                parent_cutoff: ParentCutoff::Unbounded,
                reason: RootReason::Current,
            });
        }
        let mut history = BTreeSet::new();
        for log in &reference.logs {
            history.insert(log.record.commit);
            history.extend(log.previous_commit);
        }
        for commit in history {
            roots.push(GcRoot {
                reference: reference.name.clone(),
                commit,
                parent_cutoff: ParentCutoff::Unbounded,
                // D-113 describes the destination's conservative physical
                // hold, never a verified foreign retain=forever property.
                reason: RootReason::Forever,
            });
        }
    }
    let capabilities =
        BucketCapabilities::decode(catalog.capability_bytes()).map_err(|_| denied())?;
    let mut refs = Vec::new();
    for name in capabilities.ref_names.as_ref().ok_or_else(denied)? {
        let key = BucketKey::ref_record(name).map_err(|_| denied())?;
        let current = observed
            .logical()
            .get(key.as_str())
            .ok_or_else(denied)?
            .clone();
        let class = terrane_format::refs::RefName::parse(name)
            .map_err(|_| denied())?
            .class();
        let branch = matches!(
            class,
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        );
        let selection = if branch {
            observed
                .state()
                .branches
                .iter()
                .find(|row| row.name == *name)
                .ok_or_else(denied)?
                .selection
                .clone()
        } else {
            CommittedSelection::Never
        };
        let log = match &selection {
            CommittedSelection::Selected(record) => Some(
                references
                    .iter()
                    .find(|reference| reference.name.as_str() == name)
                    .ok_or_else(denied)?
                    .logs
                    .iter()
                    .find(|log| log.record == **record)
                    .ok_or_else(denied)?
                    .clone(),
            ),
            CommittedSelection::Never => None,
            CommittedSelection::Unknown => return Err(denied().into()),
        };
        refs.push(FenceRef {
            name: name.clone(),
            current,
            selection,
            log,
        });
    }

    let generation = capabilities.generation.ok_or_else(denied)?;
    let manifest = observed
        .logical()
        .get(&format!("objects/index/{generation}/MANIFEST"))
        .and_then(Option::as_ref)
        .ok_or_else(denied)?
        .clone();
    let decoded = GenerationManifest::decode(&manifest).map_err(|_| denied())?;
    for shard in &decoded.shards {
        for suffix in std::iter::once("idx").chain(shard.filter.iter().map(|_| "flt")) {
            let key = format!("objects/index/{generation}/{}.{suffix}", shard.shard);
            let read = collection_observation::record(held, &key).await?;
            if read.bytes() != observed.logical().get(&key).and_then(Option::as_deref) {
                return Err(denied().into());
            }
            reads.push(read);
        }
    }
    let mut bodies = data::Bodies::new();
    let mut chunks = data::Chunks::new();
    let mut packs = Vec::new();
    for row in inventory {
        if burns.binary_search(&row.pack_id).is_ok()
            || exclusions
                .iter()
                .any(|excluded| excluded.pack_id == row.pack_id)
        {
            continue;
        }
        // The detached index and actual protected regular-file metadata bind
        // placement without opening or decoding a data-pack chunk body (GC-9).
        packs.push(
            metadata
                .pack_index(&catalog, PackId::from_random_bytes(row.pack_id))
                .await?,
        );
    }
    // Ordinary Sweep metadata is fetched only by the authenticated walker,
    // after its disclosure and retention decisions. Eager conservative copied
    // loading must not probe unrelated expired or private audit dependencies.
    if !ordinary_sweep {
        for row in catalog
            .shards()
            .iter()
            .flat_map(crate::pack::MergedShard::entries)
        {
            if row.state() != RecordState::Live {
                continue;
            }
            let container_id = row.pack();
            let id = container_id.as_bytes();
            // Burned/excluded catalog rows are not currently served DATA. Their
            // mere Live row state cannot make the retired family eligible again.
            // The applicable closure check below still refuses any required body
            // that has no independently eligible placement outside that family.
            if burns.binary_search(id).is_ok() || exclusions.iter().any(|row| &row.pack_id == id) {
                continue;
            }
            if *id == pack {
                return Err(denied().into());
            }
            if row.entry().kind().identity_kind() == IdentityKind::Index
                && inventory.iter().any(|record| {
                    record.index_hash == *row.entry().hash()
                        && (burns.binary_search(&record.pack_id).is_ok()
                            || exclusions.iter().any(|row| row.pack_id == record.pack_id))
                })
            {
                // A detached-index alias inherits its family's denial even when
                // copied into an otherwise eligible metadata pack. It never covers
                // a dependency merely because the physical alias is readable.
                continue;
            }
            let container = packs
                .iter()
                .find(|read| &read.inventory().pack_id == id)
                .ok_or_else(denied)?;
            let entry = container
                .snapshot()
                .entries()
                .iter()
                .find(|entry| entry.hash() == row.entry().hash())
                .ok_or_else(denied)?;
            if entry != row.entry() {
                return Err(denied().into());
            }
            if row.entry().kind().identity_kind() == IdentityKind::Chunk {
                if container.snapshot().header().class() != PackClass::Data
                    || chunks.insert(*entry.hash(), entry.clone()).is_some()
                {
                    return Err(denied().into());
                }
                continue;
            }
            if container.snapshot().header().class() != PackClass::Meta {
                return Err(denied().into());
            }
            let identity = TERRANE_V1
                .from_digest(row.entry().kind().identity_kind(), row.entry().hash())
                .map_err(|_| denied())?;
            let bytes = held.get(&identity, None).await?;
            if bodies
                .insert(
                    (
                        row.entry().kind().identity_kind() as u8,
                        *row.entry().hash(),
                    ),
                    bytes,
                )
                .is_some()
            {
                return Err(denied().into());
            }
        }
    }
    let (traversal, snapshot_at, checkpoint_cycle) = if ordinary_sweep {
        let current = ordinary::check(
            guard,
            &consumed,
            held,
            observed,
            session,
            retained,
            windows.ok_or_else(denied)?,
        )
        .await?;
        roots = current.roots.roots;
        reads.extend(current.reads);
        (
            current.traversal,
            current.roots.timestamp,
            Some(current.roots.cycle),
        )
    } else {
        let traversal = data::check(
            &bodies,
            &chunks,
            roots.iter().map(|root| root.commit),
            &guard.config().chunk_profile,
            guard.config().min_chunk_size,
        )?;
        (traversal, now, None)
    };
    reads.extend(metadata.reads()?);
    let used = consumed.finish()?;
    let owner = crate::guard::consumed_registration(authority);
    if used.controls.is_empty() || used.controls.iter().any(|pin| pin.owner != owner) {
        return Err(denied().into());
    }
    let controls = match retained {
        Some(retained) => {
            if retained.directory() != authority.control()
                || retained.owner() != observed.configured_operator_uid()
            {
                return Err(denied().into());
            }
            super::native_collection::revalidate_controls(held.fs(), retained, &used.controls)
                .await?;
            retained.clone()
        }
        None => {
            let mut exclusion = guard
                .hold_original_registration(authority, observed.identity())
                .await?;
            let retained = exclusion.retain_used(&used.controls).await?;
            exclusion.revalidate().await?;
            retained
        }
    };
    observed.revalidate().await?;
    session.recheck()?;
    Ok(CheckedDataPlacement {
        observed,
        session,
        pack,
        genesis,
        refs,
        roots,
        snapshot_at,
        checkpoint_cycle,
        packs,
        traversal,
        capabilities: catalog.capability_bytes().to_vec(),
        manifest,
        guard: guard_read,
        reads,
        effects: GcCheckpointEffectContext {
            lease: session.lease().clone(),
            final_check: OwnedFinalCheck {
                check: Shared::new(session.owned_check()),
            },
            control_owners: vec![GcControlOwner {
                registration: owner,
                configured_operator_uid: observed.configured_operator_uid(),
                pins: used.controls,
            }],
            controls: vec![controls],
        },
    })
}
