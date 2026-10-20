//! Requalifies ordinary local ownership against this collector's actual current cycle.

use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::lease::Collector;
use crate::gc::runner::{CollectionError, session::Session};
use crate::guard::{Guard, OriginalAuthority};
use crate::selected_bridge::CheckedCurrentCollection;
use crate::store::native_publication_effects::collection_local_deletion::{
    self as effects, NativeLocalDeletion,
};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use std::sync::Arc;
use terrane_format::gc::{DeleteOperation, DeletePhase, GcRoots, GcState, Windows};

/// Retains actual current qualification and an executor-produced owned observation.
pub(crate) struct CheckedLocalDeletion<'operation, 'held> {
    current: CheckedCurrentCollection<'operation, 'held>,
    observed: Arc<NativeLocalDeletion>,
    fresh_pairs: Vec<crate::store::native_publication_effects::NativeCurrentPair>,
}

impl<'operation, 'held> CheckedLocalDeletion<'operation, 'held> {
    /// Borrows complete current roots, selected catalog and whole lease authority.
    pub(crate) fn current(&self) -> &CheckedCurrentCollection<'operation, 'held> {
        &self.current
    }

    /// Borrows independently qualified fresh placement descriptors used by current roots.
    pub(crate) fn fresh_pairs(
        &self,
    ) -> &[crate::store::native_publication_effects::NativeCurrentPair] {
        &self.fresh_pairs
    }

    /// Borrows the actual native ownership and incarnation observations.
    pub(crate) fn observed(&self) -> &Arc<NativeLocalDeletion> {
        &self.observed
    }
}

fn denied() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "gc-local-deletion",
        pattern: "current exact owned local artifacts".into(),
    })
}

/// Recovers one protected intent only beneath genuinely completed current marking.
///
/// # Errors
/// Refuses old or incomplete checkpoints, changed roots, marked old dependencies,
/// lost whole lease, unknown ownership, replacements and actual durability failures.
pub(crate) async fn resume<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &mut Session,
    checkpoint: (&GcRoots, &GcState),
    windows: Windows,
    key: &str,
) -> Result<DeleteOperation, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let collector = Collector::new(guard, authority);
    let holder = SingleHeld::acquire(guard.store()).await?;
    let held = holder.destination();
    let first = held.observe_publication_unrepaired().await?;
    let current = super::native_current_collection::qualify(
        guard, authority, session, &held, &first, checkpoint, windows,
    )
    .await?;
    let retained = current
        .effect_context()
        .controls()
        .first()
        .ok_or_else(denied)?
        .clone();
    drop(current);
    let mut lease_context = collector.held(&held, Some(&retained)).await?;
    loop {
        session.renew_held(&mut lease_context).await?;
        let selected = held.observe_publication_unrepaired().await?;
        let current = super::native_current_collection::qualify_retained(
            guard,
            authority,
            session,
            &held,
            &selected,
            (checkpoint, windows),
            Some(&retained),
        )
        .await?;
        let metadata = MetadataStore::new(&held, &selected, session);
        let catalog = metadata.collection_catalog().await?;
        let generation = catalog.capabilities().generation.ok_or_else(denied)?;
        let observed = Arc::new(effects::observe(held.fs(), &current, key, generation).await?);
        let authorization = &observed.operation().authorization;
        if catalog
            .burns()?
            .binary_search(&authorization.pack_id)
            .is_ok()
            || !catalog.exclusions()?.iter().any(|row| {
                row.pack_id == authorization.pack_id
                    && row.cycle == authorization.cycle
                    && row.epoch == authorization.epoch
            })
        {
            return Err(denied().into());
        }
        let inventory = catalog
            .inventory()?
            .iter()
            .find(|row| row.pack_id == authorization.pack_id)
            .ok_or_else(denied)?;
        let expected = [
            terrane_format::gc::ArtifactBinding::Pack {
                digest: inventory.pack_hash,
                size: inventory.pack_size,
            },
            terrane_format::gc::ArtifactBinding::Index {
                digest: inventory.index_hash,
                size: inventory.index_size,
            },
        ];
        if authorization.artifacts[..2]
            .iter()
            .zip(&expected)
            .any(|(version, binding)| &version.binding != binding)
        {
            return Err(denied().into());
        }
        let mut fresh_pairs = Vec::new();
        let mut verified = std::collections::BTreeSet::new();
        for entry in observed.snapshot().entries() {
            if current.member_unmarked(entry.hash()) {
                continue;
            }
            // Current marked uses must resolve through a different, eligible
            // selected physical placement, never through this retained witness.
            let row = catalog
                .shards()
                .iter()
                .flat_map(|shard| shard.entries())
                .find(|row| {
                    row.entry().hash() == entry.hash()
                        && row.entry().kind() == entry.kind()
                        && row.state() == crate::pack::RecordState::Live
                        && row.pack().as_bytes() != &authorization.pack_id
                })
                .ok_or_else(denied)?;
            let id = *row.pack().as_bytes();
            if catalog
                .exclusions()?
                .iter()
                .any(|excluded| excluded.pack_id == id)
                || catalog.burns()?.binary_search(&id).is_ok()
            {
                return Err(denied().into());
            }
            let read = metadata.pack_index(&catalog, row.pack()).await?;
            let actual = read
                .snapshot()
                .entries()
                .iter()
                .find(|candidate| candidate.hash() == entry.hash())
                .ok_or_else(denied)?;
            if actual.kind() != row.entry().kind()
                || actual.offset() != row.entry().offset()
                || actual.body_len() != row.entry().body_len()
                || actual.plaintext_len() != row.entry().plaintext_len()
                || actual.codec() != row.entry().codec()
            {
                return Err(denied().into());
            }
            if verified.insert(id) {
                fresh_pairs.push(
                    crate::store::native_publication_effects::observe_current_pair(
                        held.fs(),
                        &selected,
                        &read,
                    )
                    .await?,
                );
            }
        }
        // Selected serving entries cannot advertise an owned physical container,
        // regardless of its current presence or the mutable operation's phase.
        if catalog
            .shards()
            .iter()
            .flat_map(|shard| shard.entries())
            .any(|row| {
                row.pack().as_bytes() == &authorization.pack_id
                    && row.state() == crate::pack::RecordState::Live
            })
        {
            return Err(denied().into());
        }
        current.revalidate().await?;
        let checked = CheckedLocalDeletion {
            current,
            observed,
            fresh_pairs,
        };
        let done = checked.observed.operation().phase == DeletePhase::Done;
        let result = effects::advance(held.fs(), &checked).await?;
        session.recheck()?;
        if done {
            return Ok(result);
        }
    }
}
