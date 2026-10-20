//! Derives first local ownership from a genuine triple and uninterrupted renewed wait.

use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::{self, MetadataStore};
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::lease::Collector;
use crate::gc::runner::{CollectionError, session::Session};
use crate::guard::{Guard, OriginalAuthority};
use crate::pack::PackId;
use crate::selected_bridge::CheckedCurrentCollection;
use crate::store::native_publication_effects::collection_local_ownership::{
    self as effects, NativeLocalTriple,
};
use crate::store::{
    Clock, ContentValidator, LocalFs, NativeEffectFailure, StoreErrorKind, StoreFailure,
};
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::bucket::PackExclusion;
use terrane_format::gc::{
    DeleteAuthorization, DeleteOperation, DeletePhase, GcError, GcRoots, GcState, Tombstone,
    Windows,
};

/// Retains live current qualification and a privately completed first-ownership wait.
pub(crate) struct CheckedLocalOwnership<'operation, 'held> {
    current: CheckedCurrentCollection<'operation, 'held>,
    triple: NativeLocalTriple,
    operation: DeleteOperation,
}

impl<'operation, 'held> CheckedLocalOwnership<'operation, 'held> {
    /// Borrows the independently verified complete current authority.
    pub(crate) fn current(&self) -> &CheckedCurrentCollection<'operation, 'held> {
        &self.current
    }

    /// Borrows the executor-produced actual triple.
    pub(crate) fn triple(&self) -> &NativeLocalTriple {
        &self.triple
    }

    /// Borrows canonical output data fixed by the live producer, never reusable permission.
    pub(crate) fn operation(&self) -> &DeleteOperation {
        &self.operation
    }
}

fn denied() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "gc-first-ownership",
        pattern: "current exact retired local triple".into(),
    })
}

fn native(error: NativeEffectFailure) -> StoreFailure {
    match error {
        NativeEffectFailure::Rejected(error) => error,
        NativeEffectFailure::Io(error) => StoreFailure::with_source(
            if error.kind() == std::io::ErrorKind::Unsupported {
                StoreErrorKind::Unsupported
            } else {
                StoreErrorKind::Unavailable { retry_after: None }
            },
            error,
        ),
    }
}

/// Waits full D while genuinely renewing one exact held whole lease, then owns its triple.
///
/// # Errors
/// Refuses changed authority/incarnations, missing creator evidence, failed timing or renewal,
/// incomplete fresh roots, clock discontinuity and actual protected publication failure.
pub(crate) async fn own<'configuration, F, B, V, C>(
    guard: &'configuration Guard<FileBucket<F, B, V>, C>,
    authority: &'configuration OriginalAuthority,
    session: &mut Session,
    checkpoint: (&GcRoots, &GcState),
    windows: Windows,
    requested: &PackExclusion,
) -> Result<DeleteOperation, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    session.recheck()?;
    let collector = Collector::new(guard, authority);
    #[cfg(test)]
    ownership_stage("holder", requested);
    let holder = SingleHeld::acquire(guard.store()).await?;
    let held = holder.destination();
    #[cfg(test)]
    ownership_stage("initial-observation", requested);
    let observed = held.observe_publication_unrepaired().await?;
    #[cfg(test)]
    ownership_stage("initial-qualification", requested);
    let current = super::native_current_collection::qualify(
        guard, authority, session, &held, &observed, checkpoint, windows,
    )
    .await?;
    #[cfg(test)]
    ownership_stage("catalog", requested);
    let metadata = MetadataStore::new(&held, &observed, session);
    let catalog = metadata.collection_catalog().await?;
    let exclusions = catalog.exclusions()?;
    let position = exclusions
        .binary_search_by_key(&requested.pack_id, |row| row.pack_id)
        .map_err(|_| denied())?;
    if exclusions.get(position) != Some(requested)
        || catalog.burns()?.binary_search(&requested.pack_id).is_ok()
        || requested.cycle != checkpoint.0.cycle
        || requested.epoch != session.lease().epoch
    {
        return Err(denied().into());
    }
    let pack = PackId::from_random_bytes(requested.pack_id);
    let read = metadata.pack_index(&catalog, pack).await?;
    if !current.members_unmarked(read.snapshot()) {
        return Err(denied().into());
    }
    let trash =
        collection_observation::record(&held, &format!("trash/{}/{}", requested.cycle, pack))
            .await?;
    let tombstone = Tombstone::decode(trash.bytes().ok_or_else(denied)?)?;
    if tombstone.pack != requested.pack_id
        || tombstone.cycle != requested.cycle
        || tombstone.epoch != requested.epoch
    {
        return Err(denied().into());
    }
    #[cfg(test)]
    ownership_stage("triple-observation", requested);
    let triple = effects::observe(held.fs(), &current, &read, &trash, &tombstone).await?;
    if !windows.sweep_age(
        session.recheck()?,
        triple.pair_modified_unix_seconds().map_err(native)?,
    ) {
        return Err(denied().into());
    }
    if triple.inventory() != read.inventory() || triple.snapshot() != read.snapshot() {
        return Err(denied().into());
    }
    let retained = current
        .effect_context()
        .controls()
        .first()
        .ok_or_else(denied)?
        .clone();
    let mut baseline = observed.logical().clone();
    baseline.remove("gc/lease");
    drop(metadata);
    drop(current);
    let clock = session.clock()?;
    let started = clock.monotonic();
    let required = Duration::from_secs(windows.deletion());
    windows
        .deletion()
        .checked_mul(1_000_000_000)
        .ok_or(GcError::Exhausted)?;
    let mut lease_context = collector.held(&held, Some(&retained)).await?;

    #[cfg(test)]
    ownership_stage("deletion-wait", requested);
    loop {
        session.recheck()?;
        triple.recheck().map_err(native)?;
        let elapsed = clock.monotonic().checked_sub(started).ok_or_else(denied)?;
        if elapsed >= required {
            break;
        }
        session.renew_held(&mut lease_context).await?;
        triple.recheck().map_err(native)?;
        {
            let fresh = held.observe_publication_unrepaired().await?;
            let mut logical = fresh.logical().clone();
            logical.remove("gc/lease");
            if logical != baseline {
                return Err(denied().into());
            }
            let current = super::native_current_collection::qualify_retained(
                guard,
                authority,
                session,
                &held,
                &fresh,
                (checkpoint, windows),
                Some(&retained),
            )
            .await?;
            if !current.members_unmarked(triple.snapshot()) {
                return Err(denied().into());
            }
            current.revalidate().await?;
        }
        session.recheck()?;
        let wall = clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?;
        let lifetime = Duration::from_secs(session.lease().expiry)
            .checked_sub(wall)
            .ok_or_else(denied)?;
        let remaining =
            required.checked_sub(clock.monotonic().checked_sub(started).ok_or_else(denied)?);
        if let Some(remaining) = remaining {
            let interval = remaining.min(lifetime / 2).min(Duration::from_secs(1));
            if interval.is_zero() {
                return Err(denied().into());
            }
            clock.sleep(interval).await.map_err(|error| {
                StoreFailure::with_source(
                    if error.kind() == std::io::ErrorKind::Unsupported {
                        StoreErrorKind::Unsupported
                    } else {
                        StoreErrorKind::Unavailable { retry_after: None }
                    },
                    error,
                )
            })?;
        }
    }
    #[cfg(test)]
    ownership_stage("deletion-wait-complete", requested);
    session.renew_held(&mut lease_context).await?;
    triple.recheck().map_err(native)?;
    let fresh = held.observe_publication_unrepaired().await?;
    let mut logical = fresh.logical().clone();
    logical.remove("gc/lease");
    if logical != baseline {
        return Err(denied().into());
    }
    #[cfg(test)]
    ownership_stage("final-qualification", requested);
    let current = super::native_current_collection::qualify_retained(
        guard,
        authority,
        session,
        &held,
        &fresh,
        (checkpoint, windows),
        Some(&retained),
    )
    .await?;
    #[cfg(test)]
    ownership_stage("final-qualification-complete", requested);
    if !current.members_unmarked(triple.snapshot()) {
        return Err(denied().into());
    }
    let elapsed_ns = u64::try_from(
        clock
            .monotonic()
            .checked_sub(started)
            .ok_or_else(denied)?
            .as_nanos(),
    )
    .map_err(|_| GcError::Exhausted)?;
    let nonce = held
        .fs()
        .random_bytes(32)
        .await
        .map_err(|error| {
            StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
        })?
        .try_into()
        .map_err(|_| denied())?;
    let authorization = DeleteAuthorization {
        nonce,
        pack_id: requested.pack_id,
        cycle: requested.cycle,
        epoch: requested.epoch,
        original_lease: session.lease().clone(),
        deletion_seconds: windows.deletion(),
        artifacts: triple.versions().map_err(native)?,
        index_witness: triple.index_witness().map_err(native)?,
        elapsed_ns,
    };
    authorization.encode()?;
    let operation = DeleteOperation {
        authorization,
        phase: DeletePhase::Authorized,
        revision: 0,
        current_lease: session.lease().clone(),
    };
    let checked = CheckedLocalOwnership {
        current,
        triple,
        operation,
    };
    #[cfg(test)]
    ownership_stage("native-publication", requested);
    Ok(effects::publish(held.fs(), &checked).await?)
}

/// Reports phase boundaries without supplying collector time or authority.
#[cfg(test)]
fn ownership_stage(phase: &'static str, requested: &PackExclusion) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!(
            "gc-local-ownership-stage phase={phase} pack={:?} process_at={:?}",
            requested.pack_id,
            crate::diagnostic_clock::tick(),
        );
    }
}
