//! Renews whole collector leases beneath one genuine retained publication holder.
//!
//! The context borrows an actual namespace holder and retains its configured
//! Guard registration, exact consumed controls and one native clock. It accepts
//! only acknowledged own lease transitions; canonical records remain data.

use super::*;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::publication::receipts::RecordRead;
use crate::gc::runner::session::Session;
use crate::guard::{ControlExclusion, RetainedControls};
use std::sync::atomic::{AtomicBool, Ordering};
use terrane_core::gc::publication::evidence::RequiredControlPin;

/// Retains genuine configuration and controls beneath the borrowed namespace.
pub(crate) struct HeldLeaseContext<'held, 'configuration, F: LocalFs, B, V, C> {
    held: &'held HeldBucket<'configuration, F, B, V, true>,
    guard: &'configuration Guard<FileBucket<F, B, V>, C>,
    authority: &'configuration OriginalAuthority,
    controls: Option<ControlExclusion<'configuration, F>>,
    pins: Vec<RequiredControlPin>,
    original: RetainedControls,
    guard_record: RecordRead,
    observed: SelectedObservation<'held>,
    snapshot: Vec<u8>,
    clock: Shared<Continuity>,
}

struct Continuity {
    clock: NativeEffectClock,
    last: Mutex<(Duration, Duration)>,
    poisoned: AtomicBool,
}

impl Continuity {
    fn sample(&self, expiry: u64, old_expiry: Option<u64>) -> Result<u64, StoreFailure> {
        let monotonic = self.clock.monotonic();
        let wall = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?;
        let mut last = self.last.lock().map_err(|_| denied())?;
        if self.poisoned.load(Ordering::Acquire)
            || monotonic < last.0
            || wall < last.1
            || wall.as_secs() >= expiry
            || old_expiry.is_some_and(|bound| wall.as_secs() >= bound)
        {
            self.poisoned.store(true, Ordering::Release);
            return Err(denied());
        }
        *last = (monotonic, wall);
        Ok(wall.as_secs())
    }
}

struct PublicationOperation {
    clock: Shared<Continuity>,
    completed: bool,
}

impl Drop for PublicationOperation {
    fn drop(&mut self) {
        if !self.completed {
            self.clock.poisoned.store(true, Ordering::Release);
        }
    }
}

impl<'held, 'configuration, F, B, V, C> HeldLeaseContext<'held, 'configuration, F, B, V, C>
where
    'configuration: 'held,
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Retains actual selected configuration and registration under this holder.
    ///
    /// # Errors
    /// Refuses another backend/configuration, changed selected Guard, unavailable
    /// native clock or exclusions and invalid consumed protected registration.
    pub(super) async fn new(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
        held: &'held HeldBucket<'configuration, F, B, V, true>,
    ) -> Result<Self, LeaseError> {
        Self::create(guard, authority, held, None).await
    }

    /// Reuses genuine already-retained controls without acquiring another lock.
    ///
    /// # Errors
    /// Refuses another configured namespace/Original, altered receipt
    /// associations, pins or actual protected paths and unavailable clock retention.
    pub(super) async fn from_retained(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
        held: &'held HeldBucket<'configuration, F, B, V, true>,
        retained: &RetainedControls,
    ) -> Result<Self, LeaseError> {
        Self::create(guard, authority, held, Some(retained)).await
    }

    async fn create(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
        held: &'held HeldBucket<'configuration, F, B, V, true>,
        existing: Option<&RetainedControls>,
    ) -> Result<Self, LeaseError> {
        let (profile_name, profile) = guard.store().publication_profile();
        if held.root() != guard.store().root()
            || held.root() != authority.root()
            || held.physical_identity() != authority.physical_identity()
            || authority.domain() != guard.config().storage_domain
            || profile_name != guard.config().chunk_profile_name
            || profile != guard.config().chunk_profile.as_ref()
        {
            return Err(denied().into());
        }

        held.retained_namespace()?;
        let observed = held.observe_publication_unrepaired().await?;
        let clock = guard.clock().retain_native_clock().map_err(|error| {
            StoreFailure::with_source(
                if error.kind() == std::io::ErrorKind::Unsupported {
                    StoreErrorKind::Unsupported
                } else {
                    StoreErrorKind::Unavailable { retry_after: None }
                },
                error,
            )
        })?;
        let started = clock.monotonic();
        let wall = clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?;
        let clock = Shared::new(Continuity {
            clock,
            last: Mutex::new((started, wall)),
            poisoned: AtomicBool::new(false),
        });
        clock.sample(u64::MAX, None)?;

        let consumed = ConsumedResolver::new(guard, authority)?;
        consumed.registration(authority)?;
        let snapshot = consumed.snapshot_bytes()?;
        let guard_record = held
            .selected_guard_snapshot_record(&observed)
            .await?
            .ok_or_else(denied)?;
        if guard_record.bytes() != Some(snapshot.as_slice()) {
            return Err(denied().into());
        }
        let used = consumed.finish()?;
        let owner = crate::guard::consumed_registration(authority);
        if used.controls.is_empty() || used.controls.iter().any(|pin| pin.owner != owner) {
            return Err(denied().into());
        }
        let (mut controls, original) = match existing {
            Some(retained) => {
                if retained.directory() != authority.control()
                    || retained.owner() != observed.configured_operator_uid()
                {
                    return Err(denied().into());
                }
                revalidate_controls(held.fs(), retained, &used.controls).await?;
                (None, retained.clone())
            }
            None => {
                let mut controls = guard
                    .hold_original_registration(authority, observed.identity())
                    .await?;
                let retained = controls.retain_used(&used.controls).await?;
                (Some(controls), retained)
            }
        };
        observed.revalidate().await?;
        if let Some(controls) = &mut controls {
            controls.revalidate().await?;
        }
        clock.sample(u64::MAX, None)?;

        Ok(Self {
            held,
            guard,
            authority,
            controls,
            pins: used.controls,
            original,
            guard_record,
            observed,
            snapshot,
            clock,
        })
    }

    /// Selects a whole lease using only this context's actual held authority.
    ///
    /// # Errors
    /// Refuses stale whole lease/configuration/control/preimages, discontinuous
    /// clocks, expiry, prior cancellation and failed or missing durable acknowledgment.
    pub(super) async fn publish(
        &mut self,
        proposal: Proposal,
        session: Option<&Session>,
    ) -> Result<LeaseReceipt, LeaseError> {
        let mut operation = PublicationOperation {
            clock: Shared::clone(&self.clock),
            completed: false,
        };

        self.observed.revalidate().await?;
        if let Some(controls) = &mut self.controls {
            controls.revalidate().await?;
        }
        let current_selection = self.held.observe_publication_unrepaired().await?;
        if current_selection.stamp() != self.observed.stamp()
            || current_selection.state() != self.observed.state()
            || current_selection.logical() != self.observed.logical()
            || current_selection.physical_reads().len() != self.observed.physical_reads().len()
        {
            return Err(denied().into());
        }
        for (old, current) in self
            .observed
            .physical_reads()
            .iter()
            .zip(current_selection.physical_reads())
        {
            if !same_read(old, current)? {
                return Err(denied().into());
            }
        }

        let consumed = ConsumedResolver::new(self.guard, self.authority)?;
        consumed.registration(self.authority)?;
        if consumed.snapshot_bytes()? != self.snapshot || consumed.finish()?.controls != self.pins {
            return Err(denied().into());
        }
        let guard_record = self
            .held
            .selected_guard_snapshot_record(&self.observed)
            .await?
            .ok_or_else(denied)?;
        if !same_read(&self.guard_record, &guard_record)? {
            return Err(denied().into());
        }

        revalidate_controls(self.held.fs(), &self.original, &self.pins).await?;
        let retained = match &mut self.controls {
            Some(controls) => controls.retain_used(&self.pins).await?,
            None => self.original.clone(),
        };
        same_controls(&self.original, &retained)?;

        let current = self
            .observed
            .logical()
            .get("gc/lease")
            .ok_or_else(denied)?
            .as_deref()
            .map(GcLease::decode)
            .transpose()?;
        let wall = self.clock.sample(u64::MAX, None)?;
        let (lease, old_expiry) = match proposal {
            Proposal::Acquire { holder, duration } => (
                GcLease::acquire(holder, wall, duration, current.as_ref())?,
                None,
            ),
            Proposal::Renew {
                current: expected,
                duration,
            } => {
                expected.check(current.as_ref(), wall)?;
                (expected.renew(wall, duration)?, Some(expected.expiry))
            }
        };

        let clock = Shared::clone(&self.clock);
        let expiry = lease.expiry;
        let session_check = session.map(Session::owned_check);
        let final_check = OwnedFinalCheck {
            check: Shared::new(move || {
                clock.sample(expiry, old_expiry)?;
                if let Some(check) = &session_check {
                    check()?;
                }
                Ok(())
            }),
        };
        final_check.recheck()?;
        let mut next = self.observed.state().clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(terrane_core::gc::GcError::Exhausted)?;
        let change = LogicalChange {
            key: "gc/lease".into(),
            expected: self
                .observed
                .logical()
                .get("gc/lease")
                .ok_or_else(denied)?
                .clone(),
            new: Some(lease.encode()?),
        };
        let checked = CheckedGcLease {
            observed: &self.observed,
            guard: self.guard_record.clone(),
            next,
            change,
            effects: GcLeaseEffectContext {
                final_check,
                controls: vec![retained],
            },
        };
        let selected = crate::store::native_publication_effects::collection::publish_checked(
            self.held.fs(),
            &checked,
        )
        .await?;

        let after = self.held.observe_publication_unrepaired().await?;
        let mut logical = self.observed.logical().clone();
        logical.insert("gc/lease".into(), checked.change().new.clone());
        if after.stamp() != (selected.revision, selected.digest)
            || after.state() != checked.next()
            || after.logical() != &logical
        {
            return Err(denied().into());
        }
        same_unchanged_reads(&self.observed, &after)?;
        if let Some(controls) = &mut self.controls {
            controls.revalidate().await?;
        }
        revalidate_controls(self.held.fs(), &self.original, &self.pins).await?;
        checked.recheck_before_slot()?;
        after.revalidate().await?;
        let guard_record = self
            .held
            .selected_guard_snapshot_record(&after)
            .await?
            .ok_or_else(denied)?;
        if !same_read(&self.guard_record, &guard_record)? {
            return Err(denied().into());
        }

        // The last protected observation must not move acknowledgment past the
        // old expiry or hide a clock rollback before the context is refreshed.
        checked.recheck_before_slot()?;
        self.observed = after;
        operation.completed = true;
        Ok(LeaseReceipt {
            lease,
            revision: selected.revision,
        })
    }

    /// Renews the exact selected whole lease for a genuine current Session.
    ///
    /// # Errors
    /// Preserves whole-lease rejection, clock/expiry/control refusal and actual
    /// durable publication errors; failed/cancelled renewal poisons this context.
    pub(crate) async fn renew(
        &mut self,
        session: &Session,
        duration: u64,
    ) -> Result<LeaseReceipt, LeaseError> {
        self.publish(
            Proposal::Renew {
                current: session.lease().clone(),
                duration,
            },
            Some(session),
        )
        .await
    }
}

#[cfg(unix)]
async fn revalidate_controls<F: LocalFs + BucketBinding>(
    fs: &F,
    controls: &RetainedControls,
    pins: &[RequiredControlPin],
) -> Result<(), StoreFailure> {
    use std::os::unix::fs::MetadataExt;
    let unavailable =
        |error| StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error);
    for ancestor in controls.ancestors() {
        let metadata = fs
            .symlink_metadata(ancestor.path())
            .await
            .map_err(unavailable)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.dev(), metadata.ino()) != ancestor.identity()
            || (metadata.uid(), metadata.mode() & 0o7777) != ancestor.protection()
        {
            return Err(denied());
        }
    }
    let (directory, lock) = controls.identities();
    let metadata = fs
        .symlink_metadata(controls.directory())
        .await
        .map_err(unavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (metadata.dev(), metadata.ino()) != directory
        || metadata.uid() != controls.owner()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(denied());
    }
    let metadata = fs
        .symlink_metadata(&controls.directory().join("retention.lock"))
        .await
        .map_err(unavailable)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || (metadata.dev(), metadata.ino()) != lock
        || metadata.uid() != controls.owner()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(denied());
    }
    for pin in pins {
        let path = controls.directory().join(&pin.key);
        let record = controls
            .records()
            .iter()
            .find(|record| record.path() == path)
            .ok_or_else(denied)?;
        pin.check_record(record.bytes()).map_err(|_| denied())?;
    }
    for record in controls.records() {
        let before = fs
            .symlink_metadata(record.path())
            .await
            .map_err(unavailable)?;
        if !before.is_file()
            || before.file_type().is_symlink()
            || (before.dev(), before.ino()) != record.identity()
            || before.uid() != controls.owner()
            || before.nlink() != 1
            || before.mode() & 0o777 != 0o600
            || fs.read_nofollow(record.path()).await.map_err(unavailable)? != record.bytes()
        {
            return Err(denied());
        }
        let after = fs
            .symlink_metadata(record.path())
            .await
            .map_err(unavailable)?;
        if !same_metadata(Some(&before), Some(&after))? {
            return Err(denied());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn revalidate_controls<F: LocalFs + BucketBinding>(
    _: &F,
    _: &RetainedControls,
    _: &[RequiredControlPin],
) -> Result<(), StoreFailure> {
    Err(StoreFailure::new(StoreErrorKind::Unsupported))
}

fn same_controls(before: &RetainedControls, after: &RetainedControls) -> Result<(), StoreFailure> {
    if before.directory() != after.directory()
        || before.owner() != after.owner()
        || before.identities() != after.identities()
        || before.ancestors() != after.ancestors()
        || before.records().len() != after.records().len()
        || before
            .records()
            .iter()
            .zip(after.records())
            .any(|(old, new)| {
                old.path() != new.path()
                    || old.identity() != new.identity()
                    || old.bytes() != new.bytes()
            })
    {
        return Err(denied());
    }
    Ok(())
}

fn same_read(before: &RecordRead, after: &RecordRead) -> Result<bool, StoreFailure> {
    Ok(before.path() == after.path()
        && before.bytes() == after.bytes()
        && same_metadata(before.metadata(), after.metadata())?)
}

// Only this acknowledged operation's selected slot and lease/pointer cache may
// change. Every previously selected immutable/control read remains exact.
fn same_unchanged_reads(
    before: &SelectedObservation<'_>,
    after: &SelectedObservation<'_>,
) -> Result<(), StoreFailure> {
    let root = before.identity().root();
    let own_slot = format!("publication/commits/{}", after.state().revision);
    for old in before.physical_reads() {
        if old.path() == root.join("gc/lease")
            || old.path() == root.join("publication/PORTABLE")
            || old.path().ends_with(&own_slot)
        {
            continue;
        }
        let new = after
            .physical_reads()
            .iter()
            .find(|read| read.path() == old.path())
            .ok_or_else(denied)?;
        if old.bytes() != new.bytes() || !same_metadata(old.metadata(), new.metadata())? {
            return Err(denied());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_metadata(
    before: Option<&std::fs::Metadata>,
    after: Option<&std::fs::Metadata>,
) -> Result<bool, StoreFailure> {
    use std::os::unix::fs::MetadataExt;
    Ok(match (before, after) {
        (None, None) => true,
        (Some(old), Some(new)) => {
            (
                old.dev(),
                old.ino(),
                old.mode(),
                old.uid(),
                old.gid(),
                old.len(),
                old.mtime(),
                old.mtime_nsec(),
                old.ctime(),
                old.ctime_nsec(),
            ) == (
                new.dev(),
                new.ino(),
                new.mode(),
                new.uid(),
                new.gid(),
                new.len(),
                new.mtime(),
                new.mtime_nsec(),
                new.ctime(),
                new.ctime_nsec(),
            )
        }
        _ => false,
    })
}

#[cfg(not(unix))]
fn same_metadata(
    _: Option<&std::fs::Metadata>,
    _: Option<&std::fs::Metadata>,
) -> Result<bool, StoreFailure> {
    Err(StoreFailure::new(StoreErrorKind::Unsupported))
}
