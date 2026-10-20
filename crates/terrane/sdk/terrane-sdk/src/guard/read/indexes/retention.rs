//! Retains the configured native Original controls and exact selected preimages.
//!
//! All records originate in real installed Original contexts or configured roles.
//! This receipt provides synchronization only; ordinary history and live request
//! checks independently establish each query result's eligibility.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

use super::{IndexLookupCurrentWork, IndexLookupError, count};
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::{SelectedObservation, receipts::RecordRead};
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{
    ConsumedResolver, ControlExclusion, Guard, OriginalAuthority, RetainedControls,
};
use crate::repository::local_authority::retention::Record as _;
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use terrane_format::gc::publication::evidence::GuardSnapshot;

/// Owns actual read data and duplicate exclusion, never a query authorization.
pub(in crate::guard) struct Inputs {
    /// Same genuinely acquired native controls with original incarnations.
    pub(super) controls: RetainedControls,
    /// Actual protected selected Guard observed before history and query work.
    pub(super) guard: RecordRead,
}

impl Inputs {
    /// Borrows the actual retained controls without exposing construction.
    pub(in crate::guard) fn controls(&self) -> &RetainedControls {
        &self.controls
    }
}

/// Captures only exact control records derived from this actual configured Guard.
///
/// # Errors
/// Refuses foreign physical owners, changed selected Guard, unsafe/replaced records,
/// unavailable native retention and contradictory installed Original contexts.
pub(in crate::guard) async fn capture<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    controls: &mut ControlExclusion<'_, F>,
    held: &HeldBucket<'_, F, B, V, false>,
    observed: &SelectedObservation<'_>,
) -> Result<Inputs, IndexLookupError>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding + Sync,
    V: ContentValidator + BucketBinding + Sync,
{
    let configured = ConsumedResolver::new(guard, authority)?;
    configured.registration(authority)?;
    let expected_snapshot = configured.snapshot_bytes()?;
    let selected_guard = held
        .selected_guard_snapshot_record(observed)
        .await?
        .ok_or(crate::guard::invalid())?;
    if selected_guard.bytes() != Some(expected_snapshot.as_slice()) {
        return Err(crate::guard::invalid().into());
    }
    let snapshot =
        GuardSnapshot::decode(&expected_snapshot).map_err(|_| crate::guard::invalid())?;
    guard
        .check_retained_trust_controls(authority, controls, &snapshot)
        .await?;
    // These are opaque contexts installed by the real native factory, never caller rows.
    // The map lock is released before filesystem awaits.
    let originals = guard
        .original_commits
        .read()
        .map_err(|_| {
            StoreFailure::new(crate::store::StoreErrorKind::Unavailable { retry_after: None })
        })?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for original in &originals {
        configured.original(original)?;
    }
    let pins = configured.finish()?.controls;
    let actual_owner = crate::guard::consumed_registration(authority);
    let mut expected = BTreeMap::new();
    for pin in pins {
        if pin.owner != actual_owner {
            return Err(crate::guard::invalid().into());
        }
        let bytes = controls.read_record(&pin.key).await?;
        pin.check_record(&bytes)
            .map_err(|_| crate::guard::invalid())?;
        if expected
            .insert(pin.key, bytes.clone())
            .is_some_and(|old| old != bytes)
        {
            return Err(crate::guard::invalid().into());
        }
    }
    for role in guard.configured_disclosure_roles()? {
        let key = role.selector().map_err(crate::guard::retention_failure)?;
        let bytes = role.encode().map_err(crate::guard::retention_failure)?;
        if controls.read_record(&key).await? != bytes {
            return Err(crate::guard::invalid().into());
        }
        if expected
            .insert(key, bytes.clone())
            .is_some_and(|old| old != bytes)
        {
            return Err(crate::guard::invalid().into());
        }
    }
    let controls = controls
        .retain_named(&expected.into_iter().collect::<Vec<_>>())
        .await?;
    observed.revalidate().await?;
    check_read(held.fs(), &selected_guard).await?;
    Ok(Inputs {
        controls,
        guard: selected_guard,
    })
}

/// Checks initial native incarnations and the final actual consumed inputs.
///
/// # Errors
/// Refuses changed records, controls, selected closure, configured roles or actual owners;
/// preserves nofollow I/O failures without changing their typed category.
pub(in crate::guard) async fn finish<F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    controls: &mut ControlExclusion<'_, F>,
    inputs: &Inputs,
    observed: &SelectedObservation<'_>,
    consumed: &ConsumedResolver,
    work: &mut IndexLookupCurrentWork,
) -> Result<(), IndexLookupError>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding + Sync,
    V: ContentValidator + BucketBinding + Sync,
{
    observed.revalidate().await?;
    count(&mut work.selection_rechecks, 1)?;
    let snapshot =
        GuardSnapshot::decode(&consumed.snapshot_bytes()?).map_err(|_| crate::guard::invalid())?;
    guard
        .check_retained_trust_controls(authority, controls, &snapshot)
        .await?;
    for pin in consumed.finish()?.controls {
        if pin.owner != crate::guard::consumed_registration(authority) {
            return Err(crate::guard::invalid().into());
        }
        let path = inputs.controls.directory().join(&pin.key);
        let record = inputs
            .controls
            .records()
            .iter()
            .find(|record| record.path() == path)
            .ok_or(crate::guard::invalid())?;
        pin.check_record(record.bytes())
            .map_err(|_| crate::guard::invalid())?;
    }
    let fs = guard.store().fs();
    for ancestor in inputs.controls.ancestors() {
        let actual = fs.symlink_metadata(ancestor.path()).await.map_err(io)?;
        if !actual.is_dir()
            || actual.file_type().is_symlink()
            || (actual.dev(), actual.ino()) != ancestor.identity()
            || (actual.uid(), actual.mode() & 0o7777) != ancestor.protection()
        {
            return Err(crate::guard::invalid().into());
        }
    }
    controls.revalidate().await?;
    for record in inputs.controls.records() {
        let before = fs.symlink_metadata(record.path()).await.map_err(io)?;
        if !before.is_file()
            || before.file_type().is_symlink()
            || before.nlink() != 1
            || before.uid() != inputs.controls.owner()
            || before.mode() & 0o777 != 0o600
            || (before.dev(), before.ino()) != record.identity()
        {
            return Err(crate::guard::invalid().into());
        }
        let bytes = fs.read_nofollow(record.path()).await.map_err(io)?;
        let after = fs.symlink_metadata(record.path()).await.map_err(io)?;
        if bytes != record.bytes() || metadata(&before) != metadata(&after) {
            return Err(crate::guard::invalid().into());
        }
        count(&mut work.control_record_checks, 1)?;
    }
    check_read(fs, &inputs.guard).await?;
    count(&mut work.physical_read_checks, 1)?;
    for read in observed.physical_reads() {
        check_read(fs, read).await?;
        count(&mut work.physical_read_checks, 1)?;
    }
    observed.revalidate().await?;
    count(&mut work.selection_rechecks, 1)?;
    controls.revalidate().await?;
    Ok(())
}

/// Compares the exact native incarnation, protection and body metadata read.
#[derive(Eq, PartialEq)]
struct Fingerprint {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

fn metadata(value: &std::fs::Metadata) -> Fingerprint {
    Fingerprint {
        device: value.dev(),
        inode: value.ino(),
        owner: value.uid(),
        mode: value.mode(),
        links: value.nlink(),
        length: value.len(),
        modified_seconds: value.mtime(),
        modified_nanoseconds: value.mtime_nsec(),
    }
}

async fn check_read<F: LocalFs + Sync>(fs: &F, read: &RecordRead) -> Result<(), IndexLookupError> {
    let before = match fs.symlink_metadata(read.path()).await {
        Ok(value) => Some(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(io(error).into()),
    };
    match (read.metadata(), read.bytes(), before) {
        (None, None, None) => Ok(()),
        (Some(expected), Some(expected_bytes), Some(before))
            if before.is_file()
                && !before.file_type().is_symlink()
                && metadata(expected) == metadata(&before) =>
        {
            let actual = fs.read_nofollow(read.path()).await.map_err(io)?;
            let after = fs.symlink_metadata(read.path()).await.map_err(io)?;
            if actual != expected_bytes || metadata(expected) != metadata(&after) {
                return Err(crate::guard::invalid().into());
            }
            Ok(())
        }
        _ => Err(crate::guard::invalid().into()),
    }
}

fn io(error: std::io::Error) -> StoreFailure {
    crate::guard::time::retention_failure(error)
}
