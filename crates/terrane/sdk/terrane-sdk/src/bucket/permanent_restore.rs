//! Observes collector-only protected progress without granting serving authority.

#[path = "permanent_restore/candidate.rs"]
pub(crate) mod candidate;

#[path = "permanent_restore/catalog.rs"]
mod catalog;

use super::publication::receipts::RecordRead;
use super::{BucketBinding, files};
use crate::store::{Clock, ContentValidator, LocalFs, NativeProtectedRead, StoreFailure};
use std::path::Path;

/// Reads one canonical permanent event through the protected backend namespace.
///
/// The caller independently checks its selected digest and typed owner binding.
/// This receipt supplies physical predicates, never collection permission.
///
/// # Errors
/// Refuses malformed event keys, unsafe nodes, replacement and unavailable I/O.
pub(crate) async fn read_pass<F: LocalFs + BucketBinding>(
    fs: &F,
    control: &Path,
    key: &str,
    owner: u32,
    cycle: u64,
) -> Result<RecordRead, StoreFailure> {
    let parts: Vec<_> = key.split('/').collect();
    if parts.len() != 5
        || parts[0] != "gc"
        || parts[1] != cycle.to_string()
        || parts[2] != "reconcile"
        || parts[3].len() != 64
        || !parts[3]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || parts[4]
            .parse::<u64>()
            .ok()
            .is_none_or(|revision| revision.to_string() != parts[4])
    {
        return Err(super::publication::corrupt());
    }
    read_protected(fs, control, key, owner).await
}

/// Observes the protected name of a typed current proposed placement fence.
///
/// This returns actual read data only, not checkpoint selection or permission.
///
/// # Errors
/// Refuses another holder, malformed fence association, unregistered backend
/// controls, unsafe physical predicates or changed selected prerequisites.
pub(crate) async fn read_fence<F, B, V>(
    held: &super::held::HeldBucket<'_, F, B, V, true>,
    observed: &super::publication::SelectedObservation<'_>,
    pointer: &terrane_format::gc::retirement::RecordPointer,
    proposed: &[u8],
) -> Result<RecordRead, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    use terrane_format::gc::publication::{Activation, BackendRegistration};
    use terrane_format::gc::retirement::CopiedPlacementFence;

    if held.root() != observed.identity().root()
        || held.physical_identity() != observed.identity().physical_identity()
    {
        return Err(super::publication::corrupt());
    }
    observed.revalidate().await?;
    let fence =
        CopiedPlacementFence::decode(proposed).map_err(|_| super::publication::corrupt())?;
    fence
        .check_pointer(pointer)
        .map_err(|_| super::publication::corrupt())?;
    if fence.state != *observed.state() || fence.backend != observed.state().binding {
        return Err(super::publication::corrupt());
    }
    let registration = observed
        .physical_reads()
        .first()
        .filter(|read| {
            read.path()
                .file_name()
                .is_some_and(|name| name == "backend-registration.cbor")
        })
        .ok_or_else(super::publication::corrupt)?;
    let bytes = registration
        .bytes()
        .ok_or_else(super::publication::corrupt)?;
    let actual = BackendRegistration::decode(bytes).map_err(|_| super::publication::corrupt())?;
    if actual.activation != Activation::Active || actual.binding != observed.state().binding {
        return Err(super::publication::corrupt());
    }
    let control = registration
        .path()
        .parent()
        .ok_or_else(super::publication::corrupt)?;
    let operator = observed.configured_operator_uid();
    let before = held
        .fs()
        .symlink_metadata(control)
        .await
        .map_err(files::io_failure)?;
    crate::store::protected_read::check_directory(&before, operator)?;
    let read = read_protected(held.fs(), control, &pointer.key, operator).await?;
    let after = held
        .fs()
        .symlink_metadata(control)
        .await
        .map_err(files::io_failure)?;
    crate::store::protected_read::check_directory(&after, operator)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(super::publication::corrupt());
        }
    }
    observed.revalidate().await?;
    Ok(read)
}

async fn read_protected<F: LocalFs + BucketBinding>(
    fs: &F,
    control: &Path,
    key: &str,
    owner: u32,
) -> Result<RecordRead, StoreFailure> {
    let path = control.join(key);
    let recipe = NativeProtectedRead::for_record(control, key, owner);
    if let Some(record) = fs.read_protected_record(recipe).await? {
        let (bytes, metadata) = record.into_parts();
        return Ok(RecordRead::observed(path, bytes, metadata));
    }

    let mut parent = control.to_owned();
    let mut parents = Vec::new();
    for part in Path::new(key)
        .parent()
        .ok_or_else(super::publication::corrupt)?
        .components()
    {
        parent.push(part);
        parents.push(parent.clone());
        parents.push(parent.clone());
    }
    let observations = fs
        .symlink_metadata_batch(&parents)
        .await
        .map_err(files::io_failure)?;
    if observations.len() != parents.len() {
        return Err(super::publication::corrupt());
    }
    let mut observations = observations.into_iter();
    while let Some(existence) = observations.next() {
        match existence {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RecordRead::observed(path, None, None));
            }
            Err(error) => return Err(files::io_failure(error)),
            Ok(_) => {
                let metadata = observations
                    .next()
                    .ok_or_else(super::publication::corrupt)?
                    .map_err(files::io_failure)?;
                crate::store::protected_read::check_directory(&metadata, owner)?;
            }
        }
    }
    let before = match fs.symlink_metadata(&path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RecordRead::observed(path, None, None));
        }
        Err(error) => return Err(files::io_failure(error)),
        Ok(metadata) => metadata,
    };
    crate::store::protected_read::check_record(&before, owner)?;
    let bytes = fs.read_nofollow(&path).await.map_err(files::io_failure)?;
    let after = fs
        .symlink_metadata(&path)
        .await
        .map_err(files::io_failure)?;
    crate::store::protected_read::check_record(&after, owner)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(super::publication::corrupt());
        }
    }
    Ok(RecordRead::observed(path, Some(bytes), Some(after)))
}
