//! Reads immutable registered profile input without activating or repairing storage.
//!
//! The protected genesis supplies profile data under existing namespace exclusion.
//! A subsequent normal open independently verifies the complete selected chain;
//! this read neither grants freshness nor constructs publication authority.

use super::control::Control;
use super::{corrupt, digest, unsupported};
use crate::bucket::{BucketBinding, FileBucketPublicationConfig, files};
use crate::store::{LocalFs, StoreFailure};
use std::path::Path;
use terrane_core::bucket::{BucketCapabilities, BucketKey, StoreProfile};
use terrane_core::gc::publication::{
    Activation, BackendRegistration, PortableCurrent, PortableSnapshot, PublicationCommit,
    PublicationProof, PublicationTransaction,
};

/// Returns the immutable profile of an actually registered existing namespace.
///
/// Mutable capability caches and portable pointers supply no bootstrap input.
/// The returned format data grants no writable or fresh-destination authority.
/// Pending registration requires an existing exact genesis and remains Pending.
///
/// # Errors
/// Refuses unsafe configured ownership or physical binding, unavailable
/// existing-only exclusion, missing or inconsistent registration/genesis,
/// malformed snapshot evidence and unsupported profiles. Performs no repairs.
pub(crate) async fn registered_profile<F: LocalFs + BucketBinding>(
    fs: &F,
    root: &Path,
    config: &FileBucketPublicationConfig,
) -> Result<StoreProfile, StoreFailure> {
    let control = Control::open_existing_config(fs, root, config).await?;
    let _held = control.lock_existing(fs).await?;
    let registration_bytes = control
        .read(fs, "backend-registration.cbor")
        .await?
        .ok_or_else(corrupt)?;
    let registration = BackendRegistration::decode(&registration_bytes).map_err(|_| corrupt())?;
    if registration.binding != control.binding {
        return Err(corrupt());
    }

    let slot = control
        .read(fs, "publication/commits/0")
        .await?
        .ok_or_else(corrupt)?;
    if registration
        .genesis
        .is_some_and(|expected| expected != digest(&slot))
        || registration.activation == Activation::Active && registration.genesis.is_none()
    {
        return Err(corrupt());
    }
    let commit = PublicationCommit::decode(&slot).map_err(|_| corrupt())?;
    let transaction_bytes = control
        .read(fs, &commit.transaction_key)
        .await?
        .ok_or_else(corrupt)?;
    commit
        .check_transaction("publication/commits/0", &transaction_bytes)
        .map_err(|_| corrupt())?;
    let transaction = PublicationTransaction::decode(&transaction_bytes).map_err(|_| corrupt())?;
    if transaction.old.is_some()
        || transaction.predecessor.is_some()
        || transaction.new.binding != control.binding
        || transaction.new.guard.is_some()
        || !transaction.new.sources.is_empty()
        || transaction.proof != PublicationProof::Raw
    {
        return Err(corrupt());
    }
    let capabilities = transaction
        .changes
        .iter()
        .find(|row| row.key == "CAPABILITIES")
        .and_then(|row| row.new.as_deref())
        .ok_or_else(corrupt)?;
    let capabilities = BucketCapabilities::decode(capabilities).map_err(|_| corrupt())?;
    if capabilities.layout_version != 2
        || capabilities.publication_protocol != Some(1)
        || capabilities.ref_names.is_none()
        || !capabilities.create_if_absent
        || !capabilities.compare_and_swap
        || !capabilities.ranges
    {
        return Err(corrupt());
    }
    if capabilities.profile.identity != "terrane-v1"
        || capabilities.profile.algorithm != "blake3"
        || capabilities.profile.chunk != "cdc-1m"
    {
        return Err(unsupported());
    }

    let snapshot_bytes = read_snapshot(fs, root, &transaction.snapshot).await?;
    transaction
        .check_snapshot(&snapshot_bytes)
        .map_err(|_| corrupt())?;
    let snapshot = PortableSnapshot::decode(&snapshot_bytes).map_err(|_| corrupt())?;
    if snapshot.predecessor.is_some() {
        return Err(corrupt());
    }
    control.recheck(fs).await?;
    Ok(capabilities.profile)
}

async fn read_snapshot<F: LocalFs + BucketBinding>(
    fs: &F,
    root: &Path,
    pointer: &PortableCurrent,
) -> Result<Vec<u8>, StoreFailure> {
    let key = BucketKey::parse(&pointer.key).map_err(|_| corrupt())?;
    let mut parent = root.to_owned();
    for component in Path::new(key.as_str())
        .parent()
        .ok_or_else(corrupt)?
        .components()
    {
        parent.push(component);
        let metadata = fs
            .symlink_metadata(&parent)
            .await
            .map_err(files::io_failure)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(corrupt());
        }
    }
    let path = root.join(key.as_str());
    let before = fs
        .symlink_metadata(&path)
        .await
        .map_err(files::io_failure)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(corrupt());
    }
    let bytes = fs.read_nofollow(&path).await.map_err(files::io_failure)?;
    let after = fs
        .symlink_metadata(&path)
        .await
        .map_err(files::io_failure)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !after.is_file()
            || after.file_type().is_symlink()
            || (before.dev(), before.ino()) != (after.dev(), after.ino())
        {
            return Err(corrupt());
        }
    }
    #[cfg(not(unix))]
    return Err(unsupported());
    pointer.check_snapshot(&bytes).map_err(|_| corrupt())?;
    Ok(bytes)
}
