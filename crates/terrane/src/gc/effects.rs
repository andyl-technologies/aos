//! Executes only a genuine checked singleton lease transition.
//!
//! This private descendant reuses the sealed retained executor. It validates the
//! closed lease key and exact selected successor before staging any bytes; every
//! command retains actual namespace and consumed control descriptors through its
//! final preimage/clock checks, syscall, and directory synchronization.

use super::{
    BTreeMap, BucketBinding, CheckedPublication, FencePolicy, Frame, LocalFs, MetadataStamp,
    Mutability, Plan, PortableCurrent, PortableSnapshot, PredecessorSlot, ProjectionEntry,
    PublicationCommit, PublicationTransaction, StoreFailure, corrupt, digest, duplicate, hex,
    io_failure, unsupported,
};
use crate::selected_bridge::CheckedGcLease;
use terrane_core::gc::GcLease;
use terrane_core::gc::publication::PublicationProof;

/// Publishes the fixed lease and its exact consecutive selected revision.
///
/// # Errors
/// Rejects changed lease/state/preimages, missing genuine retained controls,
/// unsafe metadata, failed final clock checks, or unavailable durable native effects.
/// Failure after slot submission can leave a selected lease awaiting recovery.
pub(crate) async fn publish_checked<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedGcLease<'_, '_>,
) -> Result<CheckedPublication, StoreFailure> {
    validate(checked)?;
    let observed = checked.observed();
    let context = checked.effect_context();
    let owner = observed.configured_operator_uid();
    if !observed.identity().writable() || context.controls().is_empty() {
        return Err(unsupported());
    }
    let mut exclusions = vec![duplicate(observed.identity().retained_namespace()?)?];
    let mut control_ranges = Vec::new();
    for controls in context.controls() {
        if controls.owner() != owner || controls.records().is_empty() {
            return Err(corrupt());
        }
        let start = exclusions.len();
        let retained = controls.exclusions();
        for receipt in retained.iter() {
            exclusions.push(duplicate(receipt)?);
        }
        if exclusions.len() == start {
            return Err(unsupported());
        }
        control_ranges.push(start..exclusions.len());
    }
    let mut frame = Frame {
        exclusions: exclusions.into(),
        names: Vec::new(),
        reads: Vec::new(),
        parents: BTreeMap::new(),
        final_check: Some(context.final_check()),
        owner,
    };
    for controls in context.controls() {
        for ancestor in controls.ancestors() {
            let metadata = fs
                .symlink_metadata(ancestor.path())
                .await
                .map_err(io_failure)?;
            let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
            FencePolicy::ProtectedAncestor { owner }
                .validate(stamp)
                .map_err(io_failure)?;
            if stamp.identity != ancestor.identity()
                || (stamp.owner, stamp.mode & 0o7777) != ancestor.protection()
            {
                return Err(corrupt());
            }
            frame
                .parents
                .insert(ancestor.path().to_owned(), (stamp, owner));
        }
    }
    let control = frame.observation(fs, observed, 0).await?;
    for (controls, descriptors) in context.controls().iter().zip(control_ranges) {
        let (directory, lock) = controls.identities();
        frame
            .name(
                fs,
                controls.directory().to_owned(),
                directory,
                FencePolicy::PrivateControlDirectory { owner },
                None,
            )
            .await?;
        for descriptor in descriptors {
            frame
                .name(
                    fs,
                    controls.directory().join("retention.lock"),
                    lock,
                    FencePolicy::ProtectedRecord { owner },
                    Some(descriptor),
                )
                .await?;
        }
        for record in controls.records() {
            let metadata = fs
                .symlink_metadata(record.path())
                .await
                .map_err(io_failure)?;
            if MetadataStamp::checked(&metadata)
                .map_err(io_failure)?
                .identity
                != record.identity()
            {
                return Err(corrupt());
            }
            frame
                .observed_read(
                    fs,
                    record.path(),
                    Some(record.bytes()),
                    Some(&metadata),
                    FencePolicy::ProtectedRecord { owner },
                )
                .await?;
        }
    }
    observed.revalidate().await?;
    checked.recheck_before_slot()?;
    let root = observed.identity().root();
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;

    let nonce: [u8; 32] = fs
        .random_bytes(32)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| unsupported())?;
    let operation = hex(&nonce);
    let snapshot = PortableSnapshot {
        revision: checked.next().revision,
        origin: checked.next().binding.clone(),
        projection: vec![ProjectionEntry {
            key: "gc/lease".into(),
            value: None,
        }],
        predecessor: Some(observed.snapshot().clone()),
    };
    let snapshot_bytes = snapshot.encode().map_err(|_| corrupt())?;
    let pointer = PortableCurrent {
        key: format!(
            "publication/snapshots/{}:{operation}",
            checked.next().revision
        ),
        digest: digest(&snapshot_bytes),
    };
    let transaction = PublicationTransaction {
        nonce,
        old: Some(observed.state().clone()),
        new: checked.next().clone(),
        changes: vec![checked.change().clone()],
        proof: PublicationProof::Raw,
        predecessor: Some(PredecessorSlot {
            revision: observed.stamp().0,
            digest: observed.stamp().1,
        }),
        snapshot: pointer.clone(),
    };
    transaction
        .check_snapshot(&snapshot_bytes)
        .map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            root,
            &pointer.key,
            &snapshot_bytes,
            FencePolicy::Payload { owner },
            Mutability::Immutable,
        )
        .await?;
    let transaction_key = format!("publication/transactions/{operation}");
    transaction
        .check_key(&transaction_key)
        .map_err(|_| corrupt())?;
    let transaction_bytes = transaction.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            &control,
            &transaction_key,
            &transaction_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::Immutable,
        )
        .await?;

    // The slot is the only selected-state linearization. Its native worker
    // repeats every consumed canonical control, selected exact read and actual
    // retained descriptor after staging and immediately before the syscall.
    let slot = PublicationCommit {
        revision: checked.next().revision,
        predecessor: Some(observed.stamp().1),
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    };
    let slot_bytes = slot.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            &control,
            &format!("publication/commits/{}", slot.revision),
            &slot_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::CreateOnce,
        )
        .await?;

    let mut logical = observed.logical().clone();
    logical.insert("gc/lease".into(), checked.change().new.clone());
    frame.project(fs, root, &pointer, &logical).await?;
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await?;
    Ok(CheckedPublication {
        revision: slot.revision,
        digest: digest(&slot_bytes),
    })
}

// Closed validation derives the complete expected state, preserving every
// binding, branch, Guard/source lineage, burn owner and loss generation.
fn validate(checked: &CheckedGcLease<'_, '_>) -> Result<(), StoreFailure> {
    let observed = checked.observed();
    let change = checked.change();
    if change.key != "gc/lease"
        || observed.logical().get("gc/lease") != Some(&change.expected)
        || observed.state().guard.is_none()
    {
        return Err(corrupt());
    }
    let mut expected = observed.state().clone();
    expected.revision = expected.revision.checked_add(1).ok_or_else(corrupt)?;
    if *checked.next() != expected {
        return Err(corrupt());
    }
    let next =
        GcLease::decode(change.new.as_deref().ok_or_else(corrupt)?).map_err(|_| corrupt())?;
    let previous = change
        .expected
        .as_deref()
        .map(GcLease::decode)
        .transpose()
        .map_err(|_| corrupt())?;
    let successor = match previous {
        None => next.epoch == 1,
        Some(old) => {
            (next.epoch == old.epoch && next.holder == old.holder && next.expiry > old.expiry)
                || (old.epoch.checked_add(1) == Some(next.epoch) && next.expiry > old.expiry)
        }
    };
    if !successor || next.expiry == 0 || next.epoch == 0 {
        return Err(corrupt());
    }
    checked.recheck_before_slot()
}

#[cfg(all(test, feature = "tokio", unix))]
#[path = "effects/test_fs.rs"]
/// Retains actual native test effects for runtime-specific qualification.
pub(crate) mod test_fs;

#[cfg(all(test, unix, not(feature = "tokio")))]
#[path = "effects/local_fs.rs"]
/// Retains actual native test effects for runtime-specific qualification.
pub(crate) mod test_fs;
