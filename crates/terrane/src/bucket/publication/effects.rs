//! Derives fixed physical publication effects from genuine retained inputs.
//!
//! This module is a logical descendant of the private native executor. Public
//! record bytes alone do not provide authority to construct a submitted effect.

/// Owns opaque creator receipts beneath the private retained publication frame.
#[path = "../../store/native_effect/initialization.rs"]
pub(crate) mod initialization_inputs;

pub(crate) use initialization_inputs::{
    fresh as initialization, pending as pending_initialization,
};

// The collector descendant consumes only its separately checked lease carrier;
// it reuses the retained executor without granting arbitrary effect construction.
/// Executes fixed collector lease publication under genuinely retained inputs.
#[path = "../../gc/effects.rs"]
pub(crate) mod collection;

/// Publishes fixed mark checkpoints under genuine lease and control receipts.
#[path = "../../gc/checkpoint_effects.rs"]
pub(crate) mod collection_checkpoints;

#[path = "effects/capture.rs"]
mod capture;
#[path = "effects/commands.rs"]
mod commands;
#[path = "effects/raw.rs"]
mod raw;

#[cfg(all(test, feature = "tokio", unix))]
pub(crate) use raw::{backend_sync_for_test, gate_active_cap_probe_for_test};
pub(crate) use raw::{
    probe_active, publish as publish_raw, repair, stage_container, stage_ref_log,
};

use super::{
    ExactRead, FencePolicy, MetadataStamp, NamedFence, NativeEffectFailure, NativeExclusion,
    NativeFsEffect, ParentFence, Plan,
};
use crate::bucket::BucketBinding;
use crate::bucket::publication::SelectedObservation;
use crate::selected_bridge::{CheckedMutation, OwnedFinalCheck};
use crate::store::{LocalFs, StoreErrorKind, StoreFailure};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use terrane_core::bucket::{BucketKey, Mutability};
use terrane_core::gc::publication::{
    PortableCurrent, PortableSnapshot, PredecessorSlot, ProjectionEntry, PublicationCommit,
    PublicationTransaction, RawDigest,
};

/// Reports fixed selected bytes after the actual retained lane acknowledges them.
pub(crate) struct CheckedPublication {
    /// The revision installed in the protected consecutive create-once slot.
    pub(crate) revision: u64,
    /// The raw digest of that exact canonical commit record.
    pub(crate) digest: RawDigest,
}

/// Owns the complete physical refresh data for one sealed held operation.
///
/// Every command duplicates this projection into its submitted worker. The
/// asynchronous owner can disappear without releasing that worker's exclusions.
struct Frame {
    exclusions: Arc<[NativeExclusion]>,
    names: Vec<NamedFence>,
    reads: Vec<ExactRead>,
    parents: BTreeMap<PathBuf, (MetadataStamp, u32)>,
    final_check: Option<OwnedFinalCheck>,
    owner: u32,
}

fn corrupt() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(
        crate::store::CorruptSubject::RefName("publication".into()),
    ))
}

fn unsupported() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unsupported)
}

fn io_failure(error: std::io::Error) -> StoreFailure {
    if error.kind() == std::io::ErrorKind::Unsupported {
        unsupported()
    } else {
        StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
    }
}

fn digest(bytes: &[u8]) -> RawDigest {
    *blake3::hash(bytes).as_bytes()
}

fn duplicate(receipt: &NativeExclusion) -> Result<NativeExclusion, StoreFailure> {
    // This is the private descendant of the executor. Only a receipt already
    // captured from an actual acquired exclusion reaches this descriptor.
    Ok(NativeExclusion {
        file: receipt.file.try_clone().map_err(io_failure)?,
    })
}

fn copy_parents(parents: &[ParentFence]) -> Vec<ParentFence> {
    parents
        .iter()
        .map(|parent| ParentFence {
            path: parent.path.clone(),
            stamp: parent.stamp,
        })
        .collect()
}

/// Publishes only fixed data carried by the genuine checked producer.
///
/// # Errors
/// Rejects absent native retention, changed physical/control preimages, expired
/// authority and failed durable effects. An error after slot dispatch can mean
/// that selection succeeded and its portable acknowledgment remains incomplete.
pub(crate) async fn publish_checked<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedMutation<'_, '_>,
) -> Result<CheckedPublication, StoreFailure> {
    let context = checked.effect_context().ok_or_else(unsupported)?;
    let observed = checked.observed();
    if !observed.identity().writable() {
        return Err(unsupported());
    }
    let controls = context.controls();
    let owner = observed.configured_operator_uid();
    if controls.owner() != owner {
        return Err(corrupt());
    }
    let mut exclusions = vec![duplicate(observed.identity().retained_namespace()?)?];
    for source in checked.sources() {
        exclusions.push(duplicate(source.identity().retained_namespace()?)?);
    }
    let control_start = exclusions.len();
    for exclusion in controls.exclusions().iter() {
        exclusions.push(duplicate(exclusion)?);
    }
    if exclusions.len() == control_start {
        return Err(unsupported());
    }
    let mut frame = Frame {
        exclusions: exclusions.into(),
        names: Vec::new(),
        reads: Vec::new(),
        parents: BTreeMap::new(),
        final_check: Some(context.final_check()),
        owner,
    };

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
    let control = frame.observation(fs, observed, 0).await?;
    for (index, source) in checked.sources().iter().enumerate() {
        frame.observation(fs, source, index + 1).await?;
    }
    let (directory_identity, lock_identity) = controls.identities();
    frame
        .name(
            fs,
            controls.directory().to_owned(),
            directory_identity,
            FencePolicy::PrivateControlDirectory { owner },
            None,
        )
        .await?;
    for descriptor in control_start..frame.exclusions.len() {
        frame
            .name(
                fs,
                controls.directory().join("retention.lock"),
                lock_identity,
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

    if let Some(bytes) = checked.lineage() {
        use terrane_core::gc::publication::{CommittedSelection, evidence::CheckedLineage};
        use terrane_core::refs::RefLogRecord;

        let lineage = CheckedLineage::decode(bytes).map_err(|_| corrupt())?;
        let candidate = lineage.source.candidate_id.ok_or_else(corrupt)?;
        let key = BucketKey::reflog_candidate(&lineage.source_name, lineage.source.seq, &candidate)
            .map_err(|_| corrupt())?;
        let bytes = frame
            .actual_read(
                fs,
                &observed.identity().root().join(key.as_str()),
                FencePolicy::Payload { owner },
            )
            .await?
            .ok_or_else(corrupt)?;
        let log = RefLogRecord::decode(&bytes).map_err(|_| corrupt())?;
        let change = checked
            .changes()
            .iter()
            .find(|row| row.key == format!("{}:record", lineage.source_name))
            .ok_or_else(corrupt)?;
        let previous = change
            .expected
            .as_deref()
            .map(terrane_core::refs::RefRecord::decode)
            .transpose()
            .map_err(|_| corrupt())?;
        log.validate_candidate(previous.as_ref(), &lineage.source)
            .map_err(|_| corrupt())?;
        let retained = observed
            .state()
            .branches
            .iter()
            .find(|row| row.name == lineage.source_name)
            .map(|row| &row.selection);
        let retained = match retained {
            Some(CommittedSelection::Selected(record)) => Some(record.as_ref()),
            Some(CommittedSelection::Unknown) => return Err(corrupt()),
            _ => None,
        };
        if log.selected_previous().map_err(|_| corrupt())? != retained {
            return Err(corrupt());
        }
    }

    // This check uses each actual borrowed backend before the first effect.
    // Submitted workers independently repeat the fixed full physical data.
    observed.revalidate().await?;
    for source in checked.sources() {
        source.revalidate().await?;
    }
    checked.recheck_before_slot()?;
    let root = observed.identity().root();
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;

    let guard = digest(checked.guard_snapshot());
    frame
        .install(
            fs,
            &control,
            &format!("publication/guards/{}", hex(&guard)),
            checked.guard_snapshot(),
            FencePolicy::ProtectedRecord { owner },
            Mutability::Immutable,
        )
        .await?;
    if let Some(lineage) = checked.lineage() {
        frame
            .install(
                fs,
                &control,
                &format!("publication/lineage/{}", hex(&digest(lineage))),
                lineage,
                FencePolicy::ProtectedRecord { owner },
                Mutability::Immutable,
            )
            .await?;
    }
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
        projection: checked
            .changes()
            .iter()
            .filter(|row| projectable(&row.key))
            .map(|row| ProjectionEntry {
                key: row.key.clone(),
                value: if row.key == "gc/lease" {
                    None
                } else {
                    row.new.clone()
                },
            })
            .collect(),
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
        changes: checked.changes().to_vec(),
        proof: checked.proof(),
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
    for change in checked.changes() {
        logical.insert(change.key.clone(), change.new.clone());
    }
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn projectable(key: &str) -> bool {
    matches!(
        key,
        "CAPABILITIES" | "publication/SELECTED-HISTORY" | "gc/lease"
    ) || key.starts_with("refs/")
        || key.starts_with("objects/index/")
}
