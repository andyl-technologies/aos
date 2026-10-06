//! Checks fixed genesis staging and finishes activation under actual receipts.
//!
//! The program admits only the complete canonical empty genesis produced by the
//! native creator. Existing Pending recovery consumes recorded staging; it
//! neither creates another registration nor regenerates its operation nonce.

use super::super::super::super::{
    ExactRead, FencePolicy, MetadataStamp, NamedFence, NativeExclusion, NativeOpenedDirectory,
    ParentFence, Plan, open_native, parent_paths,
};
use super::super::super::{Frame, io_failure, unsupported};
use super::super::{NativeGenesisStage, NativePublicationInitialization, corrupt, digest};
use super::genesis;
use super::io::{Directories, RetainedFs};
use crate::bucket::BucketBinding;
use crate::store::{ByteRange, LocalFs, NativeEffectFailure, StoreFailure};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use terrane_core::bucket::{BucketCapabilities, BucketKey, Mutability};
use terrane_core::gc::publication::{
    Activation, BackendBinding, BackendRegistration, LogicalChange, PublicationCommit,
};

/// Copies every ordered ancestor observation without rebinding its incarnation.
pub(super) fn copy_parents(parents: &[ParentFence]) -> Vec<ParentFence> {
    parents
        .iter()
        .map(|row| ParentFence {
            path: row.path.clone(),
            stamp: row.stamp,
        })
        .collect()
}

/// Captures a nofollow directory and every actual configured ancestor.
///
/// # Errors
/// Rejects unsafe or replaced directories, changed ancestors and unavailable reads.
pub(in super::super) fn directory(
    path: &Path,
    policy: FencePolicy,
) -> Result<NativeOpenedDirectory, StoreFailure> {
    let paths = if path == Path::new("/") {
        Vec::new()
    } else {
        parent_paths(path).map_err(io_failure)?
    };
    let mut parents = Vec::new();
    for path in paths {
        let stamp = MetadataStamp::checked(&std::fs::symlink_metadata(&path).map_err(io_failure)?)
            .map_err(io_failure)?;
        FencePolicy::ProtectedAncestor {
            owner: policy.configured_owner(),
        }
        .validate(stamp)
        .map_err(io_failure)?;
        parents.push(ParentFence { path, stamp });
    }
    let file = open_native(path, true).map_err(io_failure)?;
    let stamp =
        MetadataStamp::checked(&file.metadata().map_err(io_failure)?).map_err(io_failure)?;
    policy.validate(stamp).map_err(io_failure)?;
    let receipt = NativeOpenedDirectory {
        file,
        path: path.to_owned(),
        stamp,
        policy,
        parents,
    };
    receipt.check().map_err(io_failure)?;
    Ok(receipt)
}

/// Extends retained opened-directory ownership without rebinding older receipts.
///
/// # Errors
/// Rejects changed original receipts, poisoned storage and descriptor duplication failures.
pub(super) fn retain_directory(
    directories: &Directories,
    receipt: NativeOpenedDirectory,
) -> Result<(), StoreFailure> {
    let mut current = directories.lock().map_err(|_| corrupt())?;
    let mut next = Vec::new();
    for old in current.iter() {
        old.check().map_err(io_failure)?;
        next.push(NativeOpenedDirectory {
            file: old.file.try_clone().map_err(io_failure)?,
            path: old.path.clone(),
            stamp: old.stamp,
            policy: old.policy,
            parents: copy_parents(&old.parents),
        });
    }
    next.push(receipt);
    *current = next.into();
    Ok(())
}

/// Starts a private physical transcript with the actual retained exclusions.
pub(in super::super) fn frame(owner: u32, exclusions: Arc<[NativeExclusion]>) -> Frame {
    Frame {
        exclusions,
        names: Vec::new(),
        reads: Vec::new(),
        parents: BTreeMap::new(),
        writes: None,
        final_check: None,
        owner,
    }
}

/// Derives the local binding from original opened root and coordination descriptors.
///
/// # Errors
/// Rejects unsafe, replaced or mismatched original descriptors and names.
pub(in super::super) fn binding(
    request: &NativePublicationInitialization,
    directories: &[NativeOpenedDirectory],
    exclusions: &[NativeExclusion],
) -> Result<BackendBinding, StoreFailure> {
    use std::os::unix::ffi::OsStrExt;
    let root = directories
        .iter()
        .find(|row| row.path == request.root)
        .ok_or_else(corrupt)?;
    root.check().map_err(io_failure)?;
    let held = exclusions.first().ok_or_else(unsupported)?;
    let coordination =
        MetadataStamp::checked(&held.file.metadata().map_err(io_failure)?).map_err(io_failure)?;
    FencePolicy::NamespaceCoordination {
        owner: request.operator_uid,
    }
    .validate(coordination)
    .map_err(io_failure)?;
    let path = request.root.join(
        BucketKey::parse("CAPABILITIES")
            .map_err(|_| corrupt())?
            .lock_name(),
    );
    let named = MetadataStamp::checked(&std::fs::symlink_metadata(path).map_err(io_failure)?)
        .map_err(io_failure)?;
    if !named.same_incarnation(coordination) {
        return Err(corrupt());
    }
    Ok(BackendBinding::Local {
        root: request.root.as_os_str().as_bytes().to_vec(),
        root_device: root.stamp.identity.0,
        root_inode: root.stamp.identity.1,
        coordination_device: coordination.identity.0,
        coordination_inode: coordination.identity.1,
    })
}

/// Restores the creator's exact original physical transcript without rerebinding.
///
/// # Errors
/// Rejects contradictory ancestor observations in the original retained transcript.
pub(super) fn restore_frame(
    owner: u32,
    exclusions: Arc<[NativeExclusion]>,
    names: Vec<NamedFence>,
    reads: Vec<ExactRead>,
) -> Result<Frame, StoreFailure> {
    let mut result = frame(owner, exclusions);
    for (path, stamp) in names
        .iter()
        .flat_map(|name| &name.parents)
        .chain(reads.iter().flat_map(|read| &read.parents))
        .map(|row| (&row.path, row.stamp))
    {
        if result
            .parents
            .get(path)
            .is_some_and(|(old, _)| !stamp.same_incarnation(*old))
        {
            return Err(corrupt());
        }
        result.parents.insert(path.clone(), (stamp, owner));
    }
    result.names = names;
    result.reads = reads;
    Ok(result)
}

/// Requires the exact canonical empty proposal, without interpreting it as freshness.
///
/// # Errors
/// Rejects partial catalogs, other proof classes, imported ownership or changed staging.
pub(in super::super) fn validate_stage(
    request: &NativePublicationInitialization,
    binding: &BackendBinding,
    stage: &NativeGenesisStage,
) -> Result<(), StoreFailure> {
    let cap = stage
        .transaction
        .changes
        .iter()
        .find(|row| row.key == "CAPABILITIES")
        .and_then(|row| row.new.as_deref())
        .ok_or_else(corrupt)?;
    let cap = BucketCapabilities::decode(cap).map_err(|_| corrupt())?;
    let expected = genesis::stage(
        genesis::catalog(request.profile.clone(), binding.clone(), cap.probed_at)?,
        stage.transaction.nonce,
    )?;
    if expected.transaction != stage.transaction || expected.snapshot_bytes != stage.snapshot_bytes
    {
        return Err(corrupt());
    }
    stage
        .transaction
        .check_snapshot(&stage.snapshot_bytes)
        .map_err(|_| corrupt())
}

/// Formats the recorded operation nonce without allocating a new operation.
pub(in super::super) fn operation(stage: &NativeGenesisStage) -> String {
    stage
        .transaction
        .nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Finishes one exact recorded genesis while preserving all physical receipts.
///
/// # Errors
/// Refuses changed Pending or staging, slot conflicts, incomplete selected state,
/// unsafe paths and uncertain durability. It never infers a new creator event.
pub(in super::super) async fn finish<F: LocalFs + BucketBinding>(
    fs: &F,
    request: &NativePublicationInitialization,
    binding: &BackendBinding,
    pending: &[u8],
    stage: &NativeGenesisStage,
    frame: &mut Frame,
    directories: &Directories,
) -> Result<(), StoreFailure> {
    validate_stage(request, binding, stage)?;
    let retained = RetainedFs {
        inner: fs,
        directories: Arc::clone(directories),
    };
    let owner = request.operator_uid;
    let protected = FencePolicy::ProtectedRecord { owner };
    frame
        .execute(
            &retained,
            Plan::SyncDirectory {
                path: request.control.clone(),
            },
        )
        .await?;
    let registration_path = request.control.join("backend-registration.cbor");
    if frame
        .actual_read(&retained, &registration_path, protected)
        .await?
        .as_deref()
        != Some(pending)
    {
        return Err(corrupt());
    }
    let before = BackendRegistration::decode(pending).map_err(|_| corrupt())?;
    if before.binding != *binding || before.activation != Activation::Pending {
        return Err(corrupt());
    }
    let transaction_key = format!("publication/transactions/{}", operation(stage));
    let transaction_bytes = stage.transaction.encode().map_err(|_| corrupt())?;
    if frame
        .actual_read(
            &retained,
            &request.control.join(&transaction_key),
            protected,
        )
        .await?
        .as_deref()
        != Some(transaction_bytes.as_slice())
    {
        return Err(corrupt());
    }
    let payload = FencePolicy::Payload { owner };
    let pointer = stage.transaction.snapshot.encode().map_err(|_| corrupt())?;
    if frame
        .actual_read(
            &retained,
            &request.root.join("publication/PORTABLE"),
            payload,
        )
        .await?
        .as_deref()
        != Some(pointer.as_slice())
        || frame
            .actual_read(
                &retained,
                &request.root.join(&stage.transaction.snapshot.key),
                payload,
            )
            .await?
            .as_deref()
            != Some(stage.snapshot_bytes.as_slice())
    {
        return Err(corrupt());
    }
    let commit = PublicationCommit {
        revision: 0,
        predecessor: None,
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    };
    let slot_bytes = commit.encode().map_err(|_| corrupt())?;
    let slot = request.control.join("publication/commits/0");
    match frame.actual_read(&retained, &slot, protected).await? {
        None => {
            frame
                .install(
                    &retained,
                    &request.control,
                    "publication/commits/0",
                    &slot_bytes,
                    protected,
                    Mutability::CreateOnce,
                )
                .await?
        }
        Some(bytes) if bytes == slot_bytes => {}
        Some(_) => return Err(corrupt()),
    }
    commit
        .check_transaction("publication/commits/0", &transaction_bytes)
        .map_err(|_| corrupt())?;
    if frame
        .actual_read(
            &retained,
            &request.control.join("publication/commits/1"),
            protected,
        )
        .await?
        .is_some()
    {
        return Err(corrupt());
    }
    if before
        .genesis
        .is_some_and(|digest| digest != super::super::digest(&slot_bytes))
    {
        return Err(corrupt());
    }
    let logical = stage
        .transaction
        .changes
        .iter()
        .map(|row| (row.key.clone(), row.new.clone()))
        .collect();
    frame
        .project(
            &retained,
            &request.root,
            &stage.transaction.snapshot,
            &logical,
        )
        .await?;
    let active = BackendRegistration {
        binding: binding.clone(),
        activation: Activation::Active,
        genesis: Some(digest(&slot_bytes)),
    };
    before.check_successor(&active).map_err(|_| corrupt())?;
    frame
        .install(
            &retained,
            &request.control,
            "backend-registration.cbor",
            &active.encode().map_err(|_| corrupt())?,
            protected,
            Mutability::CompareAndSwap,
        )
        .await?;
    frame
        .execute(
            &retained,
            Plan::SyncDirectory {
                path: request.control.clone(),
            },
        )
        .await?;
    Ok(())
}

/// Verifies actual present-target create-new, range and stale whole-CAP refusal.
///
/// # Errors
/// Rejects fabricated create-new success, overwritten bytes, wrong ranges or any
/// change to the complete selected genesis transcript during the probes.
pub(super) async fn probe<F: LocalFs + BucketBinding>(
    fs: &F,
    request: &NativePublicationInitialization,
    stage: &NativeGenesisStage,
    frame: &mut Frame,
    directories: &Directories,
) -> Result<(), StoreFailure> {
    let retained = RetainedFs {
        inner: fs,
        directories: Arc::clone(directories),
    };
    for (path, policy) in [
        (
            request.root.join("CAPABILITIES"),
            FencePolicy::Payload { owner: frame.owner },
        ),
        (
            request.control.join("backend-registration.cbor"),
            FencePolicy::ProtectedRecord { owner: frame.owner },
        ),
    ] {
        let bytes = frame
            .actual_read(&retained, &path, policy)
            .await?
            .ok_or_else(corrupt)?;
        match retained
            .execute_retained_effect(frame.effect(Plan::WriteNew {
                path: path.clone(),
                bytes: bytes.clone(),
            })?)
            .await
        {
            Err(NativeEffectFailure::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(NativeEffectFailure::Rejected(error)) => return Err(error),
            Err(NativeEffectFailure::Io(error)) => return Err(io_failure(error)),
            Ok(()) => return Err(unsupported()),
        }
        if frame
            .actual_read(&retained, &path, policy)
            .await?
            .as_deref()
            != Some(bytes.as_slice())
        {
            return Err(corrupt());
        }
    }
    let cap = stage
        .transaction
        .changes
        .iter()
        .find(|row| row.key == "CAPABILITIES")
        .and_then(|row| row.new.as_deref())
        .ok_or_else(corrupt)?;
    let first = cap.get(..1).ok_or_else(corrupt)?;
    let path = request.root.join("CAPABILITIES");
    frame
        .execute(
            &retained,
            Plan::ProbeRange {
                path: path.clone(),
                start: 0,
                expected: first.to_vec(),
            },
        )
        .await?;
    if retained
        .read_range(
            &path,
            ByteRange {
                start: 0,
                length: 1,
            },
        )
        .await
        .map_err(io_failure)?
        .as_slice()
        != first
    {
        return Err(unsupported());
    }
    let mut replacement = BucketCapabilities::decode(cap).map_err(|_| corrupt())?;
    replacement.probed_at = replacement.probed_at.checked_add(1).ok_or_else(corrupt)?;
    let replacement = replacement.encode().map_err(|_| corrupt())?;
    let mut stale = cap.to_vec();
    stale.push(0);
    match prepare_capability_change(fs, request, stage, frame, directories, &stale, &replacement)
        .await
    {
        Err(error)
            if matches!(
                error.kind(),
                crate::store::StoreErrorKind::Unavailable { .. }
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(_) => Err(unsupported()),
    }
}

/// Prepares only CAP proposal data from the actual retained selected genesis.
///
/// # Errors
/// Rejects an ineligible successor or changed complete selected projection;
/// a stale whole expected CAP returns `Unavailable` before staging any data.
pub(super) async fn prepare_capability_change<F: LocalFs + BucketBinding>(
    fs: &F,
    request: &NativePublicationInitialization,
    stage: &NativeGenesisStage,
    frame: &mut Frame,
    directories: &Directories,
    expected: &[u8],
    replacement: &[u8],
) -> Result<LogicalChange, StoreFailure> {
    let logical = stage
        .transaction
        .changes
        .iter()
        .map(|row| (row.key.clone(), row.new.clone()))
        .collect::<BTreeMap<_, _>>();
    let original = logical
        .get("CAPABILITIES")
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)?;
    let mut eligible = BucketCapabilities::decode(original).map_err(|_| corrupt())?;
    let after = BucketCapabilities::decode(replacement).map_err(|_| corrupt())?;
    eligible.probed_at = after.probed_at;
    if eligible != after || after.encode().map_err(|_| corrupt())? != replacement {
        return Err(corrupt());
    }

    let retained = RetainedFs {
        inner: fs,
        directories: Arc::clone(directories),
    };
    let protected = FencePolicy::ProtectedRecord { owner: frame.owner };
    let payload = FencePolicy::Payload { owner: frame.owner };
    let transaction_key = format!("publication/transactions/{}", operation(stage));
    let bytes = frame
        .actual_read(
            &retained,
            &request.control.join(&transaction_key),
            protected,
        )
        .await?
        .ok_or_else(corrupt)?;
    if bytes != stage.transaction.encode().map_err(|_| corrupt())? {
        return Err(corrupt());
    }
    let slot_bytes = frame
        .actual_read(
            &retained,
            &request.control.join("publication/commits/0"),
            protected,
        )
        .await?
        .ok_or_else(corrupt)?;
    let slot = PublicationCommit::decode(&slot_bytes).map_err(|_| corrupt())?;
    slot.check_transaction("publication/commits/0", &bytes)
        .map_err(|_| corrupt())?;
    if slot.transaction_key != transaction_key
        || frame
            .actual_read(
                &retained,
                &request.control.join("publication/commits/1"),
                protected,
            )
            .await?
            .is_some()
    {
        return Err(corrupt());
    }
    if frame
        .actual_read(
            &retained,
            &request.root.join(&stage.transaction.snapshot.key),
            payload,
        )
        .await?
        .as_deref()
        != Some(stage.snapshot_bytes.as_slice())
        || frame
            .actual_read(
                &retained,
                &request.root.join("publication/PORTABLE"),
                payload,
            )
            .await?
            .as_deref()
            != Some(
                stage
                    .transaction
                    .snapshot
                    .encode()
                    .map_err(|_| corrupt())?
                    .as_slice(),
            )
    {
        return Err(corrupt());
    }
    for (key, value) in &logical {
        if frame
            .actual_read(&retained, &request.root.join(key), payload)
            .await?
            != *value
        {
            return Err(corrupt());
        }
    }
    frame
        .execute(
            &retained,
            Plan::SyncDirectory {
                path: request.control.clone(),
            },
        )
        .await?;
    if expected != original {
        return Err(StoreFailure::new(
            crate::store::StoreErrorKind::Unavailable { retry_after: None },
        ));
    }
    Ok(LogicalChange {
        key: "CAPABILITIES".into(),
        expected: Some(original.to_vec()),
        new: Some(replacement.to_vec()),
    })
}
