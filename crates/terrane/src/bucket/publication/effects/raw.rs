//! Derives backend-only raw repair and candidate-log effects from actual holds.
//!
//! These operations acquire no actor, branch-lineage or collector authority.
//! Their fixed effect projection independently retains actual registration,
//! selected preimages and namespace exclusion through syscall and durability.

use super::{
    BTreeMap, BucketBinding, FencePolicy, Frame, LocalFs, Mutability, PathBuf, Plan,
    PortableCurrent, PortableSnapshot, PredecessorSlot, ProjectionEntry, PublicationCommit,
    PublicationTransaction, SelectedObservation, StoreErrorKind, StoreFailure, corrupt, digest,
    duplicate, hex, projectable, unsupported,
};
use crate::bucket::publication::{ContainerArtifacts, RawMutation};
use crate::store::RefLogAppendOutcome;
use terrane_core::gc::publication::PublicationProof;

use terrane_core::bucket::BucketKey;
use terrane_core::refs::{RefLogRecord, RefName};

async fn backend<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
) -> Result<Frame, StoreFailure> {
    Ok(backend_with_control(fs, observed).await?.0)
}

async fn backend_with_control<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
) -> Result<(Frame, PathBuf), StoreFailure> {
    if !observed.identity().writable() {
        return Err(unsupported());
    }
    let receipt = duplicate(observed.identity().retained_namespace()?)?;
    let mut frame = Frame {
        exclusions: vec![receipt].into(),
        names: Vec::new(),
        reads: Vec::new(),
        parents: BTreeMap::new(),
        writes: None,
        final_check: None,
        owner: observed.configured_operator_uid(),
    };
    let control = frame.observation(fs, observed, 0).await?;
    observed.revalidate().await?;
    Ok((frame, control))
}

/// Probes fixed present CAP and registration primitives under actual retained state.
///
/// An actual create-new dispatch must report `AlreadyExists`; equal bytes alone
/// are insufficient. The private range plan binds its opened descriptor to the
/// captured CAP incarnation, while the binding range call independently verifies
/// the advertised I/O response. No selected state or lineage changes here.
///
/// # Errors
/// Rejects missing or changed present bytes, successful create-new probes, wrong
/// range responses, unavailable retention and failed complete physical/state
/// rechecks. Submitted workers retain exclusions until their syscalls complete.
pub(crate) async fn probe_active<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
) -> Result<(), StoreFailure> {
    let (mut frame, control) = backend_with_control(fs, observed).await?;
    let root = observed.identity().root();
    let cap = observed
        .logical()
        .get("CAPABILITIES")
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)?;
    let registration = observed
        .physical_reads()
        .first()
        .filter(|read| read.path() == control.join("backend-registration.cbor"))
        .and_then(|read| read.bytes())
        .ok_or_else(corrupt)?;
    let cap_path = root.join("CAPABILITIES");
    for (path, bytes, policy) in [
        (
            cap_path.clone(),
            cap,
            FencePolicy::Payload { owner: frame.owner },
        ),
        (
            control.join("backend-registration.cbor"),
            registration,
            FencePolicy::ProtectedRecord { owner: frame.owner },
        ),
    ] {
        if frame.actual_read(fs, &path, policy).await?.as_deref() != Some(bytes) {
            return Err(corrupt());
        }
        let effect = frame.effect(Plan::WriteNew {
            path: path.clone(),
            bytes: bytes.to_vec(),
        })?;
        match fs.execute_retained_effect(effect).await {
            Err(super::NativeEffectFailure::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(super::NativeEffectFailure::Rejected(error)) => return Err(error),
            Err(super::NativeEffectFailure::Io(error)) => return Err(super::io_failure(error)),
            Ok(()) => return Err(unsupported()),
        }
        if frame.actual_read(fs, &path, policy).await?.as_deref() != Some(bytes) {
            return Err(corrupt());
        }
    }

    let first = cap.get(..1).ok_or_else(corrupt)?;
    frame
        .execute(
            fs,
            Plan::ProbeRange {
                path: cap_path.clone(),
                start: 0,
                expected: first.to_vec(),
            },
        )
        .await?;
    observed.revalidate().await?;
    if fs
        .read_range(
            &cap_path,
            crate::store::ByteRange {
                start: 0,
                length: 1,
            },
        )
        .await
        .map_err(super::io_failure)?
        .as_slice()
        != first
    {
        return Err(unsupported());
    }
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await?;
    observed.revalidate().await
}

/// Repairs only the complete portable and logical projection actually selected.
///
/// This separate backend-only entry point never substitutes for missing checked
/// context. It changes no selected state, actor authorization or lineage.
///
/// # Errors
/// Rejects unavailable native retention, stale observations, unsafe physical
/// preimages and failed retained effects; durable acknowledgment can be incomplete.
pub(crate) async fn repair<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
) -> Result<(), StoreFailure> {
    let mut frame = backend(fs, observed).await?;
    frame
        .project(
            fs,
            observed.identity().root(),
            observed.snapshot(),
            observed.logical(),
        )
        .await?;
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: observed.identity().root().to_owned(),
            },
        )
        .await?;
    observed.revalidate().await
}

/// Stages one canonical candidate log at its exact immutable registered key.
///
/// Orphan proposals remain unselected. Existing numbered migration slots are
/// readable, while this backend-only path cannot create migration authority.
///
/// # Errors
/// Rejects malformed names or canonical candidates, unavailable native retention,
/// stale selected observations, unsafe preimages and failed retained durability.
pub(crate) async fn stage_ref_log<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
    name: &str,
    sequence: u64,
    record: &RefLogRecord,
) -> Result<RefLogAppendOutcome, StoreFailure> {
    RefName::parse(name).map_err(|_| malformed())?;
    if record.record.seq != sequence {
        return Err(malformed());
    }
    let key = match record.record.candidate_id {
        Some(candidate) => BucketKey::reflog_candidate(name, sequence, &candidate),
        None => BucketKey::reflog(name, sequence),
    }
    .map_err(|_| malformed())?;
    let bytes = record.encode().map_err(|_| malformed())?;
    let mut frame = backend(fs, observed).await?;
    let policy = FencePolicy::Payload { owner: frame.owner };
    let root = PathBuf::from(observed.identity().root());
    if let Some(existing) = frame
        .actual_read(fs, &root.join(key.as_str()), policy)
        .await?
    {
        if record.record.candidate_id.is_none() && existing != bytes {
            return Err(corrupt());
        }
        observed.revalidate().await?;
        return Ok(RefLogAppendOutcome::Exists);
    }
    if record.record.candidate_id.is_none() {
        return Err(unsupported());
    }
    record
        .validate_candidate(
            record.cas_expected_previous().map_err(|_| malformed())?,
            &record.record,
        )
        .map_err(|_| malformed())?;
    frame
        .install(
            fs,
            &root,
            key.as_str(),
            &bytes,
            policy,
            Mutability::Immutable,
        )
        .await?;
    frame
        .execute(fs, Plan::SyncDirectory { path: root })
        .await?;
    observed.revalidate().await?;
    Ok(RefLogAppendOutcome::Appended)
}

/// Stages only the canonical admitted container pair at its fixed header-derived names.
///
/// This operation leaves membership unselected until the separate canonical
/// catalog transition wins its consecutive protected publication slot.
///
/// # Errors
/// Rejects stale selected observations, unavailable retention, unsafe physical
/// preimages, immutable collisions and failed durable native effects.
pub(crate) async fn stage_container<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
    artifacts: &ContainerArtifacts,
) -> Result<(), StoreFailure> {
    let mut frame = backend(fs, observed).await?;
    let root = observed.identity().root();
    let policy = FencePolicy::Payload { owner: frame.owner };
    let id = artifacts.id();
    for (key, bytes) in [
        (id.pack_key(), artifacts.pack()),
        (id.index_key(), artifacts.index()),
    ] {
        let key = BucketKey::parse(&key).map_err(|_| malformed())?;
        if key.mutability() != Mutability::Immutable {
            return Err(malformed());
        }
        frame
            .install(fs, root, key.as_str(), bytes, policy, Mutability::Immutable)
            .await?;
    }
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await?;
    observed.revalidate().await
}

/// Selects a canonical backend-only raw mutation under its actual retained hold.
///
/// The proof is fixed to Raw. This factory cannot install a Guard, create
/// checked lineage, acquire actor authority or authorize physical collection.
///
/// # Errors
/// Rejects stale whole preimages, mismatched physical receipts, unsafe names or
/// proposal reads, malformed canonical data and unavailable durable effects.
/// A failed acknowledgment after slot dispatch can be indeterminate.
pub(crate) async fn publish<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
    mutation: &RawMutation,
) -> Result<super::CheckedPublication, StoreFailure> {
    if mutation.previous() != observed.state()
        || mutation.predecessor() != observed.stamp().1
        || mutation.previous_logical() != observed.logical()
        || mutation.next().binding != observed.state().binding
        || mutation.next().guard != observed.state().guard
        || mutation.next().burn_owners != observed.state().burn_owners
    {
        return Err(corrupt());
    }
    let mut frame = backend(fs, observed).await?;
    frame.writes = Some(super::CompletedWrites {
        records: BTreeMap::new(),
    });
    let root = observed.identity().root();
    let owner = frame.owner;
    let control = observed
        .physical_reads()
        .first()
        .and_then(|read| read.path().parent())
        .ok_or_else(corrupt)?;
    for read in mutation.reads() {
        let key = read.path().strip_prefix(root).map_err(|_| corrupt())?;
        let key = key.to_str().ok_or_else(corrupt)?;
        BucketKey::parse(key).map_err(|_| corrupt())?;
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::Payload { owner },
            )
            .await?;
    }
    for (path, metadata) in mutation.parent_reads() {
        let expected = super::MetadataStamp::checked(metadata).map_err(super::io_failure)?;
        let (actual, actual_owner) = frame.parents.get(path).ok_or_else(corrupt)?;
        if *actual_owner != owner || !actual.same_incarnation(expected) {
            return Err(corrupt());
        }
    }
    observed.revalidate().await?;
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;

    // Immutable catalog artifacts precede the snapshot-bearing selected slot.
    for change in mutation.changes() {
        let key = BucketKey::parse(&change.key).map_err(|_| corrupt())?;
        if key.mutability() == Mutability::Immutable {
            frame
                .install(
                    fs,
                    root,
                    key.as_str(),
                    change.new.as_deref().ok_or_else(malformed)?,
                    FencePolicy::Payload { owner },
                    Mutability::Immutable,
                )
                .await?;
        }
    }
    let nonce: [u8; 32] = fs
        .random_bytes(32)
        .await
        .map_err(super::io_failure)?
        .try_into()
        .map_err(|_| unsupported())?;
    let operation = hex(&nonce);
    let snapshot = PortableSnapshot {
        revision: mutation.next().revision,
        origin: mutation.next().binding.clone(),
        projection: mutation
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
            mutation.next().revision
        ),
        digest: digest(&snapshot_bytes),
    };
    let transaction = PublicationTransaction {
        nonce,
        old: Some(observed.state().clone()),
        new: mutation.next().clone(),
        changes: mutation.changes().to_vec(),
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
            control,
            &transaction_key,
            &transaction_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::Immutable,
        )
        .await?;

    // Exact consecutive create-once installation remains the sole selection.
    let slot = PublicationCommit {
        revision: mutation.next().revision,
        predecessor: Some(observed.stamp().1),
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    };
    let slot_bytes = slot.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            control,
            &format!("publication/commits/{}", slot.revision),
            &slot_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::CreateOnce,
        )
        .await?;
    let mut logical = observed.logical().clone();
    for change in mutation.changes() {
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
    let (acknowledgment, completed) = super::super::artifact_seal::raw_publication::raw_plan(
        observed,
        mutation,
        &slot,
        &transaction,
        &snapshot_bytes,
        frame.writes.as_ref().ok_or_else(unsupported)?,
    )
    .map_err(super::native_failure)?;
    frame.execute(fs, acknowledgment).await?;
    completed.take().map_err(|error| match error {
        super::NativeEffectFailure::Rejected(error) => error,
        super::NativeEffectFailure::Io(error) => {
            let kind = if error.kind() == std::io::ErrorKind::Unsupported {
                StoreErrorKind::Unsupported
            } else {
                StoreErrorKind::Unavailable { retry_after: None }
            };
            StoreFailure::with_source(kind, error)
        }
    })?;
    Ok(super::CheckedPublication {
        revision: slot.revision,
        digest: digest(&slot_bytes),
    })
}

fn malformed() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(
        crate::store::InvalidReason::MalformedRequest,
    ))
}

/// Builds a fixed backend sync effect for the actual cancellation regression.
///
/// # Errors
/// Rejects unavailable retention or stale, unsafe actual held observations.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) async fn backend_sync_for_test<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
    arrived: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
) -> Result<super::super::NativeFsEffect, StoreFailure> {
    let frame = backend(fs, observed).await?;
    let mut effect = frame.effect(Plan::SyncDirectory {
        path: observed.identity().root().to_owned(),
    })?;
    effect.gates.push(super::super::TestGate {
        phase: super::super::TestGatePhase::BeforeChecks,
        arrived,
        release,
    });
    Ok(effect)
}

/// Pauses only an already sealed fixed CAP create-new probe inside its worker.
///
/// # Errors
/// Rejects effects whose private command is not the actual CAP probe. This
/// diagnostic attaches no path, publication plan or authority supplied by a caller.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) fn gate_active_cap_probe_for_test(
    mut effect: super::NativeFsEffect,
    arrived: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
) -> Result<super::NativeFsEffect, StoreFailure> {
    if !matches!(
        &effect.plan,
        Plan::WriteNew { path, .. } if path.file_name().is_some_and(|name| name == "CAPABILITIES")
    ) {
        return Err(corrupt());
    }
    effect.gates.push(super::super::TestGate {
        phase: super::super::TestGatePhase::BeforeChecks,
        arrived,
        release,
    });
    Ok(effect)
}
