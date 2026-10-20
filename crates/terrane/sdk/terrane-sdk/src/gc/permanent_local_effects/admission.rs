//! Selects fresh verified recovery placements without restoring a permanent key.
//!
//! The same current owner, lease, Original inputs and original source descriptors
//! surround actual staging and raw selection. Proposed bytes confer no rights;
//! only the closed native durability receipt completes this operation.

use super::super::{
    CompletedWrites, Mutability, Plan, PortableCurrent, PortableSnapshot, PredecessorSlot,
    ProjectionEntry, PublicationCommit, PublicationTransaction, digest, hex, unsupported,
};
use super::{
    BucketBinding, CheckedPermanentLocalOwner, FencePolicy, Frame, LocalFs, StoreFailure, corrupt,
};
use crate::bucket::permanent_restore::candidate::Candidate;
use crate::bucket::publication::RawMutation;
use terrane_format::gc::publication::PublicationProof;

/// Retains actual completed staging and its current source predicates.
pub(crate) struct StagedCandidate {
    frame: Frame,
    control: std::path::PathBuf,
    root: std::path::PathBuf,
    predecessor: terrane_format::gc::publication::RawDigest,
    source: std::sync::Arc<super::NativePermanentObservation>,
    inventory: terrane_format::bucket::PackInventoryEntry,
}

/// Stages only the real qualified candidate before backend proposal validation.
///
/// # Errors
/// Refuses changed current inputs, unsafe sources or targets and missing actual
/// native pair completion. Its result confers no selected membership.
pub(crate) async fn stage_candidate<F: LocalFs + BucketBinding>(
    fs: &F,
    owner: &CheckedPermanentLocalOwner<'_, '_>,
    candidate: &Candidate,
) -> Result<StagedCandidate, StoreFailure> {
    owner.revalidate().await?;
    let observed = owner.observed();
    let root = observed.identity().root();
    let (mut frame, control) = super::capture_owned(fs, owner).await?;
    for read in candidate.reads() {
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await?;
    }
    let extraction = candidate.source().extraction().ok_or_else(corrupt)?;
    let source = crate::pack::PackId::from_random_bytes(owner.pack());
    for (key, (bytes, metadata)) in [
        (source.pack_key(), extraction.pack()),
        (source.index_key(), extraction.index()),
    ] {
        frame
            .observed_read(
                fs,
                &root.join(key),
                Some(bytes),
                Some(metadata),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await?;
    }
    let current = frame.final_check.as_ref().ok_or_else(corrupt)?;
    frame.final_check = Some(current.with_permanent_source(candidate.source()));
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;
    // Secure entropy never makes an existing orphan or journal a fresh Q.
    // Keep each actual absence (including its first missing ancestor) in the
    // submitted Frame before any creation handoff can use the proposed names.
    let fresh = candidate.artifacts().id();
    for key in [fresh.pack_key(), fresh.index_key()] {
        if frame
            .actual_read(
                fs,
                &root.join(&key),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await?
            .is_some()
        {
            return Err(corrupt());
        }
        let journal = control
            .join(".terrane-creation")
            .join(super::super::hex(blake3::hash(key.as_bytes()).as_bytes()));
        if frame
            .actual_read(
                fs,
                &journal,
                FencePolicy::ProtectedRecord { owner: frame.owner },
            )
            .await?
            .is_some()
        {
            return Err(corrupt());
        }
    }
    super::super::creation::stage_pair(fs, &mut frame, root, &control, candidate.artifacts())
        .await?;
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await?;
    owner.revalidate().await?;
    // Creator-sealed pack bytes remain whole preimages, not metadata outputs.
    frame.writes = Some(CompletedWrites {
        records: std::collections::BTreeMap::new(),
    });
    Ok(StagedCandidate {
        frame,
        control,
        root: root.to_owned(),
        predecessor: observed.stamp().1,
        source: candidate.source().clone(),
        inventory: candidate.artifacts().inventory().clone(),
    })
}

/// Stages the candidate and selects its exact checked raw successor.
///
/// # Errors
/// Refuses any changed source, owner, lease, Original input, logical predecessor,
/// unsafe physical state, staging failure, selection conflict or absent real ACK.
pub(crate) async fn publish_candidate<F: LocalFs + BucketBinding>(
    fs: &F,
    owner: &CheckedPermanentLocalOwner<'_, '_>,
    candidate: &Candidate,
    mutation: &RawMutation,
    staged: StagedCandidate,
) -> Result<(), StoreFailure> {
    owner.revalidate().await?;
    if mutation.previous() != owner.observed().state()
        || mutation.previous_logical() != owner.observed().logical()
        || mutation.predecessor() != owner.observed().stamp().1
        || mutation.changes() != candidate.changes()
    {
        return Err(corrupt());
    }
    if staged.root != owner.observed().identity().root()
        || staged.predecessor != owner.observed().stamp().1
        || !std::sync::Arc::ptr_eq(&staged.source, candidate.source())
        || staged.inventory != *candidate.artifacts().inventory()
    {
        return Err(corrupt());
    }
    let StagedCandidate {
        mut frame, control, ..
    } = staged;
    let observed = owner.observed();
    let root = observed.identity().root();
    for read in mutation.reads() {
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await?;
    }
    let uid = frame.owner;
    for change in mutation.changes() {
        let key = terrane_format::bucket::BucketKey::parse(&change.key).map_err(|_| corrupt())?;
        if key.mutability() == Mutability::Immutable {
            frame
                .install(
                    fs,
                    root,
                    &change.key,
                    change.new.as_deref().ok_or_else(corrupt)?,
                    FencePolicy::Payload { owner: uid },
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
            .map(|change| ProjectionEntry {
                key: change.key.clone(),
                value: change.new.clone(),
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
            FencePolicy::Payload { owner: uid },
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
            FencePolicy::ProtectedRecord { owner: uid },
            Mutability::Immutable,
        )
        .await?;
    owner.revalidate().await?;
    frame.verify_staged_payloads(fs, root).await?;
    let slot = PublicationCommit {
        revision: mutation.next().revision,
        predecessor: Some(observed.stamp().1),
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    };
    frame
        .install(
            fs,
            &control,
            &format!("publication/commits/{}", slot.revision),
            &slot.encode().map_err(|_| corrupt())?,
            FencePolicy::ProtectedRecord { owner: uid },
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
    let (plan, receiver) = super::super::super::artifact_seal::raw_publication::raw_plan(
        observed,
        mutation,
        &slot,
        &transaction,
        &snapshot_bytes,
        super::super::super::artifact_seal::raw_publication::RawDurabilityInputs {
            writes: frame.writes.as_ref().ok_or_else(corrupt)?,
            fresh_immutable_outputs: &std::collections::BTreeSet::new(),
            context: None,
        },
    )
    .map_err(crate::selected_bridge::native_restore_failure)?;
    frame.execute(fs, plan).await?;
    receiver
        .take()
        .map_err(crate::selected_bridge::native_restore_failure)
}
