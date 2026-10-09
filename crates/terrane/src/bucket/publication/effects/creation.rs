//! Creates native container incarnations under the actual retained backend frame.
//!
//! Only genuinely missing artifacts receive fresh Pending, same-descriptor
//! synchronization and Committed evidence. Present imported artifacts and valid
//! old journals remain unchanged and grant no current incarnation authority.
//!
//! ```text
//! both-member capture -> fresh Pending -> native Pending receipt
//! -> immutable artifact -> native descriptor seal -> durable Commit receipt
//! ```

use super::super::artifact_seal::{commit_plan, pending::pending_plan, seal_plan};
use super::{
    BucketBinding, FencePolicy, Frame, LocalFs, Mutability, NativeEffectFailure, Path, Plan,
    StoreFailure, corrupt, io_failure, unsupported,
};
use crate::bucket::publication::ContainerArtifacts;
use terrane_core::bucket::BucketKey;
use terrane_core::gc::{ArtifactBinding, CreationJournal, JournalState};

struct CapturedArtifact<'body> {
    key: String,
    journal_key: String,
    body: &'body [u8],
    binding: ArtifactBinding,
    present: bool,
    journal: Option<Vec<u8>>,
    previous_nonce: Option<[u8; 32]>,
}

fn native_failure(error: NativeEffectFailure) -> StoreFailure {
    match error {
        NativeEffectFailure::Rejected(error) => error,
        NativeEffectFailure::Io(error) => io_failure(error),
    }
}

fn journal_key(key: &str) -> String {
    let suffix: String = blake3::hash(key.as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(".terrane-creation/{suffix}")
}

async fn capture<'body, F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &Path,
    control: &Path,
    key: String,
    body: &'body [u8],
    binding: ArtifactBinding,
) -> Result<CapturedArtifact<'body>, StoreFailure> {
    let parsed = BucketKey::parse(&key).map_err(|_| corrupt())?;
    if parsed.mutability() != Mutability::Immutable {
        return Err(corrupt());
    }
    let actual = frame
        .actual_read(
            fs,
            &root.join(&key),
            FencePolicy::Payload { owner: frame.owner },
        )
        .await?;
    if actual.as_deref().is_some_and(|actual| actual != body) {
        return Err(corrupt());
    }
    let journal_key = journal_key(&key);
    let journal = frame
        .actual_read(
            fs,
            &control.join(&journal_key),
            FencePolicy::ProtectedRecord { owner: frame.owner },
        )
        .await?;
    let previous_nonce = match &journal {
        Some(bytes) => {
            let decoded = CreationJournal::decode(bytes).map_err(|_| corrupt())?;
            if decoded.key != key {
                return Err(corrupt());
            }
            if matches!(decoded.state, JournalState::DeleteOwned { .. }) {
                return Err(unsupported());
            }
            Some(decoded.nonce)
        }
        None => None,
    };
    Ok(CapturedArtifact {
        key,
        journal_key,
        body,
        binding,
        present: actual.is_some(),
        journal,
        previous_nonce,
    })
}

async fn refresh_member<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &Path,
    control: &Path,
    captured: &CapturedArtifact<'_>,
) -> Result<(), StoreFailure> {
    // Our preceding member can create a shared previously absent parent. Read
    // newly reachable leaves without discarding any unrelated original receipt.
    let actual = frame
        .actual_read(
            fs,
            &root.join(&captured.key),
            FencePolicy::Payload { owner: frame.owner },
        )
        .await?;
    let expected = captured.present.then_some(captured.body);
    if actual.as_deref() != expected {
        return Err(corrupt());
    }
    let journal = frame
        .actual_read(
            fs,
            &control.join(&captured.journal_key),
            FencePolicy::ProtectedRecord { owner: frame.owner },
        )
        .await?;
    if journal != captured.journal {
        return Err(corrupt());
    }
    Ok(())
}

async fn entropy<const LENGTH: usize, F: LocalFs>(fs: &F) -> Result<[u8; LENGTH], StoreFailure> {
    fs.random_bytes(LENGTH)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| unsupported())
}

async fn create<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &Path,
    control: &Path,
    captured: &CapturedArtifact<'_>,
    retained_nonces: &[Option<[u8; 32]>],
) -> Result<Option<[u8; 32]>, StoreFailure> {
    refresh_member(fs, frame, root, control, captured).await?;
    if captured.present {
        // An old record or equal imported bytes never mint a fresh receipt.
        return Ok(None);
    }

    let nonce = entropy::<32, _>(fs).await?;
    if retained_nonces.contains(&Some(nonce)) {
        return Err(unsupported());
    }
    let pending = CreationJournal {
        key: captured.key.clone(),
        nonce,
        state: JournalState::Pending,
    }
    .encode()
    .map_err(|_| corrupt())?;
    let protected = FencePolicy::ProtectedRecord { owner: frame.owner };
    frame
        .install(
            fs,
            control,
            &captured.journal_key,
            &pending,
            protected,
            Mutability::CompareAndSwap,
        )
        .await?;

    let (plan, receiver) = pending_plan(root, control, &captured.key, &pending, frame.owner)
        .map_err(native_failure)?;
    frame.execute(fs, plan).await?;
    let pending_receipt = receiver.take().map_err(native_failure)?;

    let payload = FencePolicy::Payload { owner: frame.owner };
    frame
        .install(
            fs,
            root,
            &captured.key,
            captured.body,
            payload,
            Mutability::Immutable,
        )
        .await?;
    let (plan, receiver) = seal_plan(pending_receipt, captured.body).map_err(native_failure)?;
    frame.execute(fs, plan).await?;
    let seal = receiver.take().map_err(native_failure)?;

    let staging = entropy::<16, _>(fs).await?;
    let (request, receiver) =
        commit_plan(seal, control, &pending, captured.binding.clone(), staging)
            .map_err(native_failure)?;
    let temporary = request.temporary_path().to_owned();
    if frame
        .actual_read(fs, &temporary, protected)
        .await?
        .is_some()
    {
        return Err(corrupt());
    }
    frame
        .execute(fs, Plan::CommitCreation(Box::new(request)))
        .await?;
    receiver.take().map_err(native_failure)?;

    recapture_committed(
        fs,
        frame,
        &control.join(&captured.journal_key),
        captured,
        nonce,
    )
    .await?;
    Ok(Some(nonce))
}

async fn recapture_committed<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    journal_path: &Path,
    captured: &CapturedArtifact<'_>,
    nonce: [u8; 32],
) -> Result<(), StoreFailure> {
    // Native acknowledgment has qualified this exact replacement. Retain every
    // other preimage, including the now-absent staging name and other member.
    frame.reads.retain(|read| read.path != journal_path);
    let bytes = frame
        .actual_read(
            fs,
            journal_path,
            FencePolicy::ProtectedRecord { owner: frame.owner },
        )
        .await?
        .ok_or_else(corrupt)?;
    let record = CreationJournal::decode(&bytes).map_err(|_| corrupt())?;
    let JournalState::Committed { binding, .. } = record.state else {
        return Err(corrupt());
    };
    if record.key != captured.key || record.nonce != nonce || binding != captured.binding {
        return Err(corrupt());
    }

    // The native commit replaces the Pending body outside Frame::install.
    // Keep the final durability inventory aligned with the same acknowledged
    // replacement, rather than asking a later publication to sync old bytes.
    if let Some(writes) = &mut frame.writes {
        let completed = writes.records.get_mut(journal_path).ok_or_else(corrupt)?;
        let previous = CreationJournal::decode(completed.expected.as_deref().ok_or_else(corrupt)?)
            .map_err(|_| corrupt())?;
        if completed.root.join(&captured.journal_key) != journal_path
            || !matches!(completed.policy, FencePolicy::ProtectedRecord { owner } if owner == frame.owner)
            || previous.key != captured.key
            || previous.nonce != nonce
            || !matches!(previous.state, JournalState::Pending)
        {
            return Err(corrupt());
        }
        completed.expected = Some(bytes);
    }
    Ok(())
}

/// Stages both canonical artifacts with native creation evidence for missing bytes.
///
/// Both journal/artifact preflights precede any effect. Existing valid records
/// remain unchanged without qualifying their claimed creation or elapsed age.
///
/// # Errors
/// Rejects collisions, malformed or wrongly associated protected journals,
/// DeleteOwned, repeated incarnation entropy, changed original captures and
/// unavailable native retention, closed acknowledgments or durable effects.
pub(super) async fn stage_pair<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &Path,
    control: &Path,
    artifacts: &ContainerArtifacts,
) -> Result<(), StoreFailure> {
    let inventory = artifacts.inventory();
    let id = artifacts.id();
    let pack = capture(
        fs,
        frame,
        root,
        control,
        id.pack_key(),
        artifacts.pack(),
        ArtifactBinding::Pack {
            digest: inventory.pack_hash,
            size: inventory.pack_size,
        },
    )
    .await?;
    let index = capture(
        fs,
        frame,
        root,
        control,
        id.index_key(),
        artifacts.index(),
        ArtifactBinding::Index {
            digest: inventory.index_hash,
            size: inventory.index_size,
        },
    )
    .await?;

    let mut retained_nonces = [pack.previous_nonce, index.previous_nonce, None];
    retained_nonces[2] = create(fs, frame, root, control, &pack, &retained_nonces).await?;
    create(fs, frame, root, control, &index, &retained_nonces).await?;
    Ok(())
}
