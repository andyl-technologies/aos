//! Captures complete current authority for closed ordinary local reclamation effects.

use super::super::artifact_seal::local_deletion::{effects, observation};
use super::{
    BucketBinding, FencePolicy, Frame, LocalFs, Plan, StoreFailure, corrupt, hex, io_failure,
};
use crate::selected_bridge::{
    CheckedCurrentCollection, native_local_deletion::CheckedLocalDeletion,
};
use terrane_format::gc::{DeleteOperation, DeletePhase};

/// Exposes only executor-produced owned incarnation observations to the selector.
pub(crate) use super::super::artifact_seal::local_deletion::NativeLocalDeletion;

async fn capture<F: LocalFs + BucketBinding>(
    fs: &F,
    current: &CheckedCurrentCollection<'_, '_>,
) -> Result<(Frame, std::path::PathBuf), StoreFailure> {
    current.revalidate().await?;
    let (mut frame, control) = super::collection_checkpoints::retained_frame(
        fs,
        current.observed(),
        current.reads(),
        current.effect_context(),
    )
    .await?;
    let payload = FencePolicy::Payload { owner: frame.owner };
    for read in std::iter::once(current.reads().roots())
        .chain(std::iter::once(current.reads().state()))
        .chain(current.reads().inputs())
    {
        frame
            .observed_read(fs, read.path(), read.bytes(), read.metadata(), payload)
            .await?;
    }
    for mark in current.reads().marks() {
        let crate::selected_bridge::GcMarkRead::Revision { record: read, .. } = mark;
        frame
            .observed_read(fs, read.path(), read.bytes(), read.metadata(), payload)
            .await?;
    }
    Ok((frame, control))
}

async fn ownership_reads<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    control: &std::path::Path,
    key: &str,
) -> Result<(Vec<u8>, [Vec<u8>; 3]), StoreFailure> {
    let policy = FencePolicy::ProtectedRecord { owner: frame.owner };
    let bytes = frame
        .actual_read(fs, &control.join(key), policy)
        .await?
        .ok_or_else(corrupt)?;
    let operation = DeleteOperation::decode(&bytes, key).map_err(|_| corrupt())?;
    let mut journals = Vec::new();
    for version in &operation.authorization.artifacts {
        let path = control
            .join(".terrane-creation")
            .join(hex(blake3::hash(version.key.as_bytes()).as_bytes()));
        journals.push(
            frame
                .actual_read(fs, &path, policy)
                .await?
                .ok_or_else(corrupt)?,
        );
    }
    Ok((bytes, journals.try_into().map_err(|_| corrupt())?))
}

/// Observes actual owner journals and artifacts through a genuine current Frame.
///
/// # Errors
/// Refuses unprotected intent, unsafe journals, changed physical evidence or no-op execution.
pub(crate) async fn observe<F: LocalFs + BucketBinding>(
    fs: &F,
    current: &CheckedCurrentCollection<'_, '_>,
    key: &str,
    generation: u64,
) -> Result<NativeLocalDeletion, StoreFailure> {
    // Parsing before joining a caller lookup hint ensures it names only the
    // exact operation key, never an arbitrary external-control path.
    terrane_format::bucket::BucketKey::parse(key).map_err(|_| corrupt())?;
    let (mut frame, control) = capture(fs, current).await?;
    let (bytes, journals) = ownership_reads(fs, &mut frame, &control, key).await?;
    let (plan, receiver) = observation::plan(
        current.observed().identity().root(),
        &control,
        key,
        bytes,
        journals,
        generation,
        frame.owner,
    )
    .map_err(crate::selected_bridge::native_restore_failure)?;
    frame.execute(fs, plan).await?;
    current.revalidate().await?;
    receiver
        .take()
        .map_err(crate::selected_bridge::native_restore_failure)
}

/// Advances only the closed current producer's next exact durable phase.
///
/// # Errors
/// Refuses changed current authority, replaced evidence, actual durability or missing acknowledgment.
pub(crate) async fn advance<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedLocalDeletion<'_, '_>,
) -> Result<DeleteOperation, StoreFailure> {
    let current = checked.current();
    let (mut frame, control) = capture(fs, current).await?;
    for pair in checked.fresh_pairs() {
        frame.retain_current_pair(current.observed().identity().root(), &control, pair)?;
    }
    let key = checked.observed().operation().authorization.operation_key();
    let (bytes, _) = ownership_reads(fs, &mut frame, &control, &key).await?;
    if bytes
        != checked
            .observed()
            .operation()
            .encode()
            .map_err(|_| corrupt())?
    {
        return Err(corrupt());
    }
    let root = current.observed().identity().root();
    let fence_key = format!(
        "gc/{}/fence/{}",
        current.selected_checkpoint().0.cycle,
        current.observed().state().revision
    );
    let fence = current.fence().encode().map_err(|_| corrupt())?;
    let authorization = &checked.observed().operation().authorization;
    let terrane_format::gc::ArtifactBinding::Index { digest: index, .. } =
        &authorization.artifacts[1].binding
    else {
        return Err(corrupt());
    };
    let reconciliation = terrane_format::gc::publication::reconciliation::LocalGcReconciliation {
        authorization: authorization.digest().map_err(|_| corrupt())?,
        fence_key: fence_key.clone(),
        fence_digest: super::digest(&fence),
        pack: authorization.pack_id,
        cycle: authorization.cycle,
        epoch: authorization.epoch,
        index: *index,
    }
    .encode()
    .map_err(|_| corrupt())?;
    let payload = FencePolicy::Payload { owner: frame.owner };
    frame
        .install(
            fs,
            root,
            &fence_key,
            &fence,
            payload,
            super::Mutability::Immutable,
        )
        .await?;
    let reconciliation_key = format!(
        "gc/{}/reconcile/{}/{}",
        current.selected_checkpoint().0.cycle,
        hex(&authorization.nonce),
        current.observed().state().revision
    );
    frame
        .install(
            fs,
            root,
            &reconciliation_key,
            &reconciliation,
            payload,
            super::Mutability::Immutable,
        )
        .await?;
    let nonce: [u8; 16] = fs
        .random_bytes(16)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| corrupt())?;
    let (request, receiver) =
        effects::plan(checked, nonce).map_err(crate::selected_bridge::native_restore_failure)?;
    let protected = FencePolicy::ProtectedRecord { owner: frame.owner };
    if frame
        .actual_read(fs, request.temporary(), protected)
        .await?
        .is_some()
    {
        return Err(corrupt());
    }
    // Retain actual directories for each possible artifact and protected update.
    // The native worker synchronizes only the relevant containing/ancestor chain.
    for version in &checked.observed().operation().authorization.artifacts {
        let path = current.observed().identity().root().join(&version.key);
        let mut parent = path.parent();
        while let Some(directory) = parent {
            frame
                .directory(
                    fs,
                    directory,
                    FencePolicy::ProtectedAncestor { owner: frame.owner },
                )
                .await?;
            if directory == current.observed().identity().root() {
                break;
            }
            parent = directory.parent();
        }
    }
    let path = control.join(&key);
    let mut parent = path.parent();
    while let Some(directory) = parent {
        frame
            .directory(
                fs,
                directory,
                FencePolicy::PrivateControlDirectory { owner: frame.owner },
            )
            .await?;
        if directory == control {
            break;
        }
        parent = directory.parent();
    }
    frame
        .execute(fs, Plan::AdvanceLocalDeletion(Box::new(request)))
        .await?;
    let result = receiver
        .take()
        .map_err(crate::selected_bridge::native_restore_failure)?;
    current.revalidate().await?;
    current.effect_context().final_check().recheck()?;
    if result.phase == DeletePhase::Cancelled {
        return Err(corrupt());
    }
    Ok(result)
}

// These are the closed cancellation executor's 16-byte staging nonce and
// optional fixed artifact index, not the operation's 32-byte nonce namespace.
fn cancellation_staging_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(".cancel-") else {
        return false;
    };
    let nonce = match suffix.split_once('.') {
        Some((nonce, "invalidate-0" | "invalidate-1" | "invalidate-2")) => nonce,
        Some(_) => return false,
        None => suffix,
    };
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Locates represented ownership only as a lookup hint for native observation.
///
/// # Errors
/// Refuses conflicting journals, malformed protected intent or failed execution.
pub(crate) async fn restore_owner<F: LocalFs + BucketBinding>(
    fs: &F,
    selected: &crate::bucket::publication::SelectedObservation<'_>,
    exclusion: &terrane_format::bucket::PackExclusion,
    generation: u64,
) -> Result<Option<std::sync::Arc<NativeLocalDeletion>>, StoreFailure> {
    let (mut frame, control) = super::raw::backend_with_control(fs, selected).await?;
    let id = crate::pack::PackId::from_random_bytes(exclusion.pack_id);
    let keys = [
        id.pack_key(),
        id.index_key(),
        format!("trash/{}/{id}", exclusion.cycle),
    ];
    let mut operation_key = None;
    let mut observed_journals = Vec::new();
    for key in keys {
        let path = super::super::artifact_seal::journal_path(&control, &key);
        let bytes = frame
            .actual_read(
                fs,
                &path,
                FencePolicy::ProtectedRecord { owner: frame.owner },
            )
            .await?;
        let Some(bytes) = bytes else { continue };
        let Ok(journal) = terrane_format::gc::CreationJournal::decode(&bytes) else {
            continue;
        };
        observed_journals.push(journal.clone());
        if let terrane_format::gc::JournalState::DeleteOwned {
            operation_key: candidate,
            ..
        } = journal.state
        {
            if operation_key.as_ref().is_some_and(|old| old != &candidate) {
                return Err(corrupt());
            }
            operation_key = Some(candidate);
        }
    }
    if operation_key.is_none() {
        // Neither Committed nor Invalidated carries an owner key. A durable
        // Authorized intent can precede the first DeleteOwned journal. Entries
        // are hints only; native observation independently checks exact intent,
        // journal state/binding/nonces and actual artifact incarnations.
        let directory = control.join(format!(
            "gc/{}/delete/{}",
            exclusion.cycle,
            hex(&exclusion.pack_id)
        ));
        let requires_intent = observed_journals
            .iter()
            .any(|journal| journal.state == terrane_format::gc::JournalState::Invalidated);
        let metadata = match fs.symlink_metadata(&directory).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !requires_intent => {
                return Ok(None);
            }
            Err(error) => return Err(io_failure(error)),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(corrupt());
        }
        frame
            .directory(
                fs,
                &directory,
                FencePolicy::PrivateControlDirectory { owner: frame.owner },
            )
            .await?;
        let candidates = fs.read_dir(&directory).await.map_err(io_failure)?;
        for path in candidates {
            if path.parent() != Some(directory.as_path()) {
                return Err(corrupt());
            }
            let key = path
                .strip_prefix(&control)
                .map_err(|_| corrupt())?
                .to_str()
                .ok_or_else(corrupt)?
                .to_owned();
            let bytes = frame
                .actual_read(
                    fs,
                    &path,
                    FencePolicy::ProtectedRecord { owner: frame.owner },
                )
                .await?
                .ok_or_else(corrupt)?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(corrupt)?;
            if cancellation_staging_name(name) {
                // A failed pre-rename sync may leave partial private staging.
                // Retain its protected nofollow preimage, but its bytes never
                // select an operation or authorize cancellation/restoration.
                continue;
            }
            terrane_format::bucket::BucketKey::parse(&key).map_err(|_| corrupt())?;
            let intent = DeleteOperation::decode(&bytes, &key).map_err(|_| corrupt())?;
            let matches_incarnation = matches!(
                intent.phase,
                DeletePhase::Authorized | DeletePhase::Cancelled
            ) && intent.authorization.pack_id == exclusion.pack_id
                && intent.authorization.cycle == exclusion.cycle
                && intent.authorization.epoch == exclusion.epoch
                && observed_journals.len() == 3
                && intent
                    .authorization
                    .artifacts
                    .iter()
                    .zip(&observed_journals)
                    .all(|(version, journal)| {
                        version.key == journal.key && version.nonce == journal.nonce
                    });
            if matches_incarnation {
                if operation_key.replace(key).is_some() {
                    return Err(corrupt());
                }
            } else if intent.phase != DeletePhase::Cancelled {
                return Err(corrupt());
            }
        }
        if operation_key.is_none() && requires_intent {
            return Err(corrupt());
        }
    }
    let Some(key) = operation_key else {
        return Ok(None);
    };
    let (bytes, journals) = ownership_reads(fs, &mut frame, &control, &key).await?;
    let (plan, receiver) = observation::plan(
        selected.identity().root(),
        &control,
        &key,
        bytes,
        journals,
        generation,
        frame.owner,
    )
    .map_err(crate::selected_bridge::native_restore_failure)?;
    frame.execute(fs, plan).await?;
    Ok(Some(std::sync::Arc::new(receiver.take().map_err(
        crate::selected_bridge::native_restore_failure,
    )?)))
}

/// Exposes the transparent observer through its actual native executor parent.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) use super::super::artifact_seal::local_deletion::test_fs::{
    DeletionBoundary, DeletionFs,
};
