//! Completes exact owned unlinks and monotone protected progress with closed acknowledgment.

#[cfg(all(test, feature = "tokio"))]
use super::super::{TestGatePhase, wait_test_gate};
use super::*;

#[cfg(test)]
use super::super::EffectFault;

/// Fixes one phase from a genuine current producer and executor-made observation.
pub(in super::super::super) struct StepRequest {
    observed: Arc<NativeLocalDeletion>,
    next: DeleteOperation,
    temporary: PathBuf,
    cancellation_pair: Option<Arc<super::super::restore_pair::PairHold>>,
    result: mpsc::Sender<DeleteOperation>,
}

/// Receives only actual durable native progress.
pub(in super::super::super) struct StepReceiver(mpsc::Receiver<DeleteOperation>);

impl StepReceiver {
    /// Takes one completed native progress value.
    ///
    /// # Errors
    /// Refuses unit/no-op completion without actual effect acknowledgment.
    pub(in super::super::super) fn take(self) -> Result<DeleteOperation, NativeEffectFailure> {
        self.0
            .try_recv()
            .map_err(|_| invalid("local deletion acknowledgment absent").into())
    }
}

impl StepRequest {
    /// Borrows the actual protected destination for finite executor observation.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super::super) fn path(&self) -> &Path {
        &self.observed.intent.path
    }

    /// Returns the genuinely submitted phase without granting permission.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super::super) fn phase(&self) -> DeletePhase {
        if self.cancellation_pair.is_some() {
            DeletePhase::Cancelled
        } else {
            self.observed.operation.phase
        }
    }

    /// Borrows the protected staging name for genuine preimage capture.
    pub(in super::super::super) fn temporary(&self) -> &Path {
        &self.temporary
    }
}

/// Builds the single successor selected by the closed current producer.
///
/// # Errors
/// Refuses unrelated backend, invalid phase or canonical progress overflow.
pub(in super::super::super) fn plan(
    checked: &crate::selected_bridge::native_local_deletion::CheckedLocalDeletion<'_, '_>,
    nonce: [u8; 16],
) -> Result<(StepRequest, StepReceiver), NativeEffectFailure> {
    let observed = Arc::clone(checked.observed());
    if observed.root != checked.current().observed().identity().root() {
        return Err(invalid("local deletion belongs to another backend").into());
    }
    let phase = match observed.operation.phase {
        DeletePhase::Authorized => DeletePhase::Invalidated,
        DeletePhase::Invalidated => DeletePhase::PackAbsent,
        DeletePhase::PackAbsent => DeletePhase::IndexAbsent,
        DeletePhase::IndexAbsent => DeletePhase::ContainersConfirmed,
        DeletePhase::ContainersConfirmed | DeletePhase::Done => DeletePhase::Done,
        _ => return Err(invalid("terminal local deletion has no successor").into()),
    };
    let next = if observed.operation.phase == DeletePhase::Done {
        observed.operation.clone()
    } else {
        observed
            .operation
            .advance(phase, checked.current().effect_context().lease().clone())
            .map_err(io::Error::other)?
    };
    let temporary = observed
        .intent
        .path
        .with_file_name(format!(".delete-{}", hex(&nonce)));
    let (result, receiver) = mpsc::channel();
    Ok((
        StepRequest {
            observed,
            next,
            temporary,
            cancellation_pair: None,
            result,
        },
        StepReceiver(receiver),
    ))
}

/// Builds cancellation only from independently current checked restoration.
///
/// # Errors
/// Refuses unrelated or absent owned artifacts and invalid terminal progress.
pub(in super::super::super) fn cancellation_plan(
    checked: &crate::selected_bridge::native_collection_restore::CheckedLocalCancellation<'_, '_>,
    observed: Arc<NativeLocalDeletion>,
    nonce: [u8; 16],
) -> Result<(StepRequest, StepReceiver), NativeEffectFailure> {
    observed.recheck()?;
    checked.pair().check_root(&observed.root)?;
    if observed.root != checked.current().observed().identity().root()
        || checked.exclusion().pack_id != observed.operation.authorization.pack_id
        || checked.exclusion().cycle != observed.operation.authorization.cycle
        || checked.exclusion().epoch != observed.operation.authorization.epoch
        || observed
            .artifacts
            .iter()
            .any(|artifact| artifact.file.is_none())
    {
        return Err(invalid("cancellation is not the exact present checked restore").into());
    }
    let next = if observed.operation.phase == DeletePhase::Cancelled {
        observed.operation.clone()
    } else {
        observed
            .operation
            .advance(
                DeletePhase::Cancelled,
                checked.current().effect_context().lease().clone(),
            )
            .map_err(io::Error::other)?
    };
    let temporary = observed
        .intent
        .path
        .with_file_name(format!(".cancel-{}", hex(&nonce)));
    let (result, receiver) = mpsc::channel();
    Ok((
        StepRequest {
            observed,
            next,
            temporary,
            cancellation_pair: Some(checked.pair().held()),
            result,
        },
        StepReceiver(receiver),
    ))
}

fn check(
    worker: &Worker,
    observed: &NativeLocalDeletion,
    changed: &[&Path],
    removed: &[usize],
    replacements: &[Protected],
) -> Result<(), NativeEffectFailure> {
    worker.refresh(changed)?;
    for (index, artifact) in observed.artifacts.iter().enumerate() {
        if removed.contains(&index) {
            absent_name(&artifact.path)?;
        } else {
            artifact.check()?;
        }
    }
    for original in &observed.journals {
        if let Some(replacement) = replacements.iter().find(|item| item.path == original.path) {
            replacement.check()?;
        } else {
            original.check()?;
        }
    }
    if let Some(replacement) = replacements
        .iter()
        .find(|item| item.path == observed.intent.path)
    {
        replacement.check()?;
    } else {
        observed.intent.check()?;
    }
    worker.refresh(changed)
}

/// Opens only the exact directory chains already fenced by the current Frame.
fn retain_directories(
    worker: &mut Worker,
    observed: &NativeLocalDeletion,
) -> Result<(), NativeEffectFailure> {
    let mut required = std::collections::BTreeSet::new();
    for path in observed
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_path())
        .chain(
            observed
                .journals
                .iter()
                .map(|journal| journal.path.as_path()),
        )
        .chain(std::iter::once(observed.intent.path.as_path()))
    {
        let boundary = if path.starts_with(&observed.control) {
            &observed.control
        } else if path.starts_with(&observed.root) {
            &observed.root
        } else {
            return Err(invalid("local deletion directory lacks its namespace").into());
        };
        let mut parent = path.parent();
        while let Some(directory) = parent {
            required.insert(directory.to_owned());
            if directory == boundary {
                break;
            }
            parent = directory.parent();
        }
    }

    let mut directories = Vec::with_capacity(required.len());
    for path in required {
        worker.refresh(&[])?;
        observed.recheck()?;
        let fence = worker
            .projection
            .names
            .iter()
            .find(|fence| fence.path == path)
            .ok_or_else(|| invalid("local deletion lacks its current directory fence"))?;
        fence.policy.validate(fence.stamp)?;
        let file = open_native(&path, true)?;
        let stamp = MetadataStamp::checked(&file.metadata()?)?;
        if !stamp.same_incarnation(fence.stamp) {
            return Err(invalid("local deletion directory incarnation changed").into());
        }
        let directory = super::super::NativeOpenedDirectory {
            file: Arc::new(file),
            path,
            stamp,
            policy: fence.policy,
            parents: fence
                .parents
                .iter()
                .map(|parent| super::super::ParentFence {
                    path: parent.path.clone(),
                    stamp: parent.stamp,
                })
                .collect(),
        };
        directory.check()?;
        directories.push(directory);
    }
    worker.projection.directories = Some(directories.into());
    worker.refresh(&[])?;
    observed.recheck()?;
    Ok(())
}

fn sync_directories(
    worker: &mut Worker,
    observed: &NativeLocalDeletion,
    path: &Path,
    changed: &[&Path],
    removed: &[usize],
    replacements: &[Protected],
) -> Result<(), NativeEffectFailure> {
    let directories = Arc::clone(
        worker
            .projection
            .directories
            .as_ref()
            .ok_or_else(|| invalid("local deletion lacks retained directories"))?,
    );
    let mut parent = path.parent();
    while let Some(required) = parent {
        let directory = directories
            .iter()
            .find(|directory| directory.path == required)
            .ok_or_else(|| invalid("local deletion lacks exact containing directory"))?;
        #[cfg(all(test, feature = "tokio"))]
        wait_test_gate(&mut worker.gates, TestGatePhase::BeforeDirectorySync)?;
        check(worker, observed, changed, removed, replacements)?;
        directory.check()?;
        #[cfg(test)]
        if worker.faults.contains(&EffectFault::BeforeDirectorySync)
            || worker
                .faults
                .contains(&EffectFault::BeforeDirectorySyncAt(directory.path.clone()))
        {
            return Err(invalid("injected creation directory sync failure").into());
        }
        #[cfg(all(test, feature = "tokio"))]
        for (index, journal) in observed.journals.iter().enumerate() {
            if journal.path.parent() == Some(directory.path.as_path())
                && replacements.iter().any(|replacement| {
                    replacement.path == journal.path
                        && CreationJournal::decode(&replacement.bytes)
                            .is_ok_and(|record| record.state == JournalState::Invalidated)
                })
                && worker
                    .faults
                    .contains(&EffectFault::BeforeCancelledJournalDirectorySync(
                        index as u8,
                    ))
            {
                return Err(invalid("injected directory sync after journal invalidation").into());
            }
        }
        directory.file.sync_all()?;
        #[cfg(all(test, feature = "tokio"))]
        wait_test_gate(&mut worker.gates, TestGatePhase::AfterDirectorySync)?;
        directory.check()?;
        #[cfg(test)]
        if worker
            .faults
            .contains(&EffectFault::AfterDirectorySyncAt(directory.path.clone()))
        {
            return Err(invalid("injected creation failure after directory sync").into());
        }
        check(worker, observed, changed, removed, replacements)?;
        if required == observed.root || required == observed.control {
            break;
        }
        parent = required.parent();
    }
    Ok(())
}

// Records only mutations actually performed in this closed native step.
// Skipped original preimages remain covered by exact replacement/absence checks.
#[derive(Default)]
struct StepState {
    changed: Vec<PathBuf>,
    removed: Vec<usize>,
    replacements: Vec<Protected>,
    cancellation_pair: Option<Arc<super::super::restore_pair::PairHold>>,
}

fn replace(
    worker: &mut Worker,
    observed: &NativeLocalDeletion,
    path: &Path,
    temporary: &Path,
    bytes: &[u8],
    state: &mut StepState,
) -> Result<(), NativeEffectFailure> {
    let mut skips = state
        .changed
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    check(
        worker,
        observed,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    absent_name(temporary)?;
    let mut staged = create_staging(temporary)?;
    let stamp = MetadataStamp::checked(&staged.metadata()?)?;
    staged.write_all(bytes)?;
    state.changed.push(temporary.to_owned());
    skips = state.changed.iter().map(PathBuf::as_path).collect();
    check(
        worker,
        observed,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    checked_protected(&mut staged, temporary, stamp, bytes, observed.intent.owner)?;
    worker.file_sync(&staged, &skips)?;
    check(
        worker,
        observed,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    sync_directories(
        worker,
        observed,
        temporary,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::BeforeOpen)?;
    check(
        worker,
        observed,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    #[cfg(test)]
    if worker.faults.contains(&EffectFault::BeforeRename) {
        return Err(invalid("injected local progress rename failure").into());
    }
    std::fs::rename(temporary, path)?;
    state.changed.push(path.to_owned());
    let replacement = Protected {
        path: path.to_owned(),
        file: staged,
        stamp,
        bytes: bytes.to_vec(),
        owner: observed.intent.owner,
    };
    if let Some(pair) = &state.cancellation_pair
        && let Some(original) = observed
            .journals
            .iter()
            .find(|journal| journal.path == path)
    {
        let token = CancelledJournal {
            replacement: Protected {
                path: replacement.path.clone(),
                file: replacement.file.try_clone()?,
                stamp: replacement.stamp,
                bytes: replacement.bytes.clone(),
                owner: replacement.owner,
            },
            original: original.bytes.clone(),
        };
        pair.adopt_cancelled_journal(&token)?;
    }
    state.replacements.retain(|item| item.path != path);
    state.replacements.push(replacement);
    #[cfg(test)]
    if worker.faults.contains(&EffectFault::AfterRename) {
        return Err(invalid("injected local failure after progress rename").into());
    }
    skips = state.changed.iter().map(PathBuf::as_path).collect();
    check(
        worker,
        observed,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    sync_directories(
        worker,
        observed,
        path,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    Ok(())
}

// Visible matching protected bytes may be the prefix of a failed prior sync.
// Reestablish durability on their actual retained descriptor before progress.
fn resynchronize_journal(
    worker: &mut Worker,
    observed: &NativeLocalDeletion,
    journal: &Protected,
    state: &StepState,
) -> Result<(), NativeEffectFailure> {
    let skips = state
        .changed
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    check(
        worker,
        observed,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    journal.check()?;
    worker.file_sync(&journal.file, &skips)?;
    check(
        worker,
        observed,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    journal.check()?;
    sync_directories(
        worker,
        observed,
        &journal.path,
        &skips,
        &state.removed,
        &state.replacements,
    )
}

/// Performs one genuine phase, retaining all exclusions until actual durability.
///
/// # Errors
/// Refuses changed current authority or incarnation before each effect, and
/// preserves actual unlink, synchronization and conditional progress failures.
pub(in super::super) fn execute(
    request: StepRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    let observed = &request.observed;
    worker
        .projection
        .root(&observed.root, observed.intent.owner, false)?;
    worker
        .projection
        .root(&observed.control, observed.intent.owner, true)?;
    observed.recheck()?;
    worker.refresh(&[])?;
    retain_directories(&mut worker, observed)?;
    let mut state = StepState {
        cancellation_pair: request.cancellation_pair.clone(),
        ..StepState::default()
    };
    if observed.operation.phase == DeletePhase::Done {
        // A visible terminal record can precede a crashed acknowledgment. Sync
        // its actual descriptor and every retained absence chain on reopen.
        resynchronize_journal(&mut worker, observed, &observed.intent, &state)?;
        for journal in &observed.journals {
            resynchronize_journal(&mut worker, observed, journal, &state)?;
        }
        for artifact in &observed.artifacts {
            absent_name(&artifact.path)?;
            sync_directories(&mut worker, observed, &artifact.path, &[], &[], &[])?;
        }
        check(&worker, observed, &[], &[], &[])?;
        let _ = request.result.send(request.next);
        return Ok(());
    }
    if request.next.phase == DeletePhase::Cancelled {
        let bytes = request.next.encode().map_err(io::Error::other)?;
        // Cancellation becomes durable before any ownership journal is
        // invalidated, and before a later restore can clear the exclusion.
        replace(
            &mut worker,
            observed,
            &observed.intent.path,
            &request.temporary,
            &bytes,
            &mut state,
        )?;
        #[cfg(all(test, feature = "tokio"))]
        if worker
            .faults
            .contains(&EffectFault::AfterCancelledIntentSync)
        {
            return Err(invalid("injected failure after durable Cancelled intent").into());
        }
        for (index, version) in observed
            .operation
            .authorization
            .artifacts
            .iter()
            .enumerate()
        {
            let journal = CreationJournal {
                key: version.key.clone(),
                nonce: version.nonce,
                state: JournalState::Invalidated,
            };
            let bytes = journal.encode().map_err(io::Error::other)?;
            if observed.journals[index].bytes != bytes {
                let temporary = request
                    .temporary
                    .with_extension(format!("invalidate-{index}"));
                replace(
                    &mut worker,
                    observed,
                    &observed.journals[index].path,
                    &temporary,
                    &bytes,
                    &mut state,
                )?;
            } else {
                resynchronize_journal(&mut worker, observed, &observed.journals[index], &state)?;
            }
        }
        let skips = state
            .changed
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        check(
            &worker,
            observed,
            &skips,
            &state.removed,
            &state.replacements,
        )?;
        let _ = request.result.send(request.next);
        return Ok(());
    }
    if observed.operation.phase == DeletePhase::Authorized {
        for (index, version) in observed
            .operation
            .authorization
            .artifacts
            .iter()
            .enumerate()
        {
            let owned = CreationJournal {
                key: version.key.clone(),
                nonce: version.nonce,
                state: JournalState::Committed {
                    binding: version.binding.clone(),
                    file_identity: version.file_identity.clone(),
                },
            }
            .own(&observed.operation.authorization)
            .map_err(io::Error::other)?;
            let bytes = owned.encode().map_err(io::Error::other)?;
            if observed.journals[index].bytes != bytes {
                let temporary = request.temporary.with_extension(format!("owner-{index}"));
                replace(
                    &mut worker,
                    observed,
                    &observed.journals[index].path,
                    &temporary,
                    &bytes,
                    &mut state,
                )?;
            } else {
                resynchronize_journal(&mut worker, observed, &observed.journals[index], &state)?;
            }
        }
    }
    let artifact = match observed.operation.phase {
        DeletePhase::Invalidated => Some(0),
        DeletePhase::PackAbsent => Some(1),
        DeletePhase::ContainersConfirmed => Some(2),
        _ => None,
    };
    if let Some(index) = artifact {
        let target = &observed.artifacts[index];
        #[cfg(all(test, feature = "tokio"))]
        wait_test_gate(&mut worker.gates, TestGatePhase::BeforeOpen)?;
        let skips = state
            .changed
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        check(
            &worker,
            observed,
            &skips,
            &state.removed,
            &state.replacements,
        )?;
        #[cfg(all(test, feature = "tokio"))]
        if worker.faults.contains(&EffectFault::BeforeUnlink) {
            return Err(invalid("injected local unlink failure").into());
        }
        if target.file.is_some() {
            target.check()?;
            std::fs::remove_file(&target.path)?;
        }
        #[cfg(all(test, feature = "tokio"))]
        if worker.faults.contains(&EffectFault::AfterUnlink) {
            return Err(invalid("injected local failure after unlink").into());
        }
        state.removed.push(index);
        state.changed.push(target.path.clone());
        let skips = state
            .changed
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        absent_name(&target.path)?;
        sync_directories(
            &mut worker,
            observed,
            &target.path,
            &skips,
            &state.removed,
            &state.replacements,
        )?;
    }
    if observed.operation.phase == DeletePhase::IndexAbsent {
        for index in 0..2 {
            if observed.artifacts[index].file.is_some() {
                return Err(invalid("container confirmation found a present name").into());
            }
            let skips = state
                .changed
                .iter()
                .map(PathBuf::as_path)
                .collect::<Vec<_>>();
            sync_directories(
                &mut worker,
                observed,
                &observed.artifacts[index].path,
                &skips,
                &state.removed,
                &state.replacements,
            )?;
        }
    }
    let bytes = request.next.encode().map_err(io::Error::other)?;
    replace(
        &mut worker,
        observed,
        &observed.intent.path,
        &request.temporary,
        &bytes,
        &mut state,
    )?;
    let skips = state
        .changed
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    check(
        &worker,
        observed,
        &skips,
        &state.removed,
        &state.replacements,
    )?;
    let _ = request.result.send(request.next);
    Ok(())
}

/// Formats a fresh staging nonce without changing its bytes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
