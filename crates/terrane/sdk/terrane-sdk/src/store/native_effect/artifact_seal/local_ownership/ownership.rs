//! Acknowledges genuine protected first ownership without deleting artifacts.

#[cfg(test)]
use super::super::EffectFault;
use super::super::{absent_name, checked_protected, create_staging};
use super::*;
use std::io::Write;
use terrane_format::gc::{DeleteOperation, DeletePhase};

/// Fixes one checked ownership boundary and its empty result channel.
pub(in super::super::super) struct OwnershipRequest {
    triple: Arc<PairHold>,
    root: PathBuf,
    control: PathBuf,
    operation: DeleteOperation,
    boundary: u8,
    target: PathBuf,
    temporary: PathBuf,
    expected: Option<Vec<u8>>,
    body: Vec<u8>,
    owner: u32,
    result: mpsc::Sender<()>,
}

impl OwnershipRequest {
    /// Borrows the exact protected operation destination for fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super::super) fn path(&self) -> &Path {
        &self.target
    }

    /// Returns the fixed native boundary solely for precise fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super::super) fn boundary(&self) -> u8 {
        self.boundary
    }
}

impl OwnershipRequest {
    /// Borrows the fixed protected staging preimage for genuine Frame capture.
    pub(in super::super::super) fn temporary_path(&self) -> &Path {
        &self.temporary
    }

    /// Borrows the one canonical body fixed by the genuine operation.
    pub(in super::super::super) fn body(&self) -> &[u8] {
        &self.body
    }

    /// Borrows the fixed protected destination and conditional preimage.
    pub(in super::super::super) fn destination(&self) -> (&Path, Option<&[u8]>) {
        (&self.target, self.expected.as_deref())
    }
}

/// Takes acknowledgment which only the actual native worker can populate.
pub(in super::super::super) struct OwnershipReceiver(mpsc::Receiver<()>);

impl OwnershipReceiver {
    /// Takes the actual durable acknowledgment once.
    ///
    /// # Errors
    /// Refuses unexecuted, failed or no-op native completion.
    pub(in super::super::super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.0
            .try_recv()
            .map_err(|_| unknown("native ownership acknowledgment absent").into())
    }
}

/// Builds only a boundary fixed by the genuine current and elapsed producer.
///
/// # Errors
/// Refuses mismatched native root, an invalid boundary or canonical operation.
pub(in super::super::super) fn plan(
    checked: &crate::selected_bridge::native_local_ownership::CheckedLocalOwnership<'_, '_>,
    boundary: u8,
    temporary_nonce: [u8; 16],
) -> Result<(OwnershipRequest, OwnershipReceiver), NativeEffectFailure> {
    let current = checked.current();
    let triple = checked.triple();
    if boundary > 4 || triple.root != current.observed().identity().root() {
        return Err(unknown("misbound native ownership boundary").into());
    }
    let mut operation = checked.operation().clone();
    if boundary == 4 {
        operation = operation
            .advance(DeletePhase::Invalidated, operation.current_lease.clone())
            .map_err(io::Error::other)?;
    }
    operation.encode().map_err(io::Error::other)?;
    let (target, expected, body) = if boundary == 0 {
        (
            triple.control.join(operation.authorization.operation_key()),
            None,
            operation.encode().map_err(io::Error::other)?,
        )
    } else if boundary == 4 {
        (
            triple.control.join(operation.authorization.operation_key()),
            Some(checked.operation().encode().map_err(io::Error::other)?),
            operation.encode().map_err(io::Error::other)?,
        )
    } else {
        let version = &operation.authorization.artifacts[usize::from(boundary - 1)];
        let original = CreationJournal {
            key: version.key.clone(),
            nonce: version.nonce,
            state: JournalState::Committed {
                binding: version.binding.clone(),
                file_identity: version.file_identity.clone(),
            },
        };
        let owned = original
            .own(&operation.authorization)
            .map_err(io::Error::other)?;
        (
            journal_path(&triple.control, &version.key),
            Some(original.encode().map_err(io::Error::other)?),
            owned.encode().map_err(io::Error::other)?,
        )
    };
    let suffix: String = temporary_nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let temporary = target
        .parent()
        .ok_or_else(|| unknown("ownership destination parent"))?
        .join(format!(".terrane-tmp:{suffix}"));
    let (sender, receiver) = mpsc::channel();
    Ok((
        OwnershipRequest {
            triple: Arc::clone(&triple.hold),
            root: triple.root.clone(),
            control: triple.control.clone(),
            operation,
            boundary,
            target,
            temporary,
            expected,
            body,
            owner: current.observed().configured_operator_uid(),
            result: sender,
        },
        OwnershipReceiver(receiver),
    ))
}

fn opened_exact(
    worker: &Worker,
    path: PathBuf,
    bytes: &[u8],
    owner: u32,
) -> Result<Opened, NativeEffectFailure> {
    let read = worker.projection.exact(&path, Some(bytes))?;
    if !matches!(read.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == owner) {
        return Err(unknown("ownership record lacks exact protected preimage").into());
    }
    let observation = Observation::checked(&std::fs::symlink_metadata(&path)?)?;
    if read
        .metadata
        .is_none_or(|stamp| !stamp.same_incarnation(observation.stamp))
    {
        return Err(unknown("ownership record changed incarnation").into());
    }
    let mut opened = Opened::open(path, observation, FencePolicy::ProtectedRecord { owner })?;
    opened.exact(bytes)?;
    Ok(opened)
}

// A legitimately replaced owner journal has one fixed new body. Skipping that
// old preimage is allowed only while its actual same descriptor/name/body is
// checked independently here; every other retained physical input stays exact.
fn check_boundary(
    worker: &Worker,
    state: &mut PairState,
    request: &OwnershipRequest,
    staged: &mut File,
    stamp: MetadataStamp,
    renamed: bool,
) -> Result<(), NativeEffectFailure> {
    let changed = if renamed {
        vec![request.temporary.as_path(), request.target.as_path()]
    } else {
        vec![request.temporary.as_path()]
    };
    worker.refresh(&changed)?;
    let replaced = renamed && (1..=3).contains(&request.boundary);
    for directory in &state.directories {
        directory.check()?;
    }
    if let Some(directories) = &state.projection.directories {
        for directory in directories.iter() {
            directory.check()?;
        }
    }
    for name in &state.projection.names {
        if !(replaced && name.path == request.target) {
            name.check(&state.projection.exclusions)?;
        }
    }
    for read in &state.projection.preimages {
        if !(replaced && read.path == request.target) {
            read.check()?;
        }
    }
    state.pack.check()?;
    state.index.check()?;
    state.trash.check()?;
    state.index.exact(&state.index_bytes)?;
    state.trash.exact(&state.trash_bytes)?;
    for (journal, bytes) in state.journals.iter_mut().zip(&state.journal_bytes) {
        if !(replaced && journal.path == request.target) {
            journal.check()?;
            journal.exact(bytes)?;
        }
    }
    let named = if renamed {
        &request.target
    } else {
        &request.temporary
    };
    checked_protected(staged, named, stamp, &request.body, request.owner)?;
    if renamed {
        absent_name(&request.temporary)?;
    }
    worker.refresh(&changed)?;
    state.pack.check()?;
    state.index.check()?;
    state.trash.check()?;
    Ok(())
}

// The pre-syscall check must run after the native test handoff as well. The
// generic Worker changed slice checks current authority but deliberately skips
// the fixed replacement; this closed callback checks that replacement and triple.
fn directory_sync(
    worker: &mut Worker,
    directory: &NativeOpenedDirectory,
    changed: &[&Path],
    mut check: impl FnMut(&Worker) -> Result<(), NativeEffectFailure>,
) -> Result<(), NativeEffectFailure> {
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::BeforeDirectorySync)?;
    worker.refresh(changed)?;
    check(worker)?;
    directory.check()?;
    #[cfg(test)]
    if worker.faults.contains(&EffectFault::BeforeDirectorySync)
        || worker
            .faults
            .contains(&EffectFault::BeforeDirectorySyncAt(directory.path.clone()))
    {
        return Err(io::Error::other("injected creation directory sync failure").into());
    }
    directory.file.sync_all()?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::AfterDirectorySync)?;
    worker.refresh(changed)?;
    check(worker)?;
    directory.check()?;
    #[cfg(test)]
    if worker
        .faults
        .contains(&EffectFault::AfterDirectorySyncAt(directory.path.clone()))
    {
        return Err(io::Error::other("injected creation failure after directory sync").into());
    }
    Ok(())
}

/// Verifies and synchronizes one exact operation and its monotone owner prefix.
///
/// # Errors
/// Refuses changed artifacts, stale boundary order, current checks or actual durability.
pub(in super::super) fn execute(
    request: OwnershipRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    #[cfg(all(test, feature = "std"))]
    let mut cost = super::super::retirement_barrier::cost_trace::Trace::new(
        "ownership-worker",
        Some(request.boundary),
    );
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    worker.refresh(&[])?;
    #[cfg(all(test, feature = "std"))]
    cost.mark("first-refresh-complete");
    let mut state = request
        .triple
        .state
        .lock()
        .map_err(|_| unknown("triple lock poisoned"))?;
    let expected = state.acknowledged.map_or(0, |prior| prior + 1);
    if request.boundary != expected {
        return Err(unknown("ownership acknowledgment is out of order").into());
    }
    state.recheck()?;
    #[cfg(all(test, feature = "std"))]
    cost.mark("first-pair-check-complete");
    let original = worker
        .projection
        .exact(&request.target, request.expected.as_deref())?;
    if !matches!(original.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == request.owner)
    {
        return Err(unknown("ownership destination lacks protected conditional preimage").into());
    }
    let directories = directories_below(original, &request.control, request.owner, true)?;
    #[cfg(all(test, feature = "std"))]
    {
        cost.inventory(0, worker.projection.preimages.len(), 0, directories.len());
        cost.mark("directories-complete");
    }
    let staging = worker.projection.exact(&request.temporary, None)?;
    if !matches!(staging.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == request.owner)
        || staging.identity.is_some()
        || staging.metadata.is_some()
    {
        return Err(unknown("ownership staging lacks protected absence").into());
    }
    let mut staged = create_staging(&request.temporary)?;
    let changed = [request.temporary.as_path()];
    worker.refresh(&changed)?;
    state.recheck()?;
    staged.write_all(&request.body)?;
    worker.refresh(&changed)?;
    state.recheck()?;
    let stamp = MetadataStamp::checked(&staged.metadata()?)?;
    checked_protected(
        &mut staged,
        &request.temporary,
        stamp,
        &request.body,
        request.owner,
    )?;
    check_boundary(&worker, &mut state, &request, &mut staged, stamp, false)?;
    worker.file_sync(&staged, &changed)?;
    check_boundary(&worker, &mut state, &request, &mut staged, stamp, false)?;
    for directory in directories.iter().rev() {
        directory_sync(&mut worker, directory, &changed, |worker| {
            check_boundary(worker, &mut state, &request, &mut staged, stamp, false)
        })?;
    }
    worker.refresh(&changed)?;
    state.recheck()?;
    checked_protected(
        &mut staged,
        &request.temporary,
        stamp,
        &request.body,
        request.owner,
    )?;
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::BeforeOpen)?;
    worker.refresh(&changed)?;
    state.recheck()?;
    check_boundary(&worker, &mut state, &request, &mut staged, stamp, false)?;
    if request.expected.is_some() {
        std::fs::rename(&request.temporary, &request.target)?;
    } else {
        super::super::super::atomic_rename_no_replace(&request.temporary, &request.target)?;
    }
    #[cfg(all(test, feature = "tokio"))]
    wait_test_gate(&mut worker.gates, TestGatePhase::AfterRename)?;
    let changed = [request.temporary.as_path(), request.target.as_path()];
    worker.refresh(&changed)?;
    absent_name(&request.temporary)?;
    checked_protected(
        &mut staged,
        &request.target,
        stamp,
        &request.body,
        request.owner,
    )?;
    for directory in directories.iter().rev() {
        directory_sync(&mut worker, directory, &changed, |worker| {
            check_boundary(worker, &mut state, &request, &mut staged, stamp, true)
        })?;
    }
    worker.refresh(&changed)?;
    checked_protected(
        &mut staged,
        &request.target,
        stamp,
        &request.body,
        request.owner,
    )?;
    let operation_path = request
        .control
        .join(request.operation.authorization.operation_key());
    let operation_bytes = request.operation.encode().map_err(io::Error::other)?;
    let operation = if operation_path == request.target {
        let mut opened = Opened::open(
            operation_path,
            Observation::checked(&staged.metadata()?)?,
            FencePolicy::ProtectedRecord {
                owner: request.owner,
            },
        )?;
        opened.exact(&operation_bytes)?;
        opened
    } else {
        opened_exact(&worker, operation_path, &operation_bytes, request.owner)?
    };
    check_boundary(&worker, &mut state, &request, &mut staged, stamp, true)?;
    operation.check()?;
    worker.file_sync(&operation.file, &changed)?;
    check_boundary(&worker, &mut state, &request, &mut staged, stamp, true)?;
    operation.check()?;

    let prefix = usize::from(request.boundary.min(3));
    let mut journals = Vec::with_capacity(3);
    for index in 0..3 {
        let version = &request.operation.authorization.artifacts[index];
        let actual = match index {
            0 => &state.pack,
            1 => &state.index,
            _ => &state.trash,
        };
        actual.check()?;
        if version.file_identity != native_identity(actual.observation).to_vec() {
            return Err(unknown("owned version changed actual artifact").into());
        }
        let original = CreationJournal {
            key: version.key.clone(),
            nonce: version.nonce,
            state: JournalState::Committed {
                binding: version.binding.clone(),
                file_identity: version.file_identity.clone(),
            },
        };
        let journal = if index < prefix {
            original
                .own(&request.operation.authorization)
                .map_err(io::Error::other)?
        } else {
            original
        };
        let bytes = journal.encode().map_err(io::Error::other)?;
        let path = journal_path(&request.control, &version.key);
        let opened = if path == request.target {
            let mut opened = Opened::open(
                path.clone(),
                Observation::checked(&staged.metadata()?)?,
                FencePolicy::ProtectedRecord {
                    owner: request.owner,
                },
            )?;
            opened.exact(&bytes)?;
            opened
        } else {
            opened_exact(&worker, path.clone(), &bytes, request.owner)?
        };
        check_boundary(&worker, &mut state, &request, &mut staged, stamp, true)?;
        opened.check()?;
        worker.file_sync(&opened.file, &changed)?;
        check_boundary(&worker, &mut state, &request, &mut staged, stamp, true)?;
        opened.check()?;
        journals.push((opened, bytes));
    }
    // Refresh retained journal bodies only after every exact durable sync succeeds.
    for (index, (opened, bytes)) in journals.into_iter().enumerate() {
        let path = &opened.path;
        state.projection.preimages.retain(|read| &read.path != path);
        state.projection.names.retain(|name| &name.path != path);
        state.journals[index] = opened;
        state.journal_bytes[index] = bytes;
    }
    state.recheck()?;
    worker.refresh(&changed)?;
    checked_protected(
        &mut staged,
        &request.target,
        stamp,
        &request.body,
        request.owner,
    )?;
    operation.check()?;
    state.acknowledged = Some(request.boundary);
    let _ = request.result.send(());
    #[cfg(all(test, feature = "std"))]
    cost.complete();
    Ok(())
}
