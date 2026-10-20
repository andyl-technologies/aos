//! Unlinks one selected Planned family instance under fresh complete current checks.
//!
//! A failure after unlink leaves the selected Planned duty unresolved. A native
//! absence receipt exists only after actual parent synchronization and final
//! current checks; it never ends permanent ownership or covers a late instance.

use super::super::{
    MetadataStamp, NamedFence, NativeEffectFailure, NativeOpenedDirectory, ParentFence, Path,
    PathBuf, Plan, Worker, open_native,
};
use super::NativePermanentObservation;
use crate::selected_bridge::native_permanent_local::CheckedPermanentReclaim;
use std::io;
use std::sync::{Arc, mpsc};
use terrane_format::gc::retirement::{ObservedArtifact, PermanentDeleteOperation};

/// Fixes one selected target and actual independently opened observation.
pub(in super::super::super) struct ReclaimRequest {
    observed: Arc<NativePermanentObservation>,
    index: usize,
    target: PathBuf,
    pass_path: PathBuf,
    pass_bytes: Vec<u8>,
    operation_bytes: Vec<u8>,
    result: mpsc::Sender<NativeReclaimReceipt>,
}

impl ReclaimRequest {
    /// Borrows the actual fixed family destination for native test fault probes.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super::super) fn path(&self) -> &Path {
        &self.target
    }
}

/// Records actual synchronized absence without universal or terminal ownership claims.
pub(crate) struct NativeReclaimReceipt {
    target: PathBuf,
    _exclusions: Arc<[super::super::NativeExclusion]>,
}

impl NativeReclaimReceipt {
    /// Borrows the actual synchronized family key, not future deletion authority.
    pub(crate) fn path(&self) -> &Path {
        &self.target
    }
}

/// Receives only actual synchronized native absence.
pub(in super::super::super) struct ReclaimReceiver(mpsc::Receiver<NativeReclaimReceipt>);

impl ReclaimReceiver {
    /// Takes actual native completion once, refusing fabricated unit success.
    ///
    /// # Errors
    /// Refuses failed, canceled, disconnected or unexecuted native requests.
    pub(in super::super::super) fn take(self) -> Result<NativeReclaimReceipt, NativeEffectFailure> {
        self.0
            .try_recv()
            .map_err(|_| io::Error::other("permanent reclaim receipt absent").into())
    }
}

/// Fixes one real observed instance from the selected current Planned request.
///
/// # Errors
/// Refuses foreign namespaces, owner associations, missing native instances or
/// current selected operation/pass disagreement.
pub(in super::super::super) fn plan(
    checked: &CheckedPermanentReclaim<'_, '_, '_>,
    observed: Arc<NativePermanentObservation>,
) -> Result<(Plan, ReclaimReceiver), NativeEffectFailure> {
    let owner = checked.current().owner();
    let operation =
        PermanentDeleteOperation::decode(&observed.operation_bytes).map_err(io::Error::other)?;
    if observed.root != owner.observed().identity().root()
        || observed.control != owner.backend_control()
        || observed.pack != owner.pack()
        || observed.operation_key != owner.key()
        || &operation.authorization != owner.authorization()
    {
        return Err(io::Error::other("permanent reclaim observation association changed").into());
    }
    let id = crate::pack::PackId::from_random_bytes(owner.pack());
    let key = match checked.artifact() {
        ObservedArtifact::Pack => id.pack_key(),
        ObservedArtifact::Index => id.index_key(),
        ObservedArtifact::Trash(cycle) => format!("trash/{cycle}/{id}"),
    };
    let target = observed.root.join(key);
    let index = observed
        .leaves
        .iter()
        .position(|leaf| leaf.path() == target)
        .ok_or_else(|| io::Error::other("permanent request lacks actual target observation"))?;
    observed.leaves[index].check(&observed.exclusions)?;
    let operation_bytes = owner
        .observed()
        .logical()
        .get(owner.key())
        .and_then(Option::as_ref)
        .ok_or_else(|| io::Error::other("permanent current operation absent"))?
        .clone();
    let (result, receiver) = mpsc::channel();
    Ok((
        Plan::ReclaimPermanentLocal(Box::new(ReclaimRequest {
            pass_path: observed.control.join(checked.key()),
            observed,
            index,
            target,
            pass_bytes: checked.bytes().to_vec(),
            operation_bytes,
            result,
        })),
        ReclaimReceiver(receiver),
    ))
}

/// Opens the exact retained parent for reclaim or durable absence confirmation.
///
/// # Errors
/// Refuses missing retained ancestry, changed parent instances or unsafe metadata.
pub(super) fn parent(worker: &Worker, target: &Path) -> io::Result<NativeOpenedDirectory> {
    let path = target
        .parent()
        .ok_or_else(|| io::Error::other("permanent target lacks sync parent"))?;
    let fence = worker
        .projection
        .names
        .iter()
        .find(|name| name.path == path)
        .ok_or_else(|| io::Error::other("permanent sync parent is not retained"))?;
    parent_from_recipe(worker, target, fence)
}

/// Opens and freshly checks the original parent selected by a fixed recipe index.
///
/// # Errors
/// Refuses a recipe for another parent, changed instances or unsafe metadata.
pub(super) fn parent_from_recipe(
    worker: &Worker,
    target: &Path,
    fence: &NamedFence,
) -> io::Result<NativeOpenedDirectory> {
    let path = target
        .parent()
        .filter(|path| *path == fence.path)
        .ok_or_else(|| io::Error::other("permanent sync parent is not retained"))?;
    fence.check(&worker.projection.exclusions)?;
    let file = open_native(path, true)?;
    let stamp = MetadataStamp::checked(&file.metadata()?)?;
    if !stamp.same_incarnation(fence.stamp) {
        return Err(io::Error::other("permanent sync parent replaced"));
    }
    let directory = NativeOpenedDirectory {
        file: Arc::new(file),
        path: path.to_owned(),
        stamp,
        policy: fence.policy,
        parents: fence
            .parents
            .iter()
            .map(|parent| ParentFence {
                path: parent.path.clone(),
                stamp: parent.stamp,
            })
            .collect(),
    };
    directory.check()?;
    Ok(directory)
}

/// Completes one actual unlink and parent sync under retained current exclusions.
///
/// # Errors
/// Refuses stale planned evidence, consumed-target conflicts, changed physical
/// instances, expired/current authority, unlink failures or incomplete durability.
pub(in super::super) fn execute(
    request: ReclaimRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    let observed = &request.observed;
    let operation_path = observed.control.join(&observed.operation_key);
    worker
        .projection
        .exact(&operation_path, Some(&request.operation_bytes))?;
    worker
        .projection
        .exact(&request.pass_path, Some(&request.pass_bytes))?;
    // An owned residue cannot also be a consumed serving/control input. Refuse
    // rather than skipping such a predicate after the irreversible syscall.
    if worker
        .projection
        .preimages
        .iter()
        .any(|read| read.path == request.target)
        || worker
            .projection
            .names
            .iter()
            .any(|name| name.path == request.target)
    {
        return Err(
            io::Error::other("permanent target conflicts with retained current input").into(),
        );
    }
    worker.refresh(&[])?;
    let leaf = observed
        .leaves
        .get(request.index)
        .ok_or_else(|| io::Error::other("permanent target observation missing"))?;
    let directory = parent(&worker, leaf.checked_path())?;
    #[cfg(all(test, feature = "tokio"))]
    super::super::wait_test_gate(&mut worker.gates, super::super::TestGatePhase::BeforeOpen)?;
    worker.refresh(&[])?;
    leaf.check(&worker.projection.exclusions)?;
    #[cfg(all(test, feature = "tokio"))]
    if worker
        .faults
        .contains(&super::super::EffectFault::BeforeUnlink)
    {
        return Err(io::Error::other("injected permanent unlink failure").into());
    }
    if leaf.is_present() {
        std::fs::remove_file(&request.target)?;
    }
    #[cfg(all(test, feature = "tokio"))]
    if worker
        .faults
        .contains(&super::super::EffectFault::AfterUnlink)
    {
        return Err(io::Error::other("injected failure after permanent unlink").into());
    }
    leaf.check_removed()?;
    worker.refresh(&[])?;
    worker.directory_sync(&directory, false, &[])?;
    leaf.check_removed()?;
    worker.refresh(&[])?;
    let _ = request.result.send(NativeReclaimReceipt {
        target: request.target,
        _exclusions: Arc::clone(&worker.projection.exclusions),
    });
    Ok(())
}
