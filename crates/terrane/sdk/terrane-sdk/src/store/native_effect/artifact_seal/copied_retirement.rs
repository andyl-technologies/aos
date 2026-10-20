//! Executes genuine copied preparation and NEW-barrier observation mechanics.
//!
//! Native channels begin empty and only successful executor paths populate them.
//! Preparation durability precedes creation of Trash; barrier timing starts after
//! actual committed-journal synchronization. These phases never physically delete
//! a pack or grant copied DATA permission from decoded record claims.

#[path = "copied_retirement/barrier.rs"]
mod barrier;
#[path = "copied_retirement/placement.rs"]
mod placement;
#[path = "copied_retirement/publication.rs"]
mod publication;

#[cfg(all(test, feature = "tokio"))]
use super::Path;
use super::{FencePolicy, NativeEffectFailure, Plan, Worker};
use crate::bucket::publication::receipts::RecordRead;
use crate::guard::RetainedControls;
use crate::selected_bridge::native_copied_retirement::{CheckedOwnership, CheckedPreparation};
use crate::store::{Clock, NativeEffectClock};
use barrier::BarrierHold;
use placement::{Placement, PlacementInput};
use publication::{ImmutablePublicationHold, SelectedPublication};
#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;
use std::{io, path::PathBuf, sync::mpsc};
use terrane_format::gc::publication::{PublicationCommit, PublicationTransaction};
use terrane_format::gc::retirement::{
    CopiedRetirementPreparation, LocalBarrierArtifact, OwnershipSlot,
};

/// Fixes genuine selected preparation inputs without a caller-built ACK.
pub(in super::super) struct PreparationRequest {
    publication: SelectedPublication,
    placement: Vec<PlacementInput>,
    checkpoints: Vec<(PathBuf, Vec<u8>, bool)>,
    root: PathBuf,
    control: PathBuf,
    owner: u32,
    preparation: CopiedRetirementPreparation,
    slot: OwnershipSlot,
    clock: NativeEffectClock,
    controls: Vec<RetainedControls>,
    guard: RecordRead,
    namespace_identity: ((u64, u64), (u64, u64)),
    control_identity: (u64, u64),
    result: mpsc::Sender<NativePreparation>,
}

impl PreparationRequest {
    /// Borrows the actual selecting slot for native fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &Path {
        self.publication.path()
    }
}

struct PreparationHold {
    root: PathBuf,
    control: PathBuf,
    owner: u32,
    preparation: CopiedRetirementPreparation,
    slot: OwnershipSlot,
    clock: NativeEffectClock,
    controls: Vec<RetainedControls>,
    guard: RecordRead,
    immutable: ImmutablePublicationHold,
    namespace_identity: ((u64, u64), (u64, u64)),
    control_identity: (u64, u64),
}

/// Retains an executor-produced genuine preparation durability acknowledgment.
pub(in super::super) struct NativePreparation {
    held: Shared<PreparationHold>,
}

impl NativePreparation {
    /// Borrows the actual selected immutable preparation plan.
    pub(in super::super) fn preparation(&self) -> &CopiedRetirementPreparation {
        &self.held.preparation
    }

    /// Returns the actual acknowledged selecting slot association.
    pub(in super::super) fn slot(&self) -> OwnershipSlot {
        self.held.slot
    }
}

/// Receives only a completed genuine native preparation acknowledgment.
pub(in super::super) struct PreparationReceiver {
    result: mpsc::Receiver<NativePreparation>,
}

impl PreparationReceiver {
    /// Consumes actual successful native completion.
    ///
    /// # Errors
    /// Refuses an unexecuted, failed or no-op native request.
    pub(in super::super) fn take(self) -> Result<NativePreparation, NativeEffectFailure> {
        self.result
            .try_recv()
            .map_err(|_| io::Error::other("native copied preparation ACK unavailable").into())
    }
}

/// Builds a request only from the actual closed destination preparation carrier.
///
/// # Errors
/// Refuses inconsistent selected slot/transaction/snapshot, replacement of the
/// checked whole preparation/state/changes, or missing actual configured control.
pub(in super::super) fn preparation_plan(
    checked: &CheckedPreparation<'_, '_>,
    slot: &PublicationCommit,
    transaction: &PublicationTransaction,
    snapshot: &[u8],
) -> Result<(Plan, PreparationReceiver), NativeEffectFailure> {
    let data = checked.data().data();
    checked
        .preparation()
        .plan
        .check_key(checked.key())
        .map_err(io::Error::other)?;
    if transaction.old.as_ref() != Some(data.observed().state())
        || &transaction.new != checked.next()
        || transaction.changes != checked.changes()
        || !matches!(
            transaction.proof,
            terrane_format::gc::publication::PublicationProof::Raw
        )
    {
        return Err(io::Error::other("copied preparation producer association differs").into());
    }
    let registration = data
        .observed()
        .physical_reads()
        .first()
        .ok_or_else(|| io::Error::other("copied preparation registration absent"))?;
    let control = registration
        .path()
        .parent()
        .ok_or_else(|| io::Error::other("copied preparation control boundary absent"))?
        .to_path_buf();
    if registration.path() != control.join("backend-registration.cbor") {
        return Err(io::Error::other("copied preparation configured registration differs").into());
    }
    let root = data.observed().identity().root().to_path_buf();
    let owner = data.observed().configured_operator_uid();
    let publication = SelectedPublication::observed(
        root.clone(),
        control.clone(),
        owner,
        slot,
        transaction,
        snapshot,
    )?;
    let slot = OwnershipSlot {
        revision: slot.revision,
        digest: *blake3::hash(&slot.encode().map_err(io::Error::other)?).as_bytes(),
    };
    let (sender, receiver) = mpsc::channel();
    let artifacts = checked.artifacts();
    let mut checkpoints: Vec<_> = [
        (artifacts.roots(), false),
        (artifacts.marks(), false),
        (artifacts.fence(), true),
    ]
    .into_iter()
    .map(|((pointer, bytes), protected)| {
        let boundary = if protected { &control } else { &root };
        (boundary.join(&pointer.key), bytes.to_vec(), protected)
    })
    .collect();
    checkpoints.extend(
        artifacts
            .checkpoints()
            .iter()
            .map(|(pointer, bytes)| (root.join(&pointer.key), bytes.clone(), false)),
    );
    Ok((
        Plan::SealCopiedPreparation(Box::new(PreparationRequest {
            publication,
            placement: data.packs().iter().map(PlacementInput::observed).collect(),
            checkpoints,
            root,
            control,
            owner,
            preparation: checked.preparation().clone(),
            slot,
            clock: data
                .session()
                .clock()
                .map_err(NativeEffectFailure::Rejected)?,
            controls: data.effects().controls().to_vec(),
            guard: data.guard().clone(),
            namespace_identity: data.observed().identity().physical_identity(),
            control_identity: data.observed().control_identity(),
            result: sender,
        })),
        PreparationReceiver { result: receiver },
    ))
}

/// Executes real descriptor synchronization before acknowledging preparation.
///
/// # Errors
/// Refuses changed complete selected inputs, actual eligible DATA placement or
/// failed native file/directory synchronization.
pub(super) fn execute_preparation(
    request: PreparationRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    request.publication.check(&worker)?;
    let check_checkpoints = |worker: &Worker| -> Result<(), NativeEffectFailure> {
        for (path, bytes, protected) in &request.checkpoints {
            let read = worker.projection.exact(path, Some(bytes))?;
            let correct = if *protected {
                matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner)
            } else {
                matches!(read.policy, FencePolicy::Payload { owner } if owner == request.owner)
            };
            if !correct {
                return Err(io::Error::other("copied checkpoint actual policy differs").into());
            }
        }
        worker.refresh(&[])
    };
    check_checkpoints(&worker)?;
    let placements: Vec<_> = request
        .placement
        .iter()
        .map(|input| Placement::open(input, &request.root, request.owner))
        .collect::<io::Result<_>>()?;
    for placement in &placements {
        placement.synchronize(&mut worker)?;
    }
    request.publication.synchronize(&mut worker)?;
    for placement in &placements {
        placement.check()?;
    }
    request.publication.check(&worker)?;
    check_checkpoints(&worker)?;
    let immutable = request
        .publication
        .retain_immutable(&request.checkpoints, &worker)?;
    let acknowledgment = NativePreparation {
        held: Shared::new(PreparationHold {
            root: request.root,
            control: request.control,
            owner: request.owner,
            preparation: request.preparation,
            slot: request.slot,
            clock: request.clock,
            controls: request.controls,
            guard: request.guard,
            immutable,
            namespace_identity: request.namespace_identity,
            control_identity: request.control_identity,
        }),
    };
    let _ = request.result.send(acknowledgment);
    Ok(())
}

/// Fixes NEW barrier observation after an executor-acknowledged preparation.
pub(in super::super) struct BarrierRequest {
    preparation: Shared<PreparationHold>,
    artifact: LocalBarrierArtifact,
    clock: NativeEffectClock,
    #[cfg(all(test, feature = "tokio"))]
    path: PathBuf,
    result: mpsc::Sender<NativeBarrier>,
}

impl BarrierRequest {
    /// Borrows the actual NEW Trash name for native fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &Path {
        &self.path
    }
}

/// Receives only actual completed NEW barrier descriptor observation.
pub(in super::super) struct BarrierReceiver {
    result: mpsc::Receiver<NativeBarrier>,
}

/// Retains a genuine observed NEW barrier and its actual acknowledged preparation.
///
/// Private fields prevent substituting decoded journal claims or caller elapsed
/// values. This observation alone is not first-ownership authorization.
pub(crate) struct NativeBarrier {
    preparation: Shared<PreparationHold>,
    barrier: Shared<BarrierHold>,
}

impl NativeBarrier {
    /// Retains only the executor-produced immutable preparation and barrier.
    pub(crate) fn retain(&self) -> Self {
        Self {
            preparation: Shared::clone(&self.preparation),
            barrier: Shared::clone(&self.barrier),
        }
    }

    /// Borrows the actual acknowledged immutable preparation.
    pub(crate) fn preparation(&self) -> &CopiedRetirementPreparation {
        &self.preparation.preparation
    }

    /// Returns the actual selecting preparation slot.
    pub(crate) fn slot(&self) -> OwnershipSlot {
        self.preparation.slot
    }

    /// Borrows the native-observed actual committed barrier association.
    pub(crate) fn artifact(&self) -> &LocalBarrierArtifact {
        self.barrier.artifact()
    }

    /// Borrows the genuinely retained original destination controls across waiting.
    pub(crate) fn controls(&self) -> &[RetainedControls] {
        &self.preparation.controls
    }

    /// Borrows the original actual protected Guard record observation.
    pub(crate) fn guard(&self) -> &RecordRead {
        &self.preparation.guard
    }

    /// Returns original actual namespace and coordination incarnations.
    pub(crate) fn namespace_identity(&self) -> ((u64, u64), (u64, u64)) {
        self.preparation.namespace_identity
    }

    /// Returns the actual protected destination backend-control incarnation.
    pub(crate) fn control_identity(&self) -> (u64, u64) {
        self.preparation.control_identity
    }

    /// Measures actual elapsed time on the retained preparing Session clock.
    ///
    /// # Errors
    /// Refuses descriptor/journal discontinuity, poisoned observation or clock
    /// regression. Complete current Session/Guard checks remain separate.
    pub(crate) fn elapsed(&self) -> Result<std::time::Duration, NativeEffectFailure> {
        self.preparation.immutable.check()?;
        self.barrier.elapsed().map_err(Into::into)
    }

    /// Waits on the same genuine preparing clock with continuity checks.
    ///
    /// # Errors
    /// Refuses failed timing, replaced barrier/journal or clock regression.
    /// Actual current lease renewal and complete final qualification remain
    /// separate; sleeping never produces an ownership acknowledgment.
    pub(crate) async fn sleep(
        &self,
        duration: std::time::Duration,
    ) -> Result<(), NativeEffectFailure> {
        self.barrier.sleep(duration).await.map_err(Into::into)
    }
}

impl BarrierReceiver {
    /// Consumes only actual successful native barrier observation.
    ///
    /// # Errors
    /// Refuses an unexecuted, failed or no-op native request.
    pub(in super::super) fn take(self) -> Result<NativeBarrier, NativeEffectFailure> {
        self.result
            .try_recv()
            .map_err(|_| io::Error::other("native copied NEW barrier ACK unavailable").into())
    }
}

/// Builds the NEW observation request from genuine preparation completion.
///
/// # Errors
/// Refuses a different zero-removal Trash body or destination barrier key.
pub(in super::super) fn barrier_plan(
    preparation: &NativePreparation,
    artifact: LocalBarrierArtifact,
) -> Result<(Plan, BarrierReceiver), NativeEffectFailure> {
    let plan = &preparation.held.preparation.plan;
    if artifact.tombstone != plan.tombstone
        || artifact.key
            != format!(
                "trash/{}/{}",
                plan.exclusion.cycle,
                crate::pack::PackId::from_random_bytes(plan.exclusion.pack)
            )
    {
        return Err(
            io::Error::other("copied NEW barrier differs from acknowledged preparation").into(),
        );
    }
    let (sender, receiver) = mpsc::channel();
    let clock = preparation.held.clock.retain_native_clock()?;
    if preparation.slot().revision <= preparation.preparation().plan.genesis.revision {
        return Err(io::Error::other("copied preparation does not follow actual genesis").into());
    }
    #[cfg(all(test, feature = "tokio"))]
    let path = preparation.held.root.join(&artifact.key);
    Ok((
        Plan::ObserveCopiedBarrier(Box::new(BarrierRequest {
            preparation: Shared::clone(&preparation.held),
            artifact,
            clock,
            #[cfg(all(test, feature = "tokio"))]
            path,
            result: sender,
        })),
        BarrierReceiver { result: receiver },
    ))
}

/// Observes actual committed descriptors and starts a fresh same-clock wait.
///
/// # Errors
/// Refuses changed current controls, actual journal/Trash association or native
/// synchronization failures. No deletion dispatch is performed.
pub(super) fn execute_barrier(
    request: BarrierRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    let held = &request.preparation;
    held.immutable.check()?;
    let barrier = BarrierHold::observe(
        &held.root,
        &held.control,
        held.owner,
        request.artifact,
        request.clock,
        &mut worker,
    )?;
    held.immutable.check()?;
    let _ = request.result.send(NativeBarrier {
        preparation: request.preparation,
        barrier: Shared::new(barrier),
    });
    Ok(())
}

/// Fixes complete current first-owner inputs and genuine retained barrier age.
pub(in super::super) struct OwnershipRequest {
    publication: SelectedPublication,
    placement: Vec<PlacementInput>,
    checkpoints: Vec<(PathBuf, Vec<u8>, bool)>,
    root: PathBuf,
    owner: u32,
    barrier: NativeBarrier,
    authorization: terrane_format::gc::retirement::CopiedRetirementAuthorization,
    result: mpsc::Sender<DurableOwnership>,
}

impl OwnershipRequest {
    /// Borrows the actual winning selecting slot for native fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &Path {
        self.publication.path()
    }
}

struct DurableOwnership {
    _private: (),
}

/// Receives only a genuine completed first-owner publication acknowledgment.
pub(in super::super) struct OwnershipReceiver {
    result: mpsc::Receiver<DurableOwnership>,
}

impl OwnershipReceiver {
    /// Consumes actual successful native first-owner completion.
    ///
    /// # Errors
    /// Refuses unexecuted, failed or no-op native ownership requests.
    pub(in super::super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result
            .try_recv()
            .map(|_| ())
            .map_err(|_| io::Error::other("native copied first-owner ACK unavailable").into())
    }
}

/// Builds a request only from the closed genuine final ownership producer.
///
/// # Errors
/// Refuses different whole selected inputs, nonempty carried lineage, inconsistent
/// canonical authorization, another actual destination registration or malformed
/// final slot/transaction/snapshot association.
pub(in super::super) fn ownership_plan(
    checked: &CheckedOwnership<'_, '_>,
    slot: &PublicationCommit,
    transaction: &PublicationTransaction,
    snapshot: &[u8],
) -> Result<(Plan, OwnershipReceiver), NativeEffectFailure> {
    use terrane_format::gc::publication::PublicationProof;
    use terrane_format::gc::retirement::PermanentDeleteAuthorization;
    let data = checked.data().data();
    let PermanentDeleteAuthorization::Copied(authorization) = &checked.operation().authorization
    else {
        return Err(io::Error::other("first-owner request is not copied qualification").into());
    };
    checked
        .operation()
        .authorization
        .check_key(checked.key())
        .map_err(io::Error::other)?;
    let authorization_bytes = checked
        .operation()
        .authorization
        .encode()
        .map_err(io::Error::other)?;
    if transaction.old.as_ref() != Some(data.observed().state())
        || &transaction.new != checked.next()
        || transaction.changes != checked.changes()
        || !matches!(&transaction.proof, PublicationProof::PermanentRetirement {
            authorization, carried,
        } if authorization == &authorization_bytes && carried.is_empty())
    {
        return Err(io::Error::other("first-owner closed producer association differs").into());
    }
    let registration = data
        .observed()
        .physical_reads()
        .first()
        .ok_or_else(|| io::Error::other("first-owner registration absent"))?;
    let control = registration
        .path()
        .parent()
        .ok_or_else(|| io::Error::other("first-owner control boundary absent"))?
        .to_path_buf();
    if registration.path() != control.join("backend-registration.cbor") {
        return Err(io::Error::other("first-owner registration path differs").into());
    }
    let root = data.observed().identity().root().to_path_buf();
    let owner = data.observed().configured_operator_uid();
    let publication = SelectedPublication::observed(
        root.clone(),
        control.clone(),
        owner,
        slot,
        transaction,
        snapshot,
    )?;
    let artifacts = checked.artifacts();
    let mut checkpoints: Vec<_> = [
        (artifacts.roots(), false),
        (artifacts.marks(), false),
        (artifacts.fence(), true),
    ]
    .into_iter()
    .map(|((pointer, bytes), protected)| {
        (
            (if protected { &control } else { &root }).join(&pointer.key),
            bytes.to_vec(),
            protected,
        )
    })
    .collect();
    checkpoints.extend(
        artifacts
            .checkpoints()
            .iter()
            .map(|(pointer, bytes)| (root.join(&pointer.key), bytes.clone(), false)),
    );
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::SealCopiedOwnership(Box::new(OwnershipRequest {
            publication,
            placement: data.packs().iter().map(PlacementInput::observed).collect(),
            checkpoints,
            root,
            owner,
            barrier: checked.barrier().retain(),
            authorization: authorization.clone(),
            result: sender,
        })),
        OwnershipReceiver { result: receiver },
    ))
}

/// Synchronizes actual final current checkpoints and selected owner before ACK.
///
/// # Errors
/// Refuses incomplete or changed current DATA, stale whole lease/Guard/control
/// Frame, discontinuous barrier, missing full genuine G/D or native sync failure.
pub(super) fn execute_ownership(
    request: OwnershipRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    let check = |worker: &Worker| -> Result<(), NativeEffectFailure> {
        request.publication.check(worker)?;
        let elapsed = request.barrier.elapsed()?.as_nanos();
        if elapsed < u128::from(request.authorization.grace_elapsed_nanos)
            || elapsed < u128::from(request.authorization.deletion_elapsed_nanos)
        {
            return Err(
                io::Error::other("first-owner actual barrier elapsed bound differs").into(),
            );
        }
        request
            .authorization
            .check_preparation(request.barrier.preparation(), &request.barrier.slot())
            .map_err(io::Error::other)?;
        for (path, bytes, protected) in &request.checkpoints {
            let read = worker.projection.exact(path, Some(bytes))?;
            let correct = if *protected {
                matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner)
            } else {
                matches!(read.policy, FencePolicy::Payload { owner } if owner == request.owner)
            };
            if !correct {
                return Err(io::Error::other("first-owner checkpoint policy differs").into());
            }
        }
        worker.refresh(&[])
    };
    check(&worker)?;
    let placements: Vec<_> = request
        .placement
        .iter()
        .map(|input| Placement::open(input, &request.root, request.owner))
        .collect::<io::Result<_>>()?;
    for placement in &placements {
        placement.synchronize(&mut worker)?;
    }
    check(&worker)?;
    request.publication.synchronize(&mut worker)?;
    for placement in &placements {
        placement.check()?;
    }
    check(&worker)?;
    let _ = request.result.send(DurableOwnership { _private: () });
    Ok(())
}
