//! Qualifies final copied ownership from fresh DATA and real barrier continuity.
//!
//! Current checkpoint cycles remain separate from the immutable barrier cycle
//! (D-115). New roots never overwrite prior CreateOnce snapshots. No decoded
//! elapsed value, source Original or carried lineage substitutes for this check.

use super::refusal;
use crate::bucket::BucketBinding;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::receipts::RecordRead;
use crate::gc::runner::session::Session;
use crate::selected_bridge::native_copied_placement::{CheckedCopiedPlacement, PlacementArtifacts};
use crate::store::native_publication_effects::collection_copied_retirement::NativeBarrier;
use crate::store::{
    Clock, ContentValidator, LocalFs, NativeEffectFailure, StoreErrorKind, StoreFailure,
};
use terrane_format::gc::publication::{
    LogicalChange, PermanentBurnOwner, PermanentOwnerSelection, PublicationState,
};
use terrane_format::gc::retirement::{
    BarrierArtifact, CopiedRetirementAuthorization, OperationPhase, PermanentDeleteAuthorization,
    PermanentDeleteOperation, RecordPointer,
};

/// Retains exact final current DATA and a genuine native barrier observation.
pub(crate) struct CheckedOwnership<'operation, 'held> {
    data: CheckedCopiedPlacement<'operation, 'held>,
    artifacts: PlacementArtifacts,
    barrier: &'operation NativeBarrier,
    operation: PermanentDeleteOperation,
    key: String,
    next: PublicationState,
    changes: Vec<LogicalChange>,
}

impl<'operation, 'held> CheckedOwnership<'operation, 'held> {
    /// Borrows the actual independently checked current physical DATA.
    pub(crate) fn data(&self) -> &CheckedCopiedPlacement<'operation, 'held> {
        &self.data
    }

    /// Borrows fresh current physical checkpoints, distinct from barrier age.
    pub(crate) fn artifacts(&self) -> &PlacementArtifacts {
        &self.artifacts
    }

    /// Borrows the genuinely observed NEW immutable barrier.
    pub(crate) fn barrier(&self) -> &'operation NativeBarrier {
        self.barrier
    }

    /// Borrows the exact complete proposed permanent operation.
    pub(crate) fn operation(&self) -> &PermanentDeleteOperation {
        &self.operation
    }

    /// Borrows the immutable preparation/operation key.
    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    /// Borrows the whole final successor preserving all unrelated selected state.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows exact sorted whole logical compares and replacements.
    pub(crate) fn changes(&self) -> &[LogicalChange] {
        &self.changes
    }
}

fn native(error: NativeEffectFailure) -> StoreFailure {
    match error {
        NativeEffectFailure::Rejected(error) => error,
        NativeEffectFailure::Io(error) => {
            StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
        }
    }
}

fn same_guard(previous: &RecordRead, current: &RecordRead) -> Result<(), StoreFailure> {
    if previous.path() != current.path() || previous.bytes() != current.bytes() {
        return Err(refusal());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let before = previous.metadata().ok_or_else(refusal)?;
        let after = current.metadata().ok_or_else(refusal)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(refusal());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(refusal())
    }
}

/// Qualifies the exact final owner proposal without resetting valid barrier age.
///
/// # Errors
/// Refuses changed consumed Guard/Original incarnations, another preparation,
/// holder/epoch takeover, expired lease, incomplete current DATA/checkpoints,
/// failed barrier continuity or incomplete genuine same-clock G/D.
pub(crate) async fn authorize<'operation, 'held, F, B, V>(
    data: CheckedCopiedPlacement<'operation, 'held>,
    held: &HeldBucket<'_, F, B, V, true>,
    session: &'operation Session,
    barrier: &'operation NativeBarrier,
) -> Result<CheckedOwnership<'operation, 'held>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    let initial = barrier.preparation();
    let plan = &initial.plan;
    if !std::ptr::eq(data.data().session(), session)
        || data.data().pack() != plan.exclusion.pack
        || data.data().observed().state().binding != plan.backend
        || data.data().genesis() != &plan.genesis
        || session.lease().holder != plan.lease.holder
        || session.lease().epoch != plan.lease.epoch
        || session.lease().expiry < plan.lease.expiry
        || data.data().observed().identity().physical_identity() != barrier.namespace_identity()
        || data.data().observed().control_identity() != barrier.control_identity()
    {
        return Err(refusal());
    }
    same_guard(barrier.guard(), data.data().guard())?;
    let current_controls = data.data().effects().controls();
    if current_controls.len() != barrier.controls().len() {
        return Err(refusal());
    }
    for (before, after) in barrier.controls().iter().zip(current_controls) {
        if before.directory() != after.directory()
            || before.owner() != after.owner()
            || before.identities() != after.identities()
            || before.records().len() != after.records().len()
            || before.ancestors() != after.ancestors()
            || before
                .records()
                .iter()
                .zip(after.records())
                .any(|(before, after)| {
                    before.path() != after.path()
                        || before.identity() != after.identity()
                        || before.bytes() != after.bytes()
                })
        {
            return Err(refusal());
        }
    }
    let suffix: String = plan
        .nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let key = format!(
        "gc/{}/delete/{}/{suffix}",
        plan.exclusion.cycle,
        crate::pack::PackId::from_random_bytes(plan.exclusion.pack)
    );
    plan.check_key(&key).map_err(|_| refusal())?;
    let before = initial.encode().map_err(|_| refusal())?;
    if data
        .data()
        .observed()
        .logical()
        .get(&key)
        .and_then(Option::as_deref)
        != Some(before.as_slice())
    {
        return Err(refusal());
    }
    let artifacts = data.artifacts(held).await?;
    let elapsed = barrier.elapsed().map_err(native)?;
    let nanos = u64::try_from(elapsed.as_nanos()).map_err(|_| refusal())?;
    let authorization = CopiedRetirementAuthorization {
        nonce: plan.nonce,
        backend: plan.backend.clone(),
        exclusion: plan.exclusion,
        lease: session.lease().clone(),
        deletion_seconds: plan.deletion_seconds,
        barrier: BarrierArtifact::Local(barrier.artifact().clone()),
        tombstone: plan.tombstone.clone(),
        deletion_elapsed_nanos: nanos,
        fence: artifacts.fence().0.clone(),
        grace_seconds: plan.grace_seconds,
        grace_elapsed_nanos: nanos,
        genesis: plan.genesis,
        preparation: barrier.slot(),
        // This first group performs no independent source-lineage qualification.
        lineage_fence: None,
    };
    authorization
        .check_preparation(initial, &barrier.slot())
        .map_err(|_| refusal())?;
    let authorization = PermanentDeleteAuthorization::Copied(authorization);
    let authorization_bytes = authorization.encode().map_err(|_| refusal())?;
    let operation = PermanentDeleteOperation {
        revision: initial.revision.checked_add(1).ok_or_else(refusal)?,
        phase: OperationPhase::Proposed,
        authorization,
        owner: None,
        pass: None,
    };
    let mut next = data.data().observed().state().clone();
    next.revision = next.revision.checked_add(1).ok_or_else(refusal)?;
    next.loss_generation = next.loss_generation.checked_add(1).ok_or_else(refusal)?;
    next.sources.clear();
    let owners = next.burn_owners.as_mut().ok_or_else(refusal)?;
    let owner = owners
        .iter_mut()
        .find(|owner| owner.pack == plan.exclusion.pack)
        .ok_or_else(refusal)?;
    if owner.selection != PermanentOwnerSelection::CopiedVisibility {
        return Err(refusal());
    }
    *owner = PermanentBurnOwner {
        pack: plan.exclusion.pack,
        selection: PermanentOwnerSelection::Permanent(RecordPointer {
            key: key.clone(),
            digest: *blake3::hash(&authorization_bytes).as_bytes(),
        }),
    };
    let mut changes = vec![LogicalChange {
        key: key.clone(),
        expected: Some(before),
        new: Some(operation.encode().map_err(|_| refusal())?),
    }];
    for (pointer, bytes) in [artifacts.roots(), artifacts.marks()].into_iter().chain(
        artifacts
            .checkpoints()
            .iter()
            .map(|(pointer, bytes)| (pointer, bytes.as_slice())),
    ) {
        if data
            .data()
            .observed()
            .logical()
            .get(&pointer.key)
            .is_some_and(Option::is_some)
        {
            return Err(refusal());
        }
        changes.push(LogicalChange {
            key: pointer.key.clone(),
            expected: None,
            new: Some(bytes.to_vec()),
        });
    }
    changes.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    session.recheck()?;
    data.data().revalidate().await?;
    barrier.elapsed().map_err(native)?;
    Ok(CheckedOwnership {
        data,
        artifacts,
        barrier,
        operation,
        key,
        next,
        changes,
    })
}
