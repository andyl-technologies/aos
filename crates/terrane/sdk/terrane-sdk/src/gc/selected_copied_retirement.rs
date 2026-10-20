//! Produces copied preparations from independently checked destination DATA.
//!
//! This bridge owns proposed selected values only. Native preparation durability,
//! genuinely committed NEW Trash and complete same-clock G/D are separate phases.
//! Decoded records cannot construct this carrier or grant first ownership.

#[path = "selected_copied_retirement/generation.rs"]
mod generation;
#[path = "selected_copied_retirement/ownership.rs"]
mod ownership;

pub(crate) use ownership::{CheckedOwnership, authorize};

use crate::bucket::BucketBinding;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::{collection_observation, receipts::RecordRead};
use crate::gc::runner::session::Session;
use crate::selected_bridge::native_copied_placement::{CheckedCopiedPlacement, PlacementArtifacts};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_format::gc::publication::{LogicalChange, PublicationState};
use terrane_format::gc::retirement::{
    CopiedRetirementPlan, CopiedRetirementPreparation, Exclusion, PreparationPhase,
};
use terrane_format::gc::{GcRoots, Tombstone, Windows};

/// Retains one closed destination preparation and every genuine input predicate.
pub(crate) struct CheckedPreparation<'operation, 'held> {
    data: CheckedCopiedPlacement<'operation, 'held>,
    artifacts: PlacementArtifacts,
    preparation: CopiedRetirementPreparation,
    key: String,
    next: PublicationState,
    changes: Vec<LogicalChange>,
    reads: Vec<RecordRead>,
}

impl<'operation, 'held> CheckedPreparation<'operation, 'held> {
    /// Borrows actual current physical DATA and retained destination controls.
    pub(crate) fn data(&self) -> &CheckedCopiedPlacement<'operation, 'held> {
        &self.data
    }

    /// Borrows proposed physical checkpoints with genuine fresh-name predicates.
    pub(crate) fn artifacts(&self) -> &PlacementArtifacts {
        &self.artifacts
    }

    /// Borrows the complete canonical destination preparing plan.
    pub(crate) fn preparation(&self) -> &CopiedRetirementPreparation {
        &self.preparation
    }

    /// Borrows the independently chosen operation key.
    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    /// Borrows the exact successor state, preserving current copied visibility.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows sorted whole logical compares and replacements.
    pub(crate) fn changes(&self) -> &[LogicalChange] {
        &self.changes
    }

    /// Borrows actual generation and operation name observations.
    pub(crate) fn reads(&self) -> &[RecordRead] {
        &self.reads
    }
}

fn refusal() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "gc-copied-preparation",
        pattern: "genuine fresh destination plan".into(),
    })
}

/// Proposes one preparation after a complete actual destination DATA check.
///
/// # Errors
/// Refuses changed current DATA/controls, occupied selected operation names,
/// unsafe catalog successors, malformed canonical plans and failed entropy.
pub(crate) async fn prepare<'operation, 'held, F, B, V>(
    data: CheckedCopiedPlacement<'operation, 'held>,
    held: &HeldBucket<'_, F, B, V, true>,
    session: &'operation Session,
    windows: Windows,
) -> Result<CheckedPreparation<'operation, 'held>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    if !std::ptr::eq(data.data().session(), session) {
        return Err(refusal());
    }
    let artifacts = data.artifacts(held).await?;
    let roots = GcRoots::decode(artifacts.roots().1).map_err(|_| refusal())?;
    let random = held.fs().random_bytes(32).await.map_err(|error| {
        StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
    })?;
    let nonce: [u8; 32] = random.try_into().map_err(|_| refusal())?;
    let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let pack = data.data().pack();
    let key = format!(
        "gc/{}/delete/{}/{suffix}",
        roots.cycle,
        crate::pack::PackId::from_random_bytes(pack)
    );
    let operation = collection_observation::record(held, &key).await?;
    if operation.bytes().is_some()
        || operation.metadata().is_some()
        || data
            .data()
            .observed()
            .logical()
            .get(&key)
            .is_some_and(Option::is_some)
    {
        return Err(refusal());
    }
    let tombstone = Tombstone {
        pack,
        cycle: roots.cycle,
        timestamp: session.recheck()?,
        removed: 0,
        epoch: session.lease().epoch,
    };
    let preparation = CopiedRetirementPreparation {
        revision: 0,
        phase: PreparationPhase::Preparing,
        plan: CopiedRetirementPlan {
            nonce,
            backend: data.data().observed().state().binding.clone(),
            exclusion: Exclusion {
                pack,
                cycle: roots.cycle,
                epoch: session.lease().epoch,
            },
            lease: session.lease().clone(),
            genesis: *data.data().genesis(),
            fence: artifacts.fence().0.clone(),
            tombstone: tombstone.encode(),
            grace_seconds: windows.grace(),
            deletion_seconds: windows.deletion(),
        },
    };
    preparation.plan.check_key(&key).map_err(|_| refusal())?;
    let mut generation = generation::propose(data.data(), held, roots.cycle).await?;
    generation.reads.push(operation);
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
        generation.changes.push(LogicalChange {
            key: pointer.key.clone(),
            expected: None,
            new: Some(bytes.to_vec()),
        });
    }
    generation.changes.push(LogicalChange {
        key: key.clone(),
        expected: None,
        new: Some(preparation.encode().map_err(|_| refusal())?),
    });
    generation
        .changes
        .sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    let mut next = data.data().observed().state().clone();
    next.revision = next.revision.checked_add(1).ok_or_else(refusal)?;
    data.data().revalidate().await?;
    Ok(CheckedPreparation {
        data,
        artifacts,
        preparation,
        key,
        next,
        changes: generation.changes,
        reads: generation.reads,
    })
}
