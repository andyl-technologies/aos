//! Encodes proposed checkpoints from independently checked destination DATA.
//!
//! Copied placement uses D-113's conservative physical closure without proof
//! contexts, parent pruning or imported age. Ordinary Sweep placement preserves
//! the proof contexts and retention cutoffs of its separately authenticated
//! current traversal. Both use the existing fence schema as proposed bytes;
//! encoding grants no authority, and copied physical claims never enter ordinary
//! authenticated GC or lineage factories.

use super::{CheckedDataPlacement, denied, digest};
use crate::bucket::BucketBinding;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::{collection_observation, receipts::RecordRead};
use crate::store::StoreFailure;
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind};
use terrane_format::gc::retirement::{CopiedPlacementFence, RecordPointer};
use terrane_format::gc::{CheckpointPointer, GcMark, GcRoots, GcState, Phase};

/// Encodes an exact proposed physical snapshot from actual checked DATA inputs.
///
/// Private fields prevent substituting caller-built roots or mark claims. This
/// type represents proposed bytes only; it grants no publication, barrier,
/// elapsed, ownership, lineage or deletion authority.
pub(crate) struct PlacementArtifacts {
    roots: RecordPointer,
    root_bytes: Vec<u8>,
    marks: RecordPointer,
    mark_bytes: Vec<u8>,
    fence: RecordPointer,
    fence_bytes: Vec<u8>,
    absent: Vec<RecordRead>,
    checkpoints: Vec<(RecordPointer, Vec<u8>)>,
}

impl PlacementArtifacts {
    /// Chooses a fresh destination checkpoint cycle under the actual holder.
    ///
    /// The returned observations must remain exact publication predicates. This
    /// method does not install artifacts or grant checkpoint selection authority.
    ///
    /// # Errors
    /// Refuses mismatched holders, failed entropy, occupied names, changed DATA
    /// observations and expired whole leases.
    pub(super) async fn fresh<F, B, V>(
        data: &CheckedDataPlacement<'_, '_>,
        held: &HeldBucket<'_, F, B, V, true>,
    ) -> Result<Self, StoreFailure>
    where
        F: LocalFs + BucketBinding,
        B: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    {
        if held.root() != data.observed().identity().root()
            || held.physical_identity() != data.observed().identity().physical_identity()
        {
            return Err(denied());
        }
        data.revalidate().await?;
        let cycle = match data.checkpoint_cycle() {
            Some(cycle) => cycle,
            None => {
                let entropy = held.fs().random_bytes(8).await.map_err(|error| {
                    StoreFailure::with_source(
                        StoreErrorKind::Unavailable { retry_after: None },
                        error,
                    )
                })?;
                let bytes: [u8; 8] = entropy.try_into().map_err(|_| denied())?;
                u64::from_be_bytes(bytes)
            }
        };
        let mut artifacts = Self::build(data, cycle)?;
        for key in [
            format!("gc/cycle/{cycle}"),
            artifacts.roots.key.clone(),
            artifacts.marks.key.clone(),
        ] {
            let read = collection_observation::record(held, &key).await?;
            if read.bytes().is_some() || read.metadata().is_some() {
                return Err(denied());
            }
            artifacts.absent.push(read);
        }
        for (pointer, _) in &artifacts.checkpoints {
            let read = collection_observation::record(held, &pointer.key).await?;
            if read.bytes().is_some() || read.metadata().is_some() {
                return Err(denied());
            }
            artifacts.absent.push(read);
        }
        // A copied fence is protected backend-control metadata, not a payload
        // BucketKey. Observe its actual configured control name under the same
        // selected holder rather than treating root-path absence as evidence.
        let fence = crate::bucket::permanent_restore::read_fence(
            held,
            data.observed(),
            &artifacts.fence,
            &artifacts.fence_bytes,
        )
        .await?;
        if fence.bytes().is_some() || fence.metadata().is_some() {
            return Err(denied());
        }
        artifacts.absent.push(fence);
        data.revalidate().await?;
        Ok(artifacts)
    }

    /// Builds canonical physical artifacts using the actual live Session clock.
    ///
    /// The containing closed producer must independently reserve this cycle and
    /// all immutable names before publication. Building bytes does not reserve
    /// a name or qualify a new barrier incarnation.
    ///
    /// # Errors
    /// Refuses expired ownership, clock discontinuity, malformed physical
    /// traversal rows or an inconsistent exact current copied-placement fence.
    fn build(data: &CheckedDataPlacement<'_, '_>, cycle: u64) -> Result<Self, StoreFailure> {
        let now = data.session().recheck()?;
        let timestamp = data.snapshot_at();
        if timestamp > now {
            return Err(denied());
        }
        let epoch = data.session().lease().epoch;
        let roots = GcRoots {
            cycle,
            epoch,
            timestamp,
            roots: data.roots().to_vec(),
        };
        let root_bytes = roots.encode();
        let roots = RecordPointer {
            key: format!("gc/{cycle}/roots"),
            digest: digest(&root_bytes),
        };

        let mut progress: Vec<_> = data
            .packs()
            .iter()
            .map(|pack| pack.inventory().pack_id)
            .collect();
        progress.sort_unstable();
        progress.dedup();
        let mut checkpoints = Vec::new();
        let mut pointers = Vec::new();
        for shard in 0..=u8::MAX {
            let hashes: Vec<_> = data
                .hashes()
                .iter()
                .filter(|hash| hash[0] == shard)
                .copied()
                .collect();
            if hashes.is_empty() {
                continue;
            }
            let mark = GcMark::new(cycle, epoch, shard, hashes).map_err(|_| denied())?;
            let bytes = mark.encode();
            let hash = digest(&bytes);
            pointers.push(CheckpointPointer {
                shard,
                revision: 0,
                hash,
            });
            checkpoints.push((
                RecordPointer {
                    key: format!("gc/{cycle}/mark/{shard}/0"),
                    digest: hash,
                },
                bytes,
            ));
        }
        let state = GcState {
            cycle,
            epoch,
            phase: Phase::Sweep,
            snapshot_at: timestamp,
            checkpoints: pointers,
            pending: Vec::new(),
            expanded: data.expanded().to_vec(),
            progress,
            objects: data.objects().to_vec(),
        };
        let mark_bytes = state.encode().map_err(|_| denied())?;
        let marks = RecordPointer {
            key: format!("gc/{cycle}/state"),
            digest: digest(&mark_bytes),
        };
        let observed = data.observed();
        let controls: Vec<_> = data
            .effects()
            .control_owners
            .iter()
            .flat_map(|owner| owner.pins.iter().cloned())
            .collect();
        let fence = CopiedPlacementFence {
            capabilities: data.capabilities().to_vec(),
            manifest: data.manifest().to_vec(),
            refs: data.refs().to_vec(),
            guard: observed.state().guard.ok_or_else(denied)?,
            state: observed.state().clone(),
            roots: roots.clone(),
            marks: marks.clone(),
            backend: observed.state().binding.clone(),
            controls,
            genesis: *data.genesis(),
            projection: RecordPointer {
                key: observed.snapshot().key.clone(),
                digest: observed.snapshot().digest,
            },
        };
        let fence_bytes = fence.encode().map_err(|_| denied())?;
        let fence_pointer = RecordPointer {
            key: format!("gc/{cycle}/fence/{}", observed.state().revision),
            digest: digest(&fence_bytes),
        };
        fence.check_pointer(&fence_pointer).map_err(|_| denied())?;
        data.session().recheck()?;
        Ok(Self {
            roots,
            root_bytes,
            marks,
            mark_bytes,
            fence: fence_pointer,
            fence_bytes,
            absent: Vec::new(),
            checkpoints,
        })
    }

    /// Borrows the exact proposed physical root pointer and canonical body.
    pub(crate) fn roots(&self) -> (&RecordPointer, &[u8]) {
        (&self.roots, &self.root_bytes)
    }

    /// Borrows the exact proposed physical traversal pointer and canonical body.
    pub(crate) fn marks(&self) -> (&RecordPointer, &[u8]) {
        (&self.marks, &self.mark_bytes)
    }

    /// Borrows the exact current copied DATA fence pointer and canonical body.
    pub(crate) fn fence(&self) -> (&RecordPointer, &[u8]) {
        (&self.fence, &self.fence_bytes)
    }

    /// Borrows genuine protected absence predicates for the fresh checkpoint.
    pub(crate) fn absent(&self) -> &[RecordRead] {
        &self.absent
    }

    /// Borrows exact sorted-hash mark bodies with rebuilt membership filters.
    pub(crate) fn checkpoints(&self) -> &[(RecordPointer, Vec<u8>)] {
        &self.checkpoints
    }
}
