//! Acknowledges actual selected exclusion durability before first Trash mutation.
//!
//! The channel starts empty and only this native worker can populate it after
//! verifying the protected slot/transaction/fence, portable snapshot/pointer,
//! actual native pair and complete refreshed Frame. It synchronizes the same
//! checked metadata descriptors and only directories below the retained actual
//! namespace/control roots. All file syncs precede a deepest-first sync of each
//! scoped original directory; no namespace mutation occurs within this phase.
//! Pack bodies are never read by this mechanic.

use super::current_pair::{NativeCurrentPair, PairHold};
use super::{
    ExactRead, FencePolicy, MetadataStamp, NativeEffectFailure, NativeExclusion,
    NativeOpenedDirectory, ParentFence, Path, PathBuf, Plan, Worker, check_opened_name,
    checked_body, checked_protected, open_native,
};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, mpsc},
};
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationTransaction,
};

/// Records bounded numeric diagnostics without retaining native observations.
#[cfg(all(test, feature = "std"))]
#[path = "retirement_barrier/cost_trace.rs"]
pub(super) mod cost_trace;

#[cfg(all(test, feature = "tokio", unix))]
#[path = "retirement_barrier/sync_observation.rs"]
mod sync_observation;

/// Reports actual original-descriptor capture and successful synchronization.
#[cfg(all(test, feature = "tokio", unix))]
pub(crate) use sync_observation::RetirementSyncEvent;

#[cfg(all(test, feature = "tokio", unix))]
use std::os::fd::AsRawFd;

/// Fixes one actual pair and exact canonical selected exclusion artifacts.
pub(in super::super) struct BarrierRequest {
    root: PathBuf,
    control: PathBuf,
    slot_path: PathBuf,
    slot: Vec<u8>,
    transaction_path: PathBuf,
    transaction: Vec<u8>,
    snapshot_path: PathBuf,
    snapshot: Vec<u8>,
    pointer: Vec<u8>,
    fence_path: PathBuf,
    fence: Vec<u8>,
    pair: Arc<PairHold>,
    owner: u32,
    sources: Vec<(
        terrane_format::gc::publication::SourceLineage,
        terrane_format::gc::publication::SourceLineage,
    )>,
    loss_generation: u64,
    #[cfg(all(test, feature = "std"))]
    cost: std::sync::OnceLock<cost_trace::Trace>,
    #[cfg(all(test, feature = "tokio", unix))]
    completed_syncs: Option<mpsc::Sender<RetirementSyncEvent>>,
    result: mpsc::Sender<DurableBarrier>,
}

impl BarrierRequest {
    /// Attaches observations without replacing any native completion channel.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(in super::super) fn observe_syncs(&mut self, sender: mpsc::Sender<RetirementSyncEvent>) {
        self.completed_syncs = Some(sender);
    }

    /// Borrows the fixed actual slot only for native fault selection.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super) fn path(&self) -> &Path {
        &self.slot_path
    }
}

/// Acknowledges actual completed durability without granting any collection authority.
struct DurableBarrier {
    _private: (),
}

/// Takes the one native barrier acknowledgment with no caller setter or constructor.
pub(in super::super) struct BarrierReceiver {
    result: mpsc::Receiver<DurableBarrier>,
}

impl BarrierReceiver {
    /// Consumes one actual completed native acknowledgment.
    ///
    /// # Errors
    /// Refuses no-op unit success, swallowed native failures or an unexecuted request.
    pub(in super::super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result.try_recv().map(|_| ()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native retirement barrier acknowledgment unavailable",
            )
            .into()
        })
    }
}

/// Borrows fixed observations without creating a native result or retirement authority.
pub(in super::super) struct BarrierInputs<'a> {
    /// Actual selected namespace retained by the Frame.
    pub(in super::super) root: &'a Path,
    /// Independently configured protected control retained by the Frame.
    pub(in super::super) control: &'a Path,
    /// Executor-produced current pair, without any descriptor access.
    pub(in super::super) pair: &'a NativeCurrentPair,
    /// Actual retained exclusions needed to bind the pair to the current Frame.
    pub(in super::super) exclusions: &'a [NativeExclusion],
    /// Exact selecting slot after closed current-root producer validation.
    pub(in super::super) slot: &'a PublicationCommit,
    /// Exact case-2 successor transaction and closed producer-qualified carried sources.
    pub(in super::super) transaction: &'a PublicationTransaction,
    /// Exact canonical successor portable snapshot body.
    pub(in super::super) snapshot: &'a [u8],
    /// Exact current-v1 predecessor fence body.
    pub(in super::super) fence: &'a [u8],
    /// Independently configured native backend owner.
    pub(in super::super) owner: u32,
}

/// Prepares a closed request from a genuine native pair and fixed publication bytes.
///
/// This creates no result or retirement authority. The executor independently
/// verifies all native observations, protection, exact bodies and durability.
///
/// # Errors
/// Refuses another pair/root/control/exclusion, inconsistent canonical slot,
/// transaction or snapshot, mismatched carry, changed refs/Guard, or a manifest
/// without the exact first unburned active exclusion.
pub(in super::super) fn barrier_plan(
    inputs: BarrierInputs<'_>,
) -> Result<(Plan, BarrierReceiver), NativeEffectFailure> {
    let BarrierInputs {
        root,
        control,
        pair,
        exclusions,
        slot,
        transaction,
        snapshot,
        fence,
        owner,
    } = inputs;
    let PublicationProof::Collection {
        fence_key,
        fence_digest,
        removed,
        carried,
    } = &transaction.proof
    else {
        return Err(io::Error::other("barrier lacks collection proof").into());
    };
    if carried.len() != transaction.new.sources.len()
        || removed.len() != 1
        || removed[0].pack != pair.inventory().pack_id
        || removed[0].index != pair.inventory().index_hash
        || *fence_digest != *blake3::hash(fence).as_bytes()
        || slot.revision != transaction.new.revision
        || slot.predecessor != transaction.predecessor.as_ref().map(|row| row.digest)
    {
        return Err(io::Error::other("barrier association differs").into());
    }
    let previous = transaction
        .old
        .as_ref()
        .ok_or_else(|| io::Error::other("barrier has no selected predecessor"))?;
    if previous.binding != transaction.new.binding
        || previous.guard != transaction.new.guard
        || previous.branches != transaction.new.branches
        || previous.burn_owners != transaction.new.burn_owners
        || carried
            .iter()
            .zip(&transaction.new.sources)
            .any(|(prior, next)| prior.name != next.name || !previous.sources.contains(prior))
    {
        return Err(io::Error::other("barrier changed protected selection semantics").into());
    }
    let cap = transaction
        .changes
        .iter()
        .find(|change| change.key == "CAPABILITIES")
        .and_then(|row| row.new.as_deref())
        .ok_or_else(|| io::Error::other("barrier lacks capabilities"))?;
    let cap = BucketCapabilities::decode(cap).map_err(io::Error::other)?;
    let generation = cap
        .generation
        .ok_or_else(|| io::Error::other("barrier lacks generation"))?;
    let manifest = transaction
        .changes
        .iter()
        .find(|row| row.key == format!("objects/index/{generation}/MANIFEST"))
        .and_then(|row| row.new.as_deref())
        .ok_or_else(|| io::Error::other("barrier lacks manifest"))?;
    let manifest = GenerationManifest::decode(manifest).map_err(io::Error::other)?;
    let binding = manifest
        .exclusions
        .as_ref()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.pack_id == pair.inventory().pack_id)
        })
        .ok_or_else(|| io::Error::other("barrier lacks active incarnation"))?;
    if manifest
        .inventory
        .as_ref()
        .is_none_or(|rows| !rows.contains(pair.inventory()))
        || manifest
            .burns
            .as_ref()
            .is_none_or(|rows| rows.binary_search(&pair.inventory().pack_id).is_ok())
        || binding.cycle != manifest.cycle
        || fence_key != &format!("gc/{}/fence/{}", binding.cycle, previous.revision)
    {
        return Err(io::Error::other("barrier manifest association differs").into());
    }
    let fence_value = terrane_format::gc::retirement::CurrentCollectionFence::decode(fence)
        .map_err(io::Error::other)?;
    fence_value
        .check_pointer(&terrane_format::gc::retirement::RecordPointer {
            key: fence_key.clone(),
            digest: *fence_digest,
        })
        .map_err(io::Error::other)?;
    if fence_value.state != *previous || fence_value.backend != previous.binding {
        return Err(io::Error::other("barrier fence is not exact predecessor").into());
    }
    transaction
        .check_snapshot(snapshot)
        .map_err(io::Error::other)?;
    transaction
        .check_key(&slot.transaction_key)
        .map_err(io::Error::other)?;
    let transaction_bytes = transaction.encode().map_err(io::Error::other)?;
    if slot.transaction_digest != *blake3::hash(&transaction_bytes).as_bytes() {
        return Err(io::Error::other("barrier slot transaction digest differs").into());
    }
    let pair = pair.retention(root, control, exclusions)?;
    let (sender, receiver) = mpsc::channel();
    Ok((
        Plan::SealRetirementBarrier(Box::new(BarrierRequest {
            root: root.to_owned(),
            control: control.to_owned(),
            slot_path: control.join(format!("publication/commits/{}", slot.revision)),
            slot: slot.encode().map_err(io::Error::other)?,
            transaction_path: control.join(&slot.transaction_key),
            transaction: transaction_bytes,
            snapshot_path: root.join(&transaction.snapshot.key),
            snapshot: snapshot.to_vec(),
            pointer: transaction.snapshot.encode().map_err(io::Error::other)?,
            fence_path: control.join(fence_key),
            fence: fence.to_vec(),
            pair,
            owner,
            sources: carried
                .iter()
                .cloned()
                .zip(transaction.new.sources.iter().cloned())
                .collect(),
            loss_generation: transaction.new.loss_generation,
            #[cfg(all(test, feature = "std"))]
            cost: std::sync::OnceLock::new(),
            #[cfg(all(test, feature = "tokio", unix))]
            completed_syncs: None,
            result: sender,
        })),
        BarrierReceiver { result: receiver },
    ))
}

fn association(request: &BarrierRequest, worker: &Worker) -> Result<(), NativeEffectFailure> {
    #[cfg(all(test, feature = "std"))]
    let mut association_cost = request
        .cost
        .get()
        .and_then(|trace| trace.span(cost_trace::Group::Association, 0));
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    if worker.projection.final_check.is_none()
        || !worker
            .projection
            .pairs
            .iter()
            .any(|pair| Arc::ptr_eq(pair, &request.pair))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "barrier lacks genuine current pair/final refresh",
        )
        .into());
    }
    for (path, bytes, protected) in [
        (&request.slot_path, request.slot.as_slice(), true),
        (
            &request.transaction_path,
            request.transaction.as_slice(),
            true,
        ),
        (&request.snapshot_path, request.snapshot.as_slice(), false),
        (&request.fence_path, request.fence.as_slice(), true),
    ] {
        let read = worker.projection.exact(path, Some(bytes))?;
        let matches = if protected {
            matches!(read.policy,FencePolicy::ProtectedRecord{owner} if owner==request.owner)
        } else {
            matches!(read.policy,FencePolicy::Payload{owner} if owner==request.owner)
        };
        if !matches {
            return Err(io::Error::other("barrier record policy differs").into());
        }
    }
    #[cfg(all(test, feature = "std"))]
    let mut lineage_cost = request
        .cost
        .get()
        .and_then(|trace| trace.span(cost_trace::Group::ExpectedLineage, 0));
    for (prior, next) in &request.sources {
        let read_lineage =
            |row: &terrane_format::gc::publication::SourceLineage| -> Result<_, NativeEffectFailure> {
                let suffix: String = row
                    .digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                let path = request
                    .control
                    .join(format!("publication/lineage/{suffix}"));
                let read = worker
                    .projection
                    .preimages
                    .iter()
                    .find(|read| read.path == path)
                    .ok_or_else(|| io::Error::other("barrier lacks carried lineage preimage"))?;
                let bytes = read
                    .expected
                    .as_deref()
                    .ok_or_else(|| io::Error::other("barrier carried lineage absent"))?;
                if !matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner)
                    || {
                        #[cfg(all(test, feature = "std"))]
                        let mut hash_cost = request.cost.get().and_then(|trace| {
                            trace.span(cost_trace::Group::LineageHash, bytes.len())
                        });
                        let digest = blake3::hash(bytes);
                        #[cfg(all(test, feature = "std"))]
                        if let Some(span) = &mut hash_cost {
                            span.complete();
                        }
                        #[cfg(all(test, feature = "std"))]
                        drop(hash_cost);
                        *digest.as_bytes() != row.digest
                    }
                {
                    return Err(
                        io::Error::other("barrier carried lineage protection differs").into(),
                    );
                }
                let lineage = {
                    #[cfg(all(test, feature = "std"))]
                    let mut decode_cost = request.cost.get().and_then(|trace| {
                        trace.span(cost_trace::Group::LineageDecode, bytes.len())
                    });
                    let decoded =
                        terrane_format::gc::publication::evidence::CheckedLineage::decode(bytes);
                    #[cfg(all(test, feature = "std"))]
                    if let Some(span) = &mut decode_cost {
                        span.finish_result(&decoded);
                    }
                    decoded
                }
                .map_err(io::Error::other)?;
                if lineage.source_name != row.name {
                    return Err(io::Error::other("barrier carried source name differs").into());
                }
                Ok(lineage)
            };
        let previous = read_lineage(prior)?;
        let successor = read_lineage(next)?;
        if previous.loss_generation.checked_add(1) != Some(request.loss_generation)
            || successor.loss_generation != request.loss_generation
            || previous.source != successor.source
            || previous.commit_id != successor.commit_id
            || previous.commit_bytes != successor.commit_bytes
            || previous.guard_digest != successor.guard_digest
            || previous.original != successor.original
        {
            return Err(io::Error::other("barrier carried lineage association differs").into());
        }
    }
    #[cfg(all(test, feature = "std"))]
    if let Some(span) = &mut lineage_cost {
        span.complete();
    }
    #[cfg(all(test, feature = "std"))]
    drop(lineage_cost);
    worker.projection.exact(
        &request.root.join("publication/PORTABLE"),
        Some(&request.pointer),
    )?;
    request.pair.recheck()?;
    let result = worker.refresh(&[]);
    #[cfg(all(test, feature = "std"))]
    if let Some(span) = &mut association_cost {
        span.finish_result(&result);
    }
    result
}

/// Retains one original directory descriptor per scoped path in a barrier frame.
///
/// Each row still checks its complete captured ancestry and the actual retained
/// descriptor. Separate barriers create separate cohorts and fresh descriptors;
/// this ownership never replaces another frame's original physical observations.
#[derive(Default)]
struct DirectoryCohort {
    originals: BTreeMap<DirectoryKey, Arc<NativeOpenedDirectory>>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct DirectoryKey {
    path: PathBuf,
    root: PathBuf,
    owner: u32,
    control: bool,
}

impl DirectoryCohort {
    fn below(
        &mut self,
        read: &ExactRead,
        root: &Path,
        owner: u32,
        control: bool,
    ) -> io::Result<Vec<Arc<NativeOpenedDirectory>>> {
        let first = read
            .parents
            .iter()
            .position(|parent| parent.path == root)
            .ok_or_else(|| io::Error::other("creation preimage lacks its root ancestry"))?;
        let policy = if control {
            FencePolicy::PrivateControlDirectory { owner }
        } else {
            FencePolicy::NamespaceDirectory { owner }
        };

        let mut result = Vec::new();
        for (index, parent) in read.parents.iter().enumerate().skip(first) {
            policy.validate(parent.stamp)?;
            let key = DirectoryKey {
                path: parent.path.clone(),
                root: root.to_owned(),
                owner,
                control,
            };
            let original = if let Some(original) = self.originals.get(&key) {
                // Replay the named-descriptor and metadata observations normally
                // made by open_native, using this cohort's retained Original.
                check_opened_name(&original.file, &parent.path, true)?;
                let stamp = MetadataStamp::checked(&original.file.metadata()?)?;
                if !stamp.same_incarnation(parent.stamp) {
                    return Err(io::Error::other("creation directory receipt changed"));
                }

                // Compare this row's observations before sharing ownership of the
                // first descriptor. Equal paths alone cannot rebind an Original.
                if original.policy != policy
                    || !original.stamp.same_incarnation(parent.stamp)
                    || original.parents.len() != index
                    || !original.parents.iter().zip(&read.parents[..index]).all(
                        |(actual, expected)| {
                            actual.path == expected.path
                                && actual.stamp.same_incarnation(expected.stamp)
                        },
                    )
                {
                    return Err(io::Error::other("barrier directory observations differ"));
                }
                Arc::clone(original)
            } else {
                let file = open_native(&parent.path, true)?;
                let stamp = MetadataStamp::checked(&file.metadata()?)?;
                if !stamp.same_incarnation(parent.stamp) {
                    return Err(io::Error::other("creation directory receipt changed"));
                }
                Arc::new(NativeOpenedDirectory {
                    file: Arc::new(file),
                    path: parent.path.clone(),
                    stamp,
                    policy,
                    parents: read.parents[..index]
                        .iter()
                        .map(|ancestor| ParentFence {
                            path: ancestor.path.clone(),
                            stamp: ancestor.stamp,
                        })
                        .collect(),
                })
            };

            // Every occurrence freshly checks descriptor, name and full ancestry;
            // the cohort only removes redundant open descriptors, never checks.
            original.check()?;
            self.originals
                .entry(key)
                .or_insert_with(|| Arc::clone(&original));
            result.push(original);
        }
        Ok(result)
    }
}

/// Retains the original metadata descriptor through file and directory durability.
struct BarrierRecord {
    path: PathBuf,
    bytes: Vec<u8>,
    stamp: MetadataStamp,
    protected: bool,
    file: std::fs::File,
}

impl BarrierRecord {
    fn check(&mut self, owner: u32) -> io::Result<()> {
        if self.protected {
            checked_protected(&mut self.file, &self.path, self.stamp, &self.bytes, owner)
        } else {
            checked_body(&mut self.file, &self.path, self.stamp, &self.bytes, owner)
        }
    }
}

/// Completes descriptor synchronization and required directory durability before acknowledgment.
///
/// # Errors
/// Refuses changed actual bodies/descriptors/names/ancestors, missing selected
/// associations or retained pair, current lease/control refusal and actual sync
/// failures. Unit return without this completion cannot populate the receiver.
pub(super) fn execute(
    request: BarrierRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    #[cfg(all(test, feature = "std"))]
    {
        let trace = request
            .cost
            .get_or_init(|| cost_trace::Trace::new("retirement-barrier", None));
        trace.inventory(
            request.sources.len(),
            worker.projection.preimages.len(),
            0,
            0,
        );
    }
    association(&request, &worker)?;
    let mut records = Vec::new();
    let mut directory_cohort = DirectoryCohort::default();
    for read in &worker.projection.preimages {
        let Some(bytes) = &read.expected else {
            continue;
        };
        let inside_control = read.path.starts_with(&request.control);
        let inside_root = read.path.starts_with(&request.root);
        if !inside_control && !inside_root {
            continue;
        }
        // Pack descriptors remain metadata-only for this protocol. Their real
        // creator/pair durability and full native continuity are checked separately.
        if read
            .path
            .extension()
            .is_some_and(|extension| extension == "pack")
        {
            continue;
        }
        let stamp = read
            .metadata
            .ok_or_else(|| io::Error::other("barrier lacks present metadata"))?;
        let expected_policy = if inside_control {
            FencePolicy::ProtectedRecord {
                owner: request.owner,
            }
        } else {
            FencePolicy::Payload {
                owner: request.owner,
            }
        };
        let correct = match (read.policy, expected_policy) {
            (
                FencePolicy::ProtectedRecord { owner: a },
                FencePolicy::ProtectedRecord { owner: b },
            )
            | (FencePolicy::Payload { owner: a }, FencePolicy::Payload { owner: b }) => a == b,
            _ => false,
        };
        if !correct || read.identity != Some(stamp.identity) {
            return Err(io::Error::other("barrier preimage policy differs").into());
        }
        let directories = directory_cohort.below(
            read,
            if inside_control {
                &request.control
            } else {
                &request.root
            },
            request.owner,
            inside_control,
        )?;
        #[cfg(all(test, feature = "tokio", unix))]
        if let Some(sender) = &request.completed_syncs {
            for directory in &directories {
                let _ = sender.send(RetirementSyncEvent::DirectoryCaptured {
                    path: directory.path.clone(),
                    root: if inside_control {
                        request.control.clone()
                    } else {
                        request.root.clone()
                    },
                    owner: request.owner,
                    control: inside_control,
                    descriptor: directory.file.as_raw_fd(),
                    identity: directory.stamp.identity,
                });
            }
        }
        // The cohort retains every original after this row's fresh checks.
        drop(directories);
        let file = open_native(&read.path, false)?;
        records.push(BarrierRecord {
            path: read.path.clone(),
            bytes: bytes.clone(),
            stamp,
            protected: inside_control,
            file,
        });
    }
    #[cfg(all(test, feature = "std"))]
    if let Some(trace) = request.cost.get() {
        trace.inventory(
            request.sources.len(),
            worker.projection.preimages.len(),
            records.len(),
            directory_cohort.originals.len(),
        );
    }
    for record in &mut records {
        association(&request, &worker)?;
        record.check(request.owner)?;
        #[cfg(all(test, feature = "tokio", unix))]
        if let Some(sender) = &request.completed_syncs {
            let _ = sender.send(RetirementSyncEvent::FileCaptured {
                path: record.path.clone(),
                descriptor: record.file.as_raw_fd(),
                identity: record.stamp.identity,
            });
        }
        worker.file_sync(&record.file, &[])?;
        record.check(request.owner)?;
        association(&request, &worker)?;
        #[cfg(all(test, feature = "tokio", unix))]
        if let Some(sender) = &request.completed_syncs {
            let _ = sender.send(RetirementSyncEvent::FileSynced {
                path: record.path.clone(),
                descriptor: record.file.as_raw_fd(),
                identity: record.stamp.identity,
            });
        }
    }

    // Only reads and syncs occur in this phase. One sync of each exact scoped
    // original after all children therefore covers every unchanged entry; it
    // does not reuse observations or omit checks around any remaining effect.
    let mut directories = directory_cohort.originals.iter().collect::<Vec<_>>();
    directories.sort_by(|(left, _), (right, _)| {
        right
            .path
            .components()
            .count()
            .cmp(&left.path.components().count())
            .then_with(|| left.cmp(right))
    });
    for (key, directory) in directories {
        #[cfg(not(all(test, feature = "tokio", unix)))]
        let _ = key;
        association(&request, &worker)?;
        worker.directory_sync(directory, false, &[])?;
        association(&request, &worker)?;
        #[cfg(all(test, feature = "tokio", unix))]
        if let Some(sender) = &request.completed_syncs {
            let _ = sender.send(RetirementSyncEvent::DirectorySynced {
                path: key.path.clone(),
                root: key.root.clone(),
                owner: key.owner,
                control: key.control,
                descriptor: directory.file.as_raw_fd(),
                identity: directory.stamp.identity,
            });
        }
    }
    for record in &mut records {
        record.check(request.owner)?;
    }
    association(&request, &worker)?;
    let _ = request.result.send(DurableBarrier { _private: () });
    #[cfg(all(test, feature = "std"))]
    if let Some(trace) = request.cost.into_inner() {
        let mut trace = trace;
        trace.complete();
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Physical cohort assertions intentionally panic."
    )]

    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture {
        root: PathBuf,
        owner: u32,
    }

    impl Fixture {
        fn new() -> Self {
            static SERIAL: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "retirement-directory-cohort-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            let owner = MetadataStamp::checked(&std::fs::symlink_metadata(&root).unwrap())
                .unwrap()
                .owner;
            Self { root, owner }
        }

        fn directory(&self, path: &Path) {
            std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }

        fn read(&self, path: &Path) -> ExactRead {
            std::fs::write(path, b"original body").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let metadata =
                MetadataStamp::checked(&std::fs::symlink_metadata(path).unwrap()).unwrap();
            ExactRead {
                path: path.to_owned(),
                expected: Some(b"original body".to_vec()),
                identity: Some(metadata.identity),
                metadata: Some(metadata),
                policy: FencePolicy::Payload { owner: self.owner },
                owner: self.owner,
                parents: super::super::super::parent_paths(path)
                    .unwrap()
                    .into_iter()
                    .map(|path| ParentFence {
                        stamp: MetadataStamp::checked(&std::fs::symlink_metadata(&path).unwrap())
                            .unwrap(),
                        path,
                    })
                    .collect(),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn one_barrier_cohort_shares_originals_across_many_rows_until_last_owner() {
        let fixture = Fixture::new();
        let parent = fixture.root.join("publication");
        let child = parent.join("commits");
        fixture.directory(&parent);
        fixture.directory(&child);

        let mut cohort = DirectoryCohort::default();
        let mut rows = Vec::new();
        for index in 0..128 {
            let read = fixture.read(&child.join(index.to_string()));
            rows.push(
                cohort
                    .below(&read, &fixture.root, fixture.owner, false)
                    .unwrap(),
            );
        }

        assert_eq!(cohort.originals.len(), 3);
        assert!(rows.iter().all(|row| row.len() == 3));
        for row in &rows {
            for (original, repeated) in rows[0].iter().zip(row) {
                assert!(Arc::ptr_eq(original, repeated));
                assert!(Arc::ptr_eq(&original.file, &repeated.file));
                assert_eq!(original.file.as_raw_fd(), repeated.file.as_raw_fd());
                repeated.check().unwrap();
            }
        }

        let descriptor = Arc::downgrade(&rows[0][0].file);
        drop(cohort);
        let last_row = rows.pop().unwrap();
        drop(rows);
        assert!(descriptor.upgrade().is_some());
        for directory in &last_row {
            directory.check().unwrap();
        }
        drop(last_row);
        assert!(descriptor.upgrade().is_none());
    }

    #[test]
    fn separate_barrier_cohorts_capture_distinct_original_descriptors() {
        let fixture = Fixture::new();
        let read = fixture.read(&fixture.root.join("record"));
        let mut first = DirectoryCohort::default();
        let mut second = DirectoryCohort::default();

        let original = first
            .below(&read, &fixture.root, fixture.owner, true)
            .unwrap();
        let fresh = second
            .below(&read, &fixture.root, fixture.owner, true)
            .unwrap();

        assert_eq!(original.len(), 1);
        assert_eq!(fresh.len(), 1);
        assert!(!Arc::ptr_eq(&original[0], &fresh[0]));
        assert!(!Arc::ptr_eq(&original[0].file, &fresh[0].file));
        assert_ne!(original[0].file.as_raw_fd(), fresh[0].file.as_raw_fd());
        original[0].check().unwrap();
        fresh[0].check().unwrap();
    }

    #[test]
    fn reused_directory_refuses_a_replaced_ancestor_without_rebinding() {
        let fixture = Fixture::new();
        let parent = fixture.root.join("parent");
        let child = parent.join("child");
        fixture.directory(&parent);
        fixture.directory(&child);
        let read = fixture.read(&child.join("record"));
        let mut cohort = DirectoryCohort::default();
        let originals = cohort
            .below(&read, &fixture.root, fixture.owner, false)
            .unwrap();
        let original_descriptor = Arc::clone(&originals[1].file);

        std::fs::rename(&parent, fixture.root.join("old-parent")).unwrap();
        fixture.directory(&parent);
        fixture.directory(&child);
        let replacement = fixture.read(&child.join("record"));

        assert!(
            cohort
                .below(&replacement, &fixture.root, fixture.owner, false)
                .is_err()
        );
        assert!(originals[2].check().is_err());
        assert!(cohort.originals.values().any(|original| {
            original.path == parent && Arc::ptr_eq(&original.file, &original_descriptor)
        }));
        assert_eq!(cohort.originals.len(), 3);
    }

    #[test]
    fn cohort_reuse_refuses_different_captured_ancestry_and_owner() {
        let fixture = Fixture::new();
        let mut read = fixture.read(&fixture.root.join("record"));
        let mut cohort = DirectoryCohort::default();
        let originals = cohort
            .below(&read, &fixture.root, fixture.owner, false)
            .unwrap();

        assert!(
            cohort
                .below(&read, &fixture.root, fixture.owner.wrapping_add(1), false)
                .is_err()
        );
        read.parents[0].stamp.identity.1 ^= 1;
        assert!(
            cohort
                .below(&read, &fixture.root, fixture.owner, false)
                .is_err()
        );
        assert_eq!(cohort.originals.len(), 1);
        assert!(Arc::ptr_eq(
            cohort.originals.values().next().unwrap(),
            &originals[0],
        ));
        originals[0].check().unwrap();
    }

    #[test]
    fn one_path_preserves_distinct_supported_root_and_policy_variants() {
        let fixture = Fixture::new();
        let parent = fixture.root.join("parent");
        fixture.directory(&parent);
        let read = fixture.read(&parent.join("record"));
        let mut cohort = DirectoryCohort::default();

        let namespace = cohort
            .below(&read, &fixture.root, fixture.owner, false)
            .unwrap();
        let control = cohort
            .below(&read, &fixture.root, fixture.owner, true)
            .unwrap();
        let narrower = cohort.below(&read, &parent, fixture.owner, false).unwrap();

        assert_eq!(cohort.originals.len(), 5);
        assert!(!Arc::ptr_eq(&namespace[1].file, &control[1].file));
        assert!(!Arc::ptr_eq(&namespace[1].file, &narrower[0].file));
        assert!(namespace[1].stamp == control[1].stamp);
        assert!(namespace[1].stamp == narrower[0].stamp);
        for original in namespace.iter().chain(&control).chain(&narrower) {
            original.check().unwrap();
        }
    }

    #[test]
    fn repeated_original_refuses_named_replacement_and_unsafe_protection() {
        for replacement in [false, true] {
            let fixture = Fixture::new();
            let parent = fixture.root.join("parent");
            fixture.directory(&parent);
            let read = fixture.read(&parent.join("record"));
            let mut cohort = DirectoryCohort::default();
            let originals = cohort
                .below(&read, &fixture.root, fixture.owner, false)
                .unwrap();

            if replacement {
                std::fs::rename(&parent, fixture.root.join("old-parent")).unwrap();
                fixture.directory(&parent);
            } else {
                std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
            }

            assert!(
                cohort
                    .below(&read, &fixture.root, fixture.owner, false)
                    .is_err()
            );
            assert!(originals[1].check().is_err());
            assert!(cohort.originals.values().any(|original| {
                original.path == parent && Arc::ptr_eq(original, &originals[1])
            }));
            assert_eq!(cohort.originals.len(), 2);
        }
    }
}
