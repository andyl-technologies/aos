//! Derives fixed physical publication effects from genuine retained inputs.
//!
//! This module is a logical descendant of the private native executor. Public
//! record bytes alone do not provide authority to construct a submitted effect.

/// Owns opaque creator receipts beneath the private retained publication frame.
#[path = "../../store/native_effect/initialization.rs"]
pub(crate) mod initialization_inputs;

pub(crate) use initialization_inputs::{
    fresh as initialization, pending as pending_initialization,
};

// The collector descendant consumes only its separately checked lease carrier;
// it reuses the retained executor without granting arbitrary effect construction.
/// Executes fixed collector lease publication under genuinely retained inputs.
#[path = "../../gc/effects.rs"]
pub(crate) mod collection;

/// Publishes fixed mark checkpoints under genuine lease and control receipts.
#[path = "../../gc/checkpoint_effects.rs"]
pub(crate) mod collection_checkpoints;

/// Executes copied destination retirement under checked placement and leases.
#[path = "../../gc/copied_retirement_effects.rs"]
pub(crate) mod collection_copied_retirement;

/// Executes fixed permanent recovery under checked ownership and current placement.
#[path = "../../gc/permanent_local_effects.rs"]
pub(crate) mod collection_permanent_local;

#[path = "effects/capture.rs"]
mod capture;
#[path = "effects/retained_read.rs"]
mod retained_read;
pub(crate) use retained_read::{PayloadReadCapture, RetainedPayloadRead};
#[cfg(all(feature = "tokio", unix))]
#[path = "effects/history_inputs.rs"]
mod history_inputs;
#[cfg(all(feature = "tokio", unix))]
pub(crate) use history_inputs::{CheckedHistoryInputs, close_history_inputs};
#[path = "effects/commands.rs"]
mod commands;
#[path = "effects/raw.rs"]
mod raw;

#[path = "effects/creation.rs"]
mod creation;

#[cfg(all(test, feature = "tokio", unix))]
pub(crate) use raw::{backend_sync_for_test, gate_active_cap_probe_for_test};
pub(crate) use raw::{
    probe_active, publish as publish_raw, publish_contextual as publish_raw_contextual, repair,
    stage_container, stage_container_contextual, stage_ref_log,
};

use super::{
    ExactRead, FencePolicy, MetadataStamp, NamedFence, NativeEffectFailure, NativeExclusion,
    NativeFsEffect, ParentFence, Plan,
};
use crate::bucket::BucketBinding;
use crate::bucket::publication::SelectedObservation;
use crate::selected_bridge::{CheckedMutation, OwnedFinalCheck};
use crate::store::{LocalFs, StoreErrorKind, StoreFailure};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use terrane_core::bucket::{BucketKey, Mutability};
use terrane_core::gc::publication::{
    PortableCurrent, PortableSnapshot, PredecessorSlot, ProjectionEntry, PublicationCommit,
    PublicationTransaction, RawDigest,
};

/// Reports fixed selected bytes after the actual retained lane acknowledges them.
pub(crate) struct CheckedPublication {
    /// The revision installed in the protected consecutive create-once slot.
    pub(crate) revision: u64,
    /// The raw digest of that exact canonical commit record.
    pub(crate) digest: RawDigest,
}

/// Owns the complete physical refresh data for one sealed held operation.
///
/// Every command duplicates this projection into its submitted worker. The
/// asynchronous owner can disappear without releasing that worker's exclusions.
struct Frame {
    exclusions: Arc<[NativeExclusion]>,
    names: Vec<NamedFence>,
    reads: Vec<ExactRead>,
    parents: BTreeMap<PathBuf, (MetadataStamp, u32)>,
    final_check: Option<OwnedFinalCheck>,
    owner: u32,
    writes: Option<CompletedWrites>,
}

/// Records completed targets, the new candidate log and required current controls.
///
/// This inventory is ordinary derived data. It supplies no permission, excludes
/// temporary names consumed by rename, and never replaces retained preimages.
/// The checked producer also retains the exact newly selected log after its
/// actual body and whole predecessor association have passed existing checks.
/// Current Original rows come from the retained opaque candidate context; other
/// producers retain all consumed administrative rows conservatively.
#[derive(Clone)]
pub(super) struct CompletedWrites {
    records: BTreeMap<PathBuf, CompletedWrite>,
}

/// Retains one final record body or removal under its actual root policy.
#[derive(Clone)]
pub(super) struct CompletedWrite {
    root: PathBuf,
    policy: FencePolicy,
    expected: Option<Vec<u8>>,
}

impl CompletedWrites {
    /// Iterates final completed targets by their exact native paths.
    pub(super) fn records(&self) -> impl Iterator<Item = (&PathBuf, &CompletedWrite)> {
        self.records.iter()
    }
}

impl CompletedWrite {
    /// Borrows the genuine namespace or control boundary of the completed write.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the retained payload or protected-record ownership policy.
    pub(super) fn policy(&self) -> FencePolicy {
        self.policy
    }

    /// Borrows the final body, or returns absence for a completed removal.
    pub(super) fn expected(&self) -> Option<&[u8]> {
        self.expected.as_deref()
    }
}

fn corrupt() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Corrupt(
        crate::store::CorruptSubject::RefName("publication".into()),
    ))
}

fn unsupported() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unsupported)
}

fn io_failure(error: std::io::Error) -> StoreFailure {
    if error.kind() == std::io::ErrorKind::Unsupported {
        StoreFailure::with_source(StoreErrorKind::Unsupported, error)
    } else {
        StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
    }
}

fn native_failure(error: NativeEffectFailure) -> StoreFailure {
    match error {
        NativeEffectFailure::Rejected(error) => error,
        NativeEffectFailure::Io(error) => io_failure(error),
    }
}

fn digest(bytes: &[u8]) -> RawDigest {
    *blake3::hash(bytes).as_bytes()
}

fn duplicate(receipt: &NativeExclusion) -> Result<NativeExclusion, StoreFailure> {
    // This is the private descendant of the executor. Only a receipt already
    // captured from an actual acquired exclusion reaches this descriptor.
    Ok(NativeExclusion {
        file: receipt.file.try_clone().map_err(io_failure)?,
    })
}

fn copy_parents(parents: &[ParentFence]) -> Vec<ParentFence> {
    parents
        .iter()
        .map(|parent| ParentFence {
            path: parent.path.clone(),
            stamp: parent.stamp,
        })
        .collect()
}

/// Captures genuine controls and selected inputs without deriving new authority.
///
/// Both selected publication and native content staging retain the same exact
/// physical evidence. The supplied context has only closed producer factories.
///
/// # Errors
/// Preserves actual descriptor/owner/ancestor/record checks and refuses changed
/// or unavailable selected/control inputs or expired retained request checks.
async fn contextual_frame<F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &SelectedObservation<'_>,
    sources: &[&SelectedObservation<'_>],
    context: &crate::selected_bridge::native_guard::GuardEffectContext,
) -> Result<(Frame, PathBuf), StoreFailure> {
    if !observed.identity().writable() {
        return Err(unsupported());
    }
    let controls = context.controls();
    let owner = observed.configured_operator_uid();
    if controls.first().ok_or_else(unsupported)?.owner() != owner {
        return Err(corrupt());
    }
    let mut exclusions = vec![duplicate(observed.identity().retained_namespace()?)?];
    for source in sources {
        exclusions.push(duplicate(source.identity().retained_namespace()?)?);
    }
    let mut control_descriptors = Vec::with_capacity(controls.len());
    for retained in controls {
        let start = exclusions.len();
        for exclusion in retained.exclusions().iter() {
            exclusions.push(duplicate(exclusion)?);
        }
        if exclusions.len() == start {
            return Err(unsupported());
        }
        control_descriptors.push(start..exclusions.len());
    }
    let mut frame = Frame {
        exclusions: exclusions.into(),
        names: Vec::new(),
        reads: Vec::new(),
        parents: BTreeMap::new(),
        final_check: Some(context.final_check()),
        owner,
        writes: Some(CompletedWrites {
            records: BTreeMap::new(),
        }),
    };

    for retained in controls {
        let control_owner = retained.owner();
        for ancestor in retained.ancestors() {
            let metadata = fs
                .symlink_metadata(ancestor.path())
                .await
                .map_err(io_failure)?;
            let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
            FencePolicy::ProtectedAncestor {
                owner: control_owner,
            }
            .validate(stamp)
            .map_err(io_failure)?;
            if stamp.identity != ancestor.identity()
                || (stamp.owner, stamp.mode & 0o7777) != ancestor.protection()
                || frame
                    .parents
                    .get(ancestor.path())
                    .is_some_and(|(previous, _)| !stamp.same_incarnation(*previous))
            {
                return Err(corrupt());
            }
            frame
                .parents
                .insert(ancestor.path().to_owned(), (stamp, control_owner));
        }
    }
    let control = frame.observation(fs, observed, 0).await?;
    for (index, source) in sources.iter().enumerate() {
        frame.observation(fs, source, index + 1).await?;
    }
    for retained in context.selected_reads() {
        let read = retained.record();
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::ProtectedRecord {
                    owner: retained.owner(),
                },
            )
            .await?;
    }
    for read in context.existing_reads() {
        if let Some(retained) = read.retained_payload() {
            frame.retained_payload_read(retained)?;
        } else {
            frame
                .observed_read(
                    fs,
                    read.path(),
                    read.bytes(),
                    read.metadata(),
                    FencePolicy::Payload { owner },
                )
                .await?;
        }
    }
    // Each submitted worker owns every descriptor, including independent
    // source configuration locks. Cancellation cannot release those inputs.
    for (retained, descriptors) in controls.iter().zip(control_descriptors) {
        let control_owner = retained.owner();
        let (directory_identity, lock_identity) = retained.identities();
        frame
            .name(
                fs,
                retained.directory().to_owned(),
                directory_identity,
                FencePolicy::PrivateControlDirectory {
                    owner: control_owner,
                },
                None,
            )
            .await?;
        for descriptor in descriptors {
            frame
                .name(
                    fs,
                    retained.directory().join("retention.lock"),
                    lock_identity,
                    FencePolicy::ProtectedRecord {
                        owner: control_owner,
                    },
                    Some(descriptor),
                )
                .await?;
        }
        for record in retained.records() {
            let metadata = fs
                .symlink_metadata(record.path())
                .await
                .map_err(io_failure)?;
            if MetadataStamp::checked(&metadata)
                .map_err(io_failure)?
                .identity
                != record.identity()
            {
                return Err(corrupt());
            }
            frame
                .observed_read(
                    fs,
                    record.path(),
                    Some(record.bytes()),
                    Some(&metadata),
                    FencePolicy::ProtectedRecord {
                        owner: control_owner,
                    },
                )
                .await?;
        }
    }

    // Candidate authoring can just have retained new Original rows through
    // generic adapters. Its opaque checked context fixes the exact current pins.
    // Other closed producers can have written imports or current setup rows;
    // conservatively retain every consumed row until they own a write inventory.
    let current_original = context.publication_original();
    let current_pins = current_original
        .map(crate::guard::publication_original_pins)
        .transpose()?;
    let mut retained_current_pins = 0;
    for retained in controls {
        for record in retained.records() {
            let include = match (&current_pins, current_original) {
                (Some(pins), Some(_)) => {
                    // The genuine context can retain an imported original under
                    // the destination owner. Match its actual derived pin owner,
                    // rather than the foreign original baseline's control path.
                    if let Some(pin) = pins.iter().find(|pin| {
                        matches!(
                            &pin.owner,
                            terrane_core::gc::publication::evidence::PhysicalRegistration::Local(owner)
                                if owner.control.as_slice()
                                    == retained.directory().as_os_str().as_encoded_bytes()
                        ) && retained.directory().join(&pin.key) == record.path()
                    }) {
                        pin.check_record(record.bytes()).map_err(|_| corrupt())?;
                        retained_current_pins += 1;
                        true
                    } else {
                        false
                    }
                }
                (None, None) => true,
                _ => return Err(corrupt()),
            };
            if include {
                frame
                    .writes
                    .as_mut()
                    .ok_or_else(unsupported)?
                    .records
                    .insert(
                        record.path().to_owned(),
                        CompletedWrite {
                            root: retained.directory().to_owned(),
                            policy: FencePolicy::ProtectedRecord {
                                owner: retained.owner(),
                            },
                            expected: Some(record.bytes().to_vec()),
                        },
                    );
            }
        }
    }
    if current_pins
        .as_ref()
        .is_some_and(|pins| pins.len() != retained_current_pins)
    {
        return Err(corrupt());
    }

    Ok((frame, control))
}

/// Publishes only fixed data carried by the genuine checked producer.
///
/// # Errors
/// Rejects absent native retention, changed physical/control preimages, expired
/// authority and failed durable effects. An error after slot dispatch can mean
/// that selection succeeded and its portable acknowledgment remains incomplete.
pub(crate) async fn publish_checked<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedMutation<'_, '_>,
) -> Result<CheckedPublication, StoreFailure> {
    let context = checked.effect_context().ok_or_else(unsupported)?;
    let observed = checked.observed();
    let (mut frame, control) = contextual_frame(fs, observed, checked.sources(), context).await?;
    let owner = frame.owner;

    if let Some(reads) = checked.requalification_history_reads() {
        if reads.is_empty() {
            return Err(corrupt());
        }
        for read in reads {
            if !read.path().starts_with(observed.identity().root()) {
                return Err(corrupt());
            }
            let bytes = read.bytes().ok_or_else(corrupt)?;
            frame
                .observed_read(
                    fs,
                    read.path(),
                    Some(bytes),
                    read.metadata(),
                    FencePolicy::Payload { owner },
                )
                .await?;
            // These are existing selected immutable logs, not a fabricated new
            // candidate. Their actual bodies and directories also receive sync.
            frame
                .writes
                .as_mut()
                .ok_or_else(unsupported)?
                .records
                .insert(
                    read.path().to_owned(),
                    CompletedWrite {
                        root: observed.identity().root().to_owned(),
                        policy: FencePolicy::Payload { owner },
                        expected: Some(bytes.to_vec()),
                    },
                );
        }
    } else if let Some(bytes) = checked.lineage() {
        use terrane_core::gc::publication::{CommittedSelection, evidence::CheckedLineage};
        use terrane_core::refs::RefLogRecord;

        let lineage = CheckedLineage::decode(bytes).map_err(|_| corrupt())?;
        let candidate = lineage.source.candidate_id.ok_or_else(corrupt)?;
        let key = BucketKey::reflog_candidate(&lineage.source_name, lineage.source.seq, &candidate)
            .map_err(|_| corrupt())?;
        let bytes = frame
            .actual_read(
                fs,
                &observed.identity().root().join(key.as_str()),
                FencePolicy::Payload { owner },
            )
            .await?
            .ok_or_else(corrupt)?;
        let log = RefLogRecord::decode(&bytes).map_err(|_| corrupt())?;
        let change = checked
            .changes()
            .iter()
            .find(|row| row.key == format!("{}:record", lineage.source_name))
            .ok_or_else(corrupt)?;
        let previous = change
            .expected
            .as_deref()
            .map(terrane_core::refs::RefRecord::decode)
            .transpose()
            .map_err(|_| corrupt())?;
        log.validate_candidate(previous.as_ref(), &lineage.source)
            .map_err(|_| corrupt())?;
        let retained = observed
            .state()
            .branches
            .iter()
            .find(|row| row.name == lineage.source_name)
            .map(|row| &row.selection);
        let retained = match retained {
            Some(CommittedSelection::Selected(record)) => Some(record.as_ref()),
            Some(CommittedSelection::Unknown) => return Err(corrupt()),
            _ => None,
        };
        if log.selected_previous().map_err(|_| corrupt())? != retained {
            return Err(corrupt());
        }
        // This staged log participates in the new selected lineage. Its fixed
        // native staging result alone cannot fill the final acknowledgment.
        frame
            .writes
            .as_mut()
            .ok_or_else(unsupported)?
            .records
            .insert(
                observed.identity().root().join(key.as_str()),
                CompletedWrite {
                    root: observed.identity().root().to_owned(),
                    policy: FencePolicy::Payload { owner },
                    expected: Some(bytes),
                },
            );
    }

    // This check uses each actual borrowed backend before the first effect.
    // Submitted workers independently repeat the fixed full physical data.
    observed.revalidate().await?;
    for source in checked.sources() {
        source.revalidate().await?;
    }
    checked.recheck_before_slot()?;
    let root = observed.identity().root();
    #[cfg(all(test, feature = "tokio"))]
    if matches!(
        checked.proof(),
        terrane_core::gc::publication::PublicationProof::Candidate(_)
    ) {
        fs.before_candidate_projection_for_tests(root)
            .await
            .map_err(io_failure)?;
    }
    frame
        .project(fs, root, observed.snapshot(), observed.logical())
        .await?;

    let guard = digest(checked.guard_snapshot());
    frame
        .install(
            fs,
            &control,
            &format!("publication/guards/{}", hex(&guard)),
            checked.guard_snapshot(),
            FencePolicy::ProtectedRecord { owner },
            Mutability::Immutable,
        )
        .await?;
    if let Some(lineage) = checked.lineage() {
        frame
            .install(
                fs,
                &control,
                &format!("publication/lineage/{}", hex(&digest(lineage))),
                lineage,
                FencePolicy::ProtectedRecord { owner },
                Mutability::Immutable,
            )
            .await?;
    }
    for carried in checked.guard_carried_lineages() {
        checked.recheck_before_slot()?;
        let lineage = carried.lineage();
        frame
            .install(
                fs,
                &control,
                &format!("publication/lineage/{}", hex(&digest(lineage))),
                lineage,
                FencePolicy::ProtectedRecord { owner },
                Mutability::Immutable,
            )
            .await?;
    }
    let nonce: [u8; 32] = fs
        .random_bytes(32)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| unsupported())?;
    let operation = hex(&nonce);
    let snapshot = PortableSnapshot {
        revision: checked.next().revision,
        origin: checked.next().binding.clone(),
        projection: checked
            .changes()
            .iter()
            .filter(|row| projectable(&row.key))
            .map(|row| ProjectionEntry {
                key: row.key.clone(),
                value: if row.key == "gc/lease" {
                    None
                } else {
                    row.new.clone()
                },
            })
            .collect(),
        predecessor: Some(observed.snapshot().clone()),
    };
    let snapshot_bytes = snapshot.encode().map_err(|_| corrupt())?;
    let pointer = PortableCurrent {
        key: format!(
            "publication/snapshots/{}:{operation}",
            checked.next().revision
        ),
        digest: digest(&snapshot_bytes),
    };
    let transaction = PublicationTransaction {
        nonce,
        old: Some(observed.state().clone()),
        new: checked.next().clone(),
        changes: checked.changes().to_vec(),
        proof: checked.proof(),
        predecessor: Some(PredecessorSlot {
            revision: observed.stamp().0,
            digest: observed.stamp().1,
        }),
        snapshot: pointer.clone(),
    };
    transaction
        .check_snapshot(&snapshot_bytes)
        .map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            root,
            &pointer.key,
            &snapshot_bytes,
            FencePolicy::Payload { owner },
            Mutability::Immutable,
        )
        .await?;
    let transaction_key = format!("publication/transactions/{operation}");
    transaction
        .check_key(&transaction_key)
        .map_err(|_| corrupt())?;
    let transaction_bytes = transaction.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            &control,
            &transaction_key,
            &transaction_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::Immutable,
        )
        .await?;

    // The slot is the only selected-state linearization. Its native worker
    // repeats every consumed canonical control, selected exact read and actual
    // retained descriptor after staging and immediately before the syscall.
    let slot = PublicationCommit {
        revision: checked.next().revision,
        predecessor: Some(observed.stamp().1),
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    };
    let slot_bytes = slot.encode().map_err(|_| corrupt())?;
    frame
        .install(
            fs,
            &control,
            &format!("publication/commits/{}", slot.revision),
            &slot_bytes,
            FencePolicy::ProtectedRecord { owner },
            Mutability::CreateOnce,
        )
        .await?;

    let mut logical = observed.logical().clone();
    for change in checked.changes() {
        logical.insert(change.key.clone(), change.new.clone());
    }
    frame.project(fs, root, &pointer, &logical).await?;
    frame
        .execute(
            fs,
            Plan::SyncDirectory {
                path: root.to_owned(),
            },
        )
        .await?;
    let (acknowledgment, completed) = super::artifact_seal::mutation_publication::mutation_plan(
        checked,
        &slot,
        &transaction,
        &snapshot_bytes,
        frame.writes.as_ref().ok_or_else(unsupported)?,
    )
    .map_err(native_failure)?;
    frame.execute(fs, acknowledgment).await?;
    completed.take().map_err(native_failure)?;

    Ok(CheckedPublication {
        revision: slot.revision,
        digest: digest(&slot_bytes),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn projectable(key: &str) -> bool {
    matches!(
        key,
        "CAPABILITIES" | "publication/SELECTED-HISTORY" | "gc/lease"
    ) || key.starts_with("refs/")
        || key.starts_with("objects/index/")
}
