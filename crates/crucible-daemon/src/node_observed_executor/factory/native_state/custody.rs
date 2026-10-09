//! Finite native fallback custody with an independently live cleanup worker.
//!
//! Every slot exists before gem5 allocation. A consumed native slot transfers
//! the entire original capsule to the worker; process-group proof permits
//! resource retirement, never modeled settlement or a replacement generation.

use std::{
    fs::File,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::Duration,
};

use crucible::node_contract::{ActivationRecord, NativeCaptureArtifact, OwnerIdentity};
use crucible::node_state::{NativeArchiveRecord, PublicationKnowledge};
use crucible_node_contract::ContentRef;
use crucible_node_provider::gem5::{Gem5CustodySlot, Gem5NativeCustody};

/// Reports failed finite native custody preparation without losing resources.
#[derive(Debug, thiserror::Error)]
pub(super) enum NativeCustodyError {
    #[error("{0}")]
    Refused(&'static str),
    #[error("bounded native custody allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("native cleanup worker could not start: {0}")]
    Worker(#[from] std::io::Error),
}

/// Preserves original whole-world publication knowledge alongside native custody.
pub(super) struct NativeOwnerScope {
    pub(super) activation: ActivationRecord,
    pub(super) owner: OwnerIdentity,
    pub(super) publication: PublicationKnowledge,
    pub(super) backing: NativeBacking,
}

/// Pins actual original source files through every native use and cleanup.
pub(super) enum NativeBacking {
    /// Holds independently installed input descriptors for a fresh native launch.
    Fresh { files: Vec<File> },
    /// Holds the sealed archive and complete verified captured descriptor roster.
    Archived {
        source: Box<NativeArchiveRecord>,
        artifacts: Vec<NativeCaptureArtifact>,
    },
}

impl NativeBacking {
    fn validate(&self, scope: &NativeOwnerScope) -> Result<(), NativeCustodyError> {
        let descriptors = match self {
            Self::Fresh { files } => files.len(),
            Self::Archived { source, artifacts } => {
                if source.manifest().world_binding_hash != scope.activation.world_binding_hash
                    || !source
                        .owners()
                        .iter()
                        .any(|owner| owner.owner == scope.owner.owner)
                {
                    return Err(NativeCustodyError::Refused(
                        "native backing names another original world or capture owner",
                    ));
                }
                artifacts.len()
            }
        };
        if descriptors > 8193 {
            return Err(NativeCustodyError::Refused(
                "native backing exceeds the installed descriptor roster",
            ));
        }
        Ok(())
    }
}

/// Returns original quarantined state after authentic native group reclamation.
///
/// Original journals, image backing and publication uncertainty remain owned.
/// The recipient must preserve those obligations; the proof does not authorize
/// output discard, operation replay or a replacement activation.
#[cfg(test)]
pub(super) struct ReclaimedGem5Custody {
    pub(super) scope: NativeOwnerScope,
    pub(super) custody: Gem5NativeCustody,
    pub(super) evidence: ContentRef,
    pub(super) bytes: Vec<u8>,
}

struct Entry {
    scope: NativeOwnerScope,
    custody: Option<Gem5NativeCustody>,
    in_flight: bool,
    proof: Option<(ContentRef, Vec<u8>)>,
    failure: String,
}

struct Registry {
    slots: Vec<Option<Entry>>,
    accepting: bool,
    shutdown: bool,
}

struct Shared {
    registry: Mutex<Registry>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Registry> {
        self.registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

struct QueueOwner {
    shared: Arc<Shared>,
}

impl Drop for QueueOwner {
    fn drop(&mut self) {
        let mut registry = self.shared.lock();
        registry.accepting = false;
        registry.shutdown = true;
        drop(registry);
        self.shared.changed.notify_one();
    }
}

/// Reserves a bounded native fallback roster before allocating any child.
///
/// The cleanup worker retains its own shared registry and survives actor unwind
/// or disappearance. It services containment only, never modeled execution.
#[derive(Clone)]
pub(super) struct Gem5CustodyQueue {
    owner: Arc<QueueOwner>,
}

impl Gem5CustodyQueue {
    /// Checks original kernel proofs without consuming their retained journals.
    pub(super) fn all_groups_reclaimed(&self) -> bool {
        self.owner
            .shared
            .lock()
            .slots
            .iter()
            .flatten()
            .all(|entry| !entry.in_flight && entry.custody.is_some() && entry.proof.is_some())
    }

    /// Reads only the original reserved activation's publication knowledge.
    pub(super) fn publication_knowledge(
        &self,
        activation: &ActivationRecord,
    ) -> Result<PublicationKnowledge, NativeCustodyError> {
        self.owner
            .shared
            .lock()
            .slots
            .iter()
            .flatten()
            .find(|entry| entry.scope.activation == *activation)
            .map(|entry| entry.scope.publication)
            .ok_or(NativeCustodyError::Refused(
                "original native activation reservation is absent",
            ))
    }

    /// Returns the one process-lifetime installed native supervisor.
    ///
    /// Actor and world factories share this queue. Losing every actor borrower
    /// cannot create a second cleanup thread or reset the global reservation
    /// budget; authenticated journals stay owned by the installed sink.
    ///
    /// # Errors
    /// Refuses a changed installed capacity or failed initial allocation.
    pub(super) fn installed(capacity: usize) -> Result<Self, NativeCustodyError> {
        static INSTALLED: Mutex<Option<Gem5CustodyQueue>> = Mutex::new(None);
        let mut installed = INSTALLED.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(queue) = installed.as_ref() {
            if queue.owner.shared.lock().slots.len() != capacity {
                return Err(NativeCustodyError::Refused(
                    "installed native custody capacity cannot change between actors",
                ));
            }
            return Ok(queue.clone());
        }
        let queue = Self::new(capacity)?;
        *installed = Some(queue.clone());
        Ok(queue)
    }

    /// Checks actual original-group proof without transferring or discarding journals.
    pub(super) fn original_group_reclaimed(
        &self,
        target: &ActivationRecord,
    ) -> Result<bool, NativeCustodyError> {
        let registry = self.owner.shared.lock();
        let original = registry
            .slots
            .iter()
            .flatten()
            .find(|entry| entry.scope.activation == *target)
            .ok_or(NativeCustodyError::Refused(
                "original native reservation is unavailable for reclamation",
            ))?;
        Ok(!original.in_flight && original.custody.is_some() && original.proof.is_some())
    }

    /// Starts one owning cleanup worker and reserves every native slot.
    ///
    /// # Errors
    /// Refuses zero/excessive capacity, unavailable bounded allocation or failure
    /// to start the cleanup worker before any native resource can be allocated.
    pub(super) fn new(capacity: usize) -> Result<Self, NativeCustodyError> {
        if capacity == 0 || capacity > 64 {
            return Err(NativeCustodyError::Refused(
                "native cleanup capacity must be between one and 64",
            ));
        }
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        slots.resize_with(capacity, || None);
        let shared = Arc::new(Shared {
            registry: Mutex::new(Registry {
                slots,
                accepting: true,
                shutdown: false,
            }),
            changed: Condvar::new(),
        });
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name("gem5-native-cleanup".into())
            .spawn(move || cleanup(worker))?;
        Ok(Self {
            owner: Arc::new(QueueOwner { shared }),
        })
    }

    /// Reserves one original owner and publication record before native spawn.
    ///
    /// # Errors
    /// Refuses a foreign owner, stopped admission or exhausted finite capacity.
    pub(super) fn reserve(
        &self,
        scope: NativeOwnerScope,
    ) -> Result<Box<dyn Gem5CustodySlot>, NativeCustodyError> {
        if !scope.activation.owners.contains(&scope.owner) {
            return Err(NativeCustodyError::Refused(
                "native reservation owner is outside the original activation",
            ));
        }
        scope.backing.validate(&scope)?;
        let mut registry = self.owner.shared.lock();
        if !registry.accepting {
            return Err(NativeCustodyError::Refused(
                "native cleanup admission is closed",
            ));
        }
        if registry
            .slots
            .iter()
            .flatten()
            .any(|entry| entry.scope.owner == scope.owner)
        {
            return Err(NativeCustodyError::Refused(
                "original native owner incarnation already has reserved custody",
            ));
        }
        let index =
            registry
                .slots
                .iter()
                .position(Option::is_none)
                .ok_or(NativeCustodyError::Refused(
                    "native cleanup reservation is exhausted",
                ))?;
        let mut failure = String::new();
        failure.try_reserve_exact(1024)?;
        registry.slots[index] = Some(Entry {
            scope,
            custody: None,
            in_flight: false,
            proof: None,
            failure,
        });
        Ok(Box::new(Slot {
            shared: Arc::clone(&self.owner.shared),
            index,
            transferred: false,
        }))
    }

    /// Authenticates a locally owned inactive restore reservation without readiness.
    ///
    /// The archive argument must match the sealed source retained by the actual
    /// reserved entry. This check grants neither a child identity nor a native
    /// certificate; fresh preparation must prove those after capsule installation.
    ///
    /// # Errors
    /// Refuses an absent lease, another original source or target generation,
    /// attempted publication, already transferred native resources or reclamation.
    pub(super) fn verify_reserved_restore(
        &self,
        activation: &ActivationRecord,
        owner: &OwnerIdentity,
        source: &NativeArchiveRecord,
    ) -> Result<(), NativeCustodyError> {
        let registry = self.owner.shared.lock();
        let entry = registry
            .slots
            .iter()
            .flatten()
            .find(|entry| &entry.scope.activation == activation && &entry.scope.owner == owner)
            .ok_or(NativeCustodyError::Refused(
                "fresh native restore lease is not reserved",
            ))?;
        if entry.scope.publication != PublicationKnowledge::NotAttempted
            || entry.custody.is_some()
            || entry.in_flight
            || entry.proof.is_some()
        {
            return Err(NativeCustodyError::Refused(
                "fresh native lease is no longer inactive",
            ));
        }
        match &entry.scope.backing {
            NativeBacking::Archived {
                source: original, ..
            } if original.artifact() == source.artifact()
                && original.manifest() == source.manifest()
                && original.owners() == source.owners() =>
            {
                Ok(())
            }
            _ => Err(NativeCustodyError::Refused(
                "fresh native lease owns another sealed source",
            )),
        }
    }

    /// Returns the number of reserved, retained or reclaimed original capsules.
    #[cfg(test)]
    pub(super) fn reserved_owners(&self) -> usize {
        self.owner.shared.lock().slots.iter().flatten().count()
    }

    /// Retains publication knowledge for the exact original activation only.
    ///
    /// This reports the existing publisher/barrier result; it grants no native
    /// permission. A committed record is permanent and cannot be downgraded.
    ///
    /// # Errors
    /// Refuses an unknown original activation or a committed-record downgrade.
    pub(super) fn record_publication(
        &self,
        activation: &ActivationRecord,
        publication: PublicationKnowledge,
    ) -> Result<(), NativeCustodyError> {
        let mut registry = self.owner.shared.lock();
        let mut found = false;
        for entry in registry.slots.iter().flatten() {
            if &entry.scope.activation != activation {
                continue;
            }
            found = true;
            if entry.scope.publication == PublicationKnowledge::Committed
                && publication != PublicationKnowledge::Committed
            {
                return Err(NativeCustodyError::Refused(
                    "original committed native activation cannot be downgraded",
                ));
            }
        }
        if !found {
            return Err(NativeCustodyError::Refused(
                "native publication names no original reserved activation",
            ));
        }
        for entry in registry.slots.iter_mut().flatten() {
            if &entry.scope.activation == activation {
                entry.scope.publication = publication;
            }
        }
        Ok(())
    }

    /// Moves authentic reclaimed capsules to their original owning supervisor.
    ///
    /// Removal requires the sealed child/group proof. Returned capsules keep
    /// original state and publication knowledge; this call grants no modeled
    /// settlement authority and does not discard their pending output or ACKs.
    ///
    /// # Errors
    /// Refuses failure to allocate the bounded return inventory before mutation.
    #[cfg(test)]
    pub(super) fn take_reclaimed(&self) -> Result<Vec<ReclaimedGem5Custody>, NativeCustodyError> {
        let mut registry = self.owner.shared.lock();
        let count = registry
            .slots
            .iter()
            .flatten()
            .filter(|entry| entry.proof.is_some())
            .count();
        let mut reclaimed = Vec::new();
        reclaimed.try_reserve_exact(count)?;
        for slot in &mut registry.slots {
            let complete = slot.as_ref().is_some_and(|entry| {
                entry.proof.is_some() && entry.custody.is_some() && !entry.in_flight
            });
            if !complete {
                continue;
            }
            if let Some(mut entry) = slot.take() {
                match (entry.custody.take(), entry.proof.take()) {
                    (Some(custody), Some((evidence, bytes))) => {
                        reclaimed.push(ReclaimedGem5Custody {
                            scope: entry.scope,
                            custody,
                            evidence,
                            bytes,
                        });
                    }
                    (custody, proof) => {
                        // Preserve the entire original entry if an internal
                        // invariant fails; an absent handle is never retirement.
                        entry.custody = custody;
                        entry.proof = proof;
                        *slot = Some(entry);
                    }
                }
            }
        }
        Ok(reclaimed)
    }
}

struct Slot {
    shared: Arc<Shared>,
    index: usize,
    transferred: bool,
}

impl Gem5CustodySlot for Slot {
    fn retain(mut self: Box<Self>, custody: Gem5NativeCustody) {
        let mut registry = self.shared.lock();
        if let Some(entry) = registry.slots[self.index].as_mut() {
            let original = &entry.scope.owner;
            if custody.launch.owner != original.owner
                || custody.launch.incarnation != original.incarnation
                || custody.launch.generation != original.generation
            {
                entry
                    .failure
                    .push_str("native callback differs from its original reserved owner");
                registry.accepting = false;
            }
        }
        // Only this consumed slot can install its original capsule. Reserved
        // slots remain present until their slot is consumed or dropped unused.
        if let Some(entry) = registry.slots[self.index].as_mut() {
            entry.custody = Some(custody);
        }
        self.transferred = true;
        drop(registry);
        self.shared.changed.notify_one();
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if !self.transferred {
            let mut registry = self.shared.lock();
            registry.slots[self.index] = None;
        }
        self.shared.changed.notify_one();
    }
}

fn cleanup(shared: Arc<Shared>) {
    loop {
        let turn = catch_unwind(AssertUnwindSafe(|| cleanup_turn(&shared)));
        if matches!(turn, Ok(true)) {
            return;
        }
        if turn.is_err() {
            shared.lock().accepting = false;
        }
        let registry = shared.lock();
        let _ = shared
            .changed
            .wait_timeout(registry, Duration::from_millis(10));
    }
}

/// Owns a taken capsule while its permanently reserved registry slot remains.
///
/// Native callbacks run outside the registry mutex. Unwind returns the same
/// capsule to the original slot before another cleanup turn can inspect it.
struct CleanupLease {
    shared: Arc<Shared>,
    index: usize,
    custody: Option<Gem5NativeCustody>,
}

impl Drop for CleanupLease {
    fn drop(&mut self) {
        let mut registry = self.shared.lock();
        if let Some(entry) = registry.slots[self.index].as_mut() {
            entry.custody = self.custody.take();
            entry.in_flight = false;
        }
    }
}

fn cleanup_turn(shared: &Arc<Shared>) -> bool {
    let capacity = shared.lock().slots.len();
    for index in 0..capacity {
        let custody = {
            let mut registry = shared.lock();
            let Some(entry) = registry.slots[index].as_mut() else {
                continue;
            };
            if entry.proof.is_some() || entry.in_flight {
                continue;
            }
            let Some(custody) = entry.custody.take() else {
                continue;
            };
            entry.in_flight = true;
            custody
        };
        let mut lease = CleanupLease {
            shared: Arc::clone(shared),
            index,
            custody: Some(custody),
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            let Some(custody) = lease.custody.as_mut() else {
                return Ok(None);
            };
            custody.begin_quarantine()?;
            let Some(proof) = custody.poll_reclamation()? else {
                return Ok(None);
            };
            let (reference, bytes) = proof.evidence();
            if bytes.len() > 64 * 1024 {
                return Err(crucible_node_provider::ProviderError::ResourceExhausted(
                    "native cleanup proof retention",
                ));
            }
            let mut retained = Vec::new();
            retained.try_reserve_exact(bytes.len()).map_err(|_| {
                crucible_node_provider::ProviderError::ResourceExhausted(
                    "native cleanup proof allocation",
                )
            })?;
            retained.extend_from_slice(bytes);
            Ok(Some((reference.clone(), retained)))
        }));
        let mut registry = shared.lock();
        if let Some(entry) = registry.slots[index].as_mut() {
            match result {
                Ok(Ok(Some(proof))) => entry.proof = Some(proof),
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    entry.failure.clear();
                    entry.failure.extend(error.to_string().chars().take(512));
                }
                Err(_) => {
                    entry.failure.clear();
                    entry
                        .failure
                        .push_str("original native cleanup callback unwound");
                }
            }
        }
        drop(registry);
        drop(lease);
    }
    // An orphaned original journal remains owned even after native reaping.
    // Only an explicit transfer to its original supervisor frees a slot.
    let registry = shared.lock();
    registry.shutdown && registry.slots.iter().all(Option::is_none)
}

#[cfg(test)]
mod tests {
    // These fixtures panic when a finite reservation or metadata invariant fails.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crucible_node_contract::{Id, Phase, Position, U64, canonical};

    fn scope() -> NativeOwnerScope {
        let owner = OwnerIdentity {
            owner: Id::new("cpu-owner").unwrap(),
            incarnation: Id::new("native/source").unwrap(),
            generation: U64::new(1),
        };
        NativeOwnerScope {
            activation: ActivationRecord {
                generation: U64::new(1),
                activation_id: Id::new("world/source").unwrap(),
                world_binding_hash: canonical::json_hash(
                    "cnp.world-binding.v1",
                    &serde_json::json!({"fixture":1}),
                )
                .unwrap(),
                owners: vec![owner.clone()],
                boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
            },
            owner,
            publication: PublicationKnowledge::NotAttempted,
            backing: NativeBacking::Fresh { files: vec![] },
        }
    }

    #[test]
    fn finite_slot_is_reserved_before_native_allocation_and_released_unused() {
        let queue = Gem5CustodyQueue::new(1).unwrap();
        let first = queue.reserve(scope()).unwrap();
        assert_eq!(queue.reserved_owners(), 1);
        assert!(matches!(
            queue.reserve(scope()),
            Err(NativeCustodyError::Refused(_))
        ));
        assert!(queue.take_reclaimed().unwrap().is_empty());

        drop(first);
        assert_eq!(queue.reserved_owners(), 0);
        let second = queue.reserve(scope()).unwrap();
        assert_eq!(queue.reserved_owners(), 1);
        drop(second);
        assert_eq!(queue.reserved_owners(), 0);
    }

    #[test]
    fn duplicate_native_incarnation_refuses_before_allocating_another_slot() {
        let queue = Gem5CustodyQueue::new(2).unwrap();
        let first = queue.reserve(scope()).unwrap();
        assert!(queue.reserve(scope()).is_err());
        assert_eq!(queue.reserved_owners(), 1);

        drop(first);
        assert_eq!(queue.reserved_owners(), 0);
    }

    #[test]
    fn original_publication_metadata_never_rebases_or_downgrades_commit() {
        let queue = Gem5CustodyQueue::new(1).unwrap();
        let original = scope().activation;
        let slot = queue.reserve(scope()).unwrap();
        queue
            .record_publication(&original, PublicationKnowledge::Unknown)
            .unwrap();
        let mut replacement = original.clone();
        replacement.generation = U64::new(2);
        assert!(
            queue
                .record_publication(&replacement, PublicationKnowledge::Committed)
                .is_err()
        );
        assert_eq!(
            queue.owner.shared.lock().slots[0]
                .as_ref()
                .unwrap()
                .scope
                .publication,
            PublicationKnowledge::Unknown
        );

        queue
            .record_publication(&original, PublicationKnowledge::Committed)
            .unwrap();
        assert!(
            queue
                .record_publication(&original, PublicationKnowledge::Unknown)
                .is_err()
        );
        assert_eq!(
            queue.owner.shared.lock().slots[0]
                .as_ref()
                .unwrap()
                .scope
                .activation,
            original
        );
        assert_eq!(
            queue.owner.shared.lock().slots[0]
                .as_ref()
                .unwrap()
                .scope
                .publication,
            PublicationKnowledge::Committed
        );
        drop(slot);
    }

    #[test]
    #[ignore = "requires the compiled source-built gem5 closed profile"]
    fn actor_unwind_transfers_actual_child_and_helpers_to_installed_supervisor() {
        use crucible_node_provider::gem5::{Gem5Launch, Gem5NativeProcess, Gem5ProcessImageTools};

        let installed = super::super::super::InstalledGem5ClosedProfile::built_in().unwrap();
        let directory = tempfile::tempdir().unwrap().keep();
        fs_private(&directory);
        let resource_root = directory.join("native");
        let image_root = directory.join("images");
        let temporary_root = directory.join("temporary");
        for path in [&resource_root, &image_root, &temporary_root] {
            std::fs::create_dir(path).unwrap();
            fs_private(path);
        }
        let launch = Gem5Launch {
            executable: installed.artifact("native_executable").unwrap(),
            owner_script: installed.artifact("controller").unwrap(),
            model_script: installed.artifact("model").unwrap(),
            guest: installed.guest("x86_64").unwrap(),
            guest_isa: "x86_64".into(),
            owner: scope().owner.owner,
            incarnation: scope().owner.incarnation,
            generation: scope().owner.generation,
            resource_root,
            timeout: Duration::from_secs(30),
            process_images: Some(Gem5ProcessImageTools {
                launcher: installed.artifact("dmtcp_launch").unwrap(),
                restarter: installed.artifact("dmtcp_restart").unwrap(),
                reconstruction_executable: installed.artifact("mtcp_restart").unwrap(),
                resource_helper: installed.artifact("image_guard").unwrap(),
                image_root,
                temporary_root,
            }),
        };
        let installed_queue = Gem5CustodyQueue::installed(8).unwrap();
        let actor_queue = Gem5CustodyQueue::installed(8).unwrap();
        assert!(Arc::ptr_eq(&installed_queue.owner, &actor_queue.owner));
        assert!(Gem5CustodyQueue::installed(9).is_err());
        let mut original = scope();
        original.publication = PublicationKnowledge::Unknown;
        original.backing = NativeBacking::Fresh {
            files: [
                &launch.executable,
                &launch.owner_script,
                &launch.model_script,
                &launch.guest,
            ]
            .into_iter()
            .map(|artifact| File::open(&artifact.path).unwrap())
            .collect(),
        };
        let original_activation = original.activation.clone();
        let original_owner = original.owner.clone();
        let slot = actor_queue.reserve(original).unwrap();
        assert!(actor_queue.reserve(scope()).is_err());
        let native = Gem5NativeProcess::spawn(launch, slot).unwrap();
        let original_pid = native.child_pid().unwrap();

        let failed_actor = catch_unwind(AssertUnwindSafe(move || {
            let _actor_queue = actor_queue;
            let _native = native;
            panic!("native actor failed after real child allocation");
        }));
        assert!(failed_actor.is_err());

        let mut original_custody = None;
        for _ in 0..3000 {
            let mut reclaimed = installed_queue.take_reclaimed().unwrap();
            if !reclaimed.is_empty() {
                original_custody = reclaimed.pop();
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut reclaimed =
            original_custody.expect("original native group must actually be reaped");
        assert_eq!(reclaimed.scope.activation, original_activation);
        assert_eq!(reclaimed.scope.owner, original_owner);
        assert_eq!(reclaimed.scope.publication, PublicationKnowledge::Unknown);
        assert_eq!(reclaimed.custody.child.id(), original_pid);
        assert!(reclaimed.custody.child.try_wait().unwrap().is_some());
        assert!(reclaimed.custody.completed.is_empty());
        assert!(reclaimed.custody.unresolved.is_none());
        assert!(reclaimed.custody.pending.is_none());
        assert!(reclaimed.custody.last_acknowledged.is_none());
        reclaimed.evidence.verify(&reclaimed.bytes).unwrap();
        match &reclaimed.scope.backing {
            NativeBacking::Fresh { files } => assert_eq!(files.len(), 4),
            NativeBacking::Archived { .. } => panic!("fresh launch cannot acquire archive lineage"),
        }
        assert_eq!(installed_queue.reserved_owners(), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn fs_private(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
