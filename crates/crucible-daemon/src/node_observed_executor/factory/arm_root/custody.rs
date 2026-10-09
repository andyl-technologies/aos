//! Reserves one process-lifetime Root supervisor before native allocation.
//!
//! Reaped capsules remain retained with original raw journals and source backing.
//! Kernel reclamation never settles output, frees logical history or mints a new
//! generation. Cleanup moves the same capsule outside the registry lock and an
//! unwind guard always returns it to its permanently reserved original entry.

use std::{
    fs::File,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::Duration,
};

use crucible::{
    node_contract::{ActivationRecord, NativeCaptureArtifact, OwnerIdentity},
    node_state::{NativeArchiveRecord, PublicationKnowledge},
};
use crucible_node_provider::gem5::{ArmRootCustodySlot, ArmRootNativeCustody};

use super::super::{NodeObservedError, refused};

pub(super) enum RootBacking {
    Fresh(Vec<File>),
    Archived {
        source: Box<NativeArchiveRecord>,
        artifacts: Vec<NativeCaptureArtifact>,
    },
}

pub(super) struct RootScope {
    pub(super) activation: ActivationRecord,
    pub(super) owner: OwnerIdentity,
    pub(super) publication: PublicationKnowledge,
    pub(super) backing: RootBacking,
}

struct Entry {
    scope: RootScope,
    custody: Option<ArmRootNativeCustody>,
    in_flight: bool,
    reclaimed: bool,
    failed: bool,
}

struct Registry {
    slots: Vec<Option<Entry>>,
    accepting: bool,
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

#[derive(Clone)]
pub(super) struct RootCustodyQueue(Arc<Shared>);

impl RootCustodyQueue {
    pub(super) fn installed() -> Result<Self, NodeObservedError> {
        static INSTALLED: Mutex<Option<RootCustodyQueue>> = Mutex::new(None);
        let mut installed = INSTALLED.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(queue) = &*installed {
            return Ok(queue.clone());
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(8)
            .map_err(|_| refused("Root supervisor reservation is unavailable"))?;
        slots.resize_with(8, || None);
        let shared = Arc::new(Shared {
            registry: Mutex::new(Registry {
                slots,
                accepting: true,
            }),
            changed: Condvar::new(),
        });
        let worker = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("arm-root-native-cleanup".into())
            .spawn(move || cleanup(worker))
            .map_err(|error| refused(&error.to_string()))?;
        let queue = Self(shared);
        *installed = Some(queue.clone());
        Ok(queue)
    }

    pub(super) fn reserve(
        &self,
        scope: RootScope,
    ) -> Result<Box<dyn ArmRootCustodySlot>, NodeObservedError> {
        if !scope.activation.owners.contains(&scope.owner)
            || scope.publication != PublicationKnowledge::NotAttempted
        {
            return Err(refused(
                "Root reservation does not own an inactive target owner",
            ));
        }
        match &scope.backing {
            RootBacking::Fresh(files) if files.len() == 33 => {}
            RootBacking::Archived { source, artifacts }
                if source.manifest().world_binding_hash == scope.activation.world_binding_hash
                    && source
                        .owners()
                        .iter()
                        .any(|owner| owner.owner == scope.owner.owner)
                    && !artifacts.is_empty()
                    && artifacts.len() <= 8192 => {}
            _ => {
                return Err(refused(
                    "Root reservation lacks complete installed or signed original backing",
                ));
            }
        }
        let mut registry = self.0.lock();
        if !registry.accepting
            || registry
                .slots
                .iter()
                .flatten()
                .any(|old| old.scope.owner == scope.owner)
        {
            return Err(refused(
                "Root original owner is occupied or supervisor admission is closed",
            ));
        }
        let index = registry
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| refused("Root process-lifetime native custody credits are exhausted"))?;
        registry.slots[index] = Some(Entry {
            scope,
            custody: None,
            in_flight: false,
            reclaimed: false,
            failed: false,
        });
        Ok(Box::new(Slot {
            shared: Arc::clone(&self.0),
            index,
            transferred: false,
        }))
    }

    pub(super) fn verify_reserved(
        &self,
        activation: &ActivationRecord,
        owner: &OwnerIdentity,
        archive: &NativeArchiveRecord,
    ) -> Result<(), NodeObservedError> {
        let registry = self.0.lock();
        let entry = registry
            .slots
            .iter()
            .flatten()
            .find(|entry| &entry.scope.activation == activation && &entry.scope.owner == owner)
            .ok_or_else(|| refused("Root original image lease is not reserved"))?;
        if entry.custody.is_some()
            || entry.in_flight
            || entry.reclaimed
            || entry.failed
            || entry.scope.publication != PublicationKnowledge::NotAttempted
        {
            return Err(refused(
                "Root image reservation no longer owns unused inactive custody",
            ));
        }
        match &entry.scope.backing {
            RootBacking::Archived { source, .. }
                if source.artifact() == archive.artifact()
                    && source.manifest() == archive.manifest()
                    && source.owners() == archive.owners() =>
            {
                Ok(())
            }
            _ => Err(refused(
                "Root reserved image lease owns another signed source",
            )),
        }
    }

    // A signed archive roster has one pinned descriptor set for the installed
    // queue lifetime. Independent worlds borrow Arc-backed handles to that same
    // backing; retaining ownership does not require reopening each file.
    pub(super) fn retained_artifacts(
        &self,
        archive: &NativeArchiveRecord,
        owner: &crucible_node_contract::Id,
    ) -> Result<Option<Vec<NativeCaptureArtifact>>, NodeObservedError> {
        let registry = self.0.lock();
        for entry in registry.slots.iter().flatten() {
            let RootBacking::Archived { source, artifacts } = &entry.scope.backing else {
                continue;
            };
            if &entry.scope.owner.owner == owner
                && source.artifact() == archive.artifact()
                && source.manifest() == archive.manifest()
                && source.owners() == archive.owners()
            {
                return clone_artifacts(artifacts).map(Some);
            }
        }
        Ok(None)
    }

    pub(super) fn reserved_artifacts(
        &self,
        target: &ActivationRecord,
        owner: &OwnerIdentity,
        archive: &NativeArchiveRecord,
    ) -> Result<Vec<NativeCaptureArtifact>, NodeObservedError> {
        self.verify_reserved(target, owner, archive)?;
        self.retained_artifacts(archive, &owner.owner)?
            .ok_or_else(|| refused("Root reserved archive descriptors are absent"))
    }

    pub(super) fn record_publication(
        &self,
        target: &ActivationRecord,
        status: PublicationKnowledge,
    ) -> Result<(), NodeObservedError> {
        let mut registry = self.0.lock();
        let entry = registry
            .slots
            .iter_mut()
            .flatten()
            .find(|entry| &entry.scope.activation == target)
            .ok_or_else(|| refused("Root publication names no original reserved target"))?;
        if entry.scope.publication == PublicationKnowledge::Committed
            && status != PublicationKnowledge::Committed
        {
            return Err(refused("Root committed publication cannot be downgraded"));
        }
        entry.scope.publication = status;
        Ok(())
    }

    pub(super) fn publication_knowledge(
        &self,
        target: &ActivationRecord,
    ) -> Result<PublicationKnowledge, NodeObservedError> {
        self.0
            .lock()
            .slots
            .iter()
            .flatten()
            .find(|entry| &entry.scope.activation == target)
            .map(|entry| entry.scope.publication)
            .ok_or_else(|| refused("Root publication names no retained original target"))
    }

    #[cfg(test)]
    pub(super) fn all_groups_reclaimed(&self) -> bool {
        self.0
            .lock()
            .slots
            .iter()
            .flatten()
            .all(|entry| entry.reclaimed && !entry.in_flight && entry.custody.is_some())
    }

    pub(super) fn original_group_reclaimed(
        &self,
        target: &ActivationRecord,
    ) -> Result<bool, NodeObservedError> {
        let registry = self.0.lock();
        let entry = registry
            .slots
            .iter()
            .flatten()
            .find(|entry| &entry.scope.activation == target)
            .ok_or_else(|| refused("Root reclamation names no retained original target"))?;
        Ok(entry.reclaimed && !entry.in_flight && entry.custody.is_some())
    }
}

struct Slot {
    shared: Arc<Shared>,
    index: usize,
    transferred: bool,
}

impl ArmRootCustodySlot for Slot {
    fn retain(mut self: Box<Self>, custody: ArmRootNativeCustody) {
        let mut registry = self.shared.lock();
        if let Some(entry) = registry.slots[self.index].as_mut() {
            let launch = custody.launch();
            if launch.owner() != &entry.scope.owner.owner
                || launch.incarnation() != &entry.scope.owner.incarnation
                || launch.generation() != entry.scope.owner.generation
            {
                entry.failed = true;
                registry.accepting = false;
            }
        }
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
            self.shared.lock().slots[self.index] = None;
        }
        self.shared.changed.notify_one();
    }
}

struct CleanupLease {
    shared: Arc<Shared>,
    index: usize,
    custody: Option<ArmRootNativeCustody>,
}

impl Drop for CleanupLease {
    fn drop(&mut self) {
        if let Some(entry) = self.shared.lock().slots[self.index].as_mut() {
            entry.custody = self.custody.take();
            entry.in_flight = false;
        }
    }
}

fn cleanup(shared: Arc<Shared>) {
    loop {
        let turn = catch_unwind(AssertUnwindSafe(|| cleanup_turn(&shared)));
        if turn.is_err() {
            shared.lock().accepting = false;
        }
        let registry = shared.lock();
        let _wake = shared
            .changed
            .wait_timeout(registry, Duration::from_millis(10));
    }
}

fn cleanup_turn(shared: &Arc<Shared>) {
    for index in 0..8 {
        let custody = {
            let mut registry = shared.lock();
            let Some(entry) = registry.slots[index].as_mut() else {
                continue;
            };
            if entry.reclaimed || entry.in_flight {
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
                return Ok(false);
            };
            custody.begin_quarantine()?;
            custody.poll_reclamation()
        }));
        let mut registry = shared.lock();
        if let Some(entry) = registry.slots[index].as_mut() {
            match result {
                Ok(Ok(true)) => entry.reclaimed = true,
                Ok(Ok(false)) => {}
                Ok(Err(_)) | Err(_) => entry.failed = true,
            }
        }
        drop(registry);
        drop(lease);
    }
}

fn clone_artifacts(
    original: &[NativeCaptureArtifact],
) -> Result<Vec<NativeCaptureArtifact>, NodeObservedError> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(original.len())
        .map_err(|error| refused(&error.to_string()))?;
    retained.extend(original.iter().cloned());
    Ok(retained)
}
