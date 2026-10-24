//! Reserves one process-lifetime X86Root supervisor before native allocation.
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

use crucible_engine::{
    node_contract::{ActivationRecord, NativeCaptureArtifact, OwnerIdentity},
    node_state::{NativeArchiveRecord, PublicationKnowledge},
};
use crucible_node_transport::gem5::{X86RootCustodySlot, X86RootNativeCustody};

use super::super::{NodeObservedError, refused};
use super::queue_diagnostics::{CleanupFailureRecord, InstalledX86RootCleanupStatus};

pub(super) enum X86RootBacking {
    Fresh(Vec<File>),
    Archived {
        source: Box<NativeArchiveRecord>,
        artifacts: Vec<NativeCaptureArtifact>,
    },
}

pub(super) struct X86RootScope {
    pub(super) command_budget: crucible_node_transport::gem5::NativeCommandConstructionBudget,
    pub(super) activation: ActivationRecord,
    pub(super) owner: OwnerIdentity,
    pub(super) publication: PublicationKnowledge,
    pub(super) backing: X86RootBacking,
}

struct Entry {
    scope: X86RootScope,
    custody: Option<X86RootNativeCustody>,
    in_flight: bool,
    reclaimed: bool,
    failed: bool,
    first_failure: Option<CleanupFailureRecord>,
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
pub(super) struct X86RootCustodyQueue(Arc<Shared>);

impl X86RootCustodyQueue {
    pub(super) fn installed() -> Result<Self, NodeObservedError> {
        static INSTALLED: Mutex<Option<X86RootCustodyQueue>> = Mutex::new(None);
        let mut installed = INSTALLED.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(queue) = &*installed {
            return Ok(queue.clone());
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(8)
            .map_err(|_| refused("X86Root supervisor reservation is unavailable"))?;
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
            .name("x86-root-native-cleanup".into())
            .spawn(move || cleanup(worker))
            .map_err(|error| refused(&error.to_string()))?;
        let queue = Self(shared);
        *installed = Some(queue.clone());
        Ok(queue)
    }

    pub(super) fn reserve(
        &self,
        scope: X86RootScope,
    ) -> Result<Box<dyn X86RootCustodySlot>, NodeObservedError> {
        if !scope.activation.owners.contains(&scope.owner)
            || scope.publication != PublicationKnowledge::NotAttempted
        {
            return Err(refused(
                "X86Root reservation does not own an inactive target owner",
            ));
        }
        match &scope.backing {
            X86RootBacking::Fresh(files)
                if files.len()
                    == crucible_node_transport::gem5::InstalledX86RootModel::artifact_roles()
                        .len() => {}
            X86RootBacking::Archived { source, artifacts }
                if source.manifest().world_binding_hash == scope.activation.world_binding_hash
                    && source
                        .owners()
                        .iter()
                        .any(|owner| owner.owner == scope.owner.owner)
                    && !artifacts.is_empty()
                    && artifacts.len() <= 8192 => {}
            _ => {
                return Err(refused(
                    "X86Root reservation lacks complete installed or signed original backing",
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
                "X86Root original owner is occupied or supervisor admission is closed",
            ));
        }
        let index = registry
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                refused("X86Root process-lifetime native custody credits are exhausted")
            })?;
        registry.slots[index] = Some(Entry {
            scope,
            custody: None,
            in_flight: false,
            reclaimed: false,
            failed: false,
            first_failure: None,
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
        let entry = original_unused_entry(&registry, activation, owner)?;
        match &entry.scope.backing {
            X86RootBacking::Archived { source, .. }
                if source.artifact() == archive.artifact()
                    && source.manifest() == archive.manifest()
                    && source.owners() == archive.owners() =>
            {
                Ok(())
            }
            _ => Err(refused(
                "X86Root reserved image lease owns another signed source",
            )),
        }
    }

    // A signed archive roster has one pinned descriptor set for the installed
    // queue lifetime. Independent worlds borrow Arc-backed handles to that same
    // backing; retaining ownership does not require reopening each file.
    pub(super) fn retained_artifacts(
        &self,
        archive: &NativeArchiveRecord,
        owner: &crucible_node_format::Id,
    ) -> Result<Option<Vec<NativeCaptureArtifact>>, NodeObservedError> {
        let registry = self.0.lock();
        for entry in registry.slots.iter().flatten() {
            let X86RootBacking::Archived { source, artifacts } = &entry.scope.backing else {
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

    pub(super) fn reserved_command_budget(
        &self,
        target: &ActivationRecord,
        owner: &OwnerIdentity,
        archive: &NativeArchiveRecord,
    ) -> Result<crucible_node_transport::gem5::NativeCommandConstructionBudget, NodeObservedError>
    {
        self.verify_reserved(target, owner, archive)?;
        self.0
            .lock()
            .slots
            .iter()
            .flatten()
            .find(|entry| &entry.scope.activation == target && &entry.scope.owner == owner)
            .map(|entry| entry.scope.command_budget.clone())
            .ok_or_else(|| refused("Root original command reservation absent"))
    }

    pub(super) fn reserved_artifacts(
        &self,
        target: &ActivationRecord,
        owner: &OwnerIdentity,
        archive: &NativeArchiveRecord,
    ) -> Result<Vec<NativeCaptureArtifact>, NodeObservedError> {
        self.verify_reserved(target, owner, archive)?;
        self.retained_artifacts(archive, &owner.owner)?
            .ok_or_else(|| refused("X86Root reserved archive descriptors are absent"))
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
            .ok_or_else(|| refused("X86Root publication names no original reserved target"))?;
        if entry.scope.publication == PublicationKnowledge::Committed
            && status != PublicationKnowledge::Committed
        {
            return Err(refused(
                "X86Root committed publication cannot be downgraded",
            ));
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
            .ok_or_else(|| refused("X86Root publication names no retained original target"))
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

    pub(super) fn cleanup_status(
        &self,
        target: &ActivationRecord,
    ) -> Result<InstalledX86RootCleanupStatus, NodeObservedError> {
        let registry = self.0.lock();
        let entry = registry
            .slots
            .iter()
            .flatten()
            .find(|entry| &entry.scope.activation == target)
            .ok_or_else(|| refused("X86Root diagnostics name no retained original target"))?;
        Ok(InstalledX86RootCleanupStatus {
            custody_present: entry.custody.is_some(),
            in_flight: entry.in_flight,
            reclaimed: entry.reclaimed,
            failed: entry.failed,
            first_failure: entry
                .first_failure
                .as_ref()
                .map(CleanupFailureRecord::status),
        })
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
            .ok_or_else(|| refused("X86Root reclamation names no retained original target"))?;
        Ok(entry.reclaimed && !entry.in_flight && entry.custody.is_some())
    }
}

// This predicate authenticates only the original entry's unused state. The
// caller still verifies its actual sealed archive backing before any transfer.
fn original_unused_entry<'a>(
    registry: &'a Registry,
    activation: &ActivationRecord,
    owner: &OwnerIdentity,
) -> Result<&'a Entry, NodeObservedError> {
    let entry = registry
        .slots
        .iter()
        .flatten()
        .find(|entry| &entry.scope.activation == activation && &entry.scope.owner == owner)
        .ok_or_else(|| refused("X86Root original image lease is not reserved"))?;
    if entry.custody.is_some()
        || entry.in_flight
        || entry.reclaimed
        || entry.failed
        || entry.scope.publication != PublicationKnowledge::NotAttempted
    {
        return Err(refused(
            "X86Root image reservation no longer owns unused inactive custody",
        ));
    }
    Ok(entry)
}

struct Slot {
    shared: Arc<Shared>,
    index: usize,
    transferred: bool,
}

impl X86RootCustodySlot for Slot {
    fn retain(mut self: Box<Self>, custody: X86RootNativeCustody) {
        let mut registry = self.shared.lock();
        if let Some(entry) = registry.slots[self.index].as_mut() {
            let launch = custody.launch();
            if launch.owner() != &entry.scope.owner.owner
                || launch.incarnation() != &entry.scope.owner.incarnation
                || launch.generation() != entry.scope.owner.generation
                || !launch
                    .command_construction_budget()
                    .is_ok_and(|budget| budget.same_reservation_data(&entry.scope.command_budget))
            {
                entry.failed = true;
                CleanupFailureRecord::retain_first(
                    &mut entry.first_failure,
                    CleanupFailureRecord::refused(
                        &"X86Root custody owner differs from its reserved original target",
                    ),
                );
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
            let mut registry = self.shared.lock();
            let spent = registry.slots[self.index].as_ref().is_some_and(|entry| {
                entry
                    .scope
                    .command_budget
                    .has_original_construction_debits_data()
            });
            if spent {
                // No Child escaped: every post-spawn path is owned by the
                // construction guard and transfers via retain. Keep the spent
                // command ledger and original owner instead of renewing credit.
                if let Some(entry) = registry.slots[self.index].as_mut() {
                    entry.failed = true;
                    entry.reclaimed = true;
                }
            } else {
                registry.slots[self.index] = None;
            }
        }
        self.shared.changed.notify_one();
    }
}

struct CleanupLease {
    shared: Arc<Shared>,
    index: usize,
    custody: Option<X86RootNativeCustody>,
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
                Ok(Err(error)) => {
                    entry.failed = true;
                    CleanupFailureRecord::retain_first(
                        &mut entry.first_failure,
                        CleanupFailureRecord::refused(&error),
                    );
                }
                Err(_) => {
                    entry.failed = true;
                    CleanupFailureRecord::retain_first(
                        &mut entry.first_failure,
                        CleanupFailureRecord::unwound(),
                    );
                }
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

#[cfg(test)]
#[path = "queue_diagnostics/queue_tests.rs"]
mod diagnostic_tests;
