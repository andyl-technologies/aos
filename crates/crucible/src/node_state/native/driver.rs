//! Backend-bound whole-world staging installed before any autonomous allocation.

use std::rc::Rc;

use crate::{
    node_admission::AdmittedGraph,
    node_contract::{
        ActivationRecord, RuntimeCustodyQueue, RuntimeCustodySlot, RuntimeCustodySupervisor,
        RuntimeError, RuntimeLimits,
    },
};

use super::super::{
    PreparedRestoreAllocation, RestoreReservations, StateError, StateLimits, VerifiedCapture,
    WorldRestoreDriver,
};
use super::{
    NativeArchiveLimits, NativeArchiveRecord, NativeWorldFactory, refused,
    require_supported_extensions,
};

/// Restores installed mixed-native state through the existing complete-world barrier.
///
/// The driver retains the authenticated archive and the actor-local supervisor.
/// Empty capsules acquire pre-reserved custody before any owner preparation may
/// allocate an autonomous resource; failed or dropped staging stays supervised
/// until authentic native process-group reaping and backing-lease retirement.
pub struct NativeWorldRestoreDriver {
    graph: Rc<AdmittedGraph>,
    archive: NativeArchiveRecord,
    factory: Rc<dyn NativeWorldFactory>,
    custody: RuntimeCustodyQueue,
}

impl NativeWorldRestoreDriver {
    /// Binds an authenticated backend-specific source to its sealed fresh graph.
    ///
    /// # Errors
    /// Refuses another immutable world or a changed native backend/schema binding.
    pub fn new(
        graph: Rc<AdmittedGraph>,
        archive: NativeArchiveRecord,
        factory: Rc<dyn NativeWorldFactory>,
        custody: RuntimeCustodyQueue,
    ) -> Result<Self, StateError> {
        require_supported_extensions(&graph)?;
        if graph.world_binding_hash() != &archive.manifest().world_binding_hash {
            return Err(refused("native restore world or backend binding differs"));
        }
        Ok(Self {
            graph,
            archive,
            factory,
            custody,
        })
    }
}

impl RuntimeCustodySupervisor for NativeWorldRestoreDriver {
    fn reserve_world(
        &self,
        activation: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<Box<dyn RuntimeCustodySlot>, RuntimeError> {
        self.custody.reserve_world(activation, limits)
    }
}

impl WorldRestoreDriver for NativeWorldRestoreDriver {
    fn stage_world(
        &mut self,
        graph: &AdmittedGraph,
        capture: &VerifiedCapture,
        target: &ActivationRecord,
        limits: StateLimits,
        allocation: &mut PreparedRestoreAllocation,
    ) -> Result<(), StateError> {
        require_supported_extensions(graph)?;
        if capture.artifact() != self.archive.artifact()
            || capture.manifest() != self.archive.manifest()
            || graph.world() != self.graph.world()
            || graph
                .node_ids()
                .any(|node| graph.binding(node) != self.graph.binding(node))
        {
            return Err(refused(
                "native authenticated source or fresh graph differs",
            ));
        }
        for object in &self.archive.index.objects {
            let actual = self
                .archive
                .object(&object.reference, limits.maximum_content_bytes)?;
            if capture.content().get(&object.reference) != Some(actual.as_slice()) {
                return Err(refused(
                    "native admitted core closure differs from authenticated source",
                ));
            }
        }
        let source_limits = NativeArchiveLimits {
            state: limits,
            native: self.archive.limits.native,
        };
        let mut reservations = RestoreReservations::default();
        for owner in &capture.manifest().owners {
            let source = self.archive.authenticated_source(
                &owner.capture_owner_id,
                &capture.runtime,
                capture.content(),
            )?;
            self.factory.authenticate_source(graph, owner, &source)?;
            let next = self
                .factory
                .reservation(graph, owner, &source, source_limits)?;
            add_reservation(&mut reservations, next, limits)?;
        }
        self.factory.authenticate_coordinator(
            graph,
            &capture.runtime,
            &capture.scheduler,
            capture.content(),
        )?;
        let empty = self.factory.empty_staging(
            Rc::clone(&self.graph),
            self.archive.clone(),
            target,
            reservations,
            source_limits,
        )?;
        // This is the only allocation boundary: the returned capsule must still
        // be empty. Every later native prepare callback runs under owned custody.
        allocation.install_capsule(empty)?;
        let actual = allocation.capsule_mut()?.reservations();
        if actual.memory_bytes != reservations.memory_bytes
            || actual.writable_bytes != reservations.writable_bytes
            || actual.processes != reservations.processes
            || actual.descriptors != reservations.descriptors
        {
            return Err(refused(
                "native staging capsule differs from complete reserved world budget",
            ));
        }
        Ok(())
    }
}

fn add_reservation(
    total: &mut RestoreReservations,
    next: RestoreReservations,
    limits: StateLimits,
) -> Result<(), StateError> {
    let memory_bytes = total.memory_bytes.checked_add(next.memory_bytes);
    let writable_bytes = total.writable_bytes.checked_add(next.writable_bytes);
    let processes = total.processes.checked_add(next.processes);
    let descriptors = total.descriptors.checked_add(next.descriptors);
    let (Some(memory_bytes), Some(writable_bytes), Some(processes), Some(descriptors)) =
        (memory_bytes, writable_bytes, processes, descriptors)
    else {
        return Err(refused("native peak reservation count overflowed"));
    };
    if memory_bytes > limits.maximum_native_memory_bytes
        || writable_bytes > limits.maximum_native_writable_bytes
        || processes > limits.maximum_native_processes
        || descriptors > limits.maximum_native_descriptors
    {
        return Err(refused(
            "native world peak reservation exceeds enforced limits",
        ));
    }
    *total = RestoreReservations {
        memory_bytes,
        writable_bytes,
        processes,
        descriptors,
    };
    Ok(())
}
