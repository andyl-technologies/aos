//! Preallocated checked assignment state; this arithmetic issues no Source.

// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) struct WorldSlot {
    identity: NativeWorldIdentity,
    epoch: u64,
    consumer_control_bytes: u64,
    consumer_issued: bool,
    node_constructor_entered: bool,
    consumer_closed: bool,
    // Retained even if every facade drops or its postcut refuses.
    _original: Arc<HostOperationGuard>,
    cleanup: std::sync::OnceLock<
        Result<Arc<HostOperationGuard>, crate::host_supervision::HostSupervisionError>,
    >,
    window: Option<HostServiceLease>,
}

pub(super) struct NodeSlot {
    world_epoch: u64,
    assignment_epoch: u64,
    request: NativeNodeReservation,
    issued: bool,
    windows_issued: [bool; 2],
    windows_closed: [bool; 2],
}

/// Carries checked accounting while the caller retains the same ledger lock.
pub(super) struct PreparedNodeReturn {
    pub(super) windows: u64,
    pub(super) tables: u64,
    index: usize,
    used: HostResourceVector,
}

/// Distinguishes real retained body custody from an invalid return attempt.
/// Ready is consumed only while the same caller still holds the ledger lock.
#[derive(Debug)]
pub(super) enum WorldReturnPreparation {
    PendingBody,
    Ready {
        index: usize,
        used: HostResourceVector,
        peak: u64,
        tables: u64,
    },
}

pub(super) struct PoolLedger {
    ceiling: HostResourceVector,
    used: HostResourceVector,
    worlds: Vec<Option<WorldSlot>>,
    nodes: Vec<Option<NodeSlot>>,
    next_world: u64,
    next_assignment: u64,
    worker_controls: Option<u64>,
}

impl PoolLedger {
    pub(super) fn new(
        ceiling: HostResourceVector,
        capacity: usize,
        controls: u64,
        shared_descriptors: u64,
    ) -> Result<Self, ServiceBirthError> {
        let control = HostResourceVector {
            resident_peak_bytes: controls,
            metadata_bytes: controls,
            file_descriptors: shared_descriptors,
            ..HostResourceVector::default()
        };
        let used =
            super::super::checked_assignment(HostResourceVector::default(), control, ceiling)?;
        let mut worlds = Vec::new();
        worlds
            .try_reserve_exact(capacity)
            .map_err(|_| ServiceBirthError::policy("native World array allocation refused"))?;
        worlds.resize_with(capacity, || None);
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(capacity)
            .map_err(|_| ServiceBirthError::policy("native node array allocation refused"))?;
        nodes.resize_with(capacity, || None);
        Ok(Self {
            ceiling,
            used,
            worlds,
            nodes,
            next_world: 0,
            next_assignment: 0,
            worker_controls: None,
        })
    }

    /// Observes component debt without issuing an account or changing a row.
    #[cfg(test)]
    pub(super) fn charged_resources(&self) -> HostResourceVector {
        self.used
    }

    pub(super) fn reserve_worker_controls(&mut self, bytes: u64) -> Result<(), ServiceBirthError> {
        if bytes == 0 || self.worker_controls.is_some() {
            return Err(ServiceBirthError::policy(
                "Main worker control assignment is empty or occupied",
            ));
        }
        let request = HostResourceVector {
            resident_peak_bytes: bytes,
            metadata_bytes: bytes,
            ..HostResourceVector::default()
        };
        let used = super::super::checked_assignment(self.used, request, self.ceiling)?;
        // These bodies and the permanent Main directory outlive every World.
        // No World return may make this separate standing debit reusable.
        self.used = used;
        self.worker_controls = Some(bytes);
        Ok(())
    }

    /// Publishes a Source's positive body charge and consumes its entry proof.
    pub(super) fn assign_source(
        &mut self,
        identity: NativeWorldIdentity,
        requests: &[NativeNodeReservation],
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
        entered: impl FnOnce(),
    ) -> Result<(u64, u64, u64), ServiceBirthError> {
        if consumer_control_bytes == 0 {
            return Err(ServiceBirthError::policy(
                "Source World body controls are absent",
            ));
        }
        self.publish_assignment(
            identity,
            requests,
            consumer_control_bytes,
            original,
            true,
            entered,
        )
    }

    // Zero-body accounting remains useful to the inert ledger controls. This
    // path issues no authenticated holder and is not a production Source seam.
    #[cfg(test)]
    pub(super) fn assign(
        &mut self,
        identity: NativeWorldIdentity,
        requests: &[NativeNodeReservation],
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(u64, u64, u64), ServiceBirthError> {
        self.publish_assignment(
            identity,
            requests,
            consumer_control_bytes,
            original,
            false,
            || {},
        )
    }

    #[expect(
        clippy::explicit_counter_loop,
        reason = "Each published row advances its checked protocol assignment epoch."
    )]
    fn publish_assignment(
        &mut self,
        identity: NativeWorldIdentity,
        requests: &[NativeNodeReservation],
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
        consumer_issued: bool,
        entered: impl FnOnce(),
    ) -> Result<(u64, u64, u64), ServiceBirthError> {
        if identity.owner == [0; 32]
            || identity.selection == [0; 32]
            || requests.is_empty()
            || self
                .worlds
                .iter()
                .flatten()
                .any(|world| world.identity == identity)
        {
            return Err(ServiceBirthError::policy(
                "native World selection is invalid or occupied",
            ));
        }
        let world_index = self
            .worlds
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| ServiceBirthError::policy("native World capacity is occupied"))?;
        if self.nodes.iter().filter(|node| node.is_none()).count() < requests.len() {
            return Err(ServiceBirthError::policy(
                "native node capacity is occupied",
            ));
        }
        let (used, peak) = checked_selection(self.ceiling, self.used, requests)?;
        let used = charge_world_controls(self.ceiling, used, consumer_control_bytes)?;
        let epoch = self
            .next_world
            .checked_add(1)
            .ok_or_else(|| ServiceBirthError::policy("native World epoch exhausted"))?;
        let assignment_end = self
            .next_assignment
            .checked_add(
                u64::try_from(requests.len())
                    .map_err(|_| ServiceBirthError::policy("native node count overflows"))?,
            )
            .ok_or_else(|| ServiceBirthError::policy("native node epoch exhausted"))?;

        let tables = requests
            .iter()
            .try_fold(0_u64, |sum, node| {
                sum.checked_add(node.resources.file_descriptors)
            })
            .ok_or_else(|| ServiceBirthError::policy("native table aggregate overflows"))?;

        // The caller's nominal no-assignment proof is consumed only after all
        // checks, immediately before the first irreversible debit/row mutation.
        entered();
        self.used = used;
        self.next_world = epoch;
        let mut assignment = self.next_assignment;
        self.next_assignment = assignment_end;
        self.worlds[world_index] = Some(WorldSlot {
            identity,
            epoch,
            consumer_control_bytes,
            consumer_issued,
            node_constructor_entered: false,
            consumer_closed: consumer_control_bytes == 0,
            _original: Arc::clone(original),
            cleanup: std::sync::OnceLock::new(),
            window: None,
        });
        for (slot, request) in self
            .nodes
            .iter_mut()
            .filter(|slot| slot.is_none())
            .zip(requests)
        {
            assignment += 1;
            *slot = Some(NodeSlot {
                world_epoch: epoch,
                assignment_epoch: assignment,
                request: *request,
                issued: false,
                windows_issued: [false; 2],
                windows_closed: [false; 2],
            });
        }
        Ok((epoch, peak, tables))
    }

    pub(super) fn bind_window(
        &mut self,
        epoch: u64,
        window: HostServiceLease,
    ) -> Result<(), ServiceBirthError> {
        let world = self
            .worlds
            .iter_mut()
            .flatten()
            .find(|world| world.epoch == epoch)
            .filter(|world| world.window.is_none())
            .ok_or_else(|| {
                ServiceBirthError::policy("native World descriptor slot is unavailable")
            })?;
        world.window = Some(window);
        Ok(())
    }

    pub(super) fn unissued_node_count(&self, epoch: u64) -> Result<usize, ServiceBirthError> {
        if !self
            .worlds
            .iter()
            .flatten()
            .any(|world| world.epoch == epoch && world.window.is_some())
        {
            return Err(ServiceBirthError::policy("native World selection is stale"));
        }
        Ok(self
            .nodes
            .iter()
            .flatten()
            .filter(|node| node.world_epoch == epoch && !node.issued)
            .count())
    }

    pub(super) fn next_node(
        &self,
        epoch: u64,
    ) -> Result<Option<NativeNodeReservation>, ServiceBirthError> {
        if !self
            .worlds
            .iter()
            .flatten()
            .any(|world| world.epoch == epoch && world.window.is_some())
        {
            return Err(ServiceBirthError::policy("native World selection is stale"));
        }
        Ok(self
            .nodes
            .iter()
            .flatten()
            .find(|node| node.world_epoch == epoch && !node.issued)
            .map(|node| node.request))
    }

    pub(super) fn take_node(
        &mut self,
        epoch: u64,
        node: [u8; 32],
    ) -> Result<(usize, u64), ServiceBirthError> {
        let world = self
            .worlds
            .iter_mut()
            .flatten()
            .find(|world| world.epoch == epoch && world.window.is_some())
            .ok_or_else(|| {
                ServiceBirthError::policy("native World descriptor custody is absent")
            })?;
        let (index, slot) = self
            .nodes
            .iter_mut()
            .enumerate()
            .find_map(|(index, slot)| {
                slot.as_mut()
                    .filter(|slot| {
                        slot.world_epoch == epoch && slot.request.node == node && !slot.issued
                    })
                    .map(|slot| (index, slot))
            })
            .ok_or_else(|| ServiceBirthError::policy("native node is absent or already issued"))?;

        // Every fallible lookup precedes either monotonic publication.
        slot.issued = true;
        let assignment_epoch = slot.assignment_epoch;
        world.node_constructor_entered = true;
        Ok((index, assignment_epoch))
    }

    pub(super) fn node_bounds(
        &self,
        epoch: u64,
        assignment: u64,
        index: usize,
    ) -> Result<HostResourceVector, ServiceBirthError> {
        self.nodes
            .get(index)
            .and_then(Option::as_ref)
            .filter(|slot| {
                slot.world_epoch == epoch && slot.assignment_epoch == assignment && slot.issued
            })
            .map(|slot| slot.request.resources)
            .ok_or_else(|| ServiceBirthError::policy("native node assignment is stale"))
    }

    pub(super) fn take_window(
        &mut self,
        epoch: u64,
        assignment: u64,
        index: usize,
        role: WindowRole,
    ) -> Result<(), ServiceBirthError> {
        let slot = self
            .nodes
            .get_mut(index)
            .and_then(Option::as_mut)
            .filter(|slot| {
                slot.world_epoch == epoch && slot.assignment_epoch == assignment && slot.issued
            })
            .ok_or_else(|| ServiceBirthError::policy("native node landing assignment is stale"))?;
        let role = match role {
            WindowRole::Source => 0,
            WindowRole::Target => 1,
        };
        if slot.windows_issued[role] {
            return Err(ServiceBirthError::policy(
                "native node landing is already issued",
            ));
        }
        slot.windows_issued[role] = true;
        Ok(())
    }

    pub(super) fn close_window(
        &mut self,
        epoch: u64,
        assignment: u64,
        index: usize,
        role: WindowRole,
    ) -> Result<(), ServiceBirthError> {
        let slot = self
            .nodes
            .get_mut(index)
            .and_then(Option::as_mut)
            .filter(|slot| {
                slot.world_epoch == epoch && slot.assignment_epoch == assignment && slot.issued
            })
            .ok_or_else(|| ServiceBirthError::policy("native landing return is stale"))?;
        let role = match role {
            WindowRole::Source => 0,
            WindowRole::Target => 1,
        };
        if !slot.windows_issued[role] || slot.windows_closed[role] {
            return Err(ServiceBirthError::policy(
                "native landing is absent or already returned",
            ));
        }
        let peak = if role == 0 {
            slot.request.source_host_descriptors
        } else {
            slot.request.target_host_descriptors
        };
        let used = self
            .used
            .file_descriptors
            .checked_sub(peak)
            .ok_or_else(|| ServiceBirthError::policy("landing return exceeds pool assignment"))?;
        slot.windows_closed[role] = true;
        self.used.file_descriptors = used;
        Ok(())
    }

    pub(super) fn verify_never_born(&self, epoch: u64) -> Result<(), ServiceBirthError> {
        let world = self
            .worlds
            .iter()
            .flatten()
            .find(|world| world.epoch == epoch)
            .ok_or_else(|| {
                ServiceBirthError::policy("native World no-birth observation is stale")
            })?;
        if world.node_constructor_entered
            || !self
                .nodes
                .iter()
                .flatten()
                .any(|node| node.world_epoch == epoch)
            || self
                .nodes
                .iter()
                .flatten()
                .any(|node| node.world_epoch == epoch && node.issued)
        {
            return Err(ServiceBirthError::policy(
                "native World may have entered a node constructor",
            ));
        }
        Ok(())
    }

    pub(super) fn enter_cleanup(
        &self,
        epoch: u64,
    ) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        let world = self
            .worlds
            .iter()
            .flatten()
            .find(|world| world.epoch == epoch)
            .ok_or_else(|| ServiceBirthError::policy("native World Cleanup is stale"))?;
        let _ = world.cleanup.get_or_init(|| {
            world
                ._original
                .begin_original_cleanup_control()
                .map(Arc::new)
        });
        self.saved_cleanup(epoch)
    }

    pub(super) fn saved_cleanup(
        &self,
        epoch: u64,
    ) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        let world = self
            .worlds
            .iter()
            .flatten()
            .find(|world| world.epoch == epoch)
            .ok_or_else(|| ServiceBirthError::policy("native World Cleanup is stale"))?;
        let entered = world.cleanup.get().ok_or_else(|| {
            ServiceBirthError::policy("native World Cleanup has not been entered")
        })?;
        entered
            .as_ref()
            .map(Arc::clone)
            .map_err(|source| ServiceBirthError::from(*source))
    }

    pub(super) fn retained_cleanup(
        &self,
        epoch: u64,
    ) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        let cleanup = self.enter_cleanup(epoch)?;
        cleanup.verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup)?;
        Ok(cleanup)
    }

    pub(super) fn verify_cleanup(
        &self,
        epoch: u64,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        let world = self
            .worlds
            .iter()
            .flatten()
            .find(|world| world.epoch == epoch)
            .ok_or_else(|| ServiceBirthError::policy("native World Cleanup is stale"))?;
        let entered = world.cleanup.get().ok_or_else(|| {
            ServiceBirthError::policy("native World Cleanup has not been entered")
        })?;
        let saved = entered
            .as_ref()
            .map_err(|source| ServiceBirthError::from(*source))?;
        if !Arc::ptr_eq(saved, cleanup) {
            return Err(ServiceBirthError::policy(
                "native World Cleanup operation is foreign",
            ));
        }
        saved.verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup)?;
        Ok(())
    }

    // A genuine preexisting loan supplies its epoch through the containing
    // pool's identity check. Only commit_world_return removes a published row;
    // assignment epochs never reset or wrap, and replacement needs an empty row.
    pub(super) fn observe_world_returned(&self, epoch: u64) -> Result<bool, ServiceBirthError> {
        self.world_return_fact(epoch)
            .map_err(ServiceBirthError::policy)
    }

    /// Shares the same physical fact with allocation-free claim Drop observation.
    pub(super) fn world_return_fact(&self, epoch: u64) -> Result<bool, &'static str> {
        if epoch == 0 || epoch > self.next_world {
            return Err("native World was never published");
        }
        let absent = !self
            .worlds
            .iter()
            .flatten()
            .any(|world| world.epoch == epoch);
        if absent
            && self
                .nodes
                .iter()
                .flatten()
                .any(|node| node.world_epoch == epoch)
        {
            return Err("native returned World retains a member");
        }
        Ok(absent)
    }

    /// Borrows the retained original of this exact already-issued World.
    pub(super) fn world_original(
        &self,
        epoch: u64,
    ) -> Result<&Arc<HostOperationGuard>, ServiceBirthError> {
        self.worlds
            .iter()
            .flatten()
            .find(|world| world.epoch == epoch)
            .map(|world| &world._original)
            .ok_or_else(|| ServiceBirthError::policy("native World original is stale"))
    }

    pub(super) fn verify_world_original(
        &self,
        epoch: u64,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        if !self
            .worlds
            .iter()
            .flatten()
            .any(|world| world.epoch == epoch && Arc::ptr_eq(&world._original, original))
        {
            return Err(ServiceBirthError::policy(
                "native World original is foreign or stale",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn take_consumer(&mut self, epoch: u64) -> Result<(), ServiceBirthError> {
        let world = self
            .worlds
            .iter_mut()
            .flatten()
            .find(|world| world.epoch == epoch && !world.consumer_issued && !world.consumer_closed)
            .ok_or_else(|| {
                ServiceBirthError::policy("World containing-body custody is absent or issued")
            })?;
        world.consumer_issued = true;
        Ok(())
    }

    pub(super) fn close_consumer(&mut self, epoch: u64) -> Result<(), ServiceBirthError> {
        let world = self
            .worlds
            .iter_mut()
            .flatten()
            .find(|world| world.epoch == epoch && world.consumer_issued && !world.consumer_closed)
            .ok_or_else(|| ServiceBirthError::policy("World containing-body return is stale"))?;
        // Accounting remains occupied until every actual native member closes.
        world.consumer_closed = true;
        Ok(())
    }

    pub(super) fn prepare_world_return(
        &self,
        epoch: u64,
    ) -> Result<WorldReturnPreparation, ServiceBirthError> {
        let world = self
            .worlds
            .iter()
            .position(|world| world.as_ref().is_some_and(|world| world.epoch == epoch))
            .ok_or_else(|| ServiceBirthError::policy("native World already returned"))?;
        let containing = self.worlds[world]
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native World custody is absent"))?;
        if self
            .worlds
            .iter()
            .flatten()
            .filter(|world| world.epoch == epoch)
            .count()
            != 1
            || containing.window.is_none()
            || (!containing.node_constructor_entered
                && !self
                    .nodes
                    .iter()
                    .flatten()
                    .any(|node| node.world_epoch == epoch))
            || (containing.consumer_control_bytes == 0
                && (!containing.consumer_closed || containing.consumer_issued))
            || (containing.consumer_control_bytes != 0
                && containing.consumer_closed
                && !containing.consumer_issued)
        {
            return Err(ServiceBirthError::policy(
                "native World return custody is inconsistent",
            ));
        }
        let consumer_control_bytes = containing.consumer_control_bytes;
        let mut returned = HostResourceVector {
            resident_peak_bytes: consumer_control_bytes,
            metadata_bytes: consumer_control_bytes,
            ..HostResourceVector::default()
        };
        let mut peak = 0_u64;
        for node in self
            .nodes
            .iter()
            .flatten()
            .filter(|node| node.world_epoch == epoch)
        {
            if node.issued || node.windows_issued != [false; 2] || node.windows_closed != [false; 2]
            {
                return Err(ServiceBirthError::policy(
                    "native World has an issued or inconsistent member not physically returned",
                ));
            }
            returned =
                super::super::checked_assignment(returned, node.request.resources, self.ceiling)?;
            peak = peak
                .checked_add(node.request.source_host_descriptors)
                .and_then(|peak| peak.checked_add(node.request.target_host_descriptors))
                .ok_or_else(|| {
                    ServiceBirthError::policy("native World landing return overflows")
                })?;
        }
        let tables = returned.file_descriptors;
        returned.file_descriptors = returned
            .file_descriptors
            .checked_add(peak)
            .ok_or_else(|| ServiceBirthError::policy("native return descriptor sum overflows"))?;
        let used = subtract(self.used, returned)?;
        if !containing.consumer_closed {
            return Ok(WorldReturnPreparation::PendingBody);
        }
        Ok(WorldReturnPreparation::Ready {
            index: world,
            used,
            peak,
            tables,
        })
    }

    pub(super) fn commit_world_return(
        &mut self,
        index: usize,
        epoch: u64,
        used: HostResourceVector,
    ) {
        for node in &mut self.nodes {
            if node.as_ref().is_some_and(|node| node.world_epoch == epoch) {
                *node = None;
            }
        }
        self.worlds[index] = None;
        self.used = used;
    }

    pub(super) fn returnable_window_peak(
        &self,
        epoch: u64,
        assignment: u64,
        index: usize,
    ) -> Result<u64, ServiceBirthError> {
        let slot = self
            .nodes
            .get(index)
            .and_then(Option::as_ref)
            .filter(|slot| {
                slot.world_epoch == epoch && slot.assignment_epoch == assignment && slot.issued
            })
            .ok_or_else(|| ServiceBirthError::policy("native node return is stale"))?;
        let mut unissued = 0_u64;
        for (role, peak) in [
            slot.request.source_host_descriptors,
            slot.request.target_host_descriptors,
        ]
        .into_iter()
        .enumerate()
        {
            if slot.windows_issued[role] && !slot.windows_closed[role] {
                return Err(ServiceBirthError::policy(
                    "native node has surviving landing custody",
                ));
            }
            if !slot.windows_issued[role] {
                unissued = unissued
                    .checked_add(peak)
                    .ok_or_else(|| ServiceBirthError::policy("native landing return overflows"))?;
            }
        }
        Ok(unissued)
    }

    pub(super) fn prepare_node_return(
        &self,
        epoch: u64,
        assignment: u64,
        index: usize,
    ) -> Result<PreparedNodeReturn, ServiceBirthError> {
        let unused_landings = self.returnable_window_peak(epoch, assignment, index)?;
        let node = self.nodes[index]
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node already returned"))?;
        let mut returned = node.request.resources;
        returned.file_descriptors = returned
            .file_descriptors
            .checked_add(unused_landings)
            .ok_or_else(|| ServiceBirthError::policy("native return descriptor sum overflows"))?;
        let used = subtract(self.used, returned)?;
        Ok(PreparedNodeReturn {
            windows: unused_landings,
            tables: node.request.resources.file_descriptors,
            index,
            used,
        })
    }

    /// Commits only after physical descriptor return under the same lock.
    pub(super) fn commit_node_return(&mut self, prepared: PreparedNodeReturn) {
        self.nodes[prepared.index] = None;
        self.used = prepared.used;
    }

    pub(super) fn window_peak(
        &self,
        epoch: u64,
        assignment: u64,
        index: usize,
        role: WindowRole,
    ) -> Result<u64, ServiceBirthError> {
        let slot = self
            .nodes
            .get(index)
            .and_then(Option::as_ref)
            .filter(|slot| {
                slot.world_epoch == epoch && slot.assignment_epoch == assignment && slot.issued
            })
            .ok_or_else(|| ServiceBirthError::policy("native node landing assignment is stale"))?;
        let (role, peak) = match role {
            WindowRole::Source => (0, slot.request.source_host_descriptors),
            WindowRole::Target => (1, slot.request.target_host_descriptors),
        };
        if !slot.windows_issued[role] || slot.windows_closed[role] {
            return Err(ServiceBirthError::policy(
                "native node landing has no issued holder",
            ));
        }
        Ok(peak)
    }
}

/// Charges the exact selected containing bodies against the same retained bank.
fn charge_world_controls(
    ceiling: HostResourceVector,
    used: HostResourceVector,
    bytes: u64,
) -> Result<HostResourceVector, ServiceBirthError> {
    super::super::checked_assignment(
        used,
        HostResourceVector {
            resident_peak_bytes: bytes,
            metadata_bytes: bytes,
            ..HostResourceVector::default()
        },
        ceiling,
    )
}

fn checked_selection(
    ceiling: HostResourceVector,
    used: HostResourceVector,
    requests: &[NativeNodeReservation],
) -> Result<(HostResourceVector, u64), ServiceBirthError> {
    let mut used = used;
    let mut peak = 0_u64;
    let mut previous = None;
    for request in requests {
        super::super::validate_request(request.resources)?;
        if request.node == [0; 32]
            || previous.is_some_and(|node| node >= request.node)
            || request.resources.file_descriptors < 2
            || request.source_host_descriptors == 0
            || request.target_host_descriptors == 0
        {
            return Err(ServiceBirthError::policy(
                "native node selection is invalid or unordered",
            ));
        }
        previous = Some(request.node);
        let landing = request
            .source_host_descriptors
            .checked_add(request.target_host_descriptors)
            .ok_or_else(|| ServiceBirthError::policy("native node landing sum overflows"))?;
        let mut charge = request.resources;
        charge.file_descriptors = charge
            .file_descriptors
            .checked_add(landing)
            .ok_or_else(|| ServiceBirthError::policy("native table and landing sum overflows"))?;
        used = super::super::checked_assignment(used, charge, ceiling)?;
        peak = peak
            .checked_add(landing)
            .ok_or_else(|| ServiceBirthError::policy("native node landing sum overflows"))?;
    }
    Ok((used, peak))
}

#[cfg(test)]
mod tests;

fn subtract(
    held: HostResourceVector,
    returned: HostResourceVector,
) -> Result<HostResourceVector, ServiceBirthError> {
    let sub = |left: u64, right: u64| {
        left.checked_sub(right).ok_or_else(|| {
            ServiceBirthError::policy("native returned vector exceeds its assignment")
        })
    };
    Ok(HostResourceVector {
        resident_peak_bytes: sub(held.resident_peak_bytes, returned.resident_peak_bytes)?,
        backing_peak_bytes: sub(held.backing_peak_bytes, returned.backing_peak_bytes)?,
        metadata_bytes: sub(held.metadata_bytes, returned.metadata_bytes)?,
        staging_bytes: sub(held.staging_bytes, returned.staging_bytes)?,
        cpu_slots: sub(held.cpu_slots, returned.cpu_slots)?,
        task_slots: sub(held.task_slots, returned.task_slots)?,
        file_descriptors: sub(held.file_descriptors, returned.file_descriptors)?,
        paging_io_slots: sub(held.paging_io_slots, returned.paging_io_slots)?,
    })
}
