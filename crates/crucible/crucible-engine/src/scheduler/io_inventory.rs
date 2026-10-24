//! Actor-owned import of complete, World-bound physical I/O queues.
//!
//! A backend authenticates its native Source and queue owners. This module
//! validates the observation against the immutable World, assigns canonical
//! event identities once, and retains the original physical keys for replay.
//! Observation does not consume a response or authorize native publication.

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    BackendIoComputedReply, BackendIoInventory, BackendIoNativeCap, BackendIoNativeCaps,
    BackendIoQueueSnapshot, IoCompletion,
};
use crucible_device::FrameDeliveryKey;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImportedIoNode {
    world: ContentHash,
    observed: NodeCounter,
    generation: NonZeroU64,
    native_caps: BackendIoNativeCaps,
    queues: BTreeMap<SchedulerNodeId, ImportedIoQueue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedIoQueue {
    source_node: u32,
    revision: NonZeroU64,
    #[serde(deserialize_with = "deserialize_pipeline_revision")]
    pipeline_revision: Option<NonZeroU64>,
    next_pipeline_boundary: Option<NodeCounter>,
    current: Vec<IoCompletion>,
    deliveries: BTreeMap<FrameDeliveryKey, ImportedIoDelivery>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedIoDelivery {
    completion: IoCompletion,
    key: ScheduledEventKey,
    published: bool,
}

// A null queue-only revision is explicit in the current checkpoint format;
// omitting the field must not manufacture that kind during restore.
fn deserialize_pipeline_revision<'de, D>(deserializer: D) -> Result<Option<NonZeroU64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<NonZeroU64>::deserialize(deserializer)
}

impl SingleScheduler {
    pub(super) fn import_initial_io_inventory(
        &mut self,
        inventory: BackendIoInventory,
    ) -> Result<(), SchedulerError> {
        let node = self.vm_node_index(&inventory.node)?;
        let observed = self.nodes[node].counter;
        self.import_io_inventory(inventory, observed)
    }

    fn import_io_inventory(
        &mut self,
        inventory: BackendIoInventory,
        expected: NodeCounter,
    ) -> Result<(), SchedulerError> {
        if inventory.observed != expected {
            return Err(inventory_error(
                "physical queue observation changed its stopped tick",
            ));
        }
        self.vm_node_index(&inventory.node)?;
        validate_native_caps(inventory.observed, inventory.native_caps)?;
        let world = self.inventory_world.as_ref().ok_or_else(|| {
            inventory_error("physical inventory lacks the actual World instantiation owner")
        })?;
        let layout =
            crate::WorldIoInstantiationLayout::derive(world, WorldIoLayoutPolicy::default())
                .map_err(|error| inventory_error(&error.to_string()))?;
        let mut declared = BTreeMap::new();
        for device in world
            .io_nodes()
            .filter(|device| device.owner == inventory.node)
        {
            let kind = match device.kind.family() {
                crate::WorldDeviceKind::Block => SchedulingNodeKind::Disk,
                crate::WorldDeviceKind::NineP => SchedulingNodeKind::NineP,
            };
            let source = layout.get(&device.id).ok_or_else(|| {
                inventory_error("World device has no canonical physical queue binding")
            })?;
            declared.insert(
                SchedulerNodeId {
                    node: device.id.clone(),
                    kind,
                },
                source.source_node,
            );
        }
        if inventory.queues.len() != declared.len() {
            return Err(inventory_error(
                "physical inventory does not cover every World queue",
            ));
        }
        let mut seen = BTreeSet::new();
        for queue in &inventory.queues {
            if queue.world != world.id()
                || declared.get(&queue.device) != Some(&queue.source_node)
                || !seen.insert(queue.device.clone())
            {
                return Err(inventory_error(
                    "physical queue has a foreign or duplicate binding",
                ));
            }
            validate_queue(inventory.observed, queue)?;
        }
        if self
            .device_sub_nodes
            .get(&inventory.node)
            .into_iter()
            .flatten()
            .any(|device| device.next_exact_local_event().is_some())
        {
            return Err(inventory_error(
                "physical queue conflicts with a live modeled queue",
            ));
        }

        // Validation and canonical sequence allocation are one actor transaction.
        // A refused later queue must not leave the earlier queue's event behind.
        let mut staged = self.clone();
        let previous = staged.imported_io.remove(&inventory.node);
        if previous
            .as_ref()
            .is_some_and(|previous| previous.world != world.id())
        {
            return Err(inventory_error(
                "physical inventory replaced its immutable World",
            ));
        }
        let mut queues = previous.map_or_else(BTreeMap::new, |previous| previous.queues);
        for queue in inventory.queues {
            staged.import_io_queue(&inventory.node, &mut queues, queue)?;
        }
        staged.imported_io.insert(
            inventory.node.clone(),
            ImportedIoNode {
                world: world.id(),
                observed: inventory.observed,
                generation: inventory.generation,
                native_caps: inventory.native_caps,
                queues,
            },
        );
        staged
            .pending_events
            .sort_by(|left, right| left.key.cmp(&right.key));
        *self = staged;
        Ok(())
    }

    fn import_io_queue(
        &mut self,
        target: &NodeId,
        queues: &mut BTreeMap<SchedulerNodeId, ImportedIoQueue>,
        queue: BackendIoQueueSnapshot,
    ) -> Result<(), SchedulerError> {
        // Queue owners observe physical keys and bytes only. Shared time and
        // consumer identity come from this actual actor's retained mapping.
        let completions = queue
            .completions
            .iter()
            .map(|reply| {
                Ok(IoCompletion {
                    sub_node: queue.device.clone(),
                    target: target.clone(),
                    delivery_tick: self.vm_delivery_time_for_tick(
                        target,
                        SimInstant {
                            ticks: reply.source_delivery.delivery_icount,
                        },
                    )?,
                    source_delivery: reply.source_delivery,
                    payload: reply.payload.clone(),
                })
            })
            .collect::<Result<Vec<_>, SchedulerError>>()?;
        let previous = queues.get(&queue.device);
        if let Some(previous) = previous {
            if queue.revision < previous.revision
                || queue.source_node != previous.source_node
                || queue.pipeline_revision < previous.pipeline_revision
                || (queue.revision == previous.revision && completions != previous.current)
                || (queue.pipeline_revision == previous.pipeline_revision
                    && (queue.pipeline_revision.is_some() || queue.revision == previous.revision)
                    && queue.next_pipeline_boundary != previous.next_pipeline_boundary)
            {
                return Err(inventory_error(
                    "physical queue revision is stale or inconsistent",
                ));
            }
            for old in &previous.current {
                let retained = previous
                    .deliveries
                    .get(&old.source_delivery)
                    .ok_or_else(|| {
                        inventory_error("physical queue lacks its retained delivery origin")
                    })?;
                if !completions
                    .iter()
                    .any(|new| new.source_delivery == old.source_delivery)
                    && !retained.published
                {
                    return Err(inventory_error(
                        "physical queue lost an unpublished delivery",
                    ));
                }
            }
        }
        let mut deliveries = previous.map_or_else(BTreeMap::new, |queue| queue.deliveries.clone());
        for completion in &completions {
            let at = completion.delivery_tick;
            if let Some(retained) = deliveries.get(&completion.source_delivery) {
                if retained.completion != *completion
                    || retained.published
                    || self
                        .pending_events
                        .iter()
                        .find(|event| event.key == retained.key)
                        .is_none_or(|event| {
                            event.payload != ScheduledEventPayload::IoCompletion(completion.clone())
                        })
                {
                    return Err(inventory_error("physical delivery was mutated or replayed"));
                }
                continue;
            }
            let consumer = SchedulerNodeId {
                node: target.clone(),
                kind: SchedulingNodeKind::Vm,
            };
            let sequence = self.event_sequences.next_sequence(&queue.device, &consumer);
            let next = sequence
                .checked_add(1)
                .ok_or_else(|| inventory_error("canonical physical delivery sequence exhausted"))?;
            let key = ScheduledEventKey::new(
                SharedTimelineKey {
                    virtual_time: at,
                    node: consumer.clone(),
                    sequence,
                },
                queue.device.clone(),
            );
            if self.pending_events.iter().any(|event| event.key == key) {
                return Err(inventory_error(
                    "physical delivery collides with an existing event",
                ));
            }
            self.event_sequences
                .set_next_sequence(queue.device.clone(), consumer, next);
            self.pending_events.push(ScheduledEvent {
                key: key.clone(),
                payload: ScheduledEventPayload::IoCompletion(completion.clone()),
            });
            deliveries.insert(
                completion.source_delivery,
                ImportedIoDelivery {
                    completion: completion.clone(),
                    key,
                    published: false,
                },
            );
        }
        queues.insert(
            queue.device,
            ImportedIoQueue {
                source_node: queue.source_node,
                revision: queue.revision,
                pipeline_revision: queue.pipeline_revision,
                next_pipeline_boundary: queue.next_pipeline_boundary,
                current: completions,
                deliveries,
            },
        );
        Ok(())
    }

    pub(super) fn imported_pipeline_boundary(&self, node: &NodeId) -> Option<NodeCounter> {
        self.imported_io
            .get(node)
            .into_iter()
            .flat_map(|node| node.queues.values())
            .filter_map(|queue| queue.next_pipeline_boundary)
            .min()
    }

    pub(super) fn imported_source_matches(
        &self,
        node: &NodeId,
        observed: NodeCounter,
        generation: NonZeroU64,
    ) -> bool {
        self.imported_io
            .get(node)
            .is_some_and(|source| source.observed == observed && source.generation == generation)
    }

    pub(super) fn imported_native_boundary(&self, node: &NodeId) -> Option<NodeCounter> {
        self.imported_io.get(node).and_then(|observed| {
            [observed.native_caps.timer, observed.native_caps.input]
                .into_iter()
                .filter_map(|cap| match cap {
                    BackendIoNativeCap::Armed(deadline) => Some(deadline),
                    BackendIoNativeCap::Unknown | BackendIoNativeCap::ObservedAbsent => None,
                })
                .min()
        })
    }

    pub(super) fn record_imported_io_publication(
        &mut self,
        event: &ScheduledEvent,
    ) -> Result<(), SchedulerError> {
        let ScheduledEventPayload::IoCompletion(completion) = &event.payload else {
            return Ok(());
        };
        let Some(node) = self.imported_io.get_mut(&completion.target) else {
            return Ok(());
        };
        let delivery = node
            .queues
            .get_mut(&completion.sub_node)
            .and_then(|queue| queue.deliveries.get_mut(&completion.source_delivery))
            .ok_or_else(|| inventory_error("published physical delivery lacks its actor origin"))?;
        if delivery.key != event.key || delivery.completion != *completion || delivery.published {
            return Err(inventory_error(
                "published physical delivery changed or reused its identity",
            ));
        }
        delivery.published = true;
        Ok(())
    }

    pub(super) fn validate_imported_io_ledger(&self) -> Result<(), SchedulerError> {
        if self.imported_io.is_empty() {
            return Ok(());
        }
        let world = self.inventory_world.as_ref().ok_or_else(|| {
            inventory_error("restored physical inventory lacks its actual World owner")
        })?;
        let layout =
            crate::WorldIoInstantiationLayout::derive(world, WorldIoLayoutPolicy::default())
                .map_err(|error| inventory_error(&error.to_string()))?;
        for (target, node) in &self.imported_io {
            let index = self.vm_node_index(target)?;
            validate_native_caps(node.observed, node.native_caps)?;
            if node.world != world.id() || node.observed > self.nodes[index].counter {
                return Err(inventory_error(
                    "restored physical inventory changed World or counter",
                ));
            }
            let devices = world
                .io_nodes()
                .filter(|device| &device.owner == target)
                .collect::<Vec<_>>();
            if devices.len() != node.queues.len() {
                return Err(inventory_error(
                    "restored physical inventory has incomplete queue coverage",
                ));
            }
            for device in devices {
                let kind = match device.kind.family() {
                    crate::WorldDeviceKind::Block => SchedulingNodeKind::Disk,
                    crate::WorldDeviceKind::NineP => SchedulingNodeKind::NineP,
                };
                let id = SchedulerNodeId {
                    node: device.id.clone(),
                    kind,
                };
                let queue = node.queues.get(&id).ok_or_else(|| {
                    inventory_error("restored physical inventory names the wrong queue")
                })?;
                if layout.get(&device.id).map(|binding| binding.source_node)
                    != Some(queue.source_node)
                {
                    return Err(inventory_error(
                        "restored physical queue changed its source number",
                    ));
                }
                validate_queue(
                    node.observed,
                    &BackendIoQueueSnapshot {
                        world: node.world,
                        device: id.clone(),
                        source_node: queue.source_node,
                        revision: queue.revision,
                        pipeline_revision: queue.pipeline_revision,
                        next_pipeline_boundary: queue.next_pipeline_boundary,
                        completions: queue
                            .current
                            .iter()
                            .map(|completion| BackendIoComputedReply {
                                source_delivery: completion.source_delivery,
                                payload: completion.payload.clone(),
                            })
                            .collect(),
                    },
                )?;
                for (physical, delivery) in &queue.deliveries {
                    let at = self.vm_delivery_time_for_tick(
                        target,
                        SimInstant {
                            ticks: physical.delivery_icount,
                        },
                    )?;
                    let pending = self
                        .pending_events
                        .iter()
                        .find(|event| event.key == delivery.key);
                    if physical != &delivery.completion.source_delivery
                        || physical.src_node != queue.source_node
                        || delivery.completion.sub_node != id
                        || delivery.completion.target != *target
                        || delivery.completion.delivery_tick != at
                        || delivery.key.virtual_time().ticks != at.ticks
                        || delivery.key.producer() != &id
                        || delivery.key.consumer() != &self.nodes[index].id
                        || delivery.key.sequence()
                            >= self
                                .event_sequences
                                .next_sequence(&id, &self.nodes[index].id)
                        || (delivery.published && pending.is_some())
                        || (!delivery.published
                            && pending.is_none_or(|event| {
                                event.payload
                                    != ScheduledEventPayload::IoCompletion(
                                        delivery.completion.clone(),
                                    )
                            }))
                    {
                        return Err(inventory_error(
                            "restored physical delivery lost its canonical origin",
                        ));
                    }
                }
                for completion in &queue.current {
                    if queue
                        .deliveries
                        .get(&completion.source_delivery)
                        .is_none_or(|delivery| delivery.completion != *completion)
                    {
                        return Err(inventory_error(
                            "restored current queue lacks its original delivery",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn validate_queue(
    observed: NodeCounter,
    queue: &BackendIoQueueSnapshot,
) -> Result<(), SchedulerError> {
    let correct_pipeline_owner = match queue.device.kind {
        SchedulingNodeKind::Disk => queue.pipeline_revision.is_some(),
        SchedulingNodeKind::NineP => queue.pipeline_revision.is_none(),
        _ => false,
    };
    if !correct_pipeline_owner {
        return Err(inventory_error(
            "physical queue lacks its exact pipeline revision owner",
        ));
    }
    if queue
        .next_pipeline_boundary
        .is_some_and(|cap| cap < observed)
    {
        return Err(inventory_error(
            "physical pipeline deadline precedes its stopped source",
        ));
    }
    let mut previous = None;
    for completion in &queue.completions {
        let key = completion.source_delivery;
        if key.src_node != queue.source_node
            || key.delivery_icount < observed.ticks
            || previous.is_some_and(|previous| previous >= key)
        {
            return Err(inventory_error(
                "physical queue completion has invalid provenance or order",
            ));
        }
        previous = Some(key);
    }
    Ok(())
}

fn inventory_error(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: message.to_owned(),
    }
}

#[cfg(test)]
#[path = "io_inventory/tests.rs"]
pub(in crate::scheduler) mod tests;

// Unknown is not absence, and a deadline before the authenticated physical
// observation is stale. A due-at-current deadline remains factual input for
// the distinct stopped consumer; it must never be widened into a positive RUN.
fn validate_native_caps(
    observed: NodeCounter,
    caps: BackendIoNativeCaps,
) -> Result<(), SchedulerError> {
    for cap in [caps.timer, caps.input] {
        match cap {
            BackendIoNativeCap::Unknown => {
                return Err(inventory_error(
                    "physical inventory lacks complete native cap knowledge",
                ));
            }
            BackendIoNativeCap::Armed(deadline) if deadline < observed => {
                return Err(inventory_error(
                    "native event cap precedes its authenticated stopped tick",
                ));
            }
            BackendIoNativeCap::ObservedAbsent | BackendIoNativeCap::Armed(_) => {}
        }
    }
    Ok(())
}
